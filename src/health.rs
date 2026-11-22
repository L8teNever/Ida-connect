//! Gesundheit von Speicher und Stromversorgung (Op `health`): SMART von SSD/HDD/NVMe (über `smartctl`, falls installiert),
//! SD-/eMMC-Karte (Verschleiß, Schreibmenge), Dateisystemfehler (read-only, ext4-Fehlerzähler, Kernel-Meldungen) und beim
//! Raspberry Pi Unterspannung/Drosselung (`vcgencmd get_throttled`). Alles nur lesend.
use serde_json::{Value, json};
use std::time::Duration;

use crate::host;

fn read(p: &str) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

/// Stufen: 0 ok, 1 Warnung, 2 Fehler
fn level_name(l: u8) -> &'static str {
    match l {
        0 => "ok",
        1 => "warn",
        _ => "fail",
    }
}

/// Befehl mit Zeitlimit, Ausgabe (stdout) auch bei Exit-Code ≠ 0 (smartctl nutzt den Exit-Code als Bitmaske).
async fn run(argv: &[&str], secs: u64) -> Option<String> {
    let mut c = host::get().command(argv);
    c.stdin(std::process::Stdio::null()).stderr(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).kill_on_drop(true);
    let out = tokio::time::timeout(Duration::from_secs(secs), c.output()).await.ok()?.ok()?;
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

// ---------- Unterspannung / Drosselung ----------

pub fn decode_throttled(v: u32) -> Value {
    let b = |m: u32| (v & m) != 0;
    json!({
        "raw": format!("0x{v:x}"),
        "undervoltage": b(0x1), "freq_capped": b(0x2), "throttled": b(0x4), "soft_temp_limit": b(0x8),
        "undervoltage_seen": b(0x10000), "freq_capped_seen": b(0x20000), "throttled_seen": b(0x40000), "soft_temp_limit_seen": b(0x80000),
    })
}

pub fn parse_throttled(s: &str) -> Option<u32> {
    let v = s.trim().rsplit('=').next()?.trim().trim_start_matches("0x");
    u32::from_str_radix(v, 16).ok()
}

/// Unterspannung gerade jetzt (Raspberry Pi, Treiber rpi_volt) – billig genug für jede Messung.
pub fn undervoltage_now() -> Option<bool> {
    let rd = std::fs::read_dir(format!("{}/class/hwmon", host::get().sys_dir)).ok()?;
    for e in rd.flatten() {
        let d = e.path().display().to_string();
        if read(&format!("{d}/name")).trim() == "rpi_volt" {
            return read(&format!("{d}/in0_lcrit_alarm")).trim().parse::<u8>().ok().map(|v| v != 0);
        }
    }
    None
}

async fn power() -> Option<(Value, u8, Vec<String>)> {
    let raw = match run(&["vcgencmd", "get_throttled"], 5).await.and_then(|s| parse_throttled(&s)) {
        Some(v) => v,
        None => parse_throttled(&read(&format!("{}/devices/platform/soc/soc:firmware/get_throttled", host::get().sys_dir)))?,
    };
    let mut lvl = 0;
    let mut p = Vec::new();
    if raw & 0x1 != 0 {
        lvl = 2;
        p.push("Unterspannung: Netzteil oder Kabel liefert gerade zu wenig Strom".to_string());
    } else if raw & 0x10000 != 0 {
        lvl = 1;
        p.push("Unterspannung seit dem Start aufgetreten (Netzteil/Kabel prüfen, Gift für SD-Karten)".to_string());
    }
    if raw & 0x4 != 0 {
        lvl = lvl.max(1);
        p.push("CPU wird gerade gedrosselt".to_string());
    } else if raw & 0x40000 != 0 {
        p.push("CPU wurde seit dem Start gedrosselt".to_string());
        lvl = lvl.max(1);
    }
    Some((decode_throttled(raw), lvl, p))
}

// ---------- SMART ----------

fn attr_raw(v: &Value, id: u64) -> Option<u64> {
    v["ata_smart_attributes"]["table"].as_array()?.iter().find(|a| a["id"].as_u64() == Some(id))?["raw"]["value"].as_u64()
}

fn attr_norm(v: &Value, id: u64) -> Option<u64> {
    v["ata_smart_attributes"]["table"].as_array()?.iter().find(|a| a["id"].as_u64() == Some(id))?["value"].as_u64()
}

/// Wertet die JSON-Ausgabe von `smartctl -j -a` aus: Kennzahlen, Stufe (0/1/2) und Probleme im Klartext.
pub fn parse_smart(v: &Value) -> Value {
    let mut lvl = 0u8;
    let mut p: Vec<String> = Vec::new();
    let mut bump = |l: u8, t: String| {
        lvl = lvl.max(l);
        p.push(t);
    };
    let passed = v["smart_status"]["passed"].as_bool();
    if passed == Some(false) {
        bump(2, "SMART-Gesamtstatus meldet einen Fehler – Daten sichern, Platte ersetzen".into());
    }
    let temp = v["temperature"]["current"].as_i64();
    if temp.is_some_and(|t| t >= 70) {
        bump(1, format!("Laufwerk ist heiß ({} °C)", temp.unwrap_or(0)));
    }
    let mut wear_used: Option<u64> = None;
    let mut out = json!({
        "name": v["device"]["name"], "type": v["device"]["type"], "model": v["model_name"], "serial": v["serial_number"],
        "size": v["user_capacity"]["bytes"], "rotational": v["rotation_rate"].as_u64().map(|r| r > 0),
        "passed": passed, "temp": temp, "power_on_hours": v["power_on_time"]["hours"],
    });
    if let Some(n) = v.get("nvme_smart_health_information_log") {
        let used = n["percentage_used"].as_u64();
        wear_used = used;
        if n["critical_warning"].as_u64().unwrap_or(0) != 0 {
            bump(2, "NVMe meldet eine kritische Warnung".into());
        }
        if let (Some(s), Some(t)) = (n["available_spare"].as_u64(), n["available_spare_threshold"].as_u64())
            && s < t {
                bump(2, format!("Ersatzspeicher ({s} %) unter der Schwelle ({t} %)"));
            }
        if n["media_errors"].as_u64().unwrap_or(0) > 0 {
            bump(1, format!("{} Medienfehler", n["media_errors"]));
        }
        out["nvme"] = json!({
            "percentage_used": used, "available_spare": n["available_spare"], "media_errors": n["media_errors"],
            "unsafe_shutdowns": n["unsafe_shutdowns"], "data_units_written": n["data_units_written"],
        });
    }
    if v.get("ata_smart_attributes").is_some() {
        let (re, pe, un) = (attr_raw(v, 5), attr_raw(v, 197), attr_raw(v, 198));
        if re.unwrap_or(0) > 0 {
            bump(1, format!("{} umgelagerte Sektoren", re.unwrap_or(0)));
        }
        if pe.unwrap_or(0) > 0 {
            bump(1, format!("{} Sektoren warten auf Umlagerung (instabil)", pe.unwrap_or(0)));
        }
        if un.unwrap_or(0) > 0 {
            bump(1, format!("{} nicht korrigierbare Sektoren", un.unwrap_or(0)));
        }
        // SSD-Restlebensdauer (normiert, 100 = neu): 231 SSD Life Left, 233 Media Wearout, 177 Wear Leveling
        let left = [231u64, 233, 177].iter().find_map(|&i| attr_norm(v, i));
        if let Some(l) = left {
            wear_used = Some(100u64.saturating_sub(l));
        }
        out["ata"] = json!({
            "reallocated": re, "pending": pe, "uncorrectable": un, "crc_errors": attr_raw(v, 199),
            "power_cycles": attr_raw(v, 12), "life_left": left,
        });
    }
    if let Some(w) = wear_used {
        out["wear_used"] = json!(w);
        if w >= 100 {
            bump(2, "Verschleißgrenze erreicht".into());
        } else if w >= 90 {
            bump(1, format!("Stark abgenutzt ({w} % der Lebensdauer verbraucht)"));
        }
    }
    out["status"] = json!(level_name(lvl));
    out["problems"] = json!(p);
    out
}

async fn smart() -> (Value, u8, Vec<String>) {
    let Some(scan) = run(&["smartctl", "--scan", "-j"], 20).await else {
        return (json!({"available": false, "hint": "smartctl fehlt – installieren: apt install smartmontools", "devices": []}), 0, vec![]);
    };
    let scan: Value = serde_json::from_str(&scan).unwrap_or(Value::Null);
    let mut devs = Vec::new();
    let (mut lvl, mut probs) = (0u8, Vec::new());
    for d in scan["devices"].as_array().cloned().unwrap_or_default() {
        let (Some(name), ty) = (d["name"].as_str(), d["type"].as_str().unwrap_or("auto")) else { continue };
        if !name.starts_with("/dev/") {
            continue;
        }
        // -n standby: schlafende Platten nicht aufwecken
        let Some(o) = run(&["smartctl", "-j", "-a", "-n", "standby", "-d", ty, name], 30).await else { continue };
        let Ok(v) = serde_json::from_str::<Value>(&o) else { continue };
        if v.get("smart_status").is_none() && v["smartctl"]["messages"].to_string().to_lowercase().contains("standby") {
            devs.push(json!({"name": name, "type": ty, "standby": true, "status": "ok", "problems": []}));
            continue;
        }
        let r = parse_smart(&v);
        let l = match r["status"].as_str() {
            Some("fail") => 2,
            Some("warn") => 1,
            _ => 0,
        };
        lvl = lvl.max(l);
        for t in r["problems"].as_array().into_iter().flatten().filter_map(|t| t.as_str()) {
            probs.push(format!("{name}: {t}"));
        }
        devs.push(r);
    }
    (json!({"available": true, "devices": devs}), lvl, probs)
}

// ---------- SD-/eMMC-Karten ----------

/// Wert aus life_time ("0x01 0x01"): 0x01 = 0–10 % verbraucht … 0x0b = über der Lebensdauer. Gibt den höheren der beiden zurück.
pub fn emmc_wear(life: &str) -> Option<u64> {
    let m = life.split_whitespace().filter_map(|x| u64::from_str_radix(x.trim_start_matches("0x"), 16).ok()).max()?;
    (1..=11).contains(&m).then_some(m * 10)
}

fn cards() -> (Vec<Value>, u8, Vec<String>) {
    let mut out = Vec::new();
    let (mut lvl, mut probs) = (0u8, Vec::new());
    let Ok(rd) = std::fs::read_dir(format!("{}/block", host::get().sys_dir)) else { return (out, 0, probs) };
    let mut names: Vec<String> = rd
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.strip_prefix("mmcblk").is_some_and(|r| !r.is_empty() && r.chars().all(|c| c.is_ascii_digit())))
        .collect();
    names.sort();
    for n in names {
        let b = format!("{}/block/{n}", host::get().sys_dir);
        let dev = format!("{b}/device");
        let g = |k: &str| read(&format!("{dev}/{k}")).trim().to_string();
        let kind = match g("type").as_str() {
            "SD" => "SD",
            "MMC" => "eMMC",
            _ => "Karte",
        };
        let stat: Vec<u64> = read(&format!("{b}/stat")).split_whitespace().filter_map(|x| x.parse().ok()).collect();
        let written = stat.get(6).copied().unwrap_or(0) * 512;
        let size = read(&format!("{b}/size")).trim().parse::<u64>().unwrap_or(0) * 512;
        let life = g("life_time");
        let wear = emmc_wear(&life);
        let eol = g("pre_eol_info"); // 0x01 normal, 0x02 Warnung (80 % Reserve weg), 0x03 kritisch
        let pre_eol = if eol.is_empty() { Value::Null } else { json!(eol) };
        let mut l = 0u8;
        if let Some(w) = wear {
            if w >= 100 {
                l = 2;
                probs.push(format!("{n}: Lebensdauer des Speichers aufgebraucht ({w} %)"));
            } else if w >= 80 {
                l = 1;
                probs.push(format!("{n}: Speicher zu {w} % abgenutzt"));
            }
        }
        match eol.trim_start_matches("0x") {
            "03" | "3" => {
                l = 2;
                probs.push(format!("{n}: Reserveblöcke fast aufgebraucht (kritisch)"));
            }
            "02" | "2" => {
                l = l.max(1);
                probs.push(format!("{n}: Reserveblöcke zu 80 % verbraucht"));
            }
            _ => {}
        }
        lvl = lvl.max(l);
        out.push(json!({
            "name": n, "kind": kind, "model": g("name"), "manufacturer": g("manfid"), "date": g("date"), "serial": g("serial"),
            "size": size, "written_since_boot": written,
            "wear_used": wear, "pre_eol": pre_eol,
            "wear_known": wear.is_some(),
            "status": level_name(l),
        }));
    }
    (out, lvl, probs)
}

// ---------- Dateisystem ----------

/// Zeilen aus dem Kernel-Log, die auf Speicher-/Dateisystemprobleme oder Unterspannung hindeuten.
pub fn kernel_problems(dmesg: &str) -> Vec<String> {
    let keys = [
        "i/o error", "ext4-fs error", "ext4-fs warning", "remounting filesystem read-only", "buffer i/o error", "blk_update_request",
        "under-voltage detected", "fat-fs", "journal has aborted", "task abort", "sd error", "ata exception",
    ];
    let mut v: Vec<String> = dmesg
        .lines()
        .filter(|l| {
            let x = l.to_lowercase();
            keys.iter().any(|k| x.contains(k)) || (x.contains("mmc") && (x.contains("error") || x.contains("timeout") || x.contains("crc") || x.contains("-110")))
        })
        .map(|l| l.trim().to_string())
        .collect();
    let n = v.len();
    if n > 20 {
        v.drain(..n - 20);
    }
    v
}

/// Eingehängte Dateisysteme von echten Geräten: (Gerät, Einhängepunkt, Typ, nur lesbar?)
pub fn mounts(proc_mounts: &str) -> Vec<(String, String, String, bool)> {
    let mut out: Vec<(String, String, String, bool)> = Vec::new();
    for l in proc_mounts.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 4 || !f[0].starts_with("/dev/") || f[0].starts_with("/dev/loop") || f[0].starts_with("/dev/zram") {
            continue;
        }
        if !["ext4", "ext3", "ext2", "f2fs", "btrfs", "xfs", "vfat", "exfat", "ntfs", "ntfs3"].contains(&f[2]) {
            continue;
        }
        if out.iter().any(|m| m.1 == f[1]) {
            continue;
        }
        out.push((f[0].to_string(), f[1].to_string(), f[2].to_string(), f[3].split(',').any(|o| o == "ro")));
    }
    out
}

async fn filesystems() -> (Value, u8, Vec<String>) {
    let h = host::get();
    let (mut lvl, mut probs) = (0u8, Vec::new());
    let mut fs = Vec::new();
    for (dev, mp, ty, ro) in mounts(&read(&format!("{}/mounts", h.proc_dir))) {
        let base = dev.rsplit('/').next().unwrap_or("").to_string();
        let errors = read(&format!("{}/fs/ext4/{base}/errors_count", h.sys_dir)).trim().parse::<u64>().ok();
        let mut l = 0u8;
        if ro {
            // ein Dateisystem, das nach Fehlern auf "nur lesen" gefallen ist, ist meist am Ende; /boot ist oft absichtlich ro
            l = if mp == "/" { 2 } else { 1 };
            probs.push(format!("{mp} ist nur lesbar eingehängt{}", if mp == "/" { " – meist nach Dateisystemfehlern" } else { "" }));
        }
        if errors.unwrap_or(0) > 0 {
            l = l.max(1);
            probs.push(format!("{mp}: {} Dateisystemfehler gemeldet ({base})", errors.unwrap_or(0)));
        }
        lvl = lvl.max(l);
        fs.push(json!({"device": dev, "mount": mp, "type": ty, "read_only": ro, "errors": errors, "status": level_name(l)}));
    }
    let log = run(&["dmesg"], 10).await.map(|s| kernel_problems(&s)).unwrap_or_default();
    if !log.is_empty() {
        lvl = lvl.max(1);
        probs.push(format!("{} Meldungen zu Speicher/Strom im Kernel-Log", log.len()));
    }
    (json!({"mounts": fs, "kernel_log": log}), lvl, probs)
}

/// Gesamtbericht für Health.
pub async fn report() -> Value {
    let (smart, ls, ps) = smart().await;
    let (cards, lc, pc) = cards();
    let (fs, lf, pf) = filesystems().await;
    let pw = power().await;
    let mut lvl = ls.max(lc).max(lf);
    let mut problems: Vec<String> = ps.into_iter().chain(pc).chain(pf).collect();
    let power = match pw {
        Some((v, l, p)) => {
            lvl = lvl.max(l);
            problems.extend(p);
            let mut v = v;
            v["status"] = json!(level_name(l));
            v
        }
        None => Value::Null, // kein Raspberry Pi
    };
    json!({"status": level_name(lvl), "problems": problems, "smart": smart, "cards": cards, "filesystems": fs, "power": power})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttled() {
        assert_eq!(parse_throttled("throttled=0x50005\n"), Some(0x50005));
        assert_eq!(parse_throttled("0"), Some(0));
        assert_eq!(parse_throttled("quatsch"), None);
        let d = decode_throttled(0x50005);
        assert_eq!(d["undervoltage"], true);
        assert_eq!(d["throttled"], true);
        assert_eq!(d["soft_temp_limit"], false);
        assert_eq!(d["undervoltage_seen"], true);
        assert_eq!(decode_throttled(0x80000)["soft_temp_limit_seen"], true);
    }

    #[test]
    fn smart_ata() {
        let v = json!({
            "device": {"name": "/dev/sda", "type": "sat"}, "model_name": "X", "smart_status": {"passed": true},
            "temperature": {"current": 41}, "ata_smart_attributes": {"table": [
                {"id": 5, "value": 100, "raw": {"value": 8}}, {"id": 197, "value": 100, "raw": {"value": 0}},
                {"id": 231, "value": 95, "raw": {"value": 0}}]}
        });
        let r = parse_smart(&v);
        assert_eq!(r["status"], "warn");
        assert_eq!(r["ata"]["reallocated"], 8);
        assert_eq!(r["wear_used"], 5);
        let bad = parse_smart(&json!({"smart_status": {"passed": false}}));
        assert_eq!(bad["status"], "fail");
    }

    #[test]
    fn smart_nvme() {
        let v = json!({"smart_status": {"passed": true}, "nvme_smart_health_information_log":
            {"percentage_used": 93, "available_spare": 100, "available_spare_threshold": 10, "media_errors": 0, "critical_warning": 0}});
        let r = parse_smart(&v);
        assert_eq!(r["status"], "warn");
        assert_eq!(parse_smart(&json!({"smart_status": {"passed": true}}))["status"], "ok");
    }

    #[test]
    fn emmc() {
        assert_eq!(emmc_wear("0x01 0x02"), Some(20));
        assert_eq!(emmc_wear("0x0b 0x01"), Some(110));
        assert_eq!(emmc_wear(""), None);
        assert_eq!(emmc_wear("0x00 0x00"), None);
    }

    #[test]
    fn kernel_and_mounts() {
        let log = "[1.0] usb 1-1: new device\n[5.0] EXT4-fs error (device mmcblk0p2): ext4_find_entry\n[6.0] mmc0: Timeout waiting for hardware interrupt\n[7.0] Under-voltage detected! (0x00050005)";
        assert_eq!(kernel_problems(log).len(), 3);
        let m = mounts("/dev/mmcblk0p2 / ext4 rw,noatime 0 0\n/dev/mmcblk0p1 /boot/firmware vfat ro,relatime 0 0\ntmpfs /run tmpfs rw 0 0\n/dev/loop0 /snap/x squashfs ro 0 0");
        assert_eq!(m.len(), 2);
        assert!(!m[0].3 && m[1].3);
    }
}

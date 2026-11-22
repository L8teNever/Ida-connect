//! Messwerte direkt aus /proc und /sys – ohne Bibliothek, damit der Agent klein und sparsam bleibt.
use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::Instant;

use crate::host;

#[derive(Default)]
pub struct Sampler {
    cpu: Vec<(u64, u64)>, // (busy, total) je Zeile in /proc/stat: [0] = gesamt, dann je Kern
    net: HashMap<String, (u64, u64)>,
    io: HashMap<String, (u64, u64)>,
    last: Option<Instant>,
}

fn read(p: &str) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

impl Sampler {
    pub fn new() -> Sampler {
        let mut s = Sampler::default();
        let _ = s.sample(); // Ausgangswerte für die Raten
        s
    }

    pub fn sample(&mut self) -> Value {
        let h = host::get();
        let now = Instant::now();
        let dt = self.last.map(|l| now.duration_since(l).as_secs_f64()).unwrap_or(0.0);
        self.last = Some(now);

        // CPU
        let stat = read(&format!("{}/stat", h.proc_dir));
        let mut cpu_now = Vec::new();
        let mut procs = 0u64;
        for line in stat.lines() {
            if line.starts_with("cpu") {
                let v: Vec<u64> = line.split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
                if v.len() >= 4 {
                    let idle = v[3] + v.get(4).copied().unwrap_or(0); // idle + iowait
                    let total: u64 = v.iter().take(8).sum(); // ohne guest (steckt schon in user)
                    cpu_now.push((total - idle, total));
                }
            } else if let Some(r) = line.strip_prefix("procs_running ") {
                procs = r.trim().parse().unwrap_or(0);
            }
        }
        let pct = |i: usize| -> f64 {
            match (cpu_now.get(i), self.cpu.get(i)) {
                (Some(&(b, t)), Some(&(b0, t0))) if t > t0 => round1((b.saturating_sub(b0)) as f64 * 100.0 / (t - t0) as f64),
                _ => 0.0,
            }
        };
        let cpu = pct(0);
        let cores: Vec<f64> = (1..cpu_now.len()).map(pct).collect();
        self.cpu = cpu_now;

        // RAM
        let mi = meminfo(&h.proc_dir);
        let g = |k: &str| mi.get(k).copied().unwrap_or(0);
        let mem_total = g("MemTotal");
        let mem_avail = if mi.contains_key("MemAvailable") { g("MemAvailable") } else { g("MemFree") + g("Buffers") + g("Cached") };
        let swap_total = g("SwapTotal");

        // Last, Laufzeit
        let la: Vec<f64> = read(&format!("{}/loadavg", h.proc_dir)).split_whitespace().take(3).filter_map(|x| x.parse().ok()).collect();
        let up: f64 = read(&format!("{}/uptime", h.proc_dir)).split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0.0);

        // Netz
        let mut net = Vec::new();
        let mut net_now = HashMap::new();
        for line in read(&format!("{}/1/net/dev", h.proc_dir)).lines().skip(2) {
            let Some((name, rest)) = line.split_once(':') else { continue };
            let name = name.trim().to_string();
            if skip_iface(&name) {
                continue;
            }
            let v: Vec<u64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
            if v.len() < 9 {
                continue;
            }
            let (rx, tx) = (v[0], v[8]);
            if let Some(&(rx0, tx0)) = self.net.get(&name)
                && dt > 0.0 {
                    net.push(json!([name, (rx.saturating_sub(rx0) as f64 / dt) as u64, (tx.saturating_sub(tx0) as f64 / dt) as u64]));
                }
            net_now.insert(name, (rx, tx));
        }
        self.net = net_now;

        // Platten-Durchsatz (nur ganze Geräte)
        let mut io = Vec::new();
        let mut io_now = HashMap::new();
        for line in read(&format!("{}/diskstats", h.proc_dir)).lines() {
            let v: Vec<&str> = line.split_whitespace().collect();
            if v.len() < 10 || !whole_disk(v[2]) {
                continue;
            }
            let (r, w) = (v[5].parse::<u64>().unwrap_or(0) * 512, v[9].parse::<u64>().unwrap_or(0) * 512);
            let name = v[2].to_string();
            if let Some(&(r0, w0)) = self.io.get(&name)
                && dt > 0.0 {
                    io.push(json!([name, (r.saturating_sub(r0) as f64 / dt) as u64, (w.saturating_sub(w0) as f64 / dt) as u64]));
                }
            io_now.insert(name, (r, w));
        }
        self.io = io_now;

        let (temps, fans) = sensors(&h.sys_dir);
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        json!({
            "t": "m", "ts": secs, "cpu": cpu, "cores": cores,
            "mem": [(mem_total.saturating_sub(mem_avail)) * 1024, mem_total * 1024],
            "swap": [(swap_total.saturating_sub(g("SwapFree"))) * 1024, swap_total * 1024],
            "load": la, "up": up as u64, "procs": procs,
            "temps": temps, "fans": fans, "disks": disks(), "net": net, "io": io,
        })
    }
}

fn meminfo(proc_dir: &str) -> HashMap<String, u64> {
    read(&format!("{proc_dir}/meminfo"))
        .lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            Some((k.to_string(), v.split_whitespace().next()?.parse().ok()?))
        })
        .collect()
}

fn skip_iface(n: &str) -> bool {
    n == "lo" || ["veth", "docker", "br-", "virbr", "vnet", "tap", "dummy", "cni", "flannel", "kube"].iter().any(|p| n.starts_with(p))
}

fn whole_disk(n: &str) -> bool {
    if n.starts_with("loop") || n.starts_with("ram") || n.starts_with("zram") || n.starts_with("dm-") {
        return false;
    }
    if n.starts_with("nvme") || n.starts_with("mmcblk") {
        return !n.contains('p');
    }
    if n.starts_with("sd") || n.starts_with("vd") || n.starts_with("xvd") || n.starts_with("hd") {
        return n.chars().last().is_some_and(|c| c.is_ascii_alphabetic());
    }
    false
}

const REAL_FS: &[&str] = &["ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "exfat", "f2fs", "zfs", "ntfs", "ntfs3", "fuseblk", "jfs", "reiserfs", "bcachefs"];

/// Belegte und gesamte Bytes der echten Dateisysteme (je Gerät nur einmal).
pub fn disks() -> Vec<Value> {
    let h = host::get();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in read(&format!("{}/1/mounts", h.proc_dir)).lines() {
        let v: Vec<&str> = line.split_whitespace().collect();
        if v.len() < 3 || !REAL_FS.contains(&v[2]) || !seen.insert(v[0].to_string()) {
            continue;
        }
        let mount = v[1].replace("\\040", " ");
        let p = format!("{}{}", h.root, mount);
        if let Ok(s) = nix::sys::statvfs::statvfs(p.as_str()) {
            #[allow(clippy::unnecessary_cast)] // auf 32-Bit-Systemen sind es u32
            let bs = s.fragment_size() as u64;
            #[allow(clippy::unnecessary_cast)]
            let total = s.blocks() as u64 * bs;
            if total == 0 {
                continue;
            }
            #[allow(clippy::unnecessary_cast)]
            let used = total - s.blocks_free() as u64 * bs;
            out.push(json!([mount, used, total]));
        }
    }
    out
}

/// Temperaturen (°C) und Lüfter (U/min) aus thermal_zone und hwmon.
fn sensors(sys: &str) -> (Vec<Value>, Vec<Value>) {
    let mut temps = Vec::new();
    let mut fans = Vec::new();
    let mut names = std::collections::HashSet::new();
    if let Ok(rd) = std::fs::read_dir(format!("{sys}/class/hwmon")) {
        let mut dirs: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        dirs.sort();
        for d in dirs {
            let chip = read(&format!("{}/name", d.display())).trim().to_string();
            let Ok(files) = std::fs::read_dir(&d) else { continue };
            let mut files: Vec<String> = files.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
            files.sort();
            for f in files {
                let p = format!("{}/{}", d.display(), f);
                if let Some(base) = f.strip_prefix("temp").and_then(|x| x.strip_suffix("_input")) {
                    if let Ok(v) = read(&p).trim().parse::<f64>() {
                        let label = read(&format!("{}/temp{}_label", d.display(), base)).trim().to_string();
                        let name = if label.is_empty() { format!("{chip} {base}") } else { format!("{chip} {label}") };
                        if v > -40000.0 && v < 150000.0 && names.insert(name.clone()) {
                            temps.push(json!([name, round1(v / 1000.0)]));
                        }
                    }
                } else if let Some(base) = f.strip_prefix("fan").and_then(|x| x.strip_suffix("_input"))
                    && let Ok(v) = read(&p).trim().parse::<u64>() {
                        let label = read(&format!("{}/fan{}_label", d.display(), base)).trim().to_string();
                        fans.push(json!([if label.is_empty() { format!("{chip} fan{base}") } else { label }, v]));
                    }
            }
        }
    }
    // thermal_zone nur, wenn hwmon nichts hat (z. B. manche Raspberry Pi / ARM-Boards)
    if temps.is_empty()
        && let Ok(rd) = std::fs::read_dir(format!("{sys}/class/thermal")) {
            let mut zones: Vec<_> = rd.flatten().map(|e| e.path()).filter(|p| p.to_string_lossy().contains("thermal_zone")).collect();
            zones.sort();
            for z in zones {
                if let Ok(v) = read(&format!("{}/temp", z.display())).trim().parse::<f64>() {
                    let name = read(&format!("{}/type", z.display())).trim().to_string();
                    temps.push(json!([name, round1(v / 1000.0)]));
                }
            }
        }
    // Raspberry Pi 5: Lüfter über cooling_device (pwm-fan) ohne fan*_input
    (temps, fans)
}

/// Feste Angaben zum Gerät (für hello/info).
pub fn info(mesh: Value) -> Value {
    let h = host::get();
    let osr = read(&format!("{}/etc/os-release", h.root));
    let os = osr
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_else(|| "Linux".into());
    let cpuinfo = read(&format!("{}/cpuinfo", h.proc_dir));
    let field = |k: &str| cpuinfo.lines().find(|l| l.starts_with(k)).and_then(|l| l.split_once(':')).map(|(_, v)| v.trim().to_string());
    let model = read(&format!("{}/firmware/devicetree/base/model", h.sys_dir)).trim_end_matches('\0').trim().to_string();
    let cpu_model = field("model name").or_else(|| field("Model")).or_else(|| if model.is_empty() { None } else { Some(model.clone()) }).unwrap_or_default();
    let cores = cpuinfo.lines().filter(|l| l.starts_with("processor")).count();
    let hostname = read(&format!("{}/sys/kernel/hostname", h.proc_dir)).trim().to_string();
    let up: f64 = read(&format!("{}/uptime", h.proc_dir)).split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0.0);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    json!({
        "hostname": hostname, "os": os, "kernel": read(&format!("{}/sys/kernel/osrelease", h.proc_dir)).trim(),
        "arch": std::env::consts::ARCH, "cpu_model": cpu_model, "board": model, "cores": cores,
        "mem_total": meminfo(&h.proc_dir).get("MemTotal").copied().unwrap_or(0) * 1024,
        "mode": "systemd", "mesh": mesh, "boot": now.saturating_sub(up as u64),
        "agent": env!("CARGO_PKG_VERSION"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disks_names() {
        assert!(whole_disk("sda"));
        assert!(!whole_disk("sda1"));
        assert!(whole_disk("nvme0n1"));
        assert!(!whole_disk("nvme0n1p2"));
        assert!(whole_disk("mmcblk0"));
        assert!(!whole_disk("mmcblk0p1"));
        assert!(!whole_disk("loop3"));
    }

    #[test]
    fn sample_works() {
        let mut s = Sampler::new();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let m = s.sample();
        assert_eq!(m["t"], "m");
        assert!(m["mem"][1].as_u64().unwrap() > 0);
        assert!(m["cpu"].as_f64().unwrap() >= 0.0);
    }
}

//! Lüftersteuerung über hwmon (`pwmN` + `pwmN_enable`): Auto (Gerät/Kernel regelt), feste Stärke oder eigene Kurve
//! (Temperatur → Prozent). Gefunden werden nur Lüfter, deren PWM beschreibbar ist. Die Einstellungen liegen in der Config.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;

use crate::host;
use crate::link::Cfg;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FanCfg {
    /// "auto" | "fixed" | "curve"
    pub mode: String,
    /// feste Stärke in Prozent (mode fixed)
    #[serde(default)]
    pub percent: u8,
    /// Kurve: [[°C, Prozent], …], aufsteigend nach Temperatur (mode curve)
    #[serde(default)]
    pub curve: Vec<(f64, u8)>,
    /// Temperaturfühler für die Kurve (Name wie in `temps`); leer = heißester Fühler
    #[serde(default)]
    pub sensor: String,
}

struct Fan {
    id: String,
    name: String,
    dir: String,
    n: String,
    rpm: Option<u64>,
}

fn read(p: &str) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

/// Alle Lüfter mit beschreibbarem PWM. id = "<chip>/pwmN" (bei mehreren gleichen Chips "<chip>#k/pwmN").
fn find() -> Vec<Fan> {
    let h = host::get();
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(format!("{}/class/hwmon", h.sys_dir)) else { return out };
    let mut dirs: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    dirs.sort();
    let mut seen: HashMap<String, usize> = HashMap::new();
    for d in dirs {
        let dir = d.display().to_string();
        let chip = read(&format!("{dir}/name")).trim().to_string();
        let k = seen.entry(chip.clone()).or_insert(0);
        let chip_id = if *k == 0 { chip.clone() } else { format!("{chip}#{k}") };
        *k += 1;
        let Ok(files) = std::fs::read_dir(&d) else { continue };
        let mut ns: Vec<String> = files
            .flatten()
            .filter_map(|e| {
                let f = e.file_name().to_string_lossy().to_string();
                let n = f.strip_prefix("pwm")?;
                (!n.is_empty() && n.chars().all(|c| c.is_ascii_digit())).then(|| n.to_string())
            })
            .collect();
        ns.sort_by_key(|n| n.parse::<u32>().unwrap_or(0));
        for n in ns {
            let writable = std::fs::metadata(format!("{dir}/pwm{n}")).map(|m| !m.permissions().readonly()).unwrap_or(false);
            if !writable || read(&format!("{dir}/pwm{n}")).trim().parse::<u32>().is_err() {
                continue;
            }
            let label = read(&format!("{dir}/fan{n}_label")).trim().to_string();
            let name = if label.is_empty() { format!("{chip} fan{n}") } else { label };
            let rpm = read(&format!("{dir}/fan{n}_input")).trim().parse().ok();
            out.push(Fan { id: format!("{chip_id}/pwm{n}"), name, dir: dir.clone(), n, rpm });
        }
    }
    out
}

fn to_pwm(pct: u8) -> u32 {
    (pct.min(100) as u32 * 255 + 50) / 100
}

fn to_pct(pwm: u32) -> u8 {
    ((pwm.min(255) * 100 + 127) / 255) as u8
}

/// Stärke (%) aus der Kurve: unterhalb des ersten Punkts dessen Wert, oberhalb des letzten dessen Wert, dazwischen linear.
pub fn curve_percent(curve: &[(f64, u8)], t: f64) -> u8 {
    let (Some(first), Some(last)) = (curve.first(), curve.last()) else { return 100 };
    if t <= first.0 {
        return first.1.min(100);
    }
    if t >= last.0 {
        return last.1.min(100);
    }
    for w in curve.windows(2) {
        let ((t0, p0), (t1, p1)) = (w[0], w[1]);
        if (t0..=t1).contains(&t) {
            if t1 <= t0 {
                return p1.min(100);
            }
            let f = (t - t0) / (t1 - t0);
            return (p0 as f64 + (p1 as f64 - p0 as f64) * f).round().clamp(0.0, 100.0) as u8;
        }
    }
    100
}

/// Prüft und ordnet eine Einstellung (Kurve sortiert, Werte begrenzt).
pub fn validate(mut c: FanCfg) -> Result<FanCfg, String> {
    match c.mode.as_str() {
        "auto" => {}
        "fixed" => c.percent = c.percent.min(100),
        "curve" => {
            if c.curve.len() < 2 || c.curve.len() > 20 {
                return Err("Kurve braucht 2 bis 20 Punkte".into());
            }
            if c.curve.iter().any(|(t, _)| !t.is_finite() || *t < -50.0 || *t > 150.0) {
                return Err("Temperatur außerhalb -50 bis 150 °C".into());
            }
            for p in c.curve.iter_mut() {
                p.1 = p.1.min(100);
            }
            c.curve.sort_by(|a, b| a.0.total_cmp(&b.0));
            c.curve.dedup_by(|b, a| a.0 == b.0);
            if c.curve.len() < 2 {
                return Err("Kurve braucht 2 verschiedene Temperaturen".into());
            }
        }
        m => return Err(format!("unbekannter Modus {m} (auto, fixed, curve)")),
    }
    Ok(c)
}

/// Aktuelle Temperatur für die Kurve: gewählter Fühler, sonst der heißeste.
fn temperature(sensor: &str) -> Option<f64> {
    let (temps, _) = crate::metrics::sensors(&host::get().sys_dir);
    let vals = temps.iter().filter_map(|t| Some((t[0].as_str()?, t[1].as_f64()?)));
    if sensor.is_empty() {
        vals.map(|(_, v)| v).fold(None, |m: Option<f64>, v| Some(m.map_or(v, |m| m.max(v))))
    } else {
        vals.filter(|(n, _)| *n == sensor).map(|(_, v)| v).next()
    }
}

/// Auf "Auto" zurück: pwmN_enable auf den Wert vor unserem Eingriff (sonst 2 = automatisch).
fn release(f: &Fan, orig: &mut HashMap<String, String>) {
    if let Some(o) = orig.remove(&f.id) {
        let _ = std::fs::write(format!("{}/pwm{}_enable", f.dir, f.n), o);
    }
}

fn apply(f: &Fan, c: &FanCfg, orig: &mut HashMap<String, String>) -> Option<u8> {
    let en = format!("{}/pwm{}_enable", f.dir, f.n);
    if c.mode == "auto" {
        release(f, orig);
        return None;
    }
    let pct = if c.mode == "fixed" {
        c.percent.min(100)
    } else {
        // ohne lesbare Temperatur lieber volle Kraft als ein stehender Lüfter
        temperature(&c.sensor).map_or(100, |t| curve_percent(&c.curve, t))
    };
    if !orig.contains_key(&f.id) {
        let cur = read(&en).trim().to_string();
        if !cur.is_empty() && cur != "1" {
            orig.insert(f.id.clone(), cur);
        } else {
            orig.insert(f.id.clone(), "2".into()); // war schon manuell (Absturz?) – automatisch ist der sichere Rückweg
        }
        let _ = std::fs::write(&en, "1");
    }
    let want = to_pwm(pct);
    if read(&format!("{}/pwm{}", f.dir, f.n)).trim().parse::<u32>().ok() != Some(want) {
        let _ = std::fs::write(format!("{}/pwm{}", f.dir, f.n), want.to_string());
    }
    Some(pct)
}

/// Lüfter mit Einstellung für Health: id, name, rpm, aktuelle Stärke, Einstellung.
pub fn list(cfg: &Cfg) -> Value {
    let conf = cfg.lock().unwrap().fans.clone();
    let fans: Vec<Value> = find()
        .iter()
        .map(|f| {
            let pwm = read(&format!("{}/pwm{}", f.dir, f.n)).trim().parse::<u32>().unwrap_or(0);
            let c = conf.get(&f.id).cloned().unwrap_or(FanCfg { mode: "auto".into(), percent: 0, curve: vec![], sensor: String::new() });
            json!({"id": f.id, "name": f.name, "rpm": f.rpm, "percent": to_pct(pwm), "config": c})
        })
        .collect();
    let sensors: Vec<Value> = crate::metrics::sensors(&host::get().sys_dir).0.iter().map(|t| t[0].clone()).collect();
    json!({"fans": fans, "sensors": sensors})
}

/// Einstellung eines Lüfters setzen, speichern und sofort anwenden.
pub fn set(cfg: &Cfg, id: &str, c: FanCfg) -> Result<Value, String> {
    if !find().iter().any(|f| f.id == id) {
        return Err(format!("Lüfter {id} nicht gefunden oder nicht steuerbar"));
    }
    let c = validate(c)?;
    {
        let mut g = cfg.lock().unwrap();
        if c.mode == "auto" {
            g.fans.remove(id);
        } else {
            g.fans.insert(id.to_string(), c);
        }
        g.save().map_err(|e| e.to_string())?;
    }
    tick_now(cfg);
    Ok(list(cfg))
}

static ORIG: std::sync::Mutex<Option<HashMap<String, String>>> = std::sync::Mutex::new(None);

/// Einmal alle Lüfter nach Config einstellen (auch von `set` genutzt, damit es ohne Wartezeit wirkt).
fn tick_now(cfg: &Cfg) {
    let conf = cfg.lock().unwrap().fans.clone();
    let mut g = ORIG.lock().unwrap();
    let orig = g.get_or_insert_with(HashMap::new);
    for f in find() {
        match conf.get(&f.id) {
            Some(c) => {
                apply(&f, c, orig);
            }
            None => release(&f, orig),
        }
    }
}

/// Regelschleife: Kurven alle 3 Sekunden nachführen. Beim Beenden gibt `restore` die Lüfter wieder frei.
pub async fn run(cfg: Cfg) {
    loop {
        let c = cfg.clone();
        let _ = tokio::task::spawn_blocking(move || tick_now(&c)).await;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

/// Alle von uns übernommenen Lüfter zurück auf den Ausgangsmodus (beim Beenden des Dienstes).
pub fn restore() {
    let mut g = ORIG.lock().unwrap();
    if let Some(orig) = g.as_mut() {
        for f in find() {
            release(&f, orig);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curve() {
        let c = [(40.0, 20), (60.0, 50), (80.0, 100)];
        assert_eq!(curve_percent(&c, 30.0), 20);
        assert_eq!(curve_percent(&c, 50.0), 35);
        assert_eq!(curve_percent(&c, 70.0), 75);
        assert_eq!(curve_percent(&c, 95.0), 100);
        assert_eq!(curve_percent(&[], 50.0), 100);
    }

    #[test]
    fn pwm_percent() {
        assert_eq!(to_pwm(0), 0);
        assert_eq!(to_pwm(100), 255);
        assert_eq!(to_pct(255), 100);
        assert_eq!(to_pct(to_pwm(50)), 50);
    }

    #[test]
    fn validation() {
        let mk = |curve: Vec<(f64, u8)>| FanCfg { mode: "curve".into(), percent: 0, curve, sensor: String::new() };
        assert!(validate(mk(vec![(50.0, 10)])).is_err());
        let v = validate(mk(vec![(70.0, 200), (40.0, 10)])).unwrap();
        assert_eq!(v.curve, vec![(40.0, 10), (70.0, 100)]);
        assert!(validate(FanCfg { mode: "x".into(), percent: 0, curve: vec![], sensor: String::new() }).is_err());
    }
}

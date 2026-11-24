//! Updates von ida-connect: nachsehen, ob es eine neuere Version gibt, und sie installieren.
//! Gekoppelte Geräte fragen zuerst IDA Health (Mesh, dann öffentliche Adresse): Health holt Version, Install-Skript und Programm
//! mit seinem GitHub-Zugang – so geht das auch, wenn das Repo privat ist. Kennt Health das noch nicht (älter) oder ist es nicht
//! erreichbar, geht es wie früher direkt zu GitHub.
//! Installiert wird immer mit install.sh --update: das lässt /etc/ida-connect (Kopplung, PIN, Einstellungen) unverändert,
//! behält den Port und stellt die alte Version wieder her, falls die neue nicht startet.
use serde_json::{Value, json};
use std::time::Duration;

use crate::link::{Cfg, Shared};
use crate::ops;

pub const REPO: &str = "L8teNever/Ida-connect";
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
/// Auto-Update: zuerst 10 Minuten nach dem Start, danach alle 6 Stunden
const FIRST_CHECK: Duration = Duration::from_secs(600);
const EVERY: Duration = Duration::from_secs(6 * 3600);

/// "v0.1.42" / "0.1.42" -> (0, 1, 42). Alles andere -> None.
pub fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().trim_start_matches('v');
    let mut it = s.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some((a, b, c))
}

/// Ist `latest` wirklich neuer als `current`? Unklare Angaben gelten nie als neuer.
pub fn newer(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

/// Aus der Weiterleitung von …/releases/latest die Version lesen: …/releases/tag/v0.1.42 -> "0.1.42"
pub fn tag_from_url(url: &str) -> Option<String> {
    let tag = url.trim().trim_end_matches('/').rsplit_once("/releases/tag/")?.1;
    parse_version(tag).map(|(a, b, c)| format!("{a}.{b}.{c}"))
}

/// Neueste Version: zuerst über Health, sonst direkt von GitHub.
pub async fn latest() -> Result<String, String> {
    let mut why = String::new();
    if let Some((bases, hdr)) = via_health() {
        for b in &bases {
            match health_release(b, &hdr).await {
                Ok(v) => return Ok(v),
                Err(e) => why = e,
            }
        }
    }
    github_latest().await.map_err(|e| if why.is_empty() { e } else { format!("{e} (über Health: {why})") })
}

/// Neueste Version auf GitHub (ohne API, also ohne Rate-Limit: GitHub leitet …/releases/latest auf den Tag weiter).
async fn github_latest() -> Result<String, String> {
    let url = std::env::var("IDA_CONNECT_RELEASES").unwrap_or_else(|_| format!("https://github.com/{REPO}/releases/latest"));
    if !url.starts_with("https://") {
        return Err("ungültige Adresse".into());
    }
    let r = ops::exec(&format!("curl -s -o /dev/null --max-time 20 -w '%{{redirect_url}}' '{url}'"), "", 30).await?;
    let loc = r["stdout"].as_str().unwrap_or("").to_string();
    if loc.is_empty() {
        return Err("GitHub nicht erreichbar (oder noch kein Release)".into());
    }
    if loc.trim_end_matches('/').ends_with("/releases") {
        return Err("auf GitHub gibt es noch kein Release".into());
    }
    tag_from_url(&loc).ok_or_else(|| format!("unerwartete Antwort von GitHub: {loc}"))
}

/// {current, latest, available, checked, error}
pub async fn check() -> Value {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    match latest().await {
        Ok(l) => json!({"current": CURRENT, "latest": l, "available": newer(&l, CURRENT), "checked": now, "error": ""}),
        Err(e) => json!({"current": CURRENT, "latest": "", "available": false, "checked": now, "error": e}),
    }
}

/// Gekoppelt? Dann Adressen von Health (Mesh zuerst) und eine Datei mit den Anmelde-Köpfen für curl (-H @datei).
/// Die Datei liegt neben der Config (Ordner nur für root) – das Secret steht so nie in einer Befehlszeile.
fn via_health() -> Option<(Vec<String>, String)> {
    let p = crate::config::path();
    // leise lesen: `ida-connect update --check` ohne root darf die Config nicht lesen können, dann eben GitHub
    let c: crate::config::Config = serde_json::from_str(&std::fs::read_to_string(&p).ok()?).ok()?;
    if !c.paired() {
        return None;
    }
    let bases: Vec<String> = [c.mesh_server.as_str(), c.server.as_str()]
        .iter()
        .map(|b| b.trim().trim_end_matches('/').to_string())
        .filter(|b| safe_url(b))
        .collect();
    if bases.is_empty() {
        return None;
    }
    let mut h = format!("Authorization: Bearer {}:{}\n", c.device_id, c.secret);
    if !c.cf_client_id.is_empty() {
        h += &format!("CF-Access-Client-Id: {}\nCF-Access-Client-Secret: {}\n", c.cf_client_id, c.cf_client_secret);
    }
    if h.contains('\r') || h.lines().count() > 3 {
        return None;
    }
    let f = p.with_file_name("health-auth");
    write_private(&f, &h).ok()?;
    Some((bases, f.to_string_lossy().to_string()))
}

/// Darf so in eine Shell-Zeile (in '…'): http(s), keine Anführungszeichen, Leerzeichen o. Ä.
pub fn safe_url(u: &str) -> bool {
    (u.starts_with("https://") || u.starts_with("http://"))
        && u.len() > 8
        && u.chars().all(|c| c.is_ascii_alphanumeric() || ":/.-_[]%".contains(c))
}

fn write_private(p: &std::path::Path, s: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(p)?;
    f.write_all(s.as_bytes())
}

async fn health_release(base: &str, hdr: &str) -> Result<String, String> {
    let r = ops::exec(&format!("curl -fsS --connect-timeout 5 --max-time 25 -H @'{hdr}' '{base}/api/v1/agent/release'"), "", 35).await?;
    if r["code"].as_i64() != Some(0) {
        return Err(r["stderr"].as_str().unwrap_or("").trim().to_string());
    }
    let v: Value = serde_json::from_str(r["stdout"].as_str().unwrap_or("")).map_err(|_| "unerwartete Antwort".to_string())?;
    let ver = v["version"].as_str().unwrap_or("");
    parse_version(ver).map(|(a, b, c)| format!("{a}.{b}.{c}")).ok_or_else(|| format!("unerwartete Version {ver}"))
}

/// Shell-Befehl, der das Update ausführt. Über Health: Skript von Health laden (nach /etc/ida-connect/install.sh) und mit
/// --health starten – das Skript lädt dann auch das Programm über Health. Sonst wie früher von GitHub.
pub async fn script() -> String {
    if std::env::var("IDA_CONNECT_INSTALL_URL").is_err()
        && let Some((bases, hdr)) = via_health()
    {
        let file = crate::config::path().with_file_name("install.sh").to_string_lossy().to_string();
        for b in &bases {
            let cmd = format!(
                "curl -fsS --connect-timeout 5 --max-time 60 -H @'{hdr}' -o '{file}.new' '{b}/api/v1/agent/install.sh' \
                 && head -c 2 '{file}.new' | grep -q '#!' && mv -f '{file}.new' '{file}'"
            );
            if ops::exec(&cmd, "", 70).await.is_ok_and(|r| r["code"].as_i64() == Some(0)) {
                return format!("sh '{file}' --update --health '{b}'");
            }
        }
    }
    format!("curl -fsSL '{}' | sh -s -- --update", install_url())
}

/// Install-Skript losgelöst vom Dienst starten (eigene systemd-Unit): der Dienst wird dabei neu gestartet,
/// das Update läuft trotzdem zu Ende. Ohne systemd-run: im Hintergrund mit Log in /tmp.
pub async fn install() -> Result<Value, String> {
    let script = script().await.replace('\'', "'\\''");
    let cmd = format!(
        "if command -v systemd-run >/dev/null 2>&1; then systemd-run --unit ida-connect-update-$(date +%s) --collect sh -c '{script}'; \
         else nohup sh -c '{script}' >/tmp/ida-connect-update.log 2>&1 & fi"
    );
    let r = ops::exec(&cmd, "", 30).await?;
    let out = format!("{}{}", r["stdout"].as_str().unwrap_or(""), r["stderr"].as_str().unwrap_or(""));
    if r["code"].as_i64() != Some(0) {
        return Err(format!("Update ließ sich nicht starten: {out}"));
    }
    Ok(json!({"started": true, "output": out}))
}

pub fn install_url() -> String {
    std::env::var("IDA_CONNECT_INSTALL_URL").unwrap_or_else(|_| ops::INSTALL_URL.to_string())
}

/// Im Dienst: regelmäßig nachsehen und – wenn Auto-Update an ist – selbst installieren.
pub async fn auto_loop(cfg: Cfg, state: Shared) {
    tokio::time::sleep(FIRST_CHECK).await;
    loop {
        let v = check().await;
        state.lock().unwrap().update = v.clone();
        let auto = cfg.lock().unwrap().auto_update;
        if auto && v["available"] == true {
            eprintln!("ida-connect: neue Version {} – installiere (aktuell {CURRENT})", v["latest"].as_str().unwrap_or("?"));
            if let Err(e) = install().await {
                eprintln!("ida-connect: Auto-Update: {e}");
            }
        }
        tokio::time::sleep(EVERY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse_version("v0.1.42"), Some((0, 1, 42)));
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("0.1.x"), None);
        assert!(newer("0.1.10", "0.1.9"));
        assert!(!newer("0.1.9", "0.1.10"));
        assert!(!newer("0.1.9", "0.1.9"));
        assert!(!newer("kaputt", "0.1.0"));
        assert!(!newer("", "0.1.0"));
    }

    #[test]
    fn urls_for_shell() {
        assert!(safe_url("https://health.example.com"));
        assert!(safe_url("http://100.96.0.5:8000"));
        assert!(!safe_url("https://h.example/'; rm -rf /"));
        assert!(!safe_url("ftp://h.example"));
        assert!(!safe_url("https://"));
    }

    #[test]
    fn tags() {
        assert_eq!(tag_from_url("https://github.com/L8teNever/Ida-connect/releases/tag/v0.1.17"), Some("0.1.17".into()));
        assert_eq!(tag_from_url("https://github.com/L8teNever/Ida-connect/releases/tag/v0.1.17/"), Some("0.1.17".into()));
        assert_eq!(tag_from_url("https://github.com/L8teNever/Ida-connect/releases"), None);
        assert_eq!(tag_from_url("https://github.com/L8teNever/Ida-connect/releases/tag/nightly"), None);
        assert_eq!(tag_from_url(""), None);
    }
}

//! Updates von ida-connect: nachsehen, ob es auf GitHub eine neuere Version gibt, und sie installieren.
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

/// Neueste Version auf GitHub (ohne API, also ohne Rate-Limit: GitHub leitet …/releases/latest auf den Tag weiter).
pub async fn latest() -> Result<String, String> {
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

/// Install-Skript losgelöst vom Dienst starten (eigene systemd-Unit): der Dienst wird dabei neu gestartet,
/// das Update läuft trotzdem zu Ende. Ohne systemd-run: im Hintergrund mit Log in /tmp.
pub async fn install() -> Result<Value, String> {
    let url = install_url();
    let cmd = format!(
        "if command -v systemd-run >/dev/null 2>&1; then systemd-run --unit ida-connect-update-$(date +%s) --collect sh -c 'curl -fsSL {url} | sh -s -- --update'; \
         else nohup sh -c 'curl -fsSL {url} | sh -s -- --update' >/tmp/ida-connect-update.log 2>&1 & fi"
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
    fn tags() {
        assert_eq!(tag_from_url("https://github.com/L8teNever/Ida-connect/releases/tag/v0.1.17"), Some("0.1.17".into()));
        assert_eq!(tag_from_url("https://github.com/L8teNever/Ida-connect/releases/tag/v0.1.17/"), Some("0.1.17".into()));
        assert_eq!(tag_from_url("https://github.com/L8teNever/Ida-connect/releases"), None);
        assert_eq!(tag_from_url("https://github.com/L8teNever/Ida-connect/releases/tag/nightly"), None);
        assert_eq!(tag_from_url(""), None);
    }
}

//! Konfiguration: eine kleine JSON-Datei (Standard /etc/ida-connect/config.json, nur root lesbar).
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct Config {
    /// Adresse von IDA Health, z. B. https://health.example.com (kein Standard: kommt mit --server oder von der lokalen Seite)
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub name: String,
    /// PIN für die lokale Seite (Port 1111) – wird bei der Installation angezeigt
    #[serde(default)]
    pub pin: String,
    /// optional: Cloudflare-Access-Service-Token (falls der Agent-Pfad nicht per Bypass offen ist)
    #[serde(default)]
    pub cf_client_id: String,
    #[serde(default)]
    pub cf_client_secret: String,
    /// Adresse von Health im Cloudflare Mesh (schickt Health selbst, z. B. http://100.96.0.5:8000). Ist das Mesh auf diesem
    /// Gerät verbunden, läuft alles darüber; sonst (oder wenn es nicht klappt) über `server`.
    #[serde(default)]
    pub mesh_server: String,
    /// Nur noch über das Mesh mit Health reden (schickt Health). Die öffentliche Adresse dann nur noch zum Koppeln,
    /// solange WARP hier noch nicht läuft, und als Notweg, wenn das Mesh lange (15 min) nicht geht.
    #[serde(default)]
    pub mesh_only: bool,
    /// Neue Versionen von GitHub selbst installieren (alle 6 Stunden nachsehen)
    #[serde(default = "yes")]
    pub auto_update: bool,
    /// Lüfter-Einstellungen (id → Modus/Stärke/Kurve); Lüfter ohne Eintrag laufen automatisch. Siehe fan.rs
    #[serde(default)]
    pub fans: std::collections::HashMap<String, crate::fan::FanCfg>,
    /// Selbstheilungs-Regeln („wenn X down, dann Neustart“). Siehe heal.rs
    #[serde(default)]
    pub heal: Vec<crate::heal::Rule>,
}

fn yes() -> bool {
    true
}


pub fn path() -> PathBuf {
    std::env::var("IDA_CONNECT_CONFIG").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/etc/ida-connect/config.json"))
}

impl Config {
    pub fn load() -> Config {
        Self::load_from(&path())
    }

    /// Lädt die Config. Ist die Datei da, aber nicht lesbar (kaputt, halb geschrieben), wird sie NIE überschrieben –
    /// sonst wäre die Kopplung weg (Updates rufen `ida-connect pin` auf).
    pub fn load_from(p: &std::path::Path) -> Config {
        let (mut c, broken) = match std::fs::read_to_string(p) {
            Ok(s) => match serde_json::from_str::<Config>(&s) {
                Ok(c) => (c, false),
                Err(e) => {
                    eprintln!("ida-connect: {} ist nicht lesbar ({e}) – bleibt unverändert", p.display());
                    (Config::default(), true)
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Config::default(), false),
            Err(e) => {
                eprintln!("ida-connect: {} nicht lesbar: {e}", p.display());
                (Config::default(), true)
            }
        };
        if broken {
            c.auto_update = false; // kaputte Config: nichts von selbst tun
        } else if std::fs::metadata(p).is_err() {
            c.auto_update = true;
        }
        if c.server.is_empty() {
            c.server = std::env::var("IDA_CONNECT_SERVER").unwrap_or_default();
        }
        if c.pin.is_empty() {
            c.pin = random_pin();
            if !broken {
                let _ = c.save_to(p);
            }
        }
        c
    }

    pub fn paired(&self) -> bool {
        !self.device_id.is_empty() && !self.secret.is_empty()
    }

    pub fn save(&self) -> std::io::Result<()> {
        self.save_to(&path())
    }

    pub fn save_to(&self, p: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let p = p.to_path_buf();
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        let tmp = p.with_extension("tmp");
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(serde_json::to_string_pretty(self).unwrap_or_default().as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, &p)
    }
}

/// Zufallsbytes aus dem Kernel.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    }
    b
}

pub fn random_hex(n: usize) -> String {
    random_bytes(n).iter().map(|b| format!("{b:02x}")).collect()
}

fn random_pin() -> String {
    random_bytes(8).iter().take(8).map(|b| char::from(b'0' + b % 10)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broken_config_is_never_overwritten() {
        let d = std::env::temp_dir().join(format!("idac-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("config.json");
        std::fs::write(&p, "{ kaputt").unwrap();
        let c = Config::load_from(&p);
        assert!(!c.paired() && !c.auto_update);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{ kaputt");
        // alte Datei ohne neue Felder: Kopplung bleibt, Auto-Update ist an, PIN wird ergänzt
        std::fs::write(&p, r#"{"server":"https://h.example","device_id":"d1","secret":"s1"}"#).unwrap();
        let c = Config::load_from(&p);
        assert!(c.paired() && c.auto_update && c.pin.len() == 8 && c.mesh_server.is_empty());
        let again = Config::load_from(&p);
        assert_eq!(again.pin, c.pin);
        assert_eq!(again.device_id, "d1");
        std::fs::remove_dir_all(&d).unwrap();
    }
}

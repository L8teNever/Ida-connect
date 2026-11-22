//! Zugriff auf das Gerät. ida-connect läuft als Systemdienst direkt auf dem Gerät (root): Dateien, /proc, /sys und Befehle
//! sind die echten. Die Pfade bleiben hier gebündelt, damit sich das an einer Stelle ändern lässt.
use std::path::PathBuf;
use std::sync::OnceLock;

pub struct Host {
    /// Wurzel des Geräts im Dateisystem ("" = direkt)
    pub root: String,
    pub proc_dir: String,
    pub sys_dir: String,
}

pub fn get() -> &'static Host {
    static H: OnceLock<Host> = OnceLock::new();
    H.get_or_init(|| Host { root: String::new(), proc_dir: "/proc".into(), sys_dir: "/sys".into() })
}

impl Host {
    /// Pfad auf dem Gerät. Nur absolute Pfade.
    pub fn path(&self, p: &str) -> Result<PathBuf, String> {
        if !p.starts_with('/') {
            return Err("Pfad muss absolut sein".into());
        }
        Ok(PathBuf::from(format!("{}{}", self.root, p)))
    }

    /// Kommando, das `argv` auf dem Gerät ausführt.
    pub fn command(&self, argv: &[&str]) -> tokio::process::Command {
        let mut c = tokio::process::Command::new(argv[0]);
        c.args(&argv[1..]);
        c.env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        c
    }

    pub fn shell(&self) -> &'static str {
        if std::path::Path::new(&format!("{}/bin/bash", self.root)).exists() { "/bin/bash" } else { "/bin/sh" }
    }
}

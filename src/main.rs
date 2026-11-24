//! ida-connect – kleiner Agent für IDA Health: schickt Messwerte, gibt Shell, Dateien und Docker frei (nur über Health),
//! lokale Seite auf Port 1111 zum Koppeln, optional Cloudflare Mesh. Siehe README.md und PROTOCOL.md.
mod config;
mod fan;
mod health;
mod heal;
mod host;
mod link;
mod metrics;
mod ops;
mod pty;
mod update;
mod web;

use std::sync::{Arc, Mutex};

const HELP: &str = "ida-connect – Agent für IDA Health

  ida-connect              Agent starten (lokale Seite auf Port 1111)
  ida-connect pin          PIN der lokalen Seite anzeigen
  ida-connect pair <code>  mit einem Code aus IDA Health koppeln (ohne Browser)
  ida-connect status       Kopplung und Verbindung anzeigen
  ida-connect server <url> Adresse von IDA Health setzen
  ida-connect mesh [<token>] [--server <url>]
                           Cloudflare Mesh hier einrichten (WARP installieren, Knoten-Token, Token auch per
                           IDA_CONNECT_MESH_TOKEN) und die Mesh-Adresse von Health merken (--server)
  ida-connect update       auf neue Version prüfen und installieren (Kopplung und Einstellungen bleiben)
  ida-connect update --check   nur nachsehen
  ida-connect update --force   auch ohne neue Version neu installieren
  ida-connect auto-update on|off   neue Versionen selbst installieren (Standard: an, alle 6 Stunden)
  ida-connect --version

Umgebung: IDA_CONNECT_LISTEN (Standard 0.0.0.0:1111), IDA_CONNECT_CONFIG, IDA_CONNECT_SERVER";

fn main() {
    // rustls kommt ohne Standard-Backend (tokio-tungstenite ohne default features) – ring fest einstellen,
    // sonst bricht die erste TLS-Verbindung (Health, GitHub) mit einer Panic ab.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("--version" | "-V" | "version") => println!("ida-connect {}", env!("CARGO_PKG_VERSION")),
        Some("--help" | "-h" | "help") => println!("{HELP}"),
        Some("pin") => println!("{}", config::Config::load().pin),
        Some("status") => {
            let c = config::Config::load();
            println!("Server:    {}", c.server);
            println!("Gekoppelt: {}", if c.paired() { format!("ja ({}, {})", c.name, c.device_id) } else { "nein".into() });
            println!("Mesh:      {}", if c.mesh_server.is_empty() { "– (Health ist nicht im Mesh)".to_string() } else {
                format!("{}{}", c.mesh_server, if c.mesh_only { "  (nur über das Mesh)" } else { "" })
            });
            println!("Version:   {}  (Auto-Update {})", update::CURRENT, if c.auto_update { "an" } else { "aus" });
        }
        Some("mesh") => cli_mesh(&args[1..]),
        Some("update") => cli_update(args.get(1).map(|s| s.as_str()).unwrap_or("")),
        Some("auto-update") => {
            let on = match args.get(1).map(|s| s.as_str()) {
                Some("on" | "an" | "1") => true,
                Some("off" | "aus" | "0") => false,
                _ => {
                    eprintln!("ida-connect auto-update on|off");
                    std::process::exit(2);
                }
            };
            let mut c = config::Config::load();
            c.auto_update = on;
            if c.save().is_err() {
                eprintln!("Kann {} nicht schreiben (als root ausführen)", config::path().display());
                std::process::exit(1);
            }
            restart_service();
            println!("Auto-Update {}", if on { "an" } else { "aus" });
        }
        Some("server") => {
            let Some(url) = args.get(1).filter(|u| u.starts_with("https://") || u.starts_with("http://")) else {
                eprintln!("Adresse fehlt: ida-connect server https://health.example.com");
                std::process::exit(2);
            };
            let mut c = config::Config::load();
            c.server = url.trim_end_matches('/').to_string();
            if c.save().is_err() {
                eprintln!("Kann {} nicht schreiben (als root ausführen)", config::path().display());
                std::process::exit(1);
            }
            println!("Server: {}", c.server);
        }
        Some("pair") => {
            let Some(code) = args.get(1) else {
                eprintln!("Code fehlt: ida-connect pair <code> [server]");
                std::process::exit(2);
            };
            let mut c = config::Config::load();
            if let Some(s) = args.get(2) {
                c.server = s.trim_end_matches('/').to_string();
            }
            // Code für den laufenden Dienst ablegen; der Dienst koppelt beim nächsten Start/Versuch
            c.device_id.clear();
            c.secret.clear();
            let _ = c.save();
            let p = config::path().with_file_name("pair-code");
            if std::fs::write(&p, code.trim()).is_err() {
                eprintln!("Kann {} nicht schreiben (als root ausführen)", p.display());
                std::process::exit(1);
            }
            println!("Code gespeichert. Jetzt den Dienst neu starten: sudo systemctl restart ida-connect");
        }
        None | Some("run") => run(),
        Some(x) => {
            eprintln!("Unbekannt: {x}\n\n{HELP}");
            std::process::exit(2);
        }
    }
}

fn run() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio");
    rt.block_on(async {
        let cfg = Arc::new(Mutex::new(config::Config::load()));
        let state: link::Shared = Arc::new(Mutex::new(link::State::default()));
        // Code aus "ida-connect pair" oder dem Install-Skript (--code)
        let pc = config::path().with_file_name("pair-code");
        if let Ok(code) = std::fs::read_to_string(&pc) {
            let _ = std::fs::remove_file(&pc);
            if !code.trim().is_empty() {
                state.lock().unwrap().pair_code = Some(code.trim().to_string());
            }
        }
        let wake = Arc::new(tokio::sync::Notify::new());
        let listen = std::env::var("IDA_CONNECT_LISTEN").unwrap_or_else(|_| "0.0.0.0:1111".into());
        if listen != "off" {
            tokio::spawn(web::serve(listen, cfg.clone(), state.clone(), wake.clone()));
        }
        tokio::spawn(update::auto_loop(cfg.clone(), state.clone()));
        tokio::spawn(fan::run(cfg.clone()));
        tokio::spawn(heal::run_loop(cfg.clone()));
        let l = tokio::spawn(link::run(cfg, state, wake));
        tokio::select! {
            _ = l => {},
            _ = tokio::signal::ctrl_c() => {},
            _ = async {
                if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) { s.recv().await; }
            } => {},
        }
        fan::restore(); // Lüfter wieder dem Gerät überlassen
    });
}

/// `ida-connect mesh`: Mesh einrichten (wie der Knopf in Health) und die Mesh-Adresse von Health speichern.
/// Das Install-Skript ruft das mit --mesh-token/--mesh-server auf, bevor der Dienst startet – so läuft schon das Koppeln übers Mesh.
fn cli_mesh(args: &[String]) {
    let mut token = std::env::var("IDA_CONNECT_MESH_TOKEN").unwrap_or_default();
    let mut server = String::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--server" => server = it.next().cloned().unwrap_or_default(),
            t if token.is_empty() => token = t.to_string(),
            x => {
                eprintln!("Unbekannt: {x}");
                std::process::exit(2);
            }
        }
    }
    let server = server.trim().trim_end_matches('/').to_string();
    if !server.is_empty() && !(server.starts_with("http://") || server.starts_with("https://")) {
        eprintln!("Mesh-Adresse muss mit http:// oder https:// anfangen");
        std::process::exit(2);
    }
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Bitte als root: sudo ida-connect mesh …");
        std::process::exit(1);
    }
    if !server.is_empty() {
        let mut c = config::Config::load();
        c.mesh_server = server.clone();
        if c.save().is_err() {
            eprintln!("Kann {} nicht schreiben", config::path().display());
            std::process::exit(1);
        }
        println!("Mesh-Adresse von Health: {server}");
    }
    if token.trim().is_empty() {
        if server.is_empty() {
            eprintln!("Token fehlt: ida-connect mesh <token> [--server <url>]");
            std::process::exit(2);
        }
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio");
    match rt.block_on(ops::mesh_setup(&token)) {
        Ok(v) => {
            let ip = v["mesh"]["ip"].as_str().unwrap_or("");
            println!("Cloudflare Mesh eingerichtet{}", if ip.is_empty() { String::new() } else { format!(" – IP {ip}") });
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

/// Dienst neu starten, damit er geänderte Einstellungen liest (er hält sie im Speicher).
fn restart_service() {
    let _ = std::process::Command::new("systemctl").args(["try-restart", "ida-connect"]).status();
}

/// `ida-connect update`: nachsehen und installieren. Läuft das Install-Skript in einer eigenen systemd-Unit, übersteht es den
/// Neustart des Dienstes – wichtig, wenn man es im Terminal von IDA Health aufruft (das hängt am Dienst).
fn cli_update(flag: &str) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio");
    let v = rt.block_on(update::check());
    let latest = v["latest"].as_str().unwrap_or("");
    println!("Installiert: {}", update::CURRENT);
    if latest.is_empty() {
        println!("Neueste:     ? ({})", v["error"].as_str().unwrap_or(""));
        if flag != "--force" {
            std::process::exit(1);
        }
    } else {
        println!("Neueste:     {latest}");
    }
    if flag == "--check" {
        println!("{}", if v["available"] == true { "Update verfügbar: sudo ida-connect update" } else { "Aktuell." });
        return;
    }
    if v["available"] != true && flag != "--force" {
        println!("Schon aktuell. (Neu installieren: sudo ida-connect update --force)");
        return;
    }
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Bitte als root: sudo ida-connect update");
        std::process::exit(1);
    }
    let script = rt.block_on(update::script());
    let has_run = std::process::Command::new("sh").args(["-c", "command -v systemd-run"]).output().is_ok_and(|o| o.status.success());
    let st = if has_run {
        std::process::Command::new("systemd-run").args(["--quiet", "--pipe", "--wait", "--collect", "sh", "-c", &script]).status()
    } else {
        std::process::Command::new("sh").args(["-c", &script]).status()
    };
    match st {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("Update fehlgeschlagen – siehe Ausgabe oben.");
            std::process::exit(1);
        }
    }
}

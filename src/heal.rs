//! Selbstheilung: Regeln der Form „wenn <Prüfung> fehlschlägt, dann <Aktion>“ – z. B. Container down → Neustart.
//! Prüfungen: container (läuft/healthy), service (systemd), http (curl), tcp (Port offen), command (Exit-Code 0).
//! Aktionen: restart (nur container/service) oder command (eigener Befehl). Schutz vor Dauerschleifen: erst nach mehreren
//! Fehlschlägen in Folge, Pause zwischen Aktionen und höchstens N Aktionen pro Stunde (danach „gave_up“, bis die Prüfung wieder klappt).
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use crate::config::random_hex;
use crate::host;
use crate::link::Cfg;

fn yes() -> bool {
    true
}
fn d_action() -> String {
    "restart".into()
}
fn d_interval() -> u64 {
    30
}
fn d_fails() -> u32 {
    3
}
fn d_cooldown() -> u64 {
    300
}
fn d_max() -> u32 {
    3
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Rule {
    /// leer beim Anlegen – der Agent vergibt eine
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// "container" | "service" | "http" | "tcp" | "command"
    pub check: String,
    /// Containername | systemd-Dienst | URL | host:port | Shell-Befehl (je nach check)
    pub target: String,
    /// "restart" (container/service) | "command"
    #[serde(default = "d_action")]
    pub action: String,
    /// Shell-Befehl bei action = command
    #[serde(default)]
    pub cmd: String,
    /// Sekunden zwischen den Prüfungen
    #[serde(default = "d_interval")]
    pub interval: u64,
    /// so viele Fehlschläge in Folge, bevor die Aktion läuft
    #[serde(default = "d_fails")]
    pub fails: u32,
    /// Mindestabstand zwischen zwei Aktionen (Sekunden)
    #[serde(default = "d_cooldown")]
    pub cooldown: u64,
    /// höchstens so viele Aktionen pro Stunde
    #[serde(default = "d_max")]
    pub max_per_hour: u32,
}

const MAX_RULES: usize = 50;

fn name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && !s.starts_with('-') && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.@:".contains(c))
}

/// Prüft und begrenzt eine Regel.
pub fn validate(mut r: Rule) -> Result<Rule, String> {
    r.target = r.target.trim().to_string();
    r.cmd = r.cmd.trim().to_string();
    match r.check.as_str() {
        "container" | "service" => {
            if !name_ok(&r.target) {
                return Err("ungültiger Name (erlaubt: Buchstaben, Ziffern, - _ . @ :)".into());
            }
        }
        "http" => {
            if !(r.target.starts_with("http://") || r.target.starts_with("https://")) || r.target.contains(char::is_whitespace) {
                return Err("URL muss mit http:// oder https:// beginnen".into());
            }
        }
        "tcp" => {
            let ok = r.target.rsplit_once(':').is_some_and(|(h, p)| !h.is_empty() && !h.contains(char::is_whitespace) && p.parse::<u16>().is_ok_and(|p| p > 0));
            if !ok {
                return Err("Ziel muss host:port sein".into());
            }
        }
        "command" => {
            if r.target.is_empty() {
                return Err("Prüfbefehl fehlt".into());
            }
        }
        c => return Err(format!("unbekannte Prüfung {c} (container, service, http, tcp, command)")),
    }
    match r.action.as_str() {
        "restart" => {
            if !matches!(r.check.as_str(), "container" | "service") {
                return Err("Neustart gibt es nur bei container und service – sonst action=command mit eigenem Befehl".into());
            }
        }
        "command" => {
            if r.cmd.is_empty() {
                return Err("Befehl für die Aktion fehlt".into());
            }
        }
        a => return Err(format!("unbekannte Aktion {a} (restart, command)")),
    }
    r.interval = r.interval.clamp(5, 3600);
    r.fails = r.fails.clamp(1, 20);
    r.cooldown = r.cooldown.clamp(10, 86400);
    r.max_per_hour = r.max_per_hour.clamp(1, 20);
    if r.name.trim().is_empty() {
        r.name = format!("{} {}", r.check, r.target.chars().take(40).collect::<String>());
    }
    r.name = r.name.trim().chars().take(80).collect();
    Ok(r)
}

// ---------- Prüfungen und Aktionen ----------

fn tail(s: &str) -> String {
    let s = s.trim();
    let n = s.chars().count();
    s.chars().skip(n.saturating_sub(300)).collect()
}

/// Befehl mit Zeitlimit: (Exit-Code, stdout+stderr gekürzt)
async fn run(argv: &[&str], secs: u64) -> Result<(i32, String), String> {
    let mut c = host::get().command(argv);
    c.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).kill_on_drop(true);
    let o = tokio::time::timeout(Duration::from_secs(secs), c.output())
        .await
        .map_err(|_| format!("{} hat nicht rechtzeitig geantwortet", argv[0]))?
        .map_err(|e| format!("{} nicht startbar: {e}", argv[0]))?;
    let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    Ok((o.status.code().unwrap_or(-1), tail(&text)))
}

async fn check(r: &Rule) -> Result<(), String> {
    let t = r.target.as_str();
    match r.check.as_str() {
        "container" => {
            let (c, o) = run(&["docker", "inspect", "-f", "{{.State.Running}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", t], 15).await?;
            if c != 0 {
                return Err(format!("Container nicht gefunden oder Docker nicht erreichbar: {o}"));
            }
            let mut w = o.split_whitespace();
            if w.next() != Some("true") {
                return Err("Container läuft nicht".into());
            }
            if w.next() == Some("unhealthy") {
                return Err("Container ist unhealthy".into());
            }
            Ok(())
        }
        "service" => match run(&["systemctl", "is-active", "--quiet", t], 10).await? {
            (0, _) => Ok(()),
            (_, o) => Err(format!("Dienst ist nicht aktiv {o}").trim().to_string()),
        },
        "tcp" => match tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(t)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(format!("Port nicht erreichbar: {e}")),
            Err(_) => Err("Port nicht erreichbar (Zeitlimit)".into()),
        },
        "http" => match run(&["curl", "-fsS", "-m", "10", "-o", "/dev/null", "--", t], 15).await? {
            (0, _) => Ok(()),
            (c, o) => Err(format!("HTTP-Prüfung fehlgeschlagen (curl {c}): {o}")),
        },
        "command" => match run(&["sh", "-c", t], 30).await? {
            (0, _) => Ok(()),
            (c, o) => Err(format!("Prüfbefehl endete mit Code {c}: {o}")),
        },
        c => Err(format!("unbekannte Prüfung {c}")),
    }
}

async fn act(r: &Rule) -> Result<String, String> {
    let t = r.target.as_str();
    let (c, o) = if r.action == "command" {
        run(&["sh", "-c", r.cmd.as_str()], 120).await?
    } else {
        match r.check.as_str() {
            "container" => run(&["docker", "restart", t], 120).await?,
            "service" => run(&["systemctl", "restart", t], 60).await?,
            _ => return Err("kein Neustart für diese Prüfung".into()),
        }
    };
    if c == 0 { Ok(o) } else { Err(format!("Aktion fehlgeschlagen (Code {c}): {o}")) }
}

// ---------- Entscheidung ----------

#[derive(Debug, PartialEq)]
pub enum Decision {
    /// noch nicht genug Fehlschläge oder Pause läuft
    Wait,
    Act,
    /// zu viele Aktionen in der letzten Stunde
    GiveUp,
}

pub fn decide(fails: u32, threshold: u32, actions_last_hour: u32, max_per_hour: u32, cooldown_over: bool) -> Decision {
    if fails < threshold {
        Decision::Wait
    } else if actions_last_hour >= max_per_hour {
        Decision::GiveUp
    } else if cooldown_over {
        Decision::Act
    } else {
        Decision::Wait
    }
}

// ---------- Zustand und Ereignisse ----------

static SEQ: AtomicU64 = AtomicU64::new(0);
static LOG: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static STAT: LazyLock<Mutex<HashMap<String, Value>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn now_ts() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn event(r: &Rule, kind: &str, ok: bool, msg: String) {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed) + 1;
    let mut l = LOG.lock().unwrap();
    l.push(json!({"seq": seq, "ts": now_ts(), "rule": r.id, "name": r.name, "kind": kind, "ok": ok, "msg": msg}));
    let n = l.len();
    if n > 50 {
        l.drain(..n - 50);
    }
}

pub fn current_seq() -> u64 {
    SEQ.load(Ordering::Relaxed)
}

/// Ereignisse nach `seq` (für die Verbindung zu Health).
pub fn events_since(seq: u64) -> Vec<Value> {
    LOG.lock().unwrap().iter().filter(|e| e["seq"].as_u64().unwrap_or(0) > seq).cloned().collect()
}

struct RState {
    fails: u32,
    last: Option<Instant>,
    last_action: Option<Instant>,
    actions: VecDeque<Instant>,
    status: &'static str,
    error: String,
    last_ok: u64,
    last_act_ts: u64,
}

impl RState {
    fn new() -> RState {
        RState { fails: 0, last: None, last_action: None, actions: VecDeque::new(), status: "unknown", error: String::new(), last_ok: 0, last_act_ts: 0 }
    }
}

/// Regelschleife: alle 5 Sekunden nachsehen, welche Regel fällig ist.
pub async fn run_loop(cfg: Cfg) {
    let mut st: HashMap<String, RState> = HashMap::new();
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let rules = cfg.lock().unwrap().heal.clone();
        st.retain(|k, _| rules.iter().any(|r| &r.id == k));
        for r in rules.iter().filter(|r| r.enabled) {
            let s = st.entry(r.id.clone()).or_insert_with(RState::new);
            if s.last.is_some_and(|l| l.elapsed() < Duration::from_secs(r.interval)) {
                continue;
            }
            s.last = Some(Instant::now());
            match check(r).await {
                Ok(()) => {
                    if matches!(s.status, "failing" | "healing" | "gave_up") {
                        event(r, "recovered", true, "läuft wieder".into());
                    }
                    s.status = "ok";
                    s.fails = 0;
                    s.error.clear();
                    s.last_ok = now_ts();
                }
                Err(e) => {
                    s.fails += 1;
                    s.error = e.clone();
                    while s.actions.front().is_some_and(|a| a.elapsed() > Duration::from_secs(3600)) {
                        s.actions.pop_front();
                    }
                    let cool = s.last_action.is_none_or(|a| a.elapsed() >= Duration::from_secs(r.cooldown));
                    match decide(s.fails, r.fails, s.actions.len() as u32, r.max_per_hour, cool) {
                        Decision::Wait => s.status = "failing",
                        Decision::GiveUp => {
                            if s.status != "gave_up" {
                                event(r, "gave_up", false, format!("{e} – schon {} Aktionen in der letzten Stunde, ich warte, bis es wieder klappt", s.actions.len()));
                            }
                            s.status = "gave_up";
                        }
                        Decision::Act => {
                            let res = act(r).await;
                            let (ok, what) = match &res {
                                Ok(_) => (true, "Aktion ausgeführt".to_string()),
                                Err(x) => (false, x.clone()),
                            };
                            event(r, "action", ok, format!("{e} → {what}"));
                            let now = Instant::now();
                            s.actions.push_back(now);
                            s.last_action = Some(now);
                            s.last_act_ts = now_ts();
                            s.fails = 0;
                            s.status = "healing";
                        }
                    }
                }
            }
        }
        let mut pub_: HashMap<String, Value> = HashMap::new();
        for r in &rules {
            let v = match st.get(&r.id) {
                Some(s) if r.enabled => json!({"status": s.status, "fails": s.fails, "error": s.error, "last_ok": s.last_ok, "last_action": s.last_act_ts, "actions_last_hour": s.actions.len()}),
                _ => json!({"status": if r.enabled { "unknown" } else { "disabled" }}),
            };
            pub_.insert(r.id.clone(), v);
        }
        *STAT.lock().unwrap() = pub_;
    }
}

// ---------- Operationen für Health ----------

pub fn list(cfg: &Cfg) -> Value {
    let rules = cfg.lock().unwrap().heal.clone();
    let stat = STAT.lock().unwrap().clone();
    let rules: Vec<Value> = rules
        .iter()
        .map(|r| {
            let mut v = serde_json::to_value(r).unwrap_or(Value::Null);
            v["state"] = stat.get(&r.id).cloned().unwrap_or_else(|| json!({"status": if r.enabled { "unknown" } else { "disabled" }}));
            v
        })
        .collect();
    json!({"rules": rules, "events": LOG.lock().unwrap().clone()})
}

/// Regel anlegen (id leer) oder ändern.
pub fn set(cfg: &Cfg, r: Rule) -> Result<Value, String> {
    let mut r = validate(r)?;
    {
        let mut g = cfg.lock().unwrap();
        if r.id.is_empty() {
            if g.heal.len() >= MAX_RULES {
                return Err(format!("höchstens {MAX_RULES} Regeln"));
            }
            r.id = random_hex(4);
            g.heal.push(r);
        } else if let Some(x) = g.heal.iter_mut().find(|x| x.id == r.id) {
            *x = r;
        } else {
            return Err("Regel nicht gefunden".into());
        }
        g.save().map_err(|e| e.to_string())?;
    }
    Ok(list(cfg))
}

pub fn delete(cfg: &Cfg, id: &str) -> Result<Value, String> {
    {
        let mut g = cfg.lock().unwrap();
        let n = g.heal.len();
        g.heal.retain(|x| x.id != id);
        if g.heal.len() == n {
            return Err("Regel nicht gefunden".into());
        }
        g.save().map_err(|e| e.to_string())?;
    }
    Ok(list(cfg))
}

/// Prüfung einer Regel jetzt ausführen (ohne Aktion) – zum Testen.
pub async fn check_now(cfg: &Cfg, id: &str) -> Result<Value, String> {
    let r = cfg.lock().unwrap().heal.iter().find(|x| x.id == id).cloned().ok_or("Regel nicht gefunden")?;
    Ok(match check(&r).await {
        Ok(()) => json!({"ok": true}),
        Err(e) => json!({"ok": false, "error": e}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(check: &str, target: &str, action: &str, cmd: &str) -> Rule {
        Rule {
            id: String::new(), name: String::new(), enabled: true, check: check.into(), target: target.into(), action: action.into(),
            cmd: cmd.into(), interval: 1, fails: 99, cooldown: 1, max_per_hour: 99,
        }
    }

    #[test]
    fn validation() {
        let r = validate(rule("container", "nginx", "restart", "")).unwrap();
        assert_eq!((r.interval, r.fails, r.cooldown, r.max_per_hour), (5, 20, 10, 20));
        assert_eq!(r.name, "container nginx");
        assert!(validate(rule("container", "-rf", "restart", "")).is_err());
        assert!(validate(rule("container", "a b", "restart", "")).is_err());
        assert!(validate(rule("http", "http://x.local/health", "restart", "")).is_err()); // kein Neustart bei http
        assert!(validate(rule("http", "http://x.local/health", "command", "systemctl restart x")).is_ok());
        assert!(validate(rule("http", "ftp://x", "command", "x")).is_err());
        assert!(validate(rule("tcp", "127.0.0.1:80", "command", "x")).is_ok());
        assert!(validate(rule("tcp", "127.0.0.1", "command", "x")).is_err());
        assert!(validate(rule("tcp", "host:0", "command", "x")).is_err());
        assert!(validate(rule("command", "", "command", "x")).is_err());
        assert!(validate(rule("service", "ssh", "command", "")).is_err());
        assert!(validate(rule("nix", "x", "command", "x")).is_err());
    }

    #[test]
    fn decisions() {
        assert_eq!(decide(2, 3, 0, 3, true), Decision::Wait);
        assert_eq!(decide(3, 3, 0, 3, true), Decision::Act);
        assert_eq!(decide(3, 3, 0, 3, false), Decision::Wait);
        assert_eq!(decide(5, 3, 3, 3, true), Decision::GiveUp);
        assert_eq!(decide(1, 3, 3, 3, true), Decision::Wait);
    }

    #[test]
    fn checks_and_actions() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            assert!(check(&rule("command", "true", "command", "x")).await.is_ok());
            assert!(check(&rule("command", "echo kaputt; false", "command", "x")).await.unwrap_err().contains("kaputt"));
            assert!(act(&rule("command", "true", "command", "echo ok")).await.is_ok());
            assert!(act(&rule("command", "true", "command", "exit 3")).await.is_err());
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = l.local_addr().unwrap().port();
            assert!(check(&rule("tcp", &format!("127.0.0.1:{port}"), "command", "x")).await.is_ok());
            drop(l);
            assert!(check(&rule("tcp", &format!("127.0.0.1:{port}"), "command", "x")).await.is_err());
        });
    }
}

//! Verbindung zu IDA Health: eine ausgehende WebSocket-Verbindung für alles (siehe PROTOCOL.md).
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest, http::HeaderValue, protocol::CloseFrame};

use crate::config::Config;
use crate::{metrics, ops, pty};

/// Gemeinsamer Zustand für die lokale Seite.
#[derive(Default)]
pub struct State {
    pub connected: bool,
    pub last_error: String,
    pub mesh: Value,
    /// Einmal-Code fürs Koppeln: die nächste Verbindung meldet sich damit an
    pub pair_code: Option<String>,
    pub pair_result: Option<Result<String, String>>,
    /// Weg der aktuellen Verbindung: "mesh" (über Cloudflare Mesh) oder "public" (über die öffentliche Adresse)
    pub route: &'static str,
    /// letzte Update-Prüfung (update::check)
    pub update: Value,
}

pub type Shared = Arc<Mutex<State>>;
pub type Cfg = Arc<Mutex<Config>>;

fn ws_url(server: &str) -> String {
    let s = server.trim().trim_end_matches('/');
    let s = if let Some(r) = s.strip_prefix("https://") {
        format!("wss://{r}")
    } else if let Some(r) = s.strip_prefix("http://") {
        format!("ws://{r}")
    } else {
        format!("wss://{s}")
    };
    format!("{s}/api/v1/agent/ws")
}

enum End {
    Retry(String),
    /// Verbindung kam gar nicht zustande (dann ggf. gleich den nächsten Weg probieren)
    Connect(String),
    Unauthorized,
    /// Mesh ist (wieder) erreichbar: neu verbinden, diesmal darüber
    ToMesh,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Route {
    Mesh,
    Public,
}

impl Route {
    pub fn name(self) -> &'static str {
        match self {
            Route::Mesh => "mesh",
            Route::Public => "public",
        }
    }
}

/// Wie lange das Mesh im Modus „nur Mesh“ nicht gehen darf, bis der Notweg über die öffentliche Adresse aufgeht
pub const MESH_EMERGENCY: Duration = Duration::from_secs(15 * 60);

/// In welcher Reihenfolge Health versucht wird. Über das Mesh nur, wenn Health seine Mesh-Adresse kennt und WARP hier verbunden ist.
/// - normal: Mesh zuerst, öffentliche Adresse als Rückfall
/// - „nur Mesh“ (Health schickt mesh_only): nur das Mesh – öffentlich nur, wenn WARP hier gar nicht eingerichtet ist
///   (Koppeln, 32-Bit-Gerät) oder als Notweg (`emergency`: Mesh geht seit MESH_EMERGENCY nicht)
pub fn routes(c: &Config, mesh_up: bool, mesh_here: bool, emergency: bool) -> Vec<(Route, String)> {
    let mut v = Vec::new();
    let has_mesh = !c.mesh_server.is_empty();
    if has_mesh && (mesh_up || (c.mesh_only && mesh_here)) {
        v.push((Route::Mesh, c.mesh_server.clone()));
    }
    if !(has_mesh && c.mesh_only && mesh_here) || emergency {
        v.push((Route::Public, c.server.clone()));
    }
    v
}

/// Ist WARP auf diesem Gerät eingerichtet (installiert, 64-Bit)? Dann gilt „nur Mesh“.
pub fn mesh_here(mesh: &Value) -> bool {
    mesh["supported"] != false && !matches!(mesh["status"].as_str(), Some("nicht eingerichtet") | None)
}

/// "http://100.96.0.5:8000/x" -> "100.96.0.5:8000"
pub fn host_port(url: &str) -> Option<String> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let hp = rest.split('/').next()?;
    if hp.is_empty() {
        return None;
    }
    if hp.rsplit_once(':').is_some_and(|(_, p)| p.parse::<u16>().is_ok()) && !hp.ends_with(']') {
        Some(hp.to_string())
    } else {
        Some(format!("{hp}:{}", if scheme == "https" { 443 } else { 80 }))
    }
}

/// Wann die erste Mesh-Probe laufen darf: nach 30 s, aber nicht vor Ablauf der Sperre.
pub fn probe_start(now: tokio::time::Instant, skip: Option<tokio::time::Instant>) -> tokio::time::Instant {
    let t = now + Duration::from_secs(30);
    match skip {
        Some(s) if s > t => s,
        _ => t,
    }
}

/// Kommt man per TCP an die Mesh-Adresse von Health?
async fn reachable(url: &str) -> bool {
    let Some(hp) = host_port(url) else { return false };
    matches!(tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(hp)).await, Ok(Ok(_)))
}

/// Infos fürs Gerät in Health: System + Mesh + Weg + Update-Stand
pub fn info(cfg: &Cfg, state: &Shared) -> Value {
    let (mesh, route, update) = {
        let st = state.lock().unwrap();
        (st.mesh.clone(), st.route, st.update.clone())
    };
    let mut v = metrics::info(mesh);
    v["route"] = json!(route);
    v["auto_update"] = json!(cfg.lock().unwrap().auto_update);
    v["update"] = update;
    v
}

pub async fn run(cfg: Cfg, state: Shared, wake: Arc<tokio::sync::Notify>) {
    let mut backoff = 2u64;
    let mut mesh_skip: Option<std::time::Instant> = None;
    // seit wann das Mesh im Modus „nur Mesh“ nicht geht (für den Notweg)
    let mut mesh_down: Option<std::time::Instant> = None;
    loop {
        let (paired, pending) = { (cfg.lock().unwrap().paired(), state.lock().unwrap().pair_code.clone()) };
        if !paired && pending.is_none() {
            state.lock().unwrap().connected = false;
            wake.notified().await; // warten, bis auf der lokalen Seite gekoppelt wird
            continue;
        }
        let c = cfg.lock().unwrap().clone();
        if !c.mesh_server.is_empty() {
            let m = ops::mesh_status().await;
            state.lock().unwrap().mesh = m;
        }
        let here = !c.mesh_server.is_empty() && mesh_here(&state.lock().unwrap().mesh);
        if c.mesh_only && here && state.lock().unwrap().mesh["status"] != "verbunden" {
            // nur Mesh, WARP aber getrennt: erst wieder verbinden
            ops::mesh_reconnect().await;
            let m = ops::mesh_status().await;
            state.lock().unwrap().mesh = m;
        }
        let mesh_ok = state.lock().unwrap().mesh["status"] == "verbunden";
        let strict = c.mesh_only && here;
        // „nur Mesh“: kein 5-Minuten-Ausweichen – das Mesh ist der Weg
        let mesh_up = mesh_ok && (strict || mesh_skip.is_none_or(|t| std::time::Instant::now() >= t));
        let pairing = state.lock().unwrap().pair_code.is_some();
        let emergency = strict && ((pairing && !mesh_ok) || mesh_down.is_some_and(|t| t.elapsed() >= MESH_EMERGENCY));
        let mut res = Err(End::Retry("keine Adresse".into()));
        let mut mesh_failed = false;
        for (route, url) in routes(&c, mesh_up, here, emergency) {
            let t = if route == Route::Mesh { 8 } else { 20 };
            if route == Route::Public && strict {
                eprintln!("ida-connect: Mesh geht nicht – Notweg über {url}");
            }
            res = session(&cfg, &state, &wake, route, &url, t, mesh_skip, strict).await;
            if route == Route::Mesh && !matches!(res, Err(End::Connect(_))) {
                mesh_down = None;
            }
            match &res {
                Err(End::Connect(_)) if route == Route::Mesh && strict => {
                    mesh_failed = true;
                }
                Err(End::Connect(e)) if route == Route::Mesh => {
                    // Mesh-Weg geht gerade nicht: 5 Minuten lang direkt die öffentliche Adresse nehmen
                    eprintln!("ida-connect: über das Mesh ({url}) nicht erreichbar: {e} – nehme {}", c.server);
                    mesh_skip = Some(std::time::Instant::now() + Duration::from_secs(300));
                }
                _ => break,
            }
        }
        if strict && (mesh_failed || !mesh_up) {
            mesh_down.get_or_insert_with(std::time::Instant::now);
            if !mesh_up {
                res = match res {
                    Err(End::Retry(e)) if e == "keine Adresse" => Err(End::Retry("WARP ist hier nicht verbunden (nur Mesh)".into())),
                    r => r,
                };
            }
        }
        let res = match res {
            Err(End::Connect(e)) => Err(End::Retry(e)),
            r => r,
        };
        match res {
            Ok(()) => {
                backoff = 2;
                continue; // neu koppeln/trennen: sofort weiter
            }
            Err(End::ToMesh) => {
                // mesh_skip bleibt: es ist ohnehin abgelaufen (die Probe wartet es ab). Klappt der Mesh-Weg wieder nicht,
                // gilt die neue Sperre – so springt die Verbindung nicht im Kreis.
                backoff = 2;
                continue;
            }
            Err(End::Connect(_)) => unreachable!(),
            Err(End::Unauthorized) => {
                let was_pairing = {
                    let mut st = state.lock().unwrap();
                    st.connected = false;
                    if st.pair_code.take().is_some() {
                        st.pair_result = Some(Err("Der Code ist ungültig oder abgelaufen.".into()));
                        true
                    } else {
                        st.last_error = "Health kennt dieses Gerät nicht (mehr) – auf der Seite neu koppeln.".into();
                        false
                    }
                };
                if !was_pairing {
                    let _ = tokio::time::timeout(Duration::from_secs(300), wake.notified()).await;
                }
                continue;
            }
            Err(End::Retry(e)) => {
                {
                    let mut st = state.lock().unwrap();
                    st.connected = false;
                    st.last_error = e.clone();
                    if st.pair_code.take().is_some() {
                        st.pair_result = Some(Err(format!("Health nicht erreichbar: {e}")));
                    }
                }
                eprintln!("ida-connect: Verbindung: {e}");
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(backoff), wake.notified()).await;
        backoff = (backoff * 2).min(60);
    }
}

#[allow(clippy::too_many_arguments)]
async fn session(
    cfg: &Cfg,
    state: &Shared,
    wake: &tokio::sync::Notify,
    route: Route,
    server: &str,
    connect_secs: u64,
    mesh_skip: Option<std::time::Instant>,
    strict: bool,
) -> Result<(), End> {
    let c = cfg.lock().unwrap().clone();
    let pair = state.lock().unwrap().pair_code.clone();
    let mut req = ws_url(server).into_client_request().map_err(|e| End::Connect(e.to_string()))?;
    let auth = match &pair {
        Some(code) => format!("Pair {code}"),
        None => format!("Bearer {}:{}", c.device_id, c.secret),
    };
    let h = req.headers_mut();
    h.insert("authorization", HeaderValue::from_str(&auth).map_err(|_| End::Connect("ungültige Zugangsdaten".into()))?);
    h.insert("user-agent", HeaderValue::from_static(concat!("ida-connect/", env!("CARGO_PKG_VERSION"))));
    if route == Route::Public
        && !c.cf_client_id.is_empty()
        && let (Ok(a), Ok(b)) = (HeaderValue::from_str(&c.cf_client_id), HeaderValue::from_str(&c.cf_client_secret)) {
            h.insert("cf-access-client-id", a);
            h.insert("cf-access-client-secret", b);
        }
    let (ws, _) = match tokio::time::timeout(Duration::from_secs(connect_secs), tokio_tungstenite::connect_async(req)).await {
        Err(_) => return Err(End::Connect("Zeitüberschreitung".into())),
        Ok(Err(tokio_tungstenite::tungstenite::Error::Http(r))) if matches!(r.status().as_u16(), 301 | 302 | 401 | 403) => {
            // Health selbst lehnt nur per Close-Code 4401 ab; ein HTTP-Nein kommt von Cloudflare Access davor
            return Err(End::Connect(format!(
                "Cloudflare Access blockiert den Agent-Pfad ({}): Bypass für /api/v1/agent oder Service-Token nötig",
                r.status()
            )));
        }
        Ok(Err(tokio_tungstenite::tungstenite::Error::Http(r))) => return Err(End::Connect(format!("Health antwortet {}", r.status()))),
        Ok(Err(e)) => return Err(End::Connect(e.to_string())),
        Ok(Ok(x)) => x,
    };
    let (mut sink, mut stream) = ws.split();

    // Koppeln: erste Nachricht enthält id + secret
    if pair.is_some() {
        let first = tokio::time::timeout(Duration::from_secs(20), stream.next()).await.map_err(|_| End::Retry("keine Antwort beim Koppeln".into()))?;
        let v: Value = match first {
            Some(Ok(Message::Text(t))) => serde_json::from_str(&t).unwrap_or_default(),
            Some(Ok(Message::Close(Some(f)))) if u16::from(f.code) == 4401 => return Err(End::Unauthorized),
            _ => return Err(End::Retry("unerwartete Antwort beim Koppeln".into())),
        };
        if v["t"] != "paired" {
            return Err(End::Unauthorized);
        }
        let name = {
            let mut cc = cfg.lock().unwrap();
            cc.device_id = v["id"].as_str().unwrap_or("").to_string();
            cc.secret = v["secret"].as_str().unwrap_or("").to_string();
            if let Some(n) = v["name"].as_str() {
                cc.name = n.to_string();
            }
            let _ = cc.save();
            cc.name.clone()
        };
        let mut st = state.lock().unwrap();
        st.pair_code = None;
        st.pair_result = Some(Ok(name));
    }

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let mesh = ops::mesh_status().await;
    {
        let mut st = state.lock().unwrap();
        st.mesh = mesh;
        st.connected = true;
        st.route = route.name();
        st.last_error.clear();
    }
    let _ = tx.send(json!({"t": "hello", "v": 1, "agent": env!("CARGO_PKG_VERSION"), "info": info(cfg, state)}).to_string());

    let ptys = pty::Ptys::default();
    let interval = Arc::new(std::sync::atomic::AtomicU64::new(10));

    // Messwerte
    let mtx = tx.clone();
    let iv = interval.clone();
    let st2 = state.clone();
    let cfg2 = cfg.clone();
    let meter = tokio::spawn(async move {
        let mut s = metrics::Sampler::new();
        let mut since_info = 0u64;
        loop {
            let secs = iv.load(std::sync::atomic::Ordering::Relaxed).clamp(1, 300);
            tokio::time::sleep(Duration::from_secs(secs)).await;
            if mtx.send(s.sample().to_string()).is_err() {
                break;
            }
            since_info += secs;
            if since_info >= 600 {
                since_info = 0;
                let mesh = ops::mesh_status().await;
                st2.lock().unwrap().mesh = mesh;
                let _ = mtx.send(json!({"t": "info", "info": info(&cfg2, &st2)}).to_string());
            }
        }
    });

    let writer = tokio::spawn(async move {
        let mut ping = tokio::time::interval(Duration::from_secs(30));
        ping.tick().await;
        loop {
            tokio::select! {
                m = rx.recv() => match m {
                    Some(t) => if sink.send(Message::Text(t.into())).await.is_err() { break },
                    None => break,
                },
                _ = ping.tick() => if sink.send(Message::Ping(Vec::new().into())).await.is_err() { break },
            }
        }
        let _ = sink.close().await;
    });

    let mut result = Ok(());
    let mut woke = false;
    // Über die öffentliche Adresse verbunden, Health hat aber eine Mesh-Adresse: ab und zu prüfen, ob das Mesh geht
    // Erste Probe frühestens nach 30 s und erst, wenn eine Sperre nach einem gescheiterten Mesh-Versuch abgelaufen ist
    // Notweg bei „nur Mesh“: jede Minute schauen, ob das Mesh wieder geht
    let first = if strict { tokio::time::Instant::now() + Duration::from_secs(60) } else {
        probe_start(tokio::time::Instant::now(), mesh_skip.map(tokio::time::Instant::from_std))
    };
    let mut probe = tokio::time::interval_at(first, Duration::from_secs(if strict { 60 } else { 300 }));
    loop {
        let next = tokio::select! {
            n = tokio::time::timeout(Duration::from_secs(120), stream.next()) => n,
            _ = wake.notified() => {
                woke = true; // lokale Seite: neu koppeln oder trennen
                break;
            }
            _ = probe.tick(), if route == Route::Public => {
                let ms = cfg.lock().unwrap().mesh_server.clone();
                if ms.is_empty() {
                    continue;
                }
                let mut m = ops::mesh_status().await;
                if strict && m["status"] != "verbunden" {
                    ops::mesh_reconnect().await;
                    m = ops::mesh_status().await;
                }
                let up = m["status"] == "verbunden";
                state.lock().unwrap().mesh = m;
                if up && reachable(&ms).await {
                    eprintln!("ida-connect: Mesh erreichbar – verbinde über {ms}");
                    result = Err(End::ToMesh);
                    break;
                }
                continue;
            }
        };
        let msg = match next {
            Err(_) => {
                result = Err(End::Retry("Verbindung eingeschlafen".into()));
                break;
            }
            Ok(None) => break,
            Ok(Some(Err(e))) => {
                result = Err(End::Retry(e.to_string()));
                break;
            }
            Ok(Some(Ok(m))) => m,
        };
        let text = match msg {
            Message::Text(t) => t.to_string(),
            Message::Close(f) => {
                if f.as_ref().map(|f: &CloseFrame| u16::from(f.code)) == Some(4401) {
                    result = Err(End::Unauthorized);
                }
                break;
            }
            _ => continue,
        };
        let v: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let sid = v["sid"].as_str().unwrap_or("").to_string();
        let dim = |k: &str, d: u64| v[k].as_u64().unwrap_or(d) as u16;
        match v["t"].as_str().unwrap_or("") {
            "config" => {
                if let Some(i) = v["interval"].as_u64() {
                    interval.store(i.clamp(1, 300), std::sync::atomic::Ordering::Relaxed);
                }
                // Mesh-Adresse von Health (leer = Health ist nicht im Mesh). Fehlt das Feld, bleibt alles, wie es ist.
                if let Some(on) = v["mesh_only"].as_bool() {
                    let mut c = cfg.lock().unwrap();
                    if c.mesh_only != on {
                        c.mesh_only = on;
                        let _ = c.save();
                        if on && route == Route::Public {
                            // ab jetzt nur Mesh: bald umziehen
                            probe.reset_at(tokio::time::Instant::now() + Duration::from_secs(5));
                        }
                    }
                }
                if let Some(ms) = v["mesh_server"].as_str() {
                    let ms = ms.trim().trim_end_matches('/');
                    let ms = if ms.is_empty() || ms.starts_with("http://") || ms.starts_with("https://") { ms } else { "" };
                    let mut c = cfg.lock().unwrap();
                    if c.mesh_server != ms {
                        c.mesh_server = ms.to_string();
                        let _ = c.save();
                        if !ms.is_empty() && route == Route::Public {
                            // neue Mesh-Adresse: in 5 s probieren, aber nicht vor Ablauf der Sperre
                            let soon = tokio::time::Instant::now() + Duration::from_secs(5);
                            probe.reset_at(mesh_skip.map(tokio::time::Instant::from_std).map_or(soon, |s| s.max(soon)));
                        }
                    }
                }
            }
            "ping" => {
                let _ = tx.send(json!({"t": "pong"}).to_string());
            }
            "req" => {
                let tx = tx.clone();
                let st = state.clone();
                let cf = cfg.clone();
                tokio::spawn(async move {
                    let id = v["id"].clone();
                    let op = v["op"].as_str().unwrap_or("").to_string();
                    let out = match op.as_str() {
                        "set_auto_update" => {
                            let on = v["on"].as_bool().unwrap_or(true);
                            let mut c = cf.lock().unwrap();
                            c.auto_update = on;
                            c.save().map(|_| json!({"auto_update": on})).map_err(|e| e.to_string())
                        }
                        _ => ops::handle(&op, &v).await,
                    };
                    if op == "update_check"
                        && let Ok(u) = &out {
                            st.lock().unwrap().update = u.clone();
                        }
                    if op == "mesh_setup" || op == "mesh_status" {
                        let mesh = ops::mesh_status().await;
                        st.lock().unwrap().mesh = mesh;
                    }
                    if matches!(op.as_str(), "mesh_setup" | "mesh_status" | "update_check" | "set_auto_update") {
                        let _ = tx.send(json!({"t": "info", "info": info(&cf, &st)}).to_string());
                    }
                    let r = match out {
                        Ok(d) => json!({"t": "res", "id": id, "ok": true, "data": d}),
                        Err(e) => json!({"t": "res", "id": id, "ok": false, "error": e}),
                    };
                    let _ = tx.send(r.to_string());
                });
            }
            "pty_open" => {
                if let Err(e) = ptys.open(&sid, dim("cols", 120), dim("rows", 32), tx.clone()) {
                    let _ = tx.send(json!({"t": "pty_exit", "sid": sid, "code": -1, "error": e}).to_string());
                }
            }
            "pty_in" => ptys.input(&sid, v["d"].as_str().unwrap_or("")),
            "pty_resize" => ptys.resize(&sid, dim("cols", 120), dim("rows", 32)),
            "pty_close" => ptys.close(&sid),
            _ => {}
        }
    }
    ptys.close_all();
    meter.abort();
    writer.abort();
    state.lock().unwrap().connected = false;
    if result.is_ok() && !woke {
        // sauber getrennt (z. B. Health neu gestartet) -> kurz warten, dann neu
        return Err(End::Retry("Verbindung beendet".into()));
    }
    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn route_order() {
        use super::Route::{Mesh, Public};
        let mut c = crate::config::Config { server: "https://health.example".into(), ..Default::default() };
        // keine Mesh-Adresse: nur öffentlich (auch mit mesh_only)
        assert_eq!(super::routes(&c, true, true, false), vec![(Public, "https://health.example".to_string())]);
        c.mesh_server = "http://100.96.0.5:8000".into();
        // Mesh-Adresse, aber WARP hier nicht verbunden: nur öffentlich
        assert_eq!(super::routes(&c, false, true, false).len(), 1);
        // beides: Mesh zuerst, öffentlich als Rückfall
        let r = super::routes(&c, true, true, false);
        assert_eq!(r[0], (Mesh, "http://100.96.0.5:8000".to_string()));
        assert_eq!(r[1].0, Public);
        // nur Mesh: kein Rückfall, auch wenn WARP gerade getrennt ist
        c.mesh_only = true;
        assert_eq!(super::routes(&c, true, true, false), vec![(Mesh, "http://100.96.0.5:8000".to_string())]);
        assert_eq!(super::routes(&c, false, true, false), vec![(Mesh, "http://100.96.0.5:8000".to_string())]);
        // nur Mesh, aber Notweg: öffentlich dahinter
        assert_eq!(super::routes(&c, true, true, true).iter().map(|x| x.0).collect::<Vec<_>>(), vec![Mesh, Public]);
        // nur Mesh, aber hier kein WARP (32-Bit, noch nicht eingerichtet): öffentlich
        assert_eq!(super::routes(&c, false, false, false).iter().map(|x| x.0).collect::<Vec<_>>(), vec![Public]);
    }

    #[test]
    fn mesh_here() {
        use serde_json::json;
        assert!(super::mesh_here(&json!({"status": "getrennt", "supported": true})));
        assert!(super::mesh_here(&json!({"status": "verbunden", "supported": true})));
        assert!(!super::mesh_here(&json!({"status": "nicht eingerichtet", "supported": true})));
        assert!(!super::mesh_here(&json!({"status": "getrennt", "supported": false})));
        assert!(!super::mesh_here(&serde_json::Value::Null));
    }

    #[test]
    fn probe_waits_for_skip() {
        let now = tokio::time::Instant::now();
        assert_eq!(super::probe_start(now, None), now + std::time::Duration::from_secs(30));
        let later = now + std::time::Duration::from_secs(300);
        assert_eq!(super::probe_start(now, Some(later)), later);
        assert_eq!(super::probe_start(now, Some(now)), now + std::time::Duration::from_secs(30));
    }

    #[test]
    fn host_ports() {
        assert_eq!(super::host_port("http://100.96.0.5:8000").as_deref(), Some("100.96.0.5:8000"));
        assert_eq!(super::host_port("https://health.example/x").as_deref(), Some("health.example:443"));
        assert_eq!(super::host_port("http://h").as_deref(), Some("h:80"));
        assert_eq!(super::host_port("kaputt"), None);
    }

    #[test]
    fn urls() {
        assert_eq!(super::ws_url("https://health.example.com/"), "wss://health.example.com/api/v1/agent/ws");
        assert_eq!(super::ws_url("http://10.0.0.2:8096"), "ws://10.0.0.2:8096/api/v1/agent/ws");
    }
}

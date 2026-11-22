//! Lokale Seite (Standard Port 1111): Status, Koppeln mit IDA Health, Cloudflare Mesh. Geschützt mit der PIN aus der Installation.
//! Bewusst ohne Shell und Dateien – das gibt es nur über Health (hinter Cloudflare Zero Trust).
//! Ein winziger HTTP/1.1-Server ohne Bibliothek: wenige Routen, kleine Formulare.
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::random_hex;
use crate::link::{Cfg, Shared};
use crate::{metrics, ops, update};

#[derive(Default)]
struct Web {
    sessions: HashMap<String, Instant>,
    pair_states: HashMap<String, Instant>,
    fails: Vec<Instant>,
    mesh_job: Option<String>,
}

const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);

struct Req {
    method: String,
    path: String,
    query: HashMap<String, String>,
    form: HashMap<String, String>,
    cookie: Option<String>,
    host: String,
}

pub async fn serve(addr: String, cfg: Cfg, state: Shared, wake: Arc<tokio::sync::Notify>) {
    let l = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ida-connect: lokale Seite auf {addr} startet nicht: {e}");
            return;
        }
    };
    eprintln!("ida-connect: lokale Seite auf http://{addr}");
    let web = Arc::new(Mutex::new(Web::default()));
    loop {
        let Ok((s, _)) = l.accept().await else { continue };
        let (cfg, state, wake, web) = (cfg.clone(), state.clone(), wake.clone(), web.clone());
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(60), conn(s, cfg, state, wake, web)).await;
        });
    }
}

fn urldecode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    out.push(v);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

pub fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|c| if c.is_ascii_alphanumeric() || b"-_.~".contains(&c) { (c as char).to_string() } else { format!("%{c:02X}") })
        .collect()
}

fn parse_qs(s: &str) -> HashMap<String, String> {
    s.split('&').filter(|x| !x.is_empty()).map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (urldecode(k), urldecode(v))
    }).collect()
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

async fn read_req(s: &mut TcpStream) -> Option<Req> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        if buf.len() > 16384 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let first = lines.next()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut headers = HashMap::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0).min(65536);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        let n = s.read(&mut tmp).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    let (path, q) = target.split_once('?').unwrap_or((&target, ""));
    let cookie = headers.get("cookie").and_then(|c| c.split(';').find_map(|p| p.trim().strip_prefix("idac=").map(|v| v.to_string())));
    Some(Req {
        method,
        path: path.to_string(),
        query: parse_qs(q),
        form: if len > 0 { parse_qs(&String::from_utf8_lossy(&body[..len.min(body.len())])) } else { HashMap::new() },
        cookie,
        host: headers.get("host").cloned().unwrap_or_default(),
    })
}

async fn respond(s: &mut TcpStream, status: &str, ctype: &str, extra: &str, body: &str) {
    let r = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https: http:\r\nConnection: close\r\n{extra}\r\n{body}",
        body.len()
    );
    let _ = s.write_all(r.as_bytes()).await;
}

async fn redirect(s: &mut TcpStream, to: &str, extra: &str) {
    respond(s, "303 See Other", "text/plain", &format!("Location: {to}\r\n{extra}"), "").await;
}

fn back(msg: &str) -> String {
    format!("/?msg={}", urlencode(msg))
}

async fn conn(mut s: TcpStream, cfg: Cfg, state: Shared, wake: Arc<tokio::sync::Notify>, web: Arc<Mutex<Web>>) {
    let Some(r) = read_req(&mut s).await else { return };
    let authed = {
        let mut w = web.lock().unwrap();
        w.sessions.retain(|_, t| t.elapsed() < SESSION_TTL);
        w.pair_states.retain(|_, t| t.elapsed() < Duration::from_secs(600));
        r.cookie.as_ref().is_some_and(|c| w.sessions.contains_key(c))
    };
    match (r.method.as_str(), r.path.as_str()) {
        ("GET", "/") => {
            let html = page(&cfg, &state, &web, authed, r.query.get("msg").map(|s| s.as_str()).unwrap_or(""));
            respond(&mut s, "200 OK", "text/html; charset=utf-8", "", &html).await;
        }
        ("GET", "/api/status") => {
            let c = cfg.lock().unwrap().clone();
            let v = {
                let st = state.lock().unwrap();
                json!({"paired": c.paired(), "connected": st.connected, "name": c.name, "server": c.server, "mesh": st.mesh, "route": st.route,
                       "mesh_server": c.mesh_server, "agent": env!("CARGO_PKG_VERSION"), "auto_update": c.auto_update, "update": st.update})
            };
            respond(&mut s, "200 OK", "application/json", "", &v.to_string()).await;
        }
        ("POST", "/login") => {
            let pin = r.form.get("pin").cloned().unwrap_or_default();
            let cur_pin = cfg.lock().unwrap().pin.clone();
            let ok = {
                let mut w = web.lock().unwrap();
                w.fails.retain(|t| t.elapsed() < Duration::from_secs(300));
                if w.fails.len() >= 5 {
                    None
                } else if !pin.is_empty() && ct_eq(pin.trim(), &cur_pin) {
                    let sid = random_hex(24);
                    w.sessions.insert(sid.clone(), Instant::now());
                    Some(sid)
                } else {
                    w.fails.push(Instant::now());
                    Some(String::new())
                }
            };
            match ok {
                None => redirect(&mut s, &back("Zu viele falsche Versuche – 5 Minuten warten."), "").await,
                Some(sid) if sid.is_empty() => redirect(&mut s, &back("PIN falsch."), "").await,
                Some(sid) => redirect(&mut s, "/", &format!("Set-Cookie: idac={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200\r\n")).await,
            }
        }
        ("POST", "/logout") => {
            if let Some(c) = &r.cookie {
                web.lock().unwrap().sessions.remove(c);
            }
            redirect(&mut s, "/", "Set-Cookie: idac=; Max-Age=0; Path=/\r\n").await;
        }
        // Koppeln über den Browser: weiter zu Health (dort Cloudflare-Anmeldung), zurück kommt ein Einmal-Code
        ("POST", "/pair/start") if authed => {
            let server = r.form.get("server").map(|x| x.trim().trim_end_matches('/').to_string()).unwrap_or_default();
            if !(server.starts_with("https://") || server.starts_with("http://")) {
                return redirect(&mut s, &back("Adresse muss mit https:// beginnen."), "").await;
            }
            let name = r.form.get("name").cloned().unwrap_or_default();
            {
                let mut c = cfg.lock().unwrap();
                c.server = server.clone();
                if !name.trim().is_empty() {
                    c.name = name.trim().chars().take(60).collect();
                }
                let _ = c.save();
            }
            let st = random_hex(16);
            web.lock().unwrap().pair_states.insert(st.clone(), Instant::now());
            let host = if r.host.is_empty() { "localhost:1111".to_string() } else { r.host.clone() };
            let cb = format!("http://{host}/pair/done");
            let hn = metrics::info(Value::Null)["hostname"].as_str().unwrap_or("").to_string();
            let to = format!("{server}/pair?name={}&host={}&cb={}&state={}", urlencode(name.trim()), urlencode(&hn), urlencode(&cb), st);
            redirect(&mut s, &to, "").await;
        }
        ("GET", "/pair/done") => {
            let st = r.query.get("state").cloned().unwrap_or_default();
            let valid = web.lock().unwrap().pair_states.remove(&st).is_some();
            if !valid {
                return redirect(&mut s, &back("Koppeln abgelaufen – bitte neu starten."), "").await;
            }
            if r.query.contains_key("error") {
                return redirect(&mut s, &back("Koppeln abgebrochen."), "").await;
            }
            let code = r.query.get("code").cloned().unwrap_or_default();
            let msg = do_pair(&cfg, &state, &wake, &code).await;
            redirect(&mut s, &back(&msg), "").await;
        }
        ("POST", "/pair/code") if authed => {
            if let Some(server) = r.form.get("server").map(|x| x.trim().trim_end_matches('/').to_string()).filter(|x| x.starts_with("http")) {
                let c = {
                    let mut c = cfg.lock().unwrap();
                    c.server = server;
                    c.clone()
                };
                let _ = c.save();
            }
            let code = r.form.get("code").cloned().unwrap_or_default();
            let msg = do_pair(&cfg, &state, &wake, &code).await;
            redirect(&mut s, &back(&msg), "").await;
        }
        ("POST", "/unpair") if authed => {
            {
                let mut c = cfg.lock().unwrap();
                c.device_id.clear();
                c.secret.clear();
                let _ = c.save();
            }
            wake.notify_one();
            redirect(&mut s, &back("Getrennt. Das Gerät schickt nichts mehr an Health."), "").await;
        }
        ("POST", "/mesh") if authed => {
            let token = r.form.get("token").cloned().unwrap_or_default();
            let busy = {
                let mut w = web.lock().unwrap();
                let busy = w.mesh_job.as_deref() == Some("läuft");
                if !busy {
                    w.mesh_job = Some("läuft".into());
                }
                busy
            };
            if busy {
                return redirect(&mut s, &back("Mesh wird gerade eingerichtet …"), "").await;
            }
            let (web2, state2) = (web.clone(), state.clone());
            tokio::spawn(async move {
                let out = ops::handle("mesh_setup", &json!({"token": token})).await;
                let mesh = ops::mesh_status().await;
                state2.lock().unwrap().mesh = mesh;
                web2.lock().unwrap().mesh_job = Some(match out {
                    Ok(v) => format!("Fertig.\n{}", v["output"].as_str().unwrap_or("")),
                    Err(e) => e,
                });
            });
            redirect(&mut s, &back("Mesh wird eingerichtet – das dauert ein bis zwei Minuten. Seite neu laden."), "").await;
        }
        ("POST", "/update/check") if authed => {
            let v = update::check().await;
            state.lock().unwrap().update = v.clone();
            let msg = if !v["error"].as_str().unwrap_or("").is_empty() {
                format!("Nachsehen ging nicht: {}", v["error"].as_str().unwrap_or(""))
            } else if v["available"] == true {
                format!("Neue Version {} ist da.", v["latest"].as_str().unwrap_or("?"))
            } else {
                "ida-connect ist aktuell.".into()
            };
            redirect(&mut s, &back(&msg), "").await;
        }
        ("POST", "/update/install") if authed => {
            let msg = match update::install().await {
                Ok(_) => "Update läuft. Der Dienst startet gleich neu – Seite in etwa einer Minute neu laden. Kopplung und Einstellungen bleiben.".to_string(),
                Err(e) => e,
            };
            redirect(&mut s, &back(&msg), "").await;
        }
        ("POST", "/update/auto") if authed => {
            let on = r.form.get("on").is_some_and(|v| v == "1");
            {
                let mut c = cfg.lock().unwrap();
                c.auto_update = on;
                let _ = c.save();
            }
            redirect(&mut s, &back(if on { "Auto-Update ist an." } else { "Auto-Update ist aus." }), "").await;
        }
        ("POST", _) => redirect(&mut s, &back("Bitte zuerst mit der PIN anmelden."), "").await,
        _ => respond(&mut s, "404 Not Found", "text/plain", "", "nicht gefunden").await,
    }
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn do_pair(cfg: &Cfg, state: &Shared, wake: &Arc<tokio::sync::Notify>, code: &str) -> String {
    let code = code.trim().to_string();
    if code.is_empty() || code.len() > 128 || !code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return "Code fehlt oder ist ungültig.".into();
    }
    {
        let mut c = cfg.lock().unwrap();
        c.device_id.clear();
        c.secret.clear();
        let _ = c.save();
        let mut st = state.lock().unwrap();
        st.pair_code = Some(code);
        st.pair_result = None;
    }
    wake.notify_one();
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Some(r) = state.lock().unwrap().pair_result.take() {
            return match r {
                Ok(name) => format!("Verbunden als „{name}“. Das Gerät erscheint jetzt in IDA Health."),
                Err(e) => e,
            };
        }
    }
    "Keine Antwort von Health – siehe Status unten.".into()
}

fn page(cfg: &Cfg, state: &Shared, web: &Arc<Mutex<Web>>, authed: bool, msg: &str) -> String {
    let c = cfg.lock().unwrap().clone();
    let (connected, err, mesh, route, upd) = {
        let st = state.lock().unwrap();
        (st.connected, st.last_error.clone(), st.mesh.clone(), st.route, st.update.clone())
    };
    let info = metrics::info(Value::Null);
    let hostname = info["hostname"].as_str().unwrap_or("").to_string();
    let mut b = String::new();
    if !msg.is_empty() {
        b += &format!("<div class=msg>{}</div>", esc(msg));
    }
    let dot = |ok: bool| if ok { "<i class='d ok'></i>" } else { "<i class='d'></i>" };
    b += &format!(
        "<section><h2>Gerät</h2><dl><dt>Name</dt><dd>{}</dd><dt>System</dt><dd>{} · {}</dd><dt>Agent</dt><dd>ida-connect {} ({})</dd></dl></section>",
        esc(if c.name.is_empty() { &hostname } else { &c.name }),
        esc(info["os"].as_str().unwrap_or("")),
        esc(info["arch"].as_str().unwrap_or("")),
        env!("CARGO_PKG_VERSION"),
        esc(info["mode"].as_str().unwrap_or(""))
    );
    let health = if c.paired() {
        format!(
            "{} {}<br><small>{}</small>{}",
            dot(connected),
            if !connected {
                "Gekoppelt, gerade nicht verbunden"
            } else if route == "mesh" {
                "Mit IDA Health verbunden – über Cloudflare Mesh"
            } else {
                "Mit IDA Health verbunden"
            },
            esc(if connected && route == "mesh" { &c.mesh_server } else { &c.server }),
            if err.is_empty() || connected { String::new() } else { format!("<p class=err>{}</p>", esc(&err)) }
        )
    } else {
        format!("{} Noch nicht gekoppelt", dot(false))
    };
    let mesh_txt = format!(
        "{} {}{}",
        dot(mesh["status"] == "verbunden"),
        esc(mesh["status"].as_str().unwrap_or("unbekannt")),
        mesh["ip"].as_str().filter(|x| !x.is_empty()).map(|ip| format!(" · <b>{}</b>", esc(ip))).unwrap_or_default()
    );
    b += &format!("<section><h2>IDA Health</h2><p>{health}</p></section><section><h2>Cloudflare Mesh</h2><p>{mesh_txt}</p>");
    if mesh["supported"] == false {
        b += "<p class=hint>Dieses Gerät ist 32-Bit: Cloudflare Mesh gibt es nur für 64-Bit. Messwerte, Shell und Dateien gehen trotzdem.</p>";
    }
    if !c.mesh_server.is_empty() && route != "mesh" {
        b += &format!("<p class=hint style='margin-top:8px'>Health ist im Mesh unter {}. Sobald WARP hier verbunden ist, läuft alles darüber.</p>", esc(&c.mesh_server));
    }
    if c.mesh_only && !c.mesh_server.is_empty() {
        b += "<p class=hint style='margin-top:8px'>Health spricht nur über das Mesh mit diesem Gerät. Geht das Mesh 15 Minuten lang nicht, \
              nimmt ida-connect als Notweg die öffentliche Adresse.</p>";
    }
    b += "</section>";

    // Updates
    let latest = upd["latest"].as_str().unwrap_or("");
    let upd_line = if upd["available"] == true {
        format!("<p><b>Neue Version {}</b> ist da (installiert: {}).</p>", esc(latest), update::CURRENT)
    } else if !latest.is_empty() {
        format!("<p>{} Aktuell ({})</p>", dot(true), update::CURRENT)
    } else {
        format!("<p>Installiert: {}</p>", update::CURRENT)
    };
    b += &format!("<section><h2>Updates</h2>{upd_line}<p class=hint style='margin-top:6px'>Auto-Update {} · Im Terminal: <code>sudo ida-connect update</code></p>", if c.auto_update { "an (alle 6 Stunden)" } else { "aus" });
    if authed {
        b += "<form method=post action=/update/check style='margin-top:10px'><button>Nach Updates suchen</button></form>";
        if upd["available"] == true {
            b += "<form method=post action=/update/install style='margin-top:8px'><button class=primary>Jetzt installieren</button></form>";
        }
        b += &format!(
            "<form method=post action=/update/auto style='margin-top:8px'><input type=hidden name=on value={}><button class=link>Auto-Update {}</button></form>",
            if c.auto_update { "0" } else { "1" },
            if c.auto_update { "ausschalten" } else { "einschalten" }
        );
    }
    b += "</section>";

    if !authed {
        b += "<section><h2>Anmelden</h2><p class=hint>Die PIN steht am Ende der Installation (oder: <code>sudo ida-connect pin</code>).</p>\
              <form method=post action=/login><input name=pin inputmode=numeric autocomplete=off placeholder=PIN autofocus><button>Anmelden</button></form></section>";
    } else {
        b += &format!(
            "<section><h2>{}</h2><p class=hint>Öffnet IDA Health. Dort meldest du dich über Cloudflare an und bestätigst das Gerät – danach geht es von selbst hierher zurück.</p>\
             <form method=post action=/pair/start><label>Health-Adresse<input name=server placeholder=https://health.example.com required value=\"{}\"></label><label>Name des Geräts<input name=name value=\"{}\"></label><button class=primary>Mit IDA verbinden</button></form>\
             <details><summary>Oder Code aus IDA Health eingeben</summary><form method=post action=/pair/code><input type=hidden name=server value=\"{}\"><input name=code placeholder=Code autocomplete=off><button>Koppeln</button></form></details></section>",
            if c.paired() { "Neu koppeln" } else { "Koppeln" },
            esc(&c.server),
            esc(if c.name.is_empty() { &hostname } else { &c.name }),
            esc(&c.server)
        );
        if mesh["supported"] != false {
            let job = web.lock().unwrap().mesh_job.clone().unwrap_or_default();
            b += &format!(
                "<section><h2>Mesh einrichten</h2><p class=hint>Normalerweise macht das IDA Health beim Koppeln. Von Hand: in Cloudflare unter Networking → Mesh einen Knoten anlegen und den Token hier einfügen.</p>\
                 <form method=post action=/mesh><input name=token placeholder=Mesh-Token autocomplete=off><button>Einrichten</button></form>{}</section>",
                if job.is_empty() { String::new() } else { format!("<pre>{}</pre>", esc(&job)) }
            );
        }
        if c.paired() {
            b += "<section><form method=post action=/unpair onsubmit=\"return confirm('Wirklich trennen?')\"><button class=danger>Von Health trennen</button></form></section>";
        }
        b += "<form method=post action=/logout class=out><button class=link>Abmelden</button></form>";
    }
    format!("<!doctype html><html lang=de><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><meta name=color-scheme content=dark><title>ida-connect · {}</title><style>{CSS}</style></head><body><main><h1>ida-connect</h1>{b}</main></body></html>", esc(&hostname))
}

const CSS: &str = r#"
:root{--accent:#7fd3ff;--on-accent:#00344a;--surface:#121316;--high:#1d1f23;--highest:#282a2f;--on:#e3e2e6;--muted:#9a9ca3}
*{box-sizing:border-box}body{margin:0;background:#000;color:var(--on);font:15px/1.5 "Google Sans Flex","Google Sans",Roboto,system-ui,sans-serif}
main{max-width:560px;margin:0 auto;padding:28px 16px 60px}h1{font-weight:500;font-size:26px;margin:0 0 18px;letter-spacing:-.3px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);font-weight:500;margin:0 0 8px}
section{background:var(--surface);border-radius:24px;padding:18px 20px;margin:0 0 12px}p{margin:0}
dl{display:grid;grid-template-columns:auto 1fr;gap:4px 16px;margin:0}dt{color:var(--muted)}dd{margin:0}
.hint{color:var(--muted);font-size:13px;margin:0 0 12px}.err{color:#f28b82;font-size:13px;margin-top:6px}
.msg{background:#0e2a38;color:#c4ecff;border-radius:18px;padding:12px 16px;margin:0 0 12px;white-space:pre-wrap}
form{display:flex;flex-wrap:wrap;gap:8px;margin:0}label{display:flex;flex-direction:column;gap:4px;width:100%;color:var(--muted);font-size:13px}
input{flex:1;min-width:0;background:var(--highest);border:0;border-radius:14px;padding:12px 14px;color:var(--on);font:inherit;outline:none}
input:focus{box-shadow:0 0 0 2px var(--accent)}
button{background:var(--highest);color:var(--on);border:0;border-radius:999px;padding:11px 20px;font:inherit;font-weight:500;cursor:pointer}
button.primary{background:var(--accent);color:var(--on-accent);width:100%}button.danger{background:#513534;color:#f6aea9}
button.link{background:none;color:var(--muted)}.out{justify-content:center}
.d{display:inline-block;width:9px;height:9px;border-radius:50%;background:#5f6368;margin-right:4px}.d.ok{background:#81c995;box-shadow:0 0 8px #81c995}
details{margin-top:12px}summary{color:var(--muted);cursor:pointer;margin-bottom:8px;font-size:13px}
pre{white-space:pre-wrap;background:var(--high);border-radius:14px;padding:10px;font-size:12px;max-height:240px;overflow:auto}
code{background:var(--highest);padding:1px 6px;border-radius:6px}small{color:var(--muted)}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decode() {
        assert_eq!(urldecode("a+b%20c%C3%A4"), "a b cä");
        assert_eq!(urldecode("100%"), "100%");
        assert_eq!(urlencode("http://x:1/a b"), "http%3A%2F%2Fx%3A1%2Fa%20b");
        assert!(ct_eq("123", "123") && !ct_eq("123", "124") && !ct_eq("1", "12"));
    }
}

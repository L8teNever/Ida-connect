//! Operationen, die Health anfordern kann (req.op): Befehle, Dateien, Mesh, Update.
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::time::Duration;
use tokio::io::AsyncReadExt;

use crate::host;

pub const INSTALL_URL: &str = "https://raw.githubusercontent.com/L8teNever/Ida-connect/main/install.sh";
const OUT_MAX: usize = 256 * 1024;
const READ_MAX: u64 = 4 * 1024 * 1024;

pub async fn handle(op: &str, r: &Value) -> Result<Value, String> {
    let s = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    match op {
        "exec" => {
            let t = r.get("timeout").and_then(|v| v.as_u64()).unwrap_or(60).clamp(1, 3600);
            exec(&s("cmd"), &s("user"), t).await
        }
        "fs_list" => fs_list(&s("path")),
        "fs_read" => fs_read(&s("path"), r.get("offset").and_then(|v| v.as_u64()).unwrap_or(0), r.get("len").and_then(|v| v.as_u64()).unwrap_or(READ_MAX)),
        "fs_write" => fs_write(&s("path"), &s("d"), r.get("append").and_then(|v| v.as_bool()).unwrap_or(false), r.get("mkdirs").and_then(|v| v.as_bool()).unwrap_or(true)),
        "fs_delete" => fs_delete(&s("path"), r.get("recursive").and_then(|v| v.as_bool()).unwrap_or(false)),
        "fs_mkdir" => std::fs::create_dir_all(host::get().path(&s("path"))?).map(|_| json!({})).map_err(|e| e.to_string()),
        "fs_rename" => std::fs::rename(host::get().path(&s("from"))?, host::get().path(&s("to"))?).map(|_| json!({})).map_err(|e| e.to_string()),
        "mesh_setup" => mesh_setup(&s("token")).await,
        "mesh_status" => Ok(mesh_status().await),
        "update" => crate::update::install().await,
        "update_check" => Ok(crate::update::check().await),
        "info" => Ok(crate::metrics::info(mesh_status().await)),
        _ => Err(format!("unbekannte Operation {op}")),
    }
}

fn cut(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(&b[..b.len().min(OUT_MAX)]).to_string();
    if b.len() > OUT_MAX { s + "\n… (gekürzt)" } else { s }
}

/// sh -c auf dem Gerät, mit Zeitlimit. user = optional anderer Benutzer.
pub async fn exec(cmd: &str, user: &str, timeout: u64) -> Result<Value, String> {
    if cmd.trim().is_empty() {
        return Err("cmd fehlt".into());
    }
    let h = host::get();
    let mut c = if user.is_empty() || user == "root" {
        h.command(&["sh", "-c", cmd])
    } else {
        if !user.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) {
            return Err("ungültiger Benutzer".into());
        }
        h.command(&["runuser", "-u", user, "--", "sh", "-c", cmd])
    };
    c.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).kill_on_drop(true);
    c.process_group(0);
    let mut child = c.spawn().map_err(|e| format!("Start fehlgeschlagen: {e}"))?;
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let read_out = async move {
        let mut b = Vec::new();
        let _ = (&mut so).take(OUT_MAX as u64 + 1).read_to_end(&mut b).await;
        let _ = tokio::io::copy(&mut so, &mut tokio::io::sink()).await;
        b
    };
    let read_err = async move {
        let mut b = Vec::new();
        let _ = (&mut se).take(OUT_MAX as u64 + 1).read_to_end(&mut b).await;
        let _ = tokio::io::copy(&mut se, &mut tokio::io::sink()).await;
        b
    };
    let pid = child.id();
    let run = async { tokio::join!(read_out, read_err, child.wait()) };
    match tokio::time::timeout(Duration::from_secs(timeout), run).await {
        Ok((o, e, st)) => Ok(json!({"code": st.ok().and_then(|s| s.code()).unwrap_or(-1), "stdout": cut(&o), "stderr": cut(&e), "timeout": false})),
        Err(_) => {
            if let Some(p) = pid {
                let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(p as i32), nix::sys::signal::Signal::SIGKILL);
            }
            Ok(json!({"code": -1, "stdout": "", "stderr": format!("Abbruch nach {timeout} s"), "timeout": true}))
        }
    }
}

fn fs_list(path: &str) -> Result<Value, String> {
    let p = host::get().path(if path.is_empty() { "/" } else { path })?;
    let mut entries = Vec::new();
    for e in std::fs::read_dir(&p).map_err(|e| e.to_string())?.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let Ok(lm) = e.path().symlink_metadata() else { continue };
        let typ = if lm.file_type().is_symlink() {
            if e.path().is_dir() { "ld" } else { "l" }
        } else if lm.is_dir() {
            "d"
        } else {
            "f"
        };
        entries.push(json!([name, typ, lm.len(), lm.mtime(), format!("{:o}", lm.permissions().mode() & 0o7777)]));
    }
    entries.sort_by(|a, b| {
        let da = a[1].as_str().unwrap_or("").contains('d');
        let db = b[1].as_str().unwrap_or("").contains('d');
        db.cmp(&da).then_with(|| a[0].as_str().unwrap_or("").to_lowercase().cmp(&b[0].as_str().unwrap_or("").to_lowercase()))
    });
    Ok(json!({"path": path, "entries": entries}))
}

fn fs_read(path: &str, offset: u64, len: u64) -> Result<Value, String> {
    use std::io::{Read, Seek, SeekFrom};
    let p = host::get().path(path)?;
    let mut f = std::fs::File::open(&p).map_err(|e| e.to_string())?;
    let size = f.metadata().map_err(|e| e.to_string())?.len();
    f.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    f.take(len.min(READ_MAX)).read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let eof = offset + buf.len() as u64 >= size;
    Ok(json!({"size": size, "d": B64.encode(&buf), "eof": eof}))
}

fn fs_write(path: &str, d: &str, append: bool, mkdirs: bool) -> Result<Value, String> {
    use std::io::Write;
    let p = host::get().path(path)?;
    let data = B64.decode(d).map_err(|_| "d ist kein Base64".to_string())?;
    if mkdirs
        && let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    if append {
        let mut f = std::fs::OpenOptions::new().append(true).create(true).open(&p).map_err(|e| e.to_string())?;
        f.write_all(&data).map_err(|e| e.to_string())?;
    } else {
        // atomar: in Nachbardatei schreiben, Rechte übernehmen, umbenennen
        let tmp = p.with_file_name(format!(".{}.ida-tmp", p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()));
        let mode = std::fs::metadata(&p).map(|m| m.permissions().mode()).ok();
        {
            let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
            f.write_all(&data).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
        }
        if let Some(m) = mode {
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(m));
        }
        std::fs::rename(&tmp, &p).map_err(|e| e.to_string())?;
    }
    let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
    Ok(json!({"size": size}))
}

fn fs_delete(path: &str, recursive: bool) -> Result<Value, String> {
    if path.trim_end_matches('/').is_empty() {
        return Err("/ wird nicht gelöscht".into());
    }
    let p = host::get().path(path)?;
    let m = p.symlink_metadata().map_err(|e| e.to_string())?;
    if m.is_dir() {
        if recursive { std::fs::remove_dir_all(&p) } else { std::fs::remove_dir(&p) }
    } else {
        std::fs::remove_file(&p)
    }
    .map_err(|e| e.to_string())?;
    Ok(json!({}))
}

/// Mesh: IP der Schnittstelle CloudflareWARP und Status von warp-cli.
pub async fn mesh_status() -> Value {
    let h = host::get();
    let ip = exec("ip -4 -o addr show CloudflareWARP 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1", "", 5)
        .await
        .ok()
        .and_then(|v| v["stdout"].as_str().map(|s| s.trim().to_string()))
        .unwrap_or_default();
    let st = exec("command -v warp-cli >/dev/null 2>&1 && warp-cli --accept-tos status 2>&1 | head -3 || echo 'nicht installiert'", "", 10)
        .await
        .ok()
        .and_then(|v| v["stdout"].as_str().map(|s| s.trim().to_string()))
        .unwrap_or_default();
    let status = if st.contains("Connected") {
        "verbunden"
    } else if st.contains("nicht installiert") {
        "nicht eingerichtet"
    } else if st.is_empty() {
        "unbekannt"
    } else {
        "getrennt"
    };
    let supported = matches!(std::env::consts::ARCH, "x86_64" | "aarch64");
    let _ = h;
    json!({"ip": ip, "status": status, "detail": st, "supported": supported})
}

/// WARP wieder verbinden (Dienst starten, `warp-cli connect`) – wenn Health nur noch über das Mesh erreichbar ist.
pub async fn mesh_reconnect() {
    let _ = exec(
        "command -v warp-cli >/dev/null 2>&1 || exit 0; \
         (systemctl is-active --quiet warp-svc || systemctl restart warp-svc) >/dev/null 2>&1; sleep 2; \
         warp-cli --accept-tos connect >/dev/null 2>&1; sleep 5",
        "",
        30,
    )
    .await;
}

const MESH_SCRIPT: &str = r#"set -e
# apt kann gerade belegt sein (Systemupdates): bis zu 7,5 Minuten warten statt sofort aufzugeben (exec-Limit 900 s)
apt_get() {
  n=0
  while :; do
    if out=$(apt-get "$@" 2>&1); then return 0; fi
    case "$out" in
      *"Could not get lock"*|*"Unable to lock"*|*"Unable to acquire"*) ;;
      *) printf '%s\n' "$out" >&2; return 1 ;;
    esac
    n=$((n+1))
    if [ "$n" -ge 45 ]; then printf '%s\n' "$out" >&2; return 1; fi
    sleep 10
  done
}
if ! command -v warp-cli >/dev/null 2>&1; then
  if ! command -v apt-get >/dev/null 2>&1; then echo "Kein apt-get: Cloudflare Mesh gibt es hier nur für Debian/Ubuntu." >&2; exit 2; fi
  export DEBIAN_FRONTEND=noninteractive
  apt_get update -qq
  apt_get install -y -qq curl gpg lsb-release
  curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
  CODENAME=$(. /etc/os-release && echo "$VERSION_CODENAME")
  echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $CODENAME main" > /etc/apt/sources.list.d/cloudflare-client.list
  apt_get update -qq
  apt_get install -y -qq cloudflare-warp
fi
# Der WARP-Dienst muss laufen – auch wenn warp-cli schon da ist (ein abgebrochener Versuch lässt ihn sonst aus)
if command -v systemctl >/dev/null 2>&1; then systemctl enable --now warp-svc >/dev/null 2>&1 || systemctl restart warp-svc || true; fi
n=0
until warp-cli --accept-tos status >/dev/null 2>&1; do
  n=$((n+1))
  if [ "$n" -ge 30 ]; then echo "Der WARP-Dienst (warp-svc) startet nicht – siehe: journalctl -u warp-svc -n 50" >&2; exit 3; fi
  sleep 2
done
warp-cli --accept-tos registration delete >/dev/null 2>&1 || true
warp-cli --accept-tos connector new "$MESH_TOKEN"
warp-cli --accept-tos connect
sleep 5
warp-cli --accept-tos status
"#;

/// Nur eine Mesh-Einrichtung gleichzeitig (Health nach dem Koppeln, Knopf in Health, lokale Seite) –
/// sonst blockieren sich die apt-Läufe gegenseitig.
static MESH_BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

struct MeshBusy;

impl Drop for MeshBusy {
    fn drop(&mut self) {
        MESH_BUSY.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

pub async fn mesh_setup(token: &str) -> Result<Value, String> {
    if MESH_BUSY.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return Err("Die Mesh-Einrichtung läuft schon – bitte warten, bis sie fertig ist.".into());
    }
    let _busy = MeshBusy;
    if !matches!(std::env::consts::ARCH, "x86_64" | "aarch64") {
        return Err(format!("Cloudflare Mesh gibt es nur für 64-Bit (x86_64/aarch64), dieses Gerät ist {}.", std::env::consts::ARCH));
    }
    let token = token.trim();
    if token.is_empty() || !token.chars().all(|c| c.is_ascii_alphanumeric() || "-_=.+/".contains(c)) {
        return Err("Mesh-Token fehlt oder ist ungültig".into());
    }
    // Token per Umgebung, nicht in der Befehlszeile des Skripts
    let script = format!("MESH_TOKEN='{token}'\n{MESH_SCRIPT}");
    let r = exec(&script, "", 900).await?;
    let ok = r["code"].as_i64() == Some(0);
    let out = format!("{}{}", r["stdout"].as_str().unwrap_or(""), r["stderr"].as_str().unwrap_or(""));
    if ok { Ok(json!({"output": out, "mesh": mesh_status().await})) } else { Err(format!("Mesh-Einrichtung fehlgeschlagen:\n{out}")) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exec_and_timeout() {
        let r = exec("echo hallo; echo fehler >&2; exit 3", "", 5).await.unwrap();
        assert_eq!(r["code"], 3);
        assert_eq!(r["stdout"], "hallo\n");
        assert_eq!(r["stderr"], "fehler\n");
        let r = exec("sleep 5", "", 1).await.unwrap();
        assert_eq!(r["timeout"], true);
    }

    #[test]
    fn files_roundtrip() {
        let dir = std::env::temp_dir().join(format!("idac-{}", std::process::id()));
        let f = dir.join("a/b.txt");
        let fs = f.to_str().unwrap();
        fs_write(fs, &B64.encode("eins"), false, true).unwrap();
        fs_write(fs, &B64.encode("zwei"), true, true).unwrap();
        let r = fs_read(fs, 0, 100).unwrap();
        assert_eq!(B64.decode(r["d"].as_str().unwrap()).unwrap(), b"einszwei");
        assert_eq!(r["eof"], true);
        let l = fs_list(dir.join("a").to_str().unwrap()).unwrap();
        assert_eq!(l["entries"][0][0], "b.txt");
        fs_delete(dir.to_str().unwrap(), true).unwrap();
        assert!(!dir.exists());
        assert!(fs_delete("/", true).is_err());
    }
}

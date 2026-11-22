//! Interaktive Shell (wie SSH) über ein Pseudo-Terminal. Lesen läuft in einem eigenen Thread, Ausgaben gehen als pty_out zurück.
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use nix::pty::{OpenptyResult, Winsize, openpty};
use serde_json::json;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedSender;

use crate::host;

pub const MAX_SESSIONS: usize = 8;

struct Session {
    master: std::fs::File,
    pid: i32,
}

#[derive(Clone, Default)]
pub struct Ptys(Arc<Mutex<HashMap<String, Session>>>);

nix::ioctl_write_ptr_bad!(set_winsize, libc::TIOCSWINSZ, Winsize);

fn ws(cols: u16, rows: u16) -> Winsize {
    Winsize { ws_row: rows.clamp(2, 500), ws_col: cols.clamp(10, 1000), ws_xpixel: 0, ws_ypixel: 0 }
}

impl Ptys {
    pub fn open(&self, sid: &str, cols: u16, rows: u16, out: UnboundedSender<String>) -> Result<(), String> {
        let mut map = self.0.lock().unwrap();
        if map.len() >= MAX_SESSIONS {
            return Err("zu viele offene Shells".into());
        }
        if map.contains_key(sid) {
            return Err("Shell gibt es schon".into());
        }
        let size = ws(cols, rows);
        let OpenptyResult { master, slave } = openpty(Some(&size), None).map_err(|e| e.to_string())?;
        let h = host::get();
        let mut cmd = std::process::Command::new(h.shell());
        cmd.arg("-l")
            .env_clear()
            .env("TERM", "xterm-256color")
            .env("HOME", "/root")
            .env("USER", "root")
            .env("LANG", std::env::var("LANG").unwrap_or_else(|_| "C.UTF-8".into()))
            .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
            .current_dir(if std::fs::read_dir("/root").is_ok() { "/root" } else { "/" });
        let sfd = slave.as_raw_fd();
        let to_stdio = |fd: &OwnedFd| -> Result<std::process::Stdio, String> { Ok(fd.try_clone().map_err(|e| e.to_string())?.into()) };
        cmd.stdin(to_stdio(&slave)?).stdout(to_stdio(&slave)?).stderr(to_stdio(&slave)?);
        unsafe {
            cmd.pre_exec(move || {
                libc::setsid();
                libc::ioctl(sfd, libc::TIOCSCTTY as _, 0);
                Ok(())
            });
        }
        let child = cmd.spawn().map_err(|e| format!("Shell startet nicht: {e}"))?;
        drop(slave);
        let pid = child.id() as i32;
        let master_file = std::fs::File::from(master);
        let mut reader = master_file.try_clone().map_err(|e| e.to_string())?;
        map.insert(sid.to_string(), Session { master: master_file, pid });
        drop(map);

        let sid2 = sid.to_string();
        let me = self.clone();
        std::thread::spawn(move || {
            let mut child = child;
            let mut buf = [0u8; 16384];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if out.send(json!({"t": "pty_out", "sid": sid2, "d": B64.encode(&buf[..n])}).to_string()).is_err() {
                            break;
                        }
                    }
                }
            }
            let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
            me.0.lock().unwrap().remove(&sid2);
            let _ = out.send(json!({"t": "pty_exit", "sid": sid2, "code": code}).to_string());
        });
        Ok(())
    }

    pub fn input(&self, sid: &str, d: &str) {
        let Ok(data) = B64.decode(d) else { return };
        if let Some(s) = self.0.lock().unwrap().get_mut(sid) {
            let _ = s.master.write_all(&data);
        }
    }

    pub fn resize(&self, sid: &str, cols: u16, rows: u16) {
        if let Some(s) = self.0.lock().unwrap().get(sid) {
            let size = ws(cols, rows);
            unsafe {
                let _ = set_winsize(s.master.as_raw_fd(), &size);
            }
        }
    }

    pub fn close(&self, sid: &str) {
        if let Some(s) = self.0.lock().unwrap().remove(sid) {
            // ganze Sitzung (setsid: Gruppe = pid), auch Kinder der Shell
            let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(s.pid), nix::sys::signal::Signal::SIGHUP);
        }
    }

    pub fn close_all(&self) {
        let ids: Vec<String> = self.0.lock().unwrap().keys().cloned().collect();
        for id in ids {
            self.close(&id);
        }
    }
}

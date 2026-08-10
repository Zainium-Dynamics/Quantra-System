// Copyright (c) 2026 Zainiumdynamics. All rights reserved.
// Designed for Zainium OS by Zainiumdynamics — https://zainiumdynamics.tech
//
// Session registration with quantra-logind — **no classic Linux pam.d / libpam**.
// Auth is elevate-pam (`/etc/elevate-pam/services/*.toml` + elevate-crypto).
// Greeter / elev open sessions via this JSON control socket (or login1 D-Bus).

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;

const LOGIND_SOCKET: &str = "/run/quantra-logind/control";
const SESSION_ID_DIR: &str = "/run/quantra-logind/sessions";

/// Paths where elevate-pam service stacks live (Zainium: no /usr, no /etc at root).
const ELEVATE_PAM_SERVICE_DIRS: &[&str] = &["/overlayer/syshub/etc/elevate-pam/services"];

// ── Logind JSON client ────────────────────────────────────────────────────────

fn call_logind(request: &serde_json::Value) -> Result<serde_json::Value, String> {
    let mut stream =
        UnixStream::connect(LOGIND_SOCKET).map_err(|e| format!("connect {LOGIND_SOCKET}: {e}"))?;

    let bytes = serde_json::to_vec(request).map_err(|e| format!("serialize: {e}"))?;
    let len = (bytes.len() as u32).to_le_bytes();
    stream
        .write_all(&len)
        .map_err(|e| format!("write len: {e}"))?;
    stream
        .write_all(&bytes)
        .map_err(|e| format!("write body: {e}"))?;

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("read len: {e}"))?;
    let resp_len = u32::from_le_bytes(len_buf) as usize;
    if resp_len > 1 << 20 {
        return Err(format!("response too large: {resp_len} bytes"));
    }
    let mut body = vec![0u8; resp_len];
    stream
        .read_exact(&mut body)
        .map_err(|e| format!("read body: {e}"))?;
    serde_json::from_slice(&body).map_err(|e| format!("parse: {e}"))
}

/// Open a user session with quantra-logind (called by greeter / elev after auth).
/// Returns (session_id, runtime_dir).
pub fn open_session(
    uid: u32,
    username: &str,
    pid: u32,
    tty: Option<&str>,
    display: Option<&str>,
    remote_host: Option<&str>,
    service: Option<&str>,
    session_type: &str,
) -> Result<(u64, String), String> {
    // Wire format matches quantra-logind Request (tag=cmd, snake_case, flat fields)
    let req = serde_json::json!({
        "cmd": "open_session",
        "uid": uid,
        "username": username,
        "leader_pid": pid,
        "session_type": session_type,
        "session_class": "user",
        "tty": tty,
        "display": display,
        "remote_host": remote_host,
        "service": service.unwrap_or("login"),
    });
    let resp = call_logind(&req)?;
    if resp.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return Err(resp
            .get("error")
            .or_else(|| resp.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("open_session failed")
            .to_string());
    }
    let data = resp.get("data").cloned().unwrap_or(serde_json::Value::Null);
    let sid = data
        .get("session_id")
        .or_else(|| data.get("id"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let runtime = data
        .get("runtime_dir")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("/run/user/{uid}"));

    let _ = fs::create_dir_all(SESSION_ID_DIR);
    let _ = fs::write(
        format!("{SESSION_ID_DIR}/{pid}"),
        format!("{sid}\n{username}\n"),
    );
    log::info!(
        "elevate-session: opened session {sid} for {username} (uid={uid}) type={session_type} runtime={runtime}"
    );
    Ok((sid, runtime))
}

/// Close session previously opened for `pid`.
pub fn close_session_for_pid(pid: u32) -> Result<(), String> {
    let path = format!("{SESSION_ID_DIR}/{pid}");
    let text = fs::read_to_string(&path).map_err(|e| format!("no session for pid={pid}: {e}"))?;
    let mut lines = text.lines();
    let sid: u64 = lines
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "bad session id file".to_string())?;
    let _ = fs::remove_file(&path);
    close_session(sid)
}

pub fn close_session(sid: u64) -> Result<(), String> {
    let req = serde_json::json!({
        "cmd": "close_session",
        "session_id": sid
    });
    let resp = call_logind(&req)?;
    if resp.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return Err(resp
            .get("error")
            .or_else(|| resp.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("close_session failed")
            .to_string());
    }
    log::info!("elevate-session: closed session {sid}");
    Ok(())
}

// ── elevate-pam service stacks (TOML only — never pam.d) ──────────────────────

/// Write elevate-pam service stacks for greeter / login / elevate.
/// Does **not** create `/etc/pam.d/*`. Auth = elevate-pam + elevate-crypto.
pub fn write_elevate_pam_stacks() -> std::io::Result<()> {
    let dir = resolve_elevate_services_dir()?;
    fs::create_dir_all(&dir)?;

    // Password auth for elevate / elev (sudo-replacement)
    write_if_missing(
        &dir.join("elevate.toml"),
        elevate_stack("elevate", "elevate (privilege) authentication"),
    )?;
    write_if_missing(
        &dir.join("elev.toml"),
        elevate_stack("elev", "elev (su-replacement) authentication"),
    )?;
    write_if_missing(
        &dir.join("elev-l.toml"),
        elevate_stack("elev-l", "elev -l login shell authentication"),
    )?;

    // Desktop greeter / user login — auth only; session via quantra-logind socket
    write_if_missing(
        &dir.join("cosmic-greeter.toml"),
        login_stack(
            "cosmic-greeter",
            "COSMIC greeter — elevate-pam auth; session via quantra-logind",
        ),
    )?;
    write_if_missing(
        &dir.join("login.toml"),
        login_stack(
            "login",
            "Console / greeter login — elevate-pam auth; session via quantra-logind",
        ),
    )?;
    write_if_missing(
        &dir.join("other.toml"),
        elevate_stack("other", "Default elevate-pam fallback stack"),
    )?;

    // Drop a short README so ops never recreate pam.d by habit
    let note = dir.parent().map(|p| p.join("README.zainium"));
    if let Some(p) = note {
        if !p.exists() {
            let body = "\
# elevate-pam on Zainium OS
#
# Classic Linux /etc/pam.d is NOT used.
# Auth stacks:  /etc/elevate-pam/services/*.toml  (or syshub mirror)
# Password:     elevate-crypto (Argon2id) via pam-unix module
# Privilege:    /bin/elevate  (elevate-sudo)
# Sessions:     quantra-logind JSON /run/quantra-logind/control  (login1 D-Bus)
#
# Do not install or write pam.d files.
";
            fs::write(p, body)?;
        }
    }

    log::info!(
        "elevate-pam stacks ready under {} (no pam.d)",
        dir.display()
    );
    Ok(())
}

fn resolve_elevate_services_dir() -> std::io::Result<std::path::PathBuf> {
    for d in ELEVATE_PAM_SERVICE_DIRS {
        let p = Path::new(d);
        if p.exists() {
            return Ok(p.to_path_buf());
        }
    }
    // Prefer syshub layout for immutable OS image
    let preferred = Path::new(ELEVATE_PAM_SERVICE_DIRS[0]);
    fs::create_dir_all(preferred)?;
    Ok(preferred.to_path_buf())
}

fn write_if_missing(path: &Path, body: impl AsRef<str>) -> std::io::Result<()> {
    if path.exists() {
        log::debug!("elevate-pam: keep existing {}", path.display());
        return Ok(());
    }
    fs::write(path, body.as_ref())?;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o644));
    log::info!("elevate-pam: wrote {}", path.display());
    Ok(())
}

fn elevate_stack(name: &str, description: &str) -> String {
    format!(
        r#"# elevate-pam service stack — Zainium OS (NO pam.d)
# Install: /overlayer/syshub/etc/elevate-pam/services/{name}.toml
# Auth: elevate-crypto via module "unix" (Argon2id / legacy $6$)

[service]
name = "{name}"
description = "{description}"

[[auth]]
control = "required"
module = "env"
args = ["readenv=1"]

[[auth]]
control = "required"
module = "unix"

[[account]]
control = "required"
module = "unix"

[[password]]
control = "required"
module = "unix"

[[session]]
control = "required"
module = "limits"

[[session]]
control = "required"
module = "unix"
"#
    )
}

fn login_stack(name: &str, description: &str) -> String {
    format!(
        r#"# elevate-pam service stack — greeter/login (NO pam.d)
# Auth only. After success, greeter/compositor opens quantra-logind session:
#   socket /run/quantra-logind/control  or  org.freedesktop.login1

[service]
name = "{name}"
description = "{description}"

[[auth]]
control = "required"
module = "env"
args = ["readenv=1"]

[[auth]]
control = "required"
module = "unix"

[[account]]
control = "required"
module = "unix"

[[password]]
control = "required"
module = "unix"

[[session]]
control = "required"
module = "env"

[[session]]
control = "required"
module = "limits"

[[session]]
control = "required"
module = "unix"
"#
    )
}

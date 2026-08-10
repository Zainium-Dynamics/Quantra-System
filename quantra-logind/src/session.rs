/// Session Manager
///
/// Manages login sessions. Each session maps to one logged-in user interaction
/// context — a VT session, an SSH connection, a Wayland compositor instance, etc.
///
/// # Flatpak / xdg-portal compatibility
///
/// Flatpak calls `GetSessionByPid()` to identify the calling session and
/// thereby determine which XDG portal backend to use.
/// `session_by_pid()` scans cgroup membership to find the session.
///
/// # COSMIC desktop compatibility
///
/// COSMIC compositor (cosmic-comp) opens a Wayland session via `OpenSession`
/// with `session_type=wayland`. It queries `GetSession` to get the VT number
/// and runtime_dir for socket placement.
use crate::types::*;
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[allow(dead_code)]
pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,
    next_id: SessionId,
    /// Subscribers waiting for events (write fds)
    pub event_sinks: Vec<std::os::unix::net::UnixStream>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_id: 1,
            event_sinks: Vec::new(),
        }
    }

    pub fn open(
        &mut self,
        uid: u32,
        username: String,
        leader_pid: u32,
        session_type: SessionType,
        session_class: SessionClass,
        tty: Option<String>,
        display: Option<String>,
        remote_host: Option<String>,
        remote_user: Option<String>,
        service: Option<String>,
        vt: Option<u32>,
    ) -> Result<SessionId> {
        let id = self.next_id;
        self.next_id += 1;

        let remote = remote_host.is_some();
        let mut s = Session::new(
            id,
            uid,
            username.clone(),
            leader_pid,
            session_type,
            session_class,
        );
        s.tty = tty.clone();
        s.display = display;
        s.remote_host = remote_host;
        s.remote_user = remote_user;
        s.remote = remote;
        s.service = service;
        s.vt_number = vt.or_else(|| tty.as_deref().and_then(extract_vt_number));

        // Create cgroup scope for session
        create_session_scope(id, uid, leader_pid)?;

        log::info!(
            "Session {} opened: user={} uid={} pid={} type={:?} vt={:?}",
            id,
            s.username,
            uid,
            leader_pid,
            s.session_type,
            s.vt_number
        );

        self.sessions.insert(id, s);
        Ok(id)
    }

    pub fn close(&mut self, id: SessionId) -> Result<()> {
        let sess = self
            .sessions
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("session {} not found", id))?;
        sess.state = SessionState::Closing;

        // Remove cgroup scope
        remove_session_scope(id);

        self.sessions
            .remove(&id)
            .map(|_| log::info!("Session {} closed", id))
            .ok_or_else(|| anyhow::anyhow!("session {} vanished during close", id))
    }

    pub fn activate(&mut self, id: SessionId) -> Result<()> {
        // Get the seat of this session for deactivating others
        let seat = self
            .sessions
            .get(&id)
            .ok_or_else(|| anyhow::anyhow!("session {} not found", id))?
            .seat
            .clone();

        // Deactivate all other sessions on same seat
        for s in self.sessions.values_mut() {
            if s.state == SessionState::Active && s.seat == seat && s.id != id {
                s.state = SessionState::Online;
                log::debug!("Session {} deactivated (seat takeover by {})", s.id, id);
            }
        }

        let sess = self.sessions.get_mut(&id).unwrap();
        sess.state = SessionState::Active;
        log::info!("Session {} activated (uid={})", id, sess.uid);
        Ok(())
    }

    pub fn lock(&mut self, id: SessionId) -> Result<()> {
        let sess = self
            .sessions
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("session {} not found", id))?;
        sess.locked_hint = true;
        // Send SIGUSR2 to session leader (conventional lock signal for compositors)
        let pid = nix::unistd::Pid::from_raw(sess.leader_pid as i32);
        if true {
            let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGUSR2);
        }
        log::info!("Session {} locked", id);
        Ok(())
    }

    pub fn unlock(&mut self, id: SessionId) -> Result<()> {
        let sess = self
            .sessions
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("session {} not found", id))?;
        sess.locked_hint = false;
        log::info!("Session {} unlocked", id);
        Ok(())
    }

    pub fn lock_all(&mut self) {
        let ids: Vec<SessionId> = self.sessions.keys().copied().collect();
        for id in ids {
            self.lock(id).ok();
        }
    }

    pub fn unlock_all(&mut self) {
        let ids: Vec<SessionId> = self.sessions.keys().copied().collect();
        for id in ids {
            self.unlock(id).ok();
        }
    }

    pub fn set_idle_hint(&mut self, id: SessionId, idle: bool) -> Result<()> {
        let sess = self
            .sessions
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("session {} not found", id))?;
        sess.idle_hint = idle;
        sess.idle_since = if idle { Some(now_unix()) } else { None };
        Ok(())
    }

    pub fn set_locked_hint(&mut self, id: SessionId, locked: bool) -> Result<()> {
        let sess = self
            .sessions
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("session {} not found", id))?;
        sess.locked_hint = locked;
        Ok(())
    }

    pub fn assign_seat(&mut self, id: SessionId, seat: String) {
        if let Some(s) = self.sessions.get_mut(&id) {
            s.seat = Some(seat);
        }
    }

    pub fn uid_of(&self, id: SessionId) -> Option<u32> {
        self.sessions.get(&id).map(|s| s.uid)
    }

    pub fn seat_of(&self, id: SessionId) -> Option<String> {
        self.sessions.get(&id).and_then(|s| s.seat.clone())
    }

    pub fn vt_of(&self, id: SessionId) -> Option<u32> {
        self.sessions.get(&id).and_then(|s| s.vt_number)
    }

    pub fn get(&self, id: SessionId) -> Option<&Session> {
        self.sessions.get(&id)
    }

    pub fn all(&self) -> Vec<&Session> {
        let mut v: Vec<&Session> = self.sessions.values().collect();
        v.sort_by_key(|s| s.id);
        v
    }

    /// Find session by PID — scans cgroup membership.
    ///
    /// Used by Flatpak (`GetSessionByPid`) to identify the calling app's session.
    pub fn session_by_pid(&self, pid: u32) -> Option<&Session> {
        // Fast path: check if pid is a direct session leader
        if let Some(s) = self.sessions.values().find(|s| s.leader_pid == pid) {
            return Some(s);
        }

        // Slow path: read /proc/<pid>/cgroup and match session scope
        if let Ok(cgroup) = fs::read_to_string(format!("/proc/{}/cgroup", pid)) {
            for s in self.sessions.values() {
                if cgroup.contains(&s.scope) {
                    return Some(s);
                }
            }
        }

        // Parent process scan — walk up ppid chain
        if let Some(ppid) = get_ppid(pid) {
            if ppid != pid && ppid > 1 {
                return self.session_by_pid(ppid);
            }
        }

        None
    }

    /// Find all sessions for a given UID.
    #[allow(dead_code)]
    pub fn sessions_for_uid(&self, uid: u32) -> Vec<&Session> {
        self.sessions.values().filter(|s| s.uid == uid).collect()
    }

    /// Kill all processes in a session cgroup.
    #[allow(dead_code)]
    pub fn terminate(&mut self, id: SessionId) -> Result<()> {
        let sess = self
            .sessions
            .get(&id)
            .ok_or_else(|| anyhow::anyhow!("session {} not found", id))?;
        kill_session_cgroup(id, sess.uid)?;
        self.close(id)
    }
}

// ── cgroup scope management ───────────────────────────────────────────────────

/// Create `session-N.scope` in the user slice cgroup.
///
/// This gives Flatpak/systemd a cgroup path to identify the session.
/// Path: `/sys/fs/cgroup/user.slice/user-UID.slice/session-N.scope`
fn create_session_scope(id: SessionId, uid: u32, leader_pid: u32) -> Result<()> {
    let scope_path = format!(
        "/sys/fs/cgroup/user.slice/user-{}.slice/session-{}.scope",
        uid, id
    );
    if let Err(e) = fs::create_dir_all(&scope_path) {
        log::debug!(
            "session scope mkdir {}: {} (cgroup v2 may not be writable — non-fatal)",
            scope_path,
            e
        );
        return Ok(());
    }

    // Add leader PID to scope
    let procs = format!("{}/cgroup.procs", scope_path);
    if let Err(e) = fs::write(&procs, leader_pid.to_string()) {
        log::debug!("session scope cgroup.procs: {} (non-fatal)", e);
    }

    log::debug!("Session {} cgroup scope: {}", id, scope_path);
    Ok(())
}

fn remove_session_scope(id: SessionId) {
    // Find and remove scope directories for this session
    for uid_dir in glob_dirs("/sys/fs/cgroup/user.slice") {
        let scope = format!("{}/session-{}.scope", uid_dir, id);
        if Path::new(&scope).exists() {
            // Write 1 to cgroup.kill (Linux 5.14+) to kill all processes
            fs::write(format!("{}/cgroup.kill", scope), "1").ok();
            fs::remove_dir(&scope).ok();
        }
    }
}

#[allow(dead_code)]
fn kill_session_cgroup(id: SessionId, uid: u32) -> Result<()> {
    let scope_path = format!(
        "/sys/fs/cgroup/user.slice/user-{}.slice/session-{}.scope",
        uid, id
    );
    // cgroup.kill (Linux 5.14+)
    if let Err(e) = fs::write(format!("{}/cgroup.kill", scope_path), "1") {
        log::debug!(
            "cgroup.kill session {}: {} (fallback to SIGTERM cgroup.procs)",
            id,
            e
        );
        // Fallback: read cgroup.procs and send SIGTERM to each PID
        if let Ok(procs) = fs::read_to_string(format!("{}/cgroup.procs", scope_path)) {
            for line in procs.lines() {
                if let Ok(pid) = line.trim().parse::<i32>() {
                    unsafe {
                        libc::kill(pid, libc::SIGTERM);
                    }
                }
            }
        }
    }
    Ok(())
}

fn glob_dirs(parent: &str) -> Vec<String> {
    fs::read_dir(parent)
        .map(|e| {
            e.flatten()
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .map(|e| e.path().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn extract_vt_number(tty: &str) -> Option<u32> {
    tty.strip_prefix("/dev/tty")
        .or_else(|| tty.strip_prefix("tty"))
        .and_then(|n| n.parse().ok())
}

fn get_ppid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in stat.lines() {
        if let Some(ppid_str) = line.strip_prefix("PPid:\t") {
            return ppid_str.trim().parse().ok();
        }
    }
    None
}

/// User Manager — /run/user/<uid> lifecycle + linger + IPC cleanup
///
/// # /run/user/<uid> compatibility
///
/// Every major desktop component expects this directory:
///
/// | Component | What it uses |
/// |-----------|-------------|
/// | Flatpak | `/run/user/UID/` as XDG_RUNTIME_DIR base |
/// | PipeWire | `/run/user/UID/pipewire-0` socket |
/// | PulseAudio | `/run/user/UID/pulse/` directory |
/// | COSMIC desktop | `/run/user/UID/wayland-0` socket |
/// | xdg-desktop-portal | `/run/user/UID/xdg-desktop-portal/` |
/// | D-Bus (user session) | `/run/user/UID/bus` socket |
/// | Systemd user bus | `/run/user/UID/systemd/` |
/// | Flatpak portal | `/run/user/UID/doc/` (document portal) |
///
/// # OSTree compatibility
///
/// OSTree-based systems (like AtomicOS or Zainium in immutable mode) rely on
/// XDG_RUNTIME_DIR for temporary session state. quantra-logind must:
/// 1. Create /run/user/UID as tmpfs (mode 0700, uid:uid)
/// 2. Pre-create standard subdirectories (systemd/, doc/, portal/)
/// 3. Set correct env vars in session cgroup via /proc/<pid>/environ injection
///
/// # Linger
///
/// `linger = true` keeps /run/user/UID alive even with no sessions.
/// Required for user systemd services that run headless (e.g. persistent Flatpak background apps).
use crate::types::*;
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub struct UserManager {
    users: HashMap<u32, UserRecord>,
}

impl UserManager {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }

    /// Called when a session is opened for this user.
    pub fn login(
        &mut self,
        uid: u32,
        username: String,
        sid: SessionId,
        config: &LogindConfig,
    ) -> Result<()> {
        if let Some(u) = self.users.get_mut(&uid) {
            if !u.session_ids.contains(&sid) {
                u.session_ids.push(sid);
                u.last_login = now_unix();
            }
            u.state = UserState::Online;
            return Ok(());
        }

        // First login — create runtime dir
        let runtime_dir = format!("/run/user/{}", uid);
        create_runtime_dir(&runtime_dir, uid, config)?;
        create_runtime_subdirs(&runtime_dir, uid)?;

        // Write user-UID.slice cgroup
        create_user_slice(uid)?;

        let mut rec = UserRecord::new(uid, username.clone());
        rec.session_ids.push(sid);
        rec.state = UserState::Online;
        self.users.insert(uid, rec);

        log::info!(
            "User {} (uid={}) first login → {}",
            username,
            uid,
            runtime_dir
        );
        Ok(())
    }

    /// Called when a session closes.
    pub fn logout(&mut self, uid: u32, sid: SessionId, config: &LogindConfig) -> Result<()> {
        let cleanup = if let Some(u) = self.users.get_mut(&uid) {
            u.session_ids.retain(|&s| s != sid);
            let empty = u.session_ids.is_empty();
            if empty {
                u.state = if u.linger {
                    UserState::Lingering
                } else {
                    UserState::Closing
                };
            }
            empty && !u.linger
        } else {
            return Ok(());
        };

        if cleanup {
            let delay = config.user_stop_delay_sec;
            let kill_procs = config.kill_user_processes;
            let kill_only = config.kill_only_users.clone();
            let kill_excl = config.kill_exclude_users.clone();
            let remove_ipc = config.remove_ipc;
            let rec = self.users.remove(&uid).unwrap();
            let username = rec.username.clone();

            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(delay));

                // KillUserProcesses — kill all processes owned by uid
                if kill_procs {
                    let should_kill = if !kill_only.is_empty() {
                        kill_only.contains(&username)
                    } else {
                        !kill_excl.contains(&username)
                    };

                    if should_kill {
                        log::info!(
                            "KillUserProcesses: sending SIGTERM to uid={} ({})",
                            uid,
                            username
                        );
                        kill_all_user_processes(uid, libc::SIGTERM);
                        std::thread::sleep(std::time::Duration::from_secs(5));
                        kill_all_user_processes(uid, libc::SIGKILL);
                        log::info!("KillUserProcesses: SIGKILL sent to uid={}", uid);
                    }
                }

                if remove_ipc {
                    remove_user_ipc(uid);
                }

                if let Some(dir) = get_runtime_dir(uid) {
                    destroy_runtime_dir(&dir).ok();
                }
                remove_user_slice(uid);
                log::info!("User uid={} cleanup complete", uid);
            });

            log::info!(
                "User uid={} ({}) logged out — cleanup in {}s (kill={})",
                uid,
                rec.username,
                delay,
                kill_procs
            );
        }
        Ok(())
    }

    pub fn set_linger(&mut self, uid: u32, enable: bool) -> Result<()> {
        // Persist linger state
        let linger_dir = "/overlayer/syshub/var/lib/quantra-logind/linger";
        fs::create_dir_all(linger_dir).map_err(|e| anyhow::anyhow!("create linger dir: {}", e))?;
        let linger_file = format!("{}/{}", linger_dir, uid);

        if enable {
            fs::write(&linger_file, b"")
                .map_err(|e| anyhow::anyhow!("write linger file: {}", e))?;
        } else {
            fs::remove_file(&linger_file).ok();
        }

        if let Some(u) = self.users.get_mut(&uid) {
            u.linger = enable;
            if !enable && u.session_ids.is_empty() {
                // No sessions and linger disabled — cleanup
                destroy_runtime_dir(&u.runtime_dir)?;
                remove_user_slice(uid);
                self.users.remove(&uid);
            }
        } else if enable {
            // Linger for user not currently logged in — create runtime dir now
            if let Some(username) = resolve_username(uid) {
                let runtime_dir = format!("/run/user/{}", uid);
                create_runtime_dir(&runtime_dir, uid, &LogindConfig::default())?;
                create_runtime_subdirs(&runtime_dir, uid)?;
                create_user_slice(uid)?;
                let mut rec = UserRecord::new(uid, username);
                rec.linger = true;
                rec.state = UserState::Lingering;
                self.users.insert(uid, rec);
            }
        }

        log::info!("uid={} linger={}", uid, enable);
        Ok(())
    }

    pub fn terminate(&mut self, uid: u32) -> Result<()> {
        // Send SIGTERM to all processes in user slice
        terminate_user_slice(uid)?;
        if let Some(rec) = self.users.get(&uid) {
            destroy_runtime_dir(&rec.runtime_dir)?;
        }
        self.users.remove(&uid);
        log::info!("User uid={} terminated", uid);
        Ok(())
    }

    #[allow(dead_code)]
    pub fn update_state(&mut self, uid: u32, has_active_session: bool) {
        if let Some(u) = self.users.get_mut(&uid) {
            u.state = if u.session_ids.is_empty() {
                if u.linger {
                    UserState::Lingering
                } else {
                    UserState::Offline
                }
            } else if has_active_session {
                UserState::Active
            } else {
                UserState::Online
            };
        }
    }

    /// Load persisted linger state from /overlayer/syshub/var/lib/quantra-logind/linger/
    pub fn load_linger_state(&mut self) {
        let linger_dir = "/overlayer/syshub/var/lib/quantra-logind/linger";
        if let Ok(entries) = fs::read_dir(linger_dir) {
            for entry in entries.flatten() {
                if let Ok(uid) = entry.file_name().to_string_lossy().parse::<u32>() {
                    if let Some(username) = resolve_username(uid) {
                        log::info!("Restoring linger for uid={}", uid);
                        self.set_linger(uid, true).ok();
                        let _ = username;
                    }
                }
            }
        }
    }

    pub fn get(&self, uid: u32) -> Option<&UserRecord> {
        self.users.get(&uid)
    }
    pub fn all(&self) -> Vec<&UserRecord> {
        let mut v: Vec<&UserRecord> = self.users.values().collect();
        v.sort_by_key(|u| u.uid);
        v
    }
}

// ── Runtime directory management ──────────────────────────────────────────────

/// Create /run/user/<uid> as tmpfs with correct ownership.
///
/// Size: 10% of RAM (matching systemd default) or config override.
fn create_runtime_dir(path: &str, uid: u32, config: &LogindConfig) -> Result<()> {
    fs::create_dir_all(path).map_err(|e| anyhow::anyhow!("create {}: {}", path, e))?;

    // Determine size
    let size = match &config.runtime_directory_size {
        Some(s) if s.ends_with('%') => {
            let pct: u64 = s.trim_end_matches('%').parse().unwrap_or(10);
            let total_ram = read_total_ram_bytes();
            format!("{}k", (total_ram * pct / 100) / 1024)
        }
        Some(s) => s.clone(),
        None => "500M".to_string(),
    };

    let opts = format!("uid={},gid={},mode=0700,size={}", uid, uid, size);

    let path_cstr = std::ffi::CString::new(path).unwrap();
    let tmpfs_cstr = std::ffi::CString::new("tmpfs").unwrap();
    let opts_cstr = std::ffi::CString::new(opts.clone()).unwrap();

    let ret = unsafe {
        libc::mount(
            tmpfs_cstr.as_ptr(),
            path_cstr.as_ptr(),
            tmpfs_cstr.as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            opts_cstr.as_ptr() as *const libc::c_void,
        )
    };

    if ret == 0 {
        log::debug!("tmpfs {} (uid={} size={})", path, uid, size);
    } else {
        // Fallback: plain dir with chown (containers, no CAP_SYS_ADMIN)
        log::warn!(
            "tmpfs mount {} failed ({}), using plain dir fallback",
            path,
            std::io::Error::last_os_error()
        );
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(path, perms)?;

        // chown
        let c_path = std::ffi::CString::new(path).unwrap();
        unsafe { libc::chown(c_path.as_ptr(), uid, uid) };
    }

    Ok(())
}

/// Create standard subdirectories inside /run/user/<uid>.
///
/// These are expected by:
/// - Flatpak:            doc/, portal/
/// - D-Bus (user):      bus (socket, not dir — created by dbus-broker)
/// - systemd user:      systemd/private/
/// - PipeWire:          pipewire-0 (socket — created by pipewire)
/// - COSMIC compositor: wayland-0 (socket — created by cosmic-comp)
/// - xdg-portal:        xdg-desktop-portal/
fn create_runtime_subdirs(runtime_dir: &str, uid: u32) -> Result<()> {
    let dirs = [
        format!("{}/systemd", runtime_dir),
        format!("{}/systemd/private", runtime_dir),
        format!("{}/doc", runtime_dir),    // Flatpak document portal
        format!("{}/portal", runtime_dir), // xdg-desktop-portal
        format!("{}/xdg-desktop-portal", runtime_dir),
    ];

    for dir in &dirs {
        if let Err(e) = fs::create_dir_all(dir) {
            log::debug!("create runtime subdir {}: {} (non-fatal)", dir, e);
            continue;
        }
        // Set ownership
        let c_dir = std::ffi::CString::new(dir.as_str()).unwrap();
        unsafe { libc::chown(c_dir.as_ptr(), uid, uid) };
    }

    // Write session env to /run/user/<uid>/systemd/private/
    // Flatpak reads this to set up env in sandboxed apps
    let env_path = format!("{}/systemd/private/env", runtime_dir);
    let env_content = format!(
        "XDG_RUNTIME_DIR={}\nDISPLAY=\nWAYLAND_DISPLAY=\n",
        runtime_dir
    );
    fs::write(&env_path, &env_content).ok();

    log::debug!("Runtime subdirs created for uid={}", uid);
    Ok(())
}

fn destroy_runtime_dir(path: &str) -> Result<()> {
    let path_cstr = std::ffi::CString::new(path).unwrap();
    unsafe {
        libc::umount2(path_cstr.as_ptr(), libc::MNT_DETACH);
    }
    match fs::remove_dir_all(path) {
        Ok(()) => log::debug!("Removed {}", path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => log::warn!("remove {}: {}", path, e),
    }
    Ok(())
}

fn get_runtime_dir(uid: u32) -> Option<String> {
    let path = format!("/run/user/{}", uid);
    if Path::new(&path).exists() {
        Some(path)
    } else {
        None
    }
}

// ── User slice cgroup ─────────────────────────────────────────────────────────

fn create_user_slice(uid: u32) -> Result<()> {
    let slice = format!("/sys/fs/cgroup/user.slice/user-{}.slice", uid);
    if let Err(e) = fs::create_dir_all(&slice) {
        log::debug!("user slice {}: {} (non-fatal)", slice, e);
    }
    Ok(())
}

fn remove_user_slice(uid: u32) {
    let slice = format!("/sys/fs/cgroup/user.slice/user-{}.slice", uid);
    fs::remove_dir(&slice).ok();
}

fn terminate_user_slice(uid: u32) -> Result<()> {
    let slice = format!("/sys/fs/cgroup/user.slice/user-{}.slice", uid);
    // cgroup.kill (Linux 5.14+)
    if fs::write(format!("{}/cgroup.kill", slice), "1").is_ok() {
        return Ok(());
    }
    // Fallback: enumerate cgroup.procs
    if let Ok(procs) = fs::read_to_string(format!("{}/cgroup.procs", slice)) {
        for line in procs.lines() {
            if let Ok(pid) = line.trim().parse::<i32>() {
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
            }
        }
    }
    Ok(())
}

// ── IPC cleanup ───────────────────────────────────────────────────────────────

/// Remove POSIX shared memory, message queues, and SysV IPC owned by UID.
/// Kill all processes owned by `uid` with `sig`.
///
/// Walks /proc and sends signal to every process whose /proc/N/status
/// shows Uid matching uid. Skips PID 1 and the current process.
fn kill_all_user_processes(uid: u32, sig: libc::c_int) {
    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return;
    };
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };
        if pid <= 1 || pid == unsafe { libc::getpid() } {
            continue;
        }

        // Read /proc/<pid>/status to get Uid line
        let status_path = format!("/proc/{}/status", pid);
        if let Ok(status) = std::fs::read_to_string(&status_path) {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("Uid:	") {
                    // "Uid:	real	eff	saved	fs"
                    let real_uid: u32 = rest
                        .split_whitespace()
                        .next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(u32::MAX);
                    if real_uid == uid {
                        unsafe { libc::kill(pid, sig) };
                    }
                    break;
                }
            }
        }
    }
}

fn remove_user_ipc(uid: u32) {
    // /dev/shm — POSIX shared memory files
    if let Ok(entries) = fs::read_dir("/dev/shm") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(meta) = fs::metadata(&path) {
                if {
                    use std::os::unix::fs::MetadataExt;
                    meta.uid() == uid || (meta.gid() == uid && meta.mode() & 0o2 != 0)
                } {
                    fs::remove_file(&path).ok();
                    log::debug!("IPC cleanup: removed {:?}", path);
                }
            }
        }
    }

    // SysV IPC — read /proc/sysvipc/shm, msg, sem (complex — skip for now)
    // Full implementation would parse those files and call shmctl/msgctl/semctl
    log::debug!("IPC cleanup for uid={} complete (posix shm only)", uid);
}

// ── RAM detection ─────────────────────────────────────────────────────────────

fn read_total_ram_bytes() -> u64 {
    fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
        })
        .map(|kb| kb * 1024)
        .unwrap_or(4 * 1024 * 1024 * 1024) // 4 GB default
}

fn resolve_username(uid: u32) -> Option<String> {
    let passwd = fs::read_to_string("/overlayer/syshub/etc/passwd").ok()?;
    for line in passwd.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 {
            if let Ok(u) = fields[2].parse::<u32>() {
                if u == uid {
                    return Some(fields[0].to_string());
                }
            }
        }
    }
    None
}

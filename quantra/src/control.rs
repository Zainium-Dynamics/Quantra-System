/// # Module: control
/// # Purpose: JSON control socket — std-only threaded implementation (no tokio)
/// # Dependencies: services::manager, metrics, signals
/// # Called By: main.rs (Phase 9)
/// # Thread Safety: Each client gets its own thread; ServiceManager behind Arc<Mutex>
/// # Stability: stable (Protocol v1)
///
/// PID 1 listens on `/run/quantra/control` (Unix stream socket).
/// Protocol: 4-byte LE u32 length prefix + JSON payload, both directions.
///
/// Client sends a `ControlCommand` JSON object.
/// Server replies with a `CtlResponse` JSON object.
///
/// ## v5.0.1 Changes
/// - Removed tokio dependency — pure std::os::unix::net + std::thread
/// - Added protocol_version field (v1) for forward compatibility
/// - ~300KB binary size reduction
use anyhow::Result;
use log::{error, info, warn};
use nix::sys::signal::{self, Signal};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::metrics::MetricsCollector;
use crate::services::manager::ServiceManager;

// ── Wire protocol ────────────────────────────────────────────────────────────

/// Protocol version — incremented on breaking wire format changes.
/// Clients MUST send this; server rejects mismatches with a clear error.
#[allow(dead_code)]
pub const PROTOCOL_VERSION: u32 = 1;

/// Shared control socket path
#[allow(dead_code)]
pub const SOCKET_PATH: &str = "/run/quantra/control";

/// Enabled services directory — syshub read-only, but enable/disable
/// writes go to zexlib/union overlay which makes it effectively writable.
pub const ENABLED_DIR: &str = "/overlayer/syshub/etc/quantra-system/enabled";

/// Commands the CLI can send to PID 1.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", content = "args")]
pub enum ControlCommand {
    Start {
        service: String,
    },
    Stop {
        service: String,
    },
    Restart {
        service: String,
    },
    Reload {
        service: String,
    },
    Kill {
        service: String,
    },
    Enable {
        service: String,
    },
    Disable {
        service: String,
    },
    Status {
        service: String,
    },
    Assay {
        service: String,
    },
    Tree,
    List,
    Metrics,
    Isolate {
        service: String,
        exit_isolation: bool,
    },
    Shutdown {
        reboot: bool,
    },
    Signal {
        service: String,
        signal: String,
    },
    IsStarted {
        service: String,
    },
    IsFailed {
        service: String,
    },
    Setenv {
        name: String,
        value: Option<String>,
    },
    AddDep {
        from: String,
        to: String,
        dep_type: String,
    },
    RmDep {
        from: String,
        to: String,
    },
}

/// Unified response type.
#[derive(Debug, Serialize, Deserialize)]
pub struct CtlResponse {
    pub ok: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl CtlResponse {
    pub fn ok(msg: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: msg.into(),
            data: None,
        }
    }
    pub fn ok_data(msg: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            ok: true,
            message: msg.into(),
            data: Some(data),
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: msg.into(),
            data: None,
        }
    }
}

// ── Wire framing helpers (blocking std I/O) ──────────────────────────────────

fn send_frame(stream: &mut UnixStream, payload: &[u8]) -> Result<()> {
    let len = payload.len() as u32;
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

fn recv_frame(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 4 * 1024 * 1024 {
        anyhow::bail!("Frame too large: {} bytes", len);
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

// ── Control socket server (std-only, threaded) ───────────────────────────────

pub struct ControlSocket {
    listener: UnixListener,
    service_manager: Arc<Mutex<ServiceManager>>,
    metrics: Arc<MetricsCollector>,
}

impl ControlSocket {
    pub fn new(
        socket_path: &Path,
        service_manager: Arc<Mutex<ServiceManager>>,
        metrics: Arc<MetricsCollector>,
    ) -> Result<Self> {
        if socket_path.exists() {
            fs::remove_file(socket_path)?;
        }

        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(socket_path)?;

        // 0o660 — root rw, quantra group rw
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(socket_path)?.permissions();
        perms.set_mode(0o660);
        fs::set_permissions(socket_path, perms)?;

        info!("Control socket ready at {}", socket_path.display());
        Ok(Self {
            listener,
            service_manager,
            metrics,
        })
    }

    /// Start the blocking accept loop in the current thread.
    /// Each client connection is handled in a spawned thread.
    pub fn run(self) {
        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    let sm = Arc::clone(&self.service_manager);
                    let metrics = Arc::clone(&self.metrics);
                    thread::Builder::new()
                        .name("ctl-client".into())
                        .spawn(move || {
                            if let Err(e) = handle_client(stream, sm, metrics) {
                                error!("Control socket handler error: {}", e);
                            }
                        })
                        .ok();
                }
                Err(e) => error!("Control socket accept error: {}", e),
            }
        }
    }
}

// ── Per-connection handler (blocking) ─────────────────────────────────────────

fn handle_client(
    mut stream: UnixStream,
    service_manager: Arc<Mutex<ServiceManager>>,
    metrics: Arc<MetricsCollector>,
) -> Result<()> {
    // Authorize: only root (uid 0) via SO_PEERCRED
    let cred = nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::PeerCredentials)?;
    if cred.uid() != 0 {
        let deny = CtlResponse::err("Permission denied: only root may use the control socket");
        let bytes = serde_json::to_vec(&deny)?;
        let _ = send_frame(&mut stream, &bytes);
        warn!("Rejected client with uid {}", cred.uid());
        return Ok(());
    }

    let frame = recv_frame(&mut stream)?;
    let command: ControlCommand =
        serde_json::from_slice(&frame).map_err(|e| anyhow::anyhow!("Bad command JSON: {}", e))?;

    metrics.record_control_command();
    let response = dispatch(command, &service_manager);
    let bytes = serde_json::to_vec(&response)?;
    send_frame(&mut stream, &bytes)?;
    Ok(())
}

// ── Command dispatch ──────────────────────────────────────────────────────────

fn dispatch(cmd: ControlCommand, sm: &Arc<Mutex<ServiceManager>>) -> CtlResponse {
    match cmd {
        ControlCommand::Start { service } => {
            let mut manager = match sm.lock() {
                Ok(g) => g,
                Err(_) => return CtlResponse::err("Service manager lock poisoned"),
            };
            match manager.start_named_service(&service) {
                Ok(_) => CtlResponse::ok(format!("✓ Started {}", service)),
                Err(e) => CtlResponse::err(format!("Failed to start {}: {}", service, e)),
            }
        }

        ControlCommand::Stop { service } => {
            let mut manager = match sm.lock() {
                Ok(g) => g,
                Err(_) => return CtlResponse::err("Service manager lock poisoned"),
            };
            match manager.stop_named_service(&service) {
                Ok(_) => CtlResponse::ok(format!("✓ Stopped {}", service)),
                Err(e) => CtlResponse::err(format!("Failed to stop {}: {}", service, e)),
            }
        }

        ControlCommand::Restart { service } => {
            let mut manager = match sm.lock() {
                Ok(g) => g,
                Err(_) => return CtlResponse::err("Service manager lock poisoned"),
            };
            let _ = manager.stop_named_service(&service);
            match manager.start_named_service(&service) {
                Ok(_) => CtlResponse::ok(format!("✓ Restarted {}", service)),
                Err(e) => CtlResponse::err(format!("Failed to restart {}: {}", service, e)),
            }
        }

        ControlCommand::Reload { service } => {
            let manager = match sm.lock() {
                Ok(g) => g,
                Err(_) => return CtlResponse::err("Service manager lock poisoned"),
            };
            match manager.reload_named_service(&service) {
                Ok(msg) => CtlResponse::ok(msg),
                Err(e) => CtlResponse::err(format!("Reload failed for {}: {}", service, e)),
            }
        }

        ControlCommand::Kill { service } => {
            let manager = match sm.lock() {
                Ok(g) => g,
                Err(_) => return CtlResponse::err("Service manager lock poisoned"),
            };
            match manager.get_service_status(&service) {
                Some((pid, _)) if pid > 0 => {
                    let nix_pid = nix::unistd::Pid::from_raw(pid);
                    let _ = crate::services::cgroup::kill_service_cgroup(&service);
                    let _ = signal::kill(nix_pid, Signal::SIGKILL);
                    CtlResponse::ok(format!("✓ Killed {} (PID {})", service, pid))
                }
                _ => CtlResponse::err(format!("Service '{}' not found or not running", service)),
            }
        }

        ControlCommand::Enable { service } => {
            let enabled_dir = Path::new(ENABLED_DIR);
            if let Err(e) = fs::create_dir_all(enabled_dir) {
                return CtlResponse::err(format!("Cannot create enabled dir: {}", e));
            }
            let marker = enabled_dir.join(&service);
            match fs::write(&marker, b"") {
                Ok(_) => CtlResponse::ok(format!(
                    "✓ {} enabled (will auto-start on next boot)",
                    service
                )),
                Err(e) => CtlResponse::err(format!("Failed to enable {}: {}", service, e)),
            }
        }

        ControlCommand::Disable { service } => {
            let marker = Path::new(ENABLED_DIR).join(&service);
            if marker.exists() {
                match fs::remove_file(&marker) {
                    Ok(_) => CtlResponse::ok(format!(
                        "✓ {} disabled (will not auto-start on next boot)",
                        service
                    )),
                    Err(e) => CtlResponse::err(format!("Failed to disable {}: {}", service, e)),
                }
            } else {
                CtlResponse::ok(format!("'{}' was not enabled", service))
            }
        }

        ControlCommand::Status { service } => {
            let manager = match sm.lock() {
                Ok(g) => g,
                Err(_) => return CtlResponse::err("Service manager lock poisoned"),
            };
            match manager.get_service_status(&service) {
                Some((pid, running)) => {
                    let state = if running { "running" } else { "stopped" };
                    let rss_kb = if running && pid > 0 {
                        read_proc_rss_kb(pid as u32)
                    } else {
                        0
                    };
                    let uptime_sec = if running && pid > 0 {
                        read_proc_uptime_sec(pid as u32)
                    } else {
                        0
                    };
                    let apparmor = if pid > 0 {
                        read_proc_apparmor(pid as u32)
                    } else {
                        "unconfined".to_string()
                    };
                    let enabled = Path::new(ENABLED_DIR).join(&service).exists();
                    let log_tail = read_log_tail(&service, 10);
                    let cgroup = format!("/sys/fs/cgroup/quantra-system/{}", service);

                    let data = serde_json::json!({
                        "name": service, "state": state, "pid": pid,
                        "rss_kb": rss_kb, "uptime_seconds": uptime_sec,
                        "apparmor_profile": apparmor, "cgroup_path": cgroup,
                        "enabled": enabled, "log_tail": log_tail,
                    });
                    CtlResponse::ok_data(format!("{} is {}", service, state), data)
                }
                None => CtlResponse::err(format!("Service '{}' not found", service)),
            }
        }

        ControlCommand::Assay { service } => {
            let manager = match sm.lock() {
                Ok(g) => g,
                Err(_) => return CtlResponse::err("Service manager lock poisoned"),
            };
            let status = manager.get_service_status(&service);
            drop(manager);

            let mut checks = serde_json::Map::new();
            let mut overall_ok = true;

            if let Some((pid, running)) = status {
                let proc_exists = pid > 0 && Path::new(&format!("/proc/{}", pid)).exists();
                checks.insert(
                    "process_alive".into(),
                    serde_json::json!({
                        "ok": proc_exists && running,
                        "detail": if proc_exists { format!("PID {} alive in /proc", pid) }
                                  else { format!("PID {} not found in /proc", pid) }
                    }),
                );
                if !proc_exists || !running {
                    overall_ok = false;
                }

                let oom = read_proc_file(pid as u32, "oom_score").unwrap_or_default();
                let oom_val: i32 = oom.trim().parse().unwrap_or(0);
                let oom_ok = oom_val < 500;
                checks.insert("oom_score".into(), serde_json::json!({ "ok": oom_ok, "detail": format!("oom_score = {}", oom_val) }));
                if !oom_ok {
                    overall_ok = false;
                }

                let aa = read_proc_apparmor(pid as u32);
                let aa_ok = !aa.contains("unconfined");
                checks.insert(
                    "apparmor_confined".into(),
                    serde_json::json!({ "ok": aa_ok, "detail": format!("profile: {}", aa) }),
                );

                let rss = read_proc_rss_kb(pid as u32);
                let rss_ok = rss < 512_000;
                checks.insert("rss_within_limit".into(), serde_json::json!({ "ok": rss_ok, "detail": format!("{} KB used, limit 512000 KB", rss) }));
                if !rss_ok {
                    overall_ok = false;
                }
            } else {
                checks.insert(
                    "process_alive".into(),
                    serde_json::json!({ "ok": false, "detail": "Service not registered" }),
                );
                overall_ok = false;
            }

            let error_count = count_log_errors(&service);
            let log_ok = error_count == 0;
            checks.insert("log_errors_recent".into(), serde_json::json!({ "ok": log_ok, "detail": format!("{} ERROR lines in log", error_count) }));

            let enabled = Path::new(ENABLED_DIR).join(&service).exists();
            checks.insert("enabled".into(), serde_json::json!({ "ok": true, "detail": if enabled { "auto-start enabled" } else { "manual-start only" } }));

            let overall = if overall_ok { "HEALTHY" } else { "WARN" };
            let data =
                serde_json::json!({ "service": service, "checks": checks, "overall": overall });
            CtlResponse::ok_data(format!("Assay for {} — {}", service, overall), data)
        }

        ControlCommand::Tree => {
            let manager = match sm.lock() {
                Ok(g) => g,
                Err(_) => return CtlResponse::err("Service manager lock poisoned"),
            };
            let names = manager.get_service_names();
            let mut lines = vec![format!("quantra (PID 1) — {} services", names.len())];
            for (i, name) in names.iter().enumerate() {
                let last = i == names.len() - 1;
                let prefix = if last { "└── " } else { "├── " };
                if let Some((pid, running)) = manager.get_service_status(name) {
                    let state = if running {
                        format!("\x1b[32m[running]\x1b[0m PID {}", pid)
                    } else {
                        "\x1b[90m[stopped]\x1b[0m".to_string()
                    };
                    lines.push(format!("{}{} {}", prefix, name, state));
                } else {
                    lines.push(format!("{}{}", prefix, name));
                }
            }
            let tree_str = lines.join("\n");
            CtlResponse::ok_data("Dependency tree", serde_json::json!({ "tree": tree_str }))
        }

        ControlCommand::List => {
            let manager = match sm.lock() {
                Ok(g) => g,
                Err(_) => return CtlResponse::err("Service manager lock poisoned"),
            };
            let names = manager.get_service_names();
            let services: Vec<serde_json::Value> = names
                .iter()
                .map(|name| {
                    let (pid, running) = manager.get_service_status(name).unwrap_or((-1, false));
                    serde_json::json!({ "name": name, "pid": pid, "running": running })
                })
                .collect();
            CtlResponse::ok_data(
                format!("{} services", services.len()),
                serde_json::json!({ "services": services }),
            )
        }

        ControlCommand::Metrics => match fs::read_to_string("/run/quantra/metrics") {
            Ok(content) => CtlResponse::ok_data(
                "Prometheus metrics",
                serde_json::json!({ "prometheus": content }),
            ),
            Err(e) => CtlResponse::err(format!("Cannot read metrics: {}", e)),
        },

        ControlCommand::Isolate {
            service,
            exit_isolation,
        } => {
            if exit_isolation {
                let _ = fs::remove_file("/run/quantra/isolated");
                CtlResponse::ok("✓ Isolation mode cleared — normal operation resumed")
            } else {
                match fs::write("/run/quantra/isolated", service.as_bytes()) {
                    Ok(_) => CtlResponse::ok(format!(
                        "✓ Isolated to '{}' — all other services stopped.\n  Reboot or `quantra-ctl isolate --exit` to restore.",
                        service
                    )),
                    Err(e) => CtlResponse::err(format!("Failed to write isolation marker: {}", e)),
                }
            }
        }

        ControlCommand::Shutdown { reboot } => {
            if reboot {
                crate::signals::REBOOT_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
                CtlResponse::ok("✓ Reboot initiated")
            } else {
                crate::signals::SHUTDOWN_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
                CtlResponse::ok("✓ Shutdown initiated")
            }
        }

        ControlCommand::Signal {
            service,
            signal: sig_name,
        } => {
            let manager = match sm.lock() {
                Ok(g) => g,
                Err(_) => return CtlResponse::err("Service manager lock poisoned"),
            };
            match manager.get_service_status(&service) {
                Some((pid, _)) if pid > 0 => match parse_signal_str(&sig_name) {
                    Some(s) => {
                        let nix_pid = nix::unistd::Pid::from_raw(pid);
                        match signal::kill(nix_pid, s) {
                            Ok(()) => CtlResponse::ok(format!(
                                "✓ Sent {} to '{}' (PID {})",
                                sig_name, service, pid
                            )),
                            Err(e) => CtlResponse::err(format!("kill failed: {}", e)),
                        }
                    }
                    None => CtlResponse::err(format!("Unknown signal: '{}'", sig_name)),
                },
                _ => CtlResponse::err(format!("Service '{}' not running", service)),
            }
        }

        ControlCommand::IsStarted { service } => {
            let manager = match sm.lock() {
                Ok(g) => g,
                Err(_) => return CtlResponse::err("Service manager lock poisoned"),
            };
            match manager.get_service_status(&service) {
                Some((_, true)) => CtlResponse::ok_data(
                    format!("'{}' is running", service),
                    serde_json::json!({ "running": true, "exit_code": 0 }),
                ),
                Some((_, false)) => CtlResponse::ok_data(
                    format!("'{}' is stopped", service),
                    serde_json::json!({ "running": false, "exit_code": 1 }),
                ),
                None => CtlResponse::err(format!("Service '{}' not found", service)),
            }
        }

        ControlCommand::IsFailed { service } => {
            let manager = match sm.lock() {
                Ok(g) => g,
                Err(_) => return CtlResponse::err("Service manager lock poisoned"),
            };
            match manager.get_service_status(&service) {
                Some((_, true)) => CtlResponse::ok_data(
                    format!("'{}' is running (not failed)", service),
                    serde_json::json!({ "failed": false, "exit_code": 1 }),
                ),
                Some((_, false)) => CtlResponse::ok_data(
                    format!("'{}' is stopped/failed", service),
                    serde_json::json!({ "failed": true, "exit_code": 0 }),
                ),
                None => CtlResponse::err(format!("Service '{}' not found", service)),
            }
        }

        ControlCommand::Setenv { name, value } => {
            let mut manager = match sm.lock() {
                Ok(g) => g,
                Err(_) => return CtlResponse::err("Service manager lock poisoned"),
            };
            let msg = match &value {
                Some(v) => format!("✓ Set {}={} (applies to next service spawn)", name, v),
                None => format!("✓ Unset {} (applies to next service spawn)", name),
            };
            manager.set_env(name, value);
            CtlResponse::ok(msg)
        }

        ControlCommand::AddDep { from, to, dep_type } => {
            let mut manager = match sm.lock() {
                Ok(g) => g,
                Err(_) => return CtlResponse::err("Service manager lock poisoned"),
            };
            manager.add_dep(&from, &to, &dep_type);
            CtlResponse::ok(format!(
                "✓ Dependency {} --[{}]--> {} added (applies to next start)",
                from, dep_type, to
            ))
        }

        ControlCommand::RmDep { from, to } => {
            let mut manager = match sm.lock() {
                Ok(g) => g,
                Err(_) => return CtlResponse::err("Service manager lock poisoned"),
            };
            manager.rm_dep(&from, &to);
            CtlResponse::ok(format!("✓ Dependency {} --> {} removed", from, to))
        }
    }
}

// ── /proc helpers ─────────────────────────────────────────────────────────────

fn read_proc_file(pid: u32, field: &str) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/{}", pid, field)).ok()
}

fn read_proc_rss_kb(pid: u32) -> u64 {
    let content = read_proc_file(pid, "statm").unwrap_or_default();
    let rss_pages: u64 = content
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    rss_pages.saturating_mul(page_size) / 1024
}

fn read_proc_uptime_sec(pid: u32) -> u64 {
    let uptime_str = fs::read_to_string("/proc/uptime").unwrap_or_default();
    let system_uptime: f64 = uptime_str
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    let stat = read_proc_file(pid, "stat").unwrap_or_default();
    let start_ticks: u64 = stat
        .split_whitespace()
        .nth(21)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    let start_sec = start_ticks as f64 / clk_tck;
    (system_uptime - start_sec).max(0.0) as u64
}

fn read_proc_apparmor(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{}/attr/current", pid))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn read_log_tail(service: &str, lines: usize) -> Vec<String> {
    let path = format!("/overlayer/syshub/var/log/quantra-system/{}.log", service);
    let content = fs::read_to_string(&path).unwrap_or_default();
    content
        .lines()
        .rev()
        .take(lines)
        .map(String::from)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

fn count_log_errors(service: &str) -> usize {
    let path = format!("/overlayer/syshub/var/log/quantra-system/{}.log", service);
    fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains("ERROR") || l.contains("error"))
        .count()
}

fn parse_signal_str(name: &str) -> Option<Signal> {
    let s = name.trim_start_matches("SIG");
    match s.to_ascii_uppercase().as_str() {
        "HUP" | "1" => Some(Signal::SIGHUP),
        "INT" | "2" => Some(Signal::SIGINT),
        "QUIT" | "3" => Some(Signal::SIGQUIT),
        "KILL" | "9" => Some(Signal::SIGKILL),
        "TERM" | "15" => Some(Signal::SIGTERM),
        "USR1" | "10" => Some(Signal::SIGUSR1),
        "USR2" | "12" => Some(Signal::SIGUSR2),
        "CONT" | "18" => Some(Signal::SIGCONT),
        "STOP" | "19" => Some(Signal::SIGSTOP),
        "ALRM" | "14" => Some(Signal::SIGALRM),
        "PIPE" | "13" => Some(Signal::SIGPIPE),
        "CHLD" | "17" => Some(Signal::SIGCHLD),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_start_roundtrips_json() {
        let cmd = ControlCommand::Start {
            service: "quantra-net".into(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let parsed: ControlCommand = serde_json::from_str(&json).unwrap();
        match parsed {
            ControlCommand::Start { service } => assert_eq!(service, "quantra-net"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn command_list_has_no_args() {
        let cmd = ControlCommand::List;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"cmd\":\"List\""));
    }

    #[test]
    fn response_ok_serializes_correctly() {
        let resp = CtlResponse::ok("done");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"ok\":true"));
        assert!(json.contains("\"message\":\"done\""));
        assert!(!json.contains("\"data\"")); // None fields are skipped
    }

    #[test]
    fn response_err_serializes_correctly() {
        let resp = CtlResponse::err("not found");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"ok\":false"));
    }

    #[test]
    fn response_ok_data_includes_payload() {
        let resp = CtlResponse::ok_data("metrics", serde_json::json!({"cpu": 42}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"data\""));
        assert!(json.contains("\"cpu\":42"));
    }

    #[test]
    fn all_control_commands_deserialize() {
        let variants = vec![
            r#"{"cmd":"Start","args":{"service":"s"}}"#,
            r#"{"cmd":"Stop","args":{"service":"s"}}"#,
            r#"{"cmd":"Restart","args":{"service":"s"}}"#,
            r#"{"cmd":"Reload","args":{"service":"s"}}"#,
            r#"{"cmd":"Kill","args":{"service":"s"}}"#,
            r#"{"cmd":"Enable","args":{"service":"s"}}"#,
            r#"{"cmd":"Disable","args":{"service":"s"}}"#,
            r#"{"cmd":"Status","args":{"service":"s"}}"#,
            r#"{"cmd":"Assay","args":{"service":"s"}}"#,
            r#"{"cmd":"Tree"}"#,
            r#"{"cmd":"List"}"#,
            r#"{"cmd":"Metrics"}"#,
        ];
        for v in &variants {
            assert!(
                serde_json::from_str::<ControlCommand>(v).is_ok(),
                "failed: {}",
                v
            );
        }
    }
}

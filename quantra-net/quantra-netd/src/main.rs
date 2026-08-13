//! # quantra-netd
//!
//! The Zainium OS network daemon.
// Author: Ali-Zain <alizain.x404@gmail.com>

use anyhow::{Context, Result};
use common::{NetCommand, NetResponse, SOCKET_PATH, recv_message, send_message};
use rtnetlink::{Handle, new_connection};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::Ordering;
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

mod autoconfig;
mod bridge;
mod config;
mod dhcp;
mod dispatch;
mod exec;
mod firewall;
mod ipv6;
mod netlink;
mod netns;
mod quality;
mod resolver;
mod routing;
mod vpn;
mod wifi;
mod wireguard;

use dispatch::{ACTIVE_CONNECTIONS, execute_command};
use exec::{Exec, RealExec};

const ALLOWED_UIDS_ENV: &str = "QUANTRA_NETD_ALLOWED_UIDS";
#[allow(dead_code)]
const EXPECTED_INIT_SECCOMP_PROFILE: &str = "network-daemon";

fn apply_runtime_hardening() {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        warn!(
            "Failed to set PR_SET_NO_NEW_PRIVS: {}",
            std::io::Error::last_os_error()
        );
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        warn!(
            "Failed to set PR_SET_DUMPABLE: {}",
            std::io::Error::last_os_error()
        );
    }
}

fn parse_uid_list(raw: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for token in raw.split(',') {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(uid) = trimmed.parse::<u32>() {
            out.push(uid);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn load_extra_allowed_uids() -> Vec<u32> {
    let raw = match std::env::var(ALLOWED_UIDS_ENV) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    for token in raw.split(',') {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.parse::<u32>().is_err() {
            warn!(
                "Ignoring invalid uid '{}' from {}",
                trimmed, ALLOWED_UIDS_ENV
            );
        }
    }
    parse_uid_list(&raw)
}

fn peer_uid_is_authorized(peer_uid: u32, daemon_uid: u32, extra_allowed_uids: &[u32]) -> bool {
    peer_uid == 0 || peer_uid == daemon_uid || extra_allowed_uids.contains(&peer_uid)
}

fn authorize_peer(stream: &UnixStream) -> Result<()> {
    let creds = stream
        .peer_cred()
        .context("Failed to fetch Unix peer credentials")?;
    let peer_uid = creds.uid();
    let peer_gid = creds.gid();
    let daemon_uid = unsafe { libc::geteuid() } as u32;
    let extra_allowed = load_extra_allowed_uids();
    if peer_uid_is_authorized(peer_uid, daemon_uid, &extra_allowed) {
        debug!(peer_uid, peer_gid, daemon_uid, "Accepted peer credentials");
        return Ok(());
    }
    anyhow::bail!(
        "peer uid {} gid {} is not authorized (daemon uid {}, extra allowed via {}='{}')",
        peer_uid,
        peer_gid,
        daemon_uid,
        ALLOWED_UIDS_ENV,
        std::env::var(ALLOWED_UIDS_ENV).unwrap_or_default()
    )
}

// ── Entry Point ───────────────────────────────────────────────────────────────

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        socket = SOCKET_PATH,
        "quantra-netd starting"
    );
    apply_runtime_hardening();

    let (netlink_conn, handle, _messages) =
        new_connection().context("Failed to open rtnetlink connection")?;
    tokio::spawn(netlink_conn);
    debug!("rtnetlink connection established");

    if let Err(e) = config::load_config_into_kernel(&handle).await {
        warn!("Could not auto-load persisted config: {e:#}");
    }

    if !quality::ping_internet().await {
        match autoconfig::auto_configure_once(&handle).await {
            Ok(()) => info!("Auto-config attempt on startup completed"),
            Err(e) => warn!("Auto-config attempt on startup failed: {e:#}"),
        }
        autoconfig::ensure_self_heal_started(handle.clone());
    }

    let socket_path = Path::new(SOCKET_PATH);
    if socket_path.exists() {
        std::fs::remove_file(socket_path)
            .with_context(|| format!("Failed to remove stale socket at {SOCKET_PATH}"))?;
        warn!("Removed stale socket from a previous run");
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create socket directory {:?}", parent))?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("Failed to harden socket directory {:?}", parent))?;
    }
    let listener = UnixListener::bind(SOCKET_PATH)
        .with_context(|| format!("Failed to bind Unix socket at {SOCKET_PATH}"))?;
    std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to harden socket permissions at {SOCKET_PATH}"))?;

    let _socket_guard = SocketCleanupGuard;
    info!("Listening on {SOCKET_PATH}");

    let mut sigint = signal(SignalKind::interrupt()).context("Failed to install SIGINT handler")?;
    let mut sigterm =
        signal(SignalKind::terminate()).context("Failed to install SIGTERM handler")?;

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _)) => {
                        let handle = handle.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, handle).await {
                                error!("Client handler error: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
            _ = sigint.recv() => { info!("SIGINT received — shutting down"); break; }
            _ = sigterm.recv() => { info!("SIGTERM received — shutting down"); break; }
        }
    }

    info!("quantra-netd stopped");
    Ok(())
}

// ── Per-Connection Handler ────────────────────────────────────────────────────

struct ConnectionGuard;

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn handle_client(mut stream: UnixStream, handle: Handle) -> Result<()> {
    if let Err(e) = authorize_peer(&stream) {
        warn!("Rejected unauthorized client: {e:#}");
        let deny = NetResponse::Error(format!("Permission denied: {e}"));
        let _ =
            tokio::time::timeout(Duration::from_secs(5), send_message(&mut stream, &deny)).await;
        return Ok(());
    }

    ACTIVE_CONNECTIONS.fetch_add(1, Ordering::SeqCst);
    let mut cfg = config::read_config().unwrap_or_default();
    cfg.total_connections = cfg.total_connections.saturating_add(1);
    let total = cfg.total_connections;
    let _ = config::upsert_config(cfg);
    let active = ACTIVE_CONNECTIONS.load(Ordering::SeqCst);
    info!("New client; active={active}, total={total}");
    let _guard = ConnectionGuard;

    let timeout = Duration::from_secs(30);
    let command: NetCommand = tokio::time::timeout(timeout, recv_message(&mut stream))
        .await
        .context("Timed out waiting for command")?
        .map_err(|e| anyhow::anyhow!("Failed to deserialise command: {e}"))?;

    debug!(?command, "Received command");
    let exec: std::sync::Arc<dyn Exec> = std::sync::Arc::new(RealExec);
    let response = execute_command(&handle, exec.as_ref(), command).await;

    tokio::time::timeout(timeout, send_message(&mut stream, &response))
        .await
        .context("Timed out sending response")?
        .map_err(|e| anyhow::anyhow!("Failed to send response: {e}"))?;
    Ok(())
}

// ── Socket Cleanup ───────────────────────────────────────────────────────────

struct SocketCleanupGuard;

impl Drop for SocketCleanupGuard {
    fn drop(&mut self) {
        if Path::new(SOCKET_PATH).exists() {
            if let Err(e) = std::fs::remove_file(SOCKET_PATH) {
                eprintln!("Warning: could not remove socket at {SOCKET_PATH}: {e}");
            } else {
                eprintln!("Removed socket at {SOCKET_PATH}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uid_list_ignores_invalid_and_deduplicates() {
        let parsed = parse_uid_list("0, 1000,invalid,1000,42,, ");
        assert_eq!(parsed, vec![0, 42, 1000]);
    }

    #[test]
    fn peer_uid_authorization_rules_are_enforced() {
        let extra = vec![1001, 2000];
        assert!(peer_uid_is_authorized(0, 1000, &extra));
        assert!(peer_uid_is_authorized(1000, 1000, &extra));
        assert!(peer_uid_is_authorized(2000, 1000, &extra));
        assert!(!peer_uid_is_authorized(3000, 1000, &extra));
    }

    #[test]
    fn expected_init_seccomp_profile_is_network_daemon() {
        assert_eq!(EXPECTED_INIT_SECCOMP_PROFILE, "network-daemon");
    }
}

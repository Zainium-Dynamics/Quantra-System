mod control;
mod dbus_bridge;
mod elevate_session;
mod inhibitor;
mod power;
mod seat;
mod session;
mod types;
mod user;
mod utmp;

use anyhow::{Context, Result};
use control::ControlServer;
use inhibitor::InhibitorManager;
use power::PowerManager;
use seat::SeatManager;
use session::SessionManager;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use types::LogindConfig;
use user::UserManager;

pub const SOCKET_PATH: &str = "/run/quantra-logind/control";
pub const RUNTIME_DIR_BASE: &str = "/run/user";
pub const CONFIG_PATH: &str = "/overlayer/syshub/etc/quantra-system/logind.conf";
pub const LINGER_DIR: &str = "/overlayer/syshub/var/lib/quantra-logind/linger";

fn main() -> ! {
    setup_logging();
    log::info!("quantra-logind v{} starting", env!("CARGO_PKG_VERSION"));
    log::info!("Compatible: login1 API | COSMIC | portals | elevate-pam (no classic pam.d/libpam)");

    if let Err(e) = run() {
        log::error!("fatal: {:#}", e);
        std::process::exit(1);
    }
    unreachable!();
}

fn run() -> Result<()> {
    // ── Load configuration ────────────────────────────────────────────────────
    let config = LogindConfig::load(CONFIG_PATH);
    log::debug!("Config loaded from {}", CONFIG_PATH);

    // ── Runtime directories ───────────────────────────────────────────────────
    fs::create_dir_all("/run/quantra-logind").context("create /run/quantra-logind")?;
    fs::create_dir_all(RUNTIME_DIR_BASE).context("create /run/user")?;
    fs::create_dir_all(LINGER_DIR).context("create linger dir")?;

    // ── utmp boot record ─────────────────────────────────────────────────────
    utmp::write_boot_time();

    // ── Shared state ──────────────────────────────────────────────────────────
    let sessions = Arc::new(Mutex::new(SessionManager::new()));
    let users = Arc::new(Mutex::new(UserManager::new()));
    let seats = Arc::new(Mutex::new(SeatManager::new()));
    let inhibitors = Arc::new(Mutex::new(InhibitorManager::new()));
    let power = Arc::new(Mutex::new(PowerManager::new(config.clone())));

    // ── Seat detection ────────────────────────────────────────────────────────
    seats.lock().unwrap().detect().context("seat detection")?;

    // ── Restore linger state ──────────────────────────────────────────────────
    users.lock().unwrap().load_linger_state();

    // ── elevate-pam stacks (TOML only — never /etc/pam.d) ─────────────────────
    if let Err(e) = elevate_session::write_elevate_pam_stacks() {
        log::warn!("elevate-pam stacks: {e}");
    }

    // ── D-Bus bridge (org.freedesktop.login1 for COSMIC / portals / polkit) ───
    // System bus must already be up (Quantra service `dbus`).
    dbus_bridge::write_dbus_service_file("/overlayer/syshub/engine/quantra-logind").ok();
    dbus_bridge::write_dbus_policy_file().ok();
    dbus_bridge::write_portal_config("cosmic").ok();
    dbus_bridge::start_dbus_bridge();

    // ── ACPI event handler ────────────────────────────────────────────────────
    power::start_acpi_handler(config.clone(), Arc::clone(&power), Arc::clone(&inhibitors));

    // ── IdleAction enforcement timer ──────────────────────────────────────────
    power::start_idle_timer(
        config.clone(),
        Arc::clone(&power),
        Arc::clone(&inhibitors),
        Arc::clone(&sessions),
    );

    // ── Control socket ────────────────────────────────────────────────────────
    let _ = fs::remove_file(SOCKET_PATH);
    let listener =
        UnixListener::bind(SOCKET_PATH).with_context(|| format!("bind {}", SOCKET_PATH))?;
    fs::set_permissions(SOCKET_PATH, fs::Permissions::from_mode(0o660)).ok();

    log::info!("Socket: {}", SOCKET_PATH);
    log::info!("D-Bus:  org.freedesktop.login1");
    log::info!("Seats:  {}", seats.lock().unwrap().list().join(", "));

    // ── READY=1 → Quantra supervisor ─────────────────────────────────────────
    notify_ready();

    // ── Block forever ─────────────────────────────────────────────────────────
    ControlServer::new(listener, sessions, users, seats, inhibitors, power, config).run()
}

fn notify_ready() {
    if let Ok(path) = std::env::var("NOTIFY_SOCKET") {
        use std::os::unix::net::UnixDatagram;
        if let Ok(sock) = UnixDatagram::unbound() {
            let _ = sock.send_to(b"READY=1\n", &path);
            log::debug!("READY=1 → {}", path);
        }
    }
}

fn setup_logging() {
    let level = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| "info".to_string())
        .parse()
        .unwrap_or(log::LevelFilter::Info);
    env_logger::Builder::new()
        .filter_level(level)
        .format_timestamp_secs()
        .init();
}

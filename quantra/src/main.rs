mod config;
mod control;
mod coredump;
mod dbus;
mod environment;
mod firstboot;
mod journald;
mod kernel;
mod logging;
mod metrics;
mod mounts;
mod network;
mod panic;
mod phases;
mod process;
mod random_seed;
mod sandbox;
mod security;
mod services;
mod shutdown;
mod signals;
mod timesyncd;
mod tmpfiles;
mod utils;
mod vconsole;

use crate::config::InitConfig;
use anyhow::{Context, Result};
use log::warn;
use phases::{InitPhase, set_phase};
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Zainium Init — PID 1 System Manager
///
/// # Boot Sequence (11-phase)
///
/// 0.  `environment::apply_to_process_env()` — native hybrid env (see environment.rs)
/// 1.  `mounts::setup()`              — procfs, sysfs, devtmpfs, cgroups
/// 2.  `logging::setup()`             — stderr + /overlayer/syshub/var/log/quantra-system/init.log
/// 3.  `security::apparmor::load()`   — load all profiles from /overlayer/syshub/etc/apparmor.d/
///     3b. `security::lockdown()`         — kernel lockdown + mlockall
/// 4.  `kernel::setup()`              — hostname, sysctl, modules, cgroup controllers
/// 5.  `network::configure_all()`     — lo up, static IP or DHCP client spawn
/// 6.  `signals::setup()` + reaper     — SA_RESTART handlers + pipe exit-code reaper
/// 7.  `mount_units::activate_all()`  — /data, /home NFS, etc.
/// 8.  `services::start_all()`        — parallel waves + AppArmor + cgroups + notify
/// 9.  `control::start_socket()`      — Unix socket for runtime service control
/// 10. `timer::start_all_timers()`    — cron replacement
/// 11. `launcher::start_optional_launcher()` — LightDM / graphical bridge
///
/// # Resource Guarantees
/// - Binary:  1.1MB static-pie musl
/// - Memory:  ~5MB RSS
/// - FDs:     max 256
/// - Signals: all 64 POSIX signals handled safely
fn main() -> ! {
    let boot_start = Instant::now();
    set_phase(InitPhase::STARTUP);

    println!("  Zainium Init PID 1 v{}", env!("ZAI_INIT_VERSION"));
    println!(
        "   Build: {} ({})",
        env!("BUILD_COMMIT"),
        env!("BUILD_TARGET")
    );
    println!("   Optimization: {}", env!("OPTIMIZATION"));
    println!("   Starting system initialization...\n");

    // Initialize metrics collector
    let metrics_collector = metrics::MetricsCollector::new();
    Arc::clone(&metrics_collector).start_background_updater();

    // Emergency panic hook — drop to shell on unrecoverable error
    panic::setup();

    // Native environment — Zainium's replacement for /etc/profile.d.
    // Set on PID 1 itself, before anything is spawned, so every child
    // inherits it through normal fork/exec. See environment.rs.
    environment::apply_to_process_env();

    // Phase 1: Essential filesystem mounts
    set_phase(InitPhase::MOUNTS);
    let t = Instant::now();
    if let Err(e) = mounts::setup() {
        eprintln!("\x1b[1;31m[FATAL] Mounts failed: {}\x1b[0m", e);
        panic::emergency_shell();
    }
    eprintln!("  [ {:>5}ms] mounts", t.elapsed().as_millis());

    // tmpfiles.d — create /run /tmp /var dirs, set permissions
    let t = Instant::now();
    if let Err(e) = tmpfiles::apply_all() {
        warn!("tmpfiles: {}", e);
    }
    eprintln!("  [ {:>5}ms] tmpfiles.d", t.elapsed().as_millis());

    // Restore entropy seed early (before any crypto operations)
    random_seed::restore();

    if let Err(e) = run(Arc::clone(&metrics_collector)) {
        eprintln!("\x1b[1;31m[CRITICAL] Zainium Init failed: {}\x1b[0m", e);
        panic::emergency_shell();
    }

    set_phase(InitPhase::READY);
    eprintln!(
        "\n  Total PID 1 boot: {}ms",
        boot_start.elapsed().as_millis()
    );

    warn!("Init reached unexpected end — entering safety park");
    loop {
        std::thread::park();
    }
}

fn run(metrics_collector: std::sync::Arc<metrics::MetricsCollector>) -> Result<()> {
    // Phase 2: Logging
    set_phase(InitPhase::LOGGING);
    let t = Instant::now();
    logging::setup(&InitConfig::default()).ok();
    log::info!("Zainium OS Init Engine starting");
    eprintln!("  [ {:>5}ms] logging", t.elapsed().as_millis());

    let mut cfg = InitConfig::default();
    if let Ok(file_cfg) = config::load("/overlayer/syshub/etc/quantra-system/init.toml") {
        cfg = file_cfg;
        log::info!("Loaded /overlayer/syshub/etc/quantra-system/init.toml");
    }

    utils::ensure_zainium_dirs()?;

    // First boot setup (machine-id, SSH keys, default configs)
    firstboot::run_if_needed();

    // Virtual console setup (keymap + font) — non-fatal
    if cfg.features.vt_support {
        vconsole::setup();
    }

    // Phase 3: AppArmor — load profiles BEFORE any service starts
    let t = Instant::now();
    security::apparmor::load_all_profiles()
        .unwrap_or_else(|e| log::warn!("AppArmor: {} (non-fatal)", e));
    eprintln!("  [ {:>5}ms] apparmor profiles", t.elapsed().as_millis());

    // Phase 3b: Kernel lockdown + memory locking (PID 1 security hardening)
    let t = Instant::now();
    // Kernel lockdown — prevent even root from modifying kernel space
    match std::fs::write("/sys/kernel/security/lockdown", "integrity") {
        Ok(()) => log::info!("Kernel lockdown: integrity mode enabled"),
        Err(e) => log::warn!(
            "Kernel lockdown: {} (non-fatal — kernel may not support it)",
            e
        ),
    }
    // mlockall — prevent PID 1 memory from ever being swapped to disk
    let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if rc == 0 {
        log::info!("mlockall: PID 1 memory locked (no swap)");
    } else {
        log::warn!("mlockall: {} (non-fatal)", std::io::Error::last_os_error());
    }
    eprintln!("  [ {:>5}ms] security lockdown", t.elapsed().as_millis());

    // Phase 4: Kernel parameters
    set_phase(InitPhase::KERNEL);
    let t = Instant::now();
    kernel::setup(&cfg).context("Kernel setup failed")?;
    eprintln!("  [ {:>5}ms] kernel", t.elapsed().as_millis());

    // Journal socket listener (structured logging)
    let t = Instant::now();
    if let Ok(journal_writer) = journald::JournalWriter::new() {
        journald::start_socket_listener(journal_writer);
        eprintln!("  [ {:>5}ms] journald socket", t.elapsed().as_millis());
    }

    // Core dump handler setup
    let core_handler = "/overlayer/syshub/engine/quantra-coredump";
    if std::path::Path::new(core_handler).exists() {
        coredump::ensure_coredump_dir().ok();
        coredump::install_core_pattern(core_handler).ok();
    }

    // Phase 5: Network interfaces
    let t = Instant::now();
    network::manager::configure_all().unwrap_or_else(|e| log::warn!("Network: {} (non-fatal)", e));
    eprintln!("  [ {:>5}ms] network", t.elapsed().as_millis());

    // NTP time sync (after network is up)
    let t = Instant::now();
    timesyncd::sync_clock();
    eprintln!("  [ {:>5}ms] ntp sync", t.elapsed().as_millis());

    // Phase 6: Signal handlers + SIGCHLD reaper thread
    set_phase(InitPhase::SIGNALS);
    let t = Instant::now();
    signals::setup().context("Signal setup failed")?;
    signals::start_reaper_thread().context("SIGCHLD reaper failed")?;
    eprintln!("  [ {:>5}ms] signals + reaper", t.elapsed().as_millis());

    // Phase 7: Mount units (user-space mounts from /overlayer/syshub/etc/quantra-system/mounts/)
    let t = Instant::now();
    {
        use mounts::manager::activate_all_mount_units;
        activate_all_mount_units();
    }
    eprintln!("  [ {:>5}ms] mount units", t.elapsed().as_millis());

    // Phase 8: System services (parallel waves + AppArmor + cgroups + sd_notify)
    set_phase(InitPhase::SERVICES);
    let t = Instant::now();
    log::info!("Launching services from '{}'", cfg.services_dir);
    let service_manager = Arc::new(Mutex::new(
        services::manager::start_all(&cfg, Arc::clone(&metrics_collector))
            .context("Service manager failed")?,
    ));
    eprintln!("  [ {:>5}ms] services", t.elapsed().as_millis());

    // Phase 9: Control socket for runtime service management (std-only, no tokio)
    let t = Instant::now();
    let control_socket_path = Path::new("/run/quantra/control");
    std::fs::create_dir_all(control_socket_path.parent().unwrap())?;
    let control_socket = control::ControlSocket::new(
        control_socket_path,
        Arc::clone(&service_manager),
        Arc::clone(&metrics_collector),
    )?;

    // Blocking accept loop in a dedicated OS thread — zero async overhead
    let _control_handle = std::thread::Builder::new()
        .name("ctl-accept".into())
        .spawn(move || control_socket.run())
        .context("Control socket thread failed")?;
    eprintln!("  [ {:>5}ms] control socket", t.elapsed().as_millis());

    // (D-Bus server removed — Quantra uses JSON-over-Unix-socket exclusively)

    // Phase 10: Timer units (cron replacement)
    let t = Instant::now();
    let (timer_tx, timer_rx) = mpsc::channel::<String>();
    services::timer::start_activation_dispatcher(Arc::clone(&service_manager), timer_rx);
    {
        let timers = services::timer::load_all_timers();
        if !timers.is_empty() {
            services::timer::start_all_timers(timers, timer_tx.clone());
        }
    }
    eprintln!("  [ {:>5}ms] timer units", t.elapsed().as_millis());

    // Phase 12: Optional graphical bridge / display manager launcher
    set_phase(InitPhase::LAUNCHER);
    let t = Instant::now();
    services::launcher::start_post_boot_launchers(&cfg.services_dir);
    eprintln!("  [ {:>5}ms] launcher", t.elapsed().as_millis());

    log::info!("Zainium Init fully active — all 11 boot phases complete");
    set_phase(InitPhase::READY);

    // Wait for shutdown / reboot signal
    let shutdown_action = shutdown::wait_for_shutdown_signal().context("Shutdown watcher error")?;

    set_phase(InitPhase::SHUTDOWN);
    log::info!("Shutdown requested: {:?}", shutdown_action);
    // Save entropy for next boot
    random_seed::save();
    drop(timer_tx);
    if let Ok(mut guard) = service_manager.lock() {
        guard.stop_all();
    } else {
        log::error!("Service manager lock poisoned during shutdown");
    }
    shutdown::execute(shutdown_action);
}

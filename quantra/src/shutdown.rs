/// System shutdown coordination module
///
/// Handles graceful system shutdown by watching atomic flags set by signal handlers:
/// - `SHUTDOWN_REQUESTED` (set by SIGTERM, SIGINT, SIGPWR handlers in signals.rs)
/// - `REBOOT_REQUESTED` (set by SIGUSR1 handler in signals.rs)
///
/// Uses `libc::pause()` to sleep until any signal is delivered, then checks atomics.
/// This avoids the POSIX conflict where `sigwait(2)` races with `sigaction` handlers
/// registered for the same signal numbers.
use anyhow::Result;
use log::{info, warn};
use nix::sys::reboot::RebootMode;
use std::sync::atomic::Ordering;

use crate::signals::{REBOOT_REQUESTED, SHUTDOWN_REQUESTED};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownAction {
    PowerOff,
    Reboot,
}

/// Block until a shutdown or reboot signal is received, then execute it.
///
/// `libc::pause()` suspends until any signal is delivered and its handler returns.
/// Our `handle_shutdown()` / `handle_reboot()` handlers set atomic flags before
/// returning, so the loop will see the flag immediately after `pause()` returns.
///
/// **POSIX guarantee:** `pause(2)` is async-signal-safe and works correctly with
/// `sigaction`-registered handlers. No race with `sigwait`.
pub fn wait_for_shutdown_signal() -> Result<ShutdownAction> {
    info!("Shutdown watcher active — waiting for SIGTERM / SIGINT / SIGPWR / SIGUSR1");

    loop {
        // Sleep until any signal wakes us up
        // SAFETY: pause(2) is async-signal-safe; no invariants broken
        unsafe { libc::pause() };

        if REBOOT_REQUESTED.load(Ordering::Acquire) {
            warn!("Reboot signal received — initiating system reboot");
            return Ok(ShutdownAction::Reboot);
        }

        if SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
            warn!("Shutdown signal received — powering off system");
            return Ok(ShutdownAction::PowerOff);
        }

        // Spurious wake (other signal, e.g. SIGCHLD) — continue sleeping
    }
}

pub fn execute(action: ShutdownAction) -> ! {
    match action {
        ShutdownAction::Reboot => trigger_reboot(),
        ShutdownAction::PowerOff => trigger_poweroff(),
    }

    log::error!("Shutdown syscall returned unexpectedly; parking PID 1");
    loop {
        std::thread::park();
    }
}

pub fn trigger_reboot() {
    // Flush all kernel buffers before reboot
    unsafe { libc::sync() };
    initiate(RebootMode::RB_AUTOBOOT);
}

pub fn trigger_poweroff() {
    // Flush all kernel buffers before poweroff
    unsafe { libc::sync() };
    initiate(RebootMode::RB_POWER_OFF);
}

fn initiate(mode: RebootMode) {
    info!("Initiating system action: {:?}", mode);
    match nix::sys::reboot::reboot(mode) {
        Ok(_) => {}
        Err(e) => log::error!(
            "Reboot syscall failed: {} — system may be in undefined state",
            e
        ),
    }
}

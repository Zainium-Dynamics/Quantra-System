/// Boot/Init phase tracking module
///
/// Provides atomic phase indicators for production monitoring.
/// Tracks PID 1 lifecycle stages for watchdog timers and monitoring tools.
use std::sync::atomic::{AtomicU32, Ordering};

/// PID 1 initialization phase enumeration
/// Phases are strictly ordered: each must complete before next
pub struct InitPhase;

impl InitPhase {
    /// PID 1 starting, basic setup
    pub const STARTUP: u32 = 0;

    /// Filesystem mounts being prepared
    pub const MOUNTS: u32 = 1;

    /// Logging system initialized
    pub const LOGGING: u32 = 2;

    /// Kernel parameters being applied
    pub const KERNEL: u32 = 3;

    /// Signal handlers being installed
    pub const SIGNALS: u32 = 4;

    /// Background reaper started
    #[allow(dead_code)]
    pub const REAPER: u32 = 5;

    /// System services launching
    pub const SERVICES: u32 = 6;

    /// Optional graphical launcher / display manager bridge
    pub const LAUNCHER: u32 = 7;

    /// Init fully active, ready for system
    pub const READY: u32 = 8;

    /// Shutdown initiated
    #[allow(dead_code)]
    pub const SHUTDOWN: u32 = 9;

    /// Get human-readable phase name
    #[inline]
    pub fn phase_name(phase: u32) -> &'static str {
        match phase {
            0 => "Startup",
            1 => "Mounts",
            2 => "Logging",
            3 => "Kernel",
            4 => "Signals",
            5 => "Reaper",
            6 => "Services",
            7 => "Launcher",
            8 => "Ready",
            9 => "Shutdown",
            _ => "Unknown",
        }
    }
}

/// Global atomic init phase counter
/// Can be read by:
/// - Kernel watchdog timers
/// - External monitoring tools
/// - Boot analysis post-mortem
pub static INIT_PHASE: AtomicU32 = AtomicU32::new(0);

/// Set current init phase and log transition
///
/// # Arguments
/// * `phase` - New init phase (one of InitPhase::* constants)
///
/// # Example
/// ```ignore
/// set_phase(InitPhase::MOUNTS);
/// if let Err(e) = mounts::setup() {
///     eprintln!("FATAL: Mount failed at phase {}", InitPhase::MOUNTS);
/// }
/// ```
#[inline]
pub fn set_phase(phase: u32) {
    INIT_PHASE.store(phase, Ordering::SeqCst);
    eprintln!("[{}] Phase: {}", phase, InitPhase::phase_name(phase));
}

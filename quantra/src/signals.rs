/// Signal handling module — PID 1 signal architecture
///
/// # Design
/// Two families of signals require different handling strategies:
///
/// **Lifecycle signals (SIGTERM, SIGINT, SIGPWR, SIGUSR1):**
/// Handler sets an `AtomicBool` flag + uses `SA_RESTART` so blocked syscalls
/// restart automatically. The main loop calls `libc::pause()` and checks flags.
///
/// **SIGCHLD (child exit):**
/// Handler writes 1 byte to a pipe (async-safe). A dedicated `sigchld-reaper`
/// thread reads the pipe, calls `waitpid(-1, WNOHANG)` in a loop, captures
/// exact exit codes, and stores them in a shared `ExitCodeMap`. This avoids
/// Mutex usage inside the signal handler while still delivering real exit codes
/// to the service restart monitor.
///
/// # Why not sigwait?
/// `sigwait(2)` and `sigaction` handlers for the same signal result in
/// POSIX-undefined behavior. We use `sigaction` + `pause()` exclusively.
use anyhow::Result;
use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, Signal};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

// ── Shutdown / Reboot flags ──────────────────────────────────────────────────
pub static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
pub static REBOOT_REQUESTED: AtomicBool = AtomicBool::new(false);

// ── SIGCHLD pipe (write end stored for signal handler) ──────────────────────
/// Write-end of the SIGCHLD notification pipe.
/// Set by `start_reaper_thread()` before signal handler registration.
static SIGCHLD_PIPE_WFD: AtomicI32 = AtomicI32::new(-1);

// ── Exit code registry ───────────────────────────────────────────────────────
/// Shared map of `pid → exit_code` populated by the reaper thread.
/// Negative values mean the process was killed by signal `-value`.
pub type ExitCodeMap = Arc<Mutex<HashMap<i32, i32>>>;

/// Global exit-code map — initialised once by `start_reaper_thread()`.
pub static EXIT_CODES: OnceLock<ExitCodeMap> = OnceLock::new();

/// Look up the captured exit code for a given PID.
/// Returns `None` if the PID hasn't been reaped yet.
pub fn get_exit_code(pid: i32) -> Option<i32> {
    EXIT_CODES.get()?.lock().ok()?.get(&pid).copied()
}

// ── Public setup API ─────────────────────────────────────────────────────────

/// Register all PID 1 signal handlers.
///
/// Must be called before any `fork()`. All handlers use `SA_RESTART` so that
/// blocking syscalls in PID 1 (e.g. `libc::pause()`) restart automatically
/// after signal delivery instead of returning `EINTR`.
#[inline]
pub fn setup() -> Result<()> {
    log::info!("Registering PID 1 signal handlers");
    unsafe {
        register_sigchld_handler()?;
        register_shutdown_handlers()?;
        register_reboot_handler()?;
    }
    Ok(())
}

/// Spawn the background SIGCHLD reaper thread and initialise EXIT_CODES.
///
/// Creates a pipe:
/// - Write-end → signal handler (1-byte notification on each SIGCHLD)
/// - Read-end  → reaper thread (calls waitpid, stores exit codes)
///
/// **Must be called after `setup()` and before any `fork()`.**
pub fn start_reaper_thread() -> Result<()> {
    let mut fds = [-1i32; 2];
    // O_CLOEXEC ensures child processes don't inherit pipe ends
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "pipe2 for SIGCHLD failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);

    // Give write-end to signal handler (atomic store — safe across fork boundary)
    SIGCHLD_PIPE_WFD.store(write_fd, Ordering::Release);

    // Initialise the global exit-code map
    let codes: ExitCodeMap = Arc::new(Mutex::new(HashMap::new()));
    EXIT_CODES
        .set(Arc::clone(&codes))
        .map_err(|_| anyhow::anyhow!("start_reaper_thread called twice"))?;

    std::thread::Builder::new()
        .name("sigchld-reaper".into())
        .spawn(move || run_reaper(read_fd, codes))
        .map_err(|e| anyhow::anyhow!("Cannot spawn reaper thread: {}", e))?;

    log::info!("SIGCHLD reaper thread started (pipe read_fd={})", read_fd);
    Ok(())
}

// ── Reaper thread ────────────────────────────────────────────────────────────

fn run_reaper(read_fd: i32, codes: ExitCodeMap) {
    let mut buf = [0u8; 256];

    loop {
        // Block until the signal handler wakes us (1-byte write per SIGCHLD)
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            log::warn!("SIGCHLD reaper pipe closed — reaper thread exiting");
            break;
        }

        // Drain ALL waiting zombies in one burst (SIGCHLD can coalesce)
        loop {
            let mut status: libc::c_int = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid <= 0 {
                break; // No more zombies
            }

            let code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                -(libc::WTERMSIG(status)) // Negative = killed by signal
            } else {
                0
            };

            log::debug!("Reaped PID {} exit_code={}", pid, code);

            if let Ok(mut map) = codes.lock() {
                map.insert(pid, code);
            }
        }
    }
}

// ── Signal handler registration ──────────────────────────────────────────────

unsafe fn register_sigchld_handler() -> Result<()> {
    let sa = SigAction::new(
        SigHandler::Handler(handle_chld),
        // SA_NOCLDSTOP: don't fire on SIGSTOP/SIGCONT
        // SA_RESTART:   restart interrupted syscalls (critical for pause() to work cleanly)
        SaFlags::SA_NOCLDSTOP | SaFlags::SA_RESTART,
        signal::SigSet::empty(),
    );
    signal::sigaction(Signal::SIGCHLD, &sa)?;
    Ok(())
}

unsafe fn register_shutdown_handlers() -> Result<()> {
    let sa = SigAction::new(
        SigHandler::Handler(handle_shutdown),
        SaFlags::SA_RESTART,
        signal::SigSet::empty(),
    );
    signal::sigaction(Signal::SIGTERM, &sa)?;
    signal::sigaction(Signal::SIGINT, &sa)?;
    signal::sigaction(Signal::SIGPWR, &sa)?;
    Ok(())
}

unsafe fn register_reboot_handler() -> Result<()> {
    let sa = SigAction::new(
        SigHandler::Handler(handle_reboot),
        SaFlags::SA_RESTART,
        signal::SigSet::empty(),
    );
    signal::sigaction(Signal::SIGUSR1, &sa)?;
    Ok(())
}

// ── Async-signal-safe handlers ───────────────────────────────────────────────

/// SIGCHLD handler: write 1 byte to pipe to wake the reaper thread.
///
/// # Async-Signal Safety
/// Only calls `write(2)` which is in the POSIX async-signal-safe list.
/// No allocation, no Mutex, no Rust runtime code.
extern "C" fn handle_chld(_: i32) {
    let fd = SIGCHLD_PIPE_WFD.load(Ordering::Relaxed);
    if fd >= 0 {
        // Ignore write errors — if the buffer is full the reaper is already busy
        unsafe { libc::write(fd, &1u8 as *const u8 as *const libc::c_void, 1) };
    }
}

/// SIGTERM / SIGINT / SIGPWR handler: request graceful shutdown.
extern "C" fn handle_shutdown(_: i32) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

/// SIGUSR1 handler: request system reboot.
extern "C" fn handle_reboot(_: i32) {
    REBOOT_REQUESTED.store(true, Ordering::SeqCst);
}

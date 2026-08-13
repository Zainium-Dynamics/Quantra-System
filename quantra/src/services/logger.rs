//! Per-service output capture and log file writing
//!
//! Creates a `pipe2(O_CLOEXEC)` pair per service:
//! - Write-end → child process (dup2'd onto stdout + stderr before exec)
//! - Read-end → parent's logger thread (reads lines, writes timestamped
//!   entries to `/overlayer/syshub/var/log/quantra-system/<service>.log`)
//!
//! Log files rotate at 10MB: current log renamed to `<service>.log.1`.

use anyhow::Result;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::io::RawFd;

const LOG_DIR: &str = "/overlayer/syshub/var/log/quantra-system";
const LOG_MAX_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

/// Create a log capture pipe for a service.
///
/// Returns `(write_fd, ServiceLogger)`.
/// - `write_fd` is dup2'd onto the child's stdout + stderr before exec
/// - The `ServiceLogger` is run in a thread in the parent to capture output
pub fn create_service_logger(service_name: &str) -> Result<(RawFd, ServiceLogger)> {
    fs::create_dir_all(LOG_DIR)
        .map_err(|e| anyhow::anyhow!("Cannot create log dir '{}': {}", LOG_DIR, e))?;

    let mut fds = [-1i32; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "pipe2 for logger failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);

    let logger = ServiceLogger {
        name: service_name.to_string(),
        read_fd,
    };

    Ok((write_fd, logger))
}

/// Background log capture state for one service.
pub struct ServiceLogger {
    /// Service name — determines log file path
    name: String,
    /// Read-end of the pipe connected to the child's stdout/stderr
    read_fd: RawFd,
}

impl ServiceLogger {
    /// Run the log capture loop — blocks until the pipe closes (all writers gone).
    ///
    /// Designed to be called inside `thread::spawn`.
    pub fn run(self) {
        let log_path = format!("{}/{}.log", LOG_DIR, self.name);
        // SAFETY: we own read_fd exclusively; it is valid until the child exits
        let reader = BufReader::new(unsafe {
            <File as std::os::unix::io::FromRawFd>::from_raw_fd(self.read_fd)
        });

        let mut log_file = match open_log_append(&log_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[zai-init logger] Cannot open '{}': {}", log_path, e);
                return;
            }
        };

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break, // Pipe closed
            };

            let ts = monotonic_ms();
            let entry = format!("[{:>12}ms] {}\n", ts, line);

            if let Err(e) = log_file.write_all(entry.as_bytes()) {
                eprintln!("[zai-init logger] Write error for '{}': {}", self.name, e);
                break;
            }

            // Rotate if log exceeds max size
            if let Ok(meta) = log_file.metadata()
                && meta.len() >= LOG_MAX_SIZE
            {
                let rotated = format!("{}/{}.log.1", LOG_DIR, self.name);
                let _ = fs::rename(&log_path, &rotated);
                log::info!("Rotated log for '{}' → {}", self.name, rotated);
                match open_log_append(&log_path) {
                    Ok(f) => log_file = f,
                    Err(e) => {
                        eprintln!("[zai-init logger] Reopen failed for '{}': {}", self.name, e);
                        break;
                    }
                }
            }
        }

        log::debug!("Log capture ended for '{}'", self.name);
    }
}

fn open_log_append(path: &str) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| anyhow::anyhow!("open '{}': {}", path, e))
}

/// Monotonic milliseconds since boot — cheap + async-safe.
fn monotonic_ms() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1000 + (ts.tv_nsec as u64) / 1_000_000
}

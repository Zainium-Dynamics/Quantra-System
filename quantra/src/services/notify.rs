use anyhow::Result;
/// sd_notify readiness protocol — receive service status over Unix socket
///
/// Implements systemd's sd_notify(3) protocol. Services compiled against
/// libsystemd (or any compatible library) post status datagrams to the
/// socket path given in `NOTIFY_SOCKET`. We parse:
///
/// | Message     | Meaning                                |
/// |-------------|----------------------------------------|
/// | `READY=1`   | Service is ready to accept work        |
/// | `STATUS=…`  | Human-readable status update           |
/// | `ERRNO=…`   | Service is reporting an error code     |
/// | `MAINPID=…` | Actual daemon PID (after double-fork)  |
/// | `WATCHDOG=1`| Keepalive heartbeat                    |
///
/// `wait_for_ready()` blocks until `READY=1` arrives or the timeout fires.
use std::fs;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

const NOTIFY_DIR: &str = "/run/quantra-system/notify";

/// sd_notify server bound to a per-service Unix datagram socket.
pub struct NotifyServer {
    socket_path: String,
    socket: UnixDatagram,
    /// Last MAINPID reported by the service (may differ from fork PID on double-fork)
    pub main_pid: Option<u32>,
}

impl NotifyServer {
    /// Create and bind a notify socket for `service_name`.
    ///
    /// The socket path is returned by `socket_path()` and must be set
    /// in the service's `NOTIFY_SOCKET` environment variable before exec.
    pub fn new(service_name: &str) -> Result<Self> {
        fs::create_dir_all(NOTIFY_DIR)
            .map_err(|e| anyhow::anyhow!("Cannot create notify dir '{}': {}", NOTIFY_DIR, e))?;

        let socket_path = format!("{}/{}.sock", NOTIFY_DIR, sanitize(service_name));

        // Remove stale socket from a previous run
        let _ = fs::remove_file(&socket_path);

        let socket = UnixDatagram::bind(&socket_path)
            .map_err(|e| anyhow::anyhow!("Cannot bind notify socket '{}': {}", socket_path, e))?;

        log::debug!("sd_notify socket bound: {}", socket_path);

        Ok(Self {
            socket_path,
            socket,
            main_pid: None,
        })
    }

    /// Path to set as `NOTIFY_SOCKET` in the service's environment.
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    /// Block until the service sends `READY=1` or the timeout fires.
    ///
    /// Returns `Ok(true)` on readiness, `Ok(false)` on timeout.
    pub fn wait_for_ready(&mut self, timeout: Duration) -> Result<bool> {
        self.socket
            .set_read_timeout(Some(timeout))
            .map_err(|e| anyhow::anyhow!("set_read_timeout: {}", e))?;

        let mut buf = [0u8; 4096];

        loop {
            match self.socket.recv(&mut buf) {
                Ok(n) => {
                    let msg = std::str::from_utf8(&buf[..n]).unwrap_or("");
                    log::debug!("sd_notify for '{}': {:?}", self.socket_path, msg);

                    for line in msg.lines() {
                        if let Some(ready) = self.handle_line(line) {
                            return Ok(ready);
                        }
                    }
                }

                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Ok(false);
                }

                Err(e) => {
                    return Err(anyhow::anyhow!("Notify socket recv error: {}", e));
                }
            }
        }
    }

    /// Parse a single sd_notify line. Returns `Some(true)` on READY=1, else `None` to continue.
    fn handle_line(&mut self, line: &str) -> Option<bool> {
        match line {
            "READY=1" => {
                log::info!("sd_notify READY=1 received");
                Some(true)
            }
            l if l.starts_with("STATUS=") => {
                log::info!("Service status update: {}", &l[7..]);
                None
            }
            l if l.starts_with("MAINPID=") => {
                if let Ok(pid) = l[8..].parse::<u32>() {
                    log::debug!("Service MAINPID={}", pid);
                    self.main_pid = Some(pid);
                }
                None
            }
            l if l.starts_with("ERRNO=") => {
                log::warn!("Service errno: {}", &l[6..]);
                None
            }
            "WATCHDOG=1" => {
                log::debug!("Watchdog keepalive received");
                None
            }
            _ => None,
        }
    }
}

impl Drop for NotifyServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket_path);
    }
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

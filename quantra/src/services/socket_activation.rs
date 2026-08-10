#![allow(dead_code)]
/// Socket activation — pre-open sockets and pass to services on exec
///
/// Implements the systemd socket activation protocol:
/// <https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html>
///
/// PID 1 creates and binds sockets (Unix stream or TCP), then before exec-ing
/// the service, dup2s them to fds starting at `SD_LISTEN_FDS_START` (3).
/// The service discovers its sockets via:
///
/// | Env var            | Meaning                              |
/// |--------------------|--------------------------------------|
/// | `LISTEN_FDS`       | Number of pre-opened sockets         |
/// | `LISTEN_FDS_PID`   | PID that should consume the fds      |
/// | `LISTEN_FDNAMES`   | Colon-separated socket names         |
///
/// Services that support socket activation (CUPS, nginx, SSH, etc.)
/// call `sd_listen_fds()` which reads these env vars and returns the fds.
use anyhow::Result;
use std::fs;
use std::os::unix::io::{IntoRawFd, RawFd};

/// The fd number at which activated sockets begin (systemd convention: 3)
pub const SD_LISTEN_FDS_START: i32 = 3;

/// A pre-opened, bound, listening socket ready to hand off to a service.
pub struct ActivationSocket {
    /// Human-readable name — used in `LISTEN_FDNAMES` env var
    pub name: String,
    /// Raw file descriptor — owned here, transferred to child via dup2
    pub fd: RawFd,
}

impl ActivationSocket {
    /// Create a Unix stream socket bound to `path` and listening.
    pub fn new_unix_stream(name: &str, path: &str) -> Result<Self> {
        use std::os::unix::net::UnixListener;

        // Remove stale socket from previous run
        let _ = fs::remove_file(path);

        let listener = UnixListener::bind(path).map_err(|e| {
            anyhow::anyhow!(
                "Socket activation: cannot bind Unix '{}' at {}: {}",
                name,
                path,
                e
            )
        })?;

        log::info!(
            "Socket activation: Unix stream '{}' bound at {}",
            name,
            path
        );
        Ok(Self {
            name: name.to_string(),
            fd: listener.into_raw_fd(),
        })
    }

    /// Create a TCP socket bound to `addr` (e.g. `"0.0.0.0:8080"`) and listening.
    pub fn new_tcp(name: &str, addr: &str) -> Result<Self> {
        use std::net::TcpListener;

        let listener = TcpListener::bind(addr).map_err(|e| {
            anyhow::anyhow!(
                "Socket activation: cannot bind TCP '{}' at {}: {}",
                name,
                addr,
                e
            )
        })?;

        log::info!("Socket activation: TCP '{}' bound at {}", name, addr);
        Ok(Self {
            name: name.to_string(),
            fd: listener.into_raw_fd(),
        })
    }
}

impl Drop for ActivationSocket {
    fn drop(&mut self) {
        // Close fd when the ActivationSocket is dropped in the PARENT.
        // In the child the fd is transferred via dup2 before exec.
        unsafe { libc::close(self.fd) };
    }
}

/// Build the sd socket activation environment variables.
///
/// Pass these to the service process alongside its regular environment.
pub fn build_listen_env(sockets: &[ActivationSocket]) -> Vec<(String, String)> {
    let names = sockets
        .iter()
        .map(|s| s.name.as_str())
        .collect::<Vec<_>>()
        .join(":");

    vec![
        ("LISTEN_FDS".into(), sockets.len().to_string()),
        ("LISTEN_FDNAMES".into(), names),
    ]
}

/// In the **child process** after fork, dup2 all activation socket fds to
/// consecutive positions starting at `SD_LISTEN_FDS_START` (fd 3, 4, 5…).
///
/// Also clears `O_CLOEXEC` on each target fd so they survive exec.
///
/// # Safety
/// Must only be called in the fork child. All calls are async-signal-safe.
#[allow(dead_code)] // Called in fork child path — static analysis cannot trace post-fork usage
pub unsafe fn setup_child_fds(sockets: &[ActivationSocket]) {
    for (i, sock) in sockets.iter().enumerate() {
        let target = SD_LISTEN_FDS_START + i as i32;
        if sock.fd != target {
            libc::dup2(sock.fd, target);
        }
        // Clear O_CLOEXEC — the fd must survive execvpe
        let flags = libc::fcntl(target, libc::F_GETFD, 0);
        libc::fcntl(target, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_listen_env_empty() {
        let env = build_listen_env(&[]);
        assert_eq!(env.len(), 2);
        assert_eq!(env[0], ("LISTEN_FDS".into(), "0".into()));
        assert_eq!(env[1], ("LISTEN_FDNAMES".into(), "".into()));
    }

    #[test]
    fn build_listen_env_single_socket() {
        // Create a mock ActivationSocket with a dummy fd
        let sockets = vec![ActivationSocket {
            name: "http".into(),
            fd: 99,
        }];
        let env = build_listen_env(&sockets);
        assert_eq!(env[0].1, "1");
        assert_eq!(env[1].1, "http");
        // Leak the fd so Drop doesn't close a random fd
        std::mem::forget(sockets);
    }

    #[test]
    fn build_listen_env_multiple_sockets_colon_separated() {
        let sockets = vec![
            ActivationSocket {
                name: "http".into(),
                fd: 99,
            },
            ActivationSocket {
                name: "https".into(),
                fd: 100,
            },
        ];
        let env = build_listen_env(&sockets);
        assert_eq!(env[0].1, "2");
        assert_eq!(env[1].1, "http:https");
        std::mem::forget(sockets);
    }

    #[test]
    fn sd_listen_fds_start_is_3() {
        assert_eq!(SD_LISTEN_FDS_START, 3);
    }
}

// ── Extended socket types ─────────────────────────────────────────────────────

impl ActivationSocket {
    /// Create a UDP socket bound to `addr`.
    pub fn new_udp(name: &str, addr: &str) -> Result<Self> {
        use std::net::UdpSocket;
        let sock = UdpSocket::bind(addr)
            .map_err(|e| anyhow::anyhow!("Socket activation: UDP '{}' at {}: {}", name, addr, e))?;
        log::info!("Socket activation: UDP '{}' bound at {}", name, addr);
        Ok(Self {
            name: name.to_string(),
            fd: sock.into_raw_fd(),
        })
    }

    /// Create a NETLINK socket for netlink-based socket activation.
    ///
    /// `netlink_family`: e.g. `libc::NETLINK_KOBJECT_UEVENT` (15),
    /// `libc::NETLINK_ROUTE` (0), etc.
    pub fn new_netlink(name: &str, netlink_family: libc::c_int, groups: u32) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                netlink_family,
            )
        };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "Socket activation: NETLINK '{}' family={}: {}",
                name,
                netlink_family,
                std::io::Error::last_os_error()
            ));
        }
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_groups = groups;
        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            unsafe {
                libc::close(fd);
            }
            return Err(anyhow::anyhow!(
                "Socket activation: NETLINK bind '{}': {}",
                name,
                std::io::Error::last_os_error()
            ));
        }
        log::info!(
            "Socket activation: NETLINK '{}' family={} groups={}",
            name,
            netlink_family,
            groups
        );
        Ok(Self {
            name: name.to_string(),
            fd,
        })
    }

    /// Create a FIFO (named pipe) for inetd-style socket activation.
    ///
    /// `ListenFIFO=` equivalent — creates a FIFO at `path` and returns
    /// a read-end fd. The service writes to stdout, reads from the FIFO.
    pub fn new_fifo(name: &str, path: &str) -> Result<Self> {
        let path_cstr = std::ffi::CString::new(path)
            .map_err(|_| anyhow::anyhow!("invalid FIFO path: {}", path))?;

        // Remove stale FIFO
        let _ = std::fs::remove_file(path);

        let ret = unsafe { libc::mkfifo(path_cstr.as_ptr(), 0o600) };
        if ret < 0 {
            return Err(anyhow::anyhow!(
                "Socket activation: mkfifo '{}' at {}: {}",
                name,
                path,
                std::io::Error::last_os_error()
            ));
        }

        let fd = unsafe {
            libc::open(
                path_cstr.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "Socket activation: open FIFO '{}': {}",
                name,
                std::io::Error::last_os_error()
            ));
        }

        log::info!("Socket activation: FIFO '{}' at {}", name, path);
        Ok(Self {
            name: name.to_string(),
            fd,
        })
    }

    /// Enable SO_REUSEPORT on an existing socket fd.
    pub fn set_reuse_port(&self) -> Result<()> {
        let one: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "SO_REUSEPORT on '{}': {}",
                self.name,
                std::io::Error::last_os_error()
            ));
        }
        log::debug!("Socket '{}': SO_REUSEPORT enabled", self.name);
        Ok(())
    }

    /// Enable SO_KEEPALIVE on a TCP socket fd.
    pub fn set_keep_alive(&self) -> Result<()> {
        let one: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_KEEPALIVE,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "SO_KEEPALIVE on '{}': {}",
                self.name,
                std::io::Error::last_os_error()
            ));
        }
        log::debug!("Socket '{}': SO_KEEPALIVE enabled", self.name);
        Ok(())
    }

    /// Enable SO_PASSCRED — pass SCM_CREDENTIALS with each message.
    ///
    /// Maps to systemd `PassCredentials=yes`.
    pub fn set_pass_credentials(&self) -> Result<()> {
        let one: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "SO_PASSCRED on '{}': {}",
                self.name,
                std::io::Error::last_os_error()
            ));
        }
        log::debug!("Socket '{}': SO_PASSCRED enabled", self.name);
        Ok(())
    }

    /// Bind socket to a specific network interface via SO_BINDTODEVICE.
    ///
    /// Maps to systemd `BindToDevice=`.
    pub fn bind_to_device(&self, iface: &str) -> Result<()> {
        let iface_cstr = std::ffi::CString::new(iface)
            .map_err(|_| anyhow::anyhow!("invalid interface name: {}", iface))?;
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                iface_cstr.as_ptr() as *const libc::c_void,
                (iface.len() + 1) as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "SO_BINDTODEVICE '{}' on '{}': {}",
                iface,
                self.name,
                std::io::Error::last_os_error()
            ));
        }
        log::debug!("Socket '{}': bound to device '{}'", self.name, iface);
        Ok(())
    }

    /// Enable IP_FREEBIND — allow binding to non-local addresses.
    ///
    /// Useful for services that start before their IP address is assigned.
    /// Maps to systemd `FreeBind=yes`.
    pub fn set_free_bind(&self) -> Result<()> {
        let one: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                libc::IPPROTO_IP,
                libc::IP_FREEBIND,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "IP_FREEBIND on '{}': {}",
                self.name,
                std::io::Error::last_os_error()
            ));
        }
        log::debug!("Socket '{}': IP_FREEBIND enabled", self.name);
        Ok(())
    }

    /// Set the socket listen backlog.
    pub fn set_backlog(&self, backlog: i32) -> Result<()> {
        let ret = unsafe { libc::listen(self.fd, backlog) };
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "listen(backlog={}) on '{}': {}",
                backlog,
                self.name,
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

// ── Accept=yes inetd-style per-connection forking ─────────────────────────────

/// Configuration for `Accept=yes` (inetd-style) socket activation.
///
/// Instead of passing the listening socket to the service, quantra forks
/// a new instance of the service for EACH incoming connection,
/// passing the accepted connection socket as stdin/stdout.
pub struct AcceptConfig {
    /// Maximum concurrent connections (0 = unlimited)
    pub max_connections: usize,
    /// Maximum connection trigger rate (connections per second)
    pub trigger_limit_burst: usize,
    /// Trigger limit interval in seconds
    pub trigger_limit_interval: u64,
}

impl Default for AcceptConfig {
    fn default() -> Self {
        Self {
            max_connections: 0,
            trigger_limit_burst: 200,
            trigger_limit_interval: 2,
        }
    }
}

/// Run accept=yes loop — fork a service instance for each connection.
///
/// The spawned process gets the accepted fd as stdin (fd 0) and stdout (fd 1).
/// This is the inetd-compatible mode for services like `sshd -i`.
pub fn run_accept_loop(
    listen_fd: RawFd,
    service_command: &[String],
    config: AcceptConfig,
    stop_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;

    let _backlog_clone = listen_fd;
    let mut active: usize = 0;
    let mut rate_count: usize = 0;
    let mut rate_window = std::time::Instant::now();

    loop {
        if stop_flag.load(Ordering::Acquire) {
            break;
        }

        // Accept a connection (blocking)
        let conn_fd =
            unsafe { libc::accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if conn_fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                continue;
            }
            log::warn!("accept() failed: {}", err);
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        }

        // Rate limiting
        if rate_window.elapsed() >= std::time::Duration::from_secs(config.trigger_limit_interval) {
            rate_window = std::time::Instant::now();
            rate_count = 0;
        }
        rate_count += 1;
        if rate_count > config.trigger_limit_burst {
            log::warn!("accept loop: trigger_limit_burst exceeded — dropping connection");
            unsafe {
                libc::close(conn_fd);
            }
            continue;
        }

        // Connection limit
        if config.max_connections > 0 && active >= config.max_connections {
            log::warn!(
                "accept loop: max_connections={} exceeded",
                config.max_connections
            );
            unsafe {
                libc::close(conn_fd);
            }
            continue;
        }

        // Fork a service instance
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // Child: redirect stdin/stdout to connection, exec service
            unsafe {
                libc::dup2(conn_fd, libc::STDIN_FILENO);
                libc::dup2(conn_fd, libc::STDOUT_FILENO);
                libc::close(conn_fd);
                libc::close(listen_fd);
            }
            if let (Some(cmd), args) = (service_command.first(), &service_command[1..]) {
                let cmd_cstr = std::ffi::CString::new(cmd.as_str()).unwrap();
                let args_cstr: Vec<std::ffi::CString> = args
                    .iter()
                    .filter_map(|a| std::ffi::CString::new(a.as_str()).ok())
                    .collect();
                let mut argv: Vec<*const libc::c_char> = std::iter::once(cmd_cstr.as_ptr())
                    .chain(args_cstr.iter().map(|a| a.as_ptr()))
                    .chain(std::iter::once(std::ptr::null()))
                    .collect();
                unsafe {
                    libc::execvp(cmd_cstr.as_ptr(), argv.as_mut_ptr());
                }
            }
            unsafe {
                libc::_exit(1);
            }
        } else if pid > 0 {
            unsafe {
                libc::close(conn_fd);
            }
            active += 1;
            // Reap children non-blocking
            let mut status = 0i32;
            while unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) } > 0 {
                if active > 0 {
                    active -= 1;
                }
            }
        } else {
            log::error!(
                "accept loop: fork failed: {}",
                std::io::Error::last_os_error()
            );
            unsafe {
                libc::close(conn_fd);
            }
        }
    }
}

#[cfg(test)]
mod ext_tests {
    use super::*;

    #[test]
    fn accept_config_default_unlimited() {
        let cfg = AcceptConfig::default();
        assert_eq!(
            cfg.max_connections, 0,
            "default max_connections must be unlimited"
        );
    }

    #[test]
    fn accept_config_default_burst() {
        let cfg = AcceptConfig::default();
        assert_eq!(cfg.trigger_limit_burst, 200);
    }
}

// ── Socket spec types (for TOML service file parsing) ─────────────────────────

/// Socket type specification in service TOML.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SocketSpec {
    /// Unix stream socket at path
    Unix(String),
    /// TCP socket at addr:port
    Tcp(String),
    /// UDP socket at addr:port
    Udp(String),
    /// Netlink socket (family, multicast groups)
    Netlink { family: i32, groups: u32 },
    /// Named FIFO (pipe)
    Fifo(String),
}

/// Extended socket options for TOML parsing.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Default)]
pub struct SocketOptions {
    /// SO_REUSEPORT — allow multiple sockets on same port
    #[serde(default)]
    pub reuse_port: bool,
    /// SO_KEEPALIVE — TCP keepalive
    #[serde(default)]
    pub keep_alive: bool,
    /// SO_PASSCRED — pass credentials with each message
    #[serde(default)]
    pub pass_credentials: bool,
    /// SO_BINDTODEVICE — bind to specific interface
    #[serde(default)]
    pub bind_to_device: Option<String>,
    /// IP_FREEBIND — allow binding to non-local addresses
    #[serde(default)]
    pub free_bind: bool,
    /// Listen backlog
    #[serde(default = "default_backlog")]
    pub backlog: i32,
    /// Accept=yes: fork per connection (inetd mode)
    #[serde(default)]
    pub accept: bool,
    /// Maximum connections (with accept=yes)
    #[serde(default)]
    pub max_connections: usize,
    /// Trigger rate limit burst
    #[serde(default = "default_trigger_burst")]
    pub trigger_limit_burst: usize,
}

fn default_backlog() -> i32 {
    128
}
fn default_trigger_burst() -> usize {
    200
}

/// Create an ActivationSocket from a spec, applying all options.
pub fn create_socket(
    name: &str,
    spec: &SocketSpec,
    opts: &SocketOptions,
) -> Result<ActivationSocket> {
    let sock = match spec {
        SocketSpec::Unix(path) => ActivationSocket::new_unix_stream(name, path)?,
        SocketSpec::Tcp(addr) => {
            let s = ActivationSocket::new_tcp(name, addr)?;
            if opts.keep_alive {
                s.set_keep_alive()?;
            }
            if opts.reuse_port {
                s.set_reuse_port()?;
            }
            if opts.free_bind {
                s.set_free_bind()?;
            }
            s
        }
        SocketSpec::Udp(addr) => {
            let s = ActivationSocket::new_udp(name, addr)?;
            if opts.reuse_port {
                s.set_reuse_port()?;
            }
            s
        }
        SocketSpec::Netlink { family, groups } => {
            ActivationSocket::new_netlink(name, *family, *groups)?
        }
        SocketSpec::Fifo(path) => ActivationSocket::new_fifo(name, path)?,
    };

    if let Some(ref iface) = opts.bind_to_device {
        sock.bind_to_device(iface)?;
    }
    if opts.pass_credentials {
        sock.set_pass_credentials()?;
    }
    if opts.backlog > 0 {
        sock.set_backlog(opts.backlog).ok(); // non-fatal for UDP/netlink
    }

    Ok(sock)
}

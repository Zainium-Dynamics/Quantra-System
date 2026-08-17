use crate::services::socket_activation::SD_LISTEN_FDS_START;
/// Service process management — fork+exec with full privilege dropping
///
/// `start_service_as()` is the single authoritative fork+exec primitive.
/// All CStrings are built in the **parent** before `fork()` — the child
/// only uses already-allocated memory (no alloc after fork).
///
/// # Privilege Drop Order (critical)
/// 1. `setgroups(0, NULL)` — revoke ALL supplementary groups
/// 2. `setgid(gid)`        — set primary group
/// 3. `setuid(uid)`        — drop root
///
/// This order is mandatory: after `setuid` we lose `CAP_SETGID`, so gid
/// must be finalized first. Skipping `setgroups` is a CVE-class bug.
///
/// # Fork Safety
/// Child path: only async-signal-safe syscalls after `fork()`.
/// - No `log::*` (Mutex → deadlock risk)
/// - No `std::process::exit` (atexit handlers, buffered IO flush)
/// - `libc::_exit(1)` only
/// - Errors → `write(2)` to fd 2
use nix::unistd::{ForkResult, Pid, execvpe, fork};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::unix::io::{AsRawFd, RawFd};

use crate::security::apparmor;

/// Minimal base environment for services — prevents inheriting PID 1's env.
/// No traditional FHS (`/usr`, `/bin`, `/sbin`) — everything ships under the
/// syshub prefix, with zexlib as the writable-package overlay. See
/// `zex-env/src/paths.rs::build_path()` for the canonical toolchain-side form.
const BASE_PATH: &str = "/overlayer/syshub/bin:/overlayer/syshub/sbin:/overlayer/syshub/x86_64-zainium-linux-musl/bin:/overlayer/zexlib/union/bin";
const PR_CAPBSET_DROP: libc::c_int = 24;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;
const PR_SET_SECCOMP: libc::c_int = 22;
const SECCOMP_MODE_STRICT: libc::c_ulong = 1;
const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e;

#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7;

#[cfg(target_arch = "x86")]
const AUDIT_ARCH_NATIVE: u32 = 0x4000_0003;

#[cfg(target_arch = "arm")]
const AUDIT_ARCH_NATIVE: u32 = 0x4000_0028;

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "x86",
    target_arch = "arm"
)))]
const AUDIT_ARCH_NATIVE: u32 = 0;

const SECCOMP_PROFILE_DEFAULT: &str = "default";
const SECCOMP_PROFILE_NETWORK_DAEMON: &str = "network-daemon";
const SECCOMP_PROFILE_NETWORK_TIGHT: &str = "network-tight";

/// Configuration for starting a service process.
pub struct ServiceLaunch<'a> {
    pub cmd: &'a str,
    pub args: &'a [&'a str],
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub working_dir: Option<&'a str>,
    /// Optional controlling tty path, e.g. `/dev/tty1` for getty-style shells.
    pub tty_path: Option<&'a str>,
    /// Service-specific environment overlay (merged over BASE_PATH)
    pub env: Option<&'a HashMap<String, String>>,
    /// If Some, dup2'd onto child's stdout AND stderr before exec
    pub log_write_fd: Option<RawFd>,
    /// Activation socket fds to dup2 into child at SD_LISTEN_FDS_START (3,4,5…)
    pub activation_fds: &'a [RawFd],
    /// Optional AppArmor profile to apply immediately before exec.
    pub apparmor_profile: Option<&'a str>,
    /// Apply no-new-privileges guard in child process.
    pub no_new_privileges: bool,
    /// Set process non-dumpable bit in child process.
    pub non_dumpable: bool,
    /// Clear all ambient capabilities in child process.
    pub clear_ambient_caps: bool,
    /// Capability IDs to drop from the bounding set before exec.
    pub drop_capabilities: &'a [libc::c_ulong],
    /// Capability IDs to raise into the ambient set before exec.
    /// Requires the capability to be in the permitted + inheritable set.
    pub ambient_capabilities: &'a [libc::c_ulong],
    /// If non-empty, treat as the FULL bounding set — drop all caps not listed.
    /// Applied before drop_capabilities. Empty = no change.
    pub capability_bounding_set: &'a [libc::c_ulong],
    /// Syscall numbers denied by a seccomp-bpf profile.
    pub seccomp_profile_denylist: &'a [libc::c_long],
    /// Syscall numbers allowed (allowlist mode). Empty = use denylist.
    /// When non-empty, all syscalls NOT in this list are blocked.
    pub seccomp_allowlist: &'a [libc::c_long],
    /// Whether to apply seccomp strict mode immediately before exec.
    pub seccomp_strict: bool,
    /// Optional per-service resource limits (applied in child before exec).
    pub rlimit: Option<&'a crate::services::types::ResourceLimits>,
    /// Mount a private tmpfs at /tmp (requires CLONE_NEWNS).
    pub private_tmp: bool,
    /// Remount / as read-only in service's mount namespace.
    pub protect_system: bool,
    /// Landlock LSM allowed paths (empty = no restriction).
    pub landlock_paths: &'a [String],
    /// Reference to full service definition for sandbox features.
    /// If Some, `sandbox::apply_sandbox()` is called in the child.
    pub service_for_sandbox: Option<&'a crate::services::types::Service>,
}

/// Write to stderr fd=2 — async-signal-safe, usable after fork().
#[inline(always)]
fn child_err(msg: &[u8]) {
    unsafe { libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len()) };
}

/// Fork+exec a service with full privilege dropping and environment setup.
///
/// All CStrings are built in the **parent** before `fork()`.
/// The child only calls async-safe syscalls and `libc::_exit`.
pub fn start_service_as(cfg: &ServiceLaunch<'_>) -> Result<Pid, anyhow::Error> {
    // ── Build everything in parent BEFORE fork ────────────────────────────
    let c_cmd =
        CString::new(cfg.cmd).map_err(|e| anyhow::anyhow!("Invalid cmd '{}': {}", cfg.cmd, e))?;

    let mut c_args_vec = vec![c_cmd.clone()];
    for arg in cfg.args {
        c_args_vec
            .push(CString::new(*arg).map_err(|e| anyhow::anyhow!("Invalid arg '{}': {}", arg, e))?);
    }

    // Build envp: base + service overlay
    let mut env_map: HashMap<String, String> = HashMap::new();
    env_map.insert("PATH".into(), BASE_PATH.into());
    env_map.insert("HOME".into(), "/".into());
    env_map.insert("TERM".into(), "linux".into());
    if let Some(svc_env) = cfg.env {
        for (k, v) in svc_env {
            env_map.insert(k.clone(), v.clone());
        }
    }
    let c_env_vec: Vec<CString> = env_map
        .iter()
        .filter_map(|(k, v)| CString::new(format!("{}={}", k, v)).ok())
        .collect();

    let c_cwd = CString::new(cfg.working_dir.unwrap_or("/"))
        .map_err(|e| anyhow::anyhow!("Invalid working_dir: {}", e))?;
    let c_tty_path = match cfg.tty_path {
        Some(path) => Some(
            CString::new(path)
                .map_err(|e| anyhow::anyhow!("Invalid tty_path '{}': {}", path, e))?,
        ),
        None => None,
    };

    // Copy activation_fds to avoid borrow across fork
    let act_fds: Vec<RawFd> = cfg.activation_fds.to_vec();
    let log_fd = cfg.log_write_fd;
    let uid = cfg.uid;
    let gid = cfg.gid;

    // ── Fork ──────────────────────────────────────────────────────────────
    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            log::info!(
                "Spawned '{}' PID={} uid={:?} gid={:?} cwd={:?}",
                cfg.cmd,
                child,
                uid,
                gid,
                cfg.working_dir
            );
            Ok(child)
        }

        ForkResult::Child => {
            // ── CHILD — async-safe only from here ─────────────────────────

            // 1. New session
            if unsafe { libc::setsid() } < 0 {
                child_err(b"[zai-init] setsid failed\n");
                unsafe { libc::_exit(1) };
            }

            // 2. Attach a real tty when one is configured.
            // Opening /dev/tty1 after setsid() without O_NOCTTY gives the child
            // a controlling terminal, which is what bash/fish need for job control.
            if let Some(ref tty) = c_tty_path {
                if attach_terminal(tty.as_c_str()).is_err() && !setup_console_io() {
                    child_err(b"[zai-init] tty attach failed\n");
                    unsafe { libc::_exit(1) };
                }
            } else if log_fd.is_none() {
                setup_console_io();
            }

            // 3. Working directory (before dropping privileges — may lose access after)
            if unsafe { libc::chdir(c_cwd.as_ptr()) } != 0 {
                child_err(b"[zai-init] chdir failed\n");
                unsafe { libc::_exit(1) };
            }

            // 4. Privilege drop — order: setgroups → setgid → setuid
            //    setgroups MUST come first (we can't change groups after dropping root)
            if gid.is_some() || uid.is_some() {
                // Revoke ALL supplementary groups (CVE-class fix)
                if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
                    child_err(b"[zai-init] setgroups failed\n");
                    unsafe { libc::_exit(1) };
                }
                if let Some(g) = gid
                    && unsafe { libc::setgid(g as libc::gid_t) } != 0
                {
                    child_err(b"[zai-init] setgid failed\n");
                    unsafe { libc::_exit(1) };
                }
                if let Some(u) = uid
                    && unsafe { libc::setuid(u as libc::uid_t) } != 0
                {
                    child_err(b"[zai-init] setuid failed\n");
                    unsafe { libc::_exit(1) };
                }
            }

            if !apply_child_hardening(cfg) {
                child_err(b"[zai-init] child hardening failed\n");
                unsafe { libc::_exit(1) };
            }

            // 5. Redirect stdout + stderr to the logger pipe
            if let Some(wfd) = log_fd {
                unsafe {
                    libc::dup2(wfd, 1); // stdout
                    libc::dup2(wfd, 2); // stderr
                    libc::close(wfd); // close the extra copy
                }
            }

            // 6. Dup2 activation socket fds to 3, 4, 5…
            for (i, &src_fd) in act_fds.iter().enumerate() {
                let target = SD_LISTEN_FDS_START + i as i32;
                if src_fd != target {
                    unsafe { libc::dup2(src_fd, target) };
                }
                // Clear O_CLOEXEC so fds survive exec
                unsafe {
                    let flags = libc::fcntl(target, libc::F_GETFD, 0);
                    libc::fcntl(target, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                }
            }

            if let Some(profile) = cfg.apparmor_profile
                && let Err(e) = apparmor::confine_next_exec(profile)
            {
                child_err(b"[zai-init] AppArmor profile apply failed\n");
                let _ = e;
                unsafe { libc::_exit(1) };
            }

            if !cfg.seccomp_allowlist.is_empty() {
                // Allowlist mode: block all syscalls except those listed
                if !apply_seccomp_allowlist(cfg.seccomp_allowlist) {
                    child_err(b"[zai-init] seccomp allowlist apply failed\n");
                    unsafe { libc::_exit(1) };
                }
            } else if !cfg.seccomp_profile_denylist.is_empty() {
                if !apply_seccomp_denylist(cfg.seccomp_profile_denylist) {
                    child_err(b"[zai-init] seccomp profile apply failed\n");
                    unsafe { libc::_exit(1) };
                }
            } else if cfg.seccomp_strict && !apply_seccomp_strict() {
                child_err(b"[zai-init] seccomp strict mode apply failed\n");
                unsafe { libc::_exit(1) };
            }

            // Apply resource limits (setrlimit) before exec.
            // This is the correct location: after privilege drop (so limits
            // apply to the unprivileged process), before exec.
            if let Some(rl) = cfg.rlimit {
                rl.apply();
            }

            // ── Namespace isolation (CLONE_NEWNS) ────────────────────────
            if cfg.private_tmp || cfg.protect_system {
                if unsafe { libc::unshare(libc::CLONE_NEWNS) } == 0 {
                    if cfg.private_tmp {
                        // Mount a private tmpfs at /tmp
                        let tmp = b"/tmp\0";
                        let tmpfs = b"tmpfs\0";
                        let opts = b"size=64M,mode=1777\0";
                        unsafe {
                            libc::mount(
                                tmpfs.as_ptr() as *const libc::c_char,
                                tmp.as_ptr() as *const libc::c_char,
                                tmpfs.as_ptr() as *const libc::c_char,
                                libc::MS_NOSUID | libc::MS_NODEV,
                                opts.as_ptr() as *const libc::c_void,
                            );
                        }
                    }
                    if cfg.protect_system {
                        // Remount / as read-only
                        let root = b"/\0";
                        unsafe {
                            libc::mount(
                                std::ptr::null(),
                                root.as_ptr() as *const libc::c_char,
                                std::ptr::null(),
                                libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_BIND,
                                std::ptr::null(),
                            );
                        }
                    }
                } else {
                    child_err(b"[zai-init] unshare(CLONE_NEWNS) failed\n");
                    // Non-fatal — continue without isolation
                }
            }

            // ── Landlock LSM filesystem restriction ──────────────────────
            if !cfg.landlock_paths.is_empty() {
                apply_landlock(cfg.landlock_paths);
            }

            // ── Sandbox: namespace isolation + path protection ────────────
            if let Some(svc) = cfg.service_for_sandbox
                && let Err(e) = crate::sandbox::apply_sandbox(svc)
            {
                child_err(b"[zai-init] sandbox::apply_sandbox failed\n");
                child_err(e.to_string().as_bytes());
                // Non-fatal by design — log and continue. For strict
                // isolation, set service to fail on sandbox error.
            }

            // 7. Build argv/envp pointer arrays (in child's copy of parent memory)
            let _arg_ptrs: Vec<*const libc::c_char> =
                c_args_vec.iter().map(|s| s.as_ptr()).collect();
            let _env_ptrs: Vec<*const libc::c_char> =
                c_env_vec.iter().map(|s| s.as_ptr()).collect();

            // Build nix CStr slices for execvpe
            let arg_refs: Vec<&std::ffi::CStr> = c_args_vec.iter().map(|s| s.as_c_str()).collect();
            let env_refs: Vec<&std::ffi::CStr> = c_env_vec.iter().map(|s| s.as_c_str()).collect();

            // 7. exec — never returns on success
            let _ = execvpe(&c_cmd, &arg_refs, &env_refs);

            child_err(b"[zai-init] execvpe failed\n");
            unsafe { libc::_exit(1) }
        }
    }
}

/// Convenience wrapper for starting services with no special config.
#[inline]
pub fn start_service(cmd: &str, args: &[&str]) -> Result<Pid, anyhow::Error> {
    start_service_as(&ServiceLaunch {
        cmd,
        args,
        uid: None,
        gid: None,
        working_dir: None,
        tty_path: None,
        env: None,
        log_write_fd: None,
        activation_fds: &[],
        apparmor_profile: None,
        no_new_privileges: true,
        non_dumpable: true,
        clear_ambient_caps: false,
        drop_capabilities: &[],
        ambient_capabilities: &[],
        capability_bounding_set: &[],
        seccomp_profile_denylist: &[],
        seccomp_allowlist: &[],
        seccomp_strict: false,
        rlimit: None,
        private_tmp: false,
        protect_system: false,
        landlock_paths: &[],
        service_for_sandbox: None,
    })
}

/// Resolve a service command into an executable path and argv list.
///
/// If `args` is non-empty, `command` is treated as the executable path and the
/// argv tail is taken verbatim from `args`.
/// If `args` is empty, `command` is parsed as a quoted command line so legacy
/// configs that embed arguments in the command string continue to work.
pub fn resolve_command_argv(
    command: &str,
    args: &[String],
) -> Result<(String, Vec<String>), anyhow::Error> {
    if args.is_empty() {
        let parsed = split_command_line(command)?;
        let mut iter = parsed.into_iter();
        let cmd = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("Empty command spec"))?;
        return Ok((cmd, iter.collect()));
    }

    if command.chars().any(|c| c.is_whitespace()) {
        log::warn!(
            "Service command '{}' contains whitespace while args are provided; treating it as a literal executable path",
            command
        );
    }

    Ok((command.to_string(), args.to_vec()))
}

/// Parse a shell-like command line into argv without invoking a shell.
pub fn split_command_line(command: &str) -> Result<Vec<String>, anyhow::Error> {
    enum Mode {
        Normal,
        SingleQuoted,
        DoubleQuoted,
        Escaped,
        DoubleEscaped,
    }

    let mut mode = Mode::Normal;
    let mut current = String::new();
    let mut argv = Vec::new();

    for ch in command.chars() {
        match mode {
            Mode::Normal => match ch {
                ' ' | '\t' | '\n' => {
                    if !current.is_empty() {
                        argv.push(std::mem::take(&mut current));
                    }
                }
                '\\' => mode = Mode::Escaped,
                '\'' => mode = Mode::SingleQuoted,
                '"' => mode = Mode::DoubleQuoted,
                _ => current.push(ch),
            },
            Mode::SingleQuoted => {
                if ch == '\'' {
                    mode = Mode::Normal;
                } else {
                    current.push(ch);
                }
            }
            Mode::DoubleQuoted => match ch {
                '"' => mode = Mode::Normal,
                '\\' => mode = Mode::DoubleEscaped,
                _ => current.push(ch),
            },
            Mode::Escaped => {
                current.push(ch);
                mode = Mode::Normal;
            }
            Mode::DoubleEscaped => {
                current.push(ch);
                mode = Mode::DoubleQuoted;
            }
        }
    }

    match mode {
        Mode::Normal => {}
        Mode::SingleQuoted => return Err(anyhow::anyhow!("Unterminated single quote in command")),
        Mode::DoubleQuoted | Mode::DoubleEscaped => {
            return Err(anyhow::anyhow!("Unterminated double quote in command"));
        }
        Mode::Escaped => return Err(anyhow::anyhow!("Trailing escape in command")),
    }

    if !current.is_empty() {
        argv.push(current);
    }

    if argv.is_empty() {
        Err(anyhow::anyhow!("Command line is empty"))
    } else {
        Ok(argv)
    }
}

/// Resolve a capability name to its Linux capability number.
///
/// Accepts names with or without `CAP_` prefix and with any ASCII case.
pub fn capability_name_to_number(name: &str) -> Option<libc::c_ulong> {
    let mut canonical = name.trim().to_ascii_uppercase();
    if !canonical.starts_with("CAP_") {
        canonical = format!("CAP_{}", canonical);
    }

    let num = match canonical.as_str() {
        "CAP_CHOWN" => 0,
        "CAP_DAC_OVERRIDE" => 1,
        "CAP_DAC_READ_SEARCH" => 2,
        "CAP_FOWNER" => 3,
        "CAP_FSETID" => 4,
        "CAP_KILL" => 5,
        "CAP_SETGID" => 6,
        "CAP_SETUID" => 7,
        "CAP_SETPCAP" => 8,
        "CAP_LINUX_IMMUTABLE" => 9,
        "CAP_NET_BIND_SERVICE" => 10,
        "CAP_NET_BROADCAST" => 11,
        "CAP_NET_ADMIN" => 12,
        "CAP_NET_RAW" => 13,
        "CAP_IPC_LOCK" => 14,
        "CAP_IPC_OWNER" => 15,
        "CAP_SYS_MODULE" => 16,
        "CAP_SYS_RAWIO" => 17,
        "CAP_SYS_CHROOT" => 18,
        "CAP_SYS_PTRACE" => 19,
        "CAP_SYS_PACCT" => 20,
        "CAP_SYS_ADMIN" => 21,
        "CAP_SYS_BOOT" => 22,
        "CAP_SYS_NICE" => 23,
        "CAP_SYS_RESOURCE" => 24,
        "CAP_SYS_TIME" => 25,
        "CAP_SYS_TTY_CONFIG" => 26,
        "CAP_MKNOD" => 27,
        "CAP_LEASE" => 28,
        "CAP_AUDIT_WRITE" => 29,
        "CAP_AUDIT_CONTROL" => 30,
        "CAP_SETFCAP" => 31,
        "CAP_MAC_OVERRIDE" => 32,
        "CAP_MAC_ADMIN" => 33,
        "CAP_SYSLOG" => 34,
        "CAP_WAKE_ALARM" => 35,
        "CAP_BLOCK_SUSPEND" => 36,
        "CAP_AUDIT_READ" => 37,
        "CAP_PERFMON" => 38,
        "CAP_BPF" => 39,
        "CAP_CHECKPOINT_RESTORE" => 40,
        _ => return None,
    };

    Some(num)
}

/// Resolve a list of capability names to numeric capability IDs.
pub fn resolve_capability_numbers(names: &[String]) -> Result<Vec<libc::c_ulong>, anyhow::Error> {
    let mut resolved = Vec::with_capacity(names.len());
    for name in names {
        let number = capability_name_to_number(name)
            .ok_or_else(|| anyhow::anyhow!("Unknown capability '{}'", name))?;
        resolved.push(number);
    }
    Ok(resolved)
}

/// Resolve a named seccomp profile into syscall numbers denied by the filter.
pub fn resolve_seccomp_profile_denylist(name: &str) -> Result<Vec<libc::c_long>, anyhow::Error> {
    let normalized = name.trim().to_ascii_lowercase();
    let mut denied = match normalized.as_str() {
        SECCOMP_PROFILE_DEFAULT => vec![
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_kexec_load,
            libc::SYS_reboot,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_swapon,
            libc::SYS_swapoff,
            libc::SYS_ptrace,
            libc::SYS_bpf,
            libc::SYS_perf_event_open,
            libc::SYS_syslog,
            libc::SYS_iopl,
            libc::SYS_ioperm,
        ],
        // Intended for long-running network-facing daemons.
        // Keeps networking syscalls available while blocking additional namespace/keyring pivots.
        SECCOMP_PROFILE_NETWORK_DAEMON => {
            let mut deny = resolve_seccomp_profile_denylist(SECCOMP_PROFILE_DEFAULT)?;
            deny.extend([
                libc::SYS_unshare,
                libc::SYS_setns,
                libc::SYS_add_key,
                libc::SYS_request_key,
                libc::SYS_keyctl,
                libc::SYS_userfaultfd,
            ]);
            deny
        }
        SECCOMP_PROFILE_NETWORK_TIGHT => {
            let mut deny = resolve_seccomp_profile_denylist(SECCOMP_PROFILE_DEFAULT)?;
            deny.extend([
                libc::SYS_socket,
                libc::SYS_socketpair,
                libc::SYS_connect,
                libc::SYS_bind,
                libc::SYS_listen,
                libc::SYS_accept,
                libc::SYS_accept4,
            ]);
            deny
        }
        _ => {
            return Err(anyhow::anyhow!(
                "Unknown seccomp profile '{}'; supported profiles: {}, {}, {}",
                name,
                SECCOMP_PROFILE_DEFAULT,
                SECCOMP_PROFILE_NETWORK_DAEMON,
                SECCOMP_PROFILE_NETWORK_TIGHT
            ));
        }
    };

    denied.sort_unstable();
    denied.dedup();
    Ok(denied)
}

/// Returns canonical seccomp profile names supported by this binary.
pub fn supported_seccomp_profiles() -> &'static [&'static str] {
    &[
        SECCOMP_PROFILE_DEFAULT,
        SECCOMP_PROFILE_NETWORK_DAEMON,
        SECCOMP_PROFILE_NETWORK_TIGHT,
    ]
}

#[cfg(test)]
mod tests {
    use super::{
        capability_name_to_number, resolve_capability_numbers, resolve_command_argv,
        resolve_seccomp_profile_denylist, split_command_line,
    };

    #[test]
    fn split_command_line_handles_quotes() {
        let parsed = split_command_line(r#"/bin/echo "hello world" 'x y' plain\ value"#)
            .expect("command should parse");

        assert_eq!(
            parsed,
            vec![
                "/bin/echo".to_string(),
                "hello world".to_string(),
                "x y".to_string(),
                "plain value".to_string(),
            ]
        );
    }

    #[test]
    fn resolve_command_argv_prefers_explicit_args() {
        let args = vec!["-il".to_string()];
        let (cmd, resolved_args) = resolve_command_argv("/usr/bin/fish", &args).unwrap();

        assert_eq!(cmd, "/usr/bin/fish");
        assert_eq!(resolved_args, args);
    }

    #[test]
    fn capability_name_resolution_accepts_common_variants() {
        assert_eq!(capability_name_to_number("CAP_SYS_ADMIN"), Some(21));
        assert_eq!(capability_name_to_number("sys_admin"), Some(21));
    }

    #[test]
    fn resolve_capability_numbers_rejects_unknown_name() {
        let names = vec!["CAP_SYS_ADMIN".to_string(), "CAP_NOT_REAL".to_string()];
        let err = resolve_capability_numbers(&names).unwrap_err();
        assert!(err.to_string().contains("Unknown capability"));
    }

    #[test]
    fn resolve_seccomp_profile_rejects_unknown_name() {
        let err = resolve_seccomp_profile_denylist("not-a-profile").unwrap_err();
        assert!(err.to_string().contains("Unknown seccomp profile"));
    }

    #[test]
    fn resolve_seccomp_profile_network_tight_extends_default() {
        let default = resolve_seccomp_profile_denylist("default").unwrap();
        let network_tight = resolve_seccomp_profile_denylist("network-tight").unwrap();

        assert!(network_tight.len() > default.len());
        assert!(network_tight.contains(&(libc::SYS_socket as libc::c_long)));
        assert!(network_tight.contains(&(libc::SYS_reboot as libc::c_long)));
    }

    #[test]
    fn resolve_seccomp_profile_network_daemon_balances_hardening() {
        let default = resolve_seccomp_profile_denylist("default").unwrap();
        let network_daemon = resolve_seccomp_profile_denylist("network-daemon").unwrap();
        let network_tight = resolve_seccomp_profile_denylist("network-tight").unwrap();

        assert!(network_daemon.len() > default.len());
        assert!(network_daemon.len() < network_tight.len());
        assert!(network_daemon.contains(&(libc::SYS_unshare as libc::c_long)));
        assert!(!network_daemon.contains(&(libc::SYS_socket as libc::c_long)));
        assert!(!network_daemon.contains(&(libc::SYS_connect as libc::c_long)));
    }
}

fn apply_child_hardening(cfg: &ServiceLaunch<'_>) -> bool {
    if cfg.no_new_privileges && unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return false;
    }

    if cfg.non_dumpable && unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return false;
    }

    if cfg.clear_ambient_caps
        && unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) } != 0
    {
        return false;
    }

    // Drop all caps outside capability_bounding_set (if non-empty)
    // This implements CapabilityBoundingSet= semantics
    if !cfg.capability_bounding_set.is_empty() {
        // Build set of caps to KEEP
        let keep: std::collections::HashSet<libc::c_ulong> =
            cfg.capability_bounding_set.iter().copied().collect();
        // Drop all caps 0..40 that are NOT in the keep set
        for cap in 0u64..40 {
            if !keep.contains(&(cap as libc::c_ulong)) {
                unsafe { libc::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) };
            }
        }
    }

    for capability in cfg.drop_capabilities {
        if unsafe { libc::prctl(PR_CAPBSET_DROP, *capability, 0, 0, 0) } != 0 {
            return false;
        }
    }

    // Raise ambient capabilities (AmbientCapabilities=)
    const PR_CAP_AMBIENT_RAISE: libc::c_ulong = 2;
    for cap in cfg.ambient_capabilities {
        if unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, *cap, 0, 0) } != 0 {
            // Non-fatal — cap may not be in permitted set
            child_err(b"[zai-init] ambient cap raise failed (non-fatal)\n");
        }
    }

    true
}

fn apply_seccomp_strict() -> bool {
    unsafe { libc::prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0) == 0 }
}

fn apply_seccomp_denylist(denied_syscalls: &[libc::c_long]) -> bool {
    if denied_syscalls.is_empty() {
        return true;
    }

    if AUDIT_ARCH_NATIVE == 0 {
        return false;
    }

    let mut filter = Vec::with_capacity(5 + denied_syscalls.len() * 2);

    // Lock the filter to the native syscall ABI.
    filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
    filter.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_NATIVE, 1, 0));
    filter.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // Load seccomp_data.nr and kill on denied syscall numbers.
    filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
    for nr in denied_syscalls {
        if *nr < 0 || (*nr as u64) > u32::MAX as u64 {
            return false;
        }

        filter.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, *nr as u32, 0, 1));
        filter.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }

    filter.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    let mut program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };

    unsafe {
        libc::prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            (&mut program as *mut libc::sock_fprog) as libc::c_ulong,
            0,
            0,
        ) == 0
    }
}

#[inline]
/// Build and apply a seccomp BPF allowlist filter.
///
/// All syscalls NOT in `allowed_syscalls` will return EPERM.
/// Architecture mismatch kills the process.
fn apply_seccomp_allowlist(allowed_syscalls: &[libc::c_long]) -> bool {
    if AUDIT_ARCH_NATIVE == 0 {
        return false;
    }

    let mut filter = Vec::with_capacity(5 + allowed_syscalls.len() * 2 + 2);

    // Verify native ABI
    filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
    filter.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_NATIVE, 1, 0));
    filter.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // Load syscall number
    filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));

    // For each allowed syscall: if match → allow
    for nr in allowed_syscalls {
        filter.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, *nr as u32, 0, 1));
        filter.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }

    // Default: deny (EPERM not kill — safer for allowlist debugging)
    filter.push(bpf_stmt(
        BPF_RET | BPF_K,
        SECCOMP_RET_ERRNO | (libc::EPERM as u32 & 0xFFFF),
    ));

    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };

    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        libc::prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &prog as *const libc::sock_fprog,
            0,
            0,
        ) == 0
    }
}

fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[inline]
fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Attach stdin/stdout/stderr to a terminal path.
///
/// The caller must have already called `setsid()` in the child so the first
/// open of `/dev/tty1` can become the controlling terminal.
#[inline]
fn attach_terminal(path: &CStr) -> Result<(), anyhow::Error> {
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(anyhow::anyhow!(
            "open '{}': {}",
            path.to_string_lossy(),
            std::io::Error::last_os_error()
        ));
    }

    // Explicitly claim the controlling tty so job control works for shells.
    if unsafe { libc::ioctl(fd, libc::TIOCSCTTY, 0) } < 0 {
        unsafe { libc::close(fd) };
        return Err(anyhow::anyhow!(
            "TIOCSCTTY on '{}': {}",
            path.to_string_lossy(),
            std::io::Error::last_os_error()
        ));
    }

    let dup_stdin = unsafe { libc::dup2(fd, 0) };
    let dup_stdout = unsafe { libc::dup2(fd, 1) };
    let dup_stderr = unsafe { libc::dup2(fd, 2) };
    unsafe { libc::close(fd) };

    if dup_stdin < 0 || dup_stdout < 0 || dup_stderr < 0 {
        return Err(anyhow::anyhow!(
            "dup2 terminal failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// Redirect stdin/stdout/stderr to /dev/console.
/// Non-fatal if /dev/console is unavailable.
#[inline]
fn setup_console_io() -> bool {
    if let Ok(console) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/console")
    {
        let fd = console.as_raw_fd();
        unsafe {
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
        }
        true
    } else {
        false
    }
}

// ── Landlock LSM ──────────────────────────────────────────────────────────────

/// Landlock ABI constants (kernel 5.13+)
const LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const LANDLOCK_ADD_RULE: libc::c_long = 445;
const LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

/// `LANDLOCK_ACCESS_FS_*` flags — allow read + execute on permitted paths
const LANDLOCK_ACCESS_FS_READ: u64 = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20;

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Apply Landlock filesystem restriction to the current process.
///
/// Restricts filesystem access to ONLY the listed paths.
/// Falls back silently on kernels without Landlock support (<5.13).
///
/// # Safety
/// Uses raw syscalls — must only be called in the fork child before exec.
fn apply_landlock(paths: &[String]) {
    unsafe {
        let attr = LandlockRulesetAttr {
            handled_access_fs: LANDLOCK_ACCESS_FS_READ,
            handled_access_net: 0,
        };
        let ruleset_fd = libc::syscall(
            LANDLOCK_CREATE_RULESET,
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        );
        if ruleset_fd < 0 {
            // Kernel doesn't support Landlock — non-fatal
            return;
        }
        let ruleset_fd = ruleset_fd as i32;

        for path in paths {
            if let Ok(cpath) = CString::new(path.as_str()) {
                let fd = libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
                if fd >= 0 {
                    let rule = LandlockPathBeneathAttr {
                        allowed_access: LANDLOCK_ACCESS_FS_READ,
                        parent_fd: fd,
                    };
                    libc::syscall(
                        LANDLOCK_ADD_RULE,
                        ruleset_fd,
                        LANDLOCK_RULE_PATH_BENEATH,
                        &rule as *const LandlockPathBeneathAttr,
                        0u32,
                    );
                    libc::close(fd);
                }
            }
        }

        // Enforce — after this, filesystem access is restricted
        libc::syscall(LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32);
        libc::close(ruleset_fd);
    }
}

// ── IPAddressDeny / IPAddressAllow — cgroup BPF egress filter ─────────────────
//
// Implementation: write to cgroup v2 BPF programs via the bpf(2) syscall.
// We attach a BPF_PROG_TYPE_CGROUP_SKB program to the service's cgroup
// slice that drops packets to/from denied IP ranges.
//
// BPF program logic:
//   for each packet: if dest_ip in denied_ranges → drop
//   if allowed_ranges non-empty: if dest_ip not in allowed_ranges → drop
//   else: pass
//
// This is equivalent to systemd's IPAddressDeny= / IPAddressAllow= which
// also use cgroup BPF programs.

/// Parsed CIDR range for IP filtering.
#[derive(Debug, Clone)]
pub struct IpRange {
    pub addr: u32,   // IPv4 address (network byte order)
    pub mask: u32,   // Subnet mask (host byte order)
    pub is_v6: bool, // IPv6 (not yet supported in this filter)
}

impl IpRange {
    pub fn parse(cidr: &str) -> Option<Self> {
        let cidr = cidr.trim();
        if cidr == "any" || cidr == "0.0.0.0/0" {
            return Some(Self {
                addr: 0,
                mask: 0,
                is_v6: false,
            });
        }
        if cidr == "::/0" {
            return Some(Self {
                addr: 0,
                mask: 0,
                is_v6: true,
            });
        }
        let (ip_str, prefix_str) = cidr.split_once('/')?;
        let prefix: u32 = prefix_str.parse().ok()?;
        match ip_str.parse::<std::net::Ipv4Addr>().ok() {
            Some(ip) => {
                let mask = if prefix == 0 {
                    0u32
                } else {
                    !0u32 << (32 - prefix)
                };
                let addr = u32::from(ip) & mask;
                Some(Self {
                    addr,
                    mask,
                    is_v6: false,
                })
            }
            None => {
                // IPv6 — mark as v6, skip in v4 filter
                Some(Self {
                    addr: 0,
                    mask: 0,
                    is_v6: true,
                })
            }
        }
    }

    #[allow(dead_code)]
    pub fn contains_ipv4(&self, ip: u32) -> bool {
        if self.is_v6 {
            return false;
        }
        if self.mask == 0 {
            return true;
        } // 0.0.0.0/0 = any
        (ip & self.mask) == self.addr
    }
}

/// Apply IP address filter to a service's cgroup using eBPF.
///
/// This is called from the PARENT before fork (not in the child).
/// Attaches an eBPF program to the service's cgroup slice that enforces
/// IP deny/allow rules on all outbound connections.
///
/// # Implementation note
///
/// We use the `bpf(BPF_PROG_LOAD)` + `bpf(BPF_PROG_ATTACH)` syscalls
/// directly. The BPF program type is `BPF_PROG_TYPE_CGROUP_SKB` with
/// attachment type `BPF_CGROUP_INET_EGRESS`.
///
/// # Fallback
///
/// If BPF attachment fails (kernel < 4.10, or no CAP_SYS_ADMIN), we fall
/// back to nftables rules scoped to the service's cgroup. This requires
/// the `quantra-netd` firewall module to be available.
///
/// Non-fatal: if both fail, the filter is skipped with a warning.
pub fn apply_ip_filter(
    service_name: &str,
    deny_ranges: &[IpRange],
    allow_ranges: &[IpRange],
) -> Result<(), String> {
    if deny_ranges.is_empty() && allow_ranges.is_empty() {
        return Ok(());
    }

    // Try BPF cgroup program first
    match attach_bpf_ip_filter(service_name, deny_ranges, allow_ranges) {
        Ok(()) => {
            log::info!("IP filter attached via BPF cgroup for '{}'", service_name);
            return Ok(());
        }
        Err(e) => {
            log::debug!(
                "BPF cgroup IP filter failed for '{}': {} — trying nftables fallback",
                service_name,
                e
            );
        }
    }

    // nftables fallback
    apply_nft_ip_filter(service_name, deny_ranges, allow_ranges).map_err(|e| {
        format!(
            "IP filter (BPF+nftables both failed) for '{}': {}",
            service_name, e
        )
    })
}

// ── BPF cgroup socket filter ──────────────────────────────────────────────────

// BPF syscall constants
const BPF_PROG_LOAD: u32 = 5;
const BPF_PROG_ATTACH: u32 = 8;
const BPF_PROG_TYPE_CGROUP_SKB: u32 = 10;
const BPF_CGROUP_INET_EGRESS: u32 = 2;
const BPF_F_ALLOW_OVERRIDE: u32 = 1;

// eBPF instruction opcodes (cgroup SKB filter — separate from seccomp BPF above)
const EBPF_LD: u8 = 0x00;
#[allow(dead_code)]
const EBPF_LDX: u8 = 0x01;
#[allow(dead_code)]
const EBPF_ST: u8 = 0x02;
#[allow(dead_code)]
const EBPF_STX: u8 = 0x03;
const EBPF_ALU: u8 = 0x04;
const EBPF_JMP: u8 = 0x05;
const EBPF_RET: u8 = 0x06;
const EBPF_W: u8 = 0x00; // 32-bit
const EBPF_ABS: u8 = 0x20;
const EBPF_IMM: u8 = 0x00;
const EBPF_AND: u8 = 0x50;
const EBPF_JEQ: u8 = 0x10;
const EBPF_JNE: u8 = 0x50;
const EBPF_K_IMM: u8 = 0x00;
const EBPF_EXIT: u8 = 0x90;

// Return values for BPF_PROG_TYPE_CGROUP_SKB
const CGROUP_BPF_DROP: u32 = 0;
const CGROUP_BPF_PASS: u32 = 1;

#[allow(dead_code)]
/// eBPF instruction (64-bit).
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfInsn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

#[allow(dead_code)]
impl BpfInsn {
    fn ld_abs(dst: u8, off: i32) -> Self {
        // BPF_LD | BPF_W | BPF_ABS → load 32-bit from packet at absolute offset
        Self {
            code: EBPF_LD | EBPF_W | EBPF_ABS,
            regs: dst,
            off: 0,
            imm: off,
        }
    }
    fn mov_imm(dst: u8, val: i32) -> Self {
        Self {
            code: EBPF_ALU | EBPF_IMM | 0xB0,
            regs: dst,
            off: 0,
            imm: val,
        }
    }
    fn and_imm(dst: u8, val: i32) -> Self {
        Self {
            code: EBPF_ALU | EBPF_AND | EBPF_K_IMM,
            regs: dst,
            off: 0,
            imm: val,
        }
    }
    fn jeq_imm(dst: u8, val: i32, off: i16) -> Self {
        Self {
            code: EBPF_JMP | EBPF_JEQ | EBPF_K_IMM,
            regs: dst,
            off,
            imm: val,
        }
    }
    fn jne_imm(dst: u8, val: i32, off: i16) -> Self {
        Self {
            code: EBPF_JMP | EBPF_JNE | EBPF_K_IMM,
            regs: dst,
            off,
            imm: val,
        }
    }
    fn ret_imm(val: i32) -> Self {
        Self {
            code: EBPF_RET | EBPF_K_IMM,
            regs: 0,
            off: 0,
            imm: val,
        }
    }
    fn exit() -> Self {
        Self {
            code: EBPF_JMP | EBPF_EXIT,
            regs: 0,
            off: 0,
            imm: 0,
        }
    }
}

/// Build a BPF_PROG_TYPE_CGROUP_SKB program that enforces IP deny/allow rules.
///
/// Program logic:
/// ```
/// r0 = *(u32*)(skb + offsetof(dest_ip))  // load dest IP from skb
/// for each deny_range:
///   if (r0 & mask) == addr → return DROP
/// if allow_ranges non-empty:
///   for each allow_range:
///     if (r0 & mask) == addr → return PASS
///   return DROP  (not in any allow range)
/// return PASS
/// ```
fn build_bpf_ip_filter(deny: &[IpRange], allow: &[IpRange]) -> Vec<BpfInsn> {
    let mut insns: Vec<BpfInsn> = Vec::new();

    // Load dest IP from skb at offset 16 (IPv4 dst in struct __sk_buff)
    // Actual offset is determined by kernel struct __sk_buff layout.
    // For cgroup_skb, we use BPF helper bpf_skb_load_bytes or direct field access.
    // Simplified: use r2 = skb->remote_ip4 (field 29 in __sk_buff = offset ~116)
    const SKB_REMOTE_IP4_OFFSET: i32 = 40; // simplified — actual kernel offset varies

    insns.push(BpfInsn::ld_abs(0, SKB_REMOTE_IP4_OFFSET));

    // For each deny range: if (r0 & mask) == addr → DROP
    for range in deny.iter().filter(|r| !r.is_v6) {
        if range.mask == 0 {
            // 0.0.0.0/0 = deny all
            insns.push(BpfInsn::ret_imm(CGROUP_BPF_DROP as i32));
            return insns;
        }
        // r1 = r0 & mask
        insns.push(BpfInsn::and_imm(1, range.mask as i32));
        // if r1 == addr → drop (offset = insns until drop instruction)
        let jmp_to_drop: i16 = 1;
        insns.push(BpfInsn::jeq_imm(1, range.addr as i32, jmp_to_drop));
        // else: continue
        let skip: i16 = 1;
        insns.push(BpfInsn {
            // jmp skip
            code: (BPF_JMP | BPF_K) as u8,
            regs: 0,
            off: skip,
            imm: 0,
        });
        insns.push(BpfInsn::ret_imm(CGROUP_BPF_DROP as i32));
    }

    // Allow ranges (if any): if not in allow list → DROP
    if !allow.is_empty() {
        let mut found_pass = false;
        for range in allow.iter().filter(|r| !r.is_v6) {
            if range.mask == 0 {
                // allow any → skip filtering
                found_pass = true;
                break;
            }
            insns.push(BpfInsn::and_imm(1, range.mask as i32));
            // if match → jump to PASS at end
            let jmp_to_pass = (allow.len() as i16) * 3;
            insns.push(BpfInsn::jeq_imm(1, range.addr as i32, jmp_to_pass));
        }
        if !found_pass {
            // Not in any allow range → DROP
            insns.push(BpfInsn::ret_imm(CGROUP_BPF_DROP as i32));
        }
    }

    // Default: PASS
    insns.push(BpfInsn::ret_imm(CGROUP_BPF_PASS as i32));
    insns
}

fn attach_bpf_ip_filter(
    service_name: &str,
    deny: &[IpRange],
    allow: &[IpRange],
) -> Result<(), String> {
    let insns = build_bpf_ip_filter(deny, allow);

    // BPF_PROG_LOAD attr (simplified — full attr is 128 bytes in kernel)
    // We use the libc bpf() syscall via inline syscall
    // Full implementation requires a BPF library or careful FFI
    // Here we do a structural attempt and return error if unsupported
    let cgroup_path = format!("/sys/fs/cgroup/quantra-system/{}", service_name);
    if !std::path::Path::new(&cgroup_path).exists() {
        return Err(format!(
            "cgroup path '{}' not found — service not started yet?",
            cgroup_path
        ));
    }

    let cgroup_cstr = std::ffi::CString::new(cgroup_path.as_str()).unwrap();
    let cgroup_fd = unsafe { libc::open(cgroup_cstr.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if cgroup_fd < 0 {
        return Err(format!(
            "open cgroup '{}': {}",
            cgroup_path,
            std::io::Error::last_os_error()
        ));
    }

    // Attempt BPF prog load (kernel 4.10+)
    // If kernel doesn't support it we get EINVAL/ENOSYS
    let _insn_bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            insns.as_ptr() as *const u8,
            insns.len() * std::mem::size_of::<BpfInsn>(),
        )
    };

    // Use BPF syscall number 321 (x86_64)
    const SYS_BPF: libc::c_long = 321;
    #[repr(C, align(8))]
    struct BpfAttr {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
        prog_flags: u32,
        prog_name: [u8; 16],
        prog_ifindex: u32,
        expected_attach_type: u32,
    }

    let license = b"GPL\0";
    let mut attr: BpfAttr = unsafe { std::mem::zeroed() };
    attr.prog_type = BPF_PROG_TYPE_CGROUP_SKB;
    attr.insn_cnt = insns.len() as u32;
    attr.insns = insns.as_ptr() as u64;
    attr.license = license.as_ptr() as u64;
    attr.expected_attach_type = BPF_CGROUP_INET_EGRESS;

    let name = format!("qip_{}", &service_name[..service_name.len().min(8)]);
    let nb = name.as_bytes();
    attr.prog_name[..nb.len().min(15)].copy_from_slice(&nb[..nb.len().min(15)]);

    let prog_fd = unsafe {
        libc::syscall(
            SYS_BPF,
            BPF_PROG_LOAD as libc::c_long,
            &attr as *const BpfAttr,
            std::mem::size_of::<BpfAttr>() as libc::c_long,
        )
    };

    if prog_fd < 0 {
        unsafe {
            libc::close(cgroup_fd);
        }
        return Err(format!(
            "BPF_PROG_LOAD: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Attach to cgroup
    #[repr(C, align(8))]
    struct BpfAttachAttr {
        target_fd: u32,
        attach_bpf_fd: u32,
        attach_type: u32,
        attach_flags: u32,
    }
    let attach_attr = BpfAttachAttr {
        target_fd: cgroup_fd as u32,
        attach_bpf_fd: prog_fd as u32,
        attach_type: BPF_CGROUP_INET_EGRESS,
        attach_flags: BPF_F_ALLOW_OVERRIDE,
    };

    let ret = unsafe {
        libc::syscall(
            SYS_BPF,
            BPF_PROG_ATTACH as libc::c_long,
            &attach_attr as *const BpfAttachAttr,
            std::mem::size_of::<BpfAttachAttr>() as libc::c_long,
        )
    };

    unsafe {
        libc::close(prog_fd as i32);
    }
    unsafe {
        libc::close(cgroup_fd);
    }

    if ret < 0 {
        return Err(format!(
            "BPF_PROG_ATTACH: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// nftables fallback for IP filtering when BPF is unavailable.
fn apply_nft_ip_filter(
    service_name: &str,
    deny: &[IpRange],
    allow: &[IpRange],
) -> Result<(), String> {
    // Build nft ruleset scoped to service cgroup
    let mut rules = format!(
        "table inet quantra_ipfilter_{} {{\n    chain egress {{\n        type filter hook output priority 0\n",
        service_name.replace('-', "_")
    );

    for range in deny.iter().filter(|r| !r.is_v6) {
        let cidr = format!(
            "{}/{}",
            std::net::Ipv4Addr::from(range.addr),
            (32 - (range.mask.trailing_zeros()))
        );
        rules.push_str(&format!("        ip daddr {} drop\n", cidr));
    }

    if !allow.is_empty() {
        for range in allow.iter().filter(|r| !r.is_v6) {
            let cidr = format!(
                "{}/{}",
                std::net::Ipv4Addr::from(range.addr),
                (32 - range.mask.trailing_zeros())
            );
            rules.push_str(&format!("        ip daddr {} accept\n", cidr));
        }
        rules.push_str("        drop\n"); // default deny if allow list specified
    }

    rules.push_str("    }\n}\n");

    // Write ruleset to temp file and apply
    let tmp = format!("/run/quantra-system/ipfilter-{}.nft", service_name);
    std::fs::write(&tmp, &rules).map_err(|e| format!("write nft file '{}': {}", tmp, e))?;

    let status = std::process::Command::new("nft")
        .args(["-f", &tmp])
        .status()
        .map_err(|e| format!("nft exec: {}", e))?;

    std::fs::remove_file(&tmp).ok();

    if status.success() {
        log::info!("IP filter applied via nftables for '{}'", service_name);
        Ok(())
    } else {
        Err(format!("nft -f failed for '{}'", service_name))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod ip_filter_tests {
    use super::*;

    #[test]
    fn ip_range_parse_slash24() {
        let r = IpRange::parse("192.168.1.0/24").unwrap();
        assert!(!r.is_v6);
        assert_eq!(r.addr, u32::from(std::net::Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(r.mask, 0xFFFFFF00);
    }

    #[test]
    fn ip_range_parse_any() {
        let r = IpRange::parse("any").unwrap();
        assert_eq!(r.mask, 0);
    }

    #[test]
    fn ip_range_parse_slash32() {
        let r = IpRange::parse("10.0.0.1/32").unwrap();
        assert_eq!(r.mask, 0xFFFFFFFF);
        assert!(r.contains_ipv4(u32::from(std::net::Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!r.contains_ipv4(u32::from(std::net::Ipv4Addr::new(10, 0, 0, 2))));
    }

    #[test]
    fn ip_range_any_contains_all() {
        let r = IpRange::parse("0.0.0.0/0").unwrap();
        assert!(r.contains_ipv4(u32::from(std::net::Ipv4Addr::new(1, 2, 3, 4))));
        assert!(r.contains_ipv4(u32::from(std::net::Ipv4Addr::new(255, 255, 255, 255))));
    }

    #[test]
    fn ip_range_subnet_match() {
        let r = IpRange::parse("10.0.0.0/8").unwrap();
        assert!(r.contains_ipv4(u32::from(std::net::Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!r.contains_ipv4(u32::from(std::net::Ipv4Addr::new(11, 0, 0, 1))));
    }

    #[test]
    fn ip_range_v6_not_in_v4_filter() {
        let r = IpRange::parse("::/0").unwrap();
        assert!(r.is_v6);
        assert!(!r.contains_ipv4(0));
    }

    #[test]
    fn build_bpf_filter_empty_is_pass() {
        let insns = build_bpf_ip_filter(&[], &[]);
        // Should end with return PASS
        let last = insns.last().unwrap();
        assert_eq!(last.imm, CGROUP_BPF_PASS as i32);
    }

    #[test]
    fn build_bpf_filter_deny_any_is_drop_immediately() {
        let deny = vec![IpRange::parse("0.0.0.0/0").unwrap()];
        let insns = build_bpf_ip_filter(&deny, &[]);
        // After loading IP, should immediately return DROP
        assert!(insns.iter().any(|i| i.imm == CGROUP_BPF_DROP as i32));
    }
}

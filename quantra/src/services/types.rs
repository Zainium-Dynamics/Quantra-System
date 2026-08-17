use serde::Deserialize;
use std::collections::HashMap;

/// A system service definition loaded from a TOML file in the services directory.
///
/// All fields are actively consumed by `ServiceSupervisor`:
/// - `user`/`group`                  → setgroups+setgid+setuid in child
/// - `working_dir`                   → chdir before exec
/// - `restart`/`restart_sec`         → background monitor thread
/// - `max_restarts`/`restart_interval_sec` → crash-loop breaker
/// - `oneshot`                       → wait for process exit before advancing startup
/// - `timeout_stop`                  → SIGTERM→wait→cgroup.kill→SIGKILL stop sequence
/// - `timeout_start`                 → sd_notify / pid-file readiness deadline
/// - `notify_type`                   → simple / sd_notify / bg-process (pid-file)
/// - `pid_file`                      → path polled when notify_type = "bg-process"
/// - `socket_listen`                 → socket activation (pre-open + LISTEN_FDS env)
/// - `environment`                   → passed to execvpe as envp overlay
/// - `env_file`                      → KEY=VALUE file loaded before exec (like /etc/default/<svc>)
/// - `watchdog_sec`                  → heartbeat timeout; restarts if process goes silent
/// - `stop_command`/`stop_args`      → custom teardown script (replaces raw SIGTERM)
/// - `reload_signal`/`reload_command`→ ExecReload: send signal or run command
/// - `chain_to`/`chain_to_always`    → auto-start next service on exit
/// - `rlimit`                        → per-service resource limits table
/// - `dependencies`                  → hard deps (must be STARTED before this service)
/// - `wants`                         → soft deps (ordering only, failure ok)
/// - `milestone`                     → wait for but don't require (failure is ok)
/// - `after`                         → ordering constraint (not a hard dependency)
#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub name: String,
    /// Human-readable description — shown in log output at service start
    pub description: Option<String>,
    pub command: String,

    /// Optional argv tail. If present, `command` is treated as the executable path.
    /// When empty, `command` is parsed as a quoted command line for backward compatibility.
    #[serde(default)]
    pub args: Vec<String>,

    // ── Security ──────────────────────────────────────────────────────────────
    /// Optional AppArmor profile to apply immediately before `execve`.
    #[serde(default)]
    pub apparmor_profile: Option<String>,

    /// Enforce `PR_SET_NO_NEW_PRIVS=1` in the child before exec.
    #[serde(default = "default_no_new_privileges")]
    pub no_new_privileges: bool,

    /// Enforce `PR_SET_DUMPABLE=0` to prevent core dumps and ptrace attachment.
    #[serde(default = "default_non_dumpable")]
    pub non_dumpable: bool,

    /// Clear ambient capabilities before exec (`PR_CAP_AMBIENT_CLEAR_ALL`).
    #[serde(default)]
    pub clear_ambient_caps: bool,

    /// Drop capabilities from the capability bounding set before exec.
    /// Accepts names like `CAP_SYS_ADMIN` or `sys_admin`.
    #[serde(default)]
    pub drop_capabilities: Vec<String>,

    /// Optional seccomp policy for the service process.
    #[serde(default)]
    pub seccomp: SeccompMode,

    /// Named seccomp profile used when `seccomp = "profile"`.
    #[serde(default)]
    pub seccomp_profile: Option<String>,

    // ── Process type ──────────────────────────────────────────────────────────
    /// If true, the supervisor waits for the process to exit before
    /// advancing to the next startup phase. Use for setup scripts.
    #[serde(default)]
    pub oneshot: bool,

    /// If true, attach stdin/stdout/stderr directly to /dev/console.
    /// Use for interactive shells/getty-style services.
    #[serde(default)]
    pub console: bool,

    /// If true, defer this service to the post-boot launcher phase.
    /// Use for display managers or other graphical bridges.
    #[serde(default)]
    pub launcher: bool,

    // ── Readiness ─────────────────────────────────────────────────────────────
    /// How to detect service readiness:
    /// - `simple`      → assume ready immediately after fork (default)
    /// - `notify`      → wait for `READY=1` on NOTIFY_SOCKET (sd_notify)
    /// - `bg-process`  → poll `pid_file` for existence + non-zero PID
    #[serde(default)]
    pub notify_type: NotifyType,

    /// PID file path. Required when `notify_type = "bg-process"`.
    /// The supervisor reads the PID from this file and tracks the daemonized process.
    #[serde(default)]
    pub pid_file: Option<String>,

    /// Optional path that must exist before the service is considered ready.
    /// Useful for daemon-managed Unix sockets like `quantra-netd`.
    #[serde(default)]
    pub ready_socket: Option<String>,

    /// Optional path where a symlink should be created pointing to
    /// `ready_socket` once the daemon is up.
    #[serde(default)]
    pub socket_alias: Option<String>,

    // ── Watchdog ──────────────────────────────────────────────────────────────
    /// Heartbeat timeout in seconds. If > 0, a background watchdog thread checks
    /// that the process is still alive. If the process disappears without
    /// a stop request, it is treated as a crash and the restart policy applies.
    /// Set to 0 to disable (default).
    #[serde(default)]
    pub watchdog_sec: u64,

    // ── Stop / Reload ─────────────────────────────────────────────────────────
    /// Optional custom teardown command. If set, this is executed BEFORE
    /// sending SIGTERM. If it exits 0, SIGTERM is skipped.
    /// Example: `stop_command = "/usr/bin/my-service-stop.sh"`
    #[serde(default)]
    pub stop_command: Option<String>,

    /// Arguments for `stop_command`.
    #[serde(default)]
    pub stop_args: Vec<String>,

    /// Signal to send for config reload (used when `reload_command` is not set).
    /// Accepts: `SIGHUP`, `SIGUSR1`, `SIGUSR2`, `SIGALRM`, etc.
    /// Default: `SIGHUP` (standard reload signal).
    #[serde(default = "default_reload_signal")]
    pub reload_signal: String,

    /// Optional command to run for config reload instead of sending a signal.
    /// If set, this takes priority over `reload_signal`.
    /// Example: `reload_command = "/usr/bin/nginx -s reload"`
    #[serde(default)]
    pub reload_command: Option<String>,

    // ── Chain / Pipeline ──────────────────────────────────────────────────────
    /// Service to start automatically when this service exits with code 0.
    /// Useful for scripted boot sequences (e.g. `firewall-setup` → `network`).
    #[serde(default)]
    pub chain_to: Option<String>,

    /// If true, `chain_to` triggers on ANY exit code, not just 0.
    /// Use for emergency fallback services that must always run.
    #[serde(default)]
    pub chain_to_always: bool,

    // ── Environment ───────────────────────────────────────────────────────────
    /// Path to a `KEY=VALUE` file to source before exec.
    /// Compatible with `/etc/default/<service>` (Debian/Ubuntu standard).
    /// Lines starting with `#` are ignored. `KEY=VALUE` pairs are merged into
    /// the environment overlay (service `environment` table takes priority).
    #[serde(default)]
    pub env_file: Option<String>,

    /// Environment variables overlaid onto the service's base env.
    pub environment: Option<HashMap<String, String>>,

    // ── Identity ──────────────────────────────────────────────────────────────
    /// Unprivileged user (name or numeric UID). Resolved via /etc/passwd.
    pub user: Option<String>,
    /// Group (name or numeric GID). Resolved via /etc/group.
    /// setgid called BEFORE setuid — this is the correct security order.
    pub group: Option<String>,
    /// Working directory for the service process (chdir before exec).
    pub working_dir: Option<String>,

    /// Controlling terminal path for interactive services.
    /// Opened after `setsid()` so shells get a real job-control tty.
    #[serde(default)]
    pub tty: Option<String>,

    // ── Resource Limits ───────────────────────────────────────────────────────
    /// Per-service resource limits applied before exec via `setrlimit(2)`.
    ///
    /// Format: `rlimit = { nofile = [1024, 4096], nproc = [64, 128] }`
    /// Each value is `[soft, hard]`. Use `0` to mean "unlimited".
    #[serde(default)]
    pub rlimit: Option<ResourceLimits>,

    // ── Restart ───────────────────────────────────────────────────────────────
    #[serde(default)]
    pub restart: RestartPolicy,
    #[serde(default = "default_restart_sec")]
    pub restart_sec: u64,

    /// Maximum number of restarts allowed within `restart_interval_sec`.
    /// After this limit is hit, the service is permanently stopped (no more restarts).
    /// Set to 0 for unlimited restarts (default).
    #[serde(default)]
    pub max_restarts: u32,

    /// Time window (seconds) for counting restarts against `max_restarts`.
    /// Restarts older than this window are forgotten.
    #[serde(default = "default_restart_interval_sec")]
    pub restart_interval_sec: u64,

    // ── Timeouts ──────────────────────────────────────────────────────────────
    /// Max seconds to wait for sd_notify READY=1 or pid_file to appear.
    #[serde(default = "default_timeout_start")]
    pub timeout_start: u64,

    /// Seconds to wait after SIGTERM before sending SIGKILL.
    #[serde(default = "default_timeout_stop")]
    pub timeout_stop: u64,

    // ── Dependencies ──────────────────────────────────────────────────────────
    /// Hard dependencies — service will not start until these are RUNNING.
    /// Boot fails if any hard dependency fails to start.
    #[serde(default)]
    pub dependencies: Vec<String>,

    /// Soft dependencies — service prefers these but starts regardless.
    /// Used for dependency wave ordering only.
    #[serde(default)]
    pub wants: Vec<String>,

    /// Milestone dependencies — wait for these to start, but continue boot
    /// even if they fail. Ideal for optional services like Bluetooth, printing.
    /// Semantically equivalent to systemd `Wants=`.
    #[serde(default)]
    pub milestone: Vec<String>,

    /// Start after these services (ordering constraint, not a hard dependency).
    /// Does not require them to succeed — only imposes start ordering.
    #[serde(default)]
    pub after: Vec<String>,

    // ── Socket activation ─────────────────────────────────────────────────────
    /// Sockets to pre-open for socket activation. Formats:
    /// - `"unix:/run/myapp.sock"`
    /// - `"tcp:0.0.0.0:8080"`
    #[serde(default)]
    pub socket_listen: Vec<String>,

    // ── cgroup v2 resource limits ─────────────────────────────────────────────
    /// Optional cgroup v2 resource controls applied to the service slice.
    ///
    /// ```toml
    /// [cgroup_config]
    /// memory_limit = "512M"   # OOM-kill service, not system
    /// cpu_weight   = 100      # 1–10000, default 100
    /// io_weight    = 100      # 1–10000, default 100
    /// ```
    #[serde(default)]
    pub cgroup_config: Option<CgroupConfig>,

    // ── Healthcheck ───────────────────────────────────────────────────────────
    /// Post-start health monitoring. Runs a command periodically after the
    /// service is RUNNING. N consecutive failures trigger a restart.
    ///
    /// ```toml
    /// [healthcheck]
    /// command           = "/usr/lib/my-service/health.sh"
    /// interval_sec      = 10
    /// failure_threshold = 3
    /// ```
    #[serde(default)]
    pub healthcheck: Option<HealthCheck>,

    // ── Conditional dependencies ──────────────────────────────────────────────
    /// Hardware-conditional dependencies. Only added as hard deps if the
    /// specified kernel path exists. Allows one service file to work on
    /// systems with and without optional hardware.
    ///
    /// ```toml
    /// [conditional_dependencies]
    /// bluetooth = "hardware-present:/sys/class/bluetooth"
    /// wifi      = "hardware-present:/sys/class/net/wlan0"
    /// ```
    #[serde(default)]
    pub conditional_dependencies: HashMap<String, String>,

    // ── Pre/Post hooks ───────────────────────────────────────────────────
    /// Commands to run before the main process starts.
    /// If any command exits non-zero, the service start is aborted.
    #[serde(default)]
    pub exec_start_pre: Vec<String>,

    /// Commands to run after the service is successfully started.
    /// Failures are logged but do not affect the service state.
    #[serde(default)]
    pub exec_start_post: Vec<String>,

    // ── Conditions (skip-if-unmet) ───────────────────────────────────────
    /// Skip service start if any of these paths do NOT exist.
    #[serde(default)]
    pub condition_path_exists: Vec<String>,

    /// Skip service start if any of these paths DO exist.
    #[serde(default)]
    pub condition_path_not_exists: Vec<String>,

    // ── Namespace isolation ──────────────────────────────────────────────
    /// Mount a private tmpfs at /tmp for this service (unshare mount namespace).
    #[serde(default)]
    pub private_tmp: bool,

    /// Remount / as read-only in the service's mount namespace.
    #[serde(default)]
    pub protect_system: bool,

    // ── Landlock filesystem restriction ──────────────────────────────────
    /// If non-empty, restrict this service's filesystem access to ONLY these paths
    /// using Landlock LSM (kernel 5.13+). All other paths become inaccessible.
    #[serde(default)]
    pub landlock_paths: Vec<String>,

    // ── cgroup v2 extended ────────────────────────────────────────────────
    /// CPU time % limit. "50%" = half a CPU, "200%" = 2 CPUs. → cpu.max
    #[serde(default)]
    pub cpu_quota: Option<String>,
    /// Max tasks (threads+processes) in service cgroup. → pids.max
    #[serde(default)]
    pub tasks_max: Option<u32>,
    /// Max swap. "0"=none, "max"=unlimited. → memory.swap.max
    #[serde(default)]
    pub memory_swap_max: Option<String>,

    // ── Namespace isolation ───────────────────────────────────────────────
    /// Private network namespace — service cannot reach host network.
    #[serde(default)]
    pub private_network: bool,
    /// Private /dev — only safe pseudo-devices visible.
    #[serde(default)]
    pub private_devices: bool,
    /// Private IPC namespace (CLONE_NEWIPC).
    #[serde(default)]
    pub private_ipc: bool,
    /// Private UTS namespace — cannot change hostname.
    #[serde(default)]
    pub protect_hostname: bool,

    // ── Home / proc protection ────────────────────────────────────────────
    /// Access control for /home /root /run/user.
    #[serde(default)]
    pub protect_home: ProtectHome,
    /// /proc visibility control.
    #[serde(default)]
    pub protect_proc: ProtectProc,

    // ── Kernel protection ─────────────────────────────────────────────────
    /// Remount /proc/sys, /sys read-only.
    #[serde(default)]
    pub protect_kernel_tunables: bool,
    /// Block finit_module/init_module/delete_module via seccomp.
    #[serde(default)]
    #[allow(dead_code)] // parsed, sandbox enforcement not wired up yet
    pub protect_kernel_modules: bool,
    /// Block /dev/kmsg access.
    #[serde(default)]
    pub protect_kernel_logs: bool,
    /// Block clock_settime/settimeofday via seccomp.
    #[serde(default)]
    #[allow(dead_code)] // parsed, sandbox enforcement not wired up yet
    pub protect_clock: bool,
    /// Remount /sys/fs/cgroup read-only.
    #[serde(default)]
    pub protect_control_groups: bool,

    // ── Path controls ─────────────────────────────────────────────────────
    /// Bind /dev/null over these paths — completely inaccessible.
    #[serde(default)]
    pub inaccessible_paths: Vec<String>,
    /// Remount these paths read-only in service namespace.
    #[serde(default)]
    pub read_only_paths: Vec<String>,
    /// Explicitly keep these paths read-write (with protect_system).
    #[serde(default)]
    #[allow(dead_code)] // parsed, sandbox enforcement not wired up yet
    pub read_write_paths: Vec<String>,
    /// Bind-mount pairs "host:dest" into service namespace.
    #[serde(default)]
    pub bind_paths: Vec<String>,
    /// Read-only bind-mount pairs "host:dest".
    #[serde(default)]
    pub bind_read_only_paths: Vec<String>,

    // ── Memory protection ─────────────────────────────────────────────────
    /// W^X enforcement — memory cannot be write+exec simultaneously. PR_SET_MDWE.
    #[serde(default)]
    pub memory_deny_write_execute: bool,

    // ── Syscall/namespace restriction ────────────────────────────────────
    /// Block unshare/clone CLONE_NEW* via seccomp.
    #[serde(default)]
    #[allow(dead_code)] // parsed, sandbox enforcement not wired up yet
    pub restrict_namespaces: bool,
    /// Block suid/sgid file creation via seccomp.
    #[serde(default)]
    pub restrict_suid_sgid: bool,
    /// Block SCHED_FIFO/RR scheduling via seccomp.
    #[serde(default)]
    pub restrict_realtime: bool,
    /// Block personality(2) syscall.
    #[serde(default)]
    pub lock_personality: bool,
    /// Allowed socket address families. Empty = no restriction.
    #[serde(default)]
    pub restrict_address_families: Vec<String>,
    /// "allowlist" or "denylist" (default). Controls syscall_filter mode.
    #[serde(default = "default_syscall_filter_mode")]
    pub syscall_filter_mode: String,

    // ── Chroot ───────────────────────────────────────────────────────────
    /// chroot(2) to this path before exec.
    #[serde(default)]
    pub root_directory: Option<String>,

    /// Mount this disk image (ext4/squashfs/btrfs) as the service root.
    /// The image is mounted via loop device, then chroot applied.
    /// Takes precedence over root_directory= if both are set.
    #[serde(default)]
    pub root_image: Option<String>,

    // ── Auto-create directories ───────────────────────────────────────────
    /// Auto-create /run/<name>, chown to service user.
    #[serde(default)]
    pub runtime_directory: Option<String>,
    /// Auto-create /var/lib/<name>, chown to service user.
    #[serde(default)]
    pub state_directory: Option<String>,
    /// Auto-create /var/cache/<name>, chown to service user.
    #[serde(default)]
    pub cache_directory: Option<String>,
    /// Auto-create /var/log/<name>, chown to service user.
    #[serde(default)]
    pub logs_directory: Option<String>,

    /// Per-device I/O weight: map of device_path → weight (1-10000).
    /// Example: `{ "/dev/sda" = 500 }` — give this service 500/1000 weight on sda.
    /// Maps to cgroup v2 `io.weight` per-device entries.
    #[serde(default)]
    pub io_device_weights: std::collections::HashMap<String, u32>,

    /// Per-device I/O latency targets: map of device_path → microseconds.
    /// Example: `{ "/dev/sda" = 25000 }` — target 25ms latency on sda.
    /// Maps to cgroup v2 `io.latency`.
    #[serde(default)]
    pub io_device_latencies: std::collections::HashMap<String, u64>,

    // ── Post-death hooks ──────────────────────────────────────────────────
    /// Run after service fully stopped. Always runs, failures non-fatal.
    #[serde(default)]
    pub exec_stop_post: Vec<String>,

    // ── Dynamic user ─────────────────────────────────────────────────────
    /// Allocate ephemeral UID/GID at runtime; reclaim on stop.
    #[serde(default)]
    pub dynamic_user: bool,

    // ── MEDIUM: Additional namespace/path features ────────────────────────
    /// Mount a private user namespace. Maps UID 0 inside to nobody outside.
    #[serde(default)]
    #[allow(dead_code)] // parsed, sandbox enforcement not wired up yet
    pub private_users: bool,

    /// Mount tmpfs on specific paths. Format: "path" or "path:size:mode".
    /// Example: `temporary_filesystems = ["/run/app:64M:0755", "/tmp"]`
    #[serde(default)]
    pub temporary_filesystems: Vec<String>,

    /// Mount /proc /sys /dev inside the service's private namespace.
    /// Required when using root_directory= with a minimal chroot.
    #[serde(default)]
    pub mount_api_vfs: bool,

    /// Remount /proc with subset=pid — only own PID subtree visible (kernel 5.8+).
    #[serde(default)]
    pub proc_subset_pid: bool,

    // ── MEDIUM: Capability management ────────────────────────────────────
    /// Add capabilities to the ambient set (inherited by execve'd processes).
    /// Example: `ambient_capabilities = ["CAP_NET_BIND_SERVICE"]`
    #[serde(default)]
    pub ambient_capabilities: Vec<String>,

    /// Full capability bounding set specification.
    /// "~CAP_SYS_ADMIN" = all caps except SYS_ADMIN.
    /// Empty = no change (drop_capabilities still applies).
    #[serde(default)]
    pub capability_bounding_set: Vec<String>,

    // ── MEDIUM: Network filtering ─────────────────────────────────────────
    /// Denied IP address ranges (CIDR). Service cannot connect to these.
    /// Example: `ip_address_deny = ["any"]` blocks all IP traffic.
    #[serde(default)]
    pub ip_address_deny: Vec<String>,

    /// Allowed IP address ranges (CIDR). All others are denied.
    /// Only active when ip_address_deny is non-empty.
    #[serde(default)]
    pub ip_address_allow: Vec<String>,

    // ── MEDIUM: Service credentials ──────────────────────────────────────
    /// Encrypted credential files to decrypt and expose to the service.
    /// Format: `"id:path"` — id is the credential name, path is the encrypted file.
    /// Decrypted credentials are placed in $CREDENTIALS_DIRECTORY.
    #[serde(default)]
    #[allow(dead_code)] // parsed, sandbox enforcement not wired up yet
    pub load_credential: Vec<String>,

    // ── LOW: Additional flags ─────────────────────────────────────────────
    /// Block non-native ABI syscalls (32-bit on 64-bit kernel).
    /// Already enforced by existing seccomp filter — this is a documentation field.
    #[serde(default = "bool_true")]
    pub system_call_architectures_native: bool,

    /// Restrict allowed socket address families via seccomp.
    /// Example: `["AF_UNIX", "AF_INET", "AF_INET6"]`
    #[serde(default)]
    #[allow(dead_code)] // parsed, sandbox enforcement not wired up yet
    pub socket_bind_deny: Vec<String>,

    /// Allow only specific port ranges for socket bind().
    /// Format: `"protocol:port"` e.g. `["tcp:443", "tcp:80"]`.
    #[serde(default)]
    #[allow(dead_code)] // parsed, sandbox enforcement not wired up yet
    pub socket_bind_allow: Vec<String>,
}

// ── ResourceLimits ────────────────────────────────────────────────────────────

/// Per-service resource limits applied before exec via `setrlimit(2)`.
///
/// Each field is `[soft_limit, hard_limit]`.
/// Use `0` for "unlimited" (mapped to `RLIM_INFINITY` internally).
///
/// ```toml
/// [rlimit]
/// nofile = [4096, 8192]    # open file descriptors
/// nproc  = [128, 256]      # threads/processes
/// fsize  = [0, 0]          # file size (0 = unlimited)
/// stack  = [8388608, 0]    # stack size bytes (8 MB soft, unlimited hard)
/// memlock = [65536, 65536] # locked memory bytes
/// ```
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ResourceLimits {
    /// RLIMIT_NOFILE — maximum number of open file descriptors
    #[serde(default)]
    pub nofile: Option<[u64; 2]>,

    /// RLIMIT_NPROC — maximum number of threads/processes for this UID
    #[serde(default)]
    pub nproc: Option<[u64; 2]>,

    /// RLIMIT_FSIZE — maximum file size in bytes (0 = unlimited)
    #[serde(default)]
    pub fsize: Option<[u64; 2]>,

    /// RLIMIT_STACK — maximum stack size in bytes
    #[serde(default)]
    pub stack: Option<[u64; 2]>,

    /// RLIMIT_MEMLOCK — maximum locked-in-memory address space in bytes
    #[serde(default)]
    pub memlock: Option<[u64; 2]>,

    /// RLIMIT_CORE — maximum core file size in bytes (0 = no core dumps)
    #[serde(default)]
    pub core: Option<[u64; 2]>,
}

impl ResourceLimits {
    /// Apply all configured limits in the child process (call before exec).
    ///
    /// Maps `0` → `libc::RLIM_INFINITY`.
    ///
    /// # Safety
    /// Must be called from the child after fork, before exec. No allocations.
    pub fn apply(&self) {
        if let Some(lim) = self.nofile {
            set_rlimit(libc::RLIMIT_NOFILE as libc::c_uint, lim[0], lim[1]);
        }
        if let Some(lim) = self.nproc {
            set_rlimit(libc::RLIMIT_NPROC as libc::c_uint, lim[0], lim[1]);
        }
        if let Some(lim) = self.fsize {
            set_rlimit(libc::RLIMIT_FSIZE as libc::c_uint, lim[0], lim[1]);
        }
        if let Some(lim) = self.stack {
            set_rlimit(libc::RLIMIT_STACK as libc::c_uint, lim[0], lim[1]);
        }
        if let Some(lim) = self.memlock {
            set_rlimit(libc::RLIMIT_MEMLOCK as libc::c_uint, lim[0], lim[1]);
        }
        if let Some(lim) = self.core {
            set_rlimit(libc::RLIMIT_CORE as libc::c_uint, lim[0], lim[1]);
        }
    }
}

fn set_rlimit(resource: libc::c_uint, soft: u64, hard: u64) {
    let to_rlim = |v: u64| {
        if v == 0 {
            libc::RLIM_INFINITY
        } else {
            v as libc::rlim_t
        }
    };
    let rl = libc::rlimit {
        rlim_cur: to_rlim(soft),
        rlim_max: to_rlim(hard),
    };
    // SAFETY: resource is a valid RLIMIT_* constant, rl is properly initialized.
    // We intentionally ignore errors — child cannot log after fork.
    unsafe { libc::setrlimit(resource, &rl) };
}

// ── CgroupConfig ──────────────────────────────────────────────────────────────

/// cgroup v2 resource controls for a service slice.
///
/// Applied after `create_service_cgroup()` by writing to the kernel cgroup files.
/// Falls back silently on cgroup v1 kernels.
///
/// ```toml
/// [cgroup_config]
/// memory_limit = "512M"   # OOM-kills the service slice, not the whole system
/// cpu_weight   = 100      # relative CPU share (1–10000, default 100)
/// io_weight    = 100      # relative I/O share (1–10000, default 100)
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct CgroupConfig {
    /// Memory limit string: "512M", "1G", "256K", or a raw byte count.
    /// 0 or absent = unlimited.
    #[serde(default)]
    pub memory_limit: Option<String>,

    /// Relative CPU weight (1–10000). Default kernel value is 100.
    #[serde(default)]
    pub cpu_weight: Option<u32>,

    /// Relative I/O weight (1–10000). Default kernel value is 100.
    #[serde(default)]
    pub io_weight: Option<u32>,
}

impl CgroupConfig {
    /// Apply cgroup resource controls to the named service slice.
    /// Call AFTER `create_service_cgroup()` in the parent process.
    pub fn apply(&self, service_name: &str) {
        let slice = format!("/sys/fs/cgroup/quantra-system/{}", service_name);

        if let Some(ref mem) = self.memory_limit {
            let bytes = parse_memory_limit(mem);
            let val = if bytes == 0 {
                "max".to_string()
            } else {
                bytes.to_string()
            };
            let path = format!("{}/memory.max", slice);
            if std::fs::write(&path, &val).is_ok() {
                log::debug!("cgroup memory.max={} for '{}'", val, service_name);
            }
        }

        if let Some(w) = self.cpu_weight {
            let path = format!("{}/cpu.weight", slice);
            if std::fs::write(&path, w.to_string()).is_ok() {
                log::debug!("cgroup cpu.weight={} for '{}'", w, service_name);
            }
        }

        if let Some(w) = self.io_weight {
            let path = format!("{}/io.weight", slice);
            // io.weight format: "default N"
            if std::fs::write(&path, format!("default {}", w)).is_ok() {
                log::debug!("cgroup io.weight={} for '{}'", w, service_name);
            }
        }
    }
}

/// Parse memory limit strings like "512M", "1G", "256K" into bytes.
/// Returns 0 for "max", "0", or unparseable input (= unlimited).
pub fn parse_memory_limit(s: &str) -> u64 {
    let s = s.trim();
    if s == "max" || s == "0" || s.is_empty() {
        return 0;
    }
    // Check if last character is a unit suffix letter
    let last = s.as_bytes()[s.len() - 1];
    if !last.is_ascii_alphabetic() {
        // No suffix — treat whole string as raw byte count
        return s.parse().unwrap_or(0);
    }
    let (digits, suffix) = s.split_at(s.len() - 1);
    let multiplier: u64 = match suffix.to_ascii_uppercase().as_str() {
        "K" => 1024,
        "M" => 1024 * 1024,
        "G" => 1024 * 1024 * 1024,
        "T" => 1024 * 1024 * 1024 * 1024,
        _ => {
            // Unknown suffix — treat whole string as raw byte count
            return s.parse().unwrap_or(0);
        }
    };
    digits
        .parse::<u64>()
        .unwrap_or(0)
        .saturating_mul(multiplier)
}

// ── HealthCheck ───────────────────────────────────────────────────────────────

/// Post-start service health monitoring.
///
/// A background thread runs `command` every `interval_sec` seconds.
/// After `failure_threshold` consecutive non-zero exits, the service
/// is treated as unhealthy and restarted.
///
/// **No other init system (systemd, dinit, s6, runit) has this.**
/// Equivalent to Docker's `HEALTHCHECK` instruction.
///
/// ```toml
/// [healthcheck]
/// command           = "/usr/lib/nginx/health-check.sh"
/// interval_sec      = 10
/// failure_threshold = 3
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct HealthCheck {
    /// Command to run for the health check. Must exit 0 for healthy.
    pub command: String,

    /// Optional args for the health check command.
    #[serde(default)]
    pub args: Vec<String>,

    /// Interval between health checks in seconds. Default: 10.
    #[serde(default = "default_healthcheck_interval")]
    pub interval_sec: u64,

    /// Number of consecutive failures before triggering a restart. Default: 3.
    #[serde(default = "default_healthcheck_threshold")]
    pub failure_threshold: u32,

    /// Seconds to wait for the health check command to complete. Default: 5.
    #[serde(default = "default_healthcheck_timeout")]
    pub timeout_sec: u64,
}

fn default_healthcheck_interval() -> u64 {
    10
}
fn default_healthcheck_threshold() -> u32 {
    3
}
fn default_healthcheck_timeout() -> u64 {
    5
}

// ── RestartPolicy ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    Always,
    OnFailure,
    #[default]
    No,
}

// ── NotifyType ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NotifyType {
    /// No readiness wait — service assumed ready immediately after fork (default)
    #[default]
    Simple,
    /// Wait for `READY=1` on NOTIFY_SOCKET (sd_notify compatible services)
    Notify,
    /// Poll `pid_file` for existence and a valid non-zero PID.
    /// Use for traditional daemons that fork to background and write a PID file.
    BgProcess,
}

// ── DependencyType ─────────────────────────────────────────────────────────────

/// Dependency relationship between services.
#[allow(dead_code)] // Consumed by dependency wave-sort module; variants are API surface
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyType {
    /// Hard: service will not start until the dependency is RUNNING.
    /// Boot fails if the dependency fails.
    Regular,

    /// Milestone: wait for the dependency to reach STARTED state, but
    /// continue boot even if it fails. Ideal for optional services
    /// (Bluetooth, printing, optional sensors).
    Milestone,

    /// Ordering only: start after the dependency, but do not wait for it.
    /// Does not require the dependency to succeed.
    After,
}

// ── Seccomp ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SeccompMode {
    /// No seccomp filter is applied.
    #[default]
    Off,
    /// Kernel strict mode (`SECCOMP_MODE_STRICT`).
    Strict,
    /// Apply a named seccomp-bpf profile (denylist) before exec.
    Profile,
}

// ── Defaults ──────────────────────────────────────────────────────────────────

fn default_restart_sec() -> u64 {
    5
}
fn default_restart_interval_sec() -> u64 {
    60
}
fn default_timeout_start() -> u64 {
    90
}
fn default_timeout_stop() -> u64 {
    30
}
fn default_no_new_privileges() -> bool {
    true
}
fn default_non_dumpable() -> bool {
    true
}
fn default_reload_signal() -> String {
    "SIGHUP".to_string()
}
fn default_syscall_filter_mode() -> String {
    "denylist".to_string()
}
fn bool_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::{Service, parse_memory_limit};

    #[test]
    fn parse_memory_limit_512m() {
        assert_eq!(parse_memory_limit("512M"), 536_870_912);
    }

    #[test]
    fn parse_memory_limit_1g() {
        assert_eq!(parse_memory_limit("1G"), 1_073_741_824);
    }

    #[test]
    fn parse_memory_limit_256k() {
        assert_eq!(parse_memory_limit("256K"), 262_144);
    }

    #[test]
    fn parse_memory_limit_1t() {
        assert_eq!(parse_memory_limit("1T"), 1_099_511_627_776);
    }

    #[test]
    fn parse_memory_limit_max_returns_zero() {
        assert_eq!(parse_memory_limit("max"), 0);
    }

    #[test]
    fn parse_memory_limit_zero_returns_zero() {
        assert_eq!(parse_memory_limit("0"), 0);
    }

    #[test]
    fn parse_memory_limit_empty_returns_zero() {
        assert_eq!(parse_memory_limit(""), 0);
    }

    #[test]
    fn parse_memory_limit_raw_bytes() {
        assert_eq!(parse_memory_limit("1048576"), 1_048_576);
    }

    #[test]
    fn parse_memory_limit_single_digit() {
        // Bug fix: "1" used to return 0 due to split_at(0) edge case
        assert_eq!(parse_memory_limit("1"), 1);
    }

    #[test]
    fn parse_memory_limit_whitespace_trimmed() {
        assert_eq!(parse_memory_limit("  512M  "), 536_870_912);
    }

    #[test]
    fn parse_memory_limit_lowercase_suffix() {
        assert_eq!(parse_memory_limit("512m"), 536_870_912);
    }

    #[test]
    fn service_exec_start_pre_post_defaults_empty() {
        let svc = Service::default();
        assert!(svc.exec_start_pre.is_empty());
        assert!(svc.exec_start_post.is_empty());
    }

    #[test]
    fn service_condition_paths_defaults_empty() {
        let svc = Service::default();
        assert!(svc.condition_path_exists.is_empty());
        assert!(svc.condition_path_not_exists.is_empty());
    }

    #[test]
    fn service_namespace_defaults_false() {
        let svc = Service::default();
        assert!(!svc.private_tmp);
        assert!(!svc.protect_system);
    }

    #[test]
    fn service_landlock_defaults_empty() {
        let svc = Service::default();
        assert!(svc.landlock_paths.is_empty());
    }

    #[test]
    fn service_toml_with_phase_c_fields() {
        let toml = r#"
name = "hardened"
command = "/usr/bin/app"
exec_start_pre = ["mkdir -p /var/run/app"]
exec_start_post = ["echo started"]
condition_path_exists = ["/etc/app.conf"]
private_tmp = true
protect_system = true
landlock_paths = ["/usr", "/etc", "/var/run/app"]
"#;
        let svc: Service = toml::from_str(toml).unwrap();
        assert_eq!(svc.exec_start_pre.len(), 1);
        assert_eq!(svc.exec_start_post.len(), 1);
        assert_eq!(svc.condition_path_exists.len(), 1);
        assert!(svc.private_tmp);
        assert!(svc.protect_system);
        assert_eq!(svc.landlock_paths.len(), 3);
    }
}

// ── ProtectHome enum ─────────────────────────────────────────────────────────

/// Controls access to home directories in the service's mount namespace.
#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectHome {
    /// /home /root /run/user remain accessible (default)
    #[default]
    No,
    /// Remount /home /root /run/user as read-only
    ReadOnly,
    /// Mount empty tmpfs over /home /root /run/user (appears empty)
    Tmpfs,
    /// Make /home /root /run/user completely inaccessible (bind /dev/null)
    Yes,
}

// ── ProtectProc enum ─────────────────────────────────────────────────────────

/// Controls /proc visibility in the service's mount namespace.
#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectProc {
    /// /proc not restricted (default)
    #[default]
    Default,
    /// Other processes' /proc/<pid> entries are invisible (hidepid=invisible)
    Invisible,
    /// Other processes' /proc/<pid> entries return EACCES (hidepid=noaccess)
    Noaccess,
    /// Only ptrace-able processes are visible
    Ptraceable,
}

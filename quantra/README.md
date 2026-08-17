# quantra — Zainium OS PID 1

**Version:** 6.0.0 · **License:** MIT · **Target:** `x86_64-unknown-linux-musl`

`quantra` is the init daemon (PID 1) for Zainium OS: parses service TOML
units, resolves dependencies, starts services in dependency-ordered waves,
applies cgroup v2 / AppArmor / seccomp, and supervises restarts and
health checks. Written in Rust, no `unsafe` outside the syscall-boundary
code that PID 1 inherently needs (`fork`/`exec`/`setuid`/cgroup/seccomp
plumbing).

## Boot sequence

From `src/main.rs`'s own phase ordering (the numbering has a real gap —
phase 11 doesn't exist in the code, phases jump 10 → 12):

```text
kernel → quantra (PID 1)
  1.  mounts::setup()          procfs, sysfs, devtmpfs, cgroups
  2.  logging setup            stderr + /overlayer/syshub/var/log/quantra-system/
  3.  AppArmor profile load    before any service starts
  3b. kernel lockdown + memory locking (PID 1 hardening)
  4.  kernel parameters        hostname / sysctl / modules
  5.  network interfaces       lo up + DHCP (non-fatal)
  6.  signal handlers          SA_RESTART + SIGCHLD reaper thread
  7.  mount units               user-space mounts from .../quantra-system/mounts/
  8.  services::start_all()    dependency-ordered parallel waves
  9.  control::start_socket()  Unix control socket (std-only, no tokio)
  10. timer units              cron-style replacement
  12. graphical launcher       optional display-manager bridge (cosmic-greeter)
```

### Service startup, per service

```text
parse TOML → resolve dependencies → validate
  → create cgroup slice → apply cgroup_config (memory/cpu/io weight)
  → load env_file + environment overlay
  → fork()
      parent: assign PID to cgroup, wait for readiness
              (simple / notify / bg-process)
      child:  setgid → setuid → chdir(working_dir)
              apply rlimit, AppArmor profile, PR_SET_NO_NEW_PRIVS,
              seccomp filter → execve(command, args, env)
  → background threads: restart monitor, watchdog (if watchdog_sec > 0),
    healthcheck poller (if [healthcheck] set)
```

### Readiness (`notify_type`)

| Value | Behavior |
|---|---|
| `simple` | ready immediately after fork (default) |
| `notify` | waits for `READY=1` on `NOTIFY_SOCKET` (sd_notify-compatible) |
| `bg-process` | polls `pid_file` for a valid, non-zero PID |

### Dependency fields

| Field | Behavior |
|---|---|
| `dependencies` | hard — must be running first; boot fails if it can't start |
| `wants` | soft — ordering only, failure doesn't block |
| `milestone` | waited for, but boot continues even if it fails |
| `after` | ordering only — no wait, no failure propagation |
| `conditional_dependencies` | added as a hard dep only if a given kernel path exists |

## quantra-ctl reference

```sh
# Lifecycle
quantra-ctl start    <service>
quantra-ctl stop     <service>      # stop_command → SIGTERM → SIGKILL
quantra-ctl restart  <service>
quantra-ctl reload   <service>      # reload_command, or reload_signal (default SIGHUP)
quantra-ctl kill     <service>      # SIGKILL immediately

# Persistence
quantra-ctl enable   <service>      # create enabled/<service> marker
quantra-ctl disable  <service>      # remove marker

# Inspection
quantra-ctl status   <service>      # JSON: pid, running, restarts, uptime
quantra-ctl list                    # all services + state
quantra-ctl tree                    # dependency graph
quantra-ctl metrics                 # Prometheus-format counters

# Runtime control
quantra-ctl signal   <sig> <svc>
quantra-ctl setenv   KEY=VALUE
quantra-ctl add-dep  <type> <a> <b>
quantra-ctl rm-dep   <a> <b>

# Scripting
quantra-ctl is-started <service>    # exit 0 = running
quantra-ctl is-failed  <service>    # exit 0 = stopped/failed

# System
quantra-ctl isolate   <target>      # stop everything except <target>
quantra-ctl shutdown
```

## Service unit reference

Fields below match `src/services/types.rs`'s `Service` struct — this is
not an exhaustive list (see that file for `ready_socket`, `socket_alias`,
`drop_capabilities`, `clear_ambient_caps`, and pre/post exec hooks too).

```toml
name        = "my-service"
description = "My production daemon"
command     = "/overlayer/syshub/bin/my-service"
args        = ["--config", "/overlayer/syshub/etc/my-service.toml"]
user        = "my-service"
group       = "my-service"
working_dir = "/overlayer/syshub/var/lib/my-service"

# Process type
oneshot  = false
console  = false
launcher = false

# Readiness
notify_type  = "bg-process"
pid_file     = "/run/my-service/my-service.pid"
watchdog_sec = 30

# Stop / reload
stop_command  = "/overlayer/syshub/lib/my-service/stop.sh"
reload_signal = "SIGHUP"

# Chain to another service on exit 0
chain_to = "next-service"

# Environment
env_file = "/overlayer/syshub/etc/default/my-service"
[environment]
MY_VAR = "value"

# Resource limits ([soft, hard], 0 = unlimited)
[rlimit]
nofile = [4096, 8192]
nproc  = [128, 256]

# cgroup v2
[cgroup_config]
memory_limit = "512M"
cpu_weight   = 200
io_weight    = 100

# Post-start health monitoring
[healthcheck]
command           = "/overlayer/syshub/lib/my-service/health.sh"
interval_sec      = 10
failure_threshold = 3
timeout_sec       = 5

# Only added as a hard dependency if the kernel path exists
[conditional_dependencies]
bluetooth = "hardware-present:/sys/class/bluetooth"

# Security
no_new_privileges = true
non_dumpable      = true
seccomp           = "profile"
seccomp_profile   = "network-daemon"
apparmor_profile  = "my-service"

# Restart policy
restart              = "on-failure"
restart_sec          = 5
max_restarts         = 5
restart_interval_sec = 60
timeout_start        = 90
timeout_stop         = 30

# Dependencies
dependencies = ["quantra-netd"]
wants        = ["bluetooth"]
milestone    = ["printer"]
after        = ["quantra-net"]
```

## Cryptographic boot chain

Integrity verification happens one stage earlier than `quantra` itself —
in [`quantra-ramfs`](../quantra-ramfs/), via dm-verity (`src/verity.rs`)
and TPM2-backed measured boot (`src/measured_boot.rs`). `quantra-ramfs`
only `pivot_root`s and `execve`s into `quantra` after that verification
passes.

## JSON structured logging

Enable in `/overlayer/syshub/etc/quantra-system/init.toml`:

```toml
[logging]
format = "json"
```

```json
{"ts":"2026-04-27T01:00:00Z","level":"INFO","target":"quantra::services","msg":"nginx started — PID 1234"}
```

## Directory layout

Zainium has no `/etc`, `/var`, or `/usr` at the real root — everything
core-OS lives under `/overlayer/syshub` (matches `src/config.rs`):

```text
/overlayer/syshub/etc/quantra-system/
  init.toml       — global init config
  services/       — service unit definitions (*.toml)
  enabled/        — boot-enable markers (presence = auto-start)
  tmpfiles.d/     — tmpfiles.d-style provisioning rules
  vconsole.conf   — virtual console config

/overlayer/syshub/var/log/quantra-system/   — persistent logs
/overlayer/syshub/var/lib/quantra-system/   — persistent state

/run/quantra/
  control    — Unix socket (quantra-ctl connects here)
  metrics    — Prometheus metrics endpoint
  isolated   — marker written by `quantra-ctl isolate`

/run/quantra-system/
  journal.socket   — journald-style log socket
```

`/run/dbus` is currently hardcoded to the bare real-root path
(`src/tmpfiles.rs`, `src/utils.rs`) rather than being scoped under
`/overlayer/syshub` like everything else here — this is intentional, not
a bug: `/run` itself (unlike `/etc`/`/var`/`/usr`) is a real-root tmpfs on
Zainium, matching `/proc`/`/sys`/`/dev`, and `/run/dbus/system_bus_socket`
is the standard, compiled-in path `libdbus`/`dbus-daemon` expect —
scoping it under `/overlayer/syshub` would actually break interop with
anything that doesn't know Zainium's own layout.

## Verified facts

- FD limit: max 256 (documented constant, `src/main.rs`)
- Test suite: `cargo test -p quantra` — real unit tests, not placeholders
- Binary size / RSS: not published here — no number in a prior draft of
  this README was measured against the actual musl release build, so
  rather than repeat an unverified guess, it's omitted; measure locally
  with `cargo build --release --target x86_64-unknown-linux-musl` if you
  need current numbers.

## License

MIT — see [../LICENSE](../LICENSE).

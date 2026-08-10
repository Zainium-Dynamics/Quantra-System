# Quantra System

Core boot + service + session + network stack for **Zainium OS** — a Rust
init system (PID 1), initramfs, session/login manager, and network daemon,
purpose-built for Zainium's non-FHS `/overlayer` root layout.

**License:** MIT · **Edition:** Rust 2024 (2021 for `quantra-logind`) · **Version:** 6.0.x

## What's in this workspace

| Crate | Binary | Role |
|---|---|---|
| [`quantra`](quantra/) | `quantra` | PID 1 — parses service TOML units, resolves dependencies, starts services in dependency-ordered waves, applies cgroup v2 / AppArmor / seccomp, watches health/crash state. |
| [`quantra-ctl`](quantra-ctl/) | `quantra-ctl` | CLI to `quantra`'s control socket — start/stop/restart/enable/disable services, inspect status, tail metrics. |
| [`quantra-logind`](quantra-logind/) | `quantra-logind`, `quantra-logindctl` | Session/login manager — a `systemd-logind` superset, provides `org.freedesktop.login1` on the system D-Bus. |
| [`quantra-ramfs`](quantra-ramfs/) | `quantra-ramfs` | Stage-1 early-userspace boot orchestrator (initramfs) — device discovery, dm-verity/LUKS+TPM2, fsck, `pivot_root`, then `execve`s into `quantra`. |
| [`quantra-net/quantra-netd`](quantra-net/quantra-netd/) | `quantra-netd` | Privileged network daemon — interfaces, routing, DHCP, WireGuard, firewall, all via raw `rtnetlink`, no external tools shelled out to. |
| [`quantra-net/quantra-net`](quantra-net/quantra-net/) | `quantra-net` | CLI that talks to `quantra-netd` over its control socket. |
| [`quantra-net/common`](quantra-net/common/) | — | Shared IPC types/protocol between `quantra-net` and `quantra-netd`. |

## Boot flow

```text
kernel
  → quantra-ramfs (initramfs: discover root, verify, pivot_root)
    → quantra (PID 1: mounts, services, sockets)
       ├─ quantra-ctl     (operator CLI, talks to /run/quantra/control)
       ├─ quantra-logind  (session/login, system D-Bus org.freedesktop.login1)
       └─ quantra-netd    (network daemon, /run/quantra-system/quantra-netd.sock)
             └─ quantra-net (CLI)
```

## Filesystem layout

Zainium has no `/usr`, `/etc`, or `/var` at the real root — everything
lives under `/overlayer` (see [Zainium OS](https://github.com/Zainium-Dynamics/ZainiumOS)
for the full layout). Quantra's own paths:

```text
/overlayer/syshub/etc/quantra-system/
  init.toml          — global init config
  services/          — service unit definitions (*.toml)
  enabled/            — boot-enable markers (presence = auto-start)
  tmpfiles.d/          — tmpfiles.d-style directory/file provisioning rules
  vconsole.conf        — virtual console config

/overlayer/syshub/var/log/quantra-system/   — persistent logs
/overlayer/syshub/var/lib/quantra-system/   — persistent state

/run/quantra/control        — quantra-ctl's Unix control socket
/run/quantra/metrics        — Prometheus-format metrics endpoint
/run/quantra-system/        — runtime state (journal socket, etc.)
/run/quantra-system/quantra-netd.sock — quantra-net's IPC socket
/run/quantra-logind/         — quantra-logind runtime socket/session state
```

> **Known issue, not yet fixed**: a few runtime paths (`/run/dbus/...` in
> `quantra`'s tmpfiles/service-unit setup and `quantra-logind`'s D-Bus
> bridge) are still hardcoded to bare real-root `/run/dbus` instead of
> being scoped consistently — most other D-Bus paths in the same files
> already use `/overlayer/syshub/...` correctly. `/run` itself is treated
> as a real-root tmpfs exception throughout (matching `/proc`, `/sys`,
> `/dev`), which may be intentional, but isn't documented anywhere yet.

## Building

```sh
cargo build --workspace --release
```

Each binary is a normal `x86_64-unknown-linux-musl`-targetable Rust
binary — no special build tooling required beyond a standard Rust
toolchain. `quantra-ramfs` and `quantra` intentionally keep integer
overflow checks on (`overflow-checks = true`) even in release builds,
since PID 1 and the early-boot orchestrator must not silently wrap on bad
input.

```sh
cargo test --workspace       # 263 tests across the workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
```

## Status

Actively developed, pre-1.0. `clippy` currently has a backlog of
non-blocking style lints across the workspace (mostly `collapsible_if` and
doc-comment formatting) — CI runs it in report-only mode until that's
cleared; `fmt` and the test suite are hard gates.

## Contributing

Part of the [Zainium Dynamics](https://github.com/Zainium-Dynamics)
ecosystem. Issues and PRs welcome — see each crate's own README for
component-specific implementation notes.

## License

MIT — see [LICENSE](LICENSE).

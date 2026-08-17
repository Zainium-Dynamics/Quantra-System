# Quantra System

Core boot + service + session + network stack for **Zainium OS** — a Rust
init system (PID 1), initramfs, session/login manager, and network daemon,
purpose-built for Zainium's non-FHS `/overlayer` root layout.

**License:** MIT · **Edition:** Rust 2024 · **Version:** 6.0.x

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

> `/run/dbus/...` is intentionally hardcoded to the bare real-root path in
> `quantra` and `quantra-logind` rather than scoped under
> `/overlayer/syshub/...` like other config paths — `/run` itself is a
> real-root tmpfs exception throughout (matching `/proc`/`/sys`/`/dev`),
> and `/run/dbus/system_bus_socket` is the standard, compiled-in path
> `libdbus`/`dbus-daemon` expect, so scoping it under syshub would break
> interop rather than improve consistency.

## Building

```sh
cargo build --workspace --release
```

Every crate targets `x86_64-unknown-linux-musl` — no special build
tooling required beyond a standard Rust toolchain — **except
`quantra-ctl`**, whose own `quantra-ctl/.cargo/config.toml` pins
`target = "x86_64-zainium-linux-musl"`, a custom target with no
`.json` spec file anywhere in this repo. Building `quantra-ctl` from
within its own directory will fail until that's either given a real
target spec or repointed at `x86_64-unknown-linux-musl` like `quantra`'s
own `.cargo/config.toml` — not yet fixed. `quantra-ramfs` and `quantra`
intentionally keep integer overflow checks on (`overflow-checks = true`)
even in release builds, since PID 1 and the early-boot orchestrator must
not silently wrap on bad input.

```sh
cargo test --workspace       # 265 tests across the workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Status

Actively developed, pre-1.0. The workspace is currently clean under
`cargo clippy --workspace --all-targets -- -D warnings` and
`cargo fmt --all -- --check`, but CI's clippy job still runs with
`continue-on-error: true` (report-only) rather than as a hard gate —
`fmt` and the test suite are the hard gates today.

## Contributing

Part of the [Zainium Dynamics](https://github.com/Zainium-Dynamics)
ecosystem. Issues and PRs welcome — see each crate's own README for
component-specific implementation notes.

## License

MIT — see [LICENSE](LICENSE).

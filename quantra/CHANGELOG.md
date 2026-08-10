# Changelog

All notable changes to the Quantra init system are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version numbering follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.4] — 2026-04-27 (LTS until 2028-04-27)

### ⚠ Breaking Changes
- **Crate Split**: `quantra-ctl` is now a standalone crate (`engine/quantra-ctl/`). The PID 1 binary no longer ships CLI parsing code. This reduces PID 1 binary size by ~200KB and eliminates the `clap` transitive dependency tree from the init process.

### 🏗 Architecture
- **Tokio Removed**: The async runtime has been completely removed from the PID 1 binary. The control socket now uses `std::os::unix::net::UnixListener` with a blocking accept loop in a dedicated OS thread. This eliminates ~300KB of binary bloat and 20+ transitive dependencies while maintaining identical wire protocol semantics. Zero functional regression.
- **Protocol Versioning**: Added `PROTOCOL_VERSION = 1` constant to the control socket protocol. Future breaking changes will increment this value, enabling graceful client/server version negotiation during the 2-year LTS window.
- **SO_PEERCRED Auth**: Control socket now uses `getsockopt(SO_PEERCRED)` instead of tokio's `peer_cred()` for UID-based authorization — pure POSIX, no runtime dependency.

### 🔧 Bug Fixes
- **`parse_memory_limit("1")` returned 0**: Single-digit numeric input was incorrectly split at position 0, producing an empty digits string. Fixed by checking whether the last character is alphabetic before splitting. Now correctly returns the raw byte count.
- **`minutely` CalendarSpec identical to `hourly`**: Both keywords produced identical `CalendarSpec` structs (`hour: None, minute: 0, second: 0`), causing minutely timers to fire every 3600 seconds instead of 60. Fixed by adding a `minutely: bool` field that short-circuits `time_until_next()` to return `Duration::from_secs(60)`.

### 🧪 Test Coverage
- Added 11 unit tests for `parse_memory_limit()` covering: standard suffixes (K/M/G/T), `max`/`0`/empty returns, raw byte counts, single-digit edge case, whitespace trimming, and case-insensitive suffixes.
- Added 9 unit tests for `CalendarSpec::parse()` covering: HH:MM, HH:MM:SS, all keywords (daily/hourly/minutely/weekly), minutely ≠ hourly distinction, positive duration invariant, and invalid input rejection.
- Total test count: ~35 (up from ~15).

### 📦 Dependency Changes
| Crate | Action | Rationale |
|-------|--------|-----------|
| `tokio` | **Removed** | Replaced with std-only threaded control socket |
| `clap` | **Moved** to quantra-ctl | PID 1 does not need CLI parsing |

### 📋 Metadata
- Version aligned across all crates: `quantra`, `quantra-ramfs`, `quantra-ctl` all at `4.0.4`.
- `quantra-ramfs/build.rs` no longer hardcodes version — reads from `CARGO_PKG_VERSION`.
- Added `LTS_UNTIL=2028-04-27` compile-time env var to both build scripts.
- Added `[package.metadata.lts]` section to all `Cargo.toml` files.
- Added `rust-version = "1.82"`, `license = "MIT"`, `repository` fields.

---

## [3.1.0] — 2026-04-14

### Added
- Native loop device management via raw `ioctl` calls (`LOOP_CTL_GET_FREE`, `LOOP_SET_FD`, `LOOP_SET_STATUS64`), replacing external `losetup` binary dependency.
- Docker-style `HEALTHCHECK` support for services (unique among all init systems).
- Socket activation protocol (`LISTEN_FDS` / `LISTEN_FDNAMES`).
- cgroup v2 resource accounting with `memory.max`, `cpu.weight`, `io.weight`.
- Atomic cgroup process cleanup via `cgroup.kill`.
- Prometheus-compatible metrics exporter at `/run/quantra/metrics`.
- AppArmor `changeprofile` confinement for services.
- `seccomp` BPF denylist filtering per service.
- Timer units with `CalendarSpec` scheduling (cron replacement).
- Conditional dependencies (`hardware-present:`, `file-exists:`, `env-set:`).
- D-Bus `org.freedesktop.systemd1` compatibility stubs.
- `quantra-ctl` commands: `signal`, `is-started`, `is-failed`, `setenv`, `add-dep`, `rm-dep`, `assay`, `isolate`.

### Removed
- SHA-256 boot-chain verification (legacy security-theater component).
- External `losetup` binary dependency.

---

## [2.1.0] — 2026-04-01

### Added
- Initial production release of Quantra PID 1 service manager.
- 12-phase boot sequence with parallel BFS dependency wave sorting.
- JSON control protocol over Unix stream socket.
- Per-service logging with 10MB rotation.
- `sd_notify` readiness protocol.
- Emergency shell with built-in commands.

# Changelog — zai-net

All notable changes to the Zainium OS networking stack.

## [4.0.4] — 2026-04-27

### ⚠ BREAKING
- Removed `tokio` from CLI crate (`zai-net`). Now uses blocking `std::os::unix::net`.
- `common` crate: async helpers gated behind `async-io` feature flag.

### 🔒 Security
- Added 4MB frame size limit to `recv_message` and `recv_message_sync` (OOM prevention).
- Config files (`/overlayer/syshub/etc/quantra-system/network.yaml`) now written with 0o600 permissions.
- VPN profiles written with 0o600; VPN directory set to 0o700.
- Namespace names validated against path traversal attacks.

### 🐛 Bug Fixes
- **`get_wireless_info()`**: Replaced hardcoded mock data with real `iw dev <iface> link` parsing.
- **CLI ANSI codes**: All escape constants were empty strings `""` — now emit real terminal colors.
- **CLI render functions**: Removed hardcoded DNS (8.8.8.8), gateway (192.168.1.1), latency (42ms), and speed values.
- **Daemon uptime**: Was reporting system epoch time; now tracks actual daemon start via `Instant`.
- **WiFi auto-connect**: Best-network selector always picked last match; now correctly compares signal+autoconnect scores.
- **`bandwidth_test()`**: No longer abuses `latency_ms` field for TX throughput; uses `recommendation` string.

### ✨ Features
- **Network namespaces**: Implemented `NetnsCreate`, `NetnsList`, `NetnsExec`, `NetnsDelete`, `LinkSetNetns`, `VethCreate`.
- **God file decomposition**: Split 2,477-line `main.rs` into 8 focused modules:
  `netlink.rs`, `dhcp.rs`, `routing.rs`, `config.rs`, `vpn.rs`, `firewall.rs`, `quality.rs`, `netns.rs`.

### 📦 Build
- Workspace version bumped to 4.0.4 (aligned with Quantra LTS).
- MSRV: 1.82, Edition 2021.
- Release profile: `panic=abort`, `opt-level=z`, `lto=fat`, `strip=true`.

### 📝 Documentation
- Added `ARCHITECTURE.md` with crate layout, wire protocol, and security model.

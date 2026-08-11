# quantra-net — Universal Network Management Stack

> A fast, memory-safe, privileged network daemon and CLI client for Linux.

**Author:** Ali Zain <alizain.x404@gmail.com>  
**Version:** 6.0.0  
**Language:** Rust (100% memory-safe)  
**License:** MIT  

---

## What Is quantra-net?

The `quantra-net` workspace provides a highly secure, zero-bloat networking stack designed to replace legacy network managers. It separates the execution of privileged network operations (daemon) from user-facing interactions (CLI), communicating exclusively over a hardened Unix domain socket using a length-prefixed JSON protocol.

### Workspace Layout

- `common/`: Shared command/response types, data models, and IPC framing helpers.
- `quantra-net/`: The user-facing CLI binary.
- `quantra-netd/`: The privileged daemon that executes networking operations.

---

## Architecture & Request Flow

1. User invokes `quantra-net` commands.
2. CLI validates arguments and serializes the `NetCommand`.
3. CLI connects to `/run/quantra-system/quantra-netd.sock`.
4. Daemon validates peer identity strictly via Unix credentials (`peer_cred`).
5. Daemon executes the command via `rtnetlink` or secure external helpers.
6. Daemon returns the `NetResponse`.

### Flow Diagram

```mermaid
flowchart LR
    U[User CLI invocation] --> C[quantra-net CLI]
    C --> S[/run/quantra-system/quantra-netd.sock]
    S --> D[quantra-netd]
    D --> A{Auth check\npeer_cred}
    A -->|allow| E[Execute network action]
    A -->|deny| R[NetResponse::Error]
    E --> T[rtnetlink or system tools]
    T --> P[Collect result]
    P --> O[NetResponse JSON]
    O --> C
```

---

## CLI Command Surface (`quantra-net`)

The client provides a comprehensive surface for system network administration:

- **State & Monitoring:** `status`, `scan`, `monitor`, `watch`
- **Link Management:** `link up`, `down`, `restart`, `add`, `remove`, `dhcp`, `renew`, `release`
- **Routing:** `route add`, `del`, `show`
- **Wireless (WiFi):** `wifi scan`, `connect`, `disconnect`, `saved`, `forget`, `autoconnect`, `diagnose`
- **Quality of Service:** `quality monitor`, `speed`, `bandwidth`
- **VPN:** `vpn create`, `up`, `down`, `status`, `show`, `killswitch`
- **Firewall:** `firewall status`, `preset`, `allow`, `block`, `zone`, `nat`
- **Configuration:** `config save`, `load`, `show`, `setup`, `diagnose`

**Examples:**
```bash
quantra-net link dhcp eth0
quantra-net route add default -v 192.168.1.1 --interface eth0
quantra-net wifi connect wlp2s0 MySSID --security wpa2-psk --password 'secret'
quantra-net firewall preset home
quantra-net quality monitor eth0 --duration 10
```

---

## Security and Hardening

The `quantra-netd` daemon is engineered with a strict, defense-in-depth security model:

- **Process Hardening:** - Sets `PR_SET_NO_NEW_PRIVS` to prevent privilege escalation.
  - Sets `PR_SET_DUMPABLE` to `0` to prevent memory dumping.
- **Socket Permissions:**
  - Parent directory strictly set to `0700`.
  - Socket file permission strictly set to `0600`.
- **Token-less Authorization:**
  - Validates clients using Kernel-level Unix peer credentials (`peer_cred`).
  - Restricts execution to root (UID 0), the daemon's effective UID, or explicitly allowed UIDs via the `QUANTRA_NETD_ALLOWED_UIDS` environment variable.
- **Seccomp Contract:**
  - The daemon strictly aligns with the `network-daemon` seccomp-bpf profile.
  - Guarded by continuous CI contract tests to prevent profile drift.

---

## External Runtime Dependencies

Link/route/DHCP/WireGuard management is all native — `netlink.rs`,
`routing.rs`, `dhcp.rs`, and `wireguard.rs` talk `rtnetlink`/generic
netlink directly, no external binary involved. What's still shelled out to
(via `exec.rs`, with `zex infuse <pkg>` install hints on failure):

- `ip` (iproute2) — a handful of remaining call sites (`netlink.rs`, `routing.rs`, `netns.rs`)
- `iw`, `wpa_supplicant`, `wpa_cli` — WiFi scan/connect (`wifi.rs`)
- `ping` (iputils) — quality/diagnostics (`quality.rs`)
- `nft` (nftables) — firewall rules (`firewall.rs`)
- `openvpn` — non-WireGuard VPN (`vpn.rs`)
- `unshare`, `nsenter`, `umount` — network namespaces (`netns.rs`)

---

## Daemon State and Configuration Paths

- Network definitions: `/overlayer/syshub/etc/quantra-system/network.yaml`
- VPN profiles: `/overlayer/syshub/etc/quantra-system/vpn/`
- Firewall rules: `/overlayer/syshub/etc/quantra-system/firewall.yaml`
- IPC Socket: `/run/quantra-system/quantra-netd.sock`
- NFT runtime cache: `/run/quantra-system/nft-quantra.rules`

---

## Build & Test Instructions

**Compilation:**
```bash
cargo build --release --workspace
```

**Testing:**
```bash
cargo fmt --all
cargo test --all

# Run the strict security contract test directly
cargo test -p quantra-netd tests::expected_init_seccomp_profile_is_network_daemon
```

---

## Troubleshooting & Failure Handling

- Unauthorized requests receive an immediate `NetResponse::Error` at the socket level.
- Stale socket files are automatically detected and purged on daemon startup.
- Connection and IPC execution paths utilize explicit timeouts to guarantee bounded failure behavior.
- If firewall or WiFi operations fail, verify kernel module support (`nftables`, `cfg80211`) and the presence of required runtime dependencies.


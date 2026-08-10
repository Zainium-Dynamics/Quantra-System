# zai-net — Universal Network Management Stack

> A fast, memory-safe, privileged network daemon and CLI client for Linux.

**Author:** Ali Zain <alizain.arch@gmail.com>  
**Version:** 5.0.1  
**Language:** Rust (100% memory-safe)  
**License:** GPLv3  

---

## What Is zai-net?

The `zai-net` workspace provides a highly secure, zero-bloat networking stack designed to replace legacy network managers. It separates the execution of privileged network operations (daemon) from user-facing interactions (CLI), communicating exclusively over a hardened Unix domain socket using a length-prefixed JSON protocol.

### Workspace Layout

- `common/`: Shared command/response types, data models, and IPC framing helpers.
- `zai-net/`: The user-facing CLI binary.
- `zai-netd/`: The privileged daemon that executes networking operations.

---

## Architecture & Request Flow

1. User invokes `zai-net` commands.
2. CLI validates arguments and serializes the `NetCommand`.
3. CLI connects to `/run/zainium/zai-netd.sock`.
4. Daemon validates peer identity strictly via Unix credentials (`peer_cred`).
5. Daemon executes the command via `rtnetlink` or secure external helpers.
6. Daemon returns the `NetResponse`.

### Flow Diagram

```mermaid
flowchart LR
    U[User CLI invocation] --> C[zai-net CLI]
    C --> S[/run/zainium/zai-netd.sock]
    S --> D[zai-netd]
    D --> A{Auth check\npeer_cred}
    A -->|allow| E[Execute network action]
    A -->|deny| R[NetResponse::Error]
    E --> T[rtnetlink or system tools]
    T --> P[Collect result]
    P --> O[NetResponse JSON]
    O --> C
```

---

## CLI Command Surface (`zai-net`)

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
zai-net link dhcp eth0
zai-net route add default -v 192.168.1.1 --interface eth0
zai-net wifi connect wlp2s0 MySSID --security wpa2-psk --password 'secret'
zai-net firewall preset home
zai-net quality monitor eth0 --duration 10
```

---

## Security and Hardening

The `zai-netd` daemon is engineered with a strict, defense-in-depth security model:

- **Process Hardening:** - Sets `PR_SET_NO_NEW_PRIVS` to prevent privilege escalation.
  - Sets `PR_SET_DUMPABLE` to `0` to prevent memory dumping.
- **Socket Permissions:**
  - Parent directory strictly set to `0700`.
  - Socket file permission strictly set to `0600`.
- **Token-less Authorization:**
  - Validates clients using Kernel-level Unix peer credentials (`peer_cred`).
  - Restricts execution to root (UID 0), the daemon's effective UID, or explicitly allowed UIDs via the `ZAI_NETD_ALLOWED_UIDS` environment variable.
- **Seccomp Contract:**
  - The daemon strictly aligns with the `network-daemon` seccomp-bpf profile.
  - Guarded by continuous CI contract tests to prevent profile drift.

---

## External Runtime Dependencies

While the daemon handles internal routing natively via `rtnetlink`, it securely orchestrates the following system tools for specific protocols:

- `ip` (iproute2)
- `dhcpcd`
- `ping` (iputils)
- `iw`, `wpa_supplicant`, `wpa_cli` (Wireless)
- `nft` (nftables for firewall management)
- `wg-quick`, `wg` (Wireguard VPN)
- `openvpn`
- `kill`

---

## Daemon State and Configuration Paths

- Network definitions: `/overlayer/syshub/etc/quantra-system/network.yaml`
- VPN profiles: `/overlayer/syshub/etc/quantra-system/vpn/`
- Firewall rules: `/overlayer/syshub/etc/quantra-system/firewall.yaml`
- IPC Socket: `/run/zainium/zai-netd.sock`
- NFT runtime cache: `/run/zainium/nft-zainium.rules`

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
cargo test -p zai-netd tests::expected_init_seccomp_profile_is_network_daemon
```

---

## Troubleshooting & Failure Handling

- Unauthorized requests receive an immediate `NetResponse::Error` at the socket level.
- Stale socket files are automatically detected and purged on daemon startup.
- Connection and IPC execution paths utilize explicit timeouts to guarantee bounded failure behavior.
- If firewall or WiFi operations fail, verify kernel module support (`nftables`, `cfg80211`) and the presence of required runtime dependencies.


//! WireGuard — native kernel integration via Generic Netlink.
//!
//! Replaces the previous `wg-quick` wrapper with direct kernel communication.
//! No `wg`, `wg-quick`, or any external binary required.
//!
//! # Implementation
//!
//! WireGuard uses the Linux Generic Netlink family `wireguard` (GENL).
//! We communicate via a raw NETLINK_GENERIC socket using the standard
//! netlink message format:
//!
//! ```text
//! nlmsghdr → genlmsghdr → WireGuard attributes (NLAS)
//! ```
//!
//! # Operations
//!
//! | Command | GENL cmd | Description |
//! |---------|----------|-------------|
//! | Get device | WG_CMD_GET_DEVICE | Read current config + stats |
//! | Set device | WG_CMD_SET_DEVICE | Set private key, peers, listen port |
//!
//! # Interface creation
//!
//! WireGuard interfaces are created via rtnetlink:
//! `ip link add <name> type wireguard`
//! (using the Exec trait, same as bridge.rs)
//!
//! # Key handling
//!
//! Keys are 32-byte Curve25519 values encoded as base64.
//! We decode/encode them here — no external crypto library needed
//! since the kernel does all actual cryptography.

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::exec::Exec;

// ── WireGuard GENL constants ──────────────────────────────────────────────────

const WG_GENL_NAME: &[u8] = b"wireguard\0";

// WireGuard commands
#[allow(dead_code)]
const WG_CMD_GET_DEVICE: u8 = 0;
const WG_CMD_SET_DEVICE: u8 = 1;

// WireGuard device attributes (WGDEVICE_A_*)
#[allow(dead_code)]
const WGDEVICE_A_IFINDEX: u16 = 1;
const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
#[allow(dead_code)]
const WGDEVICE_A_PUBLIC_KEY: u16 = 4;
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
const WGDEVICE_A_PEERS: u16 = 8;
const WGDEVICE_A_FLAGS: u16 = 5;

// WireGuard peer attributes (WGPEER_A_*)
const WGPEER_A_PUBLIC_KEY: u16 = 1;
#[allow(dead_code)]
const WGPEER_A_PRESHARED_KEY: u16 = 2;
const WGPEER_A_ENDPOINT: u16 = 3;
const WGPEER_A_PERSISTENT_KEEPALIVE: u16 = 4;
#[allow(dead_code)]
const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 5;
#[allow(dead_code)]
const WGPEER_A_RX_BYTES: u16 = 6;
#[allow(dead_code)]
const WGPEER_A_TX_BYTES: u16 = 7;
const WGPEER_A_ALLOWEDIPS: u16 = 8;
#[allow(dead_code)]
const WGPEER_A_FLAGS: u16 = 9;

// WGDEVICE_F_REPLACE_PEERS flag
const WGDEVICE_F_REPLACE_PEERS: u32 = 1;

// Netlink constants
const NETLINK_GENERIC: libc::c_int = 16;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
#[allow(dead_code)]
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
#[allow(dead_code)]
const NLMSG_DONE: u16 = 3;
const GENL_ID_CTRL: u16 = 0x10;

// CTRL commands
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_ATTR_FAMILY_ID: u16 = 1;

// ── RAII socket ───────────────────────────────────────────────────────────────

struct NlSocket(libc::c_int);

impl NlSocket {
    fn open() -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_GENERIC,
            )
        };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "socket(AF_NETLINK): {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
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
                "bind netlink: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self(fd))
    }

    fn send(&self, msg: &[u8]) -> Result<()> {
        let n = unsafe { libc::send(self.0, msg.as_ptr() as *const _, msg.len(), 0) };
        if n < 0 {
            return Err(anyhow::anyhow!(
                "netlink send: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn recv(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 32768];
        let n = unsafe { libc::recv(self.0, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        if n < 0 {
            return Err(anyhow::anyhow!(
                "netlink recv: {}",
                std::io::Error::last_os_error()
            ));
        }
        buf.truncate(n as usize);
        Ok(buf)
    }
}

impl Drop for NlSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

// ── Netlink message builder ───────────────────────────────────────────────────

struct NlMsg(Vec<u8>);

impl NlMsg {
    fn new(msg_type: u16, flags: u16, seq: u32) -> Self {
        let mut v = vec![0u8; 16]; // nlmsghdr
        // len at 0 (filled at end), type at 4, flags at 6, seq at 8, pid=0 at 12
        v[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        v[6..8].copy_from_slice(&flags.to_ne_bytes());
        v[8..12].copy_from_slice(&seq.to_ne_bytes());
        Self(v)
    }

    fn push_genl(&mut self, cmd: u8) {
        self.0.push(cmd);
        self.0.push(1); // version
        self.0.extend_from_slice(&[0u8; 2]); // reserved
    }

    fn push_nla(&mut self, nla_type: u16, data: &[u8]) {
        let len = (4 + data.len()) as u16;
        self.0.extend_from_slice(&len.to_ne_bytes());
        self.0.extend_from_slice(&nla_type.to_ne_bytes());
        self.0.extend_from_slice(data);
        // Pad to 4-byte alignment
        let pad = (4 - (data.len() % 4)) % 4;
        for _ in 0..pad {
            self.0.push(0);
        }
    }

    fn push_nla_str(&mut self, nla_type: u16, s: &[u8]) {
        // Null-terminated string NLA
        let mut data = s.to_vec();
        data.push(0);
        self.push_nla(nla_type, &data);
    }

    fn push_nla_u16(&mut self, nla_type: u16, v: u16) {
        self.push_nla(nla_type, &v.to_ne_bytes());
    }

    fn push_nla_u32(&mut self, nla_type: u16, v: u32) {
        self.push_nla(nla_type, &v.to_ne_bytes());
    }

    fn finish(&mut self) {
        let len = self.0.len() as u32;
        self.0[0..4].copy_from_slice(&len.to_ne_bytes());
    }

    fn bytes(&self) -> &[u8] {
        &self.0
    }
}

// ── Resolve WireGuard GENL family ID ─────────────────────────────────────────

fn resolve_wireguard_family(sock: &NlSocket) -> Result<u16> {
    let mut msg = NlMsg::new(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK, 1);
    msg.push_genl(CTRL_CMD_GETFAMILY);
    msg.push_nla_str(CTRL_ATTR_FAMILY_NAME, WG_GENL_NAME);
    msg.finish();

    sock.send(msg.bytes())?;
    let resp = sock.recv()?;

    // Parse response to find CTRL_ATTR_FAMILY_ID
    let mut i = 16 + 4; // nlmsghdr(16) + genlmsghdr(4)
    while i + 4 <= resp.len() {
        let nla_len = u16::from_ne_bytes([resp[i], resp[i + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([resp[i + 2], resp[i + 3]]);
        if nla_len < 4 || i + nla_len > resp.len() {
            break;
        }
        let data = &resp[i + 4..i + nla_len];
        if nla_type == CTRL_ATTR_FAMILY_ID && data.len() >= 2 {
            return Ok(u16::from_ne_bytes([data[0], data[1]]));
        }
        i += (nla_len + 3) & !3; // align to 4
    }

    Err(anyhow::anyhow!(
        "WireGuard GENL family not found — is the wireguard kernel module loaded?"
    ))
}

// ── Base64 decode for WireGuard keys ─────────────────────────────────────────

/// Decode a base64-encoded WireGuard key (44 chars → 32 bytes).
pub fn decode_key(b64: &str) -> Result<[u8; 32]> {
    let b64 = b64.trim();
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    fn val(c: u8) -> Result<u8> {
        ALPHABET
            .iter()
            .position(|&b| b == c)
            .map(|p| p as u8)
            .ok_or_else(|| anyhow::anyhow!("invalid base64 char: {}", c as char))
    }
    let b64 = b64.trim_end_matches('=');
    if b64.len() != 43 {
        // 32 bytes = 43 base64 chars + 1 padding
        anyhow::bail!("WireGuard key must be 44 base64 chars (got {})", b64.len());
    }
    let bytes: Vec<u8> = b64
        .as_bytes()
        .chunks(4)
        .flat_map(|chunk| {
            let v: Vec<u8> = chunk.iter().filter_map(|&b| val(b).ok()).collect();
            match v.len() {
                4 => vec![
                    (v[0] << 2) | (v[1] >> 4),
                    (v[1] << 4) | (v[2] >> 2),
                    (v[2] << 6) | v[3],
                ],
                3 => vec![(v[0] << 2) | (v[1] >> 4), (v[1] << 4) | (v[2] >> 2)],
                2 => vec![(v[0] << 2) | (v[1] >> 4)],
                _ => vec![],
            }
        })
        .collect();

    if bytes.len() < 32 {
        anyhow::bail!("WireGuard key decoded to {} bytes (need 32)", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    Ok(out)
}

/// Encode 32 bytes to base64 WireGuard key format.
#[allow(dead_code)]
pub fn encode_key(key: &[u8; 32]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(44);
    for chunk in key.chunks(3) {
        let (a, b, c) = (
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        );
        out.push(ALPHABET[((a >> 2) & 0x3F) as usize] as char);
        out.push(ALPHABET[(((a << 4) | (b >> 4)) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(((b << 2) | (c >> 6)) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(c & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

// ── Peer endpoint parsing ─────────────────────────────────────────────────────

fn parse_endpoint_sockaddr(endpoint: &str) -> Result<Vec<u8>> {
    // Format: "1.2.3.4:51820" or "[::1]:51820"
    use std::net::SocketAddr;
    let addr: SocketAddr = endpoint
        .parse()
        .with_context(|| format!("parse WireGuard endpoint '{}'", endpoint))?;

    match addr {
        SocketAddr::V4(a) => {
            // struct sockaddr_in (16 bytes)
            let mut buf = vec![0u8; 16];
            buf[0] = libc::AF_INET as u8;
            buf[1] = 0;
            buf[2..4].copy_from_slice(&a.port().to_be_bytes());
            buf[4..8].copy_from_slice(&a.ip().octets());
            Ok(buf)
        }
        SocketAddr::V6(a) => {
            // struct sockaddr_in6 (28 bytes)
            let mut buf = vec![0u8; 28];
            buf[0] = libc::AF_INET6 as u8;
            buf[1] = 0;
            buf[2..4].copy_from_slice(&a.port().to_be_bytes());
            buf[8..24].copy_from_slice(&a.ip().octets());
            Ok(buf)
        }
    }
}

fn parse_allowed_ip_nla(cidr: &str) -> Result<Vec<u8>> {
    // WGALLOWEDIP NLA: family(2) + cidr_mask(1) + pad(1) + ip(4 or 16)
    use std::net::IpAddr;
    let (ip_str, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("allowed_ip '{}' must be CIDR", cidr))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("parse prefix in '{}'", cidr))?;
    let ip: IpAddr = ip_str
        .parse()
        .with_context(|| format!("parse IP in '{}'", cidr))?;

    let mut nla = Vec::new();
    match ip {
        IpAddr::V4(a) => {
            nla.extend_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            nla.push(prefix);
            nla.push(0); // pad
            nla.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            nla.extend_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            nla.push(prefix);
            nla.push(0);
            nla.extend_from_slice(&a.octets());
        }
    }
    Ok(nla)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Create a WireGuard interface via rtnetlink (uses `ip` command).
pub async fn wg_create_interface(exec: &dyn Exec, name: &str) -> Result<()> {
    let out = exec
        .output("ip", &["link", "add", name, "type", "wireguard"])
        .await?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // Check if already exists
        if stderr.contains("File exists") {
            debug!("WireGuard interface '{}' already exists", name);
            return Ok(());
        }
        anyhow::bail!("ip link add {} type wireguard: {}", name, stderr.trim());
    }
    info!("WireGuard interface '{}' created", name);
    Ok(())
}

/// Delete a WireGuard interface.
pub async fn wg_delete_interface(exec: &dyn Exec, name: &str) -> Result<()> {
    exec.output("ip", &["link", "del", name]).await?;
    info!("WireGuard interface '{}' deleted", name);
    Ok(())
}

/// Configure a WireGuard interface (private key, listen port, peers) via GENL.
///
/// This replaces `wg set <name> ...` — zero external binaries.
pub fn wg_set_device(
    name: &str,
    private_key_b64: &str,
    listen_port: u16,
    peers: &[WgPeerConfig],
    replace_peers: bool,
) -> Result<()> {
    let sock = NlSocket::open().context("open GENL socket")?;
    let family_id = resolve_wireguard_family(&sock).context("resolve WireGuard GENL family")?;

    debug!("WireGuard GENL family id={}", family_id);

    let private_key = decode_key(private_key_b64).context("decode WireGuard private key")?;

    let mut msg = NlMsg::new(family_id, NLM_F_REQUEST | NLM_F_ACK, 2);
    msg.push_genl(WG_CMD_SET_DEVICE);

    // Interface name (null-terminated)
    let name_bytes = name.as_bytes();
    msg.push_nla_str(WGDEVICE_A_IFNAME, name_bytes);

    // Private key (32 bytes raw)
    msg.push_nla(WGDEVICE_A_PRIVATE_KEY, &private_key);

    // Listen port
    if listen_port > 0 {
        msg.push_nla_u16(WGDEVICE_A_LISTEN_PORT, listen_port);
    }

    // Flags
    if replace_peers {
        msg.push_nla_u32(WGDEVICE_A_FLAGS, WGDEVICE_F_REPLACE_PEERS);
    }

    // Peers nested NLA
    if !peers.is_empty() {
        // Build peers NLA payload
        let mut peers_payload = Vec::new();
        for (idx, peer) in peers.iter().enumerate() {
            let peer_nla = build_peer_nla(peer)?;
            // Each peer wrapped in index NLA (idx+1)
            let peer_len = (4 + peer_nla.len()) as u16;
            let mut peer_wrapper = Vec::new();
            peer_wrapper.extend_from_slice(&peer_len.to_ne_bytes());
            peer_wrapper.extend_from_slice(&((idx as u16 + 1) | 0x8000).to_ne_bytes()); // NLA_F_NESTED
            peer_wrapper.extend_from_slice(&peer_nla);
            peers_payload.extend_from_slice(&peer_wrapper);
        }
        msg.push_nla(WGDEVICE_A_PEERS | 0x8000, &peers_payload); // NLA_F_NESTED
    }

    msg.finish();
    sock.send(msg.bytes())?;

    // Read ACK
    let resp = sock.recv()?;
    if resp.len() >= 16 {
        let msg_type = u16::from_ne_bytes([resp[4], resp[5]]);
        if msg_type == NLMSG_ERROR {
            let err_code = i32::from_ne_bytes([resp[16], resp[17], resp[18], resp[19]]);
            if err_code != 0 {
                return Err(anyhow::anyhow!(
                    "WireGuard SET_DEVICE failed: errno={} ({})",
                    -err_code,
                    std::io::Error::from_raw_os_error(-err_code)
                ));
            }
        }
    }

    info!(
        "WireGuard '{}' configured: port={} peers={}",
        name,
        listen_port,
        peers.len()
    );
    Ok(())
}

fn build_peer_nla(peer: &WgPeerConfig) -> Result<Vec<u8>> {
    let mut p: Vec<u8> = Vec::new();

    // Public key (32 bytes)
    let pubkey = decode_key(&peer.public_key)?;
    let pk_len = (4 + 32u16).to_ne_bytes();
    p.extend_from_slice(&pk_len);
    p.extend_from_slice(&WGPEER_A_PUBLIC_KEY.to_ne_bytes());
    p.extend_from_slice(&pubkey);

    // Endpoint (optional)
    if let Some(ref ep) = peer.endpoint {
        let ep_bytes = parse_endpoint_sockaddr(ep)?;
        let ep_len = (4 + ep_bytes.len() as u16).to_ne_bytes();
        p.extend_from_slice(&ep_len);
        p.extend_from_slice(&WGPEER_A_ENDPOINT.to_ne_bytes());
        p.extend_from_slice(&ep_bytes);
        let pad = (4 - (ep_bytes.len() % 4)) % 4;
        for _ in 0..pad {
            p.push(0);
        }
    }

    // Persistent keepalive (optional)
    if let Some(ka) = peer.persistent_keepalive {
        p.extend_from_slice(&(4u16 + 2).to_ne_bytes());
        p.extend_from_slice(&WGPEER_A_PERSISTENT_KEEPALIVE.to_ne_bytes());
        p.extend_from_slice(&ka.to_ne_bytes());
        p.extend_from_slice(&[0u8; 2]); // pad
    }

    // AllowedIPs nested
    for cidr in peer.allowed_ips.iter() {
        let aip = parse_allowed_ip_nla(cidr)?;
        let entry_len = (4 + aip.len() as u16).to_ne_bytes();
        p.extend_from_slice(&entry_len);
        p.extend_from_slice(&(WGPEER_A_ALLOWEDIPS | 0x8000).to_ne_bytes());
        p.extend_from_slice(&aip);
        let pad = (4 - (aip.len() % 4)) % 4;
        for _ in 0..pad {
            p.push(0);
        }
    }

    Ok(p)
}

// ── WireGuard config from common types ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WgPeerConfig {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

/// Apply a full WireGuard configuration from the common::WireGuardConfig type.
///
/// Creates the interface, sets keys/peers, brings it up, and adds the
/// IP address if specified.
pub async fn apply_wg_config(
    exec: &dyn Exec,
    handle: &rtnetlink::Handle,
    name: &str,
    cfg: &common::WireGuardConfig,
) -> Result<()> {
    // 1. Create interface
    wg_create_interface(exec, name).await?;

    // 2. Configure via GENL (sync — kernel GENL is blocking)
    let peers: Vec<WgPeerConfig> = cfg
        .peers
        .iter()
        .map(|p| WgPeerConfig {
            public_key: p.public_key.clone(),
            allowed_ips: p.allowed_ips.clone(),
            endpoint: p.endpoint.clone(),
            persistent_keepalive: p.persistent_keepalive,
        })
        .collect();

    // Run blocking GENL call in blocking thread pool
    let name_owned = name.to_string();
    let privkey = cfg.private_key.clone();
    let port = cfg.listen_port;
    tokio::task::spawn_blocking(move || wg_set_device(&name_owned, &privkey, port, &peers, true))
        .await
        .context("spawn_blocking wg_set_device")?
        .context("wg_set_device")?;

    // 3. Assign IP address
    if let Some(ref addr) = cfg.address {
        crate::netlink::add_ip_address(handle, name, addr)
            .await
            .with_context(|| format!("add WireGuard address {} to {}", addr, name))?;
    }

    // 4. Bring interface up
    let out = exec.output("ip", &["link", "set", name, "up"]).await?;
    if !out.status.success() {
        warn!(
            "ip link set {} up: {}",
            name,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    // 5. Add routes for each peer's AllowedIPs
    for peer in &cfg.peers {
        for cidr in &peer.allowed_ips {
            if cidr == "0.0.0.0/0" || cidr == "::/0" {
                crate::routing::add_route(handle, cidr, "0.0.0.0", Some(name))
                    .await
                    .ok(); // non-fatal
            }
        }
    }

    info!(
        "WireGuard '{}' up (port={} peers={})",
        name,
        cfg.listen_port,
        cfg.peers.len()
    );
    Ok(())
}

/// Tear down a WireGuard interface completely.
pub async fn teardown_wg(exec: &dyn Exec, name: &str) -> Result<()> {
    exec.output("ip", &["link", "set", name, "down"]).await.ok();
    wg_delete_interface(exec, name).await
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_key_valid() {
        // A known valid base64 WireGuard key (all zeros → AAAA...AA=)
        let zeroes = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let key = decode_key(zeroes).expect("decode zero key");
        assert_eq!(key, [0u8; 32]);
    }

    #[test]
    fn decode_key_roundtrip() {
        let key_b64 = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        let decoded = decode_key(key_b64).expect("decode key");
        let reencoded = encode_key(&decoded);
        assert_eq!(reencoded, key_b64, "base64 roundtrip must be exact");
    }

    #[test]
    fn decode_key_rejects_wrong_length() {
        assert!(decode_key("tooshort").is_err());
        assert!(decode_key("").is_err());
    }

    #[test]
    fn encode_key_all_zeros() {
        let key = [0u8; 32];
        let b64 = encode_key(&key);
        // All-zero bytes encode to AAAA repeated
        assert!(b64.starts_with("AAAA"), "zeros must encode as AAAA...");
        assert_eq!(b64.len(), 44);
    }

    #[test]
    fn parse_endpoint_v4() {
        let r = parse_endpoint_sockaddr("192.168.1.1:51820").expect("parse v4 endpoint");
        assert_eq!(r.len(), 16);
        // family
        assert_eq!(r[0] as i32, libc::AF_INET);
        // port in big-endian at bytes 2-3
        let port = u16::from_be_bytes([r[2], r[3]]);
        assert_eq!(port, 51820);
        // IP at bytes 4-7
        assert_eq!(&r[4..8], &[192, 168, 1, 1]);
    }

    #[test]
    fn parse_endpoint_v6() {
        let r = parse_endpoint_sockaddr("[::1]:51820").expect("parse v6 endpoint");
        assert_eq!(r.len(), 28);
        assert_eq!(r[0] as i32, libc::AF_INET6);
    }

    #[test]
    fn parse_allowed_ip_v4() {
        let nla = parse_allowed_ip_nla("10.0.0.0/8").expect("parse v4 CIDR");
        // family(2) + prefix(1) + pad(1) + ip(4) = 8 bytes
        assert_eq!(nla.len(), 8);
        let family = u16::from_ne_bytes([nla[0], nla[1]]);
        assert_eq!(family, libc::AF_INET as u16);
        assert_eq!(nla[2], 8); // /8
        assert_eq!(&nla[4..8], &[10, 0, 0, 0]);
    }

    #[test]
    fn parse_allowed_ip_rejects_no_prefix() {
        assert!(parse_allowed_ip_nla("10.0.0.0").is_err());
    }

    #[test]
    fn build_peer_nla_minimal() {
        let peer = WgPeerConfig {
            public_key: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=".to_string(),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            endpoint: None,
            persistent_keepalive: None,
        };
        let nla = build_peer_nla(&peer).expect("build peer NLA");
        // Should contain at least the public key NLA (4+32=36 bytes)
        assert!(nla.len() >= 36);
    }
}

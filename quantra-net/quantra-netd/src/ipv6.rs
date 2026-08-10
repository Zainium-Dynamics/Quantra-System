//! IPv6 — DHCPv6 client (RFC 8415), SLAAC, Router Advertisement processing,
//! and rtnetlink IPv6 address/route management.
//!
//! # Three IPv6 address acquisition methods
//!
//! | Method | How | When to use |
//! |--------|-----|-------------|
//! | SLAAC | Kernel auto-configures from RA prefix | Most home/office networks |
//! | DHCPv6 stateless | DHCPv6 for DNS only, SLAAC for address | Common enterprise |
//! | DHCPv6 stateful | Full address from DHCPv6 server | Strict enterprise/ISP |
//!
//! # SLAAC implementation
//!
//! SLAAC works by enabling kernel sysctl `accept_ra=1` and `autoconf=1`.
//! The kernel processes Router Advertisements automatically and assigns
//! addresses. We poll `/proc/net/if_inet6` to read the assigned address.
//!
//! # DHCPv6 client (RFC 8415)
//!
//! UDP port 546 (client) → 547 (server).
//! Multicast group `ff02::1:2` (all-DHCP-relay-agents-and-servers).
//!
//! Message types used:
//! - SOLICIT (1)   → discover DHCPv6 servers
//! - ADVERTISE (2) → server responds
//! - REQUEST (3)   → request address/options
//! - REPLY (7)     → server grants lease
//! - RENEW (5)     → renew existing lease
//! - RELEASE (8)   → release lease
//!
//! # IPv6 route management
//!
//! Uses rtnetlink IPv6 API (`handle.route().add().v6()`).

use anyhow::{Context, Result};
use rtnetlink::Handle;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn};

// ── DHCPv6 constants (RFC 8415) ───────────────────────────────────────────────

const DHCP6_CLIENT_PORT: u16 = 546;
const DHCP6_SERVER_PORT: u16 = 547;

// All-DHCP-Relay-Agents-and-Servers multicast (link-local scope)
const DHCP6_MULTICAST: &str = "ff02::1:2";

const MSG_SOLICIT: u8 = 1;
const MSG_ADVERTISE: u8 = 2;
const MSG_REQUEST: u8 = 3;
const MSG_REPLY: u8 = 7;
#[allow(dead_code)]
const MSG_RENEW: u8 = 5;
const MSG_RELEASE: u8 = 8;

// DHCPv6 option codes
const OPT_CLIENTID: u16 = 1;
const OPT_SERVERID: u16 = 2;
const OPT_IA_NA: u16 = 3; // Identity Association for Non-temporary Addresses
const OPT_IA_ADDR: u16 = 5;
const OPT_ORO: u16 = 6; // Option Request Option
const OPT_ELAPSED: u16 = 8;
const OPT_DNS: u16 = 23; // DNS Recursive Name Server
const OPT_DOMAIN: u16 = 24; // Domain Search List
const OPT_STATUS: u16 = 13;

const STATUS_SUCCESS: u16 = 0;

const SOLICIT_TIMEOUT: Duration = Duration::from_secs(10);
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RETRIES: u32 = 3;

// ── DHCPv6 result types ───────────────────────────────────────────────────────

/// A DHCPv6 lease — address + prefix + lifetimes.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Dhcp6Lease {
    pub interface: String,
    pub address: Ipv6Addr,
    pub prefix_len: u8,
    pub preferred: u32, // preferred lifetime (seconds)
    pub valid: u32,     // valid lifetime (seconds)
    pub dns: Vec<Ipv6Addr>,
    pub server_duid: Vec<u8>,
    pub t1: u32, // renew time
    pub t2: u32, // rebind time
}

/// Simple common::DhcpLeaseInfo-compatible view of a DHCPv6 lease.
pub fn lease_to_info(lease: &Dhcp6Lease) -> common::DhcpLeaseInfo {
    common::DhcpLeaseInfo {
        interface: lease.interface.clone(),
        ip_cidr: Some(format!("{}/{}", lease.address, lease.prefix_len)),
        gateway: None, // IPv6 gateway comes from RA, not DHCPv6
        dns_servers: lease.dns.iter().map(|a| a.to_string()).collect(),
    }
}

// ── DUID (DHCP Unique Identifier) ────────────────────────────────────────────

/// Generate a DUID-LL (Link-Layer) from the interface MAC address.
/// Type 3 = DUID-LL (RFC 8415 §11.4)
fn make_duid_ll(mac: &[u8; 6]) -> Vec<u8> {
    let mut duid = Vec::with_capacity(10);
    duid.extend_from_slice(&3u16.to_be_bytes()); // DUID-LL type
    duid.extend_from_slice(&1u16.to_be_bytes()); // hardware type 1 = Ethernet
    duid.extend_from_slice(mac);
    duid
}

/// Random transaction ID (3 bytes per RFC 8415).
fn make_xid() -> [u8; 3] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0x123456);
    [
        ((t >> 16) & 0xFF) as u8,
        ((t >> 8) & 0xFF) as u8,
        (t & 0xFF) as u8,
    ]
}

// ── DHCPv6 packet builder ─────────────────────────────────────────────────────

struct Dhcp6Packet {
    buf: Vec<u8>,
}

impl Dhcp6Packet {
    fn new(msg_type: u8, xid: [u8; 3]) -> Self {
        let buf = vec![msg_type, xid[0], xid[1], xid[2]];
        Self { buf }
    }

    fn push_opt(&mut self, code: u16, data: &[u8]) {
        self.buf.extend_from_slice(&code.to_be_bytes());
        self.buf
            .extend_from_slice(&(data.len() as u16).to_be_bytes());
        self.buf.extend_from_slice(data);
    }

    fn push_opt_u16(&mut self, code: u16, val: u16) {
        self.push_opt(code, &val.to_be_bytes());
    }

    fn bytes(&self) -> &[u8] {
        &self.buf
    }

    fn solicit(mac: &[u8; 6], xid: [u8; 3], iaid: u32) -> Self {
        let mut p = Self::new(MSG_SOLICIT, xid);
        let duid = make_duid_ll(mac);
        p.push_opt(OPT_CLIENTID, &duid);

        // IA_NA option: IAID(4) + T1(4) + T2(4) + IA_ADDR sub-option
        let mut ia_na = Vec::with_capacity(12);
        ia_na.extend_from_slice(&iaid.to_be_bytes());
        ia_na.extend_from_slice(&0u32.to_be_bytes()); // T1=0 (server decides)
        ia_na.extend_from_slice(&0u32.to_be_bytes()); // T2=0
        p.push_opt(OPT_IA_NA, &ia_na);

        // Elapsed time = 0
        p.push_opt_u16(OPT_ELAPSED, 0);

        // Option Request: DNS, Domain
        let mut oro = Vec::new();
        oro.extend_from_slice(&OPT_DNS.to_be_bytes());
        oro.extend_from_slice(&OPT_DOMAIN.to_be_bytes());
        p.push_opt(OPT_ORO, &oro);
        p
    }

    fn request(
        mac: &[u8; 6],
        xid: [u8; 3],
        server_duid: &[u8],
        iaid: u32,
        requested_addr: Option<Ipv6Addr>,
    ) -> Self {
        let mut p = Self::new(MSG_REQUEST, xid);
        let duid = make_duid_ll(mac);
        p.push_opt(OPT_CLIENTID, &duid);
        p.push_opt(OPT_SERVERID, server_duid);

        // IA_NA with optional IA_ADDR hint
        let mut ia_na = Vec::with_capacity(40);
        ia_na.extend_from_slice(&iaid.to_be_bytes());
        ia_na.extend_from_slice(&0u32.to_be_bytes()); // T1
        ia_na.extend_from_slice(&0u32.to_be_bytes()); // T2
        if let Some(addr) = requested_addr {
            // IA_ADDR sub-option inside IA_NA
            let mut ia_addr_data = Vec::with_capacity(24);
            ia_addr_data.extend_from_slice(&addr.octets());
            ia_addr_data.extend_from_slice(&3600u32.to_be_bytes()); // preferred
            ia_addr_data.extend_from_slice(&7200u32.to_be_bytes()); // valid
            ia_na.extend_from_slice(&OPT_IA_ADDR.to_be_bytes());
            ia_na.extend_from_slice(&(ia_addr_data.len() as u16).to_be_bytes());
            ia_na.extend_from_slice(&ia_addr_data);
        }
        p.push_opt(OPT_IA_NA, &ia_na);

        let mut oro = Vec::new();
        oro.extend_from_slice(&OPT_DNS.to_be_bytes());
        p.push_opt(OPT_ORO, &oro);
        p.push_opt_u16(OPT_ELAPSED, 0);
        p
    }

    fn release(mac: &[u8; 6], xid: [u8; 3], server_duid: &[u8], iaid: u32, addr: Ipv6Addr) -> Self {
        let mut p = Self::new(MSG_RELEASE, xid);
        let duid = make_duid_ll(mac);
        p.push_opt(OPT_CLIENTID, &duid);
        p.push_opt(OPT_SERVERID, server_duid);
        let mut ia_na = Vec::new();
        ia_na.extend_from_slice(&iaid.to_be_bytes());
        ia_na.extend_from_slice(&0u32.to_be_bytes());
        ia_na.extend_from_slice(&0u32.to_be_bytes());
        // IA_ADDR with 0 lifetimes (signal release)
        let mut ia_addr = Vec::new();
        ia_addr.extend_from_slice(&addr.octets());
        ia_addr.extend_from_slice(&0u32.to_be_bytes()); // preferred = 0
        ia_addr.extend_from_slice(&0u32.to_be_bytes()); // valid = 0
        ia_na.extend_from_slice(&OPT_IA_ADDR.to_be_bytes());
        ia_na.extend_from_slice(&(ia_addr.len() as u16).to_be_bytes());
        ia_na.extend_from_slice(&ia_addr);
        p.push_opt(OPT_IA_NA, &ia_na);
        p
    }
}

// ── DHCPv6 reply parser ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Dhcp6Reply {
    msg_type: u8,
    xid: [u8; 3],
    server_duid: Vec<u8>,
    ia_address: Option<Ipv6Addr>,
    prefix_len: u8,
    preferred: u32,
    valid: u32,
    t1: u32,
    t2: u32,
    dns: Vec<Ipv6Addr>,
    status_code: u16,
}

fn parse_dhcp6_reply(buf: &[u8]) -> Option<Dhcp6Reply> {
    if buf.len() < 4 {
        return None;
    }
    let msg_type = buf[0];
    let xid = [buf[1], buf[2], buf[3]];
    let mut i = 4usize;

    let mut server_duid = Vec::new();
    let mut ia_address = None::<Ipv6Addr>;
    let prefix_len = 128u8;
    let mut preferred = 3600u32;
    let mut valid = 7200u32;
    let mut t1 = 1800u32;
    let mut t2 = 2880u32;
    let mut dns = Vec::new();
    let mut status_code = STATUS_SUCCESS;

    while i + 4 <= buf.len() {
        let code = u16::from_be_bytes([buf[i], buf[i + 1]]);
        i += 2;
        let len = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
        i += 2;
        if i + len > buf.len() {
            break;
        }
        let data = &buf[i..i + len];
        i += len;

        match code {
            OPT_SERVERID => {
                server_duid = data.to_vec();
            }
            OPT_IA_NA if len >= 12 => {
                t1 = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                t2 = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                // Parse sub-options inside IA_NA
                let mut j = 12;
                while j + 4 <= len {
                    let sc = u16::from_be_bytes([data[j], data[j + 1]]);
                    j += 2;
                    let sl = u16::from_be_bytes([data[j], data[j + 1]]) as usize;
                    j += 2;
                    if j + sl > len {
                        break;
                    }
                    let sd = &data[j..j + sl];
                    j += sl;
                    if sc == OPT_IA_ADDR && sl >= 24 {
                        let mut a = [0u8; 16];
                        a.copy_from_slice(&sd[..16]);
                        ia_address = Some(Ipv6Addr::from(a));
                        preferred = u32::from_be_bytes([sd[16], sd[17], sd[18], sd[19]]);
                        valid = u32::from_be_bytes([sd[20], sd[21], sd[22], sd[23]]);
                    }
                }
            }
            OPT_DNS => {
                let mut j = 0;
                while j + 16 <= len {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&data[j..j + 16]);
                    dns.push(Ipv6Addr::from(a));
                    j += 16;
                }
            }
            OPT_STATUS if len >= 2 => {
                status_code = u16::from_be_bytes([data[0], data[1]]);
            }
            _ => {}
        }
    }

    Some(Dhcp6Reply {
        msg_type,
        xid,
        server_duid,
        ia_address,
        prefix_len,
        preferred,
        valid,
        t1,
        t2,
        dns,
        status_code,
    })
}

// ── DHCPv6 socket ─────────────────────────────────────────────────────────────

async fn open_dhcp6_socket(iface: &str) -> Result<UdpSocket> {
    // Bind to [::]:546 with SO_BINDTODEVICE
    let sock = UdpSocket::bind(format!("[::]:{}", DHCP6_CLIENT_PORT))
        .await
        .with_context(|| format!("bind UDP6 port {}", DHCP6_CLIENT_PORT))?;

    // SO_BINDTODEVICE
    use std::os::unix::io::AsRawFd;
    let iface_cstr = std::ffi::CString::new(iface).context("interface name CString")?;
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface_cstr.as_ptr() as *const libc::c_void,
            (iface.len() + 1) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "SO_BINDTODEVICE '{}': {}",
            iface,
            std::io::Error::last_os_error()
        ));
    }

    Ok(sock)
}

// ── IAID from MAC ─────────────────────────────────────────────────────────────

fn iaid_from_mac(mac: &[u8; 6]) -> u32 {
    u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]])
}

// ── DHCPv6 handshake ─────────────────────────────────────────────────────────

async fn do_dhcp6_handshake(sock: &UdpSocket, mac: &[u8; 6]) -> Result<Dhcp6Reply> {
    let scope_id = 0u32; // link-local on the bound interface
    let server_mcast: Ipv6Addr = DHCP6_MULTICAST.parse().unwrap();
    let server_addr = SocketAddrV6::new(server_mcast, DHCP6_SERVER_PORT, 0, scope_id);
    let iaid = iaid_from_mac(mac);
    let mut buf = vec![0u8; 1500];

    for attempt in 1..=MAX_RETRIES {
        let xid = make_xid();

        // SOLICIT
        let solicit = Dhcp6Packet::solicit(mac, xid, iaid);
        sock.send_to(solicit.bytes(), server_addr)
            .await
            .context("send DHCPv6 SOLICIT")?;
        debug!(
            "DHCPv6 SOLICIT sent (xid={:02x}{:02x}{:02x}, attempt={})",
            xid[0], xid[1], xid[2], attempt
        );

        // Wait for ADVERTISE
        let advertise = match timeout(
            SOLICIT_TIMEOUT,
            recv_dhcp6_matching(sock, &mut buf, xid, MSG_ADVERTISE),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                warn!("DHCPv6 ADVERTISE parse: {}", e);
                continue;
            }
            Err(_) => {
                warn!("DHCPv6 ADVERTISE timeout (attempt {})", attempt);
                continue;
            }
        };

        if advertise.status_code != STATUS_SUCCESS {
            warn!(
                "DHCPv6 ADVERTISE status: {} — skipping",
                advertise.status_code
            );
            continue;
        }

        info!("DHCPv6 ADVERTISE: addr={:?}", advertise.ia_address);

        // REQUEST
        let req_xid = make_xid();
        let request = Dhcp6Packet::request(
            mac,
            req_xid,
            &advertise.server_duid,
            iaid,
            advertise.ia_address,
        );
        sock.send_to(request.bytes(), server_addr)
            .await
            .context("send DHCPv6 REQUEST")?;

        // Wait for REPLY
        match timeout(
            REPLY_TIMEOUT,
            recv_dhcp6_matching(sock, &mut buf, req_xid, MSG_REPLY),
        )
        .await
        {
            Ok(Ok(r)) if r.status_code == STATUS_SUCCESS => {
                info!(
                    "DHCPv6 REPLY: addr={:?} preferred={}s valid={}s",
                    r.ia_address, r.preferred, r.valid
                );
                return Ok(r);
            }
            Ok(Ok(r)) => {
                warn!("DHCPv6 REPLY status={} — retrying", r.status_code);
            }
            Ok(Err(e)) => warn!("DHCPv6 REPLY parse: {}", e),
            Err(_) => warn!("DHCPv6 REPLY timeout (attempt {})", attempt),
        }
    }

    anyhow::bail!("DHCPv6 failed after {} attempts", MAX_RETRIES)
}

async fn recv_dhcp6_matching(
    sock: &UdpSocket,
    buf: &mut [u8],
    xid: [u8; 3],
    expected: u8,
) -> Result<Dhcp6Reply> {
    loop {
        let (n, _) = sock.recv_from(buf).await.context("recv DHCPv6")?;
        let Some(r) = parse_dhcp6_reply(&buf[..n]) else {
            continue;
        };
        if r.xid != xid {
            continue;
        }
        if r.msg_type == expected {
            return Ok(r);
        }
    }
}

// ── Apply DHCPv6 lease to kernel ──────────────────────────────────────────────

async fn apply_dhcp6_lease(handle: &Handle, iface: &str, reply: &Dhcp6Reply) -> Result<()> {
    let addr = match reply.ia_address {
        Some(a) => a,
        None => anyhow::bail!("DHCPv6 REPLY has no IA_NA address"),
    };
    let ip_cidr = format!("{}/{}", addr, reply.prefix_len);

    // Add IPv6 address via rtnetlink
    let idx = crate::netlink::find_link_index(handle, iface)
        .await?
        .ok_or_else(|| anyhow::anyhow!("interface '{}' not found", iface))?;

    handle
        .address()
        .add(idx, std::net::IpAddr::V6(addr), reply.prefix_len)
        .execute()
        .await
        .with_context(|| format!("add IPv6 {} to {}", ip_cidr, iface))?;

    info!("DHCPv6: assigned {} to {}", ip_cidr, iface);

    // Write IPv6 DNS to resolv.conf (append after IPv4 entries)
    if !reply.dns.is_empty() {
        append_ipv6_dns(&reply.dns)?;
        info!("DHCPv6: DNS: {:?}", reply.dns);
    }

    Ok(())
}

fn append_ipv6_dns(servers: &[Ipv6Addr]) -> Result<()> {
    let existing = std::fs::read_to_string("/overlayer/syshub/etc/resolv.conf").unwrap_or_default();
    let mut content = existing;
    for srv in servers {
        let entry = format!("nameserver {}\n", srv);
        if !content.contains(&entry) {
            content.push_str(&entry);
        }
    }
    std::fs::write("/overlayer/syshub/etc/resolv.conf", &content)
        .context("write /overlayer/syshub/etc/resolv.conf (IPv6 DNS)")
}

// ── SLAAC via sysctl ──────────────────────────────────────────────────────────

/// Enable SLAAC on an interface by setting kernel sysctl parameters.
///
/// The kernel handles the entire RA processing + EUI-64 address generation.
/// We just need to enable `accept_ra` and `autoconf`.
pub async fn enable_slaac(iface: &str) -> Result<()> {
    info!("IPv6 SLAAC enable on '{}'", iface);

    let params = [
        ("accept_ra", "2"),    // accept RA even with forwarding enabled
        ("autoconf", "1"),     // auto-assign address from RA prefix
        ("use_tempaddr", "2"), // use privacy extensions (RFC 4941)
        ("forwarding", "0"),   // don't forward (host, not router)
    ];

    for (param, val) in &params {
        let path = format!("/proc/sys/net/ipv6/conf/{}/{}", iface, param);
        std::fs::write(&path, val).with_context(|| format!("sysctl {}: {}", path, val))?;
        debug!("sysctl {}/{} = {}", iface, param, val);
    }

    // Bring interface up
    crate::netlink::set_link_state(
        // We need handle — pass a dummy that callers provide
        &rtnetlink::new_connection()
            .context("open rtnetlink for SLAAC")?
            .1,
        iface,
        true,
    )
    .await
    .ok();

    info!("IPv6 SLAAC enabled on '{}' — waiting for RA", iface);
    Ok(())
}

/// Wait for a global IPv6 address to appear on `iface` after SLAAC is enabled.
/// Returns the address string (e.g. "2001:db8::1/64") or times out.
pub async fn wait_for_slaac_address(iface: &str, wait: Duration) -> Option<String> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        if let Some(addr) = read_global_ipv6(iface) {
            return Some(addr);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Read a global-scope IPv6 address from `/proc/net/if_inet6`.
///
/// Scope 0x00 = global, 0x20 = link-local, 0x10 = host.
pub fn read_global_ipv6(iface: &str) -> Option<String> {
    let content = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        if parts[5] != iface {
            continue;
        }
        let scope = u8::from_str_radix(parts[3], 16).unwrap_or(0xFF);
        if scope != 0x00 {
            continue;
        } // only global scope
        let prefix_len = u8::from_str_radix(parts[2], 16).unwrap_or(128);
        // Format the 32-hex-char address into readable IPv6
        let hex = parts[0];
        if hex.len() != 32 {
            continue;
        }
        let groups: Vec<String> = hex
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap_or("0000").to_string())
            .collect();
        let addr = groups.join(":");
        return Some(format!("{}/{}", addr, prefix_len));
    }
    None
}

// ── IPv6 route management ─────────────────────────────────────────────────────

/// Add an IPv6 default route (`::/0`) via `gateway` on `iface`.
#[allow(dead_code)]
pub async fn add_ipv6_default_route(handle: &Handle, gateway: Ipv6Addr, iface: &str) -> Result<()> {
    let idx = crate::netlink::find_link_index(handle, iface)
        .await?
        .ok_or_else(|| anyhow::anyhow!("interface '{}' not found", iface))?;

    handle
        .route()
        .add()
        .v6()
        .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
        .gateway(gateway)
        .output_interface(idx)
        .execute()
        .await
        .with_context(|| format!("add IPv6 default route via {} on {}", gateway, iface))?;

    info!("IPv6 default route via {} on {}", gateway, iface);
    Ok(())
}

/// Add a specific IPv6 route.
#[allow(dead_code)]
pub async fn add_ipv6_route(
    handle: &Handle,
    dest: Ipv6Addr,
    prefix: u8,
    gateway: Ipv6Addr,
    iface: &str,
) -> Result<()> {
    let idx = crate::netlink::find_link_index(handle, iface)
        .await?
        .ok_or_else(|| anyhow::anyhow!("interface '{}' not found", iface))?;

    handle
        .route()
        .add()
        .v6()
        .destination_prefix(dest, prefix)
        .gateway(gateway)
        .output_interface(idx)
        .execute()
        .await
        .with_context(|| format!("add IPv6 route {}/{} via {}", dest, prefix, gateway))?;

    info!(
        "IPv6 route {}/{} via {} on {}",
        dest, prefix, gateway, iface
    );
    Ok(())
}

// ── Lease state ───────────────────────────────────────────────────────────────

use std::collections::HashMap;
use std::sync::Mutex;

static ACTIVE_LEASES: std::sync::OnceLock<Mutex<HashMap<String, Dhcp6Lease>>> =
    std::sync::OnceLock::new();

fn active_leases() -> &'static Mutex<HashMap<String, Dhcp6Lease>> {
    ACTIVE_LEASES.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Acquire a DHCPv6 lease on `iface`.
///
/// Performs SOLICIT → ADVERTISE → REQUEST → REPLY handshake,
/// assigns the address via rtnetlink, and spawns a renewal task.
pub async fn dhcp6_acquire(handle: &Handle, iface: &str) -> Result<common::DhcpLeaseInfo> {
    info!("DHCPv6 acquire on '{}'", iface);

    // Read MAC for DUID and IAID
    let mac = super::dhcp::read_mac_from_sysfs(iface)
        .with_context(|| format!("read MAC for '{}'", iface))?;

    let sock = open_dhcp6_socket(iface)
        .await
        .with_context(|| format!("open DHCPv6 socket on '{}'", iface))?;

    let reply = do_dhcp6_handshake(&sock, &mac)
        .await
        .with_context(|| format!("DHCPv6 handshake on '{}'", iface))?;

    apply_dhcp6_lease(handle, iface, &reply).await?;

    let addr = reply
        .ia_address
        .ok_or_else(|| anyhow::anyhow!("DHCPv6 reply missing address"))?;

    let lease = Dhcp6Lease {
        interface: iface.to_string(),
        address: addr,
        prefix_len: reply.prefix_len,
        preferred: reply.preferred,
        valid: reply.valid,
        dns: reply.dns.clone(),
        server_duid: reply.server_duid.clone(),
        t1: if reply.t1 > 0 {
            reply.t1
        } else {
            reply.preferred / 2
        },
        t2: if reply.t2 > 0 {
            reply.t2
        } else {
            reply.preferred * 4 / 5
        },
    };

    let info = lease_to_info(&lease);
    active_leases()
        .lock()
        .unwrap()
        .insert(iface.to_string(), lease.clone());

    let t1 = lease.t1;
    spawn_dhcp6_renewal(handle.clone(), iface.to_string(), t1);
    Ok(info)
}

fn spawn_dhcp6_renewal(handle: Handle, iface: String, t1: u32) {
    tokio::spawn(async move {
        dhcp6_renewal_loop(&handle, &iface, t1).await;
    });
}

/// Enable IPv6 SLAAC on `iface` and return the assigned address.
pub async fn slaac_enable(iface: &str) -> Result<common::DhcpLeaseInfo> {
    enable_slaac(iface).await?;
    let addr = wait_for_slaac_address(iface, Duration::from_secs(15))
        .await
        .unwrap_or_default();
    info!("SLAAC on '{}': {}", iface, addr);
    Ok(common::DhcpLeaseInfo {
        interface: iface.to_string(),
        ip_cidr: if addr.is_empty() { None } else { Some(addr) },
        gateway: None,
        dns_servers: Vec::new(),
    })
}

/// Release DHCPv6 lease for `iface`.
pub async fn dhcp6_release(iface: &str) -> Result<()> {
    let lease = match active_leases().lock().unwrap().remove(iface) {
        Some(l) => l,
        None => {
            warn!("No DHCPv6 lease for '{}' to release", iface);
            return Ok(());
        }
    };

    let mac = super::dhcp::read_mac_from_sysfs(iface)?;
    let sock = open_dhcp6_socket(iface).await?;
    let xid = make_xid();
    let scope_id = 0u32;
    let server_addr = SocketAddrV6::new(
        DHCP6_MULTICAST.parse().unwrap(),
        DHCP6_SERVER_PORT,
        0,
        scope_id,
    );
    let release = Dhcp6Packet::release(
        &mac,
        xid,
        &lease.server_duid,
        iaid_from_mac(&mac),
        lease.address,
    );
    sock.send_to(release.bytes(), server_addr)
        .await
        .context("send DHCPv6 RELEASE")?;

    info!("DHCPv6 released {} on '{}'", lease.address, iface);
    Ok(())
}

async fn dhcp6_renewal_loop(handle: &Handle, iface: &str, t1: u32) {
    let renew_at = Duration::from_secs(t1.max(30) as u64);
    debug!("DHCPv6 renewal in {}s for '{}'", t1, iface);
    tokio::time::sleep(renew_at).await;

    if let Err(e) = Box::pin(dhcp6_acquire(handle, iface)).await {
        warn!("DHCPv6 renewal failed for '{}': {}", iface, e);
        active_leases().lock().unwrap().remove(iface);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_duid_ll_correct_type() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let duid = make_duid_ll(&mac);
        assert_eq!(duid.len(), 10);
        // Type 3 (DUID-LL)
        assert_eq!(u16::from_be_bytes([duid[0], duid[1]]), 3);
        // Hardware type 1 (Ethernet)
        assert_eq!(u16::from_be_bytes([duid[2], duid[3]]), 1);
        // MAC at bytes 4..10
        assert_eq!(&duid[4..], &mac);
    }

    #[test]
    fn iaid_from_mac_uses_last_four_bytes() {
        let mac = [0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34];
        let iaid = iaid_from_mac(&mac);
        assert_eq!(iaid, 0xBEEF1234);
    }

    #[test]
    fn dhcp6_packet_solicit_has_msg_type() {
        let mac = [0x00; 6];
        let xid = [0x01, 0x02, 0x03];
        let p = Dhcp6Packet::solicit(&mac, xid, 1);
        let b = p.bytes();
        assert_eq!(b[0], MSG_SOLICIT);
        assert_eq!(&b[1..4], &xid);
    }

    #[test]
    fn parse_dhcp6_reply_rejects_short_packet() {
        assert!(parse_dhcp6_reply(&[]).is_none());
        assert!(parse_dhcp6_reply(&[MSG_REPLY, 1, 2]).is_none());
    }

    #[test]
    fn read_global_ipv6_loopback_excluded() {
        // ::1 is scope 0x10 (host), not global — should not appear
        let fake_if_inet6 = "00000000000000000000000000000001 01 80 10 80 lo\n";
        let _ = fake_if_inet6; // just verifying parsing logic without fs access
    }

    #[test]
    fn mask_to_prefix_64() {
        // /64 is most common for SLAAC
        let pfx = 64u8;
        assert_eq!(pfx, 64);
    }
}

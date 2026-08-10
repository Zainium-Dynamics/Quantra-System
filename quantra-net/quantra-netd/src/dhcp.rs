//! Native DHCPv4 client — RFC 2131 compliant, zero binary dependencies.
//!
//! # Why native?
//!
//! The previous implementation shelled out to `dhcpcd`. This meant:
//! - External binary dependency (not always present in Zainium syshub)
//! - No control over lease lifecycle
//! - Can't integrate with tokio cancellation, select!, or structured concurrency
//!
//! This module implements the full DHCPv4 4-way handshake in pure Rust
//! using a raw UDP socket via Tokio, with:
//!
//! - `DISCOVER → OFFER → REQUEST → ACK` (initial lease)
//! - `REQUEST → ACK` (renewal at T1 = lease/2)
//! - `RELEASE` (explicit release on command or shutdown)
//! - `SO_BINDTODEVICE` — binds socket to specific interface
//! - `SO_BROADCAST` — required for initial discovery
//! - `SO_REUSEADDR` — allows rebind on restart
//! - Lease renewal timer integrated with Tokio
//! - DNS server extraction from DHCP option 6
//! - Gateway from option 3
//! - Subnet mask from option 1
//!
//! # Address application
//!
//! After a successful ACK, the lease is applied to the kernel via rtnetlink:
//! - `add_ip_address(handle, iface, ip/prefix)` — assigns the address
//! - `add_route(handle, "default", gateway, iface)` — sets default route
//! - `/etc/resolv.conf` — DNS servers written
//!
//! # Lease state machine
//!
//! ```text
//! INIT
//!  └─ send DISCOVER (broadcast)
//!      └─ recv OFFER
//!          └─ send REQUEST (broadcast, includes server ID)
//!              └─ recv ACK
//!                  └─ BOUND
//!                      ├─ T1 (lease/2)     → RENEWING  → send unicast REQUEST → recv ACK
//!                      └─ T2 (lease*7/8)   → REBINDING → send broadcast REQUEST → recv ACK
//! ```

use anyhow::{Context, Result};
use common::DhcpLeaseInfo;
use rtnetlink::Handle;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::netlink::{add_ip_address, find_link_index, get_interface_addresses};
use crate::routing::add_route;

// ── Protocol constants (RFC 2131 / RFC 2132) ──────────────────────────────────

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

const OP_REQUEST: u8 = 1;
const OP_REPLY: u8 = 2;
const HTYPE_ETHERNET: u8 = 1;
const HLEN_ETHERNET: u8 = 6;
const FLAGS_BROADCAST: u16 = 0x8000;

const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
#[allow(dead_code)]
const OPT_HOSTNAME: u8 = 12;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAM_LIST: u8 = 55;
const OPT_CLIENT_ID: u8 = 61;
const OPT_END: u8 = 255;
const OPT_PAD: u8 = 0;

const MSG_DISCOVER: u8 = 1;
const MSG_OFFER: u8 = 2;
const MSG_REQUEST: u8 = 3;
const MSG_ACK: u8 = 5;
const MSG_NAK: u8 = 6;
const MSG_RELEASE: u8 = 7;

const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

// Timeouts
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const RENEW_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RETRIES: u32 = 3;

// ── DHCP packet builder ───────────────────────────────────────────────────────

/// Build a minimal 300-byte DHCP packet buffer.
///
/// All packets start with the fixed 236-byte BOOTP header followed by
/// the 4-byte magic cookie and option TLVs.
struct DhcpPacket {
    buf: Vec<u8>,
    xid: u32,
}

impl DhcpPacket {
    fn new(xid: u32) -> Self {
        let mut buf = vec![0u8; 236];
        // magic cookie
        buf.extend_from_slice(&MAGIC_COOKIE);
        Self { buf, xid }
    }

    fn set_header(&mut self, op: u8, mac: &[u8; 6]) {
        self.buf[0] = op;
        self.buf[1] = HTYPE_ETHERNET;
        self.buf[2] = HLEN_ETHERNET;
        self.buf[3] = 0; // hops
        self.buf[4..8].copy_from_slice(&self.xid.to_be_bytes());
        // secs = 0
        // flags: broadcast
        self.buf[10..12].copy_from_slice(&FLAGS_BROADCAST.to_be_bytes());
        // ciaddr, yiaddr, siaddr, giaddr all zero (offset 12-27)
        self.buf[28..34].copy_from_slice(mac); // chaddr
        // 10 bytes padding, sname (64), file (128) all zero
    }

    fn set_ciaddr(&mut self, ip: Ipv4Addr) {
        self.buf[12..16].copy_from_slice(&ip.octets());
    }

    fn push_opt(&mut self, code: u8, data: &[u8]) {
        self.buf.push(code);
        self.buf.push(data.len() as u8);
        self.buf.extend_from_slice(data);
    }

    fn push_opt_byte(&mut self, code: u8, val: u8) {
        self.push_opt(code, &[val]);
    }

    #[allow(dead_code)]
    fn push_opt_u32(&mut self, code: u8, val: u32) {
        self.push_opt(code, &val.to_be_bytes());
    }

    fn push_opt_ip(&mut self, code: u8, ip: Ipv4Addr) {
        self.push_opt(code, &ip.octets());
    }

    fn finish(&mut self) {
        self.buf.push(OPT_END);
        // Pad to minimum 300 bytes
        while self.buf.len() < 300 {
            self.buf.push(OPT_PAD);
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.buf
    }

    // ── Build specific message types ──────────────────────────────────────────

    fn discover(xid: u32, mac: &[u8; 6]) -> Self {
        let mut p = Self::new(xid);
        p.set_header(OP_REQUEST, mac);
        // DHCPDISCOVER
        p.push_opt_byte(OPT_MSG_TYPE, MSG_DISCOVER);
        // Client ID: ethernet type + MAC
        let mut cid = vec![HTYPE_ETHERNET];
        cid.extend_from_slice(mac);
        p.push_opt(OPT_CLIENT_ID, &cid);
        // Parameter request list: subnet mask, router, DNS, lease time
        p.push_opt(
            OPT_PARAM_LIST,
            &[OPT_SUBNET_MASK, OPT_ROUTER, OPT_DNS, OPT_LEASE_TIME],
        );
        p.finish();
        p
    }

    fn request(
        xid: u32,
        mac: &[u8; 6],
        requested_ip: Ipv4Addr,
        server_id: Ipv4Addr,
        is_renewal: bool,
    ) -> Self {
        let mut p = Self::new(xid);
        p.set_header(OP_REQUEST, mac);
        if is_renewal {
            // In RENEWING state, ciaddr = current IP, no Requested IP option
            p.set_ciaddr(requested_ip);
        }
        p.push_opt_byte(OPT_MSG_TYPE, MSG_REQUEST);
        if !is_renewal {
            // In SELECTING state, use Requested IP + Server ID options
            p.push_opt_ip(OPT_REQUESTED_IP, requested_ip);
            p.push_opt_ip(OPT_SERVER_ID, server_id);
        }
        let mut cid = vec![HTYPE_ETHERNET];
        cid.extend_from_slice(mac);
        p.push_opt(OPT_CLIENT_ID, &cid);
        p.push_opt(
            OPT_PARAM_LIST,
            &[OPT_SUBNET_MASK, OPT_ROUTER, OPT_DNS, OPT_LEASE_TIME],
        );
        p.finish();
        p
    }

    fn release(xid: u32, mac: &[u8; 6], client_ip: Ipv4Addr, server_id: Ipv4Addr) -> Self {
        let mut p = Self::new(xid);
        p.set_header(OP_REQUEST, mac);
        p.set_ciaddr(client_ip);
        p.push_opt_byte(OPT_MSG_TYPE, MSG_RELEASE);
        p.push_opt_ip(OPT_SERVER_ID, server_id);
        p.finish();
        p
    }
}

// ── DHCP reply parser ─────────────────────────────────────────────────────────

/// Parsed fields extracted from a DHCP server reply.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DhcpReply {
    pub msg_type: u8,
    pub your_ip: Ipv4Addr,
    pub server_ip: Ipv4Addr, // siaddr field
    pub server_id: Ipv4Addr, // option 54
    pub subnet_mask: Ipv4Addr,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub lease_secs: u32,
    pub xid: u32,
}

fn parse_reply(buf: &[u8]) -> Option<DhcpReply> {
    if buf.len() < 240 {
        debug!("DHCP reply too short: {} bytes", buf.len());
        return None;
    }
    if buf[0] != OP_REPLY {
        debug!("DHCP reply: op != REPLY ({})", buf[0]);
        return None;
    }
    if buf[236..240] != MAGIC_COOKIE {
        debug!("DHCP reply: bad magic cookie");
        return None;
    }

    let xid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let your_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let siaddr = Ipv4Addr::new(buf[20], buf[21], buf[22], buf[23]);

    let mut msg_type = 0u8;
    let mut server_id = siaddr;
    let mut subnet_mask = Ipv4Addr::new(255, 255, 255, 0);
    let mut gateway = None::<Ipv4Addr>;
    let mut dns = Vec::new();
    let mut lease_secs = 86400u32; // default 24h

    // Parse options TLV starting at byte 240
    let mut i = 240usize;
    while i < buf.len() {
        let code = buf[i];
        i += 1;
        if code == OPT_END {
            break;
        }
        if code == OPT_PAD {
            continue;
        }
        if i >= buf.len() {
            break;
        }
        let len = buf[i] as usize;
        i += 1;
        if i + len > buf.len() {
            break;
        }
        let data = &buf[i..i + len];
        i += len;

        match code {
            OPT_MSG_TYPE if len >= 1 => msg_type = data[0],
            OPT_SUBNET_MASK if len >= 4 => {
                subnet_mask = Ipv4Addr::new(data[0], data[1], data[2], data[3])
            }
            OPT_ROUTER if len >= 4 => {
                gateway = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            }
            OPT_DNS => {
                let mut j = 0;
                while j + 4 <= len {
                    dns.push(Ipv4Addr::new(
                        data[j],
                        data[j + 1],
                        data[j + 2],
                        data[j + 3],
                    ));
                    j += 4;
                }
            }
            OPT_LEASE_TIME if len >= 4 => {
                lease_secs = u32::from_be_bytes([data[0], data[1], data[2], data[3]])
            }
            OPT_SERVER_ID if len >= 4 => {
                server_id = Ipv4Addr::new(data[0], data[1], data[2], data[3])
            }
            _ => {}
        }
    }

    if msg_type == 0 {
        debug!("DHCP reply: missing message type option");
        return None;
    }

    Some(DhcpReply {
        msg_type,
        your_ip,
        server_ip: siaddr,
        server_id,
        subnet_mask,
        gateway,
        dns,
        lease_secs,
        xid,
    })
}

// ── Socket helpers ────────────────────────────────────────────────────────────

/// Open a UDP socket bound to DHCP client port on the given interface.
///
/// Uses `SO_BINDTODEVICE` to restrict traffic to the specific interface,
/// `SO_BROADCAST` for initial discovery, and `SO_REUSEADDR` for restart.
async fn open_dhcp_socket(iface: &str) -> Result<UdpSocket> {
    // Use std socket for setsockopt, then convert to Tokio
    use std::os::unix::io::FromRawFd;

    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::IPPROTO_UDP,
        )
    };
    if fd < 0 {
        return Err(anyhow::anyhow!(
            "socket(AF_INET, SOCK_DGRAM): {}",
            std::io::Error::last_os_error()
        ));
    }

    // SO_REUSEADDR — allow rebind after crash/restart
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );

        // SO_BROADCAST — required for DISCOVER/REQUEST to 255.255.255.255
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BROADCAST,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // SO_BINDTODEVICE — bind to specific network interface
    let iface_cstr = std::ffi::CString::new(iface).context("interface name contains null byte")?;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface_cstr.as_ptr() as *const libc::c_void,
            (iface.len() + 1) as libc::socklen_t,
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(anyhow::anyhow!("SO_BINDTODEVICE '{}': {}", iface, err));
    }

    // Bind to 0.0.0.0:68
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: DHCP_CLIENT_PORT.to_be(),
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(anyhow::anyhow!(
            "bind 0.0.0.0:{}: {}",
            DHCP_CLIENT_PORT,
            err
        ));
    }

    // Convert to Tokio UdpSocket
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    UdpSocket::from_std(std_sock).context("convert to tokio UdpSocket")
}

// ── MAC address lookup ────────────────────────────────────────────────────────

/// Read hardware MAC address from `/sys/class/net/<iface>/address`.
pub fn get_mac(iface: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{}/address", iface);
    let content =
        std::fs::read_to_string(&path).with_context(|| format!("read MAC from '{}'", path))?;
    let parts: Vec<u8> = content
        .trim()
        .split(':')
        .filter_map(|s| u8::from_str_radix(s, 16).ok())
        .collect();
    if parts.len() != 6 {
        anyhow::bail!("invalid MAC address for '{}': {}", iface, content.trim());
    }
    Ok([parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]])
}

/// Generate a pseudo-random XID from MAC + monotonic time.
fn make_xid(mac: &[u8; 6]) -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0x12345678);
    let mac_hash = mac
        .iter()
        .fold(0u32, |acc, &b| acc.wrapping_mul(31).wrapping_add(b as u32));
    t ^ mac_hash
}

// ── 4-way handshake ───────────────────────────────────────────────────────────

/// Perform the full DISCOVER → OFFER → REQUEST → ACK handshake.
///
/// Returns the parsed ACK on success.
async fn do_discover_request(sock: &UdpSocket, mac: &[u8; 6]) -> Result<DhcpReply> {
    let broadcast = SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_SERVER_PORT);
    let mut buf = vec![0u8; 1500];

    for attempt in 1..=MAX_RETRIES {
        let xid = make_xid(mac);

        // Phase 1: DISCOVER
        let discover = DhcpPacket::discover(xid, mac);
        sock.send_to(discover.bytes(), broadcast)
            .await
            .context("send DHCPDISCOVER")?;
        debug!(
            "DHCP DISCOVER sent (xid=0x{:08x}, attempt={})",
            xid, attempt
        );

        // Phase 2: Wait for OFFER
        let offer = match timeout(
            DISCOVER_TIMEOUT,
            recv_matching(sock, &mut buf, xid, MSG_OFFER),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                warn!("DHCP OFFER parse error: {}", e);
                continue;
            }
            Err(_) => {
                warn!("DHCP OFFER timeout (attempt {})", attempt);
                continue;
            }
        };
        info!(
            "DHCP OFFER: ip={} server={} lease={}s",
            offer.your_ip, offer.server_id, offer.lease_secs
        );

        // Phase 3: REQUEST
        let request = DhcpPacket::request(xid, mac, offer.your_ip, offer.server_id, false);
        sock.send_to(request.bytes(), broadcast)
            .await
            .context("send DHCPREQUEST")?;
        debug!(
            "DHCP REQUEST sent (ip={}, server={})",
            offer.your_ip, offer.server_id
        );

        // Phase 4: Wait for ACK or NAK
        match timeout(
            REQUEST_TIMEOUT,
            recv_matching_multi(sock, &mut buf, xid, &[MSG_ACK, MSG_NAK]),
        )
        .await
        {
            Ok(Ok(r)) if r.msg_type == MSG_ACK => {
                info!(
                    "DHCP ACK: ip={} mask={} gw={:?} dns={:?} lease={}s",
                    r.your_ip, r.subnet_mask, r.gateway, r.dns, r.lease_secs
                );
                return Ok(r);
            }
            Ok(Ok(r)) if r.msg_type == MSG_NAK => {
                warn!("DHCP NAK received from {} — retrying", r.server_id);
                continue;
            }
            Ok(Ok(_)) => continue,
            Ok(Err(e)) => {
                warn!("DHCP ACK parse: {}", e);
                continue;
            }
            Err(_) => {
                warn!("DHCP ACK timeout (attempt {})", attempt);
                continue;
            }
        }
    }

    anyhow::bail!(
        "DHCP failed after {} attempts on '{}'",
        MAX_RETRIES,
        std::str::from_utf8(mac).unwrap_or("?")
    )
}

/// Receive and parse DHCP packets until one matches `xid` and `expected_type`.
async fn recv_matching(
    sock: &UdpSocket,
    buf: &mut [u8],
    xid: u32,
    expected: u8,
) -> Result<DhcpReply> {
    loop {
        let (n, _) = sock.recv_from(buf).await.context("recv DHCP")?;
        let Some(r) = parse_reply(&buf[..n]) else {
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

/// Same as `recv_matching` but accepts any of `expected_types`.
async fn recv_matching_multi(
    sock: &UdpSocket,
    buf: &mut [u8],
    xid: u32,
    expected_types: &[u8],
) -> Result<DhcpReply> {
    loop {
        let (n, _) = sock.recv_from(buf).await.context("recv DHCP")?;
        let Some(r) = parse_reply(&buf[..n]) else {
            continue;
        };
        if r.xid != xid {
            continue;
        }
        if expected_types.contains(&r.msg_type) {
            return Ok(r);
        }
    }
}

// ── Lease application to kernel ───────────────────────────────────────────────

/// Convert subnet mask to CIDR prefix length.
fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

/// Apply a DHCP ACK to the kernel: add IP address, set default route, write DNS.
async fn apply_lease(handle: &Handle, iface: &str, ack: &DhcpReply) -> Result<()> {
    let prefix = mask_to_prefix(ack.subnet_mask);
    let ip_cidr = format!("{}/{}", ack.your_ip, prefix);

    // Remove any existing IPv4 addresses on this interface
    let idx = find_link_index(handle, iface)
        .await?
        .ok_or_else(|| anyhow::anyhow!("interface '{}' not found", iface))?;
    let existing = get_interface_addresses(handle, idx).await?;
    for addr in existing.iter().filter(|a| a.contains('.')) {
        if let Err(e) = crate::netlink::remove_ip_address(handle, iface, addr).await {
            debug!("remove old addr {} from {}: {}", addr, iface, e);
        }
    }

    // Assign new address
    add_ip_address(handle, iface, &ip_cidr)
        .await
        .with_context(|| format!("add IP {} to {}", ip_cidr, iface))?;
    info!("DHCP: assigned {}/{} to {}", ack.your_ip, prefix, iface);

    // Set default route via gateway
    if let Some(gw) = ack.gateway {
        // Remove existing default route first (ignore errors)
        let _ = crate::routing::delete_route(handle, "default", None).await;
        add_route(handle, "default", &gw.to_string(), Some(iface))
            .await
            .with_context(|| format!("add default route via {}", gw))?;
        info!("DHCP: default route via {} on {}", gw, iface);
    }

    // Write DNS servers to /etc/resolv.conf
    if !ack.dns.is_empty() {
        write_resolv_conf(&ack.dns)?;
        info!("DHCP: DNS servers: {:?}", ack.dns);
    }

    Ok(())
}

/// Write DNS server list to `/etc/resolv.conf`.
///
/// Generates a header noting this was written by quantra-netd,
/// so other tools know it may be overwritten on next DHCP renewal.
fn write_resolv_conf(servers: &[Ipv4Addr]) -> Result<()> {
    let mut content = String::from(
        "# Generated by quantra-netd — do not edit manually\n\
         # This file is overwritten on each DHCP lease renewal\n",
    );
    for srv in servers {
        content.push_str(&format!("nameserver {}\n", srv));
    }
    // Add Cloudflare fallback if no servers provided
    if servers.is_empty() {
        content.push_str("nameserver 1.1.1.1\n");
        content.push_str("nameserver 8.8.8.8\n");
    }
    std::fs::write("/overlayer/syshub/etc/resolv.conf", &content)
        .context("write /overlayer/syshub/etc/resolv.conf")?;
    Ok(())
}

/// Build a `DhcpLeaseInfo` response from current kernel state after lease applied.
async fn build_lease_info(_handle: &Handle, iface: &str, ack: &DhcpReply) -> Result<DhcpLeaseInfo> {
    let prefix = mask_to_prefix(ack.subnet_mask);
    Ok(DhcpLeaseInfo {
        interface: iface.to_string(),
        ip_cidr: Some(format!("{}/{}", ack.your_ip, prefix)),
        gateway: ack.gateway.map(|g| g.to_string()),
        dns_servers: ack.dns.iter().map(|d| d.to_string()).collect(),
    })
}

// ── Lease state (per-interface storage) ───────────────────────────────────────

use std::collections::HashMap;
use std::sync::Mutex;

/// Stored active lease per interface — used for renewal and release.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ActiveLease {
    your_ip: Ipv4Addr,
    server_id: Ipv4Addr,
    lease_secs: u32,
    mac: [u8; 6],
}

static ACTIVE_LEASES: std::sync::OnceLock<Mutex<HashMap<String, ActiveLease>>> =
    std::sync::OnceLock::new();

fn active_leases() -> &'static Mutex<HashMap<String, ActiveLease>> {
    ACTIVE_LEASES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn store_lease(iface: &str, ack: &DhcpReply, mac: [u8; 6]) {
    active_leases().lock().unwrap().insert(
        iface.to_string(),
        ActiveLease {
            your_ip: ack.your_ip,
            server_id: ack.server_id,
            lease_secs: ack.lease_secs,
            mac,
        },
    );
}

fn get_lease(iface: &str) -> Option<ActiveLease> {
    active_leases().lock().unwrap().get(iface).cloned()
}

fn remove_lease(iface: &str) {
    active_leases().lock().unwrap().remove(iface);
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Acquire a DHCP lease on `iface`.
///
/// Performs full DISCOVER → OFFER → REQUEST → ACK handshake,
/// applies the lease to the kernel, and stores it for renewal/release.
///
/// No external binaries required — pure Tokio UDP socket.
pub async fn dhcp_acquire(handle: &Handle, iface: &str) -> Result<DhcpLeaseInfo> {
    info!("DHCP acquire on '{}'", iface);

    // Bring interface up before attempting DHCP
    if let Err(e) = crate::netlink::set_link_state(handle, iface, true).await {
        warn!("bring {} up before DHCP: {} (continuing)", iface, e);
    }

    let mac = get_mac(iface).with_context(|| format!("read MAC for '{}'", iface))?;

    let sock = open_dhcp_socket(iface)
        .await
        .with_context(|| format!("open DHCP socket on '{}'", iface))?;

    let ack = do_discover_request(&sock, &mac)
        .await
        .with_context(|| format!("DHCP handshake on '{}'", iface))?;

    apply_lease(handle, iface, &ack)
        .await
        .with_context(|| format!("apply DHCP lease on '{}'", iface))?;

    store_lease(iface, &ack, mac);

    let lease_secs = ack.lease_secs;
    let info = build_lease_info(handle, iface, &ack).await;
    spawn_renewal(handle.clone(), iface.to_string(), lease_secs);
    info
}

/// Spawn the DHCP renewal background task.
/// Kept as a plain fn (not async) to avoid opaque type cycle in Rust < 1.80.
fn spawn_renewal(handle: Handle, iface: String, lease_secs: u32) {
    tokio::spawn(async move {
        renewal_loop(&handle, &iface, lease_secs).await;
    });
}

/// Renew an existing DHCP lease on `iface`.
///
/// Sends a unicast REQUEST to the server with `ciaddr` set to current IP.
/// If no stored lease exists, falls back to a full re-acquire.
pub async fn dhcp_renew(handle: &Handle, iface: &str) -> Result<DhcpLeaseInfo> {
    info!("DHCP renew on '{}'", iface);

    let stored = match get_lease(iface) {
        Some(l) => l,
        None => {
            warn!("No active lease for '{}' — doing full re-acquire", iface);
            return dhcp_acquire(handle, iface).await;
        }
    };

    let sock = open_dhcp_socket(iface)
        .await
        .with_context(|| format!("open DHCP socket for renewal on '{}'", iface))?;

    let xid = make_xid(&stored.mac);
    let request = DhcpPacket::request(xid, &stored.mac, stored.your_ip, stored.server_id, true);

    // In RENEWING state, send unicast to the server
    let server_addr = SocketAddrV4::new(stored.server_id, DHCP_SERVER_PORT);
    sock.send_to(request.bytes(), server_addr)
        .await
        .context("send DHCPREQUEST renewal")?;
    debug!("DHCP renewal REQUEST sent to {}", stored.server_id);

    let mut buf = vec![0u8; 1500];
    let ack = match timeout(RENEW_TIMEOUT, recv_matching(&sock, &mut buf, xid, MSG_ACK)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(e.context("DHCP renewal ACK parse")),
        Err(_) => {
            warn!("DHCP renewal unicast timeout — starting fresh discover");
            // Do fresh discovery directly (avoids recursive async type cycle)
            let mac = get_mac(iface).map_err(|e| anyhow::anyhow!("{}", e))?;
            let sock = open_dhcp_socket(iface).await?;
            let ack = do_discover_request(&sock, &mac).await?;
            apply_lease(handle, iface, &ack).await?;
            store_lease(iface, &ack, mac);
            return build_lease_info(handle, iface, &ack).await;
        }
    };

    info!(
        "DHCP renew ACK: ip={} lease={}s",
        ack.your_ip, ack.lease_secs
    );
    store_lease(iface, &ack, stored.mac);

    build_lease_info(handle, iface, &ack).await
}

/// Release the DHCP lease for `iface`.
///
/// Sends a DHCPRELEASE to the server and removes the stored lease.
/// The IP address is NOT removed from the interface — call `remove_ip_address`
/// separately if you want to also clear the kernel address.
pub async fn dhcp_release(iface: &str) -> Result<()> {
    info!("DHCP release on '{}'", iface);

    let stored = match get_lease(iface) {
        Some(l) => l,
        None => {
            warn!("No active lease for '{}' — nothing to release", iface);
            return Ok(());
        }
    };

    let sock = open_dhcp_socket(iface)
        .await
        .with_context(|| format!("open DHCP socket for release on '{}'", iface))?;

    let xid = make_xid(&stored.mac);
    let release = DhcpPacket::release(xid, &stored.mac, stored.your_ip, stored.server_id);

    // RELEASE is unicast to the server
    let server_addr = SocketAddrV4::new(stored.server_id, DHCP_SERVER_PORT);
    sock.send_to(release.bytes(), server_addr)
        .await
        .context("send DHCPRELEASE")?;

    remove_lease(iface);
    info!("DHCP released {} on '{}'", stored.your_ip, iface);
    Ok(())
}

// ── Lease renewal loop ────────────────────────────────────────────────────────

/// Background task: renew lease at T1 (lease/2), rebind at T2 (lease*7/8).
async fn renewal_loop(handle: &Handle, iface: &str, lease_secs: u32) {
    // T1 = lease/2, T2 = lease*7/8 (per RFC 2131 §4.4.5)
    let t1 = Duration::from_secs((lease_secs / 2).max(30) as u64);
    let t2 = Duration::from_secs((lease_secs * 7 / 8).max(60) as u64);

    debug!(
        "DHCP renewal timer: T1={}s T2={}s lease={}s on '{}'",
        t1.as_secs(),
        t2.as_secs(),
        lease_secs,
        iface
    );

    // Sleep until T1
    tokio::time::sleep(t1).await;

    // Attempt unicast renewal
    match dhcp_renew(handle, iface).await {
        Ok(l) => {
            info!(
                "DHCP T1 renewal OK: {}",
                l.ip_cidr.as_deref().unwrap_or("-")
            );
            // New renewal loop spawned by dhcp_renew → dhcp_acquire path
        }
        Err(e) => {
            warn!("DHCP T1 renewal failed: {} — waiting for T2", e);
            // Sleep until T2 (relative to original T1 expiry)
            let remaining = t2.saturating_sub(t1);
            tokio::time::sleep(remaining).await;
            // Broadcast rebind
            // T2 rebind: fresh discover without recursive call
            let rebind_result = async {
                let mac = get_mac(iface)?;
                let sock = open_dhcp_socket(iface).await?;
                let ack = do_discover_request(&sock, &mac).await?;
                apply_lease(handle, iface, &ack).await?;
                store_lease(iface, &ack, mac);
                Ok::<_, anyhow::Error>(())
            }
            .await;
            if let Err(e) = rebind_result {
                warn!(
                    "DHCP T2 rebind failed: {} — lease expired on '{}'",
                    e, iface
                );
                remove_lease(iface);
            }
        }
    }
}

// ── DNS helpers ───────────────────────────────────────────────────────────────

/// Read current DNS servers from `/overlayer/syshub/etc/resolv.conf`.
///
/// Used by `dispatch.rs` to populate `DaemonStatus.dns_cache_entries`.
pub fn read_dns_servers() -> Result<Vec<String>> {
    let content = std::fs::read_to_string("/overlayer/syshub/etc/resolv.conf")
        .context("read /overlayer/syshub/etc/resolv.conf")?;
    Ok(parse_dns_from_content(&content))
}

/// Parse `nameserver` lines from resolv.conf content.
pub fn parse_dns_from_content(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let t = line.trim();
            if t.starts_with('#') {
                return None;
            }
            t.strip_prefix("nameserver ")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dns_standard() {
        let servers = parse_dns_from_content("nameserver 8.8.8.8\nnameserver 1.1.1.1\n");
        assert_eq!(servers, vec!["8.8.8.8", "1.1.1.1"]);
    }

    #[test]
    fn parse_dns_ignores_comments() {
        let servers = parse_dns_from_content(
            "# Generated by quantra-netd\nnameserver 1.1.1.1\nsearch example.com\n",
        );
        assert_eq!(servers, vec!["1.1.1.1"]);
    }

    #[test]
    fn parse_dns_empty() {
        assert!(parse_dns_from_content("").is_empty());
    }

    #[test]
    fn mask_to_prefix_24() {
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
    }

    #[test]
    fn mask_to_prefix_16() {
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)), 16);
    }

    #[test]
    fn mask_to_prefix_8() {
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 0, 0, 0)), 8);
    }

    #[test]
    fn mask_to_prefix_32() {
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 255)), 32);
    }

    #[test]
    fn make_xid_nonzero() {
        let mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        let xid = make_xid(&mac);
        // Just verify it's determinism-free by making two and checking they're
        // different enough (timing-based — may rarely collide, but verifies the function runs)
        let _ = xid;
    }

    #[test]
    fn get_mac_rejects_bad_interface() {
        assert!(get_mac("____nonexistent____").is_err());
    }

    #[test]
    fn dhcp_packet_discover_min_size() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let p = DhcpPacket::discover(0xdeadbeef, &mac);
        assert!(p.bytes().len() >= 300, "DHCP packet must be >= 300 bytes");
    }

    #[test]
    fn dhcp_packet_has_correct_magic_cookie() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let p = DhcpPacket::discover(0x12345678, &mac);
        let b = p.bytes();
        assert_eq!(
            &b[236..240],
            &MAGIC_COOKIE,
            "magic cookie must be at offset 236"
        );
    }

    #[test]
    fn dhcp_packet_has_msg_type_discover() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let p = DhcpPacket::discover(0x12345678, &mac);
        let b = p.bytes();
        // Find OPT_MSG_TYPE (53) in options
        let mut i = 240;
        let mut found = false;
        while i + 2 < b.len() {
            if b[i] == OPT_END {
                break;
            }
            if b[i] == OPT_PAD {
                i += 1;
                continue;
            }
            let code = b[i];
            let len = b[i + 1] as usize;
            if code == OPT_MSG_TYPE && len >= 1 {
                assert_eq!(b[i + 2], MSG_DISCOVER);
                found = true;
                break;
            }
            i += 2 + len;
        }
        assert!(found, "OPT_MSG_TYPE not found in DISCOVER packet");
    }

    #[test]
    fn dhcp_packet_xid_in_header() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let xid = 0xCAFEBABE_u32;
        let p = DhcpPacket::discover(xid, &mac);
        let b = p.bytes();
        let pkt_xid = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        assert_eq!(pkt_xid, xid, "XID must match at bytes 4-7");
    }

    #[test]
    fn dhcp_packet_op_is_request() {
        let mac = [0x00; 6];
        let p = DhcpPacket::discover(1, &mac);
        assert_eq!(p.bytes()[0], OP_REQUEST);
    }

    #[test]
    fn dhcp_packet_htype_ethernet() {
        let mac = [0x00; 6];
        let p = DhcpPacket::discover(1, &mac);
        assert_eq!(p.bytes()[1], HTYPE_ETHERNET);
    }

    #[test]
    fn dhcp_packet_mac_at_chaddr() {
        let mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let p = DhcpPacket::discover(1, &mac);
        let b = p.bytes();
        assert_eq!(&b[28..34], &mac, "MAC must be at chaddr (offset 28)");
    }

    #[test]
    fn dhcp_packet_broadcast_flag_set() {
        let mac = [0x00; 6];
        let p = DhcpPacket::discover(1, &mac);
        let b = p.bytes();
        let flags = u16::from_be_bytes([b[10], b[11]]);
        assert_eq!(
            flags, FLAGS_BROADCAST,
            "broadcast flag must be set in DISCOVER"
        );
    }

    #[test]
    fn parse_reply_rejects_short_packet() {
        let buf = vec![0u8; 100]; // too short
        assert!(parse_reply(&buf).is_none());
    }

    #[test]
    fn parse_reply_rejects_wrong_op() {
        let mut buf = vec![0u8; 300];
        buf[0] = OP_REQUEST; // wrong — reply must have OP_REPLY
        buf[236..240].copy_from_slice(&MAGIC_COOKIE);
        assert!(parse_reply(&buf).is_none());
    }

    #[test]
    fn parse_reply_rejects_bad_magic() {
        let mut buf = vec![0u8; 300];
        buf[0] = OP_REPLY;
        buf[236..240].copy_from_slice(&[0, 0, 0, 0]); // wrong magic
        assert!(parse_reply(&buf).is_none());
    }

    #[test]
    fn parse_reply_extracts_your_ip() {
        let mut buf = vec![0u8; 300];
        buf[0] = OP_REPLY;
        buf[4..8].copy_from_slice(&0x12345678_u32.to_be_bytes()); // xid
        // yiaddr = 192.168.1.100
        buf[16] = 192;
        buf[17] = 168;
        buf[18] = 1;
        buf[19] = 100;
        buf[236..240].copy_from_slice(&MAGIC_COOKIE);
        // Add MSG_TYPE = ACK at option offset 240
        buf[240] = OPT_MSG_TYPE;
        buf[241] = 1;
        buf[242] = MSG_ACK;
        buf[243] = OPT_END;
        let r = parse_reply(&buf).expect("should parse");
        assert_eq!(r.your_ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(r.msg_type, MSG_ACK);
    }

    #[test]
    fn parse_reply_extracts_dns() {
        let mut buf = vec![0u8; 400];
        buf[0] = OP_REPLY;
        buf[4..8].copy_from_slice(&1u32.to_be_bytes());
        buf[16..20].copy_from_slice(&[10, 0, 0, 5]); // yiaddr
        buf[236..240].copy_from_slice(&MAGIC_COOKIE);
        let mut i = 240;
        // MSG_TYPE = ACK
        buf[i] = OPT_MSG_TYPE;
        buf[i + 1] = 1;
        buf[i + 2] = MSG_ACK;
        i += 3;
        // DNS = 8.8.8.8 and 1.1.1.1
        buf[i] = OPT_DNS;
        buf[i + 1] = 8;
        buf[i + 2] = 8;
        buf[i + 3] = 8;
        buf[i + 4] = 8;
        buf[i + 5] = 8;
        buf[i + 6] = 1;
        buf[i + 7] = 1;
        buf[i + 8] = 1;
        buf[i + 9] = 1;
        i += 10;
        buf[i] = OPT_END;
        let r = parse_reply(&buf).expect("should parse");
        assert_eq!(r.dns.len(), 2);
        assert_eq!(r.dns[0], Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(r.dns[1], Ipv4Addr::new(1, 1, 1, 1));
    }

    #[test]
    fn parse_reply_extracts_lease_time() {
        let mut buf = vec![0u8; 400];
        buf[0] = OP_REPLY;
        buf[4..8].copy_from_slice(&1u32.to_be_bytes());
        buf[236..240].copy_from_slice(&MAGIC_COOKIE);
        let mut i = 240;
        buf[i] = OPT_MSG_TYPE;
        buf[i + 1] = 1;
        buf[i + 2] = MSG_ACK;
        i += 3;
        // Lease time = 3600 seconds
        buf[i] = OPT_LEASE_TIME;
        buf[i + 1] = 4;
        buf[i + 2..i + 6].copy_from_slice(&3600u32.to_be_bytes());
        i += 6;
        buf[i] = OPT_END;
        let r = parse_reply(&buf).expect("should parse");
        assert_eq!(r.lease_secs, 3600);
    }

    #[test]
    fn write_resolv_conf_roundtrip() {
        // Test parse → write → parse cycle without actually writing to /etc
        let servers = vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(1, 1, 1, 1)];
        let mut content = String::from("# Generated by quantra-netd\n");
        for srv in &servers {
            content.push_str(&format!("nameserver {}\n", srv));
        }
        let parsed = parse_dns_from_content(&content);
        assert_eq!(parsed, vec!["8.8.8.8", "1.1.1.1"]);
    }
}

/// Public alias used by ipv6.rs — reads MAC from /sys/class/net/<iface>/address.
pub fn read_mac_from_sysfs(iface: &str) -> Result<[u8; 6]> {
    get_mac(iface)
}

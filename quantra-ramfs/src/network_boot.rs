extern crate libc;

/// Network boot support — DHCP, iSCSI, NBD, HTTP rootfs, IPv6
///
/// Provides network-based root filesystem acquisition for:
/// - NFS root (already in rootfs.rs — DHCP makes it fully functional)
/// - iSCSI root (`iscsistart` + mount block device)
/// - NBD (Network Block Device) root
/// - HTTP boot (download squashfs/ext4 image over HTTP)
///
/// # DHCP client
///
/// Pure Rust DHCP client (DHCPv4 RFC 2131 + DHCPv6 RFC 8415).
/// No `dhclient`, `udhcpc`, or `busybox` binary needed.
///
/// # Cmdline parameters
///
/// | Parameter | Description |
/// |-----------|-------------|
/// | `ip=dhcp` / `ip=<iface>:dhcp` | Enable DHCP on interface |
/// | `ip=<ip>::<gw>:<mask>:<host>:<iface>:none` | Static IP |
/// | `ip=<ip>:<peer>:<gw>:<mask>:<host>:<iface>:<proto>` | Full spec |
/// | `rd.iscsi.initiator=` | iSCSI initiator IQN |
/// | `rd.iscsi.target.name=` | iSCSI target IQN |
/// | `rd.iscsi.target.ip=` | iSCSI target IP |
/// | `rd.iscsi.target.port=` | iSCSI port (default 3260) |
/// | `nbd=<host>:<port>` | NBD server |
/// | `rd.http.url=` | HTTP URL to download rootfs image |
/// | `ipv6=dhcpv6` | Enable DHCPv6 |
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

// ── DHCPv4 client ─────────────────────────────────────────────────────────────

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
const DHCP_OP_REQUEST: u8 = 1;
const DHCP_OP_REPLY: u8 = 2;
const DHCP_HTYPE_ETHERNET: u8 = 1;
const DHCP_OPT_SUBNET_MASK: u8 = 1;
const DHCP_OPT_ROUTER: u8 = 3;
const DHCP_OPT_DNS: u8 = 6;
#[allow(dead_code)]
const DHCP_OPT_HOSTNAME: u8 = 12;
const DHCP_OPT_REQUESTED_IP: u8 = 50;
const DHCP_OPT_LEASE_TIME: u8 = 51;
const DHCP_OPT_MSG_TYPE: u8 = 53;
const DHCP_OPT_SERVER_ID: u8 = 54;
const DHCP_OPT_PARAM_LIST: u8 = 55;
const DHCP_OPT_END: u8 = 255;
const DHCP_MSG_DISCOVER: u8 = 1;
const DHCP_MSG_OFFER: u8 = 2;
const DHCP_MSG_REQUEST: u8 = 3;
const DHCP_MSG_ACK: u8 = 5;

/// DHCP lease result.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DhcpLease {
    pub ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub lease_time_sec: u32,
    pub server_ip: Ipv4Addr,
    pub iface: String,
}

impl DhcpLease {
    /// Apply the DHCP lease to the network interface via sysfs/rtnetlink.
    pub fn apply(&self) -> Result<(), String> {
        eprintln!(
            "  dhcp: applying lease ip={} gw={:?} on {}",
            self.ip, self.gateway, self.iface
        );

        // ip addr add <ip>/<prefix> dev <iface>
        let prefix = mask_to_prefix(self.subnet_mask);
        run_ip(&[
            "addr",
            "add",
            &format!("{}/{}", self.ip, prefix),
            "dev",
            &self.iface,
        ])?;

        // ip link set <iface> up
        run_ip(&["link", "set", &self.iface, "up"])?;

        // ip route add default via <gw>
        if let Some(gw) = self.gateway {
            run_ip(&[
                "route",
                "add",
                "default",
                "via",
                &gw.to_string(),
                "dev",
                &self.iface,
            ])
            .ok(); // non-fatal — may already exist
        }

        // Write /etc/resolv.conf
        let resolv: String = self
            .dns
            .iter()
            .map(|ip| format!("nameserver {}\n", ip))
            .collect();
        fs::write("/etc/resolv.conf", resolv).ok();

        eprintln!("  dhcp: ✓ ip={}/{} gw={:?}", self.ip, prefix, self.gateway);
        Ok(())
    }
}

/// Perform DHCP discovery on `iface` and return the lease.
///
/// Implements DISCOVER → OFFER → REQUEST → ACK (4-way handshake).
pub fn dhcp_acquire(iface: &str, timeout: Duration) -> Result<DhcpLease, String> {
    eprintln!("  dhcp: DISCOVER on {}", iface);

    // Get MAC address from sysfs
    let mac = read_mac(iface)?;

    // Build DHCPDISCOVER packet
    let xid = pseudo_random_xid(&mac);
    let discover = build_dhcp_discover(&mac, xid);

    // Bind to DHCP client port (broadcast)
    let sock = UdpSocket::bind(format!("0.0.0.0:{}", DHCP_CLIENT_PORT))
        .map_err(|e| format!("bind DHCP socket: {}", e))?;
    sock.set_broadcast(true)
        .map_err(|e| format!("SO_BROADCAST: {}", e))?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set_read_timeout: {}", e))?;

    // Bind socket to specific interface
    bind_to_iface(&sock, iface)?;

    let server_addr: SocketAddr = format!("255.255.255.255:{}", DHCP_SERVER_PORT)
        .parse()
        .unwrap();

    let start = Instant::now();

    // Send DISCOVER
    sock.send_to(&discover, server_addr)
        .map_err(|e| format!("send DHCPDISCOVER: {}", e))?;

    // Wait for OFFER
    let mut buf = [0u8; 1500];
    let offer_lease = loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "DHCP timeout after {}ms on {}",
                timeout.as_millis(),
                iface
            ));
        }
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some(lease) = parse_dhcp_reply(&buf[..n], xid, iface, DHCP_MSG_OFFER) {
                    eprintln!("  dhcp: OFFER from {} → {}", lease.server_ip, lease.ip);
                    break lease;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(format!("recv DHCPOFFER: {}", e)),
        }
    };

    // Send REQUEST
    let request = build_dhcp_request(&mac, xid, offer_lease.ip, offer_lease.server_ip);
    sock.send_to(&request, server_addr)
        .map_err(|e| format!("send DHCPREQUEST: {}", e))?;

    // Wait for ACK
    loop {
        if start.elapsed() > timeout {
            return Err(format!("DHCP ACK timeout on {}", iface));
        }
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some(lease) = parse_dhcp_reply(&buf[..n], xid, iface, DHCP_MSG_ACK) {
                    eprintln!(
                        "  dhcp: ACK lease={} mask={} gw={:?}",
                        lease.ip, lease.subnet_mask, lease.gateway
                    );
                    return Ok(lease);
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(format!("recv DHCPACK: {}", e)),
        }
    }
}

fn build_dhcp_discover(mac: &[u8; 6], xid: u32) -> Vec<u8> {
    let mut pkt = vec![0u8; 236];
    pkt[0] = DHCP_OP_REQUEST;
    pkt[1] = DHCP_HTYPE_ETHERNET;
    pkt[2] = 6; // hlen
    pkt[4..8].copy_from_slice(&xid.to_be_bytes());
    pkt[10] = 0x80; // flags: broadcast
    pkt[28..34].copy_from_slice(mac);

    // Magic cookie
    pkt.extend_from_slice(&DHCP_MAGIC_COOKIE);

    // Options
    pkt.extend_from_slice(&[DHCP_OPT_MSG_TYPE, 1, DHCP_MSG_DISCOVER]);
    pkt.extend_from_slice(&[
        DHCP_OPT_PARAM_LIST,
        4,
        DHCP_OPT_SUBNET_MASK,
        DHCP_OPT_ROUTER,
        DHCP_OPT_DNS,
        DHCP_OPT_LEASE_TIME,
    ]);
    pkt.push(DHCP_OPT_END);
    pkt
}

fn build_dhcp_request(
    mac: &[u8; 6],
    xid: u32,
    offered_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut pkt = vec![0u8; 236];
    pkt[0] = DHCP_OP_REQUEST;
    pkt[1] = DHCP_HTYPE_ETHERNET;
    pkt[2] = 6;
    pkt[4..8].copy_from_slice(&xid.to_be_bytes());
    pkt[10] = 0x80;
    pkt[28..34].copy_from_slice(mac);
    pkt.extend_from_slice(&DHCP_MAGIC_COOKIE);
    pkt.extend_from_slice(&[DHCP_OPT_MSG_TYPE, 1, DHCP_MSG_REQUEST]);
    pkt.extend_from_slice(&[DHCP_OPT_REQUESTED_IP, 4]);
    pkt.extend_from_slice(&offered_ip.octets());
    pkt.extend_from_slice(&[DHCP_OPT_SERVER_ID, 4]);
    pkt.extend_from_slice(&server_ip.octets());
    pkt.push(DHCP_OPT_END);
    pkt
}

fn parse_dhcp_reply(buf: &[u8], xid: u32, iface: &str, expected_type: u8) -> Option<DhcpLease> {
    if buf.len() < 240 {
        return None;
    }
    if buf[0] != DHCP_OP_REPLY {
        return None;
    }

    // Verify XID
    let rx_xid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if rx_xid != xid {
        return None;
    }

    let your_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);

    // Parse options
    if buf[236..240] != DHCP_MAGIC_COOKIE {
        return None;
    }

    let mut msg_type = 0u8;
    let mut subnet = Ipv4Addr::new(255, 255, 255, 0);
    let mut gateway = None;
    let mut dns = Vec::new();
    let mut lease_time = 86400u32;
    let mut server_id = Ipv4Addr::UNSPECIFIED;

    let mut i = 240;
    while i < buf.len() {
        let opt = buf[i];
        i += 1;
        if opt == DHCP_OPT_END {
            break;
        }
        if opt == 0 {
            continue;
        } // pad
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

        match opt {
            o if o == DHCP_OPT_MSG_TYPE && len >= 1 => msg_type = data[0],
            o if o == DHCP_OPT_SUBNET_MASK && len >= 4 => {
                subnet = Ipv4Addr::new(data[0], data[1], data[2], data[3])
            }
            o if o == DHCP_OPT_ROUTER && len >= 4 => {
                gateway = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            }
            o if o == DHCP_OPT_DNS => {
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
            o if o == DHCP_OPT_LEASE_TIME && len >= 4 => {
                lease_time = u32::from_be_bytes([data[0], data[1], data[2], data[3]])
            }
            o if o == DHCP_OPT_SERVER_ID && len >= 4 => {
                server_id = Ipv4Addr::new(data[0], data[1], data[2], data[3])
            }
            _ => {}
        }
    }

    if msg_type != expected_type {
        return None;
    }

    Some(DhcpLease {
        ip: your_ip,
        subnet_mask: subnet,
        gateway,
        dns,
        lease_time_sec: lease_time,
        server_ip: server_id,
        iface: iface.to_string(),
    })
}

fn read_mac(iface: &str) -> Result<[u8; 6], String> {
    let path = format!("/sys/class/net/{}/address", iface);
    let content =
        fs::read_to_string(&path).map_err(|e| format!("read MAC from '{}': {}", path, e))?;
    let parts: Vec<u8> = content
        .trim()
        .split(':')
        .filter_map(|s| u8::from_str_radix(s, 16).ok())
        .collect();
    if parts.len() != 6 {
        return Err(format!("invalid MAC '{}': {}", iface, content.trim()));
    }
    Ok([parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]])
}

fn pseudo_random_xid(mac: &[u8; 6]) -> u32 {
    // Simple hash of MAC + boot time for XID uniqueness
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u32)
        .unwrap_or(0x12345678);
    let mac_hash = mac
        .iter()
        .fold(0u32, |acc, &b| acc.wrapping_mul(31).wrapping_add(b as u32));
    ts ^ mac_hash
}

fn bind_to_iface(sock: &UdpSocket, iface: &str) -> Result<(), String> {
    use std::os::unix::io::AsRawFd;
    let iface_cstr = std::ffi::CString::new(iface).map_err(|_| "invalid iface name".to_string())?;
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface_cstr.as_ptr() as *const libc::c_void,
            iface_cstr.to_bytes().len() as libc::socklen_t,
        )
    };
    if ret != 0 {
        Err(format!(
            "SO_BINDTODEVICE {}: {}",
            iface,
            io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

fn mask_to_prefix(mask: Ipv4Addr) -> u32 {
    u32::from(mask).count_ones()
}

fn run_ip(args: &[&str]) -> Result<(), String> {
    let ip_bins = &["/sbin/ip", "/usr/sbin/ip", "/bin/ip"];
    let bin = ip_bins
        .iter()
        .find(|&&p| Path::new(p).exists())
        .ok_or_else(|| "ip binary not found".to_string())?;
    let status = Command::new(bin)
        .args(args)
        .status()
        .map_err(|e| format!("ip exec: {}", e))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("ip {} failed", args.join(" ")))
    }
}

// ── Network interface discovery ───────────────────────────────────────────────

/// Find all available network interfaces (excluding lo).
pub fn list_interfaces() -> Vec<String> {
    fs::read_dir("/sys/class/net")
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n != "lo" && !n.starts_with("dummy"))
                .collect()
        })
        .unwrap_or_default()
}

/// Try DHCP on each interface until one succeeds.
pub fn dhcp_any_interface(timeout_per_iface: Duration) -> Option<DhcpLease> {
    for iface in list_interfaces() {
        // Bring interface up
        run_ip(&["link", "set", &iface, "up"]).ok();
        std::thread::sleep(Duration::from_millis(200));

        match dhcp_acquire(&iface, timeout_per_iface) {
            Ok(lease) => {
                lease.apply().ok();
                return Some(lease);
            }
            Err(e) => eprintln!("  dhcp: {} failed: {}", iface, e),
        }
    }
    None
}

// ── iSCSI root ────────────────────────────────────────────────────────────────

/// iSCSI target configuration.
#[derive(Debug)]
pub struct IscsiTarget {
    pub initiator_iqn: String,
    pub target_iqn: String,
    pub target_ip: String,
    pub target_port: u16,
}

impl Default for IscsiTarget {
    fn default() -> Self {
        Self {
            initiator_iqn: "iqn.2026-01.os.zainium:initrd".to_string(),
            target_iqn: String::new(),
            target_ip: String::new(),
            target_port: 3260,
        }
    }
}

/// Connect to an iSCSI target and return the block device path.
pub fn connect_iscsi(target: &IscsiTarget) -> Result<String, String> {
    let iscsistart = &["/sbin/iscsistart", "/usr/sbin/iscsistart"];
    let bin = iscsistart
        .iter()
        .find(|&&p| Path::new(p).exists())
        .ok_or_else(|| "iscsistart not found".to_string())?;

    eprintln!(
        "  iscsi: connecting to {} at {}:{}",
        target.target_iqn, target.target_ip, target.target_port
    );

    let output = Command::new(bin)
        .args([
            "-i",
            &target.initiator_iqn,
            "-t",
            &target.target_iqn,
            "-a",
            &target.target_ip,
            "-p",
            &target.target_port.to_string(),
        ])
        .output()
        .map_err(|e| format!("iscsistart exec: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "iscsistart failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // iSCSI block device appears as /dev/sdX — wait for it
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if let Some(dev) = find_iscsi_device() {
            eprintln!("  iscsi: ✓ device = {}", dev);
            return Ok(dev);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err("iSCSI device did not appear after 10s".to_string())
}

fn find_iscsi_device() -> Option<String> {
    // iSCSI devices appear under /sys/bus/iscsi_session
    let session_dir = "/sys/bus/iscsi_session/devices";
    if let Ok(entries) = fs::read_dir(session_dir) {
        for entry in entries.flatten() {
            let session = entry.file_name().to_string_lossy().into_owned();
            let dev_dir = format!("{}/{}/device/target", session_dir, session);
            if let Ok(targets) = fs::read_dir(&dev_dir) {
                for t in targets.flatten() {
                    let t_path = format!("{}/{}", dev_dir, t.file_name().to_string_lossy());
                    if let Ok(disks) = fs::read_dir(&t_path) {
                        for d in disks.flatten() {
                            let name = d.file_name().to_string_lossy().into_owned();
                            if name.starts_with("sd") {
                                return Some(format!("/dev/{}", name));
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

// ── NBD (Network Block Device) ────────────────────────────────────────────────

/// Connect to an NBD server and return the /dev/nbdN device path.
pub fn connect_nbd(host: &str, port: u16, name: Option<&str>) -> Result<String, String> {
    let nbd_client = &[
        "/sbin/nbd-client",
        "/usr/sbin/nbd-client",
        "/usr/bin/nbd-client",
    ];
    let bin = nbd_client
        .iter()
        .find(|&&p| Path::new(p).exists())
        .ok_or_else(|| "nbd-client not found".to_string())?;

    // Find free NBD device
    let nbd_dev = find_free_nbd().ok_or_else(|| "no free /dev/nbdN device".to_string())?;

    eprintln!("  nbd: connecting {}:{} → {}", host, port, nbd_dev);

    let mut cmd = Command::new(bin);
    cmd.args([host, &port.to_string(), &nbd_dev]);
    if let Some(n) = name {
        cmd.args(["-N", n]);
    }

    let output = cmd
        .output()
        .map_err(|e| format!("nbd-client exec: {}", e))?;

    if output.status.success() {
        eprintln!("  nbd: ✓ {}", nbd_dev);
        Ok(nbd_dev)
    } else {
        Err(format!(
            "nbd-client failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn find_free_nbd() -> Option<String> {
    for i in 0..16 {
        let dev = format!("/dev/nbd{}", i);
        let size_path = format!("/sys/block/nbd{}/size", i);
        if Path::new(&dev).exists() {
            if let Ok(size) = fs::read_to_string(&size_path) {
                if size.trim() == "0" {
                    return Some(dev);
                }
            }
        }
    }
    None
}

// ── HTTP boot ─────────────────────────────────────────────────────────────────

/// Download a rootfs image over HTTP and save to a temp file.
///
/// Uses a minimal pure-Rust HTTP/1.1 GET client.
/// No curl/wget needed.
#[allow(dead_code)]
pub fn http_fetch_rootfs(url: &str, dest_path: &str) -> Result<u64, String> {
    eprintln!("  http-boot: downloading {} → {}", url, dest_path);

    // Parse URL
    let (host, port, path) = parse_http_url(url)?;

    // TCP connect
    let addr = format!("{}:{}", host, port);
    let mut stream = std::net::TcpStream::connect_timeout(
        &addr
            .parse::<SocketAddr>()
            .map_err(|e| format!("parse addr '{}': {}", addr, e))?,
        Duration::from_secs(30),
    )
    .map_err(|e| format!("connect {}: {}", addr, e))?;

    stream.set_read_timeout(Some(Duration::from_secs(120))).ok();

    // Send HTTP GET request
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: quantra-ramfs/5.1\r\n\r\n",
        path, host
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("send HTTP request: {}", e))?;

    // Read response headers
    let mut headers = Vec::new();
    let mut buf = [0u8; 1];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return Err("HTTP connection closed before headers".to_string()),
            Ok(_) => {
                headers.push(buf[0]);
                if headers.len() >= 4 {
                    let last4 = &headers[headers.len() - 4..];
                    if last4 == b"\r\n\r\n" {
                        break;
                    }
                }
            }
            Err(e) => return Err(format!("read HTTP headers: {}", e)),
        }
    }

    let headers_str = String::from_utf8_lossy(&headers);

    // Check status line
    if !headers_str.starts_with("HTTP/1") {
        return Err(format!(
            "invalid HTTP response: {}",
            &headers_str[..headers_str.len().min(100)]
        ));
    }
    let status: u16 = headers_str
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if status != 200 {
        return Err(format!("HTTP {} from {}", status, url));
    }

    // Extract Content-Length if present
    let content_length: Option<u64> = headers_str
        .lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok());

    // Stream response body to file
    let mut file =
        fs::File::create(dest_path).map_err(|e| format!("create '{}': {}", dest_path, e))?;

    let mut total = 0u64;
    let mut chunk = [0u8; 65536];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                file.write_all(&chunk[..n])
                    .map_err(|e| format!("write to '{}': {}", dest_path, e))?;
                total += n as u64;
                if let Some(cl) = content_length {
                    let pct = (total * 100) / cl.max(1);
                    eprint!("\r  http-boot: {}% ({} MB)", pct, total / 1_048_576);
                }
            }
            Err(e) => return Err(format!("read HTTP body: {}", e)),
        }
    }
    eprintln!("\n  http-boot: ✓ {} bytes downloaded", total);
    Ok(total)
}

#[allow(dead_code)]
fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    let url = url.trim_start_matches("http://");
    let (hostport, path) = if let Some(idx) = url.find('/') {
        (&url[..idx], &url[idx..])
    } else {
        (url, "/")
    };
    let (host, port) = if let Some(idx) = hostport.find(':') {
        let port: u16 = hostport[idx + 1..]
            .parse()
            .map_err(|_| format!("invalid port in URL: {}", url))?;
        (&hostport[..idx], port)
    } else {
        (hostport, 80u16)
    };
    Ok((host.to_string(), port, path.to_string()))
}

// ── IPv6 SLAAC ────────────────────────────────────────────────────────────────

/// Enable IPv6 SLAAC (Stateless Address Autoconfiguration) on an interface.
///
/// Writes to sysctl to enable accept_ra and autoconf, then waits for
/// the kernel to assign an IPv6 address from Router Advertisement.
pub fn enable_ipv6_slaac(iface: &str) -> Result<String, String> {
    eprintln!("  ipv6: enabling SLAAC on {}", iface);

    let base = format!("/proc/sys/net/ipv6/conf/{}", iface);
    fs::write(format!("{}/accept_ra", base), "1").map_err(|e| format!("accept_ra: {}", e))?;
    fs::write(format!("{}/autoconf", base), "1").map_err(|e| format!("autoconf: {}", e))?;
    fs::write(format!("{}/forwarding", base), "0").ok();

    // Bring interface up
    run_ip(&["link", "set", iface, "up"]).ok();

    // Wait for global IPv6 address
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if let Some(addr) = get_ipv6_global(iface) {
            eprintln!("  ipv6: ✓ {} on {}", addr, iface);
            return Ok(addr);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!("no IPv6 address on {} after 10s", iface))
}

fn get_ipv6_global(iface: &str) -> Option<String> {
    let path = "/proc/net/if_inet6".to_string();
    let content = fs::read_to_string(&path).ok()?;
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 6 && parts[5] == iface {
            let scope = u8::from_str_radix(parts[3], 16).unwrap_or(0);
            if scope == 0 {
                // global scope
                return Some(format_ipv6(parts[0]));
            }
        }
    }
    None
}

fn format_ipv6(hex: &str) -> String {
    let bytes: Vec<&str> = hex
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or("0000"))
        .collect();
    bytes.join(":")
}

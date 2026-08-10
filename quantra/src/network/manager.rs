/// Network interface configuration manager
///
/// Configures network interfaces at boot using raw socket ioctls (no ip binary
/// dependency). Supports static IP assignment and spawning DHCP client daemons.
///
/// # Config format (`/overlayer/syshub/etc/quantra-system/network.toml`)
///
/// ```toml
/// [network]
/// hostname = "zainium-1"
///
/// [[network.interface]]
/// name = "eth0"
/// method = "dhcp"
/// dhcp_client = "/overlayer/syshub/sbin/udhcpc"   # optional, defaults to udhcpc
///
/// [[network.interface]]
/// name = "eth1"
/// method = "static"
/// address = "192.168.1.100/24"
/// gateway = "192.168.1.1"
/// dns = ["8.8.8.8", "1.1.1.1"]
/// ```
///
/// # Implementation
///
/// Static configuration uses `SIOCSIFADDR`, `SIOCSIFNETMASK`, `SIOCSIFFLAGS`
/// ioctls via a raw AF_INET socket — no dependency on `ip(8)` or `ifconfig(8)`.
///
/// DHCP: spawns the configured client (or `udhcpc`) as a supervised child process.
/// The DHCP client is NOT supervised for restart — it is expected to run its own
/// daemon mode (`-b` flag on udhcpc).
use anyhow::{Context, Result};
use log::{error, info, warn};
use serde::Deserialize;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;

const DEFAULT_DHCP_CLIENT: &str = "/overlayer/syshub/sbin/udhcpc";
const RESOLV_CONF_PATH: &str = "/overlayer/syshub/etc/resolv.conf";
const NETWORK_CONFIG_PATH: &str = "/overlayer/syshub/etc/quantra-system/network.toml";

// ── Config types ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    #[allow(dead_code)]
    pub hostname: Option<String>,
    #[serde(default, rename = "interface")]
    pub interfaces: Vec<InterfaceConfig>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct InterfaceConfig {
    pub name: String,
    pub method: ConfigMethod,
    /// Static only: CIDR address e.g. "192.168.1.100/24"
    pub address: Option<String>,
    /// Static only: default gateway
    pub gateway: Option<String>,
    /// Static only: DNS server list
    #[serde(default)]
    pub dns: Vec<String>,
    /// DHCP only: path to dhcp client binary
    pub dhcp_client: Option<String>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ConfigMethod {
    Static,
    Dhcp,
    #[serde(rename = "loopback")]
    Loopback,
}

// ── Manager ───────────────────────────────────────────────────────────────────

/// Load and apply network configuration from `/overlayer/syshub/etc/quantra-system/network.toml`.
///
/// Non-fatal: if the config file doesn't exist, only the loopback interface
/// is brought up (required for localhost and Unix socket communication).
pub fn configure_all() -> Result<()> {
    info!("Configuring network interfaces");

    // Always bring up loopback first
    if let Err(e) = bring_interface_up("lo") {
        warn!("Could not bring up loopback: {} (continuing)", e);
    } else {
        info!("Loopback (lo) is up");
    }

    // Load config — non-fatal if missing
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            warn!("Network config not found ({}): only loopback configured", e);
            return Ok(());
        }
    };

    for iface in &cfg.interfaces {
        if let Err(e) = configure_interface(iface) {
            error!("Failed to configure '{}': {} (continuing)", iface.name, e);
        }
    }

    Ok(())
}

fn load_config() -> Result<NetworkConfig> {
    let text = fs::read_to_string(NETWORK_CONFIG_PATH)
        .with_context(|| format!("Cannot read '{}'", NETWORK_CONFIG_PATH))?;

    toml::from_str::<NetworkConfig>(&text).context("Invalid network configuration TOML")
}

fn configure_interface(iface: &InterfaceConfig) -> Result<()> {
    info!(
        "Configuring interface '{}' (method={:?})",
        iface.name, iface.method
    );

    match iface.method {
        ConfigMethod::Loopback => {
            bring_interface_up(&iface.name)?;
        }

        ConfigMethod::Static => {
            let addr_cidr = iface.address.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "Interface '{}': static method requires 'address'",
                    iface.name
                )
            })?;

            let (ip, prefix_len) = parse_cidr(addr_cidr)
                .with_context(|| format!("Invalid CIDR address '{}'", addr_cidr))?;

            bring_interface_up(&iface.name)?;
            assign_ipv4_address(&iface.name, ip, prefix_len)?;

            if let Some(ref gw) = iface.gateway {
                let gw_ip = gw
                    .parse::<Ipv4Addr>()
                    .with_context(|| format!("Invalid gateway '{}'", gw))?;
                add_default_route(&iface.name, gw_ip)?;
            }

            if !iface.dns.is_empty() {
                write_resolv_conf(&iface.dns)?;
            }

            info!("Interface '{}' configured: {}", iface.name, addr_cidr);
        }

        ConfigMethod::Dhcp => {
            bring_interface_up(&iface.name)?;

            let client = iface.dhcp_client.as_deref().unwrap_or(DEFAULT_DHCP_CLIENT);
            spawn_dhcp_client(client, &iface.name)?;

            info!(
                "Interface '{}' DHCP client spawned ({})",
                iface.name, client
            );
        }
    }

    Ok(())
}

// ── Low-level interface operations ────────────────────────────────────────────

/// Bring a network interface up using `SIOCSIFFLAGS` ioctl.
fn bring_interface_up(name: &str) -> Result<()> {
    // Create raw socket for ioctls
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(anyhow::anyhow!(
            "socket() failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let _guard = SocketGuard(sock);

    let mut ifreq = make_ifreq(name)?;

    // Get current flags
    let ret = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as libc::c_ulong, &mut ifreq) };
    if ret < 0 {
        return Err(anyhow::anyhow!(
            "SIOCGIFFLAGS for '{}': {}",
            name,
            std::io::Error::last_os_error()
        ));
    }

    // Set IFF_UP flag
    unsafe {
        ifreq.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
    }

    let ret = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as libc::c_ulong, &mut ifreq) };
    if ret < 0 {
        return Err(anyhow::anyhow!(
            "SIOCSIFFLAGS for '{}': {}",
            name,
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// Assign an IPv4 address to interface `name` using `SIOCSIFADDR` + `SIOCSIFNETMASK`.
fn assign_ipv4_address(name: &str, ip: Ipv4Addr, prefix_len: u8) -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(anyhow::anyhow!(
            "socket() failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let _guard = SocketGuard(sock);

    // Set IP address
    let mut ifreq = make_ifreq(name)?;
    set_sockaddr_in(&mut ifreq, ip);
    let ret = unsafe { libc::ioctl(sock, libc::SIOCSIFADDR as libc::c_ulong, &mut ifreq) };
    if ret < 0 {
        return Err(anyhow::anyhow!(
            "SIOCSIFADDR for '{}': {}",
            name,
            std::io::Error::last_os_error()
        ));
    }

    // Set netmask
    let mask = prefix_to_mask(prefix_len);
    let mut ifreq2 = make_ifreq(name)?;
    set_sockaddr_in(&mut ifreq2, mask);
    let ret = unsafe { libc::ioctl(sock, libc::SIOCSIFNETMASK as libc::c_ulong, &mut ifreq2) };
    if ret < 0 {
        return Err(anyhow::anyhow!(
            "SIOCSIFNETMASK for '{}': {}",
            name,
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// Add a default route using `SIOCADDRT` ioctl.
fn add_default_route(iface_name: &str, gateway: Ipv4Addr) -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(anyhow::anyhow!(
            "socket() failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let _guard = SocketGuard(sock);

    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };

    // Destination: 0.0.0.0 (default route)
    set_rtentry_addr(&mut rt.rt_dst, Ipv4Addr::UNSPECIFIED);
    // Gateway
    set_rtentry_addr(&mut rt.rt_gateway, gateway);
    // Mask: 0.0.0.0 (matches all)
    set_rtentry_addr(&mut rt.rt_genmask, Ipv4Addr::UNSPECIFIED);
    rt.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;

    // Set interface name
    let name_bytes = iface_name.as_bytes();
    let max = std::cmp::min(name_bytes.len(), libc::IF_NAMESIZE - 1);
    // rt_dev is a *mut i8 pointing to the device name string
    let mut dev_name = [0i8; libc::IF_NAMESIZE];
    for (i, &b) in name_bytes[..max].iter().enumerate() {
        dev_name[i] = b as i8;
    }
    rt.rt_dev = dev_name.as_mut_ptr();

    let ret = unsafe { libc::ioctl(sock, libc::SIOCADDRT as libc::c_ulong, &rt) };
    if ret < 0 {
        return Err(anyhow::anyhow!(
            "SIOCADDRT (default route via {}) failed: {}",
            gateway,
            std::io::Error::last_os_error()
        ));
    }

    info!("Default route via {} added ({})", gateway, iface_name);
    Ok(())
}

/// Write DNS servers to `/etc/resolv.conf`.
fn write_resolv_conf(servers: &[String]) -> Result<()> {
    let mut content = String::from("# Generated by ZainiumOS Quantra-System\n");
    for server in servers {
        content.push_str(&format!("nameserver {}\n", server));
    }
    fs::write(RESOLV_CONF_PATH, content).context("Cannot write /etc/resolv.conf")?;
    info!("DNS configured: {} server(s)", servers.len());
    Ok(())
}

/// Spawn a DHCP client for `iface_name` as a background process.
fn spawn_dhcp_client(client_path: &str, iface_name: &str) -> Result<()> {
    if !Path::new(client_path).exists() {
        warn!(
            "DHCP client '{}' not found — skipping DHCP for '{}'",
            client_path, iface_name
        );
        return Ok(());
    }

    crate::process::start_service(client_path, &["-i", iface_name, "-b", "-q"]).with_context(
        || {
            format!(
                "Cannot spawn DHCP client '{}' for '{}'",
                client_path, iface_name
            )
        },
    )?;

    Ok(())
}

// ── ioctl helpers ─────────────────────────────────────────────────────────────

/// Create a zeroed `ifreq` with the interface name filled in.
fn make_ifreq(name: &str) -> Result<libc::ifreq> {
    let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
    let bytes = name.as_bytes();
    if bytes.len() >= libc::IFNAMSIZ {
        return Err(anyhow::anyhow!(
            "Interface name '{}' too long (max {} chars)",
            name,
            libc::IFNAMSIZ - 1
        ));
    }
    for (i, &b) in bytes.iter().enumerate() {
        ifreq.ifr_name[i] = b as std::os::raw::c_char;
    }
    Ok(ifreq)
}

/// Fill the sockaddr_in part of an `ifreq` with an IPv4 address.
fn set_sockaddr_in(ifreq: &mut libc::ifreq, ip: Ipv4Addr) {
    let octets = ip.octets();
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes(octets).to_be(),
        },
        sin_zero: [0u8; 8],
    };
    unsafe {
        let ptr = &mut ifreq.ifr_ifru.ifru_addr as *mut libc::sockaddr;
        *(ptr as *mut libc::sockaddr_in) = addr;
    }
}

/// Fill a sockaddr in an `rtentry` with an IPv4 address.
fn set_rtentry_addr(sa: &mut libc::sockaddr, ip: Ipv4Addr) {
    let octets = ip.octets();
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes(octets).to_be(),
        },
        sin_zero: [0u8; 8],
    };
    unsafe {
        *(sa as *mut libc::sockaddr as *mut libc::sockaddr_in) = addr;
    }
}

/// Convert CIDR prefix length to IPv4 netmask.
fn prefix_to_mask(prefix: u8) -> Ipv4Addr {
    let bits = if prefix == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(bits)
}

/// Parse "192.168.1.100/24" → (Ipv4Addr, prefix_len).
fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8)> {
    let mut parts = cidr.splitn(2, '/');
    let ip_str = parts.next().ok_or_else(|| anyhow::anyhow!("Empty CIDR"))?;
    let prefix = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("Missing prefix length in '{}'", cidr))?;
    let ip = Ipv4Addr::from_str(ip_str).with_context(|| format!("Invalid IP '{}'", ip_str))?;
    let prefix = prefix
        .parse::<u8>()
        .with_context(|| format!("Invalid prefix '{}'", prefix))?;
    if prefix > 32 {
        return Err(anyhow::anyhow!("Prefix length {} > 32", prefix));
    }
    Ok((ip, prefix))
}

/// RAII guard to close a raw socket on drop.
struct SocketGuard(libc::c_int);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cidr_standard_24() {
        let (ip, prefix) = parse_cidr("192.168.1.100/24").unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn parse_cidr_host_32() {
        let (ip, prefix) = parse_cidr("10.0.0.1/32").unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(prefix, 32);
    }

    #[test]
    fn parse_cidr_rejects_prefix_over_32() {
        assert!(parse_cidr("10.0.0.1/33").is_err());
    }

    #[test]
    fn parse_cidr_rejects_missing_prefix() {
        assert!(parse_cidr("10.0.0.1").is_err());
    }

    #[test]
    fn parse_cidr_rejects_invalid_ip() {
        assert!(parse_cidr("999.0.0.1/24").is_err());
    }

    #[test]
    fn prefix_to_mask_24_is_255_255_255_0() {
        assert_eq!(prefix_to_mask(24), Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn prefix_to_mask_32_is_all_ones() {
        assert_eq!(prefix_to_mask(32), Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn prefix_to_mask_0_is_all_zeros() {
        assert_eq!(prefix_to_mask(0), Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn prefix_to_mask_16_is_255_255_0_0() {
        assert_eq!(prefix_to_mask(16), Ipv4Addr::new(255, 255, 0, 0));
    }

    #[test]
    fn prefix_to_mask_8_is_255_0_0_0() {
        assert_eq!(prefix_to_mask(8), Ipv4Addr::new(255, 0, 0, 0));
    }
}

//! Netlink operations — link enumeration, IP management, interface state.

use anyhow::{Context, Result};
use common::{InterfaceDetail, InterfaceInfo, InterfaceStats, LinkState, WirelessInfo};
use futures::TryStreamExt;
use netlink_packet_route::{address::nlas::Nla as AddressNla, link::nlas::Nla};
use once_cell::sync::Lazy;
use rtnetlink::Handle;
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::Mutex;
use std::time::Instant;
use tokio::process::Command;
use tracing::debug;

const IFF_UP: u32 = 0x0001;

static PREV_LINK_STATS: Lazy<Mutex<HashMap<String, (InterfaceStats, Instant)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub async fn get_all_links(handle: &Handle) -> Result<Vec<InterfaceInfo>> {
    let mut link_stream = handle.link().get().execute();
    let mut interfaces: Vec<InterfaceInfo> = Vec::new();

    while let Some(link) = link_stream
        .try_next()
        .await
        .context("rtnetlink: failed to iterate links")?
    {
        let index = link.header.index;
        let flags_raw: u32 = link.header.flags;
        let is_up = (flags_raw & IFF_UP) != 0;

        let mut name: Option<String> = None;
        let mut mac = String::from("N/A");

        for attr in &link.nlas {
            match attr {
                Nla::IfName(iface_name) => {
                    name = Some(iface_name.clone());
                }
                Nla::Address(bytes) if bytes.len() == 6 => {
                    mac = format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
                    );
                }
                _ => {}
            }
        }

        if let Some(name) = name {
            let ip_addresses = get_interface_addresses(handle, index).await?;
            let statistics = parse_interface_stats(&link.nlas);

            let mut speed_mbps = None;
            let now = Instant::now();
            if let Some(stats) = &statistics {
                let mut map = PREV_LINK_STATS.lock().unwrap();
                if let Some((prev_stats, prev_time)) = map.get(&name) {
                    let dt = now.duration_since(*prev_time).as_secs_f64();
                    if dt > 0.0 {
                        let tx_delta = (stats.tx_bytes.saturating_sub(prev_stats.tx_bytes)) as f64;
                        let rx_delta = (stats.rx_bytes.saturating_sub(prev_stats.rx_bytes)) as f64;
                        let total_bits = (tx_delta + rx_delta) * 8.0;
                        speed_mbps = Some((total_bits / dt) / 1_000_000.0);
                    }
                }
                map.insert(name.clone(), (stats.clone(), now));
            }

            interfaces.push(InterfaceInfo {
                index,
                name,
                mac,
                state: if is_up {
                    LinkState::Up
                } else {
                    LinkState::Down
                },
                ip_addresses,
                statistics,
                speed_mbps,
            });
        }
    }

    interfaces.sort_by_key(|i| i.index);
    debug!("Enumerated {} interface(s)", interfaces.len());
    Ok(interfaces)
}

pub async fn get_interface_detail(handle: &Handle, name: &str) -> Result<Option<InterfaceDetail>> {
    let mut link_stream = handle.link().get().execute();

    while let Some(link) = link_stream
        .try_next()
        .await
        .context("rtnetlink: failed to iterate links")?
    {
        let mut iface_name: Option<String> = None;

        for attr in &link.nlas {
            if let Nla::IfName(n) = attr {
                iface_name = Some(n.clone());
                break;
            }
        }

        if let Some(iface_name) = iface_name
            && iface_name == name
        {
            let index = link.header.index;
            let flags_raw: u32 = link.header.flags;
            let is_up = (flags_raw & IFF_UP) != 0;

            let mut mac = String::from("N/A");
            let mut mtu = None;
            let mut iface_type = None;
            let mut qdisc = None;
            let mut group = None;
            let mut flags_list = Vec::new();

            for attr in &link.nlas {
                match attr {
                    Nla::Address(bytes) if bytes.len() == 6 => {
                        mac = format!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
                        );
                    }
                    Nla::Mtu(mtu_val) => mtu = Some(*mtu_val),
                    Nla::Link(n) => {
                        iface_type = match n {
                            1 => Some("Ethernet".to_string()),
                            772 => Some("Loopback".to_string()),
                            801 => Some("Wireless".to_string()),
                            _ => Some(format!("Type {}", n)),
                        };
                    }
                    Nla::Qdisc(q) => qdisc = Some(q.clone()),
                    Nla::Group(g) => group = Some(*g),
                    _ => {}
                }
            }

            // Parse flags
            let flag_names = [
                (0x0001, "UP"),
                (0x0002, "BROADCAST"),
                (0x0004, "DEBUG"),
                (0x0008, "LOOPBACK"),
                (0x0010, "POINTOPOINT"),
                (0x0020, "NOTRAILERS"),
                (0x0040, "RUNNING"),
                (0x0080, "NOARP"),
                (0x0100, "PROMISC"),
                (0x0200, "ALLMULTI"),
                (0x0400, "MASTER"),
                (0x0800, "SLAVE"),
                (0x1000, "MULTICAST"),
                (0x2000, "PORTSEL"),
                (0x4000, "AUTOMEDIA"),
                (0x8000, "DYNAMIC"),
            ];
            for (bit, label) in &flag_names {
                if flags_raw & bit != 0 {
                    flags_list.push(label.to_string());
                }
            }

            let ip_addresses = get_interface_addresses(handle, index).await?;
            let statistics = parse_interface_stats(&link.nlas);
            let wireless = if iface_type == Some("Wireless".to_string()) {
                get_wireless_info(handle, name).await?
            } else {
                None
            };

            return Ok(Some(InterfaceDetail {
                index,
                name: name.to_string(),
                mac,
                state: if is_up {
                    LinkState::Up
                } else {
                    LinkState::Down
                },
                ip_addresses,
                mtu,
                iface_type,
                statistics,
                wireless,
                flags: flags_list,
                qdisc,
                group,
            }));
        }
    }

    Ok(None)
}

pub async fn get_interface_addresses(handle: &Handle, index: u32) -> Result<Vec<String>> {
    let mut addr_stream = handle.address().get().execute();
    let mut addresses = Vec::new();

    while let Some(addr) = addr_stream
        .try_next()
        .await
        .context("rtnetlink: failed to iterate addresses")?
    {
        if addr.header.index == index {
            for attr in &addr.nlas {
                if let AddressNla::Address(bytes) = attr {
                    if bytes.len() == 4 {
                        let ip = format!(
                            "{}.{}.{}.{}/{}",
                            bytes[0], bytes[1], bytes[2], bytes[3], addr.header.prefix_len
                        );
                        addresses.push(ip);
                    } else if bytes.len() == 16 {
                        let ip = format!(
                            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}/{}",
                            bytes[0],
                            bytes[1],
                            bytes[2],
                            bytes[3],
                            bytes[4],
                            bytes[5],
                            bytes[6],
                            bytes[7],
                            bytes[8],
                            bytes[9],
                            bytes[10],
                            bytes[11],
                            bytes[12],
                            bytes[13],
                            bytes[14],
                            bytes[15],
                            addr.header.prefix_len
                        );
                        addresses.push(ip);
                    }
                }
            }
        }
    }

    Ok(addresses)
}

pub fn parse_interface_stats(nlas: &[Nla]) -> Option<InterfaceStats> {
    for attr in nlas {
        if let Nla::Stats64(bytes) = attr {
            if bytes.len() < 64 {
                return None;
            }
            let read64 = |offset: usize| -> Option<u64> {
                let end = offset + 8;
                let slice = bytes.get(offset..end)?;
                let arr: [u8; 8] = slice.try_into().ok()?;
                Some(u64::from_le_bytes(arr))
            };

            return Some(InterfaceStats {
                rx_packets: read64(0)?,
                tx_packets: read64(8)?,
                rx_bytes: read64(16)?,
                tx_bytes: read64(24)?,
                rx_errors: read64(32)?,
                tx_errors: read64(40)?,
                rx_dropped: read64(48)?,
                tx_dropped: read64(56)?,
            });
        }
    }
    None
}

pub async fn get_wireless_info(_handle: &Handle, name: &str) -> Result<Option<WirelessInfo>> {
    let output = Command::new("iw")
        .args(["dev", name, "link"])
        .output()
        .await;
    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Ok(None),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    if text.contains("Not connected") {
        return Ok(None);
    }

    let mut ssid = String::from("Unknown");
    let mut signal_strength: i32 = -100;
    let mut frequency: f32 = 0.0;
    let mut _bitrate: u32 = 0;

    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("SSID: ") {
            ssid = rest.to_string();
        } else if let Some(rest) = t.strip_prefix("signal: ") {
            if let Some(v) = rest
                .split_whitespace()
                .next()
                .and_then(|x| x.parse::<f32>().ok())
            {
                signal_strength = v as i32;
            }
        } else if let Some(rest) = t.strip_prefix("freq: ") {
            if let Ok(f) = rest.trim().parse::<f32>() {
                frequency = f / 1000.0;
            }
        } else if let Some(rest) = t.strip_prefix("tx bitrate: ")
            && let Some(v) = rest
                .split_whitespace()
                .next()
                .and_then(|x| x.parse::<f32>().ok())
        {
            _bitrate = v as u32;
        }
    }

    let channel = if (2.0..3.0).contains(&frequency) {
        let mhz = (frequency * 1000.0) as u32;
        if mhz <= 2484 {
            ((mhz - 2407) / 5).max(1)
        } else {
            14
        }
    } else if frequency >= 5.0 {
        let mhz = (frequency * 1000.0) as u32;
        (mhz - 5000) / 5
    } else {
        0
    };

    let quality = ((signal_strength + 90).max(0).min(60) as u32 * 100) / 60;

    Ok(Some(WirelessInfo {
        ssid,
        signal_strength,
        frequency,
        channel,
        quality,
    }))
}

pub async fn find_link_index(handle: &Handle, name: &str) -> Result<Option<u32>> {
    let mut link_stream = handle.link().get().execute();

    while let Some(link) = link_stream
        .try_next()
        .await
        .context("rtnetlink: failed to iterate links")?
    {
        for attr in &link.nlas {
            if let Nla::IfName(iface_name) = attr
                && iface_name == name
            {
                return Ok(Some(link.header.index));
            }
        }
    }

    Ok(None)
}

pub async fn set_link_state(handle: &Handle, name: &str, up: bool) -> Result<()> {
    let index = find_link_index(handle, name)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Interface '{}' not found", name))?;

    let request = handle.link().set(index);

    if up {
        request
            .up()
            .execute()
            .await
            .with_context(|| format!("rtnetlink: failed to bring '{}' up", name))?;
    } else {
        request
            .down()
            .execute()
            .await
            .with_context(|| format!("rtnetlink: failed to bring '{}' down", name))?;
    }

    tracing::info!(interface = name, up, "Link state changed");
    Ok(())
}

pub async fn add_ip_address(handle: &Handle, name: &str, ip_cidr: &str) -> Result<()> {
    let index = find_link_index(handle, name)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Interface '{}' not found", name))?;

    let parts: Vec<&str> = ip_cidr.split('/').collect();
    let ip_str = parts[0];
    let prefix: u8 = parts[1].parse()?;

    let ip: std::net::IpAddr = ip_str.parse()?;

    handle
        .address()
        .add(index, ip, prefix)
        .execute()
        .await
        .with_context(|| format!("Failed to add IP address {} to {}", ip_cidr, name))?;

    tracing::info!(interface = name, ip = ip_cidr, "IP address added");
    Ok(())
}

pub async fn remove_ip_address(handle: &Handle, name: &str, ip_cidr: &str) -> Result<()> {
    let _index = find_link_index(handle, name)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Interface '{}' not found", name))?;

    let output = Command::new("ip")
        .args(["addr", "del", ip_cidr, "dev", name])
        .output()
        .await
        .with_context(|| format!("Failed to execute ip addr del for {}", name))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Failed to remove IP address {} from {}: {}",
            ip_cidr,
            name,
            stderr.trim()
        );
    }

    tracing::info!(interface = name, ip = ip_cidr, "IP address removed");
    Ok(())
}

pub fn is_ethernet_iface(name: &str) -> bool {
    name.starts_with("eth")
        || name.starts_with("en")
        || name.starts_with("eno")
        || name.starts_with("ens")
        || name.starts_with("bond")
}

pub fn is_wifi_iface(name: &str) -> bool {
    name.starts_with("wlan") || name.starts_with("wlp")
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::link::nlas::Nla;

    #[test]
    fn parse_interface_stats_from_stats64_nla() {
        let mut stats_bytes = vec![0u8; 64];
        stats_bytes[0..8].copy_from_slice(&1u64.to_le_bytes());
        stats_bytes[8..16].copy_from_slice(&2u64.to_le_bytes());
        stats_bytes[16..24].copy_from_slice(&100u64.to_le_bytes());
        stats_bytes[24..32].copy_from_slice(&200u64.to_le_bytes());
        stats_bytes[32..40].copy_from_slice(&0u64.to_le_bytes());
        stats_bytes[40..48].copy_from_slice(&0u64.to_le_bytes());
        stats_bytes[48..56].copy_from_slice(&0u64.to_le_bytes());
        stats_bytes[56..64].copy_from_slice(&0u64.to_le_bytes());

        let stats = parse_interface_stats(&[Nla::Stats64(stats_bytes)]).expect("expected stats");
        assert_eq!(stats.rx_packets, 1);
        assert_eq!(stats.tx_packets, 2);
        assert_eq!(stats.rx_bytes, 100);
        assert_eq!(stats.tx_bytes, 200);
    }

    #[test]
    fn parse_interface_stats_short_buffer_returns_none() {
        let stats_bytes = vec![0u8; 32]; // too short
        assert!(parse_interface_stats(&[Nla::Stats64(stats_bytes)]).is_none());
    }

    #[test]
    fn parse_interface_stats_no_stats64_returns_none() {
        assert!(parse_interface_stats(&[Nla::IfName("lo".to_string())]).is_none());
    }

    #[test]
    fn is_ethernet_iface_identifies_correct_prefixes() {
        assert!(is_ethernet_iface("eth0"));
        assert!(is_ethernet_iface("enp0s3"));
        assert!(is_ethernet_iface("eno1"));
        assert!(is_ethernet_iface("ens3"));
        assert!(is_ethernet_iface("bond0"));
        assert!(!is_ethernet_iface("wlan0"));
        assert!(!is_ethernet_iface("lo"));
    }

    #[test]
    fn is_wifi_iface_identifies_correct_prefixes() {
        assert!(is_wifi_iface("wlan0"));
        assert!(is_wifi_iface("wlp2s0"));
        assert!(!is_wifi_iface("eth0"));
        assert!(!is_wifi_iface("lo"));
    }
}

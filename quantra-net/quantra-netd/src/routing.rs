//! IP routing — add, delete, list routes via rtnetlink.

use anyhow::{Context, Result};
use common::RouteInfo;
use futures::TryStreamExt;
use netlink_packet_route::route::nlas::Nla as RouteNla;
use rtnetlink::Handle;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use tokio::process::Command;

use crate::netlink::{find_link_index, get_all_links};

pub fn parse_destination(destination: &str) -> Result<(IpAddr, u8)> {
    if destination == "default" {
        return Ok((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    }
    let parts: Vec<&str> = destination.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!(
            "Invalid destination '{}', expected CIDR or default",
            destination
        );
    }
    let addr: IpAddr = parts[0].parse().context("Invalid route destination IP")?;
    let prefix: u8 = parts[1]
        .parse()
        .context("Invalid route destination prefix")?;
    Ok((addr, prefix))
}

pub async fn add_route(
    handle: &Handle,
    dest: &str,
    gateway: &str,
    iface: Option<&str>,
) -> Result<()> {
    let (destination, prefix) = parse_destination(dest)?;
    let gw: IpAddr = gateway.parse().context("Invalid gateway address")?;
    let mut request = handle.route().add().v4();
    if let IpAddr::V4(dst) = destination {
        request = request.destination_prefix(dst, prefix);
    } else {
        anyhow::bail!("Only IPv4 routes are currently supported for route add");
    }
    if let IpAddr::V4(gw4) = gw {
        request = request.gateway(gw4);
    } else {
        anyhow::bail!("Only IPv4 gateways are currently supported");
    }
    if let Some(name) = iface {
        let index = find_link_index(handle, name)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Interface '{}' not found", name))?;
        request = request.output_interface(index);
    }
    request
        .execute()
        .await
        .context("rtnetlink route add failed")
}

pub async fn delete_route(handle: &Handle, dest: &str, gateway: Option<&str>) -> Result<()> {
    let _ = handle;
    let mut args: Vec<&str> = vec!["route", "del", dest];
    if let Some(gw) = gateway {
        args.push("via");
        args.push(gw);
    }
    let output = Command::new("ip")
        .args(args)
        .output()
        .await
        .context("Failed to execute ip route del")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ip route del failed: {}", stderr.trim());
    }
    Ok(())
}

pub async fn list_routes(handle: &Handle) -> Result<Vec<RouteInfo>> {
    let mut route_stream = handle.route().get(rtnetlink::IpVersion::V4).execute();
    let mut index_to_name = HashMap::new();
    for iface in get_all_links(handle).await? {
        index_to_name.insert(iface.index, iface.name);
    }
    let mut routes = Vec::new();
    while let Some(route) = route_stream
        .try_next()
        .await
        .context("rtnetlink: failed to iterate routes")?
    {
        let destination = if route.header.destination_prefix_length == 0 {
            "default".to_string()
        } else {
            let mut dst = None;
            let mut gw = None;
            let mut oif = None;
            for nla in &route.nlas {
                match nla {
                    RouteNla::Destination(bytes) if bytes.len() == 4 => {
                        dst = Some(format!(
                            "{}.{}.{}.{}",
                            bytes[0], bytes[1], bytes[2], bytes[3]
                        ));
                    }
                    RouteNla::Gateway(bytes) if bytes.len() == 4 => {
                        gw = Some(format!(
                            "{}.{}.{}.{}",
                            bytes[0], bytes[1], bytes[2], bytes[3]
                        ));
                    }
                    RouteNla::Oif(index) => {
                        oif = Some(*index);
                    }
                    _ => {}
                }
            }
            routes.push(RouteInfo {
                destination: dst
                    .map(|d| format!("{}/{}", d, route.header.destination_prefix_length))
                    .unwrap_or_else(|| "unknown".to_string()),
                gateway: gw,
                interface: oif.and_then(|idx| index_to_name.get(&idx).cloned()),
            });
            continue;
        };

        let mut gateway = None;
        let mut interface = None;
        for nla in &route.nlas {
            match nla {
                RouteNla::Gateway(bytes) if bytes.len() == 4 => {
                    gateway = Some(format!(
                        "{}.{}.{}.{}",
                        bytes[0], bytes[1], bytes[2], bytes[3]
                    ));
                }
                RouteNla::Oif(index) => {
                    interface = index_to_name.get(index).cloned();
                }
                _ => {}
            }
        }
        routes.push(RouteInfo {
            destination,
            gateway,
            interface,
        });
    }
    Ok(routes)
}

pub async fn default_interface(handle: &Handle) -> Result<Option<String>> {
    let routes = list_routes(handle).await?;
    Ok(routes
        .into_iter()
        .find(|r| r.destination == "default")
        .and_then(|r| r.interface))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_destination_default() {
        let (ip, prefix) = parse_destination("default").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(prefix, 0);
    }

    #[test]
    fn parse_destination_valid_cidr() {
        let (ip, prefix) = parse_destination("192.168.1.0/24").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn parse_destination_invalid_no_prefix() {
        assert!(parse_destination("192.168.1.0").is_err());
    }

    #[test]
    fn parse_destination_invalid_ip() {
        assert!(parse_destination("not.an.ip/24").is_err());
    }

    #[test]
    fn parse_destination_invalid_prefix() {
        assert!(parse_destination("10.0.0.0/abc").is_err());
    }

    #[test]
    fn parse_destination_loopback_cidr() {
        let (ip, prefix) = parse_destination("127.0.0.0/8").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)));
        assert_eq!(prefix, 8);
    }

    #[test]
    fn parse_destination_host_route() {
        let (ip, prefix) = parse_destination("10.0.0.1/32").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(prefix, 32);
    }

    #[test]
    fn parse_destination_double_slash_fails() {
        assert!(parse_destination("10.0.0.0/24/extra").is_err());
    }
}

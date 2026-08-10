//! Connection quality monitoring, speed tests, bandwidth measurement, diagnostics.

use anyhow::{Context, Result};
use common::{EventType, LinkState, NetEvent, QualityMetrics};
use rtnetlink::Handle;
use std::collections::HashMap;
use tokio::time::Duration;

use crate::dhcp::read_dns_servers;
use crate::exec::Exec;
use crate::netlink::{get_all_links, is_wifi_iface};
use crate::routing::list_routes;

pub async fn measure_quality(
    handle: &Handle,
    exec: &dyn Exec,
    interface: &str,
    duration_secs: u64,
) -> Result<QualityMetrics> {
    let gateway = list_routes(handle)
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|r| r.destination == "default")
        .and_then(|r| r.gateway)
        .unwrap_or_else(|| "1.1.1.1".to_string());

    let ping_output = exec
        .output("ping", &["-c", "5", "-W", "1", &gateway])
        .await
        .context("Failed to run ping for quality monitoring")?;
    let ping_text = String::from_utf8_lossy(&ping_output.stdout);

    let mut latencies = Vec::new();
    for line in ping_text.lines() {
        if let Some(idx) = line.find("time=") {
            let rest = &line[idx + 5..];
            let val = rest
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .replace("ms", "");
            if let Ok(v) = val.parse::<f32>() {
                latencies.push(v);
            }
        }
    }

    let mut packet_loss = 1.0f32;
    for line in ping_text.lines() {
        if line.contains("packet loss") {
            let pct = line
                .split(',')
                .find(|p| p.contains("packet loss"))
                .and_then(|p| p.trim().split('%').next())
                .and_then(|p| p.trim().parse::<f32>().ok())
                .unwrap_or(100.0);
            packet_loss = pct / 100.0;
        }
    }

    let mut signal_strength = -100;
    let mut bitrate = 0u32;
    if is_wifi_iface(interface) {
        let iw = exec.output("iw", &["dev", interface, "link"]).await.ok();
        if let Some(out) = iw {
            let txt = String::from_utf8_lossy(&out.stdout);
            for line in txt.lines() {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("signal: ") {
                    if let Some(v) = rest
                        .split_whitespace()
                        .next()
                        .and_then(|x| x.parse::<f32>().ok())
                    {
                        signal_strength = v as i32;
                    }
                } else if let Some(rest) = t.strip_prefix("tx bitrate: ") {
                    if let Some(v) = rest
                        .split_whitespace()
                        .next()
                        .and_then(|x| x.parse::<f32>().ok())
                    {
                        bitrate = v as u32;
                    }
                }
            }
        }
    }

    let avg = if latencies.is_empty() {
        0.0
    } else {
        latencies.iter().sum::<f32>() / latencies.len() as f32
    };
    let variance = if latencies.is_empty() {
        0.0
    } else {
        latencies.iter().map(|v| (v - avg).powi(2)).sum::<f32>() / latencies.len() as f32
    };
    let jitter_penalty = (variance.sqrt() / 100.0).min(0.5);
    let stability = (1.0 - packet_loss - jitter_penalty).clamp(0.0, 1.0);

    if duration_secs > 5 {
        tokio::time::sleep(Duration::from_secs(duration_secs.saturating_sub(5).min(20))).await;
    }

    Ok(QualityMetrics {
        signal_strength,
        snr: 0.0,
        bitrate,
        retry_rate: 0.0,
        latency_ms: latencies,
        packet_loss,
        stability,
        recommendation: if stability < 0.7 {
            Some("Connection is unstable. Try switching channel/AP or Ethernet.".to_string())
        } else {
            Some("Connection quality looks healthy.".to_string())
        },
    })
}

pub async fn bandwidth_test(
    _exec: &dyn Exec,
    interface: &str,
    duration_secs: u64,
) -> Result<common::BandwidthResult> {
    let rx_path = format!("/sys/class/net/{}/statistics/rx_bytes", interface);
    let tx_path = format!("/sys/class/net/{}/statistics/tx_bytes", interface);
    let rx0 = std::fs::read_to_string(&rx_path)
        .with_context(|| format!("Cannot read {}", rx_path))?
        .trim()
        .parse::<u64>()
        .context("Invalid rx_bytes value")?;
    let tx0 = std::fs::read_to_string(&tx_path)
        .with_context(|| format!("Cannot read {}", tx_path))?
        .trim()
        .parse::<u64>()
        .context("Invalid tx_bytes value")?;
    let d = duration_secs.max(1).min(60);
    tokio::time::sleep(Duration::from_secs(d)).await;
    let rx1 = std::fs::read_to_string(&rx_path)
        .with_context(|| format!("Cannot read {}", rx_path))?
        .trim()
        .parse::<u64>()
        .context("Invalid rx_bytes value")?;
    let tx1 = std::fs::read_to_string(&tx_path)
        .with_context(|| format!("Cannot read {}", tx_path))?
        .trim()
        .parse::<u64>()
        .context("Invalid tx_bytes value")?;
    let rx_mbps = ((rx1.saturating_sub(rx0)) as f64 * 8.0 / d as f64) / 1_000_000.0;
    let tx_mbps = ((tx1.saturating_sub(tx0)) as f64 * 8.0 / d as f64) / 1_000_000.0;
    let combined_mbps = rx_mbps + tx_mbps;
    Ok(common::BandwidthResult {
        rx_mbps,
        tx_mbps,
        combined_mbps,
        duration_secs: d,
        interface: interface.to_string(),
    })
}

pub async fn monitor_interface_events(
    handle: &Handle,
    interface: Option<&str>,
) -> Result<Vec<NetEvent>> {
    let mut events = Vec::new();
    let before = get_all_links(handle).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let after = get_all_links(handle).await?;

    let mut before_map = HashMap::new();
    for iface in before {
        before_map.insert(iface.name.clone(), iface);
    }
    for iface in after {
        if let Some(filter) = interface {
            if iface.name != filter {
                continue;
            }
        }
        if let Some(prev) = before_map.get(&iface.name) {
            if prev.state != iface.state {
                events.push(NetEvent {
                    event_type: if iface.state == LinkState::Up {
                        EventType::LinkUp
                    } else {
                        EventType::LinkDown
                    },
                    interface: iface.name.clone(),
                    details: serde_json::json!({"state": format!("{:?}", iface.state)}),
                });
            }
            for addr in &iface.ip_addresses {
                if !prev.ip_addresses.contains(addr) {
                    events.push(NetEvent {
                        event_type: EventType::AddressAdded,
                        interface: iface.name.clone(),
                        details: serde_json::json!({ "address": addr }),
                    });
                }
            }
            for addr in &prev.ip_addresses {
                if !iface.ip_addresses.contains(addr) {
                    events.push(NetEvent {
                        event_type: EventType::AddressRemoved,
                        interface: iface.name.clone(),
                        details: serde_json::json!({ "address": addr }),
                    });
                }
            }
        }
    }
    Ok(events)
}

pub async fn diagnose_interface(handle: &Handle, interface: Option<&str>) -> Result<String> {
    let interfaces = get_all_links(handle).await?;
    let mut filtered = Vec::new();
    for i in interfaces {
        if let Some(iface) = interface {
            if i.name != iface {
                continue;
            }
        }
        filtered.push(i);
    }

    let routes = list_routes(handle).await.unwrap_or_default();
    let default = routes.iter().find(|r| r.destination == "default");
    let dns = read_dns_servers().unwrap_or_default();
    let default_target = default
        .and_then(|r| r.gateway.as_deref().map(|s| s.to_string()))
        .unwrap_or_else(|| "1.1.1.1".to_string());

    let connectivity = {
        let output = tokio::process::Command::new("ping")
            .args(["-c", "1", "-W", "1", &default_target])
            .output()
            .await;
        match output {
            Ok(o) if o.status.success() => "OK".to_string(),
            _ => "FAILED".to_string(),
        }
    };

    let mut msg = String::new();
    msg.push_str("Network diagnostics\n");
    msg.push_str("---------------------\n");
    if let Some(def) = default {
        msg.push_str(&format!(
            "Default route: via {} (iface: {})\n",
            def.gateway.as_deref().unwrap_or("-"),
            def.interface.as_deref().unwrap_or("-")
        ));
    } else {
        msg.push_str("Default route: not found\n");
    }
    msg.push_str(&format!(
        "DNS servers: {}\n",
        if dns.is_empty() {
            "-".to_string()
        } else {
            dns.join(", ")
        }
    ));
    msg.push_str(&format!(
        "Connectivity: ping {} => {}\n",
        default_target, connectivity
    ));

    msg.push_str("\nInterfaces:\n");
    if filtered.is_empty() {
        msg.push_str("  (none)\n");
    } else {
        for i in filtered {
            msg.push_str(&format!(
                "  - {} ({:?}) ips=[{}]\n",
                i.name,
                i.state,
                if i.ip_addresses.is_empty() {
                    "-".to_string()
                } else {
                    i.ip_addresses.join(", ")
                }
            ));
        }
    }
    Ok(msg)
}

pub async fn ping_internet() -> bool {
    let output = tokio::process::Command::new("ping")
        .args(["-c", "1", "-W", "1", "1.1.1.1"])
        .output()
        .await;
    output.map(|o| o.status.success()).unwrap_or(false)
}

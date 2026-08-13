//! Network configuration persistence — read/write/upsert YAML config.

use anyhow::{Context, Result};
use common::{InterfaceConfig, LinkState, NetworkConfig, RunMode};
use rtnetlink::Handle;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tracing::warn;

use crate::dhcp::read_dns_servers;
use crate::netlink::get_all_links;
use crate::routing::list_routes;

pub const CONFIG_PATH: &str = "/overlayer/syshub/etc/quantra-system/network.yaml";

pub async fn save_config(handle: &Handle) -> Result<()> {
    let interfaces = get_all_links(handle).await?;
    let routes = list_routes(handle).await?;
    let mut iface_map: BTreeMap<String, InterfaceConfig> = BTreeMap::new();
    for iface in interfaces {
        iface_map.insert(
            iface.name,
            InterfaceConfig {
                state: if iface.state == LinkState::Up {
                    "up".to_string()
                } else {
                    "down".to_string()
                },
                addresses: iface.ip_addresses,
                gateway: None,
                dns: Vec::new(),
            },
        );
    }
    let dns = read_dns_servers().unwrap_or_default();
    for route in &routes {
        if route.destination == "default"
            && let Some(iface_name) = &route.interface
            && let Some(iface) = iface_map.get_mut(iface_name)
        {
            iface.gateway = route.gateway.clone();
            iface.dns = dns.clone();
        }
    }
    let current_cfg = read_config().unwrap_or_default();
    let config = NetworkConfig {
        interfaces: iface_map,
        routes,
        wifi: current_cfg.wifi,
        wifi_autoconnect: current_cfg.wifi_autoconnect,
        mode: current_cfg.mode,
        total_connections: current_cfg.total_connections,
    };
    let serialized = serde_yaml::to_string(&config).context("Failed to serialize config")?;
    if let Some(parent) = Path::new(CONFIG_PATH).parent() {
        std::fs::create_dir_all(parent).context("Failed to create config directory")?;
    }
    std::fs::write(CONFIG_PATH, serialized).context("Failed to write config file")?;
    std::fs::set_permissions(CONFIG_PATH, std::fs::Permissions::from_mode(0o600))
        .context("Failed to set config file permissions")?;
    Ok(())
}

pub fn read_config() -> Result<NetworkConfig> {
    let data = std::fs::read_to_string(CONFIG_PATH)
        .with_context(|| format!("Configuration file not found at {}", CONFIG_PATH))?;
    serde_yaml::from_str(&data).context("Invalid configuration file format")
}

pub fn upsert_config(cfg: NetworkConfig) -> Result<()> {
    let serialized = serde_yaml::to_string(&cfg).context("Failed to serialize config")?;
    if let Some(parent) = Path::new(CONFIG_PATH).parent() {
        std::fs::create_dir_all(parent).context("Failed to create config directory")?;
    }
    std::fs::write(CONFIG_PATH, serialized).context("Failed to write config file")?;
    std::fs::set_permissions(CONFIG_PATH, std::fs::Permissions::from_mode(0o600))
        .context("Failed to set config file permissions")?;
    Ok(())
}

pub fn current_mode() -> RunMode {
    read_config().map(|cfg| cfg.mode).unwrap_or_default()
}

pub fn set_mode(mode: RunMode) -> Result<()> {
    let mut cfg = read_config().unwrap_or_default();
    cfg.mode = mode;
    upsert_config(cfg)
}

pub fn save_wifi_profile(
    ssid: &str,
    password: Option<&str>,
    security: common::WifiSecurity,
    hidden: bool,
    autoconnect: bool,
) -> Result<()> {
    let mut cfg = read_config().unwrap_or_default();
    cfg.wifi.retain(|p| p.ssid != ssid);
    cfg.wifi.push(common::WifiProfile {
        ssid: ssid.to_string(),
        security,
        password: password.map(|p| p.to_string()),
        hidden,
        autoconnect,
    });
    upsert_config(cfg)
}

pub fn forget_wifi_profile(ssid: &str) -> Result<()> {
    let mut cfg = read_config().unwrap_or_default();
    let before = cfg.wifi.len();
    cfg.wifi.retain(|p| p.ssid != ssid);
    if cfg.wifi.len() == before {
        anyhow::bail!("No saved WiFi profile found for '{ssid}'");
    }
    upsert_config(cfg)
}

pub fn set_wifi_autoconnect(interface: &str, enable: bool) -> Result<()> {
    let mut cfg = read_config().unwrap_or_default();
    cfg.wifi_autoconnect.insert(interface.to_string(), enable);
    upsert_config(cfg)
}

pub async fn load_config_into_kernel(handle: &Handle) -> Result<()> {
    let config = match read_config() {
        Ok(cfg) => cfg,
        Err(_) => return Ok(()),
    };
    for (name, iface_cfg) in config.interfaces {
        if iface_cfg.state.eq_ignore_ascii_case("up") {
            let _ = crate::netlink::set_link_state(handle, &name, true).await;
        }
        for address in iface_cfg.addresses {
            let _ = crate::netlink::add_ip_address(handle, &name, &address).await;
        }
    }
    for route in config.routes {
        if let Some(gw) = route.gateway {
            let _ = crate::routing::add_route(
                handle,
                &route.destination,
                &gw,
                route.interface.as_deref(),
            )
            .await;
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub fn increment_total_connections() -> u64 {
    let mut cfg = read_config().unwrap_or_default();
    cfg.total_connections = cfg.total_connections.saturating_add(1);
    let total = cfg.total_connections;
    if let Err(e) = upsert_config(cfg) {
        warn!("Failed to persist total connections count: {e:#}");
    } else {
        tracing::info!("New connection persisted, total_connections={}", total);
    }
    total
}

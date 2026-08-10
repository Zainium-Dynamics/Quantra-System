//! Auto-configuration & self-heal loop for quantra-net daemon.

use anyhow::{Context, Result};
use rtnetlink::Handle;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::Duration;
use tracing::{debug, info, warn};

use crate::{config, dhcp, netlink, quality, wifi};

pub static SELF_HEAL_STARTED: AtomicBool = AtomicBool::new(false);
static AUTO_CONFIG_RUNNING: AtomicBool = AtomicBool::new(false);

pub async fn auto_configure_once(handle: &Handle) -> Result<()> {
    if AUTO_CONFIG_RUNNING.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let res = async {
        let interfaces = netlink::get_all_links(handle).await?;
        let eth: Vec<String> = interfaces
            .iter()
            .filter(|i| netlink::is_ethernet_iface(&i.name))
            .map(|i| i.name.clone())
            .collect();
        let wfi: Vec<String> = interfaces
            .iter()
            .filter(|i| netlink::is_wifi_iface(&i.name))
            .map(|i| i.name.clone())
            .collect();

        for iface in &eth {
            netlink::set_link_state(handle, iface, true).await?;
            match tokio::time::timeout(Duration::from_secs(60), dhcp::dhcp_acquire(handle, iface))
                .await
            {
                Ok(Ok(lease)) if lease.ip_cidr.is_some() => {
                    info!(interface = iface, ip = ?lease.ip_cidr, "DHCP succeeded on ethernet");
                    let _ = config::save_config(handle).await;
                    return Ok(());
                }
                _ => {
                    debug!(interface = iface, "DHCP failed on ethernet");
                }
            }
        }

        let cfg = config::read_config().unwrap_or_default();
        for wifi_iface in &wfi {
            if !cfg
                .wifi_autoconnect
                .get(wifi_iface)
                .copied()
                .unwrap_or(true)
            {
                continue;
            }
            if cfg.wifi.is_empty() {
                continue;
            }
            netlink::set_link_state(handle, wifi_iface, true).await?;
            let networks = wifi::wifi_scan(wifi_iface).await.unwrap_or_default();
            let mut best: Option<(common::WifiProfile, common::WifiNetwork)> = None;
            for net in networks {
                if let Some(profile) = cfg.wifi.iter().find(|p| p.ssid == net.ssid) {
                    let bonus: i32 = if profile.autoconnect { 100 } else { 0 };
                    let score = net.signal + bonus;
                    let replace = match &best {
                        None => true,
                        Some((_, cur)) => {
                            let cb: i32 = if cfg
                                .wifi
                                .iter()
                                .find(|p| p.ssid == cur.ssid)
                                .map(|p| p.autoconnect)
                                .unwrap_or(false)
                            {
                                100
                            } else {
                                0
                            };
                            score > cur.signal + cb
                        }
                    };
                    if replace {
                        best = Some((profile.clone(), net));
                    }
                }
            }
            let Some((profile, _)) = best else { continue };
            wifi::wifi_connect(
                wifi_iface,
                &profile.ssid,
                profile.password.as_deref(),
                profile.security.clone(),
                profile.hidden,
            )
            .await?;
            let lease = tokio::time::timeout(
                Duration::from_secs(60),
                dhcp::dhcp_acquire(handle, wifi_iface),
            )
            .await
            .context("DHCP timed out")??;
            if lease.ip_cidr.is_none() {
                continue;
            }
            info!(interface = wifi_iface, ip = ?lease.ip_cidr, "DHCP succeeded on WiFi");
            let _ = config::save_config(handle).await;
            return Ok(());
        }
        anyhow::bail!("No working network found")
    }
    .await;
    AUTO_CONFIG_RUNNING.store(false, Ordering::SeqCst);
    res
}

pub async fn self_heal_loop(handle: Handle) {
    let mut backoff = Duration::from_secs(15);
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        if quality::ping_internet().await {
            backoff = Duration::from_secs(15);
            continue;
        }
        warn!("Connectivity check failed; attempting self-heal...");
        if let Err(e) = auto_configure_once(&handle).await {
            warn!("Self-heal attempt failed: {e:#}");
        }
        tokio::time::sleep(backoff).await;
        backoff = std::cmp::min(backoff * 2, Duration::from_secs(300));
    }
}

pub fn ensure_self_heal_started(handle: Handle) {
    if !SELF_HEAL_STARTED.swap(true, Ordering::SeqCst) {
        tokio::spawn(self_heal_loop(handle));
    }
}

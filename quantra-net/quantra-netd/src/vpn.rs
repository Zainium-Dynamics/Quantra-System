use rtnetlink;
// VPN management — WireGuard and OpenVPN profile CRUD + tunnel lifecycle.

use anyhow::{Context, Result};
use common::{VpnConfig, VpnStatusInfo, VpnType};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;

use crate::exec::Exec;
use crate::wireguard;

pub const VPN_DIR: &str = "/overlayer/syshub/etc/quantra-system/vpn";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VpnProfile {
    pub name: String,
    pub vpn_type: VpnType,
    pub config: VpnConfig,
}

fn vpn_profile_path(name: &str) -> String {
    format!("{}/{}.yaml", VPN_DIR, name)
}

async fn run_cmd(exec: &dyn Exec, bin: &str, args: &[&str], context_msg: &str) -> Result<()> {
    let output = exec.output(bin, args).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{context_msg}: {}", stderr.trim());
    }
    Ok(())
}

pub fn save_vpn_profile(name: &str, vpn_type: VpnType, config: VpnConfig) -> Result<()> {
    std::fs::create_dir_all(VPN_DIR).context("Failed to create VPN profile directory")?;
    std::fs::set_permissions(VPN_DIR, std::fs::Permissions::from_mode(0o700))
        .context("Failed to set VPN directory permissions")?;
    let profile = VpnProfile {
        name: name.to_string(),
        vpn_type,
        config,
    };
    let path = vpn_profile_path(name);
    let data = serde_yaml::to_string(&profile).context("Failed to serialize VPN profile")?;
    std::fs::write(&path, data).context("Failed to write VPN profile")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .context("Failed to set VPN profile permissions")?;
    Ok(())
}

fn read_vpn_profile(name: &str) -> Result<VpnProfile> {
    let data = std::fs::read_to_string(vpn_profile_path(name))
        .with_context(|| format!("VPN profile '{}' not found", name))?;
    serde_yaml::from_str(&data).context("Invalid VPN profile format")
}

pub async fn vpn_up(exec: &dyn Exec, name: &str) -> Result<()> {
    let profile = read_vpn_profile(name)?;
    match profile.vpn_type {
        VpnType::WireGuard => {
            if let VpnConfig::WireGuard(cfg) = profile.config {
                // Use native WireGuard GENL — no wg-quick binary needed
                let (_, handle, _) =
                    rtnetlink::new_connection().context("open rtnetlink for WireGuard")?;
                wireguard::apply_wg_config(exec, &handle, name, &cfg)
                    .await
                    .with_context(|| format!("WireGuard native setup for '{}'", name))
            } else {
                anyhow::bail!("VPN profile type mismatch")
            }
        }
        VpnType::OpenVPN => {
            if let VpnConfig::OpenVPN(cfg) = profile.config {
                let ovpn_path = format!("{}/{}.ovpn", VPN_DIR, name);
                std::fs::write(&ovpn_path, cfg.ovpn).context("Failed to write OpenVPN config")?;
                let pid_path = format!("/run/quantra-system/openvpn-{}.pid", name);
                run_cmd(
                    exec,
                    "openvpn",
                    &["--config", &ovpn_path, "--daemon", "--writepid", &pid_path],
                    "openvpn start failed",
                )
                .await
            } else {
                anyhow::bail!("VPN profile type mismatch")
            }
        }
    }
}

pub async fn vpn_down(exec: &dyn Exec, name: &str) -> Result<()> {
    let profile = read_vpn_profile(name)?;
    match profile.vpn_type {
        VpnType::WireGuard => wireguard::teardown_wg(exec, name)
            .await
            .with_context(|| format!("WireGuard teardown for '{}'", name)),
        VpnType::OpenVPN => {
            let pid_path = format!("/run/quantra-system/openvpn-{}.pid", name);
            let pid = std::fs::read_to_string(&pid_path)
                .with_context(|| format!("OpenVPN pid file not found: {}", pid_path))?;
            let pid = pid.trim().to_string();
            run_cmd(exec, "kill", &[&pid], "Failed to stop OpenVPN").await?;
            let _ = std::fs::remove_file(pid_path);
            Ok(())
        }
    }
}

pub async fn vpn_status(exec: &dyn Exec) -> Result<Vec<VpnStatusInfo>> {
    let mut out = Vec::new();
    if std::fs::metadata(VPN_DIR).is_err() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(VPN_DIR).context("Failed to list VPN profiles")? {
        let entry = entry.context("Failed to read VPN profile entry")?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let data = std::fs::read_to_string(&path).context("Failed to read VPN profile file")?;
        let profile: VpnProfile =
            serde_yaml::from_str(&data).context("Invalid VPN profile file")?;
        let up = match profile.vpn_type {
            VpnType::WireGuard => exec
                .output("ip", &["link", "show", &profile.name])
                .await
                .map(|o| o.status.success())
                .unwrap_or(false),
            VpnType::OpenVPN => {
                let pid_path = format!("/run/quantra-system/openvpn-{}.pid", profile.name);
                std::fs::metadata(pid_path).is_ok()
            }
        };
        out.push(VpnStatusInfo {
            name: profile.name.clone(),
            vpn_type: profile.vpn_type.clone(),
            up,
            interface: Some(profile.name),
        });
    }
    Ok(out)
}

pub async fn vpn_show(exec: &dyn Exec, name: &str) -> Result<common::VpnProfileView> {
    let profile = read_vpn_profile(name)?;
    let up = match profile.vpn_type {
        VpnType::WireGuard => exec
            .output("ip", &["link", "show", &profile.name])
            .await
            .map(|o| o.status.success())
            .unwrap_or(false),
        VpnType::OpenVPN => {
            let pid_path = format!("/run/quantra-system/openvpn-{}.pid", profile.name);
            std::fs::metadata(pid_path).is_ok()
        }
    };

    let summary = match profile.vpn_type {
        VpnType::WireGuard => {
            if let VpnConfig::WireGuard(cfg) = profile.config {
                format!(
                    "WireGuard listen_port={}, address={}, peers={}",
                    cfg.listen_port,
                    cfg.address.as_deref().unwrap_or("-"),
                    cfg.peers.len()
                )
            } else {
                "WireGuard profile (invalid config)".to_string()
            }
        }
        VpnType::OpenVPN => {
            if let VpnConfig::OpenVPN(cfg) = profile.config {
                format!("OpenVPN config length={} bytes", cfg.ovpn.len())
            } else {
                "OpenVPN profile (invalid config)".to_string()
            }
        }
    };

    Ok(common::VpnProfileView {
        name: profile.name,
        vpn_type: profile.vpn_type,
        up,
        summary,
    })
}

pub async fn set_vpn_killswitch(exec: &dyn Exec, enable: bool, iface: Option<&str>) -> Result<()> {
    let target = iface.unwrap_or("tun0");
    if enable {
        let _ = run_cmd(
            exec,
            "nft",
            &["add", "table", "inet", "quantra_killswitch"],
            "nft add table failed",
        )
        .await;
        let _ = run_cmd(
            exec,
            "nft",
            &[
                "add",
                "chain",
                "inet",
                "quantra_killswitch",
                "output",
                "{",
                "type",
                "filter",
                "hook",
                "output",
                "priority",
                "0",
                ";",
                "policy",
                "drop",
                ";",
                "}",
            ],
            "nft add chain failed",
        )
        .await;
        run_cmd(
            exec,
            "nft",
            &[
                "add",
                "rule",
                "inet",
                "quantra_killswitch",
                "output",
                "oifname",
                target,
                "accept",
            ],
            "nft add kill-switch rule failed",
        )
        .await?;
    } else {
        let _ = run_cmd(
            exec,
            "nft",
            &["delete", "table", "inet", "quantra_killswitch"],
            "nft delete kill-switch table failed",
        )
        .await;
    }
    Ok(())
}

//! Firewall management — nftables presets, rules, zones, NAT.

use anyhow::{Context, Result};
use common::{FirewallPreset, FirewallStatus, FirewallZone};
use std::collections::BTreeMap;
use std::path::Path;

use crate::exec::Exec;

const FIREWALL_STATE_PATH: &str = "/overlayer/syshub/etc/quantra-system/firewall.yaml";

fn default_firewall_status() -> FirewallStatus {
    FirewallStatus {
        active_preset: None,
        nat_enabled: false,
        zones: BTreeMap::new(),
    }
}

pub fn read_firewall_state() -> FirewallStatus {
    match std::fs::read_to_string(FIREWALL_STATE_PATH) {
        Ok(data) => serde_yaml::from_str(&data).unwrap_or_else(|_| default_firewall_status()),
        Err(_) => default_firewall_status(),
    }
}

fn write_firewall_state(state: &FirewallStatus) -> Result<()> {
    if let Some(parent) = Path::new(FIREWALL_STATE_PATH).parent() {
        std::fs::create_dir_all(parent).context("Failed to create firewall state directory")?;
    }
    let data = serde_yaml::to_string(state).context("Failed to serialize firewall state")?;
    std::fs::write(FIREWALL_STATE_PATH, data).context("Failed to write firewall state file")
}

async fn run_cmd(exec: &dyn Exec, bin: &str, args: &[&str], context_msg: &str) -> Result<()> {
    let output = exec.output(bin, args).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{context_msg}: {}", stderr.trim());
    }
    Ok(())
}

pub async fn apply_firewall_preset(exec: &dyn Exec, preset: FirewallPreset) -> Result<()> {
    let input_policy = match preset {
        FirewallPreset::Home | FirewallPreset::Work | FirewallPreset::Gaming => "accept",
        FirewallPreset::Public => "drop",
    };
    let ruleset = format!(
        "flush table inet quantra || true\n\
         table inet quantra {{\n\
           chain input {{ type filter hook input priority 0; policy {input_policy}; }}\n\
           chain forward {{ type filter hook forward priority 0; policy drop; }}\n\
           chain output {{ type filter hook output priority 0; policy accept; }}\n\
         }}\n"
    );
    let rules_path = "/run/quantra-system/nft-quantra.rules";
    if let Some(parent) = Path::new(rules_path).parent() {
        std::fs::create_dir_all(parent).context("Failed to create nft rules directory")?;
    }
    std::fs::write(rules_path, ruleset).context("Failed to write nft rules file")?;
    run_cmd(
        exec,
        "nft",
        &["-f", rules_path],
        "Failed to apply nft rules",
    )
    .await?;
    let mut state = read_firewall_state();
    state.active_preset = Some(preset);
    write_firewall_state(&state)
}

pub async fn firewall_allow(
    exec: &dyn Exec,
    service: &str,
    from: Option<&str>,
    port: Option<u16>,
) -> Result<()> {
    let mut args: Vec<String> = vec![
        "add".into(),
        "rule".into(),
        "inet".into(),
        "quantra".into(),
        "input".into(),
    ];
    if let Some(src) = from {
        args.push("ip".into());
        args.push("saddr".into());
        args.push(src.to_string());
    }
    if let Some(p) = port {
        args.push("tcp".into());
        args.push("dport".into());
        args.push(p.to_string());
    }
    args.push("accept".into());
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_cmd(
        exec,
        "nft",
        &args_ref,
        &format!("Failed to allow service '{}'", service),
    )
    .await
}

pub async fn firewall_block(exec: &dyn Exec, port: u16, from: Option<&str>) -> Result<()> {
    let mut args: Vec<String> = vec![
        "add".into(),
        "rule".into(),
        "inet".into(),
        "quantra".into(),
        "input".into(),
    ];
    if let Some(src) = from {
        args.push("ip".into());
        args.push("saddr".into());
        args.push(src.to_string());
    }
    args.push("tcp".into());
    args.push("dport".into());
    args.push(port.to_string());
    args.push("drop".into());
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_cmd(exec, "nft", &args_ref, "Failed to add firewall block rule").await
}

pub fn firewall_zone_add(interface: &str, zone: FirewallZone) -> Result<()> {
    let mut state = read_firewall_state();
    state.zones.insert(interface.to_string(), zone);
    write_firewall_state(&state)
}

pub async fn firewall_nat(exec: &dyn Exec, enable: bool, interface: &str) -> Result<()> {
    if enable {
        let _ = run_cmd(
            exec,
            "nft",
            &["add", "table", "ip", "quantra_nat"],
            "nft add nat table failed",
        )
        .await;
        let _ = run_cmd(
            exec,
            "nft",
            &[
                "add",
                "chain",
                "ip",
                "quantra_nat",
                "postrouting",
                "{",
                "type",
                "nat",
                "hook",
                "postrouting",
                "priority",
                "100",
                ";",
                "}",
            ],
            "nft add nat chain failed",
        )
        .await;
        run_cmd(
            exec,
            "nft",
            &[
                "add",
                "rule",
                "ip",
                "quantra_nat",
                "postrouting",
                "oifname",
                interface,
                "masquerade",
            ],
            "nft add masquerade rule failed",
        )
        .await?;
    } else {
        let _ = run_cmd(
            exec,
            "nft",
            &["delete", "table", "ip", "quantra_nat"],
            "nft delete nat table failed",
        )
        .await;
    }
    let mut state = read_firewall_state();
    state.nat_enabled = enable;
    write_firewall_state(&state)
}

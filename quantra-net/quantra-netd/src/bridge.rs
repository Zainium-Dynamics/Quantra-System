//! Virtual interface types — Bridge, VLAN, Bond, MACVLAN.
//!
//! All operations use the `ip` command via the `Exec` trait
//! (same pattern as existing modules) with rtnetlink where available.
//!
//! # Bridge
//! Linux software bridge (`br0`) — connects multiple interfaces at L2.
//! Use cases: VMs, containers, multi-interface routing.
//!
//! # VLAN
//! 802.1Q tagged sub-interface (`eth0.100`).
//! One physical interface can carry multiple VLANs.
//!
//! # Bond
//! Link aggregation (bond0) — combines multiple interfaces for
//! redundancy or bandwidth (mode: active-backup, balance-rr, 802.3ad, etc).
//!
//! # MACVLAN
//! Virtual interface with own MAC on top of a parent.
//! Used by containers for direct network access.

use anyhow::{Context, Result};
use tracing::info;

use crate::exec::Exec;

// ── Bond modes ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum BondMode {
    /// Round-robin — balance across all slaves (default)
    BalanceRr,
    /// Active-backup — only one active slave, failover on link down
    #[default]
    ActiveBackup,
    /// XOR balance — hash src+dst MAC
    BalanceXor,
    /// Broadcast — transmit on all slaves simultaneously
    Broadcast,
    /// 802.3ad LACP — requires switch support
    Ieee8023ad,
    /// Adaptive transmit load balancing
    BalanceTlb,
    /// Adaptive load balancing
    BalanceAlb,
}

impl BondMode {
    fn kernel_name(&self) -> &'static str {
        match self {
            Self::BalanceRr => "balance-rr",
            Self::ActiveBackup => "active-backup",
            Self::BalanceXor => "balance-xor",
            Self::Broadcast => "broadcast",
            Self::Ieee8023ad => "802.3ad",
            Self::BalanceTlb => "balance-tlb",
            Self::BalanceAlb => "balance-alb",
        }
    }
}

// ── MACVLAN modes ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum MacvlanMode {
    /// Bridge — macvlans can communicate with each other
    #[default]
    Bridge,
    /// VEPA — all traffic goes to external switch
    Vepa,
    /// Private — macvlans cannot communicate with each other
    Private,
    /// Passthrough — passes all traffic to single macvlan
    Passthrough,
}

impl MacvlanMode {
    fn kernel_name(&self) -> &'static str {
        match self {
            Self::Bridge => "bridge",
            Self::Vepa => "vepa",
            Self::Private => "private",
            Self::Passthrough => "passthrough",
        }
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

async fn ip(exec: &dyn Exec, args: &[&str]) -> Result<()> {
    let out = exec.output("ip", args).await?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("ip {}: {}", args.join(" "), stderr.trim());
    }
    Ok(())
}

// ── Bridge ────────────────────────────────────────────────────────────────────

/// Create a bridge interface.
///
/// ```sh
/// ip link add name <name> type bridge
/// ip link set <name> up
/// ```
pub async fn bridge_create(exec: &dyn Exec, name: &str) -> Result<()> {
    validate_iface_name(name)?;
    ip(exec, &["link", "add", "name", name, "type", "bridge"])
        .await
        .with_context(|| format!("create bridge '{}'", name))?;
    ip(exec, &["link", "set", name, "up"])
        .await
        .with_context(|| format!("bring bridge '{}' up", name))?;
    info!("Bridge '{}' created", name);
    Ok(())
}

/// Delete a bridge interface.
pub async fn bridge_delete(exec: &dyn Exec, name: &str) -> Result<()> {
    validate_iface_name(name)?;
    ip(exec, &["link", "set", name, "down"]).await.ok();
    ip(exec, &["link", "delete", name, "type", "bridge"])
        .await
        .with_context(|| format!("delete bridge '{}'", name))?;
    info!("Bridge '{}' deleted", name);
    Ok(())
}

/// Add a member interface to a bridge.
///
/// ```sh
/// ip link set <member> master <bridge>
/// ip link set <member> up
/// ```
pub async fn bridge_add_member(exec: &dyn Exec, bridge: &str, member: &str) -> Result<()> {
    validate_iface_name(bridge)?;
    validate_iface_name(member)?;
    ip(exec, &["link", "set", member, "master", bridge])
        .await
        .with_context(|| format!("add '{}' to bridge '{}'", member, bridge))?;
    ip(exec, &["link", "set", member, "up"]).await.ok();
    info!("Added '{}' to bridge '{}'", member, bridge);
    Ok(())
}

/// Remove a member interface from its bridge.
pub async fn bridge_remove_member(exec: &dyn Exec, member: &str) -> Result<()> {
    validate_iface_name(member)?;
    ip(exec, &["link", "set", member, "nomaster"])
        .await
        .with_context(|| format!("remove '{}' from bridge", member))?;
    info!("Removed '{}' from bridge", member);
    Ok(())
}

/// Show bridge members.
pub async fn bridge_show(exec: &dyn Exec, bridge: &str) -> Result<String> {
    let out = exec
        .output("ip", &["link", "show", "master", bridge])
        .await?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

// ── VLAN ──────────────────────────────────────────────────────────────────────

/// Create a VLAN sub-interface.
///
/// ```sh
/// ip link add link <parent> name <name> type vlan id <vlan_id>
/// ip link set <name> up
/// ```
pub async fn vlan_create(exec: &dyn Exec, name: &str, parent: &str, vlan_id: u16) -> Result<()> {
    validate_iface_name(name)?;
    validate_iface_name(parent)?;
    if vlan_id == 0 || vlan_id > 4094 {
        anyhow::bail!("VLAN ID {} out of range (1-4094)", vlan_id);
    }
    let vlan_str = vlan_id.to_string();
    ip(
        exec,
        &[
            "link", "add", "link", parent, "name", name, "type", "vlan", "id", &vlan_str,
        ],
    )
    .await
    .with_context(|| format!("create VLAN '{}' (id={}) on '{}'", name, vlan_id, parent))?;
    ip(exec, &["link", "set", name, "up"]).await.ok();
    info!("VLAN '{}' (id={}) created on '{}'", name, vlan_id, parent);
    Ok(())
}

/// Delete a VLAN sub-interface.
pub async fn vlan_delete(exec: &dyn Exec, name: &str) -> Result<()> {
    validate_iface_name(name)?;
    ip(exec, &["link", "set", name, "down"]).await.ok();
    ip(exec, &["link", "delete", name])
        .await
        .with_context(|| format!("delete VLAN '{}'", name))?;
    info!("VLAN '{}' deleted", name);
    Ok(())
}

// ── Bond ──────────────────────────────────────────────────────────────────────

/// Create a bond interface.
///
/// ```sh
/// ip link add name <name> type bond mode <mode>
/// ip link set <name> up
/// ```
pub async fn bond_create(exec: &dyn Exec, name: &str, mode: BondMode) -> Result<()> {
    validate_iface_name(name)?;
    ip(
        exec,
        &[
            "link",
            "add",
            "name",
            name,
            "type",
            "bond",
            "mode",
            mode.kernel_name(),
        ],
    )
    .await
    .with_context(|| format!("create bond '{}' mode={}", name, mode.kernel_name()))?;
    ip(exec, &["link", "set", name, "up"]).await.ok();
    info!("Bond '{}' created (mode={})", name, mode.kernel_name());
    Ok(())
}

/// Delete a bond interface.
pub async fn bond_delete(exec: &dyn Exec, name: &str) -> Result<()> {
    validate_iface_name(name)?;
    ip(exec, &["link", "set", name, "down"]).await.ok();
    ip(exec, &["link", "delete", name])
        .await
        .with_context(|| format!("delete bond '{}'", name))?;
    info!("Bond '{}' deleted", name);
    Ok(())
}

/// Add a slave interface to a bond.
///
/// The slave must be DOWN before enslaving.
pub async fn bond_add_member(exec: &dyn Exec, bond: &str, slave: &str) -> Result<()> {
    validate_iface_name(bond)?;
    validate_iface_name(slave)?;
    // Must be down to enslave
    ip(exec, &["link", "set", slave, "down"]).await.ok();
    ip(exec, &["link", "set", slave, "master", bond])
        .await
        .with_context(|| format!("add '{}' to bond '{}'", slave, bond))?;
    ip(exec, &["link", "set", slave, "up"]).await.ok();
    info!("Enslaved '{}' to bond '{}'", slave, bond);
    Ok(())
}

/// Remove a slave from a bond.
pub async fn bond_remove_member(exec: &dyn Exec, slave: &str) -> Result<()> {
    validate_iface_name(slave)?;
    ip(exec, &["link", "set", slave, "nomaster"])
        .await
        .with_context(|| format!("remove '{}' from bond", slave))?;
    info!("Removed '{}' from bond", slave);
    Ok(())
}

// ── MACVLAN ───────────────────────────────────────────────────────────────────

/// Create a MACVLAN interface.
///
/// ```sh
/// ip link add link <parent> name <name> type macvlan mode <mode>
/// ip link set <name> up
/// ```
pub async fn macvlan_create(
    exec: &dyn Exec,
    name: &str,
    parent: &str,
    mode: MacvlanMode,
) -> Result<()> {
    validate_iface_name(name)?;
    validate_iface_name(parent)?;
    ip(
        exec,
        &[
            "link",
            "add",
            "link",
            parent,
            "name",
            name,
            "type",
            "macvlan",
            "mode",
            mode.kernel_name(),
        ],
    )
    .await
    .with_context(|| format!("create MACVLAN '{}' on '{}'", name, parent))?;
    ip(exec, &["link", "set", name, "up"]).await.ok();
    info!(
        "MACVLAN '{}' (mode={}) created on '{}'",
        name,
        mode.kernel_name(),
        parent
    );
    Ok(())
}

/// Delete a MACVLAN interface.
pub async fn macvlan_delete(exec: &dyn Exec, name: &str) -> Result<()> {
    validate_iface_name(name)?;
    ip(exec, &["link", "set", name, "down"]).await.ok();
    ip(exec, &["link", "delete", name])
        .await
        .with_context(|| format!("delete MACVLAN '{}'", name))?;
    info!("MACVLAN '{}' deleted", name);
    Ok(())
}

// ── Input validation ──────────────────────────────────────────────────────────

/// Validate interface name — alphanumeric + colon/dot/dash/underscore, max 15 chars.
fn validate_iface_name(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("interface name is empty");
    }
    if name.len() > 15 {
        anyhow::bail!("interface name '{}' too long (max 15)", name);
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == ':')
    {
        anyhow::bail!("interface name '{}' contains invalid characters", name);
    }
    if name.contains("..") || name.contains('/') {
        anyhow::bail!("interface name '{}' contains path traversal", name);
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_bridge_name_ok() {
        assert!(validate_iface_name("br0").is_ok());
        assert!(validate_iface_name("bridge-lan").is_ok());
        assert!(validate_iface_name("eth0.100").is_ok());
        assert!(validate_iface_name("bond0").is_ok());
    }

    #[test]
    fn validate_empty_name_rejected() {
        assert!(validate_iface_name("").is_err());
    }

    #[test]
    fn validate_long_name_rejected() {
        assert!(validate_iface_name("a".repeat(16).as_str()).is_err());
    }

    #[test]
    fn validate_traversal_rejected() {
        assert!(validate_iface_name("br/../etc").is_err());
        assert!(validate_iface_name("br/0").is_err());
    }

    #[tokio::test]
    async fn vlan_id_zero_rejected() {
        let exec = crate::exec::MockExec::default();
        let err = vlan_create(&exec, "vlan0", "eth0", 0).await.unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[tokio::test]
    async fn vlan_id_too_large_rejected() {
        let exec = crate::exec::MockExec::default();
        let err = vlan_create(&exec, "vlan0", "eth0", 4095).await.unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn bond_mode_kernel_names() {
        assert_eq!(BondMode::ActiveBackup.kernel_name(), "active-backup");
        assert_eq!(BondMode::Ieee8023ad.kernel_name(), "802.3ad");
        assert_eq!(BondMode::BalanceRr.kernel_name(), "balance-rr");
    }

    #[test]
    fn macvlan_mode_kernel_names() {
        assert_eq!(MacvlanMode::Bridge.kernel_name(), "bridge");
        assert_eq!(MacvlanMode::Passthrough.kernel_name(), "passthrough");
    }
}

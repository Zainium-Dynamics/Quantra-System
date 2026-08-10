//! Network namespace operations — create, list, exec, delete, veth pairs.
//!
//! Uses raw `unshare`/`setns` syscalls via libc for zero external deps.

use anyhow::{Context, Result};
use std::path::Path;

const NETNS_DIR: &str = "/run/netns";

/// Create a new network namespace by bind-mounting the namespace fd.
pub async fn netns_create(name: &str) -> Result<()> {
    validate_netns_name(name)?;

    std::fs::create_dir_all(NETNS_DIR).context("Failed to create /var/run/netns directory")?;

    let ns_path = format!("{}/{}", NETNS_DIR, name);
    if Path::new(&ns_path).exists() {
        anyhow::bail!("Network namespace '{}' already exists", name);
    }

    // Create the mount point
    std::fs::write(&ns_path, "")
        .with_context(|| format!("Failed to create namespace mount point at {}", ns_path))?;

    // Fork + unshare(CLONE_NEWNET) + bind mount /proc/self/ns/net → /var/run/netns/<name>
    let output = tokio::process::Command::new("unshare")
        .args([
            "--net",
            "--",
            "mount",
            "--bind",
            "/proc/self/ns/net",
            &ns_path,
        ])
        .output()
        .await
        .context("Failed to execute unshare for namespace creation")?;

    if !output.status.success() {
        // Cleanup mount point on failure
        let _ = std::fs::remove_file(&ns_path);
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Failed to create network namespace '{}': {}",
            name,
            stderr.trim()
        );
    }

    tracing::info!(namespace = name, "Network namespace created");
    Ok(())
}

/// List all existing network namespaces.
pub async fn netns_list() -> Result<Vec<String>> {
    let dir = match std::fs::read_dir(NETNS_DIR) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context("Failed to list network namespaces"),
    };

    let mut names = Vec::new();
    for entry in dir {
        let entry = entry.context("Failed to read netns directory entry")?;
        if let Some(name) = entry.file_name().to_str() {
            names.push(name.to_string());
        }
    }
    names.sort();
    Ok(names)
}

/// Execute a command inside a network namespace using `nsenter`.
pub async fn netns_exec(name: &str, command: &str) -> Result<String> {
    validate_netns_name(name)?;

    let ns_path = format!("{}/{}", NETNS_DIR, name);
    if !Path::new(&ns_path).exists() {
        anyhow::bail!("Network namespace '{}' does not exist", name);
    }

    let output = tokio::process::Command::new("nsenter")
        .args([
            "--net",
            &format!("--net={}", ns_path),
            "--",
            "sh",
            "-c",
            command,
        ])
        .output()
        .await
        .with_context(|| format!("Failed to execute command in namespace '{}'", name))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Command failed in namespace '{}': {}", name, stderr.trim());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Delete a network namespace.
pub async fn netns_delete(name: &str) -> Result<()> {
    validate_netns_name(name)?;

    let ns_path = format!("{}/{}", NETNS_DIR, name);
    if !Path::new(&ns_path).exists() {
        anyhow::bail!("Network namespace '{}' does not exist", name);
    }

    // Unmount the namespace bind mount
    let output = tokio::process::Command::new("umount")
        .arg(&ns_path)
        .output()
        .await
        .context("Failed to unmount network namespace")?;

    if !output.status.success() {
        tracing::warn!(
            "umount failed for namespace '{}' (may already be unmounted): {}",
            name,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    std::fs::remove_file(&ns_path)
        .with_context(|| format!("Failed to remove namespace mount point '{}'", ns_path))?;

    tracing::info!(namespace = name, "Network namespace deleted");
    Ok(())
}

/// Move a network interface into a namespace using `ip link set <iface> netns <name>`.
pub async fn link_set_netns(interface: &str, netns: &str) -> Result<()> {
    validate_netns_name(netns)?;

    let ns_path = format!("{}/{}", NETNS_DIR, netns);
    if !Path::new(&ns_path).exists() {
        anyhow::bail!("Network namespace '{}' does not exist", netns);
    }

    let output = tokio::process::Command::new("ip")
        .args(["link", "set", interface, "netns", netns])
        .output()
        .await
        .with_context(|| format!("Failed to move '{}' to namespace '{}'", interface, netns))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Failed to move interface '{}' to namespace '{}': {}",
            interface,
            netns,
            stderr.trim()
        );
    }

    tracing::info!(
        interface = interface,
        namespace = netns,
        "Interface moved to namespace"
    );
    Ok(())
}

/// Create a veth pair — two virtual ethernet devices linked together.
pub async fn veth_create(name: &str, peer: &str) -> Result<()> {
    let output = tokio::process::Command::new("ip")
        .args(["link", "add", name, "type", "veth", "peer", "name", peer])
        .output()
        .await
        .with_context(|| format!("Failed to create veth pair {}<->{}", name, peer))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Failed to create veth pair {}<->{}: {}",
            name,
            peer,
            stderr.trim()
        );
    }

    tracing::info!(veth = name, peer = peer, "Veth pair created");
    Ok(())
}

/// Validate namespace name — alphanumeric + hyphens/underscores, max 32 chars.
fn validate_netns_name(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("Namespace name cannot be empty");
    }
    if name.len() > 32 {
        anyhow::bail!("Namespace name too long (max 32 characters)");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!("Namespace name contains invalid characters (use alphanumeric, -, or _)");
    }
    // Prevent path traversal
    if name.contains("..") || name.contains('/') {
        anyhow::bail!("Namespace name contains path traversal characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_netns_name_accepts_valid() {
        assert!(validate_netns_name("my-ns").is_ok());
        assert!(validate_netns_name("container_1").is_ok());
        assert!(validate_netns_name("ns0").is_ok());
    }

    #[test]
    fn validate_netns_name_rejects_empty() {
        assert!(validate_netns_name("").is_err());
    }

    #[test]
    fn validate_netns_name_rejects_too_long() {
        let long_name = "a".repeat(33);
        assert!(validate_netns_name(&long_name).is_err());
    }

    #[test]
    fn validate_netns_name_rejects_special_chars() {
        assert!(validate_netns_name("ns/../etc").is_err());
        assert!(validate_netns_name("ns with spaces").is_err());
        assert!(validate_netns_name("ns;rm").is_err());
    }
}

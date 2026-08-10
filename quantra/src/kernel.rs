use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::config::InitConfig;
use crate::utils;

// PHASE 4: Pre-computed constants (no allocations at runtime)
const SYSCTL_PATH_PREFIX: &str = "/proc/sys/";
const CGROUP_CONTROLLERS_PATH: &str = "/sys/fs/cgroup/cgroup.controllers";
const CGROUP_SUBTREE_PATH: &str = "/sys/fs/cgroup/cgroup.subtree_control";

// PHASE 4: Pre-computed module list (no allocation)
const ESSENTIAL_MODULES: &[&str] = &["loop", "squashfs", "ext4", "vfat"];

// PHASE 4: Pre-computed sysctl tuples (no allocation)
const SYSCTL_TWEAKS: &[(&str, &str)] = &[
    ("kernel.sysrq", "1"),
    ("vm.swappiness", "10"),
    ("net.ipv4.ip_forward", "1"),
    ("kernel.printk", "3 4 1 7"),
];

#[inline]
pub fn setup(cfg: &InitConfig) -> Result<()> {
    set_hostname(cfg)?;
    activate_cgroup_controllers()?;
    apply_sysctl_tweaks()?;
    load_essential_modules();

    log::info!("Kernel tuning completed");
    Ok(())
}

#[inline]
fn set_hostname(cfg: &InitConfig) -> Result<()> {
    // Delegate to utils::set_hostname which also writes /etc/hostname
    utils::set_hostname(cfg.hostname.as_deref())
}

/// Activate all available cgroup v2 subtree controllers.
///
/// GUARD: `cgroup.controllers` only exists on cgroup v2 (unified hierarchy).
/// On cgroup v1 kernels this file is absent — skip gracefully without crashing.
#[inline]
fn activate_cgroup_controllers() -> Result<()> {
    if !Path::new(CGROUP_CONTROLLERS_PATH).exists() {
        log::info!(
            "cgroup.controllers not found — cgroup v1 or no cgroup support, skipping activation"
        );
        return Ok(());
    }

    let controllers =
        fs::read_to_string(CGROUP_CONTROLLERS_PATH).context("Failed to read cgroup controllers")?;

    let enabled: String = controllers
        .split_whitespace()
        .map(|c| format!("+{}", c))
        .collect::<Vec<_>>()
        .join(" ");

    if enabled.is_empty() {
        log::info!("No cgroup v2 controllers advertised by kernel");
        return Ok(());
    }

    fs::write(CGROUP_SUBTREE_PATH, &enabled).context("Failed to activate cgroup controllers")?;

    log::info!("Cgroup v2 controllers activated: {}", enabled);
    Ok(())
}

#[inline]
fn apply_sysctl_tweaks() -> Result<()> {
    for (key, value) in SYSCTL_TWEAKS {
        let path = format!("{}{}", SYSCTL_PATH_PREFIX, key.replace('.', "/"));
        if let Err(e) = fs::write(&path, value) {
            log::warn!("sysctl {} failed: {}", key, e);
        }
    }
    Ok(())
}

/// Load essential kernel modules using modprobe.
///
/// Uses absolute path to avoid PATH-dependency at early boot.
/// Failures are logged but non-fatal — modules may be compiled-in.
#[inline]
fn load_essential_modules() {
    let modprobe = "/overlayer/syshub/sbin/modprobe";
    if !Path::new(modprobe).exists() {
        log::warn!("modprobe not found ({}) — modules not loaded", modprobe);
        return;
    }

    for module in ESSENTIAL_MODULES {
        match Command::new(modprobe).arg(module).status() {
            Ok(status) if status.success() => {
                log::info!("Module loaded: {}", module);
            }
            Ok(status) => {
                log::warn!(
                    "modprobe {} exited with {}: may be built-in or unavailable",
                    module,
                    status
                );
            }
            Err(e) => {
                log::warn!("Failed to run modprobe {}: {}", module, e);
            }
        }
    }
}

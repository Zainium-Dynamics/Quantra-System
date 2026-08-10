use anyhow::{Context, Result};
use log::info;
use std::fs;
use std::path::Path;

// Sirf WRITABLE directories
// - /overlayer/syshub/var → zexlib/union/var (OverlayFS upperdir se, COW)
// - /run → tmpfs (quantra mount karta hai mounts.rs mein)
// NO /etc entries — syshub/etc READ-ONLY hai
const ZAINIUM_DIRS: &[&str] = &[
    "/overlayer/syshub/var/log/quantra-system",
    "/overlayer/syshub/var/lib/quantra-system",
    "/run/quantra-system",
    "/run/user",    // quantra-logind: /run/user/<uid>
    "/run/quantra", // control socket dir
    "/run/dbus",    // dbus socket
];

pub fn set_hostname(hostname: Option<&str>) -> Result<()> {
    let name = hostname.unwrap_or("ZainiumOS");
    fs::write("/proc/sys/kernel/hostname", name).context("write /proc/sys/kernel/hostname")?;
    // syshub/etc READ-ONLY — non-fatal
    if let Err(e) = fs::write("/overlayer/syshub/etc/hostname", name) {
        log::warn!("hostname persist skipped: {} (read-only syshub)", e);
    }
    info!("Hostname: {}", name);
    Ok(())
}

pub fn ensure_zainium_dirs() -> Result<()> {
    for dir in ZAINIUM_DIRS {
        if !Path::new(dir).exists() {
            match fs::create_dir_all(dir) {
                Ok(()) => info!("Created dir: {}", dir),
                Err(e) => log::warn!("mkdir '{}' failed: {} (continuing)", dir, e),
            }
        }
    }
    Ok(())
}

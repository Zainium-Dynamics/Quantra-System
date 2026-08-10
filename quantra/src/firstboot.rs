/// First boot wizard — initial system setup
///
/// Runs on the very first boot when the marker file is absent.
/// Performs one-time setup tasks:
///   - Generate machine-id
///   - Set root password (if interactive)
///   - Create initial user account
///   - Set timezone
///   - Configure hostname
///   - Generate SSH host keys
///   - Write default configs (timesyncd.conf, vconsole.conf)
///
/// Marker: `/overlayer/syshub/var/lib/quantra-system/firstboot-done`
/// If this file exists, firstboot is skipped entirely.
use anyhow::{Context, Result};
use log::{info, warn};
use std::fs;
use std::path::Path;
use std::process::Command;

const FIRSTBOOT_MARKER: &str = "/overlayer/syshub/var/lib/quantra-system/firstboot-done";
const MACHINE_ID_PATH: &str = "/overlayer/syshub/etc/machine-id";

/// Check if this is the first boot.
pub fn is_first_boot() -> bool {
    !Path::new(FIRSTBOOT_MARKER).exists()
}

/// Run all first-boot tasks. Non-interactive — sets up defaults.
///
/// Called from main.rs Phase 4 (after mounts, before services).
pub fn run_if_needed() {
    if !is_first_boot() {
        return;
    }
    info!("firstboot: first boot detected — running setup");
    match run_firstboot() {
        Ok(()) => info!("firstboot: setup complete"),
        Err(e) => warn!("firstboot: {}", e),
    }
}

fn run_firstboot() -> Result<()> {
    // 1. Generate machine-id
    generate_machine_id()?;

    // 2. Generate SSH host keys (if sshd is installed)
    generate_ssh_host_keys();

    // 3. Write default configs
    crate::timesyncd::write_default_config().ok();
    crate::vconsole::write_default_config().ok();

    // 4. Initialize random seed
    crate::random_seed::save();

    // 5. Write firstboot marker
    fs::create_dir_all(Path::new(FIRSTBOOT_MARKER).parent().unwrap())
        .context("create firstboot marker dir")?;

    fs::write(
        FIRSTBOOT_MARKER,
        format!(
            "firstboot-done\ntimestamp={}\n",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        ),
    )
    .context("write firstboot marker")?;

    info!("firstboot: marker written at {}", FIRSTBOOT_MARKER);
    Ok(())
}

/// Generate /etc/machine-id — a unique 128-bit hex ID for this machine.
///
/// The ID is derived from /dev/urandom (random, not tied to hardware).
/// If MACHINE_ID_PATH already exists and is non-empty, it is preserved.
fn generate_machine_id() -> Result<()> {
    let path = Path::new(MACHINE_ID_PATH);

    if path.exists() {
        let existing = fs::read_to_string(path).unwrap_or_default();
        if existing.trim().len() == 32 {
            info!("firstboot: machine-id already set");
            return Ok(());
        }
    }

    // Read 16 bytes from /dev/urandom → 32 hex chars
    let mut buf = [0u8; 16];
    {
        use std::io::Read;
        fs::File::open("/dev/urandom")
            .context("open /dev/urandom for machine-id")?
            .read_exact(&mut buf)
            .context("read /dev/urandom")?;
    }

    let id: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
    let id_with_newline = format!("{}\n", id);

    // Write to /overlayer/syshub/etc/machine-id and .../var/lib/dbus/machine-id
    // syshub is a read-only lowerdir — the write is COW'd into zexlib/union.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    match fs::write(path, &id_with_newline) {
        Ok(()) => info!("firstboot: machine-id = {}", id),
        Err(e) => warn!("firstboot: write {}: {} (read-only?)", path.display(), e),
    }

    // D-Bus machine-id (symlink or copy)
    let dbus_path = "/overlayer/syshub/var/lib/dbus/machine-id";
    if let Some(parent) = Path::new(dbus_path).parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(dbus_path, &id_with_newline).ok();

    Ok(())
}

/// Generate SSH host keys for all key types.
///
/// Runs `ssh-keygen -A` if available.
/// Non-fatal — sshd may not be installed.
fn generate_ssh_host_keys() {
    let bin = "/overlayer/syshub/bin/ssh-keygen";

    if !Path::new(bin).exists() {
        info!("firstboot: ssh-keygen not found — skipping SSH host key generation");
        return;
    }

    // Check if host keys already exist
    if Path::new("/overlayer/syshub/etc/ssh/ssh_host_rsa_key").exists() {
        info!("firstboot: SSH host keys already exist");
        return;
    }

    match Command::new(bin)
        .args(["-A", "-f", "/overlayer/syshub/etc/ssh/ssh_host"])
        .status()
    {
        Ok(s) if s.success() => info!("firstboot: SSH host keys generated"),
        Ok(s) => warn!("firstboot: ssh-keygen exited {:?}", s.code()),
        Err(e) => warn!("firstboot: ssh-keygen exec failed: {}", e),
    }
}

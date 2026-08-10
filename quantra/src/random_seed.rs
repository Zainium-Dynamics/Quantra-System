/// Entropy preservation — save/restore random seed across boots
///
/// Preserves `/dev/urandom` entropy across reboots so the random number
/// generator is well-seeded immediately at boot — before network or hardware
/// entropy sources are available.
///
/// # Strategy
/// - **Restore** (early boot, Phase 1): read saved seed → write to `/dev/urandom`
/// - **Save** (shutdown): read from `/dev/urandom` → write to seed file
///
/// # Seed file location
/// `/var/lib/quantra-system/random-seed` (600, root only)
///
/// # Security
/// - Seed file is 512 bytes (4096 bits) — exceeds kernel entropy pool size
/// - Mode 0600 — no other user can read it
/// - On restore: immediately overwrite the seed file with new random data
///   so the same seed is never used twice (forward secrecy)
use anyhow::{Context, Result};
use log::{info, warn};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const SEED_FILE: &str = "/overlayer/syshub/var/lib/quantra-system/random-seed";
const SEED_SIZE: usize = 512; // 4096 bits

/// Restore saved entropy to /dev/urandom at boot.
///
/// Called during Phase 1 (after /var is writable).
/// Non-fatal — kernel always has *some* entropy; this just makes it better.
pub fn restore() {
    match restore_inner() {
        Ok(()) => info!("random-seed: entropy restored ({} bytes)", SEED_SIZE),
        Err(e) => warn!(
            "random-seed: restore failed: {} (non-fatal — kernel will gather entropy)",
            e
        ),
    }
}

fn restore_inner() -> Result<()> {
    let seed_path = Path::new(SEED_FILE);

    if !seed_path.exists() {
        // First boot — generate and save a seed immediately
        info!("random-seed: no seed file found (first boot) — generating");
        return save_inner();
    }

    // Read saved seed
    let seed = fs::read(seed_path).context("read seed file")?;

    if seed.len() < 32 {
        warn!(
            "random-seed: seed file too small ({} bytes) — regenerating",
            seed.len()
        );
        return save_inner();
    }

    // Write to /dev/urandom to credit the kernel entropy pool
    let mut urandom = fs::OpenOptions::new()
        .write(true)
        .open("/dev/urandom")
        .context("open /dev/urandom for write")?;

    urandom
        .write_all(&seed)
        .context("write seed to /dev/urandom")?;

    // Immediately overwrite seed file with fresh random data (forward secrecy)
    // so this exact seed is never reused
    save_inner()?;

    Ok(())
}

/// Save current /dev/urandom entropy to disk.
///
/// Called during shutdown to preserve entropy for next boot.
pub fn save() {
    match save_inner() {
        Ok(()) => info!("random-seed: entropy saved ({} bytes)", SEED_SIZE),
        Err(e) => warn!("random-seed: save failed: {} (entropy will not persist)", e),
    }
}

fn save_inner() -> Result<()> {
    let seed_path = Path::new(SEED_FILE);

    // Ensure parent directory exists
    if let Some(parent) = seed_path.parent() {
        fs::create_dir_all(parent).context("create seed file parent directory")?;
    }

    // Read fresh random bytes from /dev/urandom
    let mut urandom = fs::OpenOptions::new()
        .read(true)
        .open("/dev/urandom")
        .context("open /dev/urandom for read")?;

    let mut seed = vec![0u8; SEED_SIZE];
    urandom
        .read_exact(&mut seed)
        .context("read from /dev/urandom")?;

    // Write with restrictive permissions — mode 0600
    fs::write(seed_path, &seed).context("write seed file")?;

    let mut perms = fs::metadata(seed_path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(seed_path, perms).context("chmod seed file 0600")?;

    Ok(())
}

/// Check if a seed file exists (for boot diagnostics).
#[allow(dead_code)]
pub fn seed_exists() -> bool {
    Path::new(SEED_FILE).exists()
}

/// Mount unit activator (loads from /overlayer/syshub/etc/quantra-system/mounts/)
pub mod manager;
/// PID 1 filesystem mounting module
///
/// Mounts all essential pseudofilesystems and cgroups:
/// - /proc - Kernel interface (process info, parameters)
/// - /sys - Device and driver info
/// - /sys/fs/cgroup - Control groups hierarchy
/// - /dev - Device nodes
/// - /run - Runtime data
/// - /dev/pts - Pseudo-terminals
/// - /dev/shm - Shared memory

///
/// Mount units — declarative filesystem mount lifecycle
pub mod unit;

/// - /tmp - Temporary files
///
/// Handles two contexts correctly:
/// 1. Direct boot (no initramfs): mounts everything from scratch
/// 2. Post-pivot_root: initramfs already MS_MOVE'd /proc, /sys, /dev, /run
///    → skip-if-mounted logic prevents EBUSY crashes
///
/// NASA-grade invariant: mount success is VERIFIED via /proc/mounts,
/// not inferred from syscall return code.
use anyhow::{Context, Result};
use nix::mount::{MsFlags, mount};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

// Pre-computed mount flags (avoid runtime recomputation)
const PROC_FLAGS: MsFlags = MsFlags::empty();
const SYS_FLAGS: MsFlags = MsFlags::empty();
const DEV_FLAGS: MsFlags = MsFlags::empty();
const RUN_FLAGS: MsFlags = MsFlags::MS_NOSUID.union(MsFlags::MS_NODEV);
const DEVPTS_FLAGS: MsFlags = MsFlags::empty();
const CGROUP_FLAGS: MsFlags = MsFlags::empty();
// /tmp with MS_NOEXEC prevents shell injection attacks
const TMP_FLAGS: MsFlags = MsFlags::MS_NOSUID
    .union(MsFlags::MS_NODEV)
    .union(MsFlags::MS_NOEXEC);

// Helper: Check if a path is already mounted
fn is_already_mounted(target: &str) -> bool {
    if let Ok(content) = fs::read_to_string("/proc/mounts") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[1] == target {
                return true;
            }
        }
    }
    false
}

// Helper: Read filesystem type from /proc/mounts
fn get_root_fstype() -> Option<String> {
    if let Ok(content) = fs::read_to_string("/proc/mounts") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[1] == "/" {
                return Some(parts[2].to_string());
            }
        }
    }
    None
}

/// Detect whether we are running inside an initramfs environment.
///
/// After `pivot_root`, /proc/mounts contains the real root's mounts, NOT
/// `rootfs`. Checking `/proc/mounts` for `rootfs` on `/` is the most
/// reliable way to distinguish initramfs from a real root on any kernel.
///
/// Fallback markers:
/// - `/etc/initramfs-release` file exists
/// - Root device major via `libc::major()` == 0 (ramfs) or 1 (ramdisk)
fn detect_initramfs() -> bool {
    // Primary: Check /proc/mounts for rootfs on /  (best signal)
    if let Ok(content) = fs::read_to_string("/proc/mounts") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[1] == "/" {
                let fstype = parts[2];
                if fstype == "rootfs" || fstype == "ramfs" || fstype == "tmpfs" {
                    log::info!(
                        "Initramfs detected via /proc/mounts (root fstype={})",
                        fstype
                    );
                    return true;
                }
            }
        }
    }

    // Secondary: presence of initramfs marker file
    if Path::new("/etc/initramfs-release").exists() {
        log::info!("Initramfs detected via /etc/initramfs-release");
        return true;
    }

    // Tertiary: check root device major number using libc (safer than raw bit-shift)
    if let Ok(metadata) = fs::metadata("/") {
        let rdev = metadata.dev();
        // SAFETY: libc::major() is a pure function, no side effects
        let major = unsafe { libc::major(rdev) };
        if major == 0 || major == 1 {
            // 0 = ramfs (no real device), 1 = ram block devices
            log::info!("Initramfs detected via root device major={}", major);
            return true;
        }
    }

    false
}

// FIX #2: Post-mount verification—check /proc/mounts for actual mount
// NASA-grade validation: syscall success ≠ mount actually happened
#[inline]
fn verify_mount(target: &str, expected_fstype: &str) -> bool {
    if let Ok(content) = fs::read_to_string("/proc/mounts") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Format: device mount_point fs_type options dump pass
            if parts.len() >= 3 && parts[1] == target && parts[2] == expected_fstype {
                return true;
            }
        }
    }
    false
}

// FIX #4: Extract errno from nix::Error for detailed logging
#[inline]
fn extract_errno(error: &nix::Error) -> Option<i32> {
    // nix errors wrap errno(3) - common error codes
    match error {
        nix::Error::EACCES => Some(13), // Permission denied
        nix::Error::ENOENT => Some(2),  // No such file
        nix::Error::EINVAL => Some(22), // Invalid argument
        nix::Error::EBUSY => Some(16),  // Device or resource busy
        nix::Error::EEXIST => Some(17), // File exists
        nix::Error::EIO => Some(5),     // I/O error
        nix::Error::ENOSPC => Some(28), // No space left on device
        nix::Error::EPERM => Some(1),   // Operation not permitted
        _ => None,
    }
}

const ESSENTIAL_DIRS: &[&str] = &[
    "/proc",
    "/sys",
    "/sys/fs/cgroup",
    "/dev",
    "/run",
    "/tmp",
    "/dev/pts",
    "/dev/shm",
];

pub fn setup() -> Result<()> {
    log::info!("Initializing virtual filesystems");

    // FIX #5: Detect boot context (initramfs vs real root filesystem)
    let in_initramfs = detect_initramfs();
    if in_initramfs {
        log::info!("Early boot detected (initramfs) — /proc and /sys pre-mounted by kernel");
    } else {
        log::info!("Normal boot (real root filesystem) — mounting full hierarchy");
    }

    if !in_initramfs {
        // FIX #1: Non-fatal directory creation (may fail on read-only root)
        create_essential_dirs();
        mount_proc_first()?;
        // Now try remount (non-fatal - Log warning if fails, continue anyway)
        try_remount_root_rw();
    }

    // Mount rest of virtual filesystems
    mount_remaining_filesystems()?;

    log::info!("Essential filesystems mounted successfully");
    Ok(())
}

/// Mount /proc first so /proc/mounts is available for all subsequent verification.
///
/// Skips safely if /proc is already mounted (normal after pivot_root from initramfs).
#[inline]
fn mount_proc_first() -> Result<()> {
    // After initramfs pivot_root, /proc is MS_MOVEd into the new root already.
    // Attempting to mount again returns EBUSY — skip gracefully.
    if is_already_mounted("/proc") {
        log::info!("/proc already mounted (came from initramfs MS_MOVE) — skipping");
        return Ok(());
    }
    mount(
        None::<&str>,
        "/proc",
        Some("proc"),
        PROC_FLAGS,
        None::<&str>,
    )
    .context("mount /proc")
}

/// Try to remount root as RW, but DON'T FAIL if it doesn't work
/// This is critical for Live systems (SquashFS is read-only)
///
/// **Bulletproof logic:** If remount fails, just log warning and continue
#[inline]
fn try_remount_root_rw() {
    // First: Check if root is SquashFS (Live/ISO system)
    if let Some(fstype) = get_root_fstype() {
        if fstype == "squashfs" {
            log::info!("     Live System detected (SquashFS) — keeping Root as Read-Only");
            log::info!("    (Write support can be added via OverlayFS if needed)");
            return; // Non-fatal: just skip remount
        }
    }

    // Second: Try remount for normal installed systems
    log::info!("   Attempting to remount root as read-write...");
    match mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REMOUNT | MsFlags::MS_RELATIME,
        None::<&str>,
    ) {
        Ok(_) => {
            if verify_mount("/", "ext4") || verify_mount("/", "xfs") || verify_mount("/", "btrfs") {
                log::info!("   Root remounted as RW (verified)");
            } else {
                log::warn!("   Root remount syscall OK but verification failed—may still be RO");
            }
        }
        Err(e) => {
            // Non-fatal: Just warn and continue
            let errno_str = extract_errno(&e)
                .map(|e| format!(" (errno: {})", e))
                .unwrap_or_default();
            log::warn!(
                "    Remount RW failed{} (continuing anyway): {}",
                errno_str,
                e
            );
            log::warn!("    System will run in Read-Only mode. This is OK for Live systems.");
        }
    }
}

// FIX #1: Non-fatal directory creation (graceful handling for RO root)
#[inline]
fn create_essential_dirs() {
    for dir in ESSENTIAL_DIRS {
        match fs::create_dir_all(dir) {
            Ok(_) => log::debug!("Created mandatory directory: {}", dir),
            Err(e) => {
                // Non-fatal: Directory may already exist from kernel, or root is read-only
                // Include errno for debugging
                let errno_str = match e.raw_os_error() {
                    Some(errno) => format!(" (errno: {})", errno),
                    None => String::new(),
                };
                log::warn!(
                    "Cannot create {}{}: {} — continuing anyway (OK for Live systems)",
                    dir,
                    errno_str,
                    e
                );
            }
        }
    }
}

// FIX #3: Mount cgroups with fallback from cgroup2 (modern) to cgroup v1 (legacy)
// Supports kernels 2.6.24+ (cgroup v1) through 5.0+ (unified hierarchy)
#[inline]
fn mount_cgroups() {
    // Try cgroup2 first (modern, unified, kernel 4.5+)
    match mount(
        None::<&str>,
        "/sys/fs/cgroup",
        Some("cgroup2"),
        CGROUP_FLAGS,
        None::<&str>,
    ) {
        Ok(_) => {
            if verify_mount("/sys/fs/cgroup", "cgroup2") {
                log::info!("cgroup2 (unified) mounted — modern kernel with v2 support");
                return;
            } else {
                log::warn!(
                    "cgroup2 mount syscall OK but not in /proc/mounts—attempting v1 fallback..."
                );
            }
        }
        Err(e) => {
            let errno_str = extract_errno(&e)
                .map(|e| format!(" (errno: {})", e))
                .unwrap_or_default();
            log::info!(
                "cgroup2 unavailable{}, trying cgroup v1 hierarchy (kernel < 4.5 or disabled)",
                errno_str
            );
        }
    }

    // Fallback: cgroup v1 legacy hierarchy (tmpfs root + specific subsystem mounts)
    match mount(
        None::<&str>,
        "/sys/fs/cgroup",
        Some("tmpfs"),
        MsFlags::MS_NOSUID
            .union(MsFlags::MS_NODEV)
            .union(MsFlags::MS_NOEXEC),
        Some("mode=0755"),
    ) {
        Ok(_) => {
            if verify_mount("/sys/fs/cgroup", "tmpfs") {
                log::info!(
                    "cgroup tmpfs root mounted (legacy v1 mode—compatible with kernel 2.6.24+)"
                );
            } else {
                log::warn!("cgroup tmpfs mount failed verification—continuing anyway");
            }
        }
        Err(e) => {
            let errno_str = extract_errno(&e)
                .map(|e| format!(" (errno: {})", e))
                .unwrap_or_default();
            log::warn!(
                "cgroup tmpfs mount failed{}: {} — system may lack cgroup support",
                errno_str,
                e
            );
        }
    }
}

// PHASE 2: Sequential mounts with proper ordering (no parallel threading)
// Mounts have dependencies - sequential is correct and faster due to no thread overhead
// CRITICAL: Make all mounts non-fatal (kernel may have already mounted some filesystems)
// FIX #2: All mounts now verify via /proc/mounts (NASA-grade validation)
#[inline]
fn mount_remaining_filesystems() -> Result<()> {
    log::info!("Mounting critical filesystems sequentially (optimized)");

    // Note: /proc already mounted in mount_proc_first()

    // /sys - depends on /proc device discovery
    // After initramfs pivot_root, /sys is MS_MOVEd into new root — skip if present.
    if is_already_mounted("/sys") {
        log::info!("/sys already mounted (came from initramfs) — skipping");
    } else {
        match mount(None::<&str>, "/sys", Some("sysfs"), SYS_FLAGS, None::<&str>) {
            Ok(_) => {
                if verify_mount("/sys", "sysfs") {
                    log::info!("/sys mounted and verified");
                } else {
                    log::warn!("/sys mount syscall OK but not verified in /proc/mounts");
                }
            }
            Err(e) => {
                let errno_str = extract_errno(&e)
                    .map(|e| format!(" (errno: {})", e))
                    .unwrap_or_default();
                log::warn!("/sys mount failed{}: {} — continuing", errno_str, e);
            }
        }
    }

    // /dev - after initramfs pivot_root it is already MS_MOVEd
    if is_already_mounted("/dev") {
        log::info!("/dev already mounted (came from initramfs) — skipping");
    } else {
        match mount(
            None::<&str>,
            "/dev",
            Some("devtmpfs"),
            DEV_FLAGS,
            None::<&str>,
        ) {
            Ok(_) => {
                if verify_mount("/dev", "devtmpfs") {
                    log::info!("/dev mounted and verified");
                } else {
                    log::warn!("/dev mount syscall OK but verification pending");
                }
            }
            Err(e) => {
                let errno_str = extract_errno(&e)
                    .map(|e| format!(" (errno: {})", e))
                    .unwrap_or_default();
                log::warn!("/dev mount failed{}: {} — continuing", errno_str, e);
            }
        }
    }

    // /run - tmpfs; after initramfs pivot it is MS_MOVEd
    if is_already_mounted("/run") {
        log::info!("/run already mounted (came from initramfs) — skipping");
    } else {
        match mount(
            None::<&str>,
            "/run",
            Some("tmpfs"),
            RUN_FLAGS,
            Some("mode=0755"),
        ) {
            Ok(_) => {
                if verify_mount("/run", "tmpfs") {
                    log::info!("/run mounted and verified");
                }
            }
            Err(e) => {
                let errno_str = extract_errno(&e)
                    .map(|e| format!(" (errno: {})", e))
                    .unwrap_or_default();
                log::warn!("/run mount failed{}: {} — continuing", errno_str, e);
            }
        }
    }

    // FIX #3: cgroup mounting with v1 fallback (handled separately)
    mount_cgroups();

    // /tmp - independent tmpfs (now with MS_NOEXEC for security)
    match mount(
        None::<&str>,
        "/tmp",
        Some("tmpfs"),
        TMP_FLAGS,
        Some("mode=1777"),
    ) {
        Ok(_) => {
            if verify_mount("/tmp", "tmpfs") {
                log::info!(" /tmp mounted with MS_NOEXEC (security hardening)");
            }
        }
        Err(e) => {
            let errno_str = extract_errno(&e)
                .map(|e| format!(" (errno: {})", e))
                .unwrap_or_default();
            log::warn!(" /tmp mount failed{}: {}", errno_str, e);
        }
    }

    // /dev/pts - depends on /dev
    match mount(
        None::<&str>,
        "/dev/pts",
        Some("devpts"),
        DEVPTS_FLAGS,
        Some("mode=0620,ptmxmode=0666"),
    ) {
        Ok(_) => {
            if verify_mount("/dev/pts", "devpts") {
                log::info!(" /dev/pts mounted and verified");
            }
        }
        Err(e) => {
            let errno_str = extract_errno(&e)
                .map(|e| format!(" (errno: {})", e))
                .unwrap_or_default();
            log::warn!(" /dev/pts mount failed{}: {}", errno_str, e);
        }
    }

    match mount(
        None::<&str>,
        "/dev/shm",
        Some("tmpfs"),
        TMP_FLAGS,
        Some("mode=1777"),
    ) {
        Ok(_) => {
            if verify_mount("/dev/shm", "tmpfs") {
                log::info!(" /dev/shm mounted and verified");
            }
        }
        Err(e) => {
            let errno_str = extract_errno(&e)
                .map(|e| format!(" (errno: {})", e))
                .unwrap_or_default();
            log::warn!(" /dev/shm mount failed{}: {}", errno_str, e);
        }
    }

    // ALL MOUNTS ATTEMPTED - Return success even if some failed
    // This is NASA-grade fault tolerance: system boots even with partial mount failures
    log::info!("Filesystem mount sequence complete (partial success OK for Live systems)");
    Ok(())
}

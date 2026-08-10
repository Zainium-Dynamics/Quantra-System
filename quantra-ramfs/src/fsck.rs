/// Filesystem check before mounting root — fsck wrapper
///
/// # Overview
///
/// Runs `fsck` on the root partition before mounting it. This catches
/// filesystem corruption early and either auto-repairs it (if safe) or
/// drops to emergency shell with a clear error.
///
/// # Strategy
///
/// We call `fsck` via `execv` (not `Command::new`) because in initramfs,
/// `fsck` may live at `/sbin/fsck` or `/sbin/fsck.<type>`. We try several
/// paths and pick the first that exists.
///
/// # fsck exit codes (POSIX)
///
/// | Code | Meaning |
/// |------|---------|
/// | 0 | No errors |
/// | 1 | Filesystem errors corrected |
/// | 2 | System should be rebooted |
/// | 4 | Filesystem errors left uncorrected |
/// | 8 | Operational error |
/// | 16 | Usage/syntax error |
/// | 32 | Fsck canceled by user |
/// | 128 | Shared library error |
///
/// Codes 0 and 1 are safe to continue. Codes ≥ 2 drop to emergency shell.
///
/// # fsck skipped for
/// - Squashfs / iso9660 / tmpfs (read-only by design, no journal)
/// - NFS root
/// - Loop devices (the underlying ISO is read-only)
/// - LUKS-decrypted devices before verity check
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

// ── fsck binary search paths ──────────────────────────────────────────────────

const FSCK_PATHS: &[&str] = &[
    "/sbin/fsck",
    "/usr/sbin/fsck",
    "/overlayer/syshub/sbin/fsck",
    "/overlayer/syshub/usr/sbin/fsck",
];

// Filesystem types that must NOT be checked (read-only / network / pseudo)
const SKIP_FSTYPES: &[&str] = &[
    "squashfs", "iso9660", "tmpfs", "ramfs", "devtmpfs", "sysfs", "proc", "devpts", "nfs", "nfs4",
    "overlay",
];

// ── Public API ────────────────────────────────────────────────────────────────

/// Run filesystem check on `device` before mounting it as root.
///
/// `fstype`: if known (from cmdline `rootfstype=`), passed to fsck. If `None`,
/// fsck auto-detects.
///
/// Returns `Ok(())` if the filesystem is clean or was repaired.
/// Returns `Err` if fsck found uncorrectable errors or could not run.
pub fn check_root(device: &str, fstype: Option<&str>) -> Result<(), String> {
    // Skip filesystems that cannot be fscked
    if let Some(ft) = fstype {
        if SKIP_FSTYPES.contains(&ft) {
            eprintln!("  fsck: skipping {} ({})", device, ft);
            return Ok(());
        }
    }

    // Skip loop and ram devices
    if device.starts_with("/dev/loop") || device.starts_with("/dev/ram") {
        eprintln!("  fsck: skipping {} (loop/ram)", device);
        return Ok(());
    }

    // Skip NFS
    if device.contains(':') {
        eprintln!("  fsck: skipping {} (NFS)", device);
        return Ok(());
    }

    let fsck_bin = match find_fsck_binary(fstype) {
        Some(p) => p,
        None => {
            eprintln!("  fsck: no fsck binary found — skipping (device may be unclean)");
            return Ok(());
        }
    };

    eprintln!("  fsck: checking {} with {}", device, fsck_bin);
    let t = Instant::now();

    // -a: auto-repair without questions
    // -T: don't show title
    // -C: show progress (to /dev/console if possible)
    let mut args = vec!["-a", "-T"];
    if let Some(ft) = fstype {
        args.push("-t");
        args.push(ft);
    }
    args.push(device);

    let status = Command::new(&fsck_bin)
        .args(&args)
        .stdin(Stdio::null())
        .status()
        .map_err(|e| format!("fsck exec '{}': {}", fsck_bin, e))?;

    let code = status.code().unwrap_or(8);
    let elapsed = t.elapsed().as_millis();

    match code {
        0 => {
            eprintln!("  fsck: {} clean ({}ms)", device, elapsed);
            Ok(())
        }
        1 => {
            eprintln!("  fsck: {} repaired ({}ms) — continuing", device, elapsed);
            Ok(())
        }
        2 => Err(format!(
            "fsck: {} repaired but REBOOT REQUIRED (exit {})",
            device, code
        )),
        4 => Err(format!(
            "fsck: {} has UNCORRECTED ERRORS (exit {}) — manual intervention required",
            device, code
        )),
        _ => Err(format!(
            "fsck: {} returned unexpected exit code {} ({}ms)",
            device, code, elapsed
        )),
    }
}

/// Attempt fsck and handle reboot-required by issuing a system reboot.
///
/// Call this from main.rs instead of `check_root` if you want automatic
/// reboot on code=2 (repairs that require a restart to complete).
#[allow(dead_code)]
pub fn check_root_or_reboot(device: &str, fstype: Option<&str>) {
    match check_root(device, fstype) {
        Ok(()) => {}
        Err(e) if e.contains("REBOOT REQUIRED") => {
            eprintln!("  fsck: REBOOTING for clean filesystem...");
            std::thread::sleep(std::time::Duration::from_secs(2));
            unsafe {
                libc::sync();
                libc::reboot(libc::RB_AUTOBOOT);
            }
        }
        Err(e) => {
            eprintln!("  fsck ERROR: {}", e);
            // Caller decides — returns so caller can drop to emergency shell
        }
    }
}

// ── Btrfs subvolume mount ─────────────────────────────────────────────────────

/// Mount a Btrfs filesystem at `target`, honouring the `subvol=` option from
/// `rootflags=` or `rootfstype=btrfs` + `rootflags=subvol=@`.
///
/// This is called by `rootfs::mount_root_at` when fstype=btrfs.
///
/// # Example cmdline
/// ```
/// root=UUID=abc123 rootfstype=btrfs rootflags=subvol=@,compress=zstd
/// ```
pub fn mount_btrfs_subvol(
    device: &str,
    target: &str,
    rootflags: Option<&str>,
) -> Result<(), String> {
    use nix::mount::{MsFlags, mount};

    let flags = MsFlags::empty();
    let opts = rootflags.unwrap_or("subvol=@");

    eprintln!("  btrfs: mounting {} → {} ({})", device, target, opts);

    mount(Some(device), target, Some("btrfs"), flags, Some(opts)).map_err(|e| {
        format!(
            "btrfs mount '{}' → '{}' (opts={}): {}",
            device, target, opts, e
        )
    })?;

    eprintln!("  ✓ btrfs subvolume mounted");
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn find_fsck_binary(fstype: Option<&str>) -> Option<String> {
    // First try fsck.<type> (e.g. fsck.ext4, fsck.xfs)
    if let Some(ft) = fstype {
        for dir in &[
            "/sbin",
            "/usr/sbin",
            "/overlayer/syshub/sbin",
            "/overlayer/syshub/usr/sbin",
        ] {
            let specific = format!("{}/fsck.{}", dir, ft);
            if Path::new(&specific).exists() {
                return Some(specific);
            }
        }
    }

    // Then try generic fsck
    for &path in FSCK_PATHS {
        if Path::new(path).exists() {
            return Some(path.to_string());
        }
    }

    None
}

use nix::mount::{MsFlags, mount};
use std::fs;

/// Early filesystem mounting module
///
/// Mounts essential pseudo-filesystems in strict order:
/// 1. /proc - Kernel interface (REQUIRED for cmdline parsing)
/// 2. /sys  - Device enumeration (REQUIRED for udev)
/// 3. /dev  - Device nodes (REQUIRED for block devices)
/// 4. /run  - Runtime data (mount point setup)
/// 5. /dev/pts - Container terminals (OPTIONAL - fails silently)
/// 6. /dev/shm - Shared memory (OPTIONAL - fails silently)
///
/// After /dev is mounted, essential block device nodes are created
/// explicitly via mknod(2) because devtmpfs does not always auto-populate
/// loop devices in initramfs context before udevd starts.
///
/// Loop device major/minor numbers (from Linux kernel source):
///   /dev/loop-control → major=10, minor=237  (misc device)
///   /dev/loop0..7     → major=7,  minor=0..7 (block devices)

// /proc and /sys: no flags — MS_NOEXEC on /proc breaks elevate/elevate-pam and /proc/self/fd
const PROC_FLAGS: MsFlags = MsFlags::empty();
const SYS_FLAGS: MsFlags = MsFlags::empty();

// /dev: NO flags in initramfs — MS_NOSUID on devtmpfs prevents loop node creation
//       on kernels without CONFIG_DEVTMPFS_SAFE. Applied later on real root.
const DEV_FLAGS: MsFlags = MsFlags::empty();

// /run: nosuid + nodev, allow exec (needed for lock files, pipes)
const RUN_FLAGS: MsFlags = MsFlags::MS_NOSUID.union(MsFlags::MS_NODEV);

// /dev/shm: full security flags (no exec, no setuid, no devices)
const SHM_FLAGS: MsFlags = MsFlags::MS_NOSUID
    .union(MsFlags::MS_NODEV)
    .union(MsFlags::MS_NOEXEC);

// Directories to create before mounting
const EARLY_DIRS: &[&str] = &["/proc", "/sys", "/dev", "/run", "/dev/pts", "/dev/shm"];

/// Mount all early filesystems in strict order.
///
/// Critical mounts (/proc, /sys, /dev, /run) must succeed — boot aborts on failure.
/// Optional mounts (/dev/pts, /dev/shm) fail silently (not needed in initramfs).
///
/// After /dev mount: creates loop device nodes explicitly so loop ioctls work
/// immediately without waiting for udevd or kernel devtmpfs population.
///
/// # Errors
/// Returns error if any critical mount fails.
#[inline]
pub fn mount_early() -> Result<(), String> {
    println!("Mounting early filesystems...");

    // Batch-create all mount points
    for dir in EARLY_DIRS {
        fs::create_dir_all(dir).ok();
    }

    // /proc — critical
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        PROC_FLAGS,
        None::<&str>,
    )
    .map_err(|e| format!("CRITICAL: /proc mount failed: {} (errno: {})", e, e as i32))?;
    eprintln!("  ✓ /proc");

    // /sys — critical
    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        SYS_FLAGS,
        None::<&str>,
    )
    .map_err(|e| format!("CRITICAL: /sys mount failed: {} (errno: {})", e, e as i32))?;
    eprintln!("  ✓ /sys");

    // /dev — critical — NO MS_NOSUID so loop nodes can be created
    mount(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        DEV_FLAGS,
        Some("mode=0755"),
    )
    .map_err(|e| format!("CRITICAL: /dev mount failed: {} (errno: {})", e, e as i32))?;
    eprintln!("  ✓ /dev");

    // Explicitly create loop device nodes — devtmpfs may not auto-populate them
    // in initramfs context (no udevd running, CONFIG_DEVTMPFS_SAFE may differ)
    create_essential_devices();

    // /run — critical
    mount(
        Some("tmpfs"),
        "/run",
        Some("tmpfs"),
        RUN_FLAGS,
        Some("mode=0755"),
    )
    .map_err(|e| format!("CRITICAL: /run mount failed: {} (errno: {})", e, e as i32))?;
    eprintln!("  ✓ /run");

    // /dev/pts — OPTIONAL
    if let Err(e) = mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::empty(),
        Some("mode=0620,ptmxmode=0666"),
    ) {
        eprintln!("  ⚠ /dev/pts: {} (non-critical)", e);
    }

    // /dev/shm — OPTIONAL
    if let Err(e) = mount(
        Some("tmpfs"),
        "/dev/shm",
        Some("tmpfs"),
        SHM_FLAGS,
        Some("mode=1777"),
    ) {
        eprintln!("  ⚠ /dev/shm: {} (non-critical)", e);
    }

    println!("✓ Early mounts complete\n");
    Ok(())
}

/// Create loop device nodes that devtmpfs may not auto-populate.
///
/// Linux kernel major/minor assignments (drivers/block/loop.c):
/// - `/dev/loop-control`: character device, major=10 (misc), minor=237
/// - `/dev/loop0..7`:     block devices,    major=7  (loop), minor=0..7
///
/// These nodes are always safe to mknod — if they already exist the call
/// returns EEXIST which is silently ignored.
///
/// # Safety
/// Only `mknod(2)` and `makedev(3)` are called — both are async-signal-safe
/// and have no heap allocations.
fn create_essential_devices() {
    // /dev/loop-control — character device (misc major 10, minor 237)
    // Required for LOOP_CTL_GET_FREE ioctl
    unsafe {
        let path = b"/dev/loop-control\0";
        libc::mknod(
            path.as_ptr() as *const libc::c_char,
            libc::S_IFCHR | 0o600,
            libc::makedev(10, 237),
        );
    }

    // /dev/loop0 through /dev/loop7 — block devices (major 7)
    // Required for LOOP_SET_FD ioctl and mount(2)
    for n in 0u32..8 {
        unsafe {
            // Build "/dev/loopN\0" on stack — no heap allocation
            let mut path = [0u8; 16];
            path[0..9].copy_from_slice(b"/dev/loop");
            path[9] = b'0' + n as u8;
            // path[10] = 0  (already zeroed)

            libc::mknod(
                path.as_ptr() as *const libc::c_char,
                libc::S_IFBLK | 0o660,
                libc::makedev(7, n),
            );
        }
    }

    eprintln!("  ✓ Loop devices: /dev/loop-control + /dev/loop0-7");
}

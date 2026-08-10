use crate::cmdline::Cmdline;
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use std::ffi::CString;
use std::fs;
use std::mem;
use std::os::unix::fs::symlink;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

/// Root filesystem detection and mounting module
///
/// Responsibilities:
/// 1. Parse root device from kernel cmdline
/// 2. Wait for device to appear in /dev (with retries)
/// 3. Handle loop mount if loop= parameter provided (via raw ioctls — no losetup binary)
/// 4. Mount the root filesystem to /mnt/root
/// 5. Handle LABEL=, UUID=, and ISO/squashfs loop mounts
///
/// # Loop Device Strategy
///
/// The old implementation called `Command::new("losetup")` which fails in initramfs
/// because the losetup binary lives on the root filesystem (not yet mounted).
///
/// The new implementation uses raw Linux ioctls directly:
///
/// | Step | Call | Purpose |
/// |------|------|---------|
/// | 1 | `open("/dev/loop-control", O_RDWR)` | Open loop controller |
/// | 2 | `ioctl(LOOP_CTL_GET_FREE)` | Get next free loop device number N |
/// | 3 | `open("/dev/loopN", O_RDWR)` | Open that loop device |
/// | 4 | `open(image, O_RDONLY)` | Open squashfs image file |
/// | 5 | `ioctl(LOOP_SET_FD, image_fd)` | Attach image to loop device |
/// | 6 | `ioctl(LOOP_SET_STATUS64, &info)` | Set backing filename (cosmetic) |
/// | 7 | return `"/dev/loopN"` | Used for mount(2) call |
///
/// This is exactly what `losetup -f --show <file>` does internally.

// ── Device path prefix constants ──────────────────────────────────────────────

const LABEL_PREFIX: &str = "/dev/disk/by-label/";
const UUID_PREFIX: &str = "/dev/disk/by-uuid/";
const LIVE_SEARCH_MOUNT: &str = "/run/live/search";
const LIVE_MEDIUM_MOUNT: &str = "/run/live/medium";
const CALAMARES_BRIDGE: &str = "/cdrom";
/// Root image candidates inside the live medium, checked in priority order.
/// EROFS (`zairoot.img`) is the default eclipse-iso-builder output; the
/// `.squashfs` name is still checked for media built with `--format squashfs`.
const ZAINIUM_ROOT_IMAGE_CANDIDATES: &[&str] = &["zaisys/zairoot.img", "zaisys/zairoot.squashfs"];
const SEARCH_FILESYSTEMS: &[&str] = &[
    "iso9660", "udf", "erofs", "squashfs", "ext4", "xfs", "btrfs", "f2fs", "vfat",
];

// ── Loop device ioctl constants (from <linux/loop.h>) ─────────────────────────

/// Request next free loop device number
const LOOP_CTL_GET_FREE: libc::c_int = 0x4C82u32 as libc::c_int;
/// Attach open file descriptor to loop device
const LOOP_SET_FD: libc::c_int = 0x4C00u32 as libc::c_int;
/// Set loop device status (backing filename, flags)
const LOOP_SET_STATUS64: libc::c_int = 0x4C04u32 as libc::c_int;

/// `struct loop_info64` from `<linux/loop.h>`
///
/// Used with `LOOP_SET_STATUS64` to record the backing filename in
/// `/proc/mounts` and `losetup -l` output.
#[repr(C)]
struct LoopInfo64 {
    lo_device: u64,
    lo_inode: u64,
    lo_rdevice: u64,
    lo_offset: u64,
    lo_sizelimit: u64,
    lo_number: u32,
    lo_encrypt_type: u32,
    lo_encrypt_key_size: u32,
    lo_flags: u32,
    lo_file_name: [u8; 64],
    lo_crypt_name: [u8; 64],
    lo_encrypt_key: [u8; 32],
    lo_init: [u64; 2],
}

// ── RAII fd guard ──────────────────────────────────────────────────────────────

/// Closes a raw file descriptor on drop — prevents fd leaks on error paths.
struct FdGuard(RawFd);
impl Drop for FdGuard {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                libc::close(self.0);
            }
        }
    }
}
impl FdGuard {
    /// Release ownership without closing (transfer fd to caller).
    #[allow(dead_code)]
    fn release(mut self) -> RawFd {
        let fd = self.0;
        self.0 = -1;
        fd
    }
}

// ── Device existence check ────────────────────────────────────────────────────

/// O(1) non-blocking device existence check.
#[inline]
fn probe_device_fast(path: &str) -> bool {
    Path::new(path).exists()
}

/// List available block devices to stderr (used in emergency diagnostics).
fn list_available_devices() {
    if let Ok(entries) = fs::read_dir("/dev") {
        let mut devices: Vec<String> = entries
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| {
                n.starts_with("sd")
                    || n.starts_with("vd")
                    || n.starts_with("nvme")
                    || n.starts_with("mmcblk")
                    || n.starts_with("ram")
                    || n.starts_with("loop")
                    || n.starts_with("sr")
            })
            .collect();
        devices.sort();
        if devices.is_empty() {
            eprintln!("  No block devices found in /dev");
        } else {
            eprintln!("  Available: {}", devices.join(", "));
        }
    }
}

/// Enumerate block devices from `/sys/class/block`.
///
/// This covers modern device families that do not fit the old `sd*` model,
/// including NVMe, MMC/SD, virtio, and CD/DVD devices.
fn list_all_block_devices() -> Vec<PathBuf> {
    let mut devices = Vec::new();

    if let Ok(entries) = fs::read_dir("/sys/class/block") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();

            // Skip transient pseudo-devices; scan real block hardware only.
            if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("zram") {
                continue;
            }

            let dev_path = PathBuf::from("/dev").join(&name);
            if dev_path.exists() {
                devices.push(dev_path);
            }
        }
    }

    devices.sort_by(|left, right| left.to_string_lossy().cmp(&right.to_string_lossy()));
    devices
}

/// Best-effort read-only mount probe for a candidate block device.
fn try_mount_candidate(device: &Path, mount_point: &Path) -> Result<bool, String> {
    fs::create_dir_all(mount_point).map_err(|e| {
        format!(
            "create mount point '{}' failed: {}",
            mount_point.display(),
            e
        )
    })?;

    for fstype in SEARCH_FILESYSTEMS {
        match mount(
            Some(device),
            mount_point,
            Some(*fstype),
            MsFlags::MS_RDONLY,
            None::<&str>,
        ) {
            Ok(()) => return Ok(true),
            Err(_) => continue,
        }
    }

    match mount(
        Some(device),
        mount_point,
        None::<&str>,
        MsFlags::MS_RDONLY,
        None::<&str>,
    ) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn cleanup_mount(path: &Path) {
    let _ = umount2(path, MntFlags::MNT_DETACH);
}

fn bridge_calamares_source() -> Result<(), String> {
    let bridge = Path::new(CALAMARES_BRIDGE);

    if bridge.exists() {
        if let Ok(metadata) = fs::symlink_metadata(bridge) {
            if metadata.file_type().is_symlink() {
                let _ = fs::remove_file(bridge);
            } else if metadata.is_dir() {
                let _ = fs::remove_dir(bridge);
            } else {
                let _ = fs::remove_file(bridge);
            }
        }
    }

    symlink(LIVE_MEDIUM_MOUNT, bridge).map_err(|e| format!("create /cdrom symlink failed: {}", e))
}

/// Search all visible block devices for the Zainium live medium.
///
/// The found device is mounted read-only at `/run/live/medium` and exposed
/// through `/cdrom` so Calamares can resolve `/cdrom/zaisys/zairoot.squashfs`.
pub fn prepare_live_medium_bridge() -> Result<Option<PathBuf>, String> {
    let devices = list_all_block_devices();
    if devices.is_empty() {
        return Ok(None);
    }

    fs::create_dir_all(LIVE_SEARCH_MOUNT)
        .map_err(|e| format!("create '{}' failed: {}", LIVE_SEARCH_MOUNT, e))?;
    fs::create_dir_all(LIVE_MEDIUM_MOUNT)
        .map_err(|e| format!("create '{}' failed: {}", LIVE_MEDIUM_MOUNT, e))?;

    eprintln!(
        "Searching {} block device(s) for Zainium live medium...",
        devices.len()
    );

    for device in devices {
        eprintln!("  Probing {}...", device.display());

        if !try_mount_candidate(&device, Path::new(LIVE_SEARCH_MOUNT))? {
            continue;
        }

        let found_candidate = ZAINIUM_ROOT_IMAGE_CANDIDATES
            .iter()
            .find(|rel| Path::new(LIVE_SEARCH_MOUNT).join(rel).exists());

        if let Some(rel) = found_candidate {
            eprintln!("  ✓ Found Zainium medium on {} ({})", device.display(), rel);

            cleanup_mount(Path::new(LIVE_MEDIUM_MOUNT));
            mount(
                Some(Path::new(LIVE_SEARCH_MOUNT)),
                Path::new(LIVE_MEDIUM_MOUNT),
                None::<&str>,
                MsFlags::MS_MOVE,
                None::<&str>,
            )
            .map_err(|e| {
                format!(
                    "move '{}' → '{}' failed: {}",
                    LIVE_SEARCH_MOUNT, LIVE_MEDIUM_MOUNT, e
                )
            })?;

            bridge_calamares_source()?;

            let image_path = Path::new(LIVE_MEDIUM_MOUNT).join(rel);
            return Ok(Some(image_path));
        }

        cleanup_mount(Path::new(LIVE_SEARCH_MOUNT));
    }

    Ok(None)
}

// ── find_root ─────────────────────────────────────────────────────────────────

/// Detect and return root device path from kernel cmdline.
///
/// Retries are configurable via kernel cmdline:
/// - `rootwait`   → infinite wait (for slow USB/NVMe enumeration)
/// - `rootwait=N` → N retries × 50ms
/// - (absent)     → default 20 retries × 50ms = 1 second
#[inline]
pub fn find_root(cmdline: &Cmdline) -> Result<String, String> {
    let root_spec = cmdline.root.as_ref().ok_or("No root= parameter")?;
    println!("Searching for root: {}", root_spec);

    // Handle NFS root (e.g., root=192.168.1.1:/path)
    if root_spec.contains(':')
        && !root_spec.starts_with("UUID=")
        && !root_spec.starts_with("LABEL=")
    {
        println!("✓ NFS root detected: {}", root_spec);
        return Ok(root_spec.clone());
    }

    // Resolve LABEL= and UUID= to /dev/disk/by-*/ symlinks
    let device_path = if let Some(label) = root_spec.strip_prefix("LABEL=") {
        format!("{}{}", LABEL_PREFIX, label)
    } else if let Some(uuid) = root_spec.strip_prefix("UUID=") {
        format!("{}{}", UUID_PREFIX, uuid)
    } else {
        root_spec.clone()
    };

    // Dynamic root wait — configurable via kernel cmdline rootwait=N
    // rootwait=100 → 100 retries × 50ms = 5 seconds
    // rootwait (bare, no value) → infinite wait (0 = infinite)
    // No rootwait → default 20 retries (1 second)
    const RETRY_MS: u64 = 50;
    let max_retries: u32 = match cmdline.rootwait {
        Some(0) => u32::MAX, // rootwait (bare) — wait indefinitely
        Some(n) => n,        // rootwait=N — wait N × 50ms
        None => 20,          // default — 20 × 50ms = 1s
    };

    for attempt in 0..max_retries {
        if probe_device_fast(&device_path) {
            if attempt > 0 {
                println!(
                    "✓ Root device found (retry {}): {}",
                    attempt + 1,
                    device_path
                );
            } else {
                println!("✓ Root device: {}", device_path);
            }
            return Ok(device_path);
        }
        if attempt < max_retries - 1 {
            std::thread::sleep(std::time::Duration::from_millis(RETRY_MS));
        }
    }

    // Universal fallback strategy
    eprintln!(
        "Primary device '{}' not found — trying fallbacks...",
        device_path
    );
    list_available_devices();

    for fallback in &[
        "/dev/sda1",
        "/dev/sr0",
        "/dev/ram0",
        "/dev/sda2",
        "/dev/sda3",
        "/dev/vda1",
    ] {
        if probe_device_fast(fallback) {
            println!("✓ Fallback device: {}", fallback);
            return Ok(fallback.to_string());
        }
    }

    Err(format!(
        "No root device found (tried '{}' + fallbacks)",
        device_path
    ))
}

// ── Loop device setup via raw ioctls ─────────────────────────────────────────

/// Attach `image_path` to a free loop device using raw Linux ioctls.
///
/// This replaces `Command::new("losetup")` — no external binary required.
/// All calls are libc functions available in any musl static binary.
///
/// Returns the loop device path (e.g. `"/dev/loop0"`).
fn setup_loop_ioctl(image_path: &str) -> Result<String, String> {
    // Step 1: Open /dev/loop-control
    let ctrl_path = CString::new("/dev/loop-control").map_err(|_| "invalid loop-control path")?;

    let ctrl_fd = unsafe { libc::open(ctrl_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if ctrl_fd < 0 {
        return Err(format!(
            "open /dev/loop-control failed: {} — ensure loop nodes were created in mounts::mount_early()",
            std::io::Error::last_os_error()
        ));
    }
    let ctrl_guard = FdGuard(ctrl_fd);

    // Step 2: Get next free loop device number
    let loop_num = unsafe { libc::ioctl(ctrl_fd, LOOP_CTL_GET_FREE as _) };
    if loop_num < 0 {
        return Err(format!(
            "LOOP_CTL_GET_FREE failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    drop(ctrl_guard); // Close /dev/loop-control — no longer needed

    let loop_dev_path = format!("/dev/loop{}", loop_num);
    eprintln!(
        "  LOOP_CTL_GET_FREE → {} (device #{})",
        loop_dev_path, loop_num
    );

    // Step 3: Open /dev/loopN
    let loop_cpath =
        CString::new(loop_dev_path.as_str()).map_err(|_| "invalid loop device path")?;

    let loop_fd = unsafe { libc::open(loop_cpath.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if loop_fd < 0 {
        // Device node may not exist yet — create it on-demand (major=7, minor=loopnum)
        eprintln!("  /dev/loop{} not found — creating node...", loop_num);
        unsafe {
            libc::mknod(
                loop_cpath.as_ptr(),
                libc::S_IFBLK | 0o660,
                libc::makedev(7, loop_num as u32),
            );
        }
        let fd2 = unsafe { libc::open(loop_cpath.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd2 < 0 {
            return Err(format!(
                "open {} failed: {}",
                loop_dev_path,
                std::io::Error::last_os_error()
            ));
        }
        return attach_loop_fd(fd2, image_path, &loop_dev_path, loop_num as u32);
    }

    attach_loop_fd(loop_fd, image_path, &loop_dev_path, loop_num as u32)
}

/// Attach `image_path` to the already-open loop device fd.
///
/// Takes ownership of `loop_fd` via FdGuard (closed on error or after attach).
fn attach_loop_fd(
    loop_fd: RawFd,
    image_path: &str,
    loop_dev_path: &str,
    loop_num: u32,
) -> Result<String, String> {
    let _loop_guard = FdGuard(loop_fd);

    // Step 4: Open image file read-only
    let img_cpath = CString::new(image_path).map_err(|_| "invalid image path")?;

    let img_fd = unsafe { libc::open(img_cpath.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if img_fd < 0 {
        return Err(format!(
            "open image '{}' failed: {}",
            image_path,
            std::io::Error::last_os_error()
        ));
    }
    let img_guard = FdGuard(img_fd);

    // Step 5: LOOP_SET_FD — attach image fd to loop device
    let ret = unsafe { libc::ioctl(loop_fd, LOOP_SET_FD as _, img_fd) };
    if ret < 0 {
        return Err(format!(
            "LOOP_SET_FD failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    drop(img_guard); // kernel has the reference now, close our fd

    // Step 6: LOOP_SET_STATUS64 — record backing filename (cosmetic, ignore failure)
    let mut info: LoopInfo64 = unsafe { mem::zeroed() };
    info.lo_number = loop_num;
    info.lo_flags = 1; // LO_FLAGS_READ_ONLY
    let name_bytes = image_path.as_bytes();
    let copy_len = name_bytes.len().min(63);
    info.lo_file_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    let _ = unsafe { libc::ioctl(loop_fd, LOOP_SET_STATUS64 as _, &info as *const LoopInfo64) };

    eprintln!("  ✓ {} attached to {}", image_path, loop_dev_path);
    Ok(loop_dev_path.to_string())
}

// ── setup_loop_device ─────────────────────────────────────────────────────────

/// Mount ISO/CDROM and attach squashfs image to a loop device.
///
/// 1. Mount `root_device` (ISO9660) to `iso_mount_path`
/// 2. Find `loop_image_path` inside the ISO
/// 3. Attach it to a free loop device via `setup_loop_ioctl()`
/// 4. Return the loop device path for `mount_root()` to mount
fn setup_loop_device(
    root_device: &str,
    iso_mount_path: &str,
    loop_image_path: &str,
    _loop_fstype: Option<&str>,
) -> Result<String, String> {
    eprintln!("\nSetting up loop mount (ISO/squashfs strategy)...");

    // Step 1: Mount ISO9660 device
    eprintln!(
        "  Step 1: Mounting ISO device {} to {}...",
        root_device, iso_mount_path
    );
    fs::create_dir_all(iso_mount_path).map_err(|_| "create ISO mount dir failed")?;

    mount(
        Some(root_device),
        iso_mount_path,
        Some("iso9660"),
        MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .map_err(|e| format!("mount ISO failed: {}", e))?;
    eprintln!("  ✓ ISO mounted read-only");

    // Step 2: Verify squashfs image exists inside ISO
    let full_image_path = format!("{}{}", iso_mount_path, loop_image_path);
    eprintln!("  Step 2: Looking for image at {}...", full_image_path);

    if !Path::new(&full_image_path).exists() {
        eprintln!("  ✗ Image not found at {}", full_image_path);
        let _ = umount2(iso_mount_path, MntFlags::MNT_DETACH);
        return Err(format!("loop image not found: {}", full_image_path));
    }
    eprintln!("  ✓ Image file found");

    // Step 3: Attach image to free loop device via raw ioctls (NO losetup binary)
    eprintln!("  Step 3: Attaching {} to loop device...", loop_image_path);
    let loop_device = setup_loop_ioctl(&full_image_path).map_err(|e| {
        let _ = umount2(iso_mount_path, MntFlags::MNT_DETACH);
        format!("loop device setup failed: {}", e)
    })?;

    eprintln!("  ✓ Loop device ready: {}", loop_device);
    Ok(loop_device)
}

// ── mount_root ────────────────────────────────────────────────────────────────

fn is_luks_device(device: &str) -> Result<bool, String> {
    // Read first 6 bytes to check LUKS magic ("LUKS\xba\xbe")
    let mut file =
        fs::File::open(device).map_err(|e| format!("Cannot open device {}: {}", device, e))?;
    let mut magic = [0u8; 6];
    use std::io::Read;
    file.read_exact(&mut magic)
        .map_err(|e| format!("Cannot read device {}: {}", device, e))?;
    Ok(magic == [b'L', b'U', b'K', b'S', 0xba, 0xbe])
}

/// Open a LUKS-encrypted device and map it to /dev/mapper/<name>.
///
/// Three-tier passphrase strategy:
///   0. TPM2 unseal — silent, no user interaction (fails → next)
///   1. Keyfile from cmdline luks_keyfile= (fails → next)
///   2. Interactive passphrase on /dev/console (echo disabled)
fn open_luks_device(device: &str, name: &str, keyfile: Option<&str>) -> Result<String, String> {
    eprintln!("\n╔══════════════════════════════════════╗");
    eprintln!("║   LUKS Encrypted Device Detected     ║");
    eprintln!("╚══════════════════════════════════════╝");
    eprintln!("  Device : {}", device);
    eprintln!("  Mapping: /dev/mapper/{}", name);

    // Strategy 0: TPM2 unseal (silent — no passphrase needed)
    if crate::tpm2::tpm2_available() && crate::tpm2::tpm2_blob_exists() {
        eprintln!("  TPM2 unseal attempt...");
        match crate::tpm2::unseal_luks_key() {
            Ok(key) => {
                eprintln!("  ✓ TPM2 unseal OK — unlocking without passphrase");
                return open_luks_with_passphrase(device, name, &key);
            }
            Err(e) => {
                eprintln!("  ⚠ TPM2 unseal failed: {} — next strategy", e);
            }
        }
    }

    // Strategy 1: keyfile provided via cmdline luks_keyfile=<dev>:<path>
    if let Some(kf_spec) = keyfile {
        eprintln!("  Keyfile: {} (reading...)", kf_spec);
        match read_keyfile(kf_spec) {
            Ok(passphrase) => {
                return open_luks_with_passphrase(device, name, &passphrase);
            }
            Err(e) => {
                eprintln!(
                    "  ⚠ Keyfile read failed: {} — falling back to interactive prompt",
                    e
                );
            }
        }
    }

    // Strategy 2: Interactive passphrase prompt on /dev/console
    let passphrase = prompt_luks_passphrase(name)?;
    open_luks_with_passphrase(device, name, &passphrase)
}

/// Read keyfile from a spec like "/dev/sdb1:/luks.key" or just "/path/to/file".
///
/// Format: `<block_device>:<path_inside>` → mount block_device, read file.
/// Format: `<path>` → read directly (file already accessible).
fn read_keyfile(spec: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;

    if let Some((dev, path_inside)) = spec.split_once(':') {
        // Mount the key device read-only to a temp location
        let mount_point = "/run/luks-key-mount";
        fs::create_dir_all(mount_point).map_err(|e| format!("create mount point: {}", e))?;

        mount(
            Some(dev),
            mount_point,
            None::<&str>,
            MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|e| format!("mount keyfile device '{}': {}", dev, e))?;

        let full_path = format!("{}/{}", mount_point, path_inside.trim_start_matches('/'));
        let mut data = Vec::new();
        fs::File::open(&full_path)
            .and_then(|mut f| f.read_to_end(&mut data))
            .map_err(|e| format!("read keyfile '{}': {}", full_path, e))?;

        // Unmount — ignore errors (keyfile is in memory)
        let _ = umount2(mount_point, MntFlags::MNT_DETACH);

        Ok(data)
    } else {
        // Direct file path
        let mut data = Vec::new();
        fs::File::open(spec)
            .and_then(|mut f| f.read_to_end(&mut data))
            .map_err(|e| format!("read keyfile '{}': {}", spec, e))?;
        Ok(data)
    }
}

/// Prompt for LUKS passphrase on /dev/console with echo disabled.
///
/// Uses `tcsetattr` to turn off ECHO, reads a line, restores terminal state.
fn prompt_luks_passphrase(name: &str) -> Result<Vec<u8>, String> {
    use std::io::{Read, Write};

    let mut console = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/console")
        .map_err(|e| format!("open /dev/console: {}", e))?;

    write!(console, "\n  Enter LUKS passphrase for '{}': ", name)
        .map_err(|e| format!("write prompt: {}", e))?;
    console.flush().map_err(|e| format!("flush: {}", e))?;

    // Disable echo via termios
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&console);
    let mut termios = unsafe { std::mem::zeroed::<libc::termios>() };
    unsafe { libc::tcgetattr(fd, &mut termios) };
    let old_termios = termios;
    termios.c_lflag &= !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL);
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) };

    let mut passphrase = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match console.read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if byte[0] == b'\n' || byte[0] == b'\r' {
                    break;
                }
                passphrase.push(byte[0]);
            }
        }
    }

    // Restore echo
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old_termios) };
    writeln!(console).ok(); // newline after hidden input

    if passphrase.is_empty() {
        return Err("Empty passphrase — aborting LUKS open".to_string());
    }

    Ok(passphrase)
}

/// Call `cryptsetup luksOpen` with the passphrase provided on stdin.
///
/// We use `cryptsetup` if present (most reliable, supports all LUKS versions).
/// The passphrase is piped via stdin so it never appears in /proc/cmdline or ps.
fn open_luks_with_passphrase(
    device: &str,
    name: &str,
    passphrase: &[u8],
) -> Result<String, String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // Find cryptsetup
    let cryptsetup = if std::path::Path::new("/sbin/cryptsetup").exists() {
        "/sbin/cryptsetup"
    } else if std::path::Path::new("/usr/sbin/cryptsetup").exists() {
        "/usr/sbin/cryptsetup"
    } else {
        return Err(
            "cryptsetup not found at /sbin/cryptsetup or /usr/sbin/cryptsetup. \
                    Install cryptsetup in initramfs or compile with dm-crypt ioctl support."
                .to_string(),
        );
    };

    let mut child = Command::new(cryptsetup)
        .args(["luksOpen", "--key-file=-", "--batch-mode", device, name])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cryptsetup spawn failed: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(passphrase).ok();
        // passphrase is zeroed from memory on drop
    }

    let status = child
        .wait()
        .map_err(|e| format!("cryptsetup wait: {}", e))?;

    if status.success() {
        let mapped = format!("/dev/mapper/{}", name);
        eprintln!("  ✓ LUKS device opened: {}", mapped);
        Ok(mapped)
    } else {
        Err(format!(
            "cryptsetup luksOpen failed (exit {}). Wrong passphrase?",
            status.code().unwrap_or(-1)
        ))
    }
}

/// Mount root filesystem to `/mnt/root`.
///
/// Detects device type and applies correct mount strategy:
/// - ISO/CDROM + loop=: ISO9660 → loop ioctl → squashfs mount
/// - Ramdisk: explicit filesystem candidates with fallback
/// - Partition (HDD/SSD/NVMe): explicit `rootfstype=` with fallback candidates
/// - Unknown: explicit `rootfstype=` first, then fallback candidates
///
/// Flexible variant that mounts to `mount_target` (e.g. `/zairoot`, `/mnt/root`, `/sysroot`)
/// instead of the hardcoded `/mnt/root`. Called from main.rs with the discovered mount point.
pub fn mount_root_at(device: &str, cmdline: &Cmdline, mount_target: &str) -> Result<(), String> {
    mount_root_impl(device, cmdline, mount_target)
}

/// Original convenience wrapper — kept for backward compat; uses `/mnt/root`.
#[allow(dead_code)]
pub fn mount_root(device: &str, cmdline: &Cmdline) -> Result<(), String> {
    mount_root_impl(device, cmdline, "/mnt/root")
}

#[inline]
fn mount_root_impl(device: &str, cmdline: &Cmdline, mount_target: &str) -> Result<(), String> {
    println!("\n🔧 Root Mount Strategy (target: {})\n", mount_target);

    fs::create_dir_all(mount_target)
        .map_err(|e| format!("create '{}' failed: {}", mount_target, e))?;

    // Check if device is LUKS encrypted
    let actual_device = if is_luks_device(device)? {
        eprintln!("Device {} is LUKS encrypted", device);
        if let Some(luks_name) = &cmdline.luks_name {
            open_luks_device(device, luks_name, cmdline.luks_keyfile.as_deref())?
        } else {
            return Err("LUKS device detected but no luks_name= parameter provided".to_string());
        }
    } else {
        device.to_string()
    };

    let device_type = if actual_device.contains(':') {
        "NFS"
    } else if actual_device.starts_with("/dev/sr")
        || actual_device.starts_with("/dev/cdrom")
        || actual_device.starts_with("/dev/dvd")
    {
        "ISO_CDROM"
    } else if actual_device.starts_with("/dev/ram") {
        "RAMDISK"
    } else if actual_device.starts_with("/dev/sd")
        || actual_device.starts_with("/dev/nvme")
        || actual_device.starts_with("/dev/vd")
        || actual_device.starts_with("/dev/mmcblk")
        || actual_device.starts_with("/dev/hd")
        || actual_device.starts_with("/dev/xvd")
        || actual_device.starts_with("/dev/disk/")
        || actual_device.starts_with("/dev/mapper/")
    {
        "PARTITION"
    } else {
        "UNKNOWN"
    };

    eprintln!("Device: {}  Type: {}", actual_device, device_type);

    let explicit_root_fstype = cmdline.root_fstype.as_deref();

    match device_type {
        "NFS" => {
            eprintln!("Strategy: NFS mount");
            mount(
                Some(actual_device.as_str()),
                mount_target,
                Some("nfs"),
                MsFlags::empty(),
                None::<&str>,
            )
            .map_err(|e| format!("NFS mount failed: {}", e))?;
            eprintln!("✓ NFS mounted to {}\n", mount_target);
        }
        "ISO_CDROM" => {
            eprintln!("Strategy: ISO9660 → loop ioctl → root image");

            if let (Some(loop_image), loop_fstype) = (&cmdline.loop_image, &cmdline.loop_fstype) {
                eprintln!(
                    "Loop image: {} (fstype: {})",
                    loop_image,
                    loop_fstype.as_deref().unwrap_or("auto")
                );

                let loop_device =
                    setup_loop_device(device, "/mnt/iso-root", loop_image, loop_fstype.as_deref())?;

                // No loopfstype= supplied — guess from the image filename, since
                // eclipse-iso-builder now emits EROFS (.img) by default and
                // SquashFS (.squashfs) only when built with --format squashfs.
                let mount_fstype = loop_fstype.as_deref().unwrap_or_else(|| {
                    let guess = if loop_image.ends_with(".squashfs") {
                        "squashfs"
                    } else {
                        "erofs"
                    };
                    eprintln!(
                        "  No loopfstype= supplied, guessing '{}' from image name",
                        guess
                    );
                    guess
                });

                eprintln!("\n  Mounting {} to {}...", loop_device, mount_target);
                mount(
                    Some(loop_device.as_str()),
                    mount_target,
                    Some(mount_fstype),
                    MsFlags::MS_RDONLY,
                    None::<&str>,
                )
                .map_err(|e| {
                    format!("mount loop device failed: {} (device: {})", e, loop_device)
                })?;

                eprintln!("✓ Loop device mounted to {}\n", mount_target);
            } else {
                eprintln!("No loop= parameter — trying direct ISO9660 mount...");
                mount(
                    Some(device),
                    mount_target,
                    Some("iso9660"),
                    MsFlags::MS_RDONLY,
                    None::<&str>,
                )
                .map_err(|e| format!("direct ISO mount failed: {}", e))?;
                eprintln!("✓ ISO mounted to {}\n", mount_target);
            }
        }

        "RAMDISK" => {
            eprintln!("Strategy: Ramdisk → explicit filesystem with fallback");

            if !try_mount_root_candidates(
                device,
                explicit_root_fstype,
                mount_target,
                &["ext4", "erofs", "squashfs", "tmpfs"],
            ) {
                return Err(format!(
                    "ramdisk mount failed after filesystem attempts: {}",
                    device
                ));
            }

            eprintln!("✓ Ramdisk mounted\n");
        }

        "PARTITION" | "UNKNOWN" => {
            // Btrfs subvolume: if rootfstype=btrfs and rootflags= has subvol=
            if explicit_root_fstype == Some("btrfs") {
                eprintln!("Strategy: Partition → Btrfs subvolume");
                return crate::fsck::mount_btrfs_subvol(
                    actual_device.as_str(),
                    mount_target,
                    cmdline.root_flags.as_deref(),
                );
            }

            if let Some(fstype) = explicit_root_fstype {
                eprintln!(
                    "Strategy: Partition → explicit rootfstype={} with fallback",
                    fstype
                );
            } else {
                eprintln!("Strategy: Partition → fallback candidates (no rootfstype= provided)");
            }

            if !try_mount_root_candidates(
                device,
                explicit_root_fstype,
                mount_target,
                &[
                    "ext4", "erofs", "xfs", "btrfs", "f2fs", "vfat", "ntfs", "exfat", "zfs",
                ],
            ) {
                return Err(format!(
                    "partition mount failed after filesystem attempts: {}",
                    device
                ));
            }

            eprintln!("✓ Partition mounted\n");
        }

        _ => unreachable!(),
    }

    println!("✓ Root filesystem mounted at {}\n", mount_target);
    Ok(())
}

#[inline]
fn try_mount_root_candidates(
    device: &str,
    explicit_root_fstype: Option<&str>,
    mount_target: &str,
    fallback_fs: &[&str],
) -> bool {
    let mut candidates: Vec<&str> = Vec::new();

    if let Some(fstype) = explicit_root_fstype {
        candidates.push(fstype);
    }

    for &fstype in fallback_fs {
        if !candidates.contains(&fstype) {
            candidates.push(fstype);
        }
    }

    for fstype in candidates {
        eprintln!("  Trying mount {} as {}...", device, fstype);
        match mount(
            Some(device),
            mount_target,
            Some(fstype),
            MsFlags::empty(),
            None::<&str>,
        ) {
            Ok(_) => {
                eprintln!("  ✓ Mounted {} as {}", device, fstype);
                return true;
            }
            Err(e) => {
                eprintln!("  ⚠ mount as {} failed: {}", fstype, e);
            }
        }
    }

    eprintln!("  Trying auto-detect mount {}...", device);
    match mount(
        Some(device),
        mount_target,
        None::<&str>,
        MsFlags::empty(),
        None::<&str>,
    ) {
        Ok(_) => {
            eprintln!("  ✓ Mounted {} using auto-detect", device);
            true
        }
        Err(e) => {
            eprintln!("  ⚠ auto-detect mount failed: {}", e);
            false
        }
    }
}

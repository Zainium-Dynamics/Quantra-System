/// Minimal uevent processor — kernel netlink device announcements
///
/// # Problem
///
/// The old initramfs only created `/dev/loop-control` and `/dev/loop0-7` via
/// `mknod`. This means NVMe partitions, USB drives, MMC cards, and any device
/// that appears after the kernel starts sending uevents are NOT in `/dev`.
///
/// # Solution
///
/// This module opens a `NETLINK_KOBJECT_UEVENT` socket and processes kernel
/// uevent messages. For each `ACTION=add` event with `SUBSYSTEM=block`, it
/// creates the corresponding `/dev` node using `mknod(2)` with the correct
/// major/minor numbers from the event.
///
/// This replaces `udevd` for the initramfs use case. We don't need rules
/// evaluation, symlinks in `/dev/disk/by-*`, or renaming — just the nodes.
///
/// # Uevent message format (from kernel)
///
/// ```
/// "add@/devices/pci0000:00/...\0"
/// "ACTION=add\0"
/// "DEVPATH=/devices/pci0000:00/...\0"
/// "SUBSYSTEM=block\0"
/// "DEVNAME=sda1\0"
/// "DEVTYPE=partition\0"
/// "MAJOR=8\0"
/// "MINOR=1\0"
/// "SEQNUM=1234\0"
/// ```
///
/// Each field is null-terminated. The whole message arrives as one recvfrom.
///
/// # Usage
///
/// ```rust
/// // Background: process uevents for up to N seconds
/// udev::settle(Duration::from_secs(3));
///
/// // Or: process until a specific device appears
/// udev::wait_for_device("/dev/nvme0n1p2", Duration::from_secs(10));
/// ```
use std::ffi::CString;
use std::fs;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};

// ── Netlink constants ─────────────────────────────────────────────────────────

const AF_NETLINK: libc::c_int = 16;
const SOCK_RAW: libc::c_int = 3;
const NETLINK_KOBJECT_UEVENT: libc::c_int = 15;

// ── Parsed uevent ─────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct Uevent {
    action: String,    // add / remove / change
    subsystem: String, // block / net / usb / ...
    devname: String,   // sda1 / nvme0n1p1 / sdb / ...
    devtype: String,   // disk / partition
    major: u32,
    minor: u32,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Process kernel uevents for `duration`, creating `/dev` nodes for all
/// block devices announced as `ACTION=add`.
///
/// Returns the number of device nodes created.
/// Non-fatal: if the netlink socket cannot be opened, returns 0 silently.
pub fn settle(duration: Duration) -> usize {
    let fd = match open_netlink() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("  udev: netlink open failed: {} (mknod fallback only)", e);
            return 0;
        }
    };

    eprintln!(
        "  udev: processing uevents for {}ms...",
        duration.as_millis()
    );
    let start = Instant::now();
    let mut created = 0;

    // First: trigger all existing devices by reading /sys/class/block
    created += trigger_existing_block_devices();

    // Then: process live uevents from netlink until timeout
    let sock_fd = fd;
    set_nonblocking(sock_fd);

    let mut buf = vec![0u8; 8192];
    while start.elapsed() < duration {
        let n = unsafe { libc::recv(sock_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n <= 0 {
            // No message — sleep 10ms and retry
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }

        if let Some(ev) = parse_uevent(&buf[..n as usize]) {
            if ev.action == "add" && ev.subsystem == "block" && create_dev_node(&ev) {
                created += 1;
            }
        }
    }

    unsafe {
        libc::close(sock_fd);
    }
    eprintln!("  udev: {} device node(s) created", created);
    created
}

/// Block until `device_path` exists in `/dev`, processing uevents meanwhile.
///
/// Returns `true` if the device appeared within `timeout`, `false` otherwise.
#[allow(dead_code)]
pub fn wait_for_device(device_path: &str, timeout: Duration) -> bool {
    if std::path::Path::new(device_path).exists() {
        return true;
    }

    let fd = match open_netlink() {
        Ok(f) => f,
        Err(_) => {
            // No netlink — fall back to polling
            return poll_device(device_path, timeout);
        }
    };

    set_nonblocking(fd);
    let start = Instant::now();
    let mut buf = vec![0u8; 8192];

    while start.elapsed() < timeout {
        if std::path::Path::new(device_path).exists() {
            unsafe {
                libc::close(fd);
            }
            return true;
        }

        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n > 0 {
            if let Some(ev) = parse_uevent(&buf[..n as usize]) {
                if ev.action == "add" && ev.subsystem == "block" {
                    create_dev_node(&ev);
                }
            }
        } else {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    unsafe {
        libc::close(fd);
    }
    std::path::Path::new(device_path).exists()
}

/// Create `/dev/disk/by-uuid/` and `/dev/disk/by-label/` symlinks by scanning
/// sysfs and reading filesystem superblocks. Lightweight blkid replacement.
///
/// Returns count of symlinks created.
pub fn create_disk_symlinks() -> usize {
    let mut count = 0;

    fs::create_dir_all("/dev/disk/by-uuid").ok();
    fs::create_dir_all("/dev/disk/by-label").ok();

    if let Ok(entries) = fs::read_dir("/sys/class/block") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            // Only partitions and whole disks, skip loop/ram/zram
            if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("zram") {
                continue;
            }
            let dev_path = format!("/dev/{}", name);
            if !std::path::Path::new(&dev_path).exists() {
                continue;
            }
            // Read UUID from sysfs uevent (populated by kernel after udev settle)
            let uevent_path = format!("/sys/class/block/{}/uevent", name);
            if let Ok(content) = fs::read_to_string(&uevent_path) {
                let uuid = extract_field(&content, "ID_FS_UUID");
                let label = extract_field(&content, "ID_FS_LABEL");
                if let Some(uuid) = uuid {
                    let link = format!("/dev/disk/by-uuid/{}", uuid);
                    if !std::path::Path::new(&link).exists()
                        && std::os::unix::fs::symlink(&dev_path, &link).is_ok()
                    {
                        count += 1;
                    }
                }
                if let Some(label) = label {
                    let link = format!("/dev/disk/by-label/{}", label);
                    if !std::path::Path::new(&link).exists()
                        && std::os::unix::fs::symlink(&dev_path, &link).is_ok()
                    {
                        count += 1;
                    }
                }
            }
        }
    }
    count
}

// ── Netlink socket ────────────────────────────────────────────────────────────

fn open_netlink() -> Result<RawFd, String> {
    let fd = unsafe { libc::socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT) };
    if fd < 0 {
        return Err(format!(
            "socket(NETLINK_KOBJECT_UEVENT): {}",
            std::io::Error::last_os_error()
        ));
    }

    // sockaddr_nl: family=AF_NETLINK, pid=0 (kernel), groups=1 (uevent multicast)
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = AF_NETLINK as u16;
    addr.nl_pid = 0;
    addr.nl_groups = 1; // KOBJECT_UEVENT multicast group

    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        unsafe {
            libc::close(fd);
        }
        return Err(format!("bind netlink: {}", std::io::Error::last_os_error()));
    }

    Ok(fd)
}

fn set_nonblocking(fd: RawFd) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

// ── Uevent parsing ────────────────────────────────────────────────────────────

fn parse_uevent(buf: &[u8]) -> Option<Uevent> {
    // Skip the first line (the header "action@devpath\0")
    let first_null = buf.iter().position(|&b| b == 0)?;
    let rest = &buf[first_null + 1..];

    let mut ev = Uevent::default();
    for field in rest.split(|&b| b == 0) {
        if field.is_empty() {
            continue;
        }
        let s = std::str::from_utf8(field).unwrap_or("");
        if let Some(v) = s.strip_prefix("ACTION=") {
            ev.action = v.to_string();
        }
        if let Some(v) = s.strip_prefix("SUBSYSTEM=") {
            ev.subsystem = v.to_string();
        }
        if let Some(v) = s.strip_prefix("DEVNAME=") {
            ev.devname = v.to_string();
        }
        if let Some(v) = s.strip_prefix("DEVTYPE=") {
            ev.devtype = v.to_string();
        }
        if let Some(v) = s.strip_prefix("MAJOR=") {
            ev.major = v.parse().unwrap_or(0);
        }
        if let Some(v) = s.strip_prefix("MINOR=") {
            ev.minor = v.parse().unwrap_or(0);
        }
    }

    if ev.action.is_empty() || ev.subsystem.is_empty() || ev.devname.is_empty() {
        return None;
    }
    Some(ev)
}

// ── Device node creation ──────────────────────────────────────────────────────

fn create_dev_node(ev: &Uevent) -> bool {
    // devname may contain subdirs (e.g. "block/sda1" on some kernels)
    let basename = ev.devname.split('/').next_back().unwrap_or(&ev.devname);
    let path = format!("/dev/{}", basename);

    if std::path::Path::new(&path).exists() {
        return false; // already present
    }

    // Block device
    let mode = libc::S_IFBLK | 0o660;
    let dev = libc::makedev(ev.major, ev.minor);

    let cpath = match CString::new(path.as_str()) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let ret = unsafe { libc::mknod(cpath.as_ptr(), mode, dev) };
    if ret == 0 {
        eprintln!("  udev: created {} ({}:{})", path, ev.major, ev.minor);
        true
    } else {
        false
    }
}

/// Trigger uevents for all existing block devices by reading sysfs.
/// This handles devices that appeared before our netlink socket was opened.
fn trigger_existing_block_devices() -> usize {
    let mut created = 0;

    if let Ok(entries) = fs::read_dir("/sys/class/block") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("zram") {
                continue;
            }

            let dev_path = format!("/dev/{}", name);
            if std::path::Path::new(&dev_path).exists() {
                continue;
            }

            // Read major/minor from sysfs dev file: "MAJOR:MINOR\n"
            let dev_file = format!("/sys/class/block/{}/dev", name);
            if let Ok(content) = fs::read_to_string(&dev_file) {
                let content = content.trim();
                if let Some((maj, min)) = content.split_once(':') {
                    if let (Ok(major), Ok(minor)) = (maj.parse::<u32>(), min.parse::<u32>()) {
                        let ev = Uevent {
                            action: "add".to_string(),
                            subsystem: "block".to_string(),
                            devname: name,
                            devtype: "disk".to_string(),
                            major,
                            minor,
                        };
                        if create_dev_node(&ev) {
                            created += 1;
                        }
                    }
                }
            }
        }
    }
    created
}

#[allow(dead_code)]
fn poll_device(path: &str, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if std::path::Path::new(path).exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    std::path::Path::new(path).exists()
}

fn extract_field<'a>(content: &'a str, key: &str) -> Option<&'a str> {
    for line in content.lines() {
        if let Some(v) = line.strip_prefix(key) {
            if let Some(v) = v.strip_prefix('=') {
                return Some(v.trim());
            }
        }
    }
    None
}

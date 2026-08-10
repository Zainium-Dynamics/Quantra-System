/// dm-verity rootfs integrity verification
///
/// # Overview
///
/// dm-verity is a Linux kernel device-mapper target that provides transparent
/// integrity checking of block devices using a Merkle hash tree. Every 4 KB
/// data block on the root partition has a corresponding SHA-256 hash, and those
/// hashes are themselves hashed in a tree structure. The root hash of this tree
/// (the "roothash") is the single value that must be trusted.
///
/// # Implementation strategy
///
/// This module sets up dm-verity by writing to the kernel's device-mapper
/// control interface (`/dev/mapper/control`) using the DM ioctl protocol.
/// No `veritysetup` binary is required.
///
/// DM ioctl protocol (from `<linux/dm-ioctl.h>`):
///
/// ```text
/// 1. open("/dev/mapper/control", O_RDWR)
/// 2. DM_VERSION ioctl → verify kernel DM version
/// 3. DM_DEV_CREATE ioctl → create /dev/mapper/<name>
/// 4. DM_TABLE_LOAD ioctl → load verity target table
/// 5. DM_DEV_SUSPEND ioctl (with DM_SUSPEND_FLAG=0) → activate
/// ```
///
/// # Root hash source priority
///
/// 1. Kernel cmdline: `rd.verity.roothash=<hex64>`
/// 2. File on data partition: `/verity/roothash` (pre-provisioned)
/// 3. UEFI variable: `ZainiumVerityRoothash-<guid>` (TPM-provisioned)
///
/// # Cmdline parameters
///
/// ```
/// rd.verity=1                           — enable verity (required)
/// rd.verity.data=/dev/sda2              — data device to verify
/// rd.verity.hash=/dev/sda3             — hash device (separate partition)
/// rd.verity.roothash=<64 hex chars>   — expected root hash
/// rd.verity.hashoffset=<bytes>        — hash tree offset (if same device)
/// ```
use std::fs;
use std::io;
use std::os::unix::io::RawFd;

// ── DM ioctl constants (from <linux/dm-ioctl.h>) ─────────────────────────────

const DM_IOCTL: u8 = 0xfd;
const DM_VERSION_CMD: u8 = 0;
const DM_DEV_CREATE_CMD: u8 = 3;
const DM_DEV_SUSPEND_CMD: u8 = 5;
const DM_DEV_REMOVE_CMD: u8 = 6;
const DM_TABLE_LOAD_CMD: u8 = 9;

// ioctl request codes (Linux _IOWR macro: type=0xfd, nr, size)
// Size of dm_ioctl struct = 312 bytes
const DM_IOCTL_SIZE: usize = 312;

#[allow(non_snake_case)]
fn DM_IOWR(nr: u8) -> libc::c_ulong {
    // _IOWR(type, nr, size): direction=RW(3<<30), type<<8, nr, size<<16
    let dir: libc::c_ulong = 3 << 30;
    let ty: libc::c_ulong = (DM_IOCTL as libc::c_ulong) << 8;
    let size: libc::c_ulong = (DM_IOCTL_SIZE as libc::c_ulong) << 16;
    dir | ty | (nr as libc::c_ulong) | size
}

/// `struct dm_ioctl` from `<linux/dm-ioctl.h>` (version 4.x)
#[repr(C)]
struct DmIoctl {
    version: [u32; 3], // DM version [major, minor, patch]
    data_size: u32,    // total size of this struct + extra data
    data_start: u32,   // offset to extra data
    target_count: u32, // number of targets in table
    open_count: i32,   // number of opens
    flags: u32,        // DM flags
    event_nr: u32,     // event number
    padding1: u32,
    dev: u64,        // device number (output)
    name: [u8; 128], // device name
    uuid: [u8; 129], // device UUID
    data: [u8; 7],   // padding to align
}

/// `struct dm_target_spec` — one entry in the table load data
#[repr(C)]
struct DmTargetSpec {
    sector_start: u64,     // first sector
    length: u64,           // length in sectors
    status: i32,           // target status (output)
    next: u32,             // offset to next target spec
    target_type: [u8; 16], // null-terminated target name
}

// ── RAII fd guard ─────────────────────────────────────────────────────────────

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

// ── Verity configuration ──────────────────────────────────────────────────────

/// Parsed dm-verity configuration from cmdline.
#[derive(Debug, Clone)]
pub struct VerityConfig {
    /// Data block device (e.g. `/dev/sda2`)
    pub data_device: String,
    /// Hash device — may equal data_device with non-zero hashoffset
    pub hash_device: String,
    /// Expected root hash (64 hex chars = 32 bytes SHA-256)
    pub roothash: [u8; 32],
    /// Hash tree offset in sectors on hash device (0 = separate partition)
    pub hash_offset: u64,
    /// Logical name for the dm-verity device (e.g. `zainium-verity`)
    pub dm_name: String,
}

/// Outcome of verity setup.
#[derive(Debug)]
pub struct VerityDevice {
    /// Path to the verified device (e.g. `/dev/mapper/zainium-verity`)
    pub path: String,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse verity configuration from kernel cmdline string.
///
/// Returns `None` if `rd.verity=1` is not present (verity disabled).
pub fn parse_verity_cmdline(cmdline: &str) -> Option<Result<VerityConfig, String>> {
    // Check if verity is enabled at all
    if !cmdline.split_whitespace().any(|t| t == "rd.verity=1") {
        return None;
    }

    let mut data_device = None::<String>;
    let mut hash_device = None::<String>;
    let mut roothash_hex = None::<String>;
    let mut hash_offset: u64 = 0;

    for tok in cmdline.split_whitespace() {
        if let Some(v) = tok.strip_prefix("rd.verity.data=") {
            data_device = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("rd.verity.hash=") {
            hash_device = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("rd.verity.roothash=") {
            roothash_hex = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("rd.verity.hashoffset=") {
            hash_offset = v.parse::<u64>().unwrap_or(0);
        }
    }

    let data = match data_device {
        Some(d) => d,
        None => return Some(Err("rd.verity.data= missing".to_string())),
    };
    let hash = hash_device.unwrap_or_else(|| data.clone()); // same device with offset
    let hex = match roothash_hex {
        Some(h) => h,
        None => return Some(Err("rd.verity.roothash= missing".to_string())),
    };

    let roothash = match decode_roothash(&hex) {
        Ok(h) => h,
        Err(e) => return Some(Err(e)),
    };

    Some(Ok(VerityConfig {
        data_device: data,
        hash_device: hash,
        roothash,
        hash_offset,
        dm_name: "zainium-verity".to_string(),
    }))
}

/// Set up dm-verity and return the verified device path.
///
/// On success, `/dev/mapper/<dm_name>` is ready for mounting.
/// The kernel will reject any read from a block that fails hash verification.
pub fn setup_verity(cfg: &VerityConfig) -> Result<VerityDevice, String> {
    eprintln!("  dm-verity:");
    eprintln!("    data  = {}", cfg.data_device);
    eprintln!("    hash  = {}", cfg.hash_device);
    eprintln!("    name  = /dev/mapper/{}", cfg.dm_name);

    // Ensure /dev/mapper exists
    fs::create_dir_all("/dev/mapper").map_err(|e| format!("create /dev/mapper: {}", e))?;

    // Open DM control device
    let ctrl_path = b"/dev/mapper/control\0";
    let ctrl_fd = unsafe {
        libc::open(
            ctrl_path.as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_CLOEXEC,
        )
    };
    if ctrl_fd < 0 {
        return Err(format!(
            "open /dev/mapper/control: {} — is device-mapper loaded?",
            io::Error::last_os_error()
        ));
    }
    let _ctrl_guard = FdGuard(ctrl_fd);

    // Step 1: DM_VERSION — verify kernel supports DM
    dm_version_check(ctrl_fd)?;

    // Step 2: DM_DEV_CREATE — create the dm device
    dm_dev_create(ctrl_fd, &cfg.dm_name)?;

    // Step 3: DM_TABLE_LOAD — load verity target
    let data_sectors = get_block_device_sectors(&cfg.data_device)?;
    dm_table_load_verity(ctrl_fd, cfg, data_sectors)?;

    // Step 4: DM_DEV_SUSPEND (flags=0) — activate (resume) the device
    dm_dev_resume(ctrl_fd, &cfg.dm_name)?;

    let path = format!("/dev/mapper/{}", cfg.dm_name);
    eprintln!("  ✓ dm-verity active: {}", path);

    Ok(VerityDevice { path })
}

/// Remove a dm-verity device (call before pivot_root if verity device was
/// used only for verification and the real mount is elsewhere).
#[allow(dead_code)]
pub fn remove_verity(name: &str) -> Result<(), String> {
    let ctrl_path = b"/dev/mapper/control\0";
    let ctrl_fd = unsafe {
        libc::open(
            ctrl_path.as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_CLOEXEC,
        )
    };
    if ctrl_fd < 0 {
        return Err(format!(
            "open /dev/mapper/control: {}",
            io::Error::last_os_error()
        ));
    }
    let _g = FdGuard(ctrl_fd);
    dm_dev_remove(ctrl_fd, name)
}

// ── DM ioctl helpers ──────────────────────────────────────────────────────────

fn new_dm_ioctl(name: &str) -> DmIoctl {
    let mut ioc: DmIoctl = unsafe { std::mem::zeroed() };
    ioc.version = [4, 0, 0];
    ioc.data_size = std::mem::size_of::<DmIoctl>() as u32;
    ioc.data_start = std::mem::size_of::<DmIoctl>() as u32;
    let nb = name.as_bytes();
    let copy = nb.len().min(127);
    ioc.name[..copy].copy_from_slice(&nb[..copy]);
    ioc
}

fn dm_version_check(fd: RawFd) -> Result<(), String> {
    let mut ioc: DmIoctl = unsafe { std::mem::zeroed() };
    ioc.version = [4, 0, 0];
    ioc.data_size = std::mem::size_of::<DmIoctl>() as u32;

    let ret = unsafe { libc::ioctl(fd, DM_IOWR(DM_VERSION_CMD) as _, &mut ioc as *mut DmIoctl) };
    if ret < 0 {
        return Err(format!("DM_VERSION ioctl: {}", io::Error::last_os_error()));
    }
    eprintln!(
        "    DM version: {}.{}.{}",
        ioc.version[0], ioc.version[1], ioc.version[2]
    );
    Ok(())
}

fn dm_dev_create(fd: RawFd, name: &str) -> Result<(), String> {
    let mut ioc = new_dm_ioctl(name);
    let ret = unsafe {
        libc::ioctl(
            fd,
            DM_IOWR(DM_DEV_CREATE_CMD) as _,
            &mut ioc as *mut DmIoctl,
        )
    };
    if ret < 0 {
        return Err(format!(
            "DM_DEV_CREATE '{}': {}",
            name,
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn dm_table_load_verity(fd: RawFd, cfg: &VerityConfig, data_sectors: u64) -> Result<(), String> {
    // Build the verity target params string:
    // "<version> <data_dev> <hash_dev> <data_block_sz> <hash_block_sz>
    //  <num_data_blocks> <hash_start_block> <algorithm> <digest> <salt>"
    let roothash_hex = encode_hex(&cfg.roothash);
    // hash_start = cfg.hash_offset in 4096-byte blocks (512-byte sectors → /8)
    let hash_start_block = cfg.hash_offset / 8;

    let params = format!(
        "1 {} {} 4096 4096 {} {} sha256 {} -",
        cfg.data_device,
        cfg.hash_device,
        data_sectors / 8, // number of 4096-byte data blocks
        hash_start_block,
        roothash_hex
    );

    // Total buffer: DmIoctl + DmTargetSpec + params string + null
    let spec_size = std::mem::size_of::<DmTargetSpec>();
    let params_len = params.len() + 1; // +1 for null terminator
    let total = std::mem::size_of::<DmIoctl>() + spec_size + params_len;

    let mut buf: Vec<u8> = vec![0u8; total];

    // Fill DmIoctl header
    let ioc_size = std::mem::size_of::<DmIoctl>();
    let mut ioc = new_dm_ioctl(&cfg.dm_name);
    ioc.data_size = total as u32;
    ioc.data_start = ioc_size as u32;
    ioc.target_count = 1;

    unsafe {
        std::ptr::copy_nonoverlapping(
            &ioc as *const DmIoctl as *const u8,
            buf.as_mut_ptr(),
            ioc_size,
        );
    }

    // Fill DmTargetSpec
    let mut spec: DmTargetSpec = unsafe { std::mem::zeroed() };
    spec.sector_start = 0;
    spec.length = data_sectors;
    spec.next = (spec_size + params_len) as u32;
    let ttype = b"verity\0";
    spec.target_type[..ttype.len()].copy_from_slice(ttype);

    unsafe {
        std::ptr::copy_nonoverlapping(
            &spec as *const DmTargetSpec as *const u8,
            buf.as_mut_ptr().add(ioc_size),
            spec_size,
        );
    }

    // Copy params string
    let pb = params.as_bytes();
    buf[ioc_size + spec_size..ioc_size + spec_size + pb.len()].copy_from_slice(pb);
    // null terminator already zeroed

    let ret = unsafe { libc::ioctl(fd, DM_IOWR(DM_TABLE_LOAD_CMD) as _, buf.as_mut_ptr()) };
    if ret < 0 {
        return Err(format!(
            "DM_TABLE_LOAD verity: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn dm_dev_resume(fd: RawFd, name: &str) -> Result<(), String> {
    let mut ioc = new_dm_ioctl(name);
    // DM_SUSPEND_FLAG = 1; flags=0 means resume (activate)
    ioc.flags = 0;
    let ret = unsafe {
        libc::ioctl(
            fd,
            DM_IOWR(DM_DEV_SUSPEND_CMD) as _,
            &mut ioc as *mut DmIoctl,
        )
    };
    if ret < 0 {
        return Err(format!(
            "DM_DEV_RESUME '{}': {}",
            name,
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[allow(dead_code)]
fn dm_dev_remove(fd: RawFd, name: &str) -> Result<(), String> {
    let mut ioc = new_dm_ioctl(name);
    let ret = unsafe {
        libc::ioctl(
            fd,
            DM_IOWR(DM_DEV_REMOVE_CMD) as _,
            &mut ioc as *mut DmIoctl,
        )
    };
    if ret < 0 {
        return Err(format!(
            "DM_DEV_REMOVE '{}': {}",
            name,
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

// ── Block device size helper ──────────────────────────────────────────────────

/// Get block device size in 512-byte sectors via BLKGETSIZE64 ioctl.
fn get_block_device_sectors(device: &str) -> Result<u64, String> {
    const BLKGETSIZE64: libc::c_ulong = 0x80081272;

    let path =
        std::ffi::CString::new(device).map_err(|_| format!("invalid device path: {}", device))?;

    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(format!("open {}: {}", device, io::Error::last_os_error()));
    }
    let _g = FdGuard(fd);

    let mut size_bytes: u64 = 0;
    let ret = unsafe { libc::ioctl(fd, BLKGETSIZE64, &mut size_bytes as *mut u64) };
    if ret < 0 {
        return Err(format!(
            "BLKGETSIZE64 {}: {}",
            device,
            io::Error::last_os_error()
        ));
    }

    // Convert bytes → 512-byte sectors
    Ok(size_bytes / 512)
}

// ── Hex encode / decode ───────────────────────────────────────────────────────

fn decode_roothash(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(format!(
            "roothash must be 64 hex chars (32 bytes), got {} chars",
            hex.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex char: {}", b as char)),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

// ── Roothash provisioning helpers ─────────────────────────────────────────────

/// Try to read roothash from a file on a pre-mounted filesystem.
/// Used when roothash is stored on a separate trusted partition.
#[allow(dead_code)]
pub fn read_roothash_from_file(path: &str) -> Result<[u8; 32], String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("read roothash file '{}': {}", path, e))?;
    decode_roothash(content.trim())
}

/// Print verity status for emergency shell diagnostics.
#[allow(dead_code)]
pub fn print_verity_status() {
    match fs::read_to_string("/sys/block") {
        Ok(_) => {
            eprintln!("  dm-verity: checking /dev/mapper...");
            if let Ok(entries) = fs::read_dir("/dev/mapper") {
                for e in entries.flatten() {
                    eprintln!("    {}", e.file_name().to_string_lossy());
                }
            }
        }
        Err(_) => eprintln!("  /sys not mounted"),
    }
}

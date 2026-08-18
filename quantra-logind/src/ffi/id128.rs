//! sd-id128.h subset: machine and boot identifiers.
//!
//! No quantra-logind dependency. Both read straight from the same
//! kernel/OS-level files systemd's own implementation reads.

/// Mirrors `sd_id128_t` from sd-id128.h. Upstream is a union of
/// `uint8_t[16]` and `uint64_t[2]`; `#[repr(C)]` over `[u8; 16]` has the
/// same layout/size/align for the `bytes` view, which is what C callers
/// actually use (compare/format on the bytes).
#[repr(C)]
pub struct SdId128 {
    pub bytes: [u8; 16],
}

fn parse_hex32(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn read_id_file(path: &str) -> Option<[u8; 16]> {
    let raw = std::fs::read_to_string(path).ok()?;
    let hex: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    parse_hex32(&hex)
}

/// sd_id128_get_machine(3). Reads `/etc/machine-id`, the standard file
/// dbus/systemd/elogind all already agree on.
///
/// Returns 0 on success, `-ENOENT` if the file doesn't exist, `-EINVAL`
/// if its contents aren't a valid 128-bit hex ID.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sd_id128_get_machine(ret: *mut SdId128) -> i32 {
    if ret.is_null() {
        return -libc::EINVAL;
    }
    match read_id_file("/etc/machine-id") {
        Some(bytes) => {
            unsafe { (*ret).bytes = bytes };
            0
        }
        None if std::path::Path::new("/etc/machine-id").exists() => -libc::EINVAL,
        None => -libc::ENOENT,
    }
}

/// sd_id128_get_boot(3). Reads the kernel's own
/// `/proc/sys/kernel/random/boot_id` (dashed UUID form, regenerated
/// every boot).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sd_id128_get_boot(ret: *mut SdId128) -> i32 {
    if ret.is_null() {
        return -libc::EINVAL;
    }
    match read_id_file("/proc/sys/kernel/random/boot_id") {
        Some(bytes) => {
            unsafe { (*ret).bytes = bytes };
            0
        }
        None => -libc::EIO,
    }
}

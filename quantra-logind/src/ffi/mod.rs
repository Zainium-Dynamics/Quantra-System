//! Shared plumbing for the qlogind C-ABI surface.
//!
//! Every exported function is synchronous and must not panic across the
//! FFI boundary. Errors return as negative errno, matching sd-login.h /
//! sd-daemon.h / sd-id128.h.

pub mod daemon;
pub mod id128;
pub mod login;

use std::io::{Read, Write};
use std::os::raw::c_char;
use std::os::unix::net::UnixStream;
use std::time::Duration;

const LOGIND_SOCKET: &str = "/run/quantra-logind/control";

/// Blocking JSON round-trip to quantra-logind's control socket. Same
/// wire protocol as `dbus_bridge.rs`'s `call_logind()` (u32 LE length
/// prefix + JSON body, both directions). Duplicated here rather than
/// shared via a lib target the bins don't have yet.
pub(crate) fn call_logind(request: &serde_json::Value) -> Result<serde_json::Value, i32> {
    let mut stream = UnixStream::connect(LOGIND_SOCKET).map_err(|e| errno_of(&e))?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    let req_bytes = serde_json::to_vec(request).map_err(|_| libc::EINVAL)?;
    let len = req_bytes.len() as u32;
    stream.write_all(&len.to_le_bytes()).map_err(|e| errno_of(&e))?;
    stream.write_all(&req_bytes).map_err(|e| errno_of(&e))?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| errno_of(&e))?;
    let resp_len = u32::from_le_bytes(len_buf) as usize;
    if resp_len > 4 * 1024 * 1024 {
        return Err(libc::EMSGSIZE);
    }

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).map_err(|e| errno_of(&e))?;

    serde_json::from_slice(&resp_buf).map_err(|_| libc::EIO)
}

fn errno_of(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

/// Send `{"cmd": ...}`, return `data` from `{"ok": true, "data": ...}`.
/// `not_found_errno` is returned on `{"ok": false}` (e.g. `ENXIO` for
/// "no such session").
pub(crate) fn query(
    request: serde_json::Value,
    not_found_errno: i32,
) -> Result<serde_json::Value, i32> {
    let resp = call_logind(&request)?;
    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        resp.get("data").cloned().ok_or(libc::EIO)
    } else {
        Err(not_found_errno)
    }
}

/// NUL-terminated copy of `s`, allocated with `libc::malloc`. Callers
/// free it with plain `free()` (sd-login.h contract), not a Rust
/// deallocator. Null on allocation failure.
pub(crate) unsafe fn malloc_cstring(s: &str) -> *mut c_char {
    unsafe {
        let len = s.len();
        let buf = libc::malloc(len + 1) as *mut u8;
        if buf.is_null() {
            return std::ptr::null_mut();
        }
        std::ptr::copy_nonoverlapping(s.as_ptr(), buf, len);
        *buf.add(len) = 0;
        buf as *mut c_char
    }
}

/// Write `s` through a sd-login.h-style `char **ret` out-param. 0 on
/// success, `-ENOMEM` on allocation failure, `-EINVAL` if `out` is null.
pub(crate) unsafe fn set_out_string(out: *mut *mut c_char, s: &str) -> i32 {
    unsafe {
        if out.is_null() {
            return -libc::EINVAL;
        }
        let ptr = malloc_cstring(s);
        if ptr.is_null() {
            return -libc::ENOMEM;
        }
        *out = ptr;
        0
    }
}

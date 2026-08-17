//! sd-daemon.h subset: service readiness notification.
//!
//! Wire-compatible with quantra's own service manager, not with
//! quantra-logind. `NOTIFY_SOCKET` is read/written directly here, no
//! control-socket round-trip. Confirmed against
//! `quantra/src/services/notify.rs`: newline-separated `KEY=VALUE`
//! datagrams over `AF_UNIX SOCK_DGRAM`, same vocabulary as systemd's
//! sd_notify(3) (`READY=1`, `STATUS=`, `MAINPID=`, `ERRNO=`,
//! `WATCHDOG=1`). Same protocol, straight reimplementation.

use std::os::raw::c_char;
use std::os::unix::net::UnixDatagram;

// sd_notifyf(3, ...) not implemented: needs a C-variadic extern "C" fn,
// which requires the unstable c_variadic feature (nightly-only). This
// workspace is pinned to stable Rust 1.82 (rust-toolchain.toml).
// Callers should format their own status string and call sd_notify.

/// sd_booted(3). Always true: Zainium always boots under quantra.
#[unsafe(no_mangle)]
pub extern "C" fn sd_booted() -> i32 {
    1
}

/// sd_notify(3). `state` must be a valid, non-null, NUL-terminated C
/// string (same requirement as the real sd_notify).
///
/// Returns 1 on successful send, 0 if `$NOTIFY_SOCKET` isn't set,
/// negative errno on send failure.
///
/// `unset_environment`: if non-zero, unset `NOTIFY_SOCKET` after a
/// successful send (prevents child processes re-notifying on the same
/// socket).
///
/// Only pathname sockets are supported, not abstract-namespace `@name`
/// sockets. quantra's notify server only binds pathname sockets under
/// `/run/quantra-system/notify/`, so this covers every real
/// `NOTIFY_SOCKET` value seen in practice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sd_notify(unset_environment: i32, state: *const c_char) -> i32 {
    if state.is_null() {
        return -libc::EINVAL;
    }

    let socket_path = match std::env::var("NOTIFY_SOCKET") {
        Ok(p) if !p.is_empty() => p,
        _ => return 0,
    };

    if socket_path.starts_with('@') {
        return -libc::EAFNOSUPPORT;
    }

    let msg_bytes = unsafe { std::ffi::CStr::from_ptr(state) }.to_bytes();
    if msg_bytes.is_empty() {
        return -libc::EINVAL;
    }

    let sock = match UnixDatagram::unbound() {
        Ok(s) => s,
        Err(e) => return -e.raw_os_error().unwrap_or(libc::EIO),
    };

    match sock.send_to(msg_bytes, &socket_path) {
        Ok(_) => {
            if unset_environment != 0 {
                unsafe { std::env::remove_var("NOTIFY_SOCKET") };
            }
            1
        }
        Err(e) => -e.raw_os_error().unwrap_or(libc::EIO),
    }
}

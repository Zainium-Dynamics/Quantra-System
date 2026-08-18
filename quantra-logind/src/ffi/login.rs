//! sd-login.h subset, backed by quantra-logind's control socket
//! (`/run/quantra-logind/control`). Same JSON protocol `dbus_bridge.rs`
//! speaks; field names confirmed against `types.rs`'s
//! `Session`/`UserRecord`/`Seat` structs directly.
//!
//! Known gap: `GetUser`/`ListUsers` in `control.rs` require the calling
//! process's peer uid to be root or the target uid. A caller like
//! polkit querying a different user's session gets `EPERM`. Real
//! logind allows this via a polkit check on the bus instead of a flat
//! uid match. Not fixed here, needs quantra-logind's own ACL loosened.

use super::{query, set_out_string};
use libc::{pid_t, uid_t};
use serde_json::json;
use std::os::raw::c_char;

/// Positive errno on failure, matching `call_logind`/`query`. Every
/// call site negates uniformly with `-e`.
fn parse_session_id(session: *const c_char) -> Result<u64, i32> {
    if session.is_null() {
        return Err(libc::EINVAL);
    }
    let s = unsafe { std::ffi::CStr::from_ptr(session) }
        .to_str()
        .map_err(|_| libc::EINVAL)?;
    s.parse::<u64>().map_err(|_| libc::EINVAL)
}

/// `sd_pid_get_session(3)`. `ret` receives a malloc'd, free()-able
/// decimal session-id string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sd_pid_get_session(pid: pid_t, ret: *mut *mut c_char) -> i32 {
    if pid <= 0 {
        return -libc::EINVAL;
    }
    let data = match query(json!({"cmd": "get_session_by_pid", "pid": pid as u32}), libc::ENXIO) {
        Ok(d) => d,
        Err(e) => return -e,
    };
    let Some(id) = data.get("id").and_then(|v| v.as_u64()) else {
        return -libc::EIO;
    };
    unsafe { set_out_string(ret, &id.to_string()) }
}

/// `sd_session_is_active(3)`. 1 (active) / 0 (not active) on success,
/// negative errno on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sd_session_is_active(session: *const c_char) -> i32 {
    let id = match parse_session_id(session) {
        Ok(id) => id,
        Err(e) => return -e,
    };
    let data = match query(json!({"cmd": "get_session", "session_id": id}), libc::ENXIO) {
        Ok(d) => d,
        Err(e) => return -e,
    };
    match data.get("state").and_then(|v| v.as_str()) {
        Some("active") => 1,
        Some(_) => 0,
        None => -libc::EIO,
    }
}

/// `sd_session_get_state(3)`. `ret` receives one of quantra-logind's
/// session states: `opening`, `active`, `online`, `closing`. Subset of
/// systemd's vocabulary, same spelling.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sd_session_get_state(
    session: *const c_char,
    ret: *mut *mut c_char,
) -> i32 {
    let id = match parse_session_id(session) {
        Ok(id) => id,
        Err(e) => return -e,
    };
    let data = match query(json!({"cmd": "get_session", "session_id": id}), libc::ENXIO) {
        Ok(d) => d,
        Err(e) => return -e,
    };
    match data.get("state").and_then(|v| v.as_str()) {
        Some(state) => unsafe { set_out_string(ret, state) },
        None => -libc::EIO,
    }
}

/// `sd_session_get_seat(3)`. `-ENODATA` if the session has no seat
/// assigned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sd_session_get_seat(
    session: *const c_char,
    ret: *mut *mut c_char,
) -> i32 {
    let id = match parse_session_id(session) {
        Ok(id) => id,
        Err(e) => return -e,
    };
    let data = match query(json!({"cmd": "get_session", "session_id": id}), libc::ENXIO) {
        Ok(d) => d,
        Err(e) => return -e,
    };
    match data.get("seat").and_then(|v| v.as_str()) {
        Some(seat) => unsafe { set_out_string(ret, seat) },
        None => -libc::ENODATA,
    }
}

/// `sd_uid_get_state(3)`. `ret` receives one of: `offline`,
/// `lingering`, `online`, `active`, `closing`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sd_uid_get_state(uid: uid_t, ret: *mut *mut c_char) -> i32 {
    let data = match query(json!({"cmd": "get_user", "uid": uid}), libc::ENOENT) {
        Ok(d) => d,
        Err(e) => return -e,
    };
    match data.get("state").and_then(|v| v.as_str()) {
        Some(state) => unsafe { set_out_string(ret, state) },
        None => -libc::EIO,
    }
}

/// `sd_seat_get_active(3)`. Either out-pointer may be null. `-ENODATA`
/// if the seat has no active session.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sd_seat_get_active(
    seat: *const c_char,
    session_ret: *mut *mut c_char,
    uid_ret: *mut uid_t,
) -> i32 {
    if seat.is_null() {
        return -libc::EINVAL;
    }
    let seat_id = match unsafe { std::ffi::CStr::from_ptr(seat) }.to_str() {
        Ok(s) => s,
        Err(_) => return -libc::EINVAL,
    };

    let seat_data = match query(json!({"cmd": "get_seat", "seat_id": seat_id}), libc::ENXIO) {
        Ok(d) => d,
        Err(e) => return -e,
    };
    let Some(active_session) = seat_data.get("active_session").and_then(|v| v.as_u64()) else {
        return -libc::ENODATA;
    };

    if !uid_ret.is_null() {
        let session_data = match query(
            json!({"cmd": "get_session", "session_id": active_session}),
            libc::ENXIO,
        ) {
            Ok(d) => d,
            Err(e) => return -e,
        };
        let Some(uid) = session_data.get("uid").and_then(|v| v.as_u64()) else {
            return -libc::EIO;
        };
        unsafe { *uid_ret = uid as uid_t };
    }

    if !session_ret.is_null() {
        let rc = unsafe { set_out_string(session_ret, &active_session.to_string()) };
        if rc != 0 {
            return rc;
        }
    }

    0
}

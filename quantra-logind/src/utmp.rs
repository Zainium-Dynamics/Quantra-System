//! utmp/wtmp — login record compatibility
//!
//! Maintains `/var/run/utmp` (current logins) and `/var/log/wtmp` (login history).
//!
//! # Compatibility
//!
//! Standard POSIX login accounting. Required by:
//! - `who(1)`, `w(1)`, `last(1)`, `users(1)`
//! - PAM modules (`pam_lastlog.so`)
//! - SSH (`sshd` reads utmp to track active sessions)
//! - Flatpak (reads utmp for desktop detection in some configurations)
//!
//! # Record format
//!
//! We write the `struct utmp` (glibc) format directly.
//! Each record is 384 bytes (x86-64 glibc).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

const UTMP_PATH: &str = "/var/run/utmp";
const WTMP_PATH: &str = "/var/log/wtmp";

// struct utmp field constants
const UT_LINESIZE: usize = 32;
const UT_NAMESIZE: usize = 32;
const UT_HOSTSIZE: usize = 256;

// ut_type values
#[allow(dead_code)]
const EMPTY:         i16 = 0;
#[allow(dead_code)]
const RUN_LVL:       i16 = 1;
const BOOT_TIME:     i16 = 2;
const USER_PROCESS:  i16 = 7;
const DEAD_PROCESS:  i16 = 8;

/// Write a user login record to utmp and wtmp.
pub fn write_login(
    pid: u32,
    tty: &str,
    username: &str,
    remote_host: &str,
    session_id: u64,
) {
    let rec = build_utmp(
        USER_PROCESS, pid, tty, username, remote_host,
        &format!("{}", session_id),
    );
    write_utmp_record(&rec);
    append_wtmp_record(&rec);
    log::debug!("utmp: LOGIN user={} tty={} pid={}", username, tty, pid);
}

/// Write a user logout record to utmp and wtmp.
pub fn write_logout(pid: u32, tty: &str) {
    let rec = build_utmp(DEAD_PROCESS, pid, tty, "", "", "");
    write_utmp_record(&rec);
    append_wtmp_record(&rec);
    log::debug!("utmp: LOGOUT tty={} pid={}", tty, pid);
}

/// Write boot time record (called at daemon start).
pub fn write_boot_time() {
    let rec = build_utmp(BOOT_TIME, 0, "~", "reboot", "", "");
    append_wtmp_record(&rec);
}

// ── Raw utmp struct (glibc layout, 384 bytes) ─────────────────────────────────

#[repr(C)]
struct UtExit { e_termination: i16, e_exit: i16 }

#[repr(C)]
struct Utmp {
    ut_type:    i16,
    _pad0:      [u8; 2],
    ut_pid:     i32,
    ut_line:    [u8; UT_LINESIZE],
    ut_id:      [u8; 4],
    ut_user:    [u8; UT_NAMESIZE],
    ut_host:    [u8; UT_HOSTSIZE],
    ut_exit:    UtExit,
    ut_session: i32,
    ut_tv_sec:  i32,
    ut_tv_usec: i32,
    ut_addr_v6: [u32; 4],
    __unused:   [u8; 20],
}

fn build_utmp(
    ut_type: i16,
    pid: u32,
    tty: &str,
    user: &str,
    host: &str,
    id: &str,
) -> Utmp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    let mut rec: Utmp = unsafe { std::mem::zeroed() };
    rec.ut_type    = ut_type;
    rec.ut_pid     = pid as i32;
    rec.ut_tv_sec  = now.as_secs() as i32;
    rec.ut_tv_usec = now.subsec_micros() as i32;

    copy_str(&mut rec.ut_line, tty.trim_start_matches("/dev/"));
    copy_str(&mut rec.ut_user, user);
    copy_str(&mut rec.ut_host, host);

    // ut_id: last 4 chars of tty (e.g. "tty1" → "tty1")
    let id_src = if id.is_empty() {
        let t = tty.trim_start_matches("/dev/");
        &t[t.len().saturating_sub(4)..]
    } else {
        &id[id.len().saturating_sub(4)..]
    };
    let ib = id_src.as_bytes();
    for (i, &b) in ib.iter().take(4).enumerate() {
        rec.ut_id[i] = b;
    }

    rec
}

fn copy_str<const N: usize>(dst: &mut [u8; N], src: &str) {
    let bytes = src.as_bytes();
    let len = bytes.len().min(N - 1);
    dst[..len].copy_from_slice(&bytes[..len]);
}

fn utmp_as_bytes(rec: &Utmp) -> &[u8] {
    let size = std::mem::size_of::<Utmp>();
    unsafe { std::slice::from_raw_parts(rec as *const Utmp as *const u8, size) }
}

/// Update the utmp entry for this pid/tty (overwrite matching record or append).
fn write_utmp_record(rec: &Utmp) {
    ensure_file(UTMP_PATH);
    let bytes = utmp_as_bytes(rec);
    let rec_size = std::mem::size_of::<Utmp>();

    // Read existing records, find matching pid or tty
    if let Ok(mut data) = std::fs::read(UTMP_PATH) {
        let n = data.len() / rec_size;
        for i in 0..n {
            let start = i * rec_size;
            let existing = &data[start..start + rec_size];
            let existing_pid = i32::from_ne_bytes([
                existing[4], existing[5], existing[6], existing[7]
            ]);
            if existing_pid == rec.ut_pid
               || existing[8..8 + 32] == rec.ut_line[..] {
                // Overwrite this record
                data[start..start + rec_size].copy_from_slice(bytes);
                std::fs::write(UTMP_PATH, &data).ok();
                return;
            }
        }
        // Append new record
        if let Ok(mut f) = OpenOptions::new().append(true).open(UTMP_PATH) {
            f.write_all(bytes).ok();
        }
    }
}

/// Always append to wtmp (historical log).
fn append_wtmp_record(rec: &Utmp) {
    ensure_file(WTMP_PATH);
    let bytes = utmp_as_bytes(rec);
    if let Ok(mut f) = OpenOptions::new().append(true).open(WTMP_PATH) {
        f.write_all(bytes).ok();
    }
}

fn ensure_file(path: &str) {
    if !Path::new(path).exists() {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent).ok();
        }
        File::create(path).ok();
    }
}

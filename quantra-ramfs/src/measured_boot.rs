/// Measured boot — TPM2 PCR extension at each boot phase
///
/// # Overview
///
/// Measured boot creates a tamper-evident audit trail of the boot process by
/// extending TPM2 PCR[8] at every phase transition. Each extension is a
/// SHA-256 hash of a measurement string. Because PCR extension is:
///
/// ```
/// PCR[n] = SHA-256(PCR[n] || new_value)
/// ```
///
/// the final PCR[8] value is uniquely determined by the exact sequence of
/// measurements. Any deviation — a phase skipped, a different binary, a
/// different cmdline — produces a different PCR[8] value, which causes the
/// TPM2 policy session in `tpm2.rs` to reject the unseal.
///
/// # What gets measured
///
/// | Measurement | Content |
/// |-------------|---------|
/// | Phase transition | `"zainium-phase:<N>:<name>"` |
/// | Cmdline | `"zainium-cmdline:<sha256 of /proc/cmdline>"` |
/// | Init binary | `"zainium-init:<sha256 of init binary>"` |
/// | Overlay config | `"zainium-overlay:<enabled|disabled>"` |
///
/// # PCR choice
///
/// PCR 8 is used (not 0–7 which are reserved for firmware/UEFI/Secure Boot).
/// PCR 8 starts at zero on every boot, giving a clean slate for our measurements.
///
/// # TPM2 command
///
/// TPM2_PCR_Extend (CC=0x0182):
/// ```
/// header: tag=TPM2_ST_SESSIONS, size, cc=0x0182
/// pcrHandle: 8
/// auth area: password session (empty auth)
/// digests: count=1, hashAlg=SHA256, digest[32]
/// ```
use std::fs;
use std::io;
use std::os::unix::io::RawFd;

// ── TPM2 constants ────────────────────────────────────────────────────────────

const TPM2_ST_SESSIONS: u16 = 0x8002;
const TPM2_CC_PCR_EXTEND: u32 = 0x0182;
const TPM2_RS_PW: u32 = 0x40000009;
const TPM2_ALG_SHA256: u16 = 0x000B;
const TPM2_RC_SUCCESS: u32 = 0x000;

const PCR_INDEX: u32 = 8;

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

// ── Public API ────────────────────────────────────────────────────────────────

/// Extend PCR[8] with a measurement of the current boot phase.
///
/// Called by `set_phase()` in `phases.rs` for each phase transition.
/// If no TPM2 device is present, this is a no-op (non-fatal).
pub fn measure_phase(phase: u32, phase_name: &str) {
    let measurement = format!("zainium-phase:{}:{}", phase, phase_name);
    if let Err(e) = extend_pcr(PCR_INDEX, measurement.as_bytes()) {
        // TPM2 absent or error — non-fatal, just log
        eprintln!("  [tpm2] PCR extend phase {}: {}", phase, e);
    }
}

/// Extend PCR[8] with SHA-256 of /proc/cmdline content.
///
/// Ensures the full kernel cmdline is measured — any change to boot parameters
/// invalidates the PCR policy.
pub fn measure_cmdline() {
    match fs::read_to_string("/proc/cmdline") {
        Ok(cmdline) => {
            let hash = sha256(cmdline.as_bytes());
            let measurement = format!("zainium-cmdline:{}", encode_hex(&hash));
            if let Err(e) = extend_pcr(PCR_INDEX, measurement.as_bytes()) {
                eprintln!("  [tpm2] PCR extend cmdline: {}", e);
            }
        }
        Err(e) => {
            eprintln!("  [tpm2] measure_cmdline: read /proc/cmdline: {}", e);
        }
    }
}

/// Extend PCR[8] with SHA-256 of the init binary.
///
/// Called after init binary is discovered but before pivot_root.
/// Ensures the exact binary being handed control is recorded.
pub fn measure_init_binary(new_root: &str, init_path: &str) {
    let full = format!("{}{}", new_root, init_path);
    match fs::read(&full) {
        Ok(data) => {
            let hash = sha256(&data);
            let measurement = format!("zainium-init:{}", encode_hex(&hash));
            if let Err(e) = extend_pcr(PCR_INDEX, measurement.as_bytes()) {
                eprintln!("  [tpm2] PCR extend init binary: {}", e);
            } else {
                eprintln!(
                    "  [tpm2] measured init: {} sha256={}",
                    init_path,
                    encode_hex(&hash)
                );
            }
        }
        Err(e) => {
            eprintln!("  [tpm2] measure_init: read '{}': {}", full, e);
        }
    }
}

/// Extend PCR[8] with overlay mode (enabled/disabled).
pub fn measure_overlay_mode(enabled: bool) {
    let s = if enabled {
        "zainium-overlay:enabled"
    } else {
        "zainium-overlay:disabled"
    };
    if let Err(e) = extend_pcr(PCR_INDEX, s.as_bytes()) {
        eprintln!("  [tpm2] PCR extend overlay mode: {}", e);
    }
}

/// Read current PCR[8] value for diagnostics.
#[allow(dead_code)]
pub fn read_pcr8() -> Option<[u8; 32]> {
    read_pcr(PCR_INDEX).ok()
}

// ── TPM2 PCR extend ───────────────────────────────────────────────────────────

/// Extend `pcr_index` with SHA-256(`data`).
fn extend_pcr(pcr_index: u32, data: &[u8]) -> Result<(), String> {
    let digest = sha256(data);

    let fd = open_tpm()?;
    let _g = FdGuard(fd);

    // Build TPM2_PCR_Extend command
    // Auth area: password session for PCR (empty auth — PCRs have no auth by default)
    let mut auth = Vec::with_capacity(9);
    push_u32(&mut auth, TPM2_RS_PW);
    push_u16(&mut auth, 0); // nonce
    auth.push(0); // attrs
    push_u16(&mut auth, 0); // hmac

    // digests: TPML_DIGEST_VALUES — count=1, hashAlg=SHA256, digest[32]
    let mut digests = Vec::with_capacity(38);
    push_u32(&mut digests, 1); // count
    push_u16(&mut digests, TPM2_ALG_SHA256);
    digests.extend_from_slice(&digest);

    let body = 4 + 4 + auth.len() + digests.len();
    let total = 10 + body;
    let mut cmd = Vec::with_capacity(total);

    push_u16(&mut cmd, TPM2_ST_SESSIONS);
    push_u32(&mut cmd, total as u32);
    push_u32(&mut cmd, TPM2_CC_PCR_EXTEND);
    push_u32(&mut cmd, pcr_index);
    push_u32(&mut cmd, auth.len() as u32);
    cmd.extend_from_slice(&auth);
    cmd.extend_from_slice(&digests);

    let resp = tpm2_send(fd, &cmd)?;
    let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
    if rc != TPM2_RC_SUCCESS {
        return Err(format!("TPM2_PCR_Extend RC=0x{:08X}", rc));
    }
    Ok(())
}

/// Read PCR value (TPM2_PCR_Read).
#[allow(dead_code)]
fn read_pcr(pcr_index: u32) -> Result<[u8; 32], String> {
    const TPM2_CC_PCR_READ: u32 = 0x017E;
    const TPM2_ST_NO_SESSIONS: u16 = 0x8001;

    let fd = open_tpm()?;
    let _g = FdGuard(fd);

    // TPML_PCR_SELECTION: count=1, SHA256, 3-byte mask
    let mask: u32 = 1 << pcr_index;
    let mut sel = Vec::with_capacity(12);
    push_u32(&mut sel, 1); // count
    push_u16(&mut sel, TPM2_ALG_SHA256);
    sel.push(3); // sizeofSelect
    sel.push((mask & 0xFF) as u8);
    sel.push(((mask >> 8) & 0xFF) as u8);
    sel.push(((mask >> 16) & 0xFF) as u8);

    let total = 10 + sel.len();
    let mut cmd = Vec::with_capacity(total);
    push_u16(&mut cmd, TPM2_ST_NO_SESSIONS);
    push_u32(&mut cmd, total as u32);
    push_u32(&mut cmd, TPM2_CC_PCR_READ);
    cmd.extend_from_slice(&sel);

    let resp = tpm2_send(fd, &cmd)?;
    // Response: header(10) + updateCounter(4) + pcrSelectionOut + pcrValues
    // pcrValues = TPML_DIGEST: count(4) + TPM2B_DIGEST: size(2) + digest[32]
    // offset: 10(hdr) + 4(counter) + 4(count) + 2+1+3(sel) + 4(count) + 2 = 30
    if resp.len() < 30 + 32 {
        return Err("TPM2_PCR_Read response too short".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&resp[30..62]);
    Ok(out)
}

// ── I/O helpers ───────────────────────────────────────────────────────────────

fn open_tpm() -> Result<RawFd, String> {
    for path in &["/dev/tpmrm0", "/dev/tpm0"] {
        let cpath = std::ffi::CString::new(*path).unwrap();
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd >= 0 {
            return Ok(fd);
        }
    }
    Err("TPM2 device not found".to_string())
}

fn tpm2_send(fd: RawFd, cmd: &[u8]) -> Result<Vec<u8>, String> {
    let mut written = 0;
    while written < cmd.len() {
        let n = unsafe {
            libc::write(
                fd,
                cmd.as_ptr().add(written) as *const libc::c_void,
                cmd.len() - written,
            )
        };
        if n <= 0 {
            return Err(format!("TPM2 write: {}", io::Error::last_os_error()));
        }
        written += n as usize;
    }
    let mut resp = vec![0u8; 256];
    let n = unsafe { libc::read(fd, resp.as_mut_ptr() as *mut libc::c_void, 256) };
    if n < 10 {
        return Err(format!("TPM2 read: {}", io::Error::last_os_error()));
    }
    resp.truncate(n as usize);
    Ok(resp)
}

fn push_u16(v: &mut Vec<u8>, val: u16) {
    v.extend_from_slice(&val.to_be_bytes());
}
fn push_u32(v: &mut Vec<u8>, val: u32) {
    v.extend_from_slice(&val.to_be_bytes());
}

// ── Pure-Rust SHA-256 (FIPS 180-4) ───────────────────────────────────────────

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] =
            [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, &word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
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

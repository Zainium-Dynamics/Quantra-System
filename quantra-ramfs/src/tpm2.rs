/// TPM2 key unsealing — LUKS key from PCR policy
///
/// # Overview
///
/// This module communicates with the TPM2 device directly via the kernel's
/// `/dev/tpm0` or `/dev/tpmrm0` (resource manager) character device using
/// the TPM2 wire protocol (TPM2 Part 3 Commands specification).
///
/// # Use case
///
/// A LUKS encryption key is sealed to the TPM2 at install time, bound to a
/// PCR policy. At boot, if PCR values match the policy (meaning no tampering
/// has occurred), the TPM2 releases the key → LUKS is unlocked without user
/// passphrase input.
///
/// # PCR policy
///
/// PCRs used by default:
/// - PCR 0 — UEFI firmware code
/// - PCR 1 — UEFI firmware configuration
/// - PCR 7 — Secure Boot state
/// - PCR 8 — Zainium measured boot phases (extended by measured_boot.rs)
///
/// # TPM2 commands used
///
/// | Command | Purpose |
/// |---------|---------|
/// | TPM2_CC_StartAuthSession | Create HMAC/policy session |
/// | TPM2_CC_PolicyPCR | Bind session to PCR values |
/// | TPM2_CC_Unseal | Unseal the blob using the policy session |
/// | TPM2_CC_FlushContext | Clean up session handle |
///
/// # Blob storage
///
/// The sealed blob is stored at `/overlayer/syshub/etc/zainium/tpm2-luks-blob`
/// on the syshub (read-only). This file contains the serialized TPM2B_PUBLIC +
/// TPM2B_PRIVATE written by the enrollment tool at install time.
///
/// # Fallback
///
/// If TPM2 unsealing fails for any reason (PCR mismatch, device absent,
/// malformed blob), the module returns `Err` and the caller falls back to
/// interactive passphrase prompt.
use std::fs;
use std::io;
use std::os::unix::io::RawFd;

// ── TPM2 constants ────────────────────────────────────────────────────────────

const TPM2_ST_NO_SESSIONS: u16 = 0x8001;
const TPM2_ST_SESSIONS: u16 = 0x8002;
#[allow(dead_code)]
const TPM2_CC_STARTUP: u32 = 0x0144;
const TPM2_CC_START_AUTH_SESSION: u32 = 0x0176;
const TPM2_CC_POLICY_PCR: u32 = 0x017F;
const TPM2_CC_UNSEAL: u32 = 0x015E;
const TPM2_CC_FLUSH_CONTEXT: u32 = 0x0165;
const TPM2_CC_LOAD: u32 = 0x0157;

const TPM2_SE_POLICY: u8 = 0x01;
const TPM2_ALG_NULL: u16 = 0x0010;
const TPM2_ALG_SHA256: u16 = 0x000B;
const TPM2_RH_NULL: u32 = 0x40000007;
const TPM2_RS_PW: u32 = 0x40000009;

const TPM2_RC_SUCCESS: u32 = 0x000;

/// Default PCR selection: PCR 0,1,7,8 in bank SHA-256
const DEFAULT_PCR_MASK: u32 = (1 << 0) | (1 << 1) | (1 << 7) | (1 << 8);

/// Path to sealed LUKS key blob on the syshub
const BLOB_PATH: &str = "/overlayer/syshub/etc/zainium/tpm2-luks-blob";
/// Parent handle persistence handle (written at enroll time)
const PARENT_HANDLE_PATH: &str = "/overlayer/syshub/etc/zainium/tpm2-parent-handle";

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

/// Attempt to unseal the LUKS key from TPM2.
///
/// Returns the raw key bytes on success. The caller should:
/// 1. Pipe these bytes to `cryptsetup luksOpen --key-file=-`
/// 2. Zero the Vec immediately after use
///
/// Returns `Err` on any failure (device absent, PCR mismatch, blob corrupt).
/// Callers MUST fall back to interactive passphrase on `Err`.
pub fn unseal_luks_key() -> Result<Vec<u8>, String> {
    eprintln!("  TPM2: unsealing LUKS key...");

    // Read the sealed blob
    let blob = fs::read(BLOB_PATH).map_err(|e| format!("read TPM2 blob '{}': {}", BLOB_PATH, e))?;

    if blob.len() < 8 {
        return Err("TPM2 blob too small — corrupted?".to_string());
    }

    // Read parent handle (u32 big-endian, 4 bytes)
    let parent_handle = read_parent_handle()?;
    eprintln!("    parent handle: 0x{:08X}", parent_handle);

    // Open TPM device — prefer resource manager (handles reference counting)
    let tpm_fd = open_tpm_device()?;
    let _tpm_guard = FdGuard(tpm_fd);

    // Parse blob: first 4 bytes = public_size (u16 BE), then public, then private
    let (public_data, private_data) = parse_blob(&blob)?;

    // Step 1: Load the sealed object into TPM
    let object_handle = tpm2_load(tpm_fd, parent_handle, &public_data, &private_data)?;
    eprintln!("    object handle: 0x{:08X}", object_handle);

    // Step 2: Create policy session
    let session_handle = tpm2_start_auth_session(tpm_fd)?;
    eprintln!("    policy session: 0x{:08X}", session_handle);

    // Step 3: Satisfy PCR policy
    let pcr_mask = read_pcr_mask();
    tpm2_policy_pcr(tpm_fd, session_handle, pcr_mask)?;
    eprintln!("    PCR policy satisfied (mask: 0x{:08X})", pcr_mask);

    // Step 4: Unseal
    let key = tpm2_unseal(tpm_fd, object_handle, session_handle)?;
    eprintln!("  ✓ TPM2 unseal: {} bytes", key.len());

    // Flush handles
    let _ = tpm2_flush_context(tpm_fd, session_handle);
    let _ = tpm2_flush_context(tpm_fd, object_handle);

    Ok(key)
}

/// Check if TPM2 device is present and accessible.
pub fn tpm2_available() -> bool {
    std::path::Path::new("/dev/tpmrm0").exists() || std::path::Path::new("/dev/tpm0").exists()
}

/// Check if a sealed blob exists (i.e. TPM2 enrollment was performed).
pub fn tpm2_blob_exists() -> bool {
    std::path::Path::new(BLOB_PATH).exists()
}

// ── TPM2 device I/O ───────────────────────────────────────────────────────────

fn open_tpm_device() -> Result<RawFd, String> {
    // Prefer resource manager — handles concurrent access and session cleanup
    for path in &["/dev/tpmrm0", "/dev/tpm0"] {
        let cpath = std::ffi::CString::new(*path).unwrap();
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd >= 0 {
            eprintln!("    TPM2 device: {}", path);
            return Ok(fd);
        }
    }
    Err(format!(
        "TPM2 device not found (/dev/tpmrm0, /dev/tpm0): {}",
        io::Error::last_os_error()
    ))
}

/// Send a TPM2 command and receive the response.
///
/// Writes `cmd` to the TPM fd, reads back up to 4096 bytes response.
/// Validates response tag and checks RC == TPM2_RC_SUCCESS.
fn tpm2_send(fd: RawFd, cmd: &[u8]) -> Result<Vec<u8>, String> {
    // Write command
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

    // Read response
    let mut resp = vec![0u8; 4096];
    let n = unsafe { libc::read(fd, resp.as_mut_ptr() as *mut libc::c_void, 4096) };
    if n < 10 {
        return Err(format!(
            "TPM2 read short response ({} bytes): {}",
            n,
            io::Error::last_os_error()
        ));
    }
    resp.truncate(n as usize);

    // Check RC at bytes 6-9 (big-endian u32)
    let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
    if rc != TPM2_RC_SUCCESS {
        return Err(format!("TPM2 command failed: RC=0x{:08X}", rc));
    }

    Ok(resp)
}

// ── TPM2 command builders ─────────────────────────────────────────────────────

fn tpm2_load(fd: RawFd, parent: u32, public: &[u8], private: &[u8]) -> Result<u32, String> {
    // TPM2_CC_LOAD:
    // Header: tag(2) size(4) cc(4)
    // parentHandle(4) + authorization(sessions) + inPrivate(TPM2B) + inPublic(TPM2B)
    let mut cmd = Vec::with_capacity(256);

    // Session area: password authorization for parent (empty auth)
    let auth_area = build_pw_auth_area();

    let priv_size = private.len() as u16;
    let pub_size = public.len() as u16;
    let body_size = 4 + 4 + auth_area.len() + 2 + private.len() + 2 + public.len();
    let total = 10 + body_size;

    push_u16(&mut cmd, TPM2_ST_SESSIONS);
    push_u32(&mut cmd, total as u32);
    push_u32(&mut cmd, TPM2_CC_LOAD);
    push_u32(&mut cmd, parent);
    push_u32(&mut cmd, auth_area.len() as u32);
    cmd.extend_from_slice(&auth_area);
    push_u16(&mut cmd, priv_size);
    cmd.extend_from_slice(private);
    push_u16(&mut cmd, pub_size);
    cmd.extend_from_slice(public);

    let resp = tpm2_send(fd, &cmd)?;
    // Response: header(10) + paramSize(4) + handle(4) + ...
    if resp.len() < 18 {
        return Err("TPM2_CC_LOAD response too short".to_string());
    }
    let handle = u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]);
    Ok(handle)
}

fn tpm2_start_auth_session(fd: RawFd) -> Result<u32, String> {
    // TPM2_StartAuthSession with SE_POLICY, symmetric=null, authHash=SHA256
    let mut cmd = Vec::with_capacity(64);
    let body_size = 4 + 4 + 2 + 2 + 1 + 2 + 2; // tpmKey + bind + nonce(size=0) + se + symmetric + hash
    let total = 10 + body_size;

    push_u16(&mut cmd, TPM2_ST_NO_SESSIONS);
    push_u32(&mut cmd, total as u32);
    push_u32(&mut cmd, TPM2_CC_START_AUTH_SESSION);
    push_u32(&mut cmd, TPM2_RH_NULL); // tpmKey = TPM_RH_NULL (no salting)
    push_u32(&mut cmd, TPM2_RH_NULL); // bind = TPM_RH_NULL
    push_u16(&mut cmd, 0); // nonceCaller size = 0 (empty)
    push_u16(&mut cmd, 0); // encryptedSalt size = 0
    cmd.push(TPM2_SE_POLICY); // sessionType = TPM2_SE_POLICY
    push_u16(&mut cmd, TPM2_ALG_NULL); // symmetric = TPM2_ALG_NULL (no encryption)
    push_u16(&mut cmd, TPM2_ALG_SHA256); // authHash = SHA-256

    let resp = tpm2_send(fd, &cmd)?;
    if resp.len() < 14 {
        return Err("TPM2_StartAuthSession response too short".to_string());
    }
    let handle = u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]);
    Ok(handle)
}

fn tpm2_policy_pcr(fd: RawFd, session: u32, pcr_mask: u32) -> Result<(), String> {
    // TPM2_PolicyPCR with empty pcrDigest (use current PCR values) and PCR selection
    let mut cmd = Vec::with_capacity(64);

    // PCR selection: count=1, bank SHA-256, 3-byte mask
    let pcr_sel = build_pcr_selection(pcr_mask);
    let body_size = 4 + 2 + pcr_sel.len(); // session + pcrDigest(size=0) + pcrSelectionIn
    let total = 10 + body_size;

    push_u16(&mut cmd, TPM2_ST_NO_SESSIONS);
    push_u32(&mut cmd, total as u32);
    push_u32(&mut cmd, TPM2_CC_POLICY_PCR);
    push_u32(&mut cmd, session);
    push_u16(&mut cmd, 0); // pcrDigest = empty (compute from current PCR values)
    cmd.extend_from_slice(&pcr_sel);

    tpm2_send(fd, &cmd)?;
    Ok(())
}

fn tpm2_unseal(fd: RawFd, object: u32, session: u32) -> Result<Vec<u8>, String> {
    let mut cmd = Vec::with_capacity(64);
    let auth_area = build_policy_auth_area(session);
    let body_size = 4 + 4 + auth_area.len();
    let total = 10 + body_size;

    push_u16(&mut cmd, TPM2_ST_SESSIONS);
    push_u32(&mut cmd, total as u32);
    push_u32(&mut cmd, TPM2_CC_UNSEAL);
    push_u32(&mut cmd, object);
    push_u32(&mut cmd, auth_area.len() as u32);
    cmd.extend_from_slice(&auth_area);

    let resp = tpm2_send(fd, &cmd)?;
    // Response: header(10) + paramSize(4) + outData(TPM2B: 2+data)
    if resp.len() < 16 {
        return Err("TPM2_Unseal response too short".to_string());
    }
    let _param_size = u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]) as usize;
    let data_offset = 14;
    if resp.len() < data_offset + 2 {
        return Err("TPM2_Unseal data too short".to_string());
    }
    let data_size = u16::from_be_bytes([resp[data_offset], resp[data_offset + 1]]) as usize;
    if resp.len() < data_offset + 2 + data_size {
        return Err(format!(
            "TPM2_Unseal truncated: need {} bytes",
            data_offset + 2 + data_size
        ));
    }
    Ok(resp[data_offset + 2..data_offset + 2 + data_size].to_vec())
}

fn tpm2_flush_context(fd: RawFd, handle: u32) -> Result<(), String> {
    let mut cmd = Vec::with_capacity(14);
    push_u16(&mut cmd, TPM2_ST_NO_SESSIONS);
    push_u32(&mut cmd, 14);
    push_u32(&mut cmd, TPM2_CC_FLUSH_CONTEXT);
    push_u32(&mut cmd, handle);
    tpm2_send(fd, &cmd)?;
    Ok(())
}

// ── Helper builders ───────────────────────────────────────────────────────────

fn build_pw_auth_area() -> Vec<u8> {
    // TPMS_AUTH_COMMAND: handle=TPM2_RS_PW, nonce=empty, attrs=0, hmac=empty
    let mut v = Vec::with_capacity(9);
    push_u32(&mut v, TPM2_RS_PW);
    push_u16(&mut v, 0); // nonce size = 0
    v.push(0); // sessionAttributes = 0
    push_u16(&mut v, 0); // hmac size = 0
    v
}

fn build_policy_auth_area(session: u32) -> Vec<u8> {
    // Same as PW auth but with policy session handle instead
    let mut v = Vec::with_capacity(9);
    push_u32(&mut v, session);
    push_u16(&mut v, 0); // nonce
    v.push(0); // attrs
    push_u16(&mut v, 0); // hmac
    v
}

/// Build TPML_PCR_SELECTION for a SHA-256 bank with given 32-bit PCR mask.
fn build_pcr_selection(mask: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(12);
    // count = 1
    push_u32(&mut v, 1);
    // TPMS_PCR_SELECTION: hash=SHA256, sizeofSelect=3, pcrSelect[3]
    push_u16(&mut v, TPM2_ALG_SHA256);
    v.push(3); // sizeofSelect = 3 bytes = 24 PCRs
    v.push((mask & 0xFF) as u8);
    v.push(((mask >> 8) & 0xFF) as u8);
    v.push(((mask >> 16) & 0xFF) as u8);
    v
}

fn push_u16(v: &mut Vec<u8>, val: u16) {
    v.extend_from_slice(&val.to_be_bytes());
}

fn push_u32(v: &mut Vec<u8>, val: u32) {
    v.extend_from_slice(&val.to_be_bytes());
}

// ── Blob parsing ──────────────────────────────────────────────────────────────

/// Parse the enrollment blob into (public_area, private_area).
///
/// Blob format (written by enrollment tool):
/// ```
/// [2 bytes] public_size (big-endian u16)
/// [n bytes] public_data (TPM2B_PUBLIC)
/// [2 bytes] private_size (big-endian u16)
/// [m bytes] private_data (TPM2B_PRIVATE)
/// ```
fn parse_blob(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if blob.len() < 4 {
        return Err("TPM2 blob too short".to_string());
    }
    let pub_size = u16::from_be_bytes([blob[0], blob[1]]) as usize;
    if blob.len() < 2 + pub_size + 2 {
        return Err(format!(
            "TPM2 blob truncated: pub_size={} but blob len={}",
            pub_size,
            blob.len()
        ));
    }
    let public = blob[2..2 + pub_size].to_vec();
    let priv_offset = 2 + pub_size;
    let priv_size = u16::from_be_bytes([blob[priv_offset], blob[priv_offset + 1]]) as usize;
    if blob.len() < priv_offset + 2 + priv_size {
        return Err("TPM2 blob private area truncated".to_string());
    }
    let private = blob[priv_offset + 2..priv_offset + 2 + priv_size].to_vec();
    Ok((public, private))
}

fn read_parent_handle() -> Result<u32, String> {
    let data = fs::read(PARENT_HANDLE_PATH)
        .map_err(|e| format!("read parent handle '{}': {}", PARENT_HANDLE_PATH, e))?;
    if data.len() < 4 {
        return Err("parent handle file too short".to_string());
    }
    Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
}

fn read_pcr_mask() -> u32 {
    // Try to read custom PCR mask from syshub config
    if let Ok(s) = fs::read_to_string("/overlayer/syshub/etc/zainium/tpm2-pcr-mask") {
        if let Ok(n) = u32::from_str_radix(s.trim().trim_start_matches("0x"), 16) {
            return n;
        }
    }
    DEFAULT_PCR_MASK
}

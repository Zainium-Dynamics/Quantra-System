#![allow(dead_code)]
/// Core dump handler — capture and store service crash dumps
///
/// Installs a kernel core pattern that pipes core dumps through this handler.
/// Core dumps are stored in `/var/lib/quantra-system/coredump/` with metadata.
///
/// # Kernel core pattern
///
/// ```
/// echo '|/overlayer/syshub/engine/quantra-coredump %P %u %g %s %t %e' > /proc/sys/kernel/core_pattern
/// ```
///
/// Parameters passed by kernel:
/// - `%P` — PID of crashed process
/// - `%u` — UID
/// - `%g` — GID
/// - `%s` — signal number that caused the dump
/// - `%t` — timestamp (Unix)
/// - `%e` — executable filename (truncated to 15 chars)
///
/// # Storage format
/// ```
/// /var/lib/quantra-system/coredump/
///   core.nginx.1234.1720000000.zst     ← zstd-compressed core
///   core.nginx.1234.1720000000.json    ← metadata
/// ```
///
/// # Retention policy
/// Keep last 5 coredumps per unit. Older ones are deleted automatically.
use anyhow::{Context, Result};
use log::{info, warn};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

const COREDUMP_DIR: &str = "/overlayer/syshub/var/lib/quantra-system/coredump";
const MAX_CORE_SIZE_BYTES: u64 = 256 * 1024 * 1024; // 256 MB
const MAX_CORES_PER_UNIT: usize = 5;

/// Install the kernel core pattern.
///
/// Called during Phase 4 (kernel setup) to set `/proc/sys/kernel/core_pattern`.
pub fn install_core_pattern(handler_path: &str) -> Result<()> {
    let pattern = format!("|{} %P %u %g %s %t %e", handler_path);
    fs::write("/proc/sys/kernel/core_pattern", &pattern)
        .context("write /proc/sys/kernel/core_pattern")?;

    // Also set core_pipe_limit to allow piping
    fs::write("/proc/sys/kernel/core_pipe_limit", "16")
        .map_err(|e| warn!("core_pipe_limit: {} (non-fatal)", e))
        .ok();

    info!("coredump: core_pattern installed: {}", pattern);
    Ok(())
}

/// Ensure the coredump storage directory exists.
pub fn ensure_coredump_dir() -> Result<()> {
    fs::create_dir_all(COREDUMP_DIR).context("create coredump dir")?;

    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(COREDUMP_DIR)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(COREDUMP_DIR, perms)?;
    Ok(())
}

/// Process a core dump piped from the kernel.
///
/// Reads core data from stdin, writes compressed to storage, saves metadata.
/// Called as: `quantra-coredump <pid> <uid> <gid> <signal> <timestamp> <exe>`
///
/// This function is the entry point when running as the core dump handler binary.
pub fn handle_piped_core(
    pid: u32,
    uid: u32,
    gid: u32,
    signal: u32,
    timestamp: u64,
    exe: &str,
) -> Result<()> {
    ensure_coredump_dir()?;

    let safe_exe: String = exe
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();

    let base = format!("core.{}.{}.{}", safe_exe, pid, timestamp);
    let core_path = format!("{}/{}", COREDUMP_DIR, base);
    let meta_path = format!("{}/{}.json", COREDUMP_DIR, base);

    info!(
        "coredump: capturing {} (PID {} signal {})",
        exe, pid, signal
    );

    // Read core from stdin with size limit
    let mut stdin = io::stdin();
    let mut core_data = Vec::new();
    let mut buf = [0u8; 65536];
    let mut total = 0u64;

    loop {
        let n = stdin.read(&mut buf).context("read core from stdin")?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_CORE_SIZE_BYTES {
            warn!(
                "coredump: core too large (>{} MB) — truncating",
                MAX_CORE_SIZE_BYTES / 1024 / 1024
            );
            break;
        }
        core_data.extend_from_slice(&buf[..n]);
    }

    // Write raw core (zstd compression would require the zstd crate — write raw for now)
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&core_path)
        .with_context(|| format!("create core file '{}'", core_path))?;

    use std::os::unix::fs::PermissionsExt;
    file.write_all(&core_data).context("write core data")?;
    drop(file);

    let mut perms = fs::metadata(&core_path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&core_path, perms)?;

    // Write metadata JSON
    let meta = format!(
        "{{\
            \"exe\":\"{}\",\
            \"pid\":{},\
            \"uid\":{},\
            \"gid\":{},\
            \"signal\":{},\
            \"signal_name\":\"{}\",\
            \"timestamp\":{},\
            \"size_bytes\":{},\
            \"core_path\":\"{}\"\
        }}\n",
        safe_exe,
        pid,
        uid,
        gid,
        signal,
        signal_name(signal),
        timestamp,
        total,
        core_path
    );
    fs::write(&meta_path, &meta).with_context(|| format!("write metadata '{}'", meta_path))?;

    info!("coredump: saved {} ({} bytes) → {}", exe, total, core_path);

    // Enforce retention policy
    cleanup_old_cores(&safe_exe)?;

    Ok(())
}

/// List recent core dumps, optionally filtered by unit name.
pub fn list_cores(unit: Option<&str>) -> Vec<CoreInfo> {
    let dir = Path::new(COREDUMP_DIR);
    if !dir.exists() {
        return Vec::new();
    }

    let mut cores: Vec<CoreInfo> = Vec::new();

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".json") {
                continue;
            }

            if let Some(u) = unit
                && !name.contains(&format!("core.{}.", u))
            {
                continue;
            }

            if let Ok(content) = fs::read_to_string(entry.path())
                && let Some(info) = parse_core_meta(&content)
            {
                cores.push(info);
            }
        }
    }

    cores.sort_by_key(|c| std::cmp::Reverse(c.timestamp));
    cores
}

#[derive(Debug)]
pub struct CoreInfo {
    pub exe: String,
    pub pid: u32,
    pub signal: u32,
    pub signal_name: String,
    pub timestamp: u64,
    pub size_bytes: u64,
    pub core_path: String,
}

fn parse_core_meta(json: &str) -> Option<CoreInfo> {
    // Simple key extraction without full JSON parsing
    let exe = extract_json_str(json, "exe")?;
    let pid = extract_json_u64(json, "pid")? as u32;
    let signal = extract_json_u64(json, "signal")? as u32;
    let sig_name = extract_json_str(json, "signal_name").unwrap_or_default();
    let timestamp = extract_json_u64(json, "timestamp")?;
    let size_bytes = extract_json_u64(json, "size_bytes")?;
    let core_path = extract_json_str(json, "core_path")?;
    Some(CoreInfo {
        exe,
        pid,
        signal,
        signal_name: sig_name,
        timestamp,
        size_bytes,
        core_path,
    })
}

fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\":\"", key);
    let start = json.find(&pat)? + pat.len();
    let end = json[start..].find('"')? + start;
    Some(json[start..end].to_string())
}

fn extract_json_u64(json: &str, key: &str) -> Option<u64> {
    let pat = format!("\"{}\":", key);
    let start = json.find(&pat)? + pat.len();
    let rest = &json[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn cleanup_old_cores(exe: &str) -> Result<()> {
    let dir = Path::new(COREDUMP_DIR);
    let prefix = format!("core.{}.", exe);

    let mut cores: Vec<(u64, String)> = Vec::new(); // (timestamp, path)
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(&prefix) && !name.ends_with(".json") {
                // Extract timestamp from filename: core.exe.pid.timestamp
                let parts: Vec<&str> = name.split('.').collect();
                if let Some(ts_str) = parts.get(3)
                    && let Ok(ts) = ts_str.parse::<u64>()
                {
                    cores.push((ts, entry.path().to_string_lossy().into_owned()));
                }
            }
        }
    }

    // Sort oldest first
    cores.sort_by_key(|(ts, _)| *ts);

    // Delete excess cores (keep newest MAX_CORES_PER_UNIT)
    while cores.len() > MAX_CORES_PER_UNIT {
        let (_, path) = cores.remove(0);
        fs::remove_file(&path).ok();
        fs::remove_file(format!("{}.json", path)).ok();
        info!("coredump: removed old core: {}", path);
    }

    Ok(())
}

fn signal_name(sig: u32) -> &'static str {
    match sig {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        31 => "SIGSYS",
        _ => "SIG?",
    }
}

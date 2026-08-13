/// Per-service cgroup v2 slice management
///
/// Creates `/sys/fs/cgroup/quantra-system/<service>/` for each service.
/// This provides:
/// - CPU + memory accounting (`cpu.stat`, `memory.current`)
/// - Hard resource limits (future: `memory.max`, `cpu.weight`)
/// - Atomic kill of all processes in the slice (`cgroup.kill`, Linux 5.14+)
///
/// Gracefully falls back to a no-op on cgroup v1 kernels where the unified
/// hierarchy is not mounted at `/sys/fs/cgroup/`.
use anyhow::Result;
use std::fs;
use std::path::Path;

const ZAINIUM_CGROUP_ROOT: &str = "/sys/fs/cgroup/quantra-system";
const CGROUP_V2_SENTINEL: &str = "/sys/fs/cgroup/cgroup.controllers";

/// Returns true if cgroup v2 unified hierarchy is available on this kernel.
#[inline]
pub fn is_cgroup_v2() -> bool {
    Path::new(CGROUP_V2_SENTINEL).exists()
}

/// Create a cgroup slice for the named service.
///
/// Idempotent — safe to call if the slice already exists.
/// Returns `Ok(())` on cgroup v1 (no-op).
pub fn create_service_cgroup(name: &str) -> Result<()> {
    if !is_cgroup_v2() {
        return Ok(());
    }
    let path = slice_path(name);
    fs::create_dir_all(&path)
        .map_err(|e| anyhow::anyhow!("Cannot create cgroup slice '{}': {}", path, e))?;
    log::debug!("cgroup slice created: {}", path);
    Ok(())
}

/// Move a PID into the service's cgroup slice.
///
/// Must be called in the **parent** after `fork()` returns the child PID.
pub fn assign_pid_to_cgroup(name: &str, pid: u32) -> Result<()> {
    if !is_cgroup_v2() {
        return Ok(());
    }
    let procs = format!("{}/cgroup.procs", slice_path(name));
    if !Path::new(&procs).exists() {
        return Ok(()); // Slice not created — skip
    }
    fs::write(&procs, pid.to_string())
        .map_err(|e| anyhow::anyhow!("Cannot assign PID {} to cgroup '{}': {}", pid, procs, e))?;
    log::debug!("PID {} → cgroup/{}", pid, name);
    Ok(())
}

/// Kill all processes in the service's cgroup slice atomically.
///
/// Uses `cgroup.kill` (Linux 5.14+). Falls back silently on older kernels.
pub fn kill_service_cgroup(name: &str) -> Result<()> {
    if !is_cgroup_v2() {
        return Ok(());
    }
    let kill_path = format!("{}/cgroup.kill", slice_path(name));
    if Path::new(&kill_path).exists() {
        fs::write(&kill_path, "1")
            .map_err(|e| anyhow::anyhow!("cgroup.kill failed for '{}': {}", name, e))?;
        log::info!("cgroup.kill issued for '{}'", name);
    }
    Ok(())
}

/// Read current memory usage in bytes for the service's cgroup slice.
/// Returns `None` on cgroup v1 or if not yet assigned.
#[allow(dead_code)] // Future: exposed via /proc/zainium/health monitoring endpoint
pub fn get_memory_bytes(name: &str) -> Option<u64> {
    if !is_cgroup_v2() {
        return None;
    }
    let path = format!("{}/memory.current", slice_path(name));
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Remove the service's cgroup slice directory (only succeeds when empty).
pub fn remove_service_cgroup(name: &str) {
    if !is_cgroup_v2() {
        return;
    }
    let _ = fs::remove_dir(slice_path(name));
}

/// Build the cgroup slice path for a service name.
fn slice_path(name: &str) -> String {
    format!("{}/{}", ZAINIUM_CGROUP_ROOT, sanitize(name))
}

/// Sanitize a service name for use as a directory name.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Apply CPU quota to service cgroup slice.
///
/// `quota_str` format: "50%" = 50% of one CPU, "200%" = 2 CPUs.
/// Maps to cgroup v2 `cpu.max` file format: "quota period" in microseconds.
/// Example: "50%" with default 100ms period → "50000 100000"
pub fn apply_cpu_quota(name: &str, quota_str: &str) -> Result<()> {
    if !is_cgroup_v2() {
        return Ok(());
    }
    let path = format!("{}/cpu.max", slice_path(name));
    if !std::path::Path::new(&path).exists() {
        return Ok(());
    }

    let quota_str = quota_str.trim();
    if quota_str == "max" || quota_str == "0" {
        std::fs::write(&path, "max 100000")?;
        return Ok(());
    }

    let pct: f64 = if let Some(p) = quota_str.strip_suffix('%') {
        p.trim()
            .parse::<f64>()
            .map_err(|_| anyhow::anyhow!("invalid cpu_quota: {}", quota_str))?
    } else {
        return Err(anyhow::anyhow!(
            "cpu_quota must end with '%': got '{}'",
            quota_str
        ));
    };

    // period = 100000 µs (100ms — kernel default)
    let period: u64 = 100_000;
    let quota_us = ((pct / 100.0) * period as f64) as u64;
    let val = format!("{} {}", quota_us, period);
    std::fs::write(&path, &val)
        .map_err(|e| anyhow::anyhow!("cpu.max write for '{}': {}", name, e))?;
    log::debug!("cgroup cpu.max='{}' for '{}'", val, name);
    Ok(())
}

/// Apply tasks (pids) maximum to service cgroup slice.
///
/// `n = 0` means unlimited (writes "max").
/// Maps to cgroup v2 `pids.max`.
pub fn apply_tasks_max(name: &str, n: u32) -> Result<()> {
    if !is_cgroup_v2() {
        return Ok(());
    }
    let path = format!("{}/pids.max", slice_path(name));
    if !std::path::Path::new(&path).exists() {
        return Ok(());
    }

    let val = if n == 0 {
        "max".to_string()
    } else {
        n.to_string()
    };
    std::fs::write(&path, &val)
        .map_err(|e| anyhow::anyhow!("pids.max write for '{}': {}", name, e))?;
    log::debug!("cgroup pids.max='{}' for '{}'", val, name);
    Ok(())
}

/// Apply swap memory maximum to service cgroup slice.
///
/// `swap_str`: "0" = no swap, "max" = unlimited, "512M" etc.
/// Maps to cgroup v2 `memory.swap.max`.
pub fn apply_memory_swap_max(name: &str, swap_str: &str) -> Result<()> {
    if !is_cgroup_v2() {
        return Ok(());
    }
    let path = format!("{}/memory.swap.max", slice_path(name));
    if !std::path::Path::new(&path).exists() {
        return Ok(());
    }

    let s = swap_str.trim();
    let val = if s == "max" {
        "max".to_string()
    } else if s == "0" {
        "0".to_string()
    } else {
        let bytes = super::types::parse_memory_limit(s);
        if bytes == 0 {
            "max".to_string()
        } else {
            bytes.to_string()
        }
    };
    std::fs::write(&path, &val)
        .map_err(|e| anyhow::anyhow!("memory.swap.max write for '{}': {}", name, e))?;
    log::debug!("cgroup memory.swap.max='{}' for '{}'", val, name);
    Ok(())
}

/// Apply per-device I/O weight to service cgroup.
///
/// `device` is the block device path (e.g. `/dev/sda`).
/// `weight` is in range 1–10000 (default 100).
/// Maps to cgroup v2 `io.weight` per-device entry.
pub fn apply_io_device_weight(name: &str, device: &str, weight: u32) -> Result<()> {
    if !is_cgroup_v2() {
        return Ok(());
    }
    let major_minor = get_device_major_minor(device)?;
    let path = format!("{}/io.weight", slice_path(name));
    if !std::path::Path::new(&path).exists() {
        return Ok(());
    }

    let val = format!("{} {}", major_minor, weight.clamp(1, 10000));
    std::fs::write(&path, &val)
        .map_err(|e| anyhow::anyhow!("io.weight device '{}': {}", device, e))?;
    log::debug!("cgroup io.weight='{}' for '{}'", val, name);
    Ok(())
}

/// Apply per-device I/O latency target to service cgroup.
///
/// `device`: block device path (e.g. `/dev/sda`).
/// `target_usec`: target latency in microseconds.
/// Maps to cgroup v2 `io.latency` file.
pub fn apply_io_device_latency(name: &str, device: &str, target_usec: u64) -> Result<()> {
    if !is_cgroup_v2() {
        return Ok(());
    }
    let major_minor = get_device_major_minor(device)?;
    let path = format!("{}/io.latency", slice_path(name));
    if !std::path::Path::new(&path).exists() {
        log::debug!("io.latency not available (kernel < 4.19 or blk-cgroup not compiled in)");
        return Ok(());
    }

    let val = format!("{} target={}", major_minor, target_usec);
    std::fs::write(&path, &val)
        .map_err(|e| anyhow::anyhow!("io.latency device '{}': {}", device, e))?;
    log::debug!("cgroup io.latency='{}' for '{}'", val, name);
    Ok(())
}

/// Get "major:minor" string for a block device path via sysfs.
fn get_device_major_minor(device: &str) -> Result<String> {
    // Read /sys/class/block/<name>/dev  → "major:minor\n"
    let dev_name = std::path::Path::new(device)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid device path: {}", device))?;

    let sysfs_dev = format!("/sys/class/block/{}/dev", dev_name);
    let content = std::fs::read_to_string(&sysfs_dev)
        .map_err(|e| anyhow::anyhow!("read {}: {} (device not found?)", sysfs_dev, e))?;
    Ok(content.trim().to_string())
}

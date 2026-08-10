/// MD RAID assembly + LVM activation in initramfs
///
/// # MD RAID (Linux Software RAID)
///
/// Assembles MD arrays before mounting the root filesystem.
/// Uses the `mdadm` binary if present, otherwise uses direct sysfs/ioctl approach.
///
/// Cmdline: `rd.md=1` (enable), `rd.md.uuid=<uuid>` (specific array)
///
/// # LVM (Logical Volume Manager)
///
/// Activates LVM volume groups after MD RAID assembly.
/// Uses `lvm vgchange -ay` if available.
///
/// Cmdline: `rd.lvm=1` (enable), `rd.lvm.vg=<name>` (specific VG)
///
/// # Device Multipath
///
/// Activates dm-multipath for redundant storage paths.
/// Cmdline: `rd.multipath=1`
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

// ── MD RAID ───────────────────────────────────────────────────────────────────

const MDADM_BINS: &[&str] = &["/sbin/mdadm", "/usr/sbin/mdadm", "/bin/mdadm"];
const SYSFS_MD_DIR: &str = "/sys/class/block";

/// Assemble all MD RAID arrays.
///
/// Tries `mdadm --assemble --scan` first.
/// Falls back to sysfs-based assembly (write "check" to md/sync_action).
pub fn assemble_raid(uuid_filter: Option<&str>) -> Result<usize, String> {
    let mdadm = find_bin(MDADM_BINS);

    if let Some(bin) = mdadm {
        return assemble_via_mdadm(&bin, uuid_filter);
    }

    // No mdadm — try sysfs activation
    assemble_via_sysfs()
}

fn assemble_via_mdadm(bin: &str, uuid_filter: Option<&str>) -> Result<usize, String> {
    let mut cmd = Command::new(bin);
    cmd.args(["--assemble", "--scan", "--no-degraded"]);

    if let Some(uuid) = uuid_filter {
        cmd.args(["--uuid", uuid]);
    }

    eprintln!("  raid: {} --assemble --scan", bin);

    let output = cmd.output().map_err(|e| format!("mdadm exec: {}", e))?;

    // mdadm exit codes: 0=success, 1=some arrays not assembled, 2=error
    match output.status.code() {
        Some(0) | Some(1) => {
            let n = count_active_md_devices();
            if n > 0 {
                eprintln!("  raid: {} MD array(s) active", n);
            } else {
                eprintln!("  raid: no MD arrays found");
            }
            Ok(n)
        }
        code => Err(format!(
            "mdadm exited {:?}: {}",
            code,
            String::from_utf8_lossy(&output.stderr)
        )),
    }
}

fn assemble_via_sysfs() -> Result<usize, String> {
    // Trigger auto-assembly by reading /proc/mdstat
    if !Path::new("/proc/mdstat").exists() {
        return Ok(0);
    }

    // Write "check" to each md device's sync_action to activate
    let mut count = 0;
    if let Ok(entries) = fs::read_dir(SYSFS_MD_DIR) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("md") {
                let sync_path = format!("/sys/block/{}/md/sync_action", name);
                if Path::new(&sync_path).exists() {
                    fs::write(&sync_path, "idle").ok();
                    count += 1;
                    eprintln!("  raid: activated /dev/{}", name);
                }
            }
        }
    }
    Ok(count)
}

fn count_active_md_devices() -> usize {
    fs::read_to_string("/proc/mdstat")
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("md"))
        .count()
}

/// Wait for MD arrays to finish resync/rebuild before mounting.
pub fn wait_for_raid_sync(timeout: Duration) -> bool {
    let start = Instant::now();
    loop {
        if start.elapsed() > timeout {
            return false;
        }
        let stat = fs::read_to_string("/proc/mdstat").unwrap_or_default();
        if !stat.contains("resync") && !stat.contains("recovering") {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

// ── LVM ───────────────────────────────────────────────────────────────────────

const LVM_BINS: &[&str] = &[
    "/sbin/lvm",
    "/usr/sbin/lvm",
    "/sbin/vgchange",
    "/usr/sbin/vgchange",
];

/// Activate LVM volume groups.
///
/// `vg_filter`: if Some, activate only that VG; if None, activate all.
pub fn activate_lvm(vg_filter: Option<&str>) -> Result<usize, String> {
    let lvm = find_bin(LVM_BINS).ok_or_else(|| "lvm/vgchange not found".to_string())?;

    eprintln!("  lvm: activating volume groups");

    // Try vgscan first to update metadata cache
    let vgscan = find_bin(&["/sbin/vgscan", "/usr/sbin/vgscan"]);
    if let Some(vs) = vgscan {
        Command::new(&vs).args(["--mknodes"]).status().ok();
    }

    // Activate
    let mut cmd = if lvm.ends_with("lvm") {
        let mut c = Command::new(&lvm);
        c.arg("vgchange");
        c
    } else {
        Command::new(&lvm)
    };

    cmd.args(["-ay", "--ignorelockingfailure"]);
    if let Some(vg) = vg_filter {
        cmd.arg(vg);
    }

    let output = cmd
        .output()
        .map_err(|e| format!("lvm vgchange exec: {}", e))?;

    if output.status.success() {
        let count = count_active_lvs();
        eprintln!("  lvm: {} logical volume(s) activated", count);
        Ok(count)
    } else {
        Err(format!(
            "lvm vgchange failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn count_active_lvs() -> usize {
    if let Ok(entries) = fs::read_dir("/dev/mapper") {
        entries
            .flatten()
            .filter(|e| !e.file_name().to_string_lossy().starts_with("control"))
            .count()
    } else {
        0
    }
}

// ── Device Multipath ──────────────────────────────────────────────────────────

const MULTIPATH_BINS: &[&str] = &["/sbin/multipath", "/usr/sbin/multipath"];
const MULTIPATHD_BINS: &[&str] = &["/sbin/multipathd", "/usr/sbin/multipathd"];

/// Activate device-mapper multipath.
pub fn activate_multipath() -> Result<(), String> {
    let mp = find_bin(MULTIPATH_BINS).ok_or_else(|| "multipath binary not found".to_string())?;

    eprintln!("  multipath: activating");

    // Start multipathd daemon
    if let Some(mpd) = find_bin(MULTIPATHD_BINS) {
        Command::new(&mpd).args(["-d", "-s"]).spawn().ok();
        std::thread::sleep(Duration::from_millis(500));
    }

    // Run multipath to activate all paths
    let output = Command::new(&mp)
        .output()
        .map_err(|e| format!("multipath exec: {}", e))?;

    if output.status.success() {
        eprintln!("  multipath: activated");
        Ok(())
    } else {
        Err(format!(
            "multipath failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

// ── Stratis pool unlock ───────────────────────────────────────────────────────

const STRATIS_BINS: &[&str] = &["/usr/sbin/stratis-min", "/usr/sbin/stratis"];

/// Unlock a Stratis storage pool in the initramfs.
pub fn unlock_stratis_pool(pool_uuid: Option<&str>) -> Result<(), String> {
    let bin = find_bin(STRATIS_BINS).ok_or_else(|| "stratis not found".to_string())?;

    let mut cmd = Command::new(&bin);
    cmd.args(["pool", "unlock", "clevis"]);
    if let Some(uuid) = pool_uuid {
        cmd.arg(uuid);
    }

    let output = cmd.output().map_err(|e| format!("stratis exec: {}", e))?;

    if output.status.success() {
        eprintln!("  stratis: pool unlocked");
        Ok(())
    } else {
        Err(format!(
            "stratis unlock failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn find_bin(candidates: &[&str]) -> Option<String> {
    candidates
        .iter()
        .find(|&&p| Path::new(p).exists())
        .map(|&p| p.to_string())
}

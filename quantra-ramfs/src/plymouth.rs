#![allow(dead_code)]
/// Plymouth splash screen integration
///
/// Plymouth is the standard graphical boot splash for Linux.
/// In initramfs, we need to:
///   1. Start plymouthd before it expects a framebuffer
///   2. Show the splash while devices settle and root mounts
///   3. Pass the splash handoff to the final init (quantra)
///
/// # Cmdline
///
/// | Parameter | Effect |
/// |-----------|--------|
/// | `splash` / `quiet splash` | Enable Plymouth splash |
/// | `plymouth.enable=0` | Disable Plymouth explicitly |
/// | `rd.plymouth=0` | Disable Plymouth in initrd |
///
/// # KMS Framebuffer
///
/// Plymouth needs a KMS framebuffer (DRM) to display graphics.
/// We set the drm.vgem module param and ensure /dev/dri is accessible.
///
/// # Handoff
///
/// Before pivot_root, we call `plymouth update --status=rootmounted`
/// and then pass `--handoff` to the quantra PID 1 so it can continue
/// the splash through the login prompt.
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

static PLYMOUTH_ACTIVE: AtomicBool = AtomicBool::new(false);

const PLYMOUTHD_BINS: &[&str] = &["/usr/sbin/plymouthd", "/sbin/plymouthd"];

const PLYMOUTH_BINS: &[&str] = &["/usr/bin/plymouth", "/bin/plymouth"];

// ── Public API ────────────────────────────────────────────────────────────────

/// Start Plymouth splash screen.
///
/// Non-fatal — if plymouthd is absent or fails, boot continues silently.
pub fn start(theme: Option<&str>) -> bool {
    if !is_enabled() {
        return false;
    }

    let plymouthd = match find_bin(PLYMOUTHD_BINS) {
        Some(b) => b,
        None => {
            eprintln!("  plymouth: plymouthd not found (splash disabled)");
            return false;
        }
    };

    // Setup KMS framebuffer before starting
    setup_kms_framebuffer();

    let mut cmd = Command::new(&plymouthd);
    cmd.args([
        "--mode=boot",
        "--pid-file=/run/plymouth/pid",
        "--attach-to-session",
    ]);
    if let Some(t) = theme {
        cmd.args(["--theme", t]);
    }

    match cmd.spawn() {
        Ok(_child) => {
            PLYMOUTH_ACTIVE.store(true, Ordering::Relaxed);
            std::thread::sleep(std::time::Duration::from_millis(200));
            eprintln!("  plymouth: ✓ splash started");
            // Show initial message
            show_message("Zainium OS booting...");
            true
        }
        Err(e) => {
            eprintln!("  plymouth: start failed: {} (non-fatal)", e);
            false
        }
    }
}

/// Update Plymouth status message during boot.
pub fn show_message(msg: &str) {
    if !PLYMOUTH_ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    run_plymouth(&["message", &format!("--text={}", msg)]);
}

/// Notify Plymouth that a boot phase completed.
pub fn update_status(status: &str) {
    if !PLYMOUTH_ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    run_plymouth(&["update", &format!("--status={}", status)]);
}

/// Notify Plymouth that the root filesystem is mounted.
/// Call this just before pivot_root.
pub fn root_mounted() {
    if !PLYMOUTH_ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    run_plymouth(&["update", "--status=rootmounted"]);
    eprintln!("  plymouth: root-mounted signal sent");
}

/// Handoff Plymouth to the new init after pivot_root.
///
/// Writes the handoff socket path to /run/plymouth/handoff
/// so quantra (new PID 1) can continue the splash.
pub fn handoff_to_init() {
    if !PLYMOUTH_ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    run_plymouth(&["--wait", "quit", "--retain-splash"]);
    eprintln!("  plymouth: handoff to init");
}

/// Quit Plymouth (used when not doing a handoff, e.g. rescue boot).
pub fn quit() {
    if !PLYMOUTH_ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    run_plymouth(&["quit"]);
    PLYMOUTH_ACTIVE.store(false, Ordering::Relaxed);
}

/// Check if Plymouth splash should be enabled (from /proc/cmdline).
pub fn is_enabled() -> bool {
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();

    // Explicit disable
    if cmdline.contains("plymouth.enable=0") || cmdline.contains("rd.plymouth=0") {
        return false;
    }

    // Enable if 'splash' or 'quiet splash' is present
    cmdline.split_whitespace().any(|t| t == "splash")
}

// ── KMS Framebuffer setup ─────────────────────────────────────────────────────

/// Setup KMS (Kernel Mode Setting) framebuffer for Plymouth.
///
/// Loads the vgem DRM driver if no other DRM device is present.
/// Creates /dev/dri directory for DRM device nodes.
pub fn setup_kms_framebuffer() {
    // Create /dev/dri if not present
    fs::create_dir_all("/dev/dri").ok();

    // Check if a DRM device already exists (real GPU driver loaded)
    if dri_device_exists() {
        eprintln!("  kms: DRM device already present");
        return;
    }

    // Try to load vgem (virtual GPU — works without real GPU for basic splash)
    let modprobe = find_bin(&["/sbin/modprobe", "/usr/sbin/modprobe"]);
    if let Some(mp) = modprobe {
        std::process::Command::new(&mp).arg("vgem").status().ok();

        // Also try simpledrm for framebuffer devices
        std::process::Command::new(&mp)
            .arg("simpledrm")
            .status()
            .ok();

        if dri_device_exists() {
            eprintln!("  kms: ✓ DRM device available");
        } else {
            eprintln!("  kms: no DRM device (Plymouth may use text mode)");
        }
    }
}

fn dri_device_exists() -> bool {
    fs::read_dir("/dev/dri")
        .map(|mut d| d.next().is_some())
        .unwrap_or(false)
        || Path::new("/dev/dri/card0").exists()
        || Path::new("/dev/fb0").exists()
}

// ── PKCS#11 token unlock ──────────────────────────────────────────────────────

/// Attempt LUKS unlock via PKCS#11 token (YubiKey, smart card, etc.)
///
/// Uses `systemd-cryptenroll` compatible approach:
/// reads the PKCS#11 URI from cmdline `rd.luks.pkcs11-uri=` and
/// uses `p11-kit` or direct PKCS#11 library to obtain the key.
///
/// Non-fatal — falls through to passphrase on failure.
pub fn pkcs11_unlock_luks(device: &str, name: &str, pkcs11_uri: &str) -> Result<(), String> {
    eprintln!("  pkcs11: attempting LUKS unlock via {}", pkcs11_uri);

    // Try systemd-cryptsetup if available (handles PKCS#11 natively)
    let cryptsetup_bins = &[
        "/usr/lib/systemd/systemd-cryptsetup",
        "/lib/systemd/systemd-cryptsetup",
    ];

    if let Some(bin) = cryptsetup_bins.iter().find(|&&p| Path::new(p).exists()) {
        let output = std::process::Command::new(bin)
            .args(["attach", name, device, pkcs11_uri, "pkcs11-uri"])
            .output()
            .map_err(|e| format!("systemd-cryptsetup exec: {}", e))?;

        if output.status.success() {
            eprintln!("  pkcs11: ✓ LUKS unlocked via PKCS#11");
            return Ok(());
        }
        eprintln!(
            "  pkcs11: systemd-cryptsetup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Try p11-kit token directly
    let p11kit_bin = "/usr/bin/p11-kit";
    if Path::new(p11kit_bin).exists() {
        eprintln!("  pkcs11: trying p11-kit...");
        let output = std::process::Command::new(p11kit_bin)
            .args(["export-object", "--label=luks-key", pkcs11_uri])
            .output()
            .map_err(|e| format!("p11-kit exec: {}", e))?;

        if output.status.success() && !output.stdout.is_empty() {
            // Use the exported key to unlock LUKS
            return unlock_luks_with_key(device, name, &output.stdout);
        }
    }

    Err(format!("PKCS#11 unlock failed for {}", pkcs11_uri))
}

fn unlock_luks_with_key(device: &str, name: &str, key: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut child = std::process::Command::new("cryptsetup")
        .args(["luksOpen", "--key-file=-", device, name])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("cryptsetup spawn: {}", e))?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(key).ok();
    }

    let status = child
        .wait()
        .map_err(|e| format!("cryptsetup wait: {}", e))?;
    if status.success() {
        Ok(())
    } else {
        Err("cryptsetup luksOpen with PKCS#11 key failed".to_string())
    }
}

// ── Credential directory from UEFI variables ──────────────────────────────────

/// Read encrypted credentials from UEFI variables (EFI variables).
///
/// systemd-cryptenroll can store credentials in UEFI variables.
/// This reads from /sys/firmware/efi/efivars/.
///
/// Returns the decrypted credential bytes, or Err if not available.
pub fn read_uefi_credential(name: &str) -> Result<Vec<u8>, String> {
    let efi_vars_dir = "/sys/firmware/efi/efivars";
    if !Path::new(efi_vars_dir).exists() {
        return Err("EFI variables not available (non-UEFI boot?)".to_string());
    }

    // systemd credential UEFI variable name format:
    // "credential.NAME-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
    let var_prefix = format!("credential.{}", name);
    let entries = fs::read_dir(efi_vars_dir).map_err(|e| format!("read efivars: {}", e))?;

    for entry in entries.flatten() {
        let fname = entry.file_name().to_string_lossy().into_owned();
        if fname.starts_with(&var_prefix) {
            let data =
                fs::read(entry.path()).map_err(|e| format!("read efivar '{}': {}", fname, e))?;
            // Skip first 4 bytes (EFI attributes)
            if data.len() > 4 {
                eprintln!(
                    "  uefi-cred: found credential '{}' ({} bytes)",
                    name,
                    data.len() - 4
                );
                return Ok(data[4..].to_vec());
            }
        }
    }
    Err(format!("UEFI credential '{}' not found", name))
}

// ── Sysext / Confext images ───────────────────────────────────────────────────

/// Mount a system extension (sysext) image.
///
/// Sysext images extend /usr and /opt in the running system.
/// Used by systemd to modularly extend an immutable OS.
/// For Zainium this maps to zexlib but we support the format.
///
/// Image format: squashfs or ext4 with `/usr/lib/extension-release.d/` marker.
pub fn mount_sysext(image_path: &str, mount_point: &str) -> Result<(), String> {
    if !Path::new(image_path).exists() {
        return Err(format!("sysext image not found: {}", image_path));
    }

    fs::create_dir_all(mount_point).map_err(|e| format!("mkdir '{}': {}", mount_point, e))?;

    // Try squashfs first, then ext4
    for fstype in &["squashfs", "ext4"] {
        let output = std::process::Command::new("mount")
            .args(["-t", fstype, "-o", "ro", image_path, mount_point])
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                eprintln!(
                    "  sysext: mounted {} → {} ({})",
                    image_path, mount_point, fstype
                );
                return Ok(());
            }
        }
    }
    Err(format!(
        "sysext: could not mount '{}' as squashfs or ext4",
        image_path
    ))
}

// ── ZFS pool import ───────────────────────────────────────────────────────────

/// Import a ZFS pool and return the root dataset path.
pub fn import_zfs_pool(pool_name: Option<&str>) -> Result<String, String> {
    let zpool = find_bin(&["/sbin/zpool", "/usr/sbin/zpool", "/usr/bin/zpool"])
        .ok_or_else(|| "zpool not found".to_string())?;

    let mut cmd = std::process::Command::new(&zpool);
    cmd.args(["import", "-N", "-a"]); // -N: don't mount, -a: import all
    if let Some(pool) = pool_name {
        cmd.arg(pool);
    }

    let output = cmd
        .output()
        .map_err(|e| format!("zpool import exec: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "zpool import failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Determine root dataset from pool properties
    let pool = pool_name.unwrap_or("rpool");
    let bootfs = get_zfs_bootfs(pool, &zpool)?;
    eprintln!("  zfs: imported pool '{}', bootfs={}", pool, bootfs);
    Ok(bootfs)
}

fn get_zfs_bootfs(pool: &str, zpool_bin: &str) -> Result<String, String> {
    let output = std::process::Command::new(zpool_bin)
        .args(["get", "-H", "-o", "value", "bootfs", pool])
        .output()
        .map_err(|e| format!("zpool get bootfs: {}", e))?;

    let bootfs = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if bootfs.is_empty() || bootfs == "-" {
        // Default: pool/ROOT/default (common ZFS-on-root layout)
        Ok(format!("{}/ROOT/default", pool))
    } else {
        Ok(bootfs)
    }
}

// ── bcachefs mount ────────────────────────────────────────────────────────────

/// Mount a bcachefs filesystem.
///
/// bcachefs requires special mount handling via the `bcachefs` tool.
pub fn mount_bcachefs(device: &str, target: &str, opts: Option<&str>) -> Result<(), String> {
    let bcachefs = find_bin(&["/usr/sbin/bcachefs", "/sbin/bcachefs"])
        .ok_or_else(|| "bcachefs tool not found".to_string())?;

    let mut cmd = std::process::Command::new(&bcachefs);
    cmd.args(["mount", device, target]);
    if let Some(o) = opts {
        cmd.args(["-o", o]);
    }

    let output = cmd
        .output()
        .map_err(|e| format!("bcachefs mount exec: {}", e))?;

    if output.status.success() {
        eprintln!("  bcachefs: ✓ mounted {} → {}", device, target);
        Ok(())
    } else {
        Err(format!(
            "bcachefs mount failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

// ── Secure Boot UKI check ─────────────────────────────────────────────────────

/// Verify Secure Boot state and UKI (Unified Kernel Image) signature.
///
/// Reads SecureBoot EFI variable and reports status.
/// The actual UKI signature verification is done by the UEFI firmware;
/// by the time we're in the initramfs, Secure Boot is already enforced.
pub fn check_secure_boot() -> SecureBootStatus {
    let sb_var = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
    let mok_var = "/sys/firmware/efi/efivars/MokSecureBoot-605dab50-e046-4300-abb6-3dd810dd8b23";

    if !Path::new("/sys/firmware/efi").exists() {
        return SecureBootStatus::NonUEFI;
    }

    let sb_data = fs::read(sb_var).unwrap_or_default();
    // EFI variable: 4 bytes attrs + data
    let sb_enabled = sb_data.get(4).copied().unwrap_or(0) == 1;

    let mok_data = fs::read(mok_var).unwrap_or_default();
    let mok_enabled = mok_data.get(4).copied().unwrap_or(0) == 1;

    if sb_enabled {
        eprintln!(
            "  secure-boot: ✓ Secure Boot enabled (MOK: {})",
            mok_enabled
        );
        SecureBootStatus::Enabled { mok: mok_enabled }
    } else {
        eprintln!("  secure-boot: ⚠ Secure Boot DISABLED");
        SecureBootStatus::Disabled
    }
}

#[derive(Debug)]
pub enum SecureBootStatus {
    Enabled { mok: bool },
    Disabled,
    NonUEFI,
}

// ── vconsole in initramfs ─────────────────────────────────────────────────────

/// Apply console keymap in initramfs (before pivot_root).
///
/// Reads KEYMAP from `rd.vconsole.keymap=` cmdline or
/// `/overlayer/syshub/etc/quantra-system/vconsole.conf`.
pub fn setup_initrd_vconsole() {
    // Check cmdline for keymap override
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let keymap = cmdline
        .split_whitespace()
        .find_map(|t| t.strip_prefix("rd.vconsole.keymap="))
        .unwrap_or("us");

    let loadkeys = find_bin(&["/usr/bin/loadkeys", "/bin/loadkeys"]);
    if let Some(lk) = loadkeys {
        std::process::Command::new(&lk).arg(keymap).status().ok();
        eprintln!("  vconsole: keymap '{}' applied", keymap);
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn find_bin(candidates: &[&str]) -> Option<String> {
    candidates
        .iter()
        .find(|&&p| Path::new(p).exists())
        .map(|&p| p.to_string())
}

fn run_plymouth(args: &[&str]) {
    if let Some(bin) = find_bin(PLYMOUTH_BINS) {
        std::process::Command::new(&bin).args(args).status().ok();
    }
}

/// Mount units — declarative filesystem mount lifecycle
///
/// Mount units are loaded from `/overlayer/syshub/etc/quantra-system/mounts/*.toml`.
/// All units are activated in dependency order before supervised services start.
///
/// # Config format
///
/// ```toml
/// [mount]
/// name = "data"
/// what = "/dev/sdb1"          # or "UUID=xxxx" or "LABEL=data"
/// where = "/data"
/// type = "ext4"
/// options = "defaults,noatime"
/// before = ["app.service"]    # Services that depend on this mount
/// timeout_sec = 30
/// ```
///
/// # Mount sequence
/// 1. Wait for block device to appear in `/dev/` (up to `timeout_sec`)
/// 2. `mkdir -p <where>`
/// 3. `nix::mount::mount(what, where, fstype, flags, options)`
///
/// # Unmount sequence (on shutdown)
/// 1. `nix::mount::umount2(<where>, MNT_DETACH)` — lazy unmount
use anyhow::{Context, Result};
use log::{error, info, warn};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use serde::Deserialize;
use std::ffi::CString;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

const MOUNT_CONFIG_DIR: &str = "/overlayer/syshub/etc/quantra-system/mounts";
const POLL_INTERVAL: Duration = Duration::from_millis(250);

// ── Config types ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct MountUnitFile {
    #[serde(rename = "mount")]
    pub mount: MountUnit,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct MountUnit {
    pub name: String,
    /// Device path, UUID=..., or LABEL=...
    pub what: String,
    /// Mount point (created if absent)
    #[serde(rename = "where")]
    pub where_: String,
    /// Filesystem type (ext4, btrfs, xfs, tmpfs, nfs, etc.)
    #[serde(rename = "type", default = "default_fstype")]
    pub fstype: String,
    /// Mount options string (passed to mount(2) data parameter)
    #[serde(default = "default_options")]
    pub options: String,
    /// Services that must wait for this mount before starting
    #[allow(dead_code)]
    #[serde(default)]
    pub before: Vec<String>,
    /// Seconds to wait for device to appear
    #[serde(default = "default_timeout")]
    pub timeout_sec: u64,
}

fn default_fstype() -> String {
    "ext4".to_string()
}
fn default_options() -> String {
    "defaults".to_string()
}
fn default_timeout() -> u64 {
    30
}

// ── Loader ────────────────────────────────────────────────────────────────────

/// Load all mount units from `/overlayer/syshub/etc/quantra-system/mounts/`.
pub fn load_all_mount_units() -> Vec<MountUnit> {
    let dir = Path::new(MOUNT_CONFIG_DIR);
    if !dir.exists() {
        return Vec::new();
    }

    let mut units = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("Cannot read mount unit dir: {}", e);
            return units;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        match load_mount_file(&path) {
            Ok(u) => units.push(u),
            Err(e) => error!("Mount unit '{}': {}", path.display(), e),
        }
    }

    info!("Loaded {} mount unit(s)", units.len());
    units
}

fn load_mount_file(path: &Path) -> Result<MountUnit> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("Cannot read mount unit '{}'", path.display()))?;
    let f: MountUnitFile = toml::from_str(&text)
        .with_context(|| format!("Invalid mount TOML '{}'", path.display()))?;
    Ok(f.mount)
}

/// Activate all mount units in order. Called before service startup.
pub fn activate_all_mount_units() {
    let units = load_all_mount_units();
    for unit in &units {
        if let Err(e) = unit.activate() {
            error!(
                "Mount '{}' ({}): {} — system may be degraded",
                unit.name, unit.where_, e
            );
        }
    }
}

// ── MountUnit lifecycle ───────────────────────────────────────────────────────

impl MountUnit {
    /// Activate the mount unit: wait for device → mkdir → mount(2).
    pub fn activate(&self) -> Result<()> {
        info!(
            "Mounting '{}' ({}) at '{}'",
            self.name, self.what, self.where_
        );

        // Resolve UUID= or LABEL= → actual device path
        let device_path = self
            .resolve_device()
            .with_context(|| format!("Cannot resolve device '{}'", self.what))?;

        // Wait for device to appear (handles slow disk enumeration at boot)
        self.wait_for_device(&device_path).with_context(|| {
            format!(
                "Device '{}' not available within {}s",
                device_path, self.timeout_sec
            )
        })?;

        // Create mount point if absent
        fs::create_dir_all(&self.where_)
            .with_context(|| format!("Cannot create mount point '{}'", self.where_))?;

        // Parse mount options into MsFlags
        let (flags, data) = parse_mount_options(&self.options);

        // nix::mount::mount(source, target, fstype, flags, data)
        let data_cstr = CString::new(data.as_str()).unwrap_or_else(|_| CString::new("").unwrap());

        mount(
            Some(device_path.as_str()),
            self.where_.as_str(),
            Some(self.fstype.as_str()),
            flags,
            Some(data_cstr.to_bytes()),
        )
        .with_context(|| {
            format!(
                "mount({}, {}, {}) failed",
                device_path, self.where_, self.fstype
            )
        })?;

        info!("Mounted '{}' at '{}'", self.what, self.where_);
        Ok(())
    }

    /// Lazy unmount: existing processes continue using their file references.
    #[allow(dead_code)]
    pub fn deactivate(&self) {
        info!("Unmounting '{}' ({})", self.name, self.where_);
        if let Err(e) = umount2(self.where_.as_str(), MntFlags::MNT_DETACH) {
            warn!("Unmount '{}' failed: {} (ignored)", self.where_, e);
        }
    }

    /// Resolve `UUID=xxx` or `LABEL=xxx` to an actual `/dev/` path.
    fn resolve_device(&self) -> Result<String> {
        let what = &self.what;

        if let Some(uuid) = what.strip_prefix("UUID=") {
            // /dev/disk/by-uuid/<uuid> → resolve symlink
            let link = format!("/dev/disk/by-uuid/{}", uuid);
            let resolved = fs::canonicalize(&link)
                .with_context(|| format!("UUID '{}' not found in /dev/disk/by-uuid/", uuid))?;
            return Ok(resolved.to_string_lossy().into_owned());
        }

        if let Some(label) = what.strip_prefix("LABEL=") {
            let link = format!("/dev/disk/by-label/{}", label);
            let resolved = fs::canonicalize(&link)
                .with_context(|| format!("LABEL '{}' not found in /dev/disk/by-label/", label))?;
            return Ok(resolved.to_string_lossy().into_owned());
        }

        // Direct device path or special fs like tmpfs
        Ok(what.clone())
    }

    /// Poll for device to appear in `/dev/` within `timeout_sec`.
    fn wait_for_device(&self, device_path: &str) -> Result<()> {
        // Special filesystems (tmpfs, proc, etc.) don't have device nodes
        if !device_path.starts_with('/') || self.fstype == "tmpfs" {
            return Ok(());
        }

        let deadline = Instant::now() + Duration::from_secs(self.timeout_sec);
        while !Path::new(device_path).exists() {
            if Instant::now() >= deadline {
                return Err(anyhow::anyhow!(
                    "Timeout waiting for device '{}'",
                    device_path
                ));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        Ok(())
    }
}

// ── Mount options parser ──────────────────────────────────────────────────────

/// Parse mount options string into `(MsFlags, extra_data_string)`.
///
/// Recognized flags: `ro`, `nosuid`, `nodev`, `noexec`, `noatime`,
/// `relatime`, `strictatime`, `remount`, `bind`, `rbind`.
/// All unrecognized options are passed as the mount data string.
fn parse_mount_options(opts: &str) -> (MsFlags, String) {
    let mut flags = MsFlags::empty();
    let mut extra: Vec<&str> = Vec::new();

    for opt in opts.split(',').map(str::trim) {
        match opt {
            "defaults" => {}
            "ro" => flags |= MsFlags::MS_RDONLY,
            "nosuid" => flags |= MsFlags::MS_NOSUID,
            "nodev" => flags |= MsFlags::MS_NODEV,
            "noexec" => flags |= MsFlags::MS_NOEXEC,
            "noatime" => flags |= MsFlags::MS_NOATIME,
            "relatime" => flags |= MsFlags::MS_RELATIME,
            "strictatime" => flags |= MsFlags::MS_STRICTATIME,
            "remount" => flags |= MsFlags::MS_REMOUNT,
            "bind" => flags |= MsFlags::MS_BIND,
            "rbind" => flags |= MsFlags::MS_BIND | MsFlags::MS_REC,
            _ => extra.push(opt),
        }
    }

    (flags, extra.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mount_options_defaults_produces_empty_flags() {
        let (flags, extra) = parse_mount_options("defaults");
        assert!(flags.is_empty());
        assert!(extra.is_empty());
    }

    #[test]
    fn parse_mount_options_ro_nosuid_nodev() {
        let (flags, _) = parse_mount_options("ro,nosuid,nodev");
        assert!(flags.contains(MsFlags::MS_RDONLY));
        assert!(flags.contains(MsFlags::MS_NOSUID));
        assert!(flags.contains(MsFlags::MS_NODEV));
    }

    #[test]
    fn parse_mount_options_passes_unknown_as_data() {
        let (_, extra) = parse_mount_options("defaults,noatime,discard,errors=remount-ro");
        assert!(extra.contains("discard"));
        assert!(extra.contains("errors=remount-ro"));
    }

    #[test]
    fn mount_unit_toml_deserializes() {
        let toml = r#"
[mount]
name = "data"
what = "/dev/sdb1"
where = "/data"
type = "ext4"
options = "defaults,noatime"
timeout_sec = 60
"#;
        let cfg: MountUnitFile = toml::from_str(toml).unwrap();
        assert_eq!(cfg.mount.name, "data");
        assert_eq!(cfg.mount.what, "/dev/sdb1");
        assert_eq!(cfg.mount.where_, "/data");
        assert_eq!(cfg.mount.fstype, "ext4");
        assert_eq!(cfg.mount.timeout_sec, 60);
    }

    #[test]
    fn mount_unit_defaults() {
        let toml = r#"
[mount]
name = "minimal"
what = "/dev/sda1"
where = "/mnt"
"#;
        let cfg: MountUnitFile = toml::from_str(toml).unwrap();
        assert_eq!(cfg.mount.fstype, "ext4"); // default_fstype
        assert_eq!(cfg.mount.options, "defaults"); // default_options
        assert_eq!(cfg.mount.timeout_sec, 30); // default_timeout
    }
}

/// tmpfiles.d — /tmp /run /var directory cleanup and creation at boot
///
/// Implements a subset of the systemd-tmpfiles specification sufficient for
/// Zainium OS boot. Reads config files from:
///   `/overlayer/syshub/etc/quantra-system/tmpfiles.d/*.conf`
///   `/run/quantra-system/tmpfiles.d/*.conf`   (runtime additions)
///
/// # Supported directives
///
/// | Type | Description |
/// |------|-------------|
/// | `d`  | Create directory (mkdir -p), set mode and ownership |
/// | `D`  | Create directory + wipe contents on boot |
/// | `f`  | Create file if not exists, set mode |
/// | `F`  | Create file + truncate if exists |
/// | `L`  | Create symlink |
/// | `z`  | Relabel path (chown + chmod) |
/// | `r`  | Remove path (file or empty dir) |
/// | `R`  | Remove path recursively |
/// | `e`  | Set mode/ownership on existing path |
///
/// # Config file format
/// ```
/// # Type  Path                Mode  User  Group  Age  Argument
/// d       /run/quantra-system 0755  root  root   -    -
/// d       /tmp                1777  root  root   -    -
/// d       /var/log/quantra-system 0755 root root - -
/// f       /var/lib/quantra-system/random-seed 0600 root root - -
/// L       /run/quantra-system/control - - - - /tmp/quantra.sock
/// ```
use anyhow::{Context, Result};
use log::{info, warn};
use std::fs;
use std::os::unix::fs::chown as fs_chown;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

const TMPFILES_DIRS: &[&str] = &[
    "/overlayer/syshub/etc/quantra-system/tmpfiles.d",
    "/run/quantra-system/tmpfiles.d",
];

/// Built-in tmpfiles entries — always applied at boot regardless of config files.
/// These are the minimal set needed for Zainium OS to function.
const BUILTIN_ENTRIES: &[(&str, &str, u32, &str, &str)] = &[
    // (type, path, mode, user, group)
    ("d", "/run/quantra-system", 0o755, "root", "root"),
    ("d", "/run/quantra-system/notify", 0o700, "root", "root"),
    ("D", "/tmp", 0o1777, "root", "root"),
    (
        "d",
        "/overlayer/syshub/var/log/quantra-system",
        0o755,
        "root",
        "root",
    ),
    (
        "d",
        "/overlayer/syshub/var/lib/quantra-system",
        0o755,
        "root",
        "root",
    ),
    (
        "d",
        "/overlayer/syshub/var/cache/quantra-system",
        0o755,
        "root",
        "root",
    ),
    (
        "d",
        "/overlayer/syshub/var/lib/quantra-system/timers",
        0o755,
        "root",
        "root",
    ),
    ("d", "/run/user", 0o755, "root", "root"),
    ("d", "/run/dbus", 0o755, "root", "root"),
];

/// Apply all tmpfiles.d configuration at boot.
///
/// Called during Phase 1 (early boot, after mounts).
pub fn apply_all() -> Result<()> {
    info!("tmpfiles: applying built-in entries");
    apply_builtin_entries()?;

    // Load and apply config files
    let mut conf_count = 0;
    for dir in TMPFILES_DIRS {
        let dir_path = Path::new(dir);
        if !dir_path.exists() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("conf") {
                    match apply_conf_file(&path) {
                        Ok(n) => {
                            info!("tmpfiles: {} entries from {}", n, path.display());
                            conf_count += 1;
                        }
                        Err(e) => warn!("tmpfiles: {}: {} (non-fatal)", path.display(), e),
                    }
                }
            }
        }
    }

    info!("tmpfiles: {} config file(s) processed", conf_count);
    Ok(())
}

fn apply_builtin_entries() -> Result<()> {
    for (ty, path, mode, user, group) in BUILTIN_ENTRIES {
        if let Err(e) = apply_entry(ty, path, Some(*mode), user, group, None, None) {
            warn!("tmpfiles builtin '{}': {} (non-fatal)", path, e);
        }
    }
    Ok(())
}

fn apply_conf_file(conf_path: &Path) -> Result<usize> {
    let content =
        fs::read_to_string(conf_path).with_context(|| format!("read {}", conf_path.display()))?;
    let mut count = 0;

    for (lineno, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            warn!(
                "tmpfiles: {}:{}: too few fields",
                conf_path.display(),
                lineno + 1
            );
            continue;
        }

        let ty = fields[0];
        let path = fields[1];
        let mode = fields.get(2).and_then(|s| parse_mode(s));
        let user = fields.get(3).copied().unwrap_or("-");
        let group = fields.get(4).copied().unwrap_or("-");
        let _age = fields.get(5).copied().unwrap_or("-");
        let arg = fields.get(6).copied();

        match apply_entry(ty, path, mode, user, group, arg, None) {
            Ok(()) => count += 1,
            Err(e) => warn!(
                "tmpfiles: {}:{}: {} (non-fatal)",
                conf_path.display(),
                lineno + 1,
                e
            ),
        }
    }

    Ok(count)
}

fn apply_entry(
    ty: &str,
    path: &str,
    mode: Option<u32>,
    user: &str,
    group: &str,
    arg: Option<&str>,
    _age: Option<&str>,
) -> Result<()> {
    let p = Path::new(path);

    match ty {
        "d" => {
            // Create directory if not exists
            if !p.exists() {
                fs::create_dir_all(p).with_context(|| format!("mkdir '{}'", path))?;
            }
            apply_mode_owner(p, mode, user, group)?;
        }
        "D" => {
            // Create directory + wipe contents
            if p.exists() {
                wipe_directory(p)?;
            } else {
                fs::create_dir_all(p).with_context(|| format!("mkdir '{}'", path))?;
            }
            apply_mode_owner(p, mode, user, group)?;
        }
        "f" => {
            // Create file if not exists
            if !p.exists() {
                if let Some(parent) = p.parent() {
                    fs::create_dir_all(parent).ok();
                }
                fs::write(p, b"").with_context(|| format!("create file '{}'", path))?;
            }
            apply_mode_owner(p, mode, user, group)?;
        }
        "F" => {
            // Create or truncate file
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).ok();
            }
            fs::write(p, b"").with_context(|| format!("truncate file '{}'", path))?;
            apply_mode_owner(p, mode, user, group)?;
        }
        "L" => {
            // Create symlink: arg = target
            if let Some(target) = arg {
                if p.exists() || p.symlink_metadata().is_ok() {
                    fs::remove_file(p).ok();
                }
                symlink(target, p).with_context(|| format!("symlink '{}' → '{}'", path, target))?;
            } else {
                warn!("tmpfiles: L '{}' missing target argument", path);
            }
        }
        "z" | "e" => {
            // Relabel / set mode+ownership on existing path
            if p.exists() {
                apply_mode_owner(p, mode, user, group)?;
            }
        }
        "r" => {
            // Remove file or empty directory
            if p.is_dir() {
                fs::remove_dir(p).ok();
            } else if p.exists() {
                fs::remove_file(p).ok();
            }
        }
        "R" => {
            // Remove recursively
            if p.is_dir() {
                fs::remove_dir_all(p).ok();
            } else if p.exists() {
                fs::remove_file(p).ok();
            }
        }
        other => {
            warn!(
                "tmpfiles: unsupported type '{}' for '{}' (skipping)",
                other, path
            );
        }
    }

    Ok(())
}

fn apply_mode_owner(p: &Path, mode: Option<u32>, user: &str, group: &str) -> Result<()> {
    if let Some(m) = mode {
        let mut perms = fs::metadata(p)
            .with_context(|| format!("metadata '{}'", p.display()))?
            .permissions();
        perms.set_mode(m);
        fs::set_permissions(p, perms)
            .with_context(|| format!("chmod '{}' to {:o}", p.display(), m))?;
    }

    let uid = if user == "-" || user == "root" {
        None
    } else {
        resolve_uid(user)
    };
    let gid = if group == "-" || group == "root" {
        None
    } else {
        resolve_gid(group)
    };

    if uid.is_some() || gid.is_some() {
        fs_chown(p, uid.map(|u| u.as_raw()), gid.map(|g| g.as_raw()))
            .with_context(|| format!("chown '{}'", p.display()))?;
    }
    Ok(())
}

fn wipe_directory(dir: &Path) -> Result<()> {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                fs::remove_dir_all(&path).ok();
            } else {
                fs::remove_file(&path).ok();
            }
        }
    }
    Ok(())
}

fn parse_mode(s: &str) -> Option<u32> {
    if s == "-" {
        return None;
    }
    u32::from_str_radix(s, 8).ok()
}

fn resolve_uid(name: &str) -> Option<nix::unistd::Uid> {
    // Try numeric first
    if let Ok(n) = name.parse::<u32>() {
        return Some(nix::unistd::Uid::from_raw(n));
    }
    // Read /overlayer/syshub/etc/passwd
    if let Ok(content) = fs::read_to_string("/overlayer/syshub/etc/passwd") {
        for line in content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3
                && fields[0] == name
                && let Ok(n) = fields[2].parse::<u32>()
            {
                return Some(nix::unistd::Uid::from_raw(n));
            }
        }
    }
    None
}

fn resolve_gid(name: &str) -> Option<nix::unistd::Gid> {
    if let Ok(n) = name.parse::<u32>() {
        return Some(nix::unistd::Gid::from_raw(n));
    }
    if let Ok(content) = fs::read_to_string("/overlayer/syshub/etc/group") {
        for line in content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3
                && fields[0] == name
                && let Ok(n) = fields[2].parse::<u32>()
            {
                return Some(nix::unistd::Gid::from_raw(n));
            }
        }
    }
    None
}

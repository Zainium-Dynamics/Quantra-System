/// AppArmor Mandatory Access Control integration
///
/// Loads profiles at boot and confines services to their profile before exec.
///
/// # Architecture
///
/// AppArmor works entirely through kernel pseudo-files:
///
/// | Path | Purpose |
/// |------|---------|
/// | `/sys/kernel/security/apparmor/.load`  | Write profile text to load into kernel |
/// | `/sys/kernel/security/apparmor/.remove`| Write profile name to unload |
/// | `/proc/self/attr/exec`                 | Write `changeprofile <name>` in child to set next-exec label |
/// | `/sys/kernel/security/apparmor/profiles` | Read active profiles |
///
/// # Security Ordering
///
/// AppArmor confinement MUST be the LAST security operation before `execvpe`:
/// ```text
/// setgroups(0, NULL)
/// setgid(gid)
/// setuid(uid)
/// write("/proc/self/attr/exec", "changeprofile <name>")  ← here
/// execvpe(...)
/// ```
/// This ensures the confined process cannot escape by manipulating its own attr
/// before exec using the elevated credentials it still had.
///
/// # Async-Signal Safety
///
/// `confine_next_exec()` uses only `open(2)` and `write(2)` which are in the
/// POSIX async-signal-safe list. Safe to call in the fork child.
use anyhow::{Context, Result};
use std::ffi::CString;
use std::fs;
use std::path::Path;

const APPARMOR_LOAD_PATH: &str = "/sys/kernel/security/apparmor/.load";
const APPARMOR_PROFILES_DIR: &str = "/overlayer/syshub/etc/apparmor.d";
#[allow(dead_code)]
const APPARMOR_ACTIVE_PATH: &str = "/sys/kernel/security/apparmor/profiles";

/// Returns true if AppArmor is compiled into this kernel and active.
#[inline]
pub fn is_available() -> bool {
    Path::new(APPARMOR_LOAD_PATH).exists()
}

/// Load all AppArmor profiles from `/etc/apparmor.d/` into the kernel.
///
/// Called once during PID 1 boot, before any service is started.
/// Profiles are loaded in directory order — subdirectories (abstractions, tunables)
/// are skipped since they are `#include`d by top-level profiles.
///
/// Non-fatal: a missing profile directory is logged and skipped.
pub fn load_all_profiles() -> Result<()> {
    if !is_available() {
        log::info!("AppArmor not available on this kernel — skipping");
        return Ok(());
    }

    let profile_dir = Path::new(APPARMOR_PROFILES_DIR);
    if !profile_dir.exists() {
        log::warn!(
            "AppArmor profile directory '{}' not found — no profiles loaded",
            APPARMOR_PROFILES_DIR
        );
        return Ok(());
    }

    let mut loaded = 0usize;
    let mut failed = 0usize;

    for entry in fs::read_dir(profile_dir).context("Cannot read AppArmor profile directory")? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                log::warn!("AppArmor: readdir error: {}", e);
                continue;
            }
        };

        let path = entry.path();

        // Skip directories (abstractions/, tunables/, etc.)
        if path.is_dir() {
            continue;
        }

        // Skip non-profile files
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with('.') || name.ends_with('~') || name.ends_with(".dpkg-new") {
            continue;
        }

        match load_profile(&path) {
            Ok(()) => {
                log::debug!("AppArmor: loaded profile '{}'", name);
                loaded += 1;
            }
            Err(e) => {
                log::error!("AppArmor: failed to load '{}': {}", name, e);
                failed += 1;
            }
        }
    }

    if loaded > 0 {
        log::info!("AppArmor: loaded {} profile(s), {} failed", loaded, failed);
    }

    Ok(())
}

/// Load a single AppArmor profile from `path` into the kernel.
///
/// Reads the profile text and writes it to `/sys/kernel/security/apparmor/.load`.
pub fn load_profile(path: &Path) -> Result<()> {
    let profile_text = fs::read(path)
        .with_context(|| format!("Cannot read AppArmor profile '{}'", path.display()))?;

    fs::write(APPARMOR_LOAD_PATH, &profile_text).with_context(|| {
        format!(
            "Cannot load AppArmor profile '{}' into kernel",
            path.display()
        )
    })?;

    Ok(())
}

/// Confine the next `exec()` call to the named AppArmor profile.
///
/// Writes `changeprofile <name>` to `/proc/self/attr/exec`. The kernel then
/// enforces the profile immediately when `execvpe()` is called.
///
/// # When to call
/// In the **fork child** after setuid/setgid, immediately before execvpe.
///
/// # Returns
/// - `Ok(())` if successfully set
/// - `Err(...)` if AppArmor is unavailable or the profile name is invalid
///   (caller should treat this as fatal and call `_exit(1)`)
#[allow(dead_code)]
pub fn confine_next_exec(profile_name: &str) -> Result<()> {
    if !is_available() {
        // AppArmor not active — silently skip (not a security failure if not configured)
        return Ok(());
    }

    let label = format!("changeprofile {}", profile_name);

    let path = CString::new("/proc/self/attr/exec").unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(anyhow::anyhow!(
            "Cannot open AppArmor exec attr for '{}': {}",
            profile_name,
            std::io::Error::last_os_error()
        ));
    }

    let bytes = label.as_bytes();
    let written = unsafe { libc::write(fd, bytes.as_ptr() as *const libc::c_void, bytes.len()) };
    let close_result = unsafe { libc::close(fd) };

    if written < 0 || written as usize != bytes.len() || close_result != 0 {
        return Err(anyhow::anyhow!(
            "Cannot set AppArmor profile '{}' on next exec: {}",
            profile_name,
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// List all currently loaded AppArmor profile names.
///
/// Parses `/sys/kernel/security/apparmor/profiles` which has format:
/// `profile-name (enforce|complain|kill|unconfined)`
#[allow(dead_code)]
pub fn list_active_profiles() -> Vec<String> {
    if !is_available() {
        return Vec::new();
    }

    fs::read_to_string(APPARMOR_ACTIVE_PATH)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            // Format: "profile-name (enforce)"
            line.rsplit_once(' ')
                .map(|(profile, _)| profile.trim().to_string())
        })
        .collect()
}

/// Remove an AppArmor profile from the kernel.
///
/// Used by service stop — removes the profile if no other processes use it.
#[allow(dead_code)]
pub fn remove_profile(profile_name: &str) -> Result<()> {
    if !is_available() {
        return Ok(());
    }
    fs::write("/sys/kernel/security/apparmor/.remove", profile_name)
        .with_context(|| format!("Cannot remove AppArmor profile '{}'", profile_name))
}

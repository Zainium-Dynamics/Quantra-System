use anyhow::{Context, Result};
use log::warn;
use std::fs;
use std::path::Path;

use super::types::Service;

/// Directory where boot-enable marker files live.
/// Presence of `/overlayer/syshub/etc/quantra-system/enabled/<service_name>` means the service
/// auto-starts on boot. Absence means manual-start only.
pub const ENABLED_DIR: &str = "/overlayer/syshub/etc/quantra-system/enabled";

/// Services in the hardcoded bootstrap lane always start regardless of
/// marker files — the system would not boot without them.
const BOOTSTRAP_SERVICES: &[&str] = &["quantra-netd", "quantra-net", "console-shell"];

#[derive(Debug, Clone)]
pub struct ServiceParseError {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Clone)]
pub struct ServiceParseReport {
    pub services: Vec<Service>,
    pub errors: Vec<ServiceParseError>,
}

/// Parse all TOML service files in `dir`, return all of them regardless of
/// enabled/ markers. Used by `quantra-ctl list` and management commands.
pub fn parse_services(dir: &str) -> Result<ServiceParseReport> {
    parse_services_inner(dir, None)
}

/// Parse all TOML service files in `dir`, then filter by the enabled/
/// marker files in `enabled_dir`.
///
/// Behavior:
/// - If `enabled_dir` does not exist: **fail-open** → return all services
///   (fresh install, no markers configured yet).
/// - Bootstrap services (`quantra-netd`, `quantra-net`, `console-shell`) always
///   pass the filter regardless of markers.
/// - All other services require `<enabled_dir>/<service_name>` to exist.
pub fn parse_services_with_enabled_filter(
    dir: &str,
    enabled_dir: &str,
) -> Result<ServiceParseReport> {
    parse_services_inner(dir, Some(enabled_dir))
}

fn parse_services_inner(dir: &str, enabled_dir: Option<&str>) -> Result<ServiceParseReport> {
    let entries =
        fs::read_dir(dir).with_context(|| format!("Failed to read services directory: {}", dir))?;

    let mut services = Vec::new();
    let mut errors = Vec::new();

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if is_toml_file(&path) {
            match parse_service_file(&path) {
                Ok(service) => services.push(service),
                Err(e) => {
                    let error = ServiceParseError {
                        path: path.display().to_string(),
                        error: e.to_string(),
                    };
                    warn!("Service parse error in '{}': {}", error.path, error.error);
                    errors.push(error);
                }
            }
        }
    }

    log::info!("Parsed {} services from {}", services.len(), dir);
    if !errors.is_empty() {
        warn!(
            "{} service file(s) were rejected while loading '{}'",
            errors.len(),
            dir
        );
    }

    // Apply enabled/ filter if requested
    if let Some(enabled_dir) = enabled_dir {
        services = apply_enabled_filter(services, enabled_dir);
    }

    Ok(ServiceParseReport { services, errors })
}

/// Filter `services` to only those with an enabled/ marker file, plus
/// all hardcoded bootstrap services (which always pass).
///
/// Fail-open: if the enabled/ directory itself doesn't exist, all services
/// are returned unchanged (supports fresh installs with no markers yet).
fn apply_enabled_filter(services: Vec<Service>, enabled_dir: &str) -> Vec<Service> {
    let enabled_path = Path::new(enabled_dir);

    // Fail-open: no enabled/ dir means "everything is enabled" (fresh install)
    if !enabled_path.exists() {
        log::info!(
            "enabled/ directory '{}' not found — all services pass filter (fail-open mode)",
            enabled_dir
        );
        return services;
    }

    let filtered: Vec<Service> = services
        .into_iter()
        .filter(|svc| {
            // Bootstrap services always start
            if BOOTSTRAP_SERVICES.contains(&svc.name.as_str()) {
                return true;
            }

            // Check marker file
            let marker = enabled_path.join(&svc.name);
            let enabled = marker.exists();

            if !enabled {
                log::debug!(
                    "Service '{}' skipped at boot (no marker at {})",
                    svc.name,
                    marker.display()
                );
            }

            enabled
        })
        .collect();

    log::info!(
        "{} service(s) pass enabled/ filter (out of loaded set)",
        filtered.len()
    );

    filtered
}

fn is_toml_file(path: &Path) -> bool {
    path.extension().and_then(|s| s.to_str()) == Some("toml")
}

fn parse_service_file(path: &Path) -> Result<Service> {
    let content =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;

    let service: Service =
        toml::from_str(&content).with_context(|| format!("Failed to parse {}", path.display()))?;

    // Additional validation
    validate_service(&service, path)?;

    Ok(service)
}

fn validate_service(service: &Service, _path: &Path) -> Result<()> {
    // Check for empty name
    if service.name.trim().is_empty() {
        return Err(anyhow::anyhow!("Service name cannot be empty"));
    }

    // Check for valid name (no spaces, special chars)
    if !service
        .name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err(anyhow::anyhow!(
            "Service name '{}' contains invalid characters. Use only alphanumeric, underscore, and dash",
            service.name
        ));
    }

    // Check command is not empty
    if service.command.trim().is_empty() {
        return Err(anyhow::anyhow!("Service command cannot be empty"));
    }

    // Check restart policy values
    match service.restart {
        super::types::RestartPolicy::Always
        | super::types::RestartPolicy::OnFailure
        | super::types::RestartPolicy::No => {}
    }

    // Validate timeout values
    if service.timeout_start > 300 {
        warn!(
            "Service '{}' has very long start timeout ({}s), consider reducing",
            service.name, service.timeout_start
        );
    }
    if service.timeout_stop > 120 {
        warn!(
            "Service '{}' has very long stop timeout ({}s), consider reducing",
            service.name, service.timeout_stop
        );
    }

    // BgProcess requires pid_file
    if service.notify_type == super::types::NotifyType::BgProcess && service.pid_file.is_none() {
        return Err(anyhow::anyhow!(
            "Service '{}': notify_type = \"bg-process\" requires pid_file to be set",
            service.name
        ));
    }

    // chain_to must not self-reference
    if let Some(ref chain) = service.chain_to
        && chain == &service.name
    {
        return Err(anyhow::anyhow!(
            "Service '{}': chain_to cannot reference itself",
            service.name
        ));
    }

    // Validate rlimit pairs: soft <= hard (unless hard is 0 = unlimited)
    if let Some(ref rl) = service.rlimit {
        for (name, pair) in [
            ("nofile", rl.nofile),
            ("nproc", rl.nproc),
            ("fsize", rl.fsize),
            ("stack", rl.stack),
            ("memlock", rl.memlock),
            ("core", rl.core),
        ] {
            if let Some([soft, hard]) = pair
                && hard != 0
                && soft > hard
            {
                return Err(anyhow::anyhow!(
                    "Service '{}': rlimit.{}: soft ({}) > hard ({})",
                    service.name,
                    name,
                    soft,
                    hard
                ));
            }
        }
    }

    // Check socket activation specs
    for spec in &service.socket_listen {
        if !spec.starts_with("unix:") && !spec.starts_with("tcp:") {
            return Err(anyhow::anyhow!(
                "Socket spec '{}' must start with 'unix:' or 'tcp:'",
                spec
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_services;
    use std::fs;

    #[test]
    fn parse_services_reports_bad_files() {
        let dir = unique_temp_dir("parser_reports_bad_files");
        fs::create_dir_all(&dir).unwrap();

        fs::write(
            dir.join("good.toml"),
            r#"
name = "good"
command = "/bin/true"
"#,
        )
        .unwrap();

        fs::write(dir.join("bad.toml"), "name = [broken").unwrap();

        let report = parse_services(dir.to_str().unwrap()).unwrap();

        assert_eq!(report.services.len(), 1);
        assert_eq!(report.errors.len(), 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bgprocess_without_pid_file_is_rejected() {
        let dir = unique_temp_dir("bgprocess_no_pidfile");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("daemon.toml"),
            r#"
name = "daemon"
command = "/usr/sbin/my-daemon"
notify_type = "bg-process"
"#,
        )
        .unwrap();

        let report = parse_services(dir.to_str().unwrap()).unwrap();
        assert_eq!(report.services.len(), 0);
        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].error.contains("pid_file"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_to_self_reference_is_rejected() {
        let dir = unique_temp_dir("chain_self_ref");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("loop.toml"),
            r#"
name = "loop"
command = "/bin/true"
chain_to = "loop"
"#,
        )
        .unwrap();

        let report = parse_services(dir.to_str().unwrap()).unwrap();
        assert_eq!(report.services.len(), 0);
        assert_eq!(report.errors.len(), 1);

        let _ = fs::remove_dir_all(&dir);
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let nonce = format!(
            "{}-{}-{}",
            prefix,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(nonce)
    }
}

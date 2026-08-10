use log::{info, warn};
use std::thread;
use std::time::Duration;

use super::dependency;
use super::parser;
use super::supervisor::ServiceSupervisor;
use super::types::Service;

/// Start all post-boot launcher services declared in the services directory.
///
/// Any TOML in `/overlayer/syshub/etc/quantra-system/services/` can opt into this phase by setting
/// `launcher = true`. This keeps the boot hook universal: LightDM, SDDM,
/// sway launchers, or any future graphical bridge can use the same path.
pub fn start_post_boot_launchers(services_dir: &str) {
    let launchers = load_launchers(services_dir);
    if launchers.is_empty() {
        info!(
            "No launcher services found in '{}' — skipping graphical bridge",
            services_dir
        );
        return;
    }

    let launchers = match dependency::wave_sort_services(&launchers) {
        Ok(waves) => waves.into_iter().flatten().collect::<Vec<Service>>(),
        Err(e) => {
            warn!(
                "Launcher dependency resolution failed: {} (using config order)",
                e
            );
            launchers
        }
    };

    info!("Starting {} post-boot launcher service(s)", launchers.len());
    for launcher in launchers {
        info!(
            "Starting post-boot launcher '{}': {}",
            launcher.name, launcher.command
        );
        let mut supervisor = ServiceSupervisor::new(launcher);
        if let Err(e) = supervisor.start() {
            warn!("Launcher '{}' failed: {}", supervisor.service.name, e);
        }
        // Keep the launcher phase responsive even if one launcher takes a bit.
        thread::sleep(Duration::from_millis(10));
    }
}

fn load_launchers(services_dir: &str) -> Vec<Service> {
    match parser::parse_services(services_dir) {
        Ok(report) => {
            if !report.errors.is_empty() {
                warn!(
                    "Loaded launcher catalog from '{}' with {} parse error(s)",
                    services_dir,
                    report.errors.len()
                );
            }
            report
                .services
                .into_iter()
                .filter(|svc| svc.launcher)
                .collect()
        }
        Err(e) => {
            warn!(
                "Could not load launcher services from '{}': {}",
                services_dir, e
            );
            Vec::new()
        }
    }
}

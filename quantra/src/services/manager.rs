/// Service manager — hardcoded bootstrap lane + parallel wave startup
///
/// Startup now has two stages:
/// - a hardcoded bootstrap lane for `quantra-netd`, `quantra-net`, and
///   `console-shell` (syshub paths) if service TOMLs are missing
/// - parallel BFS dependency waves for any remaining disk-defined services
///
/// Shutdown walks services in **reverse** dependency order, calling each
/// supervisor's `stop()` (SIGTERM → wait → cgroup.kill → SIGKILL).
use anyhow::Result;
use log::{error, info, warn};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Mutex, OnceLock};

use crate::config::InitConfig;
use crate::metrics::MetricsCollector;
use crate::process;

use super::supervisor::ServiceSupervisor;
use super::types::{NotifyType, RestartPolicy, SeccompMode, Service};
use super::{dependency, parser};

/// Global channel for chain_to: supervisor threads queue service names here,
/// and a background manager thread picks them up to start the chained service.
static CHAIN_QUEUE: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

/// Called by `restart_monitor` when a `chain_to` service should start.
/// Thread-safe, non-blocking. Manager background thread drains this queue.
pub fn queue_chain_start(service_name: String) {
    let queue = CHAIN_QUEUE.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut q) = queue.lock() {
        q.push(service_name);
    }
}

const BUILTIN_BOOTSTRAP_ORDER: [&str; 3] = ["quantra-netd", "quantra-net", "console-shell"];

pub struct ServiceManager {
    supervisors: Vec<ServiceSupervisor>,
    catalog: HashMap<String, Service>,
    #[allow(dead_code)]
    pub started_count: usize,
    #[allow(dead_code)]
    pub failed_count: usize,
    #[allow(dead_code)]
    metrics: std::sync::Arc<MetricsCollector>,
    /// Global environment variables injected into all future service spawns
    /// via `quantra-ctl setenv`. Applied on the NEXT start/restart of each service.
    pub global_env: HashMap<String, String>,
}

impl ServiceManager {
    /// Load service definitions, resolve dependencies, return the manager.
    ///
    /// Within each wave, every service is started in its own thread.
    /// Wave N+1 begins only after all threads of wave N complete.
    pub fn start_all(cfg: &InitConfig, metrics: std::sync::Arc<MetricsCollector>) -> Result<Self> {
        info!("Starting services with hardcoded bootstrap fallback");

        // Use enabled/ filter at boot: only auto-start services with a marker file.
        // Bootstrap services (quantra-netd, quantra-net, console-shell) always start.
        let services = load_services_or_default_filtered(cfg)?;
        validate_service_catalog(&services, cfg.strict_service_validation)?;
        let catalog = build_catalog(&services);
        let bootstrap = bootstrap_services(&services);
        let remaining = remaining_services(services);

        let mut all_supervisors: Vec<ServiceSupervisor> = Vec::new();

        let mut started_count = 0;
        let mut failed_count = 0;

        info!(
            "Launching hardcoded bootstrap services ({} service(s))",
            bootstrap.len()
        );
        for svc in bootstrap {
            let mut sup = ServiceSupervisor::new(svc);
            if let Err(e) = sup.start() {
                error!(
                    "Failed to start bootstrap service '{}': {}",
                    sup.service.name, e
                );
                failed_count += 1;
                metrics.record_service_failed();
            } else {
                started_count += 1;
                metrics.record_service_started();
            }
            all_supervisors.push(sup);
        }

        if remaining.is_empty() {
            info!("No additional non-bootstrap services found");
        } else {
            match dependency::wave_sort_services(&remaining) {
                Ok(waves) => {
                    for (wave_idx, wave) in waves.into_iter().enumerate() {
                        let wave_count = wave.len();
                        info!(
                            "Wave {}: launching {} service(s) in parallel",
                            wave_idx, wave_count
                        );

                        // Spawn one thread per service in this wave
                        let handles: Vec<_> = wave
                            .into_iter()
                            .map(|svc| {
                                std::thread::Builder::new()
                                    .name(format!("start-{}", svc.name))
                                    .spawn(move || {
                                        let mut sup = ServiceSupervisor::new(svc);
                                        let success = sup.start().is_ok();
                                        (sup, success)
                                    })
                            })
                            .collect();

                        // Wait for all threads in this wave to return before continuing
                        for result in handles {
                            match result {
                                Ok(handle) => match handle.join() {
                                    Ok((sup, success)) => {
                                        all_supervisors.push(sup);
                                        if success {
                                            started_count += 1;
                                            metrics.record_service_started();
                                        } else {
                                            failed_count += 1;
                                            metrics.record_service_failed();
                                        }
                                    }
                                    Err(_) => {
                                        warn!("Service start thread panicked");
                                        failed_count += 1;
                                    }
                                },
                                Err(e) => {
                                    error!("Failed to spawn service thread: {}", e);
                                    failed_count += 1;
                                }
                            }
                        }

                        info!("Wave {} complete", wave_idx);
                    }
                }
                Err(e) => warn!(
                    "Dependency resolution failed for non-bootstrap services: {} (continuing with bootstrap services only)",
                    e
                ),
            }
        }

        info!(
            "All service waves launched ({} services)",
            all_supervisors.len()
        );
        Ok(Self {
            supervisors: all_supervisors,
            catalog,
            started_count,
            failed_count,
            metrics,
            global_env: HashMap::new(),
        })
    }

    /// Inject an environment variable into all future service spawns.
    /// Does not affect currently running processes.
    pub fn set_env(&mut self, key: String, value: Option<String>) {
        match value {
            Some(v) => {
                self.global_env.insert(key, v);
            }
            None => {
                self.global_env.remove(&key);
            }
        }
    }

    /// Start a service by name using the loaded service catalog.
    pub fn start_named_service(&mut self, name: &str) -> Result<()> {
        if let Some(sup) = self
            .supervisors
            .iter_mut()
            .find(|sup| sup.service.name == name)
        {
            if sup.running.load(Ordering::Acquire) {
                info!("Service '{}' already running — skipping activation", name);
                return Ok(());
            }

            info!("Restarting service '{}' on demand", name);
            sup.start()?;
            return Ok(());
        }

        let service = self
            .catalog
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Unknown service '{}' requested", name))?;

        info!("Activating service '{}' on demand", name);
        let mut supervisor = ServiceSupervisor::new(service);
        supervisor.start()?;
        self.supervisors.push(supervisor);
        Ok(())
    }

    /// Add a transient (in-memory) service and start it immediately.
    /// The service is NOT persisted to disk — it lives only until PID 1 exits.
    #[allow(dead_code)]
    pub fn add_and_start_transient(&mut self, service: Service) -> Result<()> {
        let name = service.name.clone();
        info!("Starting transient service '{}'", name);
        let mut supervisor = ServiceSupervisor::new(service);
        supervisor.start()?;
        self.supervisors.push(supervisor);
        Ok(())
    }

    /// Stop a single service by name if it is known to the manager.
    pub fn stop_named_service(&mut self, name: &str) -> Result<()> {
        let supervisor = self
            .supervisors
            .iter()
            .find(|sup| sup.service.name == name)
            .ok_or_else(|| anyhow::anyhow!("Unknown service '{}' requested", name))?;

        supervisor.stop();
        Ok(())
    }

    /// Reload a service by sending its configured reload_signal or running
    /// its reload_command. Delegates to `ServiceSupervisor::reload()`.
    pub fn reload_named_service(&self, name: &str) -> Result<String> {
        let supervisor = self
            .supervisors
            .iter()
            .find(|sup| sup.service.name == name)
            .ok_or_else(|| anyhow::anyhow!("Unknown service '{}'", name))?;

        supervisor.reload()?;

        let sig_or_cmd = supervisor
            .service
            .reload_command
            .as_deref()
            .unwrap_or(&supervisor.service.reload_signal);
        Ok(format!("✓ Reloaded '{}' via {}", name, sig_or_cmd))
    }

    /// Record a successful service start in metrics
    #[allow(dead_code)]
    pub fn record_service_started(&self) {
        self.metrics.record_service_started();
    }

    /// Record a failed service start in metrics
    #[allow(dead_code)]
    pub fn record_service_failed(&self) {
        self.metrics.record_service_failed();
    }

    /// Publish the current catalog and runtime state into the D-Bus registry.
    #[allow(dead_code)]
    pub fn seed_dbus_registry(&self) {
        for service in self.catalog.values() {
            let supervisor = self
                .supervisors
                .iter()
                .find(|sup| sup.service.name == service.name);

            let (pid, active) = match supervisor {
                Some(sup) => (
                    sup.pid.load(Ordering::Acquire),
                    sup.running.load(Ordering::Acquire),
                ),
                None => (-1, false),
            };

            crate::dbus::register_service_global(&service.name, pid, active);
        }
    }

    /// Stop all services in **reverse dependency order**.
    ///
    /// This ensures leaf services (those with no dependents) are stopped first,
    /// preventing dependent services from receiving requests after their backends die.
    #[allow(dead_code)]
    pub fn stop_all(&mut self) {
        info!("Stopping all services in reverse dependency order");

        // Supervisors are stored in forward dependency order — reverse for shutdown
        for sup in self.supervisors.iter().rev() {
            sup.stop();
        }
    }

    /// Get the status of a service by name.
    pub fn get_service_status(&self, name: &str) -> Option<(i32, bool)> {
        self.supervisors
            .iter()
            .find(|sup| sup.service.name == name)
            .map(|sup| {
                (
                    sup.pid.load(Ordering::Acquire),
                    sup.running.load(Ordering::Acquire),
                )
            })
    }

    /// Get list of all service names.
    pub fn get_service_names(&self) -> Vec<String> {
        self.catalog.keys().cloned().collect()
    }

    /// Add a runtime dependency edge from `from` to `to`.
    /// The edge type string is logged for diagnostics.
    /// Does NOT affect already-running services — takes effect on next start.
    pub fn add_dep(&mut self, from: &str, to: &str, dep_type: &str) {
        if let Some(svc) = self.catalog.get_mut(from) {
            match dep_type {
                "need" | "regular" => {
                    if !svc.dependencies.contains(&to.to_string()) {
                        svc.dependencies.push(to.to_string());
                    }
                }
                "milestone" => {
                    if !svc.milestone.contains(&to.to_string()) {
                        svc.milestone.push(to.to_string());
                    }
                }
                _ => {
                    // "after" and unknown types go into after = ordering only
                    if !svc.after.contains(&to.to_string()) {
                        svc.after.push(to.to_string());
                    }
                }
            }
            log::info!("Runtime dep added: {} --[{}]--> {}", from, dep_type, to);
        } else {
            log::warn!("add_dep: service '{}' not in catalog — skipped", from);
        }
    }

    /// Remove a runtime dependency edge from `from` to `to` (any type).
    pub fn rm_dep(&mut self, from: &str, to: &str) {
        if let Some(svc) = self.catalog.get_mut(from) {
            svc.dependencies.retain(|d| d != to);
            svc.wants.retain(|d| d != to);
            svc.milestone.retain(|d| d != to);
            svc.after.retain(|d| d != to);
            log::info!("Runtime dep removed: {} --> {}", from, to);
        } else {
            log::warn!("rm_dep: service '{}' not in catalog — skipped", from);
        }
    }
}

/// Convenience function used by `main.rs` — does not retain supervisor handles.
pub fn start_all(
    cfg: &InitConfig,
    metrics: std::sync::Arc<MetricsCollector>,
) -> Result<ServiceManager> {
    ServiceManager::start_all(cfg, metrics)
}

#[allow(dead_code)]
fn startup_plan(cfg: &InitConfig) -> Vec<Service> {
    let services = load_services_or_default(cfg).unwrap_or_default();
    startup_plan_from_services(&services)
}

fn startup_plan_from_services(services: &[Service]) -> Vec<Service> {
    let bootstrap = bootstrap_services(services);
    let remaining = remaining_services(services.to_vec());

    let mut plan = bootstrap;
    if remaining.is_empty() {
        return plan;
    }

    match dependency::wave_sort_services(&remaining) {
        Ok(waves) => plan.extend(waves.into_iter().flatten()),
        Err(e) => {
            warn!(
                "Dependency resolution failed for shutdown planning: {} (falling back to config order)",
                e
            );
            plan.extend(remaining);
        }
    }

    plan
}

fn build_catalog(services: &[Service]) -> HashMap<String, Service> {
    let mut catalog: HashMap<String, Service> = services
        .iter()
        .cloned()
        .map(|service| (service.name.clone(), service))
        .collect();

    for builtin in BUILTIN_BOOTSTRAP_ORDER {
        catalog
            .entry(builtin.to_string())
            .or_insert_with(|| builtin_service(builtin));
    }

    // Phase 4C: Resolve conditional dependencies
    // For each service with `conditional_dependencies`, check the kernel path.
    // If the hardware is present, promote the dep to a hard dependency.
    for svc in catalog.values_mut() {
        let resolved: Vec<String> = svc
            .conditional_dependencies
            .iter()
            .filter_map(|(dep_name, condition)| resolve_conditional_dep(dep_name, condition))
            .collect();
        if !resolved.is_empty() {
            info!(
                "Service '{}': {} conditional dep(s) activated: {:?}",
                svc.name,
                resolved.len(),
                resolved
            );
            svc.dependencies.extend(resolved);
        }
    }

    catalog
}

/// Evaluate a single conditional dependency expression.
///
/// Supported forms:
/// - `hardware-present:/sys/class/bluetooth` → add dep if path exists
/// - `file-exists:/etc/my-service.conf`      → add dep if file exists
/// - `env-set:MY_VAR`                        → add dep if env var is non-empty
///
/// Returns `Some(dep_name)` if the condition is true, `None` otherwise.
fn resolve_conditional_dep(dep_name: &str, condition: &str) -> Option<String> {
    if let Some(path) = condition.strip_prefix("hardware-present:") {
        if std::path::Path::new(path).exists() {
            log::debug!(
                "Conditional dep '{}': hardware present at '{}' ✓",
                dep_name,
                path
            );
            return Some(dep_name.to_string());
        }
        log::debug!(
            "Conditional dep '{}': hardware absent at '{}' — skipped",
            dep_name,
            path
        );
        return None;
    }

    if let Some(path) = condition.strip_prefix("file-exists:") {
        if std::path::Path::new(path).exists() {
            return Some(dep_name.to_string());
        }
        return None;
    }

    if let Some(var) = condition.strip_prefix("env-set:") {
        if std::env::var(var).map(|v| !v.is_empty()).unwrap_or(false) {
            return Some(dep_name.to_string());
        }
        return None;
    }

    // Unknown condition — log and skip (fail-open)
    log::warn!(
        "Unknown conditional_dependency format for '{}': '{}' — skipped",
        dep_name,
        condition
    );
    None
}

fn load_services_or_default(cfg: &InitConfig) -> Result<Vec<Service>> {
    // Use enabled_dir filter from config — only boot-enabled services start automatically.
    // parse_services_with_enabled_filter is fail-open: if enabled_dir is missing,
    // all services pass the filter (supports fresh installs with no markers yet).
    match parser::parse_services_with_enabled_filter(&cfg.services_dir, &cfg.enabled_dir) {
        Ok(report) => {
            if !report.errors.is_empty() {
                let message = format!(
                    "Loaded {} service(s) from '{}' with {} parse error(s)",
                    report.services.len(),
                    cfg.services_dir,
                    report.errors.len()
                );
                if cfg.strict_service_validation {
                    return Err(anyhow::anyhow!(message));
                }
                warn!("{}", message);
            }
            Ok(report.services)
        }
        Err(e) => {
            warn!(
                "Service directory '{}' unavailable: {} (using hardcoded bootstrap services)",
                cfg.services_dir, e
            );
            Ok(Vec::new())
        }
    }
}

fn validate_service_catalog(services: &[Service], strict: bool) -> Result<()> {
    use std::collections::HashSet;

    let mut issues = Vec::new();
    let mut names = HashSet::new();

    for service in services {
        if !names.insert(service.name.clone()) {
            issues.push(format!("duplicate service name '{}'", service.name));
        }

        if service.command.trim().is_empty() {
            issues.push(format!("service '{}' has an empty command", service.name));
            continue;
        }

        if let Err(e) = process::resolve_command_argv(&service.command, &service.args) {
            issues.push(format!("service '{}' command invalid: {}", service.name, e));
        }

        for capability in &service.drop_capabilities {
            if process::capability_name_to_number(capability).is_none() {
                issues.push(format!(
                    "service '{}' has unknown capability '{}' in drop_capabilities",
                    service.name, capability
                ));
            }
        }

        match service.seccomp {
            SeccompMode::Profile => {
                let profile_name = service
                    .seccomp_profile
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty());

                match profile_name {
                    Some(profile) => {
                        if let Err(e) = process::resolve_seccomp_profile_denylist(profile) {
                            let supported = process::supported_seccomp_profiles().join(", ");
                            issues.push(format!(
                                "service '{}' has invalid seccomp_profile '{}': {} (supported: {})",
                                service.name, profile, e, supported
                            ));
                        }
                    }
                    None => issues.push(format!(
                        "service '{}' sets seccomp='profile' but seccomp_profile is missing",
                        service.name
                    )),
                }
            }
            SeccompMode::Off | SeccompMode::Strict => {
                if let Some(profile) = service
                    .seccomp_profile
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    issues.push(format!(
                        "service '{}' sets seccomp_profile='{}' but seccomp mode is '{:?}'",
                        service.name, profile, service.seccomp
                    ));
                }
            }
        }

        if service.seccomp != SeccompMode::Off && !service.no_new_privileges {
            issues.push(format!(
                "service '{}' enables seccomp but no_new_privileges=false",
                service.name
            ));
        }
    }

    let mut known = names;
    for builtin in BUILTIN_BOOTSTRAP_ORDER {
        known.insert(builtin.to_string());
    }

    for service in services {
        for dep in service.dependencies.iter().chain(service.after.iter()) {
            if dep == &service.name {
                issues.push(format!("service '{}' depends on itself", service.name));
            } else if !known.contains(dep) {
                issues.push(format!(
                    "service '{}' references unknown dependency '{}'",
                    service.name, dep
                ));
            }
        }

        for want in &service.wants {
            if !known.contains(want) {
                issues.push(format!(
                    "service '{}' wants unknown unit '{}'",
                    service.name, want
                ));
            }
        }

        for ms in &service.milestone {
            if ms == &service.name {
                issues.push(format!(
                    "service '{}' has itself as a milestone",
                    service.name
                ));
            } else if !known.contains(ms) {
                issues.push(format!(
                    "service '{}' references unknown milestone '{}'",
                    service.name, ms
                ));
            }
        }
    }

    if issues.is_empty() {
        return Ok(());
    }

    let summary = format!("Service catalog validation found {} issue(s)", issues.len());
    if strict {
        Err(anyhow::anyhow!("{}\n- {}", summary, issues.join("\n- ")))
    } else {
        warn!("{}", summary);
        for issue in issues {
            warn!(" - {}", issue);
        }
        Ok(())
    }
}

fn bootstrap_services(services: &[Service]) -> Vec<Service> {
    BUILTIN_BOOTSTRAP_ORDER
        .iter()
        .map(|name| service_or_builtin(services, name))
        .collect()
}

fn remaining_services(services: Vec<Service>) -> Vec<Service> {
    services
        .into_iter()
        .filter(|svc| !BUILTIN_BOOTSTRAP_ORDER.contains(&svc.name.as_str()) && !svc.launcher)
        .collect()
}

fn service_or_builtin(services: &[Service], name: &str) -> Service {
    services
        .iter()
        .find(|svc| svc.name == name)
        .cloned()
        .unwrap_or_else(|| builtin_service(name))
}

fn builtin_service(name: &str) -> Service {
    match name {
        "quantra-net" => Service {
            name: "quantra-net".into(),
            description: Some("Hardcoded network setup client".into()),
            command: "/overlayer/syshub/bin/quantra-net".into(),
            args: vec!["setup".into()],
            apparmor_profile: None,
            no_new_privileges: true,
            non_dumpable: true,
            clear_ambient_caps: false,
            drop_capabilities: vec![],
            seccomp: SeccompMode::Off,
            seccomp_profile: None,
            oneshot: true,
            console: false,
            launcher: false,
            notify_type: NotifyType::Simple,
            pid_file: None,
            ready_socket: None,
            socket_alias: None,
            tty: None,
            user: None,
            group: None,
            working_dir: Some("/".into()),
            watchdog_sec: 0,
            stop_command: None,
            stop_args: vec![],
            reload_signal: "SIGHUP".into(),
            reload_command: None,
            chain_to: None,
            chain_to_always: false,
            env_file: None,
            environment: None,
            rlimit: None,
            restart: RestartPolicy::No,
            restart_sec: 1,
            max_restarts: 0,
            restart_interval_sec: 60,
            dependencies: vec![],
            wants: vec![],
            milestone: vec![],
            after: vec!["quantra-netd".into()],
            timeout_start: 30,
            timeout_stop: 5,
            socket_listen: vec![],
            cgroup_config: None,
            healthcheck: None,
            conditional_dependencies: HashMap::new(),
            ..Default::default()
        },
        "quantra-netd" => Service {
            name: "quantra-netd".into(),
            description: Some("Hardcoded network daemon".into()),
            command: "/overlayer/syshub/engine/quantra-netd".into(),
            args: vec![],
            apparmor_profile: None,
            no_new_privileges: true,
            non_dumpable: true,
            clear_ambient_caps: false,
            drop_capabilities: vec![],
            seccomp: SeccompMode::Profile,
            seccomp_profile: Some("network-daemon".into()),
            oneshot: false,
            console: false,
            launcher: false,
            notify_type: NotifyType::Simple,
            pid_file: None,
            ready_socket: Some("/run/quantra-system/quantra-netd.sock".into()),
            socket_alias: None,
            tty: None,
            user: None,
            group: None,
            working_dir: Some("/".into()),
            watchdog_sec: 0,
            stop_command: None,
            stop_args: vec![],
            reload_signal: "SIGHUP".into(),
            reload_command: None,
            chain_to: None,
            chain_to_always: false,
            env_file: None,
            environment: None,
            rlimit: None,
            restart: RestartPolicy::OnFailure,
            restart_sec: 2,
            max_restarts: 0,
            restart_interval_sec: 60,
            dependencies: vec![],
            wants: vec![],
            milestone: vec![],
            after: vec![],
            timeout_start: 90,
            timeout_stop: 5,
            socket_listen: vec![],
            cgroup_config: None,
            healthcheck: None,
            conditional_dependencies: HashMap::new(),
            ..Default::default()
        },
        "console-shell" => {
            // Base env from the same native source PID 1 sets on itself
            // (see environment.rs) — plus the console-specific overrides.
            let mut environment = crate::environment::base_map();
            environment.insert("TERM".into(), "linux".into());
            environment.insert("HOME".into(), "/root".into());
            environment.insert("SHELL".into(), "/overlayer/syshub/bin/bash".into());

            Service {
                name: "console-shell".into(),
                description: Some("Interactive Zainium console shell".into()),
                command: "/overlayer/syshub/bin/bash".into(),
                args: vec!["-il".into()],
                apparmor_profile: None,
                no_new_privileges: true,
                non_dumpable: true,
                clear_ambient_caps: false,
                drop_capabilities: vec![],
                seccomp: SeccompMode::Off,
                seccomp_profile: None,
                oneshot: false,
                console: true,
                launcher: false,
                notify_type: NotifyType::Simple,
                pid_file: None,
                ready_socket: None,
                socket_alias: None,
                tty: Some("/dev/tty1".into()),
                user: None,
                group: None,
                working_dir: Some("/".into()),
                watchdog_sec: 0,
                stop_command: None,
                stop_args: vec![],
                reload_signal: "SIGHUP".into(),
                reload_command: None,
                chain_to: None,
                chain_to_always: false,
                env_file: None,
                environment: Some(environment),
                rlimit: None,
                restart: RestartPolicy::Always,
                restart_sec: 1,
                max_restarts: 0,
                restart_interval_sec: 60,
                dependencies: vec![],
                wants: vec![],
                milestone: vec![],
                after: vec!["quantra-net".into()],
                timeout_start: 90,
                timeout_stop: 5,
                socket_listen: vec![],
                cgroup_config: None,
                healthcheck: None,
                conditional_dependencies: HashMap::new(),
                ..Default::default()
            }
        }
        _ => unreachable!(
            "Unknown bootstrap service '{}'; builtin table is fixed",
            name
        ),
    }
}

/// Load services with the enabled/ marker filter applied.
/// Only services with `/overlayer/syshub/etc/quantra-system/enabled/<name>` marker auto-start at boot.
/// Fails open if the enabled/ directory doesn't exist yet.
fn load_services_or_default_filtered(cfg: &InitConfig) -> Result<Vec<Service>> {
    use parser::ENABLED_DIR;
    let dir = &cfg.services_dir;

    let report = if std::path::Path::new(dir).exists() {
        parser::parse_services_with_enabled_filter(dir, ENABLED_DIR)?
    } else {
        warn!(
            "Services directory '{}' not found — using hardcoded bootstrap only",
            dir
        );
        return Ok(vec![]);
    };

    Ok(report.services)
}

#[cfg(test)]
mod tests {
    use super::{builtin_service, validate_service_catalog};
    use crate::services::types::{NotifyType, RestartPolicy, SeccompMode, Service};
    use std::collections::HashMap;

    #[test]
    fn validation_rejects_duplicate_names_in_strict_mode() {
        let services = vec![base_service("alpha"), base_service("alpha")];
        let err = validate_service_catalog(&services, true).unwrap_err();
        assert!(err.to_string().contains("duplicate service name 'alpha'"));
    }

    #[test]
    fn validation_warns_on_unknown_dependency_in_lenient_mode() {
        let mut svc = base_service("beta");
        svc.dependencies = vec!["missing".into()];

        validate_service_catalog(&[svc], false).unwrap();
    }

    #[test]
    fn validation_rejects_unknown_capability_in_strict_mode() {
        let mut svc = base_service("cap-test");
        svc.drop_capabilities = vec!["CAP_NOT_REAL".into()];

        let err = validate_service_catalog(&[svc], true).unwrap_err();
        assert!(err.to_string().contains("unknown capability"));
    }

    #[test]
    fn validation_rejects_missing_seccomp_profile_in_strict_mode() {
        let mut svc = base_service("seccomp-test");
        svc.seccomp = SeccompMode::Profile;
        svc.seccomp_profile = None;

        let err = validate_service_catalog(&[svc], true).unwrap_err();
        assert!(err.to_string().contains("seccomp='profile'"));
    }

    #[test]
    fn builtin_quantra_netd_uses_network_daemon_seccomp_profile() {
        let svc = builtin_service("quantra-netd");
        assert_eq!(svc.seccomp, SeccompMode::Profile);
        assert_eq!(svc.seccomp_profile.as_deref(), Some("network-daemon"));
        validate_service_catalog(&[svc], true)
            .expect("builtin quantra-netd should remain valid in strict mode");
    }

    fn base_service(name: &str) -> Service {
        Service {
            name: name.into(),
            description: None,
            command: "/bin/true".into(),
            args: vec![],
            apparmor_profile: None,
            no_new_privileges: true,
            non_dumpable: true,
            clear_ambient_caps: false,
            drop_capabilities: vec![],
            seccomp: SeccompMode::Off,
            seccomp_profile: None,
            oneshot: false,
            console: false,
            launcher: false,
            notify_type: NotifyType::Simple,
            pid_file: None,
            ready_socket: None,
            socket_alias: None,
            tty: None,
            user: None,
            group: None,
            working_dir: None,
            watchdog_sec: 0,
            stop_command: None,
            stop_args: vec![],
            reload_signal: "SIGHUP".into(),
            reload_command: None,
            chain_to: None,
            chain_to_always: false,
            env_file: None,
            environment: None,
            rlimit: None,
            restart: RestartPolicy::No,
            restart_sec: 5,
            max_restarts: 0,
            restart_interval_sec: 60,
            timeout_start: 90,
            timeout_stop: 30,
            dependencies: vec![],
            wants: vec![],
            milestone: vec![],
            after: vec![],
            socket_listen: vec![],
            cgroup_config: None,
            healthcheck: None,
            conditional_dependencies: HashMap::new(),
            ..Default::default()
        }
    }
}

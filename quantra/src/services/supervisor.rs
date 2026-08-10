/// Full-lifecycle service supervisor
///
/// Integrates every Phase 1–3 feature:
/// - **cgroup v2 slice**: isolates the service's resources
/// - **per-service log file**: pipes stdout+stderr to `/var/log/quantra-system/<name>.log`
/// - **sd_notify**: waits for READY=1 within `timeout_start` seconds
/// - **socket activation**: pre-opens sockets and hands off via LISTEN_FDS
/// - **privilege drop**: setgroups → setgid → setuid (correct order)
/// - **restart monitor**: real exit codes from `signals::get_exit_code()`
/// - **graceful stop**: SIGTERM → wait `timeout_stop` → cgroup.kill → SIGKILL
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs as unix_fs;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicI32, Ordering},
};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use log::{error, info, warn};
use nix::sys::signal::{self, Signal};

use super::cgroup;
use super::logger::create_service_logger;
use super::notify::NotifyServer;
use super::socket_activation::{ActivationSocket, build_listen_env};
use super::types::{HealthCheck, NotifyType, RestartPolicy, SeccompMode, Service};
use crate::dbus;
use crate::process::{
    ServiceLaunch, resolve_capability_numbers, resolve_command_argv,
    resolve_seccomp_profile_denylist, start_service_as,
};
use crate::sandbox;

// Used for max_restarts crash-loop breaker
use std::collections::VecDeque;
use std::time::Instant;

/// Manages the complete lifecycle of one system service.
pub struct ServiceSupervisor {
    pub service: Service,
    /// Current PID (-1 = not running)
    pub pid: Arc<AtomicI32>,
    /// True while process is believed alive
    pub running: Arc<AtomicBool>,
    /// True when an explicit stop is in progress; suppresses restart loops.
    pub stop_requested: Arc<AtomicBool>,
}

impl ServiceSupervisor {
    pub fn new(service: Service) -> Self {
        Self {
            service,
            pid: Arc::new(AtomicI32::new(-1)),
            running: Arc::new(AtomicBool::new(false)),
            stop_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the service with the full feature set.
    pub fn start(&mut self) -> Result<()> {
        self.stop_requested.store(false, Ordering::Release);
        self.running.store(false, Ordering::Release);

        if let Some(ref desc) = self.service.description {
            info!("Starting '{}': {}", self.service.name, desc);
        } else {
            info!("Starting service '{}'", self.service.name);
        }

        // ── SERVICE_CONDITION state ─────────────────────────────────────────
        // Explicit condition-check phase before START_PRE.
        // If any condition fails → service transitions to DEAD (not FAILED).
        // This mirrors systemd's SERVICE_CONDITION state.
        info!(
            "SERVICE_CONDITION: checking conditions for '{}'",
            self.service.name
        );

        for path in &self.service.condition_path_exists {
            if !Path::new(path).exists() {
                info!(
                    "SERVICE_CONDITION: '{}' → DEAD (ConditionPathExists='{}' not met)",
                    self.service.name, path
                );
                return Ok(());
            }
        }
        for path in &self.service.condition_path_not_exists {
            if Path::new(path).exists() {
                info!(
                    "Service '{}' skipped: ConditionPathNotExists='{}' path exists",
                    self.service.name, path
                );
                return Ok(());
            }
        }

        // ── ExecStartPre hooks ────────────────────────────────────────────
        for pre_cmd in &self.service.exec_start_pre {
            info!("ExecStartPre for '{}': {}", self.service.name, pre_cmd);
            let status = std::process::Command::new("/overlayer/syshub/bin/sh")
                .args(["-c", pre_cmd])
                .status();
            match status {
                Ok(s) if s.success() => {}
                Ok(s) => {
                    let code = s.code().unwrap_or(-1);
                    anyhow::bail!(
                        "ExecStartPre '{}' failed with exit code {} — aborting start of '{}'",
                        pre_cmd,
                        code,
                        self.service.name
                    );
                }
                Err(e) => {
                    anyhow::bail!(
                        "ExecStartPre '{}' failed to execute: {} — aborting start of '{}'",
                        pre_cmd,
                        e,
                        self.service.name
                    );
                }
            }
        }

        // ── Credentials / DynamicUser ────────────────────────────────────
        let (uid, gid) = if self.service.dynamic_user {
            match sandbox::allocate_dynamic_uid() {
                Ok((u, g)) => (Some(u), Some(g)),
                Err(e) => {
                    warn!(
                        "dynamic_user for '{}': {} — falling back to root",
                        self.service.name, e
                    );
                    (None, None)
                }
            }
        } else {
            resolve_credentials(&self.service)?
        };

        // ── cgroup v2 slice ───────────────────────────────────────────────
        if let Err(e) = cgroup::create_service_cgroup(&self.service.name) {
            warn!(
                "cgroup slice creation failed for '{}': {} (continuing)",
                self.service.name, e
            );
        }

        // ── cgroup v2 resource limits ────────────────────────────────────
        // Apply memory.max / cpu.weight / io.weight / cpu.max / pids.max
        if let Some(ref cgcfg) = self.service.cgroup_config {
            cgcfg.apply(&self.service.name);
        }
        if let Some(ref quota) = self.service.cpu_quota {
            if let Err(e) = cgroup::apply_cpu_quota(&self.service.name, quota) {
                warn!(
                    "cgroup cpu_quota for '{}': {} (non-fatal)",
                    self.service.name, e
                );
            }
        }
        if let Some(n) = self.service.tasks_max {
            if let Err(e) = cgroup::apply_tasks_max(&self.service.name, n) {
                warn!(
                    "cgroup tasks_max for '{}': {} (non-fatal)",
                    self.service.name, e
                );
            }
        }
        if let Some(ref swap) = self.service.memory_swap_max {
            if let Err(e) = cgroup::apply_memory_swap_max(&self.service.name, swap) {
                warn!(
                    "cgroup memory_swap_max for '{}': {} (non-fatal)",
                    self.service.name, e
                );
            }
        }

        // IODeviceWeight and IODeviceLatencyTargetSec
        for (device, weight) in &self.service.io_device_weights {
            if let Err(e) = cgroup::apply_io_device_weight(&self.service.name, device, *weight) {
                warn!(
                    "cgroup io_device_weight '{}' for '{}': {} (non-fatal)",
                    device, self.service.name, e
                );
            }
        }
        for (device, latency_usec) in &self.service.io_device_latencies {
            if let Err(e) =
                cgroup::apply_io_device_latency(&self.service.name, device, *latency_usec)
            {
                warn!(
                    "cgroup io_latency '{}' for '{}': {} (non-fatal)",
                    device, self.service.name, e
                );
            }
        }

        // ── Auto-create service directories (in parent before fork) ───────
        if let Err(e) = sandbox::setup_service_directories(&self.service, uid, gid) {
            warn!(
                "service dirs for '{}': {} (non-fatal)",
                self.service.name, e
            );
        }

        // ── IPAddressDeny / IPAddressAllow — cgroup BPF egress filter ────────
        if !self.service.ip_address_deny.is_empty() || !self.service.ip_address_allow.is_empty() {
            use crate::process::{IpRange, apply_ip_filter};
            let deny: Vec<IpRange> = self
                .service
                .ip_address_deny
                .iter()
                .filter_map(|s| IpRange::parse(s))
                .collect();
            let allow: Vec<IpRange> = self
                .service
                .ip_address_allow
                .iter()
                .filter_map(|s| IpRange::parse(s))
                .collect();
            if let Err(e) = apply_ip_filter(&self.service.name, &deny, &allow) {
                warn!(
                    "IPAddressFilter for '{}': {} (non-fatal)",
                    self.service.name, e
                );
            }
        }

        // ── Logger pipe ───────────────────────────────────────────────────
        let log_write_fd = if self.service.console {
            info!("Console mode enabled for '{}'", self.service.name);
            None
        } else {
            match create_service_logger(&self.service.name) {
                Ok((wfd, logger)) => {
                    let name = self.service.name.clone();
                    thread::Builder::new()
                        .name(format!("log-{}", name))
                        .spawn(move || logger.run())
                        .ok();
                    Some(wfd)
                }
                Err(e) => {
                    warn!(
                        "Logger creation failed for '{}': {} (using /dev/console)",
                        self.service.name, e
                    );
                    None
                }
            }
        };

        // ── env_file loading ─────────────────────────────────────────────
        // Merge KEY=VALUE file into env overlay BEFORE service.environment
        // so that explicit environment = { ... } table takes priority.
        let mut env_overlay: HashMap<String, String> = HashMap::new();
        if let Some(ref ef_path) = self.service.env_file {
            match load_env_file(ef_path) {
                Ok(pairs) => {
                    info!(
                        "Loaded {} env var(s) from env_file '{}' for '{}'",
                        pairs.len(),
                        ef_path,
                        self.service.name
                    );
                    env_overlay.extend(pairs);
                }
                Err(e) => warn!(
                    "env_file '{}' for '{}' could not be read: {} (skipping)",
                    ef_path, self.service.name, e
                ),
            }
        }

        // ── sd_notify socket ─────────────────────────────────────────────
        let notify_server = if self.service.notify_type == NotifyType::Notify {
            match NotifyServer::new(&self.service.name) {
                Ok(srv) => Some(srv),
                Err(e) => {
                    warn!(
                        "sd_notify setup failed for '{}': {} (skipping)",
                        self.service.name, e
                    );
                    None
                }
            }
        } else {
            None
        };

        // ── Socket activation ─────────────────────────────────────────────
        let mut activation_sockets: Vec<ActivationSocket> = Vec::new();
        for spec in &self.service.socket_listen {
            let socket = if let Some(path) = spec.strip_prefix("unix:") {
                ActivationSocket::new_unix_stream(&self.service.name, path)
            } else if let Some(addr) = spec.strip_prefix("tcp:") {
                ActivationSocket::new_tcp(&self.service.name, addr)
            } else {
                Err(anyhow::anyhow!(
                    "Unknown socket spec '{}' (use unix: or tcp:)",
                    spec
                ))
            };
            match socket {
                Ok(s) => activation_sockets.push(s),
                Err(e) => warn!("Socket activation error for '{}': {}", self.service.name, e),
            }
        }

        // ── Build environment ─────────────────────────────────────────────
        // env_overlay already populated from env_file above; now merge service.environment
        // (explicit env table takes priority over env_file values)
        if let Some(ref svc_env) = self.service.environment {
            env_overlay.extend(svc_env.clone());
        }
        if let Some(ref ns) = notify_server {
            env_overlay.insert("NOTIFY_SOCKET".into(), ns.socket_path().into());
        }
        if !activation_sockets.is_empty() {
            for (k, v) in build_listen_env(&activation_sockets) {
                env_overlay.insert(k, v);
            }
        }

        let act_fds: Vec<i32> = activation_sockets.iter().map(|s| s.fd).collect();
        let drop_capabilities = resolve_capability_numbers(&self.service.drop_capabilities)
            .map_err(|e| anyhow::anyhow!("Service '{}': {}", self.service.name, e))?;
        let seccomp_profile_denylist = resolve_seccomp_profile_for_service(&self.service)
            .map_err(|e| anyhow::anyhow!("Service '{}': {}", self.service.name, e))?;

        let (exec_cmd, exec_args) = resolve_command_argv(&self.service.command, &self.service.args)
            .map_err(|e| anyhow::anyhow!("Service '{}': {}", self.service.name, e))?;
        let exec_args_refs: Vec<&str> = exec_args.iter().map(String::as_str).collect();

        let pid = start_service_as(&ServiceLaunch {
            cmd: &exec_cmd,
            args: &exec_args_refs,
            uid,
            gid,
            working_dir: self.service.working_dir.as_deref(),
            tty_path: self.service.tty.as_deref(),
            env: Some(&env_overlay),
            log_write_fd,
            activation_fds: &act_fds,
            apparmor_profile: self.service.apparmor_profile.as_deref(),
            no_new_privileges: self.service.no_new_privileges,
            non_dumpable: self.service.non_dumpable,
            clear_ambient_caps: self.service.clear_ambient_caps,
            drop_capabilities: &drop_capabilities,
            ambient_capabilities: &resolve_ambient_caps(&self.service.ambient_capabilities),
            capability_bounding_set: &resolve_bounding_set(&self.service.capability_bounding_set),
            seccomp_profile_denylist: &seccomp_profile_denylist,
            seccomp_allowlist: &resolve_seccomp_allowlist(&self.service),
            seccomp_strict: self.service.seccomp == SeccompMode::Strict,
            rlimit: self.service.rlimit.as_ref(),
            private_tmp: self.service.private_tmp,
            protect_system: self.service.protect_system,
            landlock_paths: &self.service.landlock_paths,
            service_for_sandbox: Some(&self.service),
        })?;

        // Parent: close the log write end (child has its own copy via dup2)
        if let Some(wfd) = log_write_fd {
            unsafe { libc::close(wfd) };
        }

        // ── Assign to cgroup ──────────────────────────────────────────────
        let pid_raw = pid.as_raw() as u32;
        if let Err(e) = cgroup::assign_pid_to_cgroup(&self.service.name, pid_raw) {
            warn!(
                "cgroup assign failed for '{}': {} (continuing)",
                self.service.name, e
            );
        }

        if let Some(ref ready_socket) = self.service.ready_socket {
            let wait = Duration::from_secs(self.service.timeout_start);
            match wait_for_path(ready_socket, wait) {
                Ok(true) => {
                    info!(
                        "Service '{}' readiness socket present: {}",
                        self.service.name, ready_socket
                    );
                    if let Some(ref alias_path) = self.service.socket_alias {
                        if alias_path != ready_socket {
                            if let Err(e) = create_socket_alias(alias_path, ready_socket) {
                                warn!(
                                    "Could not create socket alias '{}' -> '{}': {}",
                                    alias_path, ready_socket, e
                                );
                            }
                        }
                    }
                }
                Ok(false) => warn!(
                    "Service '{}' socket '{}' did not appear within {}s",
                    self.service.name, ready_socket, self.service.timeout_start
                ),
                Err(e) => warn!(
                    "Service '{}' readiness wait failed for '{}': {}",
                    self.service.name, ready_socket, e
                ),
            }
        }

        self.pid.store(pid.as_raw(), Ordering::Release);
        self.running.store(true, Ordering::Release);
        dbus::register_service_global(&self.service.name, pid_raw as i32, true);

        // ── bgprocess (pid-file) readiness ────────────────────────────────
        // For traditional daemons that fork to background and write a PID file.
        // We wait for the PID file to appear, then update our tracked PID to
        // the daemonized child's PID (the original fork exits after daemonizing).
        if self.service.notify_type == NotifyType::BgProcess {
            if let Some(ref pid_file) = self.service.pid_file {
                let timeout = Duration::from_secs(self.service.timeout_start);
                match wait_for_pid_file(pid_file, timeout) {
                    Ok(daemon_pid) => {
                        info!(
                            "Service '{}' daemonized — PID file '{}' → PID {}",
                            self.service.name, pid_file, daemon_pid
                        );
                        self.pid.store(daemon_pid as i32, Ordering::Release);
                        let _ = cgroup::assign_pid_to_cgroup(&self.service.name, daemon_pid);
                        dbus::register_service_global(&self.service.name, daemon_pid as i32, true);
                    }
                    Err(e) => warn!(
                        "Service '{}' pid-file readiness failed: {} (tracking original PID)",
                        self.service.name, e
                    ),
                }
            }
        }

        info!("Service '{}' running — PID {}", self.service.name, pid_raw);

        if self.service.oneshot {
            let exit_code = wait_for_exit(pid_raw);
            self.running.store(false, Ordering::Release);
            dbus::register_service_global(&self.service.name, pid_raw as i32, false);

            if exit_code == 0 {
                info!(
                    "One-shot service '{}' completed successfully",
                    self.service.name
                );
            } else {
                warn!(
                    "One-shot service '{}' exited with code {}",
                    self.service.name, exit_code
                );
            }

            return Ok(());
        }

        // ── Wait for readiness (sd_notify or simple) ──────────────────────
        if let Some(mut ns) = notify_server {
            let timeout = Duration::from_secs(self.service.timeout_start);
            match ns.wait_for_ready(timeout) {
                Ok(true) => info!("Service '{}' ready (sd_notify)", self.service.name),
                Ok(false) => warn!(
                    "Service '{}' did not signal READY=1 within {}s",
                    self.service.name, self.service.timeout_start
                ),
                Err(e) => warn!("sd_notify error for '{}': {}", self.service.name, e),
            }
        }

        // ── Restart monitor ───────────────────────────────────────────────
        if self.service.restart != RestartPolicy::No {
            let svc = self.service.clone();
            let pid_ref = Arc::clone(&self.pid);
            let running = Arc::clone(&self.running);
            let stop_requested = Arc::clone(&self.stop_requested);

            thread::Builder::new()
                .name(format!("monitor-{}", self.service.name))
                .spawn(move || restart_monitor(svc, pid_ref, running, stop_requested))
                .map_err(|e| {
                    anyhow::anyhow!("Cannot spawn monitor for '{}': {}", self.service.name, e)
                })?;
        }

        // ── Watchdog thread ───────────────────────────────────────────────
        if self.service.watchdog_sec > 0 {
            let watcher_name = self.service.name.clone();
            let watcher_pid = Arc::clone(&self.pid);
            let watcher_running = Arc::clone(&self.running);
            let watcher_stop = Arc::clone(&self.stop_requested);
            let interval = self.service.watchdog_sec;

            thread::Builder::new()
                .name(format!("watchdog-{}", self.service.name))
                .spawn(move || {
                    watchdog_thread(
                        watcher_name,
                        watcher_pid,
                        watcher_running,
                        watcher_stop,
                        interval,
                    );
                })
                .ok();
        }

        // ── Healthcheck thread (Phase 4D — Docker-style, world first in init) ──
        if let Some(ref hc) = self.service.healthcheck {
            let hc = hc.clone();
            let hc_name = self.service.name.clone();
            let hc_pid = Arc::clone(&self.pid);
            let hc_running = Arc::clone(&self.running);
            let hc_stop = Arc::clone(&self.stop_requested);

            thread::Builder::new()
                .name(format!("health-{}", self.service.name))
                .spawn(move || {
                    healthcheck_thread(hc_name, hc, hc_pid, hc_running, hc_stop);
                })
                .ok();
        }

        // ── ExecStartPost hooks ───────────────────────────────────────────
        for post_cmd in &self.service.exec_start_post {
            info!("ExecStartPost for '{}': {}", self.service.name, post_cmd);
            match std::process::Command::new("/overlayer/syshub/bin/sh")
                .args(["-c", post_cmd])
                .status()
            {
                Ok(s) if s.success() => {}
                Ok(s) => warn!(
                    "ExecStartPost '{}' exited {} for '{}' (non-fatal)",
                    post_cmd,
                    s.code().unwrap_or(-1),
                    self.service.name
                ),
                Err(e) => warn!(
                    "ExecStartPost '{}' failed for '{}': {} (non-fatal)",
                    post_cmd, self.service.name, e
                ),
            }
        }

        Ok(())
    }

    /// Send a reload signal or run the reload command.
    ///
    /// Called by the control socket handler for `ControlCommand::Reload`.
    pub fn reload(&self) -> anyhow::Result<()> {
        let raw_pid = self.pid.load(Ordering::Acquire);
        if raw_pid <= 0 || !self.running.load(Ordering::Acquire) {
            anyhow::bail!("Service '{}' is not running", self.service.name);
        }

        // reload_command takes priority over reload_signal
        if let Some(ref cmd) = self.service.reload_command {
            info!("Reloading '{}' via command: {}", self.service.name, cmd);
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            if parts.is_empty() {
                anyhow::bail!("reload_command for '{}' is empty", self.service.name);
            }
            let status = std::process::Command::new(parts[0])
                .args(&parts[1..])
                .status()
                .map_err(|e| anyhow::anyhow!("reload_command exec failed: {}", e))?;
            if !status.success() {
                anyhow::bail!(
                    "reload_command for '{}' exited with {}",
                    self.service.name,
                    status.code().unwrap_or(-1)
                );
            }
            return Ok(());
        }

        // Fall back to reload_signal
        let sig = parse_signal_name(&self.service.reload_signal).unwrap_or(Signal::SIGHUP);

        let nix_pid = nix::unistd::Pid::from_raw(raw_pid);
        signal::kill(nix_pid, sig)
            .map_err(|e| anyhow::anyhow!("kill({}) failed: {}", self.service.reload_signal, e))?;

        info!(
            "Sent {} to '{}' (PID {})",
            self.service.reload_signal, self.service.name, raw_pid
        );
        Ok(())
    }

    /// Full 2-stage stop state machine (matches systemd behavior):
    ///
    /// ```
    /// STOP_WATCHDOG  → send watchdog ping, wait TimeoutStopSec/2
    /// STOP_SIGTERM   → SIGTERM + ExecStop, wait TimeoutStopSec
    /// STOP_SIGKILL   → cgroup.kill + SIGKILL
    /// FINAL_SIGTERM  → SIGTERM to remaining processes
    /// FINAL_SIGKILL  → SIGKILL to remaining processes
    /// DEAD           → ExecStopPost
    /// ```
    #[allow(dead_code)]
    pub fn stop(&self) {
        self.stop_requested.store(true, Ordering::Release);

        let raw_pid = self.pid.load(Ordering::Acquire);
        if raw_pid <= 0 {
            self.run_exec_stop_post();
            return;
        }

        let pid = nix::unistd::Pid::from_raw(raw_pid);
        info!(
            "Stopping '{}' (PID {}) [2-stage kill]",
            self.service.name, raw_pid
        );
        dbus::register_service_global(&self.service.name, raw_pid, false);

        // ── STOP_WATCHDOG: send watchdog ping, give watchdog_sec/2 to react ────
        if self.service.watchdog_sec > 0 {
            // Send SIGABRT to make watchdog-aware services do clean shutdown
            let _ = signal::kill(pid, Signal::SIGABRT);
            let watchdog_wait = Duration::from_secs((self.service.watchdog_sec / 2).max(1));
            info!(
                "STOP_WATCHDOG '{}': waiting {}s for watchdog shutdown",
                self.service.name,
                watchdog_wait.as_secs()
            );
            let poll = Duration::from_millis(200);
            let mut elapsed = Duration::ZERO;
            while elapsed < watchdog_wait {
                thread::sleep(poll);
                elapsed += poll;
                if !proc_exists(raw_pid as u32) {
                    info!(
                        "Service '{}' exited during STOP_WATCHDOG",
                        self.service.name
                    );
                    self.running.store(false, Ordering::Release);
                    self.run_exec_stop_post();
                    return;
                }
            }
        }

        // ── STOP: run stop_command if configured (replaces SIGTERM) ──────────
        if let Some(ref stop_cmd) = self.service.stop_command {
            info!("ExecStop '{}': {}", self.service.name, stop_cmd);
            let mut cmd = std::process::Command::new(stop_cmd);
            if !self.service.stop_args.is_empty() {
                cmd.args(&self.service.stop_args);
            }
            let timeout = Duration::from_secs((self.service.timeout_stop / 2).max(5));
            match run_with_timeout(cmd, timeout) {
                Ok(true) => {
                    thread::sleep(Duration::from_millis(500));
                    if !proc_exists(raw_pid as u32) {
                        info!("Service '{}' stopped via ExecStop", self.service.name);
                        self.running.store(false, Ordering::Release);
                        self.run_exec_stop_post();
                        return;
                    }
                }
                Ok(false) => warn!("ExecStop '{}' timed out", self.service.name),
                Err(e) => warn!("ExecStop '{}': {}", self.service.name, e),
            }
        }

        // ── STOP_SIGTERM: first SIGTERM ───────────────────────────────────────
        info!("STOP_SIGTERM '{}' (PID {})", self.service.name, raw_pid);
        if signal::kill(pid, Signal::SIGTERM).is_err() {
            self.running.store(false, Ordering::Release);
            self.run_exec_stop_post();
            return;
        }

        // Poll until dead or timeout_stop
        let poll = Duration::from_millis(250);
        let deadline = Duration::from_secs(self.service.timeout_stop);
        let mut elapsed = Duration::ZERO;
        while elapsed < deadline {
            thread::sleep(poll);
            elapsed += poll;
            if !proc_exists(raw_pid as u32) {
                info!(
                    "Service '{}' stopped after SIGTERM ({}ms)",
                    self.service.name,
                    elapsed.as_millis()
                );
                self.running.store(false, Ordering::Release);
                self.run_exec_stop_post();
                return;
            }
        }

        // ── STOP_SIGKILL: cgroup.kill + SIGKILL ──────────────────────────────
        warn!(
            "STOP_SIGKILL '{}': still alive after {}s",
            self.service.name, self.service.timeout_stop
        );
        let _ = cgroup::kill_service_cgroup(&self.service.name);
        let _ = signal::kill(pid, Signal::SIGKILL);

        // Wait up to 3s for SIGKILL to land
        let mut k = 0u32;
        while k < 12 && proc_exists(raw_pid as u32) {
            thread::sleep(Duration::from_millis(250));
            k += 1;
        }

        // ── FINAL_SIGTERM: any processes remaining in cgroup ──────────────────
        // (Handles child processes that survived SIGKILL to leader)
        info!("FINAL_SIGTERM '{}': cleaning up cgroup", self.service.name);
        self.kill_cgroup_procs(Signal::SIGTERM);
        thread::sleep(Duration::from_millis(500));

        // ── FINAL_SIGKILL: last resort ────────────────────────────────────────
        info!(
            "FINAL_SIGKILL '{}': force kill remaining",
            self.service.name
        );
        self.kill_cgroup_procs(Signal::SIGKILL);

        self.running.store(false, Ordering::Release);
        cgroup::remove_service_cgroup(&self.service.name);

        // ── DEAD → ExecStopPost ───────────────────────────────────────────────
        self.run_exec_stop_post();
    }

    /// Kill all PIDs in the service cgroup with `sig`.
    fn kill_cgroup_procs(&self, sig: Signal) {
        let cgroup_procs = format!(
            "/sys/fs/cgroup/quantra-system/{}/cgroup.procs",
            self.service.name
        );
        if let Ok(data) = std::fs::read_to_string(&cgroup_procs) {
            for line in data.lines() {
                if let Ok(pid) = line.trim().parse::<i32>() {
                    let p = nix::unistd::Pid::from_raw(pid);
                    let _ = signal::kill(p, sig);
                }
            }
        }
    }

    /// Run ExecStopPost commands after service is fully dead.
    fn run_exec_stop_post(&self) {
        for post_cmd in &self.service.exec_stop_post {
            log::info!("ExecStopPost '{}': {}", self.service.name, post_cmd);
            std::process::Command::new("/overlayer/syshub/bin/sh")
                .args(["-c", post_cmd.as_str()])
                .status()
                .ok();
        }
    }
}

// ── Restart monitor ──────────────────────────────────────────────────────────

fn restart_monitor(
    svc: Service,
    pid_cell: Arc<AtomicI32>,
    running: Arc<AtomicBool>,
    stop_requested: Arc<AtomicBool>,
) {
    let mut current_pid = pid_cell.load(Ordering::Acquire) as u32;
    // Crash-loop breaker: sliding window of restart timestamps
    let mut restart_times: VecDeque<Instant> = VecDeque::new();

    loop {
        let exit_code = wait_for_exit(current_pid);
        running.store(false, Ordering::Release);
        dbus::register_service_global(&svc.name, current_pid as i32, false);

        if stop_requested.load(Ordering::Acquire) {
            info!("Service '{}' stopping — restart suppressed", svc.name);
            break;
        }

        // ── max_restarts crash-loop breaker ────────────────────────────────
        if svc.max_restarts > 0 {
            let window = Duration::from_secs(svc.restart_interval_sec);
            let now = Instant::now();
            // Evict timestamps outside the window
            while restart_times
                .front()
                .map(|t| now.duration_since(*t) > window)
                .unwrap_or(false)
            {
                restart_times.pop_front();
            }
            if restart_times.len() as u32 >= svc.max_restarts {
                error!(
                    "Service '{}' has restarted {} times in {}s — giving up (crash-loop detected)",
                    svc.name, svc.max_restarts, svc.restart_interval_sec
                );
                break;
            }
            restart_times.push_back(now);
        }

        match svc.restart {
            RestartPolicy::No => break,
            RestartPolicy::OnFailure if exit_code == 0 => {
                info!(
                    "Service '{}' exited cleanly — no restart (OnFailure)",
                    svc.name
                );
                break;
            }
            RestartPolicy::OnFailure => {
                warn!(
                    "Service '{}' failed (code {}) — restarting in {}s",
                    svc.name, exit_code, svc.restart_sec
                );
            }
            RestartPolicy::Always => {
                info!(
                    "Service '{}' exited (code {}) — restarting in {}s",
                    svc.name, exit_code, svc.restart_sec
                );
            }
        }

        thread::sleep(Duration::from_secs(svc.restart_sec));

        // ── chain_to: on clean exit, start next service ────────────────────────
        if let Some(ref chain) = svc.chain_to {
            let trigger = if svc.chain_to_always {
                true
            } else {
                exit_code == 0
            };
            if trigger {
                info!(
                    "Service '{}' exited (code {}) — chain_to '{}'",
                    svc.name, exit_code, chain
                );
                // Signal the manager via the global CHAIN_TO channel.
                // We don't block the monitor thread on the new service starting.
                crate::services::manager::queue_chain_start(chain.clone());
                break; // Don't also restart this service
            }
        }

        let (uid, gid) = match resolve_credentials(&svc) {
            Ok(c) => c,
            Err(e) => {
                error!("Credential error on restart for '{}': {}", svc.name, e);
                continue;
            }
        };

        let (exec_cmd, exec_args) = match resolve_command_argv(&svc.command, &svc.args) {
            Ok(spec) => spec,
            Err(e) => {
                error!("Invalid restart command for '{}': {}", svc.name, e);
                break;
            }
        };

        let exec_args_refs: Vec<&str> = exec_args.iter().map(String::as_str).collect();
        let drop_capabilities = match resolve_capability_numbers(&svc.drop_capabilities) {
            Ok(v) => v,
            Err(e) => {
                error!("Invalid capability drop list for '{}': {}", svc.name, e);
                break;
            }
        };
        let seccomp_profile_denylist = match resolve_seccomp_profile_for_service(&svc) {
            Ok(v) => v,
            Err(e) => {
                error!("Invalid seccomp profile for '{}': {}", svc.name, e);
                break;
            }
        };

        let log_write_fd: Option<i32> = if svc.console {
            None
        } else {
            match create_service_logger(&svc.name) {
                Ok((wfd, logger)) => {
                    let svc_name = svc.name.clone();
                    thread::Builder::new()
                        .name(format!("log-{}-restart", svc_name))
                        .spawn(move || logger.run())
                        .ok();
                    Some(wfd)
                }
                Err(e) => {
                    log::warn!(
                        "Logger recreation failed for '{}' on restart: {} (using /dev/console)",
                        svc.name,
                        e
                    );
                    None
                }
            }
        };

        // Build environment: env_file base + service.environment overlay
        let mut restart_env: HashMap<String, String> = HashMap::new();
        if let Some(ref ef) = svc.env_file {
            if let Ok(pairs) = load_env_file(ef) {
                restart_env.extend(pairs);
            }
        }
        if let Some(ref svc_env) = svc.environment {
            restart_env.extend(svc_env.clone());
        }
        let restart_env_opt: Option<&HashMap<String, String>> = if restart_env.is_empty() {
            None
        } else {
            Some(&restart_env)
        };

        let seccomp_allowlist_restart = resolve_seccomp_allowlist(&svc);
        let launch = ServiceLaunch {
            cmd: &exec_cmd,
            args: &exec_args_refs,
            uid,
            gid,
            working_dir: svc.working_dir.as_deref(),
            tty_path: svc.tty.as_deref(),
            env: restart_env_opt,
            log_write_fd,
            activation_fds: &[],
            apparmor_profile: svc.apparmor_profile.as_deref(),
            no_new_privileges: svc.no_new_privileges,
            non_dumpable: svc.non_dumpable,
            clear_ambient_caps: svc.clear_ambient_caps,
            drop_capabilities: &drop_capabilities,
            ambient_capabilities: &resolve_ambient_caps(&svc.ambient_capabilities),
            capability_bounding_set: &resolve_bounding_set(&svc.capability_bounding_set),
            seccomp_allowlist: &seccomp_allowlist_restart,
            seccomp_profile_denylist: &seccomp_profile_denylist,
            seccomp_strict: svc.seccomp == SeccompMode::Strict,
            rlimit: svc.rlimit.as_ref(),
            private_tmp: svc.private_tmp,
            protect_system: svc.protect_system,
            landlock_paths: &svc.landlock_paths,
            service_for_sandbox: Some(&svc),
        };

        match start_service_as(&launch) {
            Ok(new_pid) => {
                let raw = new_pid.as_raw();
                info!("Service '{}' restarted — PID {}", svc.name, raw);
                let _ = cgroup::assign_pid_to_cgroup(&svc.name, raw as u32);
                pid_cell.store(raw, Ordering::Release);
                current_pid = raw as u32;
                running.store(true, Ordering::Release);
                dbus::register_service_global(&svc.name, raw, true);
            }
            Err(e) => {
                error!(
                    "Restart failed for '{}': {} — retrying in {}s",
                    svc.name,
                    e,
                    svc.restart_sec * 2
                );
                thread::sleep(Duration::from_secs(svc.restart_sec * 2));
            }
        }
    }
}

/// Wait for a process to be fully reaped, using the real exit code from signals module.
fn wait_for_exit(pid: u32) -> i32 {
    loop {
        // Real exit code from SIGCHLD reaper thread
        if let Some(code) = crate::signals::get_exit_code(pid as i32) {
            return code;
        }
        // Process still alive — keep polling
        if !proc_exists(pid) {
            // Reaped but code not yet in map — give reaper thread a moment
            thread::sleep(Duration::from_millis(50));
            return crate::signals::get_exit_code(pid as i32).unwrap_or(0);
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn wait_for_path(path: &str, timeout: Duration) -> Result<bool> {
    let deadline = std::time::Instant::now() + timeout;
    while !Path::new(path).exists() {
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(true)
}

fn create_socket_alias(alias_path: &str, target_path: &str) -> Result<()> {
    let alias = Path::new(alias_path);
    if alias.exists() {
        return Ok(());
    }

    if let Some(parent) = alias.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            anyhow::anyhow!("Cannot create alias parent '{}': {}", parent.display(), e)
        })?;
    }

    unix_fs::symlink(target_path, alias_path).map_err(|e| {
        anyhow::anyhow!(
            "Cannot symlink '{}' -> '{}': {}",
            alias_path,
            target_path,
            e
        )
    })?;
    info!("Socket alias created: {} -> {}", alias_path, target_path);
    Ok(())
}

#[inline]
fn proc_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

// ── Credential resolution ─────────────────────────────────────────────────────

fn resolve_credentials(svc: &Service) -> Result<(Option<u32>, Option<u32>)> {
    let uid = svc.user.as_deref().map(lookup_uid).transpose()?;
    let gid = svc.group.as_deref().map(lookup_gid).transpose()?;
    Ok((uid, gid))
}

fn resolve_seccomp_profile_for_service(svc: &Service) -> Result<Vec<libc::c_long>> {
    match svc.seccomp {
        SeccompMode::Off | SeccompMode::Strict => Ok(Vec::new()),
        SeccompMode::Profile => {
            let profile_name = svc
                .seccomp_profile
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("seccomp is 'profile' but seccomp_profile is not set")
                })?;

            resolve_seccomp_profile_denylist(profile_name)
        }
    }
}

fn lookup_uid(user: &str) -> Result<u32> {
    if let Ok(n) = user.parse::<u32>() {
        return Ok(n);
    }
    let passwd = std::fs::read_to_string("/overlayer/syshub/etc/passwd").map_err(|e| {
        anyhow::anyhow!(
            "Cannot read /overlayer/syshub/etc/passwd (user '{}'): {}",
            user,
            e
        )
    })?;
    for line in passwd.lines() {
        let f: Vec<&str> = line.splitn(7, ':').collect();
        if f.len() >= 3 && f[0] == user {
            return f[2]
                .parse()
                .map_err(|_| anyhow::anyhow!("Bad UID for user '{}'", user));
        }
    }
    Err(anyhow::anyhow!(
        "User '{}' not found in /overlayer/syshub/etc/passwd",
        user
    ))
}

fn lookup_gid(group: &str) -> Result<u32> {
    if let Ok(n) = group.parse::<u32>() {
        return Ok(n);
    }
    let gfile = std::fs::read_to_string("/overlayer/syshub/etc/group").map_err(|e| {
        anyhow::anyhow!(
            "Cannot read /overlayer/syshub/etc/group (group '{}'): {}",
            group,
            e
        )
    })?;
    for line in gfile.lines() {
        let f: Vec<&str> = line.splitn(4, ':').collect();
        if f.len() >= 3 && f[0] == group {
            return f[2]
                .parse()
                .map_err(|_| anyhow::anyhow!("Bad GID for group '{}'", group));
        }
    }
    Err(anyhow::anyhow!(
        "Group '{}' not found in /overlayer/syshub/etc/group",
        group
    ))
}

// ── env_file helper ───────────────────────────────────────────────────────────

/// Parse a `KEY=VALUE` file (like `/etc/default/<service>`).
///
/// Rules:
/// - Lines starting with `#` are comments (skipped).
/// - Empty lines are skipped.
/// - Lines must contain `=`. Key is left of first `=`, value is right.
/// - Leading/trailing whitespace is stripped from both key and value.
/// - `export KEY=VALUE` lines (bash format) are also supported.
fn load_env_file(path: &str) -> anyhow::Result<HashMap<String, String>> {
    let content = fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Cannot read env_file '{}': {}", path, e))?;

    let mut map = HashMap::new();
    for (lineno, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Strip optional "export " prefix (bash compatibility)
        let line = line.strip_prefix("export ").unwrap_or(line).trim();

        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_string();
            let value = value.trim().trim_matches('"').to_string(); // strip optional quotes
            if key.is_empty() {
                warn!(
                    "env_file '{}' line {}: empty key — skipped",
                    path,
                    lineno + 1
                );
                continue;
            }
            map.insert(key, value);
        } else {
            warn!(
                "env_file '{}' line {}: no '=' found — skipped: '{}'",
                path,
                lineno + 1,
                line
            );
        }
    }
    Ok(map)
}

// ── bgprocess PID-file polling ────────────────────────────────────────────────

/// Poll `pid_file_path` until it appears AND contains a valid non-zero PID.
/// Returns the PID on success, or an error on timeout.
fn wait_for_pid_file(pid_file_path: &str, timeout: Duration) -> anyhow::Result<u32> {
    let deadline = std::time::Instant::now() + timeout;
    let poll_interval = Duration::from_millis(100);

    loop {
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "Timed out waiting for PID file '{}' to appear ({}s)",
                pid_file_path,
                timeout.as_secs()
            );
        }

        if let Ok(content) = fs::read_to_string(pid_file_path) {
            let trimmed = content.trim();
            if let Ok(pid) = trimmed.parse::<u32>() {
                if pid > 0 && proc_exists(pid) {
                    return Ok(pid);
                }
            }
        }

        thread::sleep(poll_interval);
    }
}

// ── Watchdog thread ───────────────────────────────────────────────────────────

/// Background thread that checks every `interval_sec / 2` seconds that the
/// service process is still alive. If the process disappears without a stop
/// request, logs an ERROR (the restart_monitor will handle restarting).
fn watchdog_thread(
    name: String,
    pid_cell: Arc<AtomicI32>,
    running: Arc<AtomicBool>,
    stop_requested: Arc<AtomicBool>,
    interval_sec: u64,
) {
    let check_interval = Duration::from_secs(interval_sec.max(1) / 2 + 1);

    loop {
        thread::sleep(check_interval);

        if stop_requested.load(Ordering::Acquire) {
            return; // Service is intentionally being stopped
        }

        if !running.load(Ordering::Acquire) {
            return; // Already noted as stopped
        }

        let raw_pid = pid_cell.load(Ordering::Acquire);
        if raw_pid <= 0 {
            return;
        }

        if !proc_exists(raw_pid as u32) {
            error!(
                "Watchdog: service '{}' (PID {}) has disappeared — marking as crashed",
                name, raw_pid
            );
            running.store(false, Ordering::Release);
            return; // restart_monitor will handle the restart
        }
    }
}

// ── Signal name parser ────────────────────────────────────────────────────────

/// Parse a signal name string (e.g. `"SIGHUP"`, `"HUP"`, `"SIGUSR1"`) into
/// a `nix::sys::signal::Signal`. Returns `None` if unrecognised.
fn parse_signal_name(name: &str) -> Option<Signal> {
    let canonical = name.trim_start_matches("SIG");
    match canonical.to_ascii_uppercase().as_str() {
        "HUP" => Some(Signal::SIGHUP),
        "INT" => Some(Signal::SIGINT),
        "QUIT" => Some(Signal::SIGQUIT),
        "TERM" => Some(Signal::SIGTERM),
        "KILL" => Some(Signal::SIGKILL),
        "USR1" => Some(Signal::SIGUSR1),
        "USR2" => Some(Signal::SIGUSR2),
        "CONT" => Some(Signal::SIGCONT),
        "STOP" => Some(Signal::SIGSTOP),
        "ALRM" => Some(Signal::SIGALRM),
        "PIPE" => Some(Signal::SIGPIPE),
        "CHLD" => Some(Signal::SIGCHLD),
        _ => {
            warn!("Unknown signal name '{}' — defaulting to SIGHUP", name);
            None
        }
    }
}

// ── run_with_timeout ──────────────────────────────────────────────────────────

/// Run the health check command.
/// Returns `true` if healthy (exit 0), `false` otherwise.
fn run_healthcheck_once(hc: &HealthCheck) -> bool {
    let timeout = Duration::from_secs(hc.timeout_sec);
    let mut cmd = std::process::Command::new(&hc.command);
    cmd.args(&hc.args);
    match run_with_timeout(cmd, timeout) {
        Ok(success) => success,
        Err(e) => {
            warn!(
                "Healthcheck command '{}' failed to spawn: {}",
                hc.command, e
            );
            false
        }
    }
}

// ── Healthcheck thread ────────────────────────────────────────────────────────

/// Background thread that runs a health-check command every `interval_sec`.
/// After `failure_threshold` consecutive failures, marks the service as not
/// running so the restart_monitor kicks in and restarts it.
///
/// This is equivalent to Docker's `HEALTHCHECK` instruction —
/// **no other production init system has this feature.**
fn healthcheck_thread(
    name: String,
    hc: HealthCheck,
    pid_cell: Arc<AtomicI32>,
    running: Arc<AtomicBool>,
    stop_requested: Arc<AtomicBool>,
) {
    // Give the service a moment to finish starting before first check
    thread::sleep(Duration::from_secs(hc.interval_sec));

    let mut consecutive_failures: u32 = 0;

    loop {
        // Stop if service is being shut down
        if stop_requested.load(Ordering::Acquire) {
            return;
        }
        if !running.load(Ordering::Acquire) {
            return;
        }
        // Stop if the process is gone (watchdog / restart_monitor handles restart)
        let raw_pid = pid_cell.load(Ordering::Acquire);
        if raw_pid <= 0 || !proc_exists(raw_pid as u32) {
            return;
        }

        if run_healthcheck_once(&hc) {
            if consecutive_failures > 0 {
                info!(
                    "Healthcheck '{}': recovered (was {} failures)",
                    name, consecutive_failures
                );
            }
            consecutive_failures = 0;
        } else {
            consecutive_failures += 1;
            warn!(
                "Healthcheck '{}': failure {}/{} (cmd='{}')",
                name, consecutive_failures, hc.failure_threshold, hc.command
            );

            if consecutive_failures >= hc.failure_threshold {
                error!(
                    "Healthcheck '{}': exceeded failure threshold ({}/{}) — triggering restart",
                    name, consecutive_failures, hc.failure_threshold
                );
                // Signal to restart_monitor that the service is unhealthy
                running.store(false, Ordering::Release);
                return;
            }
        }

        thread::sleep(Duration::from_secs(hc.interval_sec));
    }
}

/// Spawn `cmd` and wait up to `timeout`. Returns:
/// - `Ok(true)` if process exited with code 0 within the timeout
/// - `Ok(false)` if the process timed out or exited non-zero
/// - `Err(...)` if the command could not be spawned
fn run_with_timeout(mut cmd: std::process::Command, timeout: Duration) -> anyhow::Result<bool> {
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn failed: {}", e))?;

    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.success()),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    return Ok(false); // timed out
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => anyhow::bail!("wait error: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_signal_hup() {
        assert_eq!(parse_signal_name("HUP"), Some(Signal::SIGHUP));
    }

    #[test]
    fn parse_signal_with_sig_prefix() {
        assert_eq!(parse_signal_name("SIGTERM"), Some(Signal::SIGTERM));
    }

    #[test]
    fn parse_signal_usr1() {
        assert_eq!(parse_signal_name("USR1"), Some(Signal::SIGUSR1));
    }

    #[test]
    fn parse_signal_unknown_returns_none() {
        assert!(parse_signal_name("BOGUS").is_none());
    }

    /// Helper: parse env content from string (mirrors load_env_file logic)
    fn parse_env_content(content: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").unwrap_or(line).trim();
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim().to_string();
                let value = value.trim().trim_matches('"').to_string();
                if !key.is_empty() {
                    map.insert(key, value);
                }
            }
        }
        map
    }

    #[test]
    fn env_parse_simple_key_value() {
        let map = parse_env_content("FOO=bar\nBAZ=123");
        assert_eq!(map.get("FOO").unwrap(), "bar");
        assert_eq!(map.get("BAZ").unwrap(), "123");
    }

    #[test]
    fn env_parse_skips_comments_and_empty() {
        let map = parse_env_content("# comment\n\nFOO=bar\n  # another\n");
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("FOO").unwrap(), "bar");
    }

    #[test]
    fn env_parse_strips_export_prefix() {
        let map = parse_env_content("export FOO=bar\nexport BAZ=qux");
        assert_eq!(map.get("FOO").unwrap(), "bar");
        assert_eq!(map.get("BAZ").unwrap(), "qux");
    }

    #[test]
    fn env_parse_strips_quotes() {
        let map = parse_env_content("FOO=\"hello world\"");
        assert_eq!(map.get("FOO").unwrap(), "hello world");
    }

    #[test]
    fn env_parse_handles_value_with_equals() {
        let map = parse_env_content("OPTS=--flag=value");
        assert_eq!(map.get("OPTS").unwrap(), "--flag=value");
    }
}

// ── Capability / seccomp helpers ──────────────────────────────────────────────

fn resolve_ambient_caps(names: &[String]) -> Vec<libc::c_ulong> {
    use crate::process::capability_name_to_number;
    names
        .iter()
        .filter_map(|n| capability_name_to_number(n))
        .collect()
}

fn resolve_bounding_set(names: &[String]) -> Vec<libc::c_ulong> {
    use crate::process::capability_name_to_number;
    if names.is_empty() {
        return Vec::new();
    }
    names
        .iter()
        .filter_map(|n| {
            let n = n.trim_start_matches('~');
            capability_name_to_number(n)
        })
        .collect()
}

fn resolve_seccomp_allowlist(svc: &super::types::Service) -> Vec<libc::c_long> {
    if svc.syscall_filter_mode != "allowlist" || svc.seccomp == super::types::SeccompMode::Off {
        return Vec::new();
    }
    // Base set of syscalls every process needs
    let base: Vec<libc::c_long> = vec![
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_open,
        libc::SYS_close,
        libc::SYS_stat,
        libc::SYS_fstat,
        libc::SYS_lstat,
        libc::SYS_poll,
        libc::SYS_lseek,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_ioctl,
        libc::SYS_access,
        libc::SYS_pipe,
        libc::SYS_select,
        libc::SYS_sched_yield,
        libc::SYS_mremap,
        libc::SYS_msync,
        libc::SYS_mincore,
        libc::SYS_madvise,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_nanosleep,
        libc::SYS_getitimer,
        libc::SYS_alarm,
        libc::SYS_setitimer,
        libc::SYS_getpid,
        libc::SYS_sendfile,
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_accept,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_shutdown,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_socketpair,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_clone,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_execve,
        libc::SYS_exit,
        libc::SYS_wait4,
        libc::SYS_kill,
        libc::SYS_uname,
        libc::SYS_fcntl,
        libc::SYS_flock,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_truncate,
        libc::SYS_ftruncate,
        libc::SYS_getdents,
        libc::SYS_getcwd,
        libc::SYS_chdir,
        libc::SYS_rename,
        libc::SYS_mkdir,
        libc::SYS_rmdir,
        libc::SYS_creat,
        libc::SYS_link,
        libc::SYS_unlink,
        libc::SYS_symlink,
        libc::SYS_readlink,
        libc::SYS_chmod,
        libc::SYS_fchmod,
        libc::SYS_chown,
        libc::SYS_fchown,
        libc::SYS_lchown,
        libc::SYS_umask,
        libc::SYS_gettimeofday,
        libc::SYS_getrlimit,
        libc::SYS_getrusage,
        libc::SYS_sysinfo,
        libc::SYS_times,
        libc::SYS_getuid,
        libc::SYS_syslog,
        libc::SYS_getgid,
        libc::SYS_setuid,
        libc::SYS_setgid,
        libc::SYS_geteuid,
        libc::SYS_getegid,
        libc::SYS_setpgid,
        libc::SYS_getppid,
        libc::SYS_getpgrp,
        libc::SYS_setsid,
        libc::SYS_setreuid,
        libc::SYS_setregid,
        libc::SYS_getgroups,
        libc::SYS_setgroups,
        libc::SYS_setresuid,
        libc::SYS_getresuid,
        libc::SYS_setresgid,
        libc::SYS_getresgid,
        libc::SYS_getpgid,
        libc::SYS_setfsuid,
        libc::SYS_setfsgid,
        libc::SYS_getsid,
        libc::SYS_rt_sigpending,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_sigsuspend,
        libc::SYS_sigaltstack,
        libc::SYS_utime,
        libc::SYS_mknod,
        libc::SYS_personality,
        libc::SYS_statfs,
        libc::SYS_fstatfs,
        libc::SYS_sysfs,
        libc::SYS_getpriority,
        libc::SYS_setpriority,
        libc::SYS_prctl,
        libc::SYS_arch_prctl,
        libc::SYS_setrlimit,
        libc::SYS_chroot,
        libc::SYS_sync,
        libc::SYS_acct,
        libc::SYS_settimeofday,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_reboot,
        libc::SYS_gettid,
        libc::SYS_futex,
        libc::SYS_sched_setaffinity,
        libc::SYS_sched_getaffinity,
        libc::SYS_set_thread_area,
        libc::SYS_io_setup,
        libc::SYS_epoll_create,
        libc::SYS_getdents64,
        libc::SYS_set_tid_address,
        libc::SYS_restart_syscall,
        libc::SYS_openat,
        libc::SYS_mkdirat,
        libc::SYS_mknodat,
        libc::SYS_fchownat,
        libc::SYS_futimesat,
        libc::SYS_newfstatat,
        libc::SYS_unlinkat,
        libc::SYS_renameat,
        libc::SYS_linkat,
        libc::SYS_symlinkat,
        libc::SYS_readlinkat,
        libc::SYS_fchmodat,
        libc::SYS_faccessat,
        libc::SYS_pselect6,
        libc::SYS_ppoll,
        libc::SYS_unshare,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_splice,
        libc::SYS_tee,
        libc::SYS_sync_file_range,
        libc::SYS_vmsplice,
        libc::SYS_move_pages,
        libc::SYS_utimensat,
        libc::SYS_epoll_pwait,
        libc::SYS_signalfd,
        libc::SYS_timerfd_create,
        libc::SYS_eventfd,
        libc::SYS_fallocate,
        libc::SYS_timerfd_settime,
        libc::SYS_timerfd_gettime,
        libc::SYS_accept4,
        libc::SYS_signalfd4,
        libc::SYS_eventfd2,
        libc::SYS_epoll_create1,
        libc::SYS_dup3,
        libc::SYS_pipe2,
        libc::SYS_inotify_init1,
        libc::SYS_preadv,
        libc::SYS_pwritev,
        libc::SYS_rt_tgsigqueueinfo,
        libc::SYS_recvmmsg,
        libc::SYS_fanotify_init,
        libc::SYS_prlimit64,
        libc::SYS_sendmmsg,
        libc::SYS_getcpu,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_getrandom,
        libc::SYS_memfd_create,
        libc::SYS_execveat,
        libc::SYS_copy_file_range,
        libc::SYS_statx,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_close_range,
        libc::SYS_openat2,
        libc::SYS_faccessat2,
        libc::SYS_exit_group,
    ];
    base
}

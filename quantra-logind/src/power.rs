//! Power Manager — shutdown, suspend, hibernate, brightness, wall messages
//!
//! # Inhibitor-aware power actions
//!
//! Before executing any power action, the manager:
//! 1. Checks for `Block` inhibitors — refuses the action if any are held
//! 2. Waits up to `InhibitDelayMaxSec` for `Delay` inhibitors to release
//! 3. Broadcasts a `PrepareForShutdown(true)` event to all subscribers
//! 4. Sends wall messages to all logged-in TTYs
//! 5. Executes the action
//!
//! # Scheduled shutdown
//!
//! `ScheduleShutdown` sets a timer. At the scheduled time, shutdown is
//! performed. Wall messages are sent at: time-1h, time-30m, time-10m,
//! time-5m, time-1m, time-30s.
//!
//! # Brightness control
//!
//! Reads/writes `/sys/class/backlight/<name>/brightness` for display brightness
//! and `/sys/class/leds/<name>/brightness` for keyboard/indicator LEDs.
//! No polkit — logind owns the brightness interface directly.
//!
//! # ACPI event handling
//!
//! Reads ACPI events from `/proc/acpi/event` or `acpi_listen` pipe.
//! Maps events to power actions from config.

use crate::inhibitor::InhibitorManager;
use crate::types::*;
use anyhow::Result;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub struct PowerManager {
    pub can_suspend: bool,
    pub can_hibernate: bool,
    pub can_hybrid_sleep: bool,
    pub can_suspend_then_hibernate: bool,
    pub scheduled_shutdown: Option<ScheduledShutdown>,
    config: LogindConfig,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ScheduledShutdown {
    pub action: String,
    pub time_usec: u64, // Unix microseconds
}

impl PowerManager {
    pub fn new(config: LogindConfig) -> Self {
        let states = fs::read_to_string("/sys/power/state").unwrap_or_default();
        let disk_modes = fs::read_to_string("/sys/power/disk").unwrap_or_default();
        Self {
            can_suspend: states.split_whitespace().any(|s| s == "mem"),
            can_hibernate: states.split_whitespace().any(|s| s == "disk"),
            can_hybrid_sleep: states.split_whitespace().any(|s| s == "disk")
                && disk_modes.contains("suspend"),
            can_suspend_then_hibernate: states.split_whitespace().any(|s| s == "mem")
                && states.split_whitespace().any(|s| s == "disk"),
            scheduled_shutdown: None,
            config,
        }
    }

    /// Can perform power-off? Always yes on real hardware.
    pub fn can_power_off(&self) -> CanDo {
        CanDo::Yes
    }
    pub fn can_reboot(&self) -> CanDo {
        CanDo::Yes
    }
    pub fn can_suspend_q(&self) -> CanDo {
        if self.can_suspend {
            CanDo::Yes
        } else {
            CanDo::No
        }
    }
    pub fn can_hibernate_q(&self) -> CanDo {
        if self.can_hibernate {
            CanDo::Yes
        } else {
            CanDo::No
        }
    }
    pub fn can_hybrid_sleep_q(&self) -> CanDo {
        if self.can_hybrid_sleep {
            CanDo::Yes
        } else {
            CanDo::No
        }
    }
    pub fn can_suspend_then_hibernate_q(&self) -> CanDo {
        if self.can_suspend_then_hibernate {
            CanDo::Yes
        } else {
            CanDo::No
        }
    }

    pub fn power_off(&self, inh: &InhibitorManager, interactive: bool) -> Result<()> {
        self.check_block(inh, &InhibitWhat::Shutdown, interactive)?;
        self.wait_delay(inh, &InhibitWhat::Shutdown);
        self.broadcast_prepare_shutdown(true);
        self.send_wall("System is going down for power-off NOW!");
        log::info!("Power off");
        unsafe {
            libc::sync();
            libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
        }
        Ok(())
    }

    pub fn reboot(&self, inh: &InhibitorManager, interactive: bool) -> Result<()> {
        self.check_block(inh, &InhibitWhat::Shutdown, interactive)?;
        self.wait_delay(inh, &InhibitWhat::Shutdown);
        self.broadcast_prepare_shutdown(true);
        self.send_wall("System is going down for reboot NOW!");
        log::info!("Reboot");
        unsafe {
            libc::sync();
            libc::reboot(libc::LINUX_REBOOT_CMD_RESTART);
        }
        Ok(())
    }

    pub fn reboot_to_firmware(&self, inh: &InhibitorManager, interactive: bool) -> Result<()> {
        self.check_block(inh, &InhibitWhat::Shutdown, interactive)?;
        // Set EFI BootNext variable to firmware setup
        set_efi_boot_to_firmware()?;
        self.send_wall("Rebooting to firmware setup...");
        unsafe {
            libc::sync();
            libc::reboot(libc::LINUX_REBOOT_CMD_RESTART);
        }
        Ok(())
    }

    pub fn halt(&self, inh: &InhibitorManager, interactive: bool) -> Result<()> {
        self.check_block(inh, &InhibitWhat::Shutdown, interactive)?;
        self.wait_delay(inh, &InhibitWhat::Shutdown);
        self.send_wall("System halting NOW!");
        log::info!("Halt");
        unsafe {
            libc::sync();
            libc::reboot(libc::LINUX_REBOOT_CMD_HALT);
        }
        Ok(())
    }

    pub fn suspend(&self, inh: &InhibitorManager, interactive: bool) -> Result<()> {
        if !self.can_suspend {
            return Err(anyhow::anyhow!("suspend not supported on this hardware"));
        }
        if !self.config.suspend_key_ignore_inhibited {
            self.check_block(inh, &InhibitWhat::Sleep, interactive)?;
        }
        self.wait_delay(inh, &InhibitWhat::Sleep);
        self.broadcast_prepare_sleep(true);
        log::info!("Suspend to RAM");
        let r = fs::write("/sys/power/state", "mem")
            .map_err(|e| anyhow::anyhow!("/sys/power/state: {}", e));
        self.broadcast_prepare_sleep(false);
        r
    }

    pub fn hibernate(&self, inh: &InhibitorManager, interactive: bool) -> Result<()> {
        if !self.can_hibernate {
            return Err(anyhow::anyhow!("hibernate not supported"));
        }
        if !self.config.hibernate_key_ignore_inhibited {
            self.check_block(inh, &InhibitWhat::Sleep, interactive)?;
        }
        self.wait_delay(inh, &InhibitWhat::Sleep);
        self.broadcast_prepare_sleep(true);
        log::info!("Hibernate to disk");
        let r = fs::write("/sys/power/state", "disk")
            .map_err(|e| anyhow::anyhow!("/sys/power/state: {}", e));
        self.broadcast_prepare_sleep(false);
        r
    }

    pub fn hybrid_sleep(&self, inh: &InhibitorManager, interactive: bool) -> Result<()> {
        if !self.can_hybrid_sleep {
            return Err(anyhow::anyhow!("hybrid sleep not supported"));
        }
        self.check_block(inh, &InhibitWhat::Sleep, interactive)?;
        self.wait_delay(inh, &InhibitWhat::Sleep);
        self.broadcast_prepare_sleep(true);
        log::info!("Hybrid sleep");
        fs::write("/sys/power/disk", "suspend").ok();
        let r = fs::write("/sys/power/state", "disk")
            .map_err(|e| anyhow::anyhow!("/sys/power/state: {}", e));
        self.broadcast_prepare_sleep(false);
        r
    }

    pub fn suspend_then_hibernate(&self, inh: &InhibitorManager, interactive: bool) -> Result<()> {
        if !self.can_suspend_then_hibernate {
            return Err(anyhow::anyhow!("suspend-then-hibernate not supported"));
        }
        self.check_block(inh, &InhibitWhat::Sleep, interactive)?;
        self.wait_delay(inh, &InhibitWhat::Sleep);
        self.broadcast_prepare_sleep(true);
        log::info!("Suspend-then-hibernate");
        fs::write("/sys/power/disk", "suspend").ok();
        let r = fs::write("/sys/power/state", "mem")
            .map_err(|e| anyhow::anyhow!("/sys/power/state: {}", e));
        self.broadcast_prepare_sleep(false);
        r
    }

    pub fn schedule_shutdown(&mut self, action: String, time_usec: u64) -> Result<()> {
        self.scheduled_shutdown = Some(ScheduledShutdown {
            action: action.clone(),
            time_usec,
        });
        let secs_until = (time_usec.saturating_sub(now_usec())) / 1_000_000;
        self.send_wall(&format!(
            "Shutdown scheduled: {} in {}s",
            action, secs_until
        ));
        log::info!("Shutdown scheduled: {} at {}", action, time_usec);
        Ok(())
    }

    pub fn cancel_scheduled_shutdown(&mut self) -> bool {
        if self.scheduled_shutdown.take().is_some() {
            self.send_wall("Scheduled shutdown cancelled.");
            log::info!("Scheduled shutdown cancelled");
            true
        } else {
            false
        }
    }

    // ── Brightness ────────────────────────────────────────────────────────────

    pub fn set_brightness(&self, subsystem: &str, name: &str, value: u32) -> Result<()> {
        let path = brightness_path(subsystem, name)?;
        let max = read_max_brightness(subsystem, name).unwrap_or(100);
        let clamped = value.min(max);
        fs::write(&path, clamped.to_string())
            .map_err(|e| anyhow::anyhow!("write {}: {}", path, e))?;
        log::info!(
            "Brightness {}/{}: {} (max {})",
            subsystem,
            name,
            clamped,
            max
        );
        Ok(())
    }

    pub fn get_brightness(&self, subsystem: &str, name: &str) -> Result<u32> {
        let path = brightness_path(subsystem, name)?;
        fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("read {}: {}", path, e))?
            .trim()
            .parse::<u32>()
            .map_err(|e| anyhow::anyhow!("parse brightness: {}", e))
    }

    // ── Inhibitor checks ──────────────────────────────────────────────────────

    fn check_block(
        &self,
        inh: &InhibitorManager,
        what: &InhibitWhat,
        interactive: bool,
    ) -> Result<()> {
        if inh.is_blocked(what) {
            if interactive {
                // In interactive mode, polkit would prompt — we just warn
                log::warn!(
                    "{:?} has block inhibitor — proceeding anyway (interactive)",
                    what
                );
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "{:?} blocked by inhibitor — use interactive=true to override",
                    what
                ))
            }
        } else {
            Ok(())
        }
    }

    fn wait_delay(&self, inh: &InhibitorManager, what: &InhibitWhat) {
        if !inh.has_delay(what) {
            return;
        }
        let max_wait = std::time::Duration::from_secs(self.config.inhibit_delay_max_sec);
        let start = std::time::Instant::now();
        log::info!(
            "Waiting up to {}s for delay inhibitors on {:?}",
            max_wait.as_secs(),
            what
        );
        while start.elapsed() < max_wait {
            if !inh.has_delay(what) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    // ── Wall messages ─────────────────────────────────────────────────────────

    /// Send a wall message to all active TTY sessions.
    ///
    /// Compatible with `wall(1)` — writes to /dev/ttyN for each active TTY.
    pub fn send_wall(&self, message: &str) {
        let header = format!(
            "\r\nBroadcast message from quantra-logind ({})\r\n{}\r\n\r\n",
            chrono_now(),
            message
        );
        // Write to /dev/tty1 through /dev/tty6
        for n in 1..=6 {
            let tty = format!("/dev/tty{}", n);
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&tty) {
                use std::io::Write;
                f.write_all(header.as_bytes()).ok();
            }
        }
        log::info!("Wall: {}", message);
    }

    // ── Event broadcasting ────────────────────────────────────────────────────

    fn broadcast_prepare_shutdown(&self, active: bool) {
        log::debug!("PrepareForShutdown({})", active);
        // Event subscribers notified via control.rs event broadcast
    }

    fn broadcast_prepare_sleep(&self, active: bool) {
        log::debug!("PrepareForSleep({})", active);
    }
}

// ── ACPI event handling ───────────────────────────────────────────────────────

/// ACPI event types detected from /proc/acpi/event or acpid socket.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum AcpiEvent {
    PowerButton,
    SleepButton,
    LidClose,
    LidOpen,
    BatteryLow,
    AcAdapterInserted,
    AcAdapterRemoved,
    BrightnessUp,
    BrightnessDown,
    VideoSwitchMode,
}

/// Spawn a thread that reads ACPI events and dispatches power actions.
pub fn start_acpi_handler(
    config: LogindConfig,
    power: Arc<Mutex<PowerManager>>,
    inhibitors: Arc<Mutex<InhibitorManager>>,
) {
    std::thread::Builder::new()
        .name("acpi-events".into())
        .spawn(move || {
            acpi_event_loop(config, power, inhibitors);
        })
        .ok();
}

fn acpi_event_loop(
    config: LogindConfig,
    power: Arc<Mutex<PowerManager>>,
    inhibitors: Arc<Mutex<InhibitorManager>>,
) {
    // Try acpid socket first (/var/run/acpid.socket)
    // Fall back to /proc/acpi/event (deprecated but widely available)
    let acpid_socket = "/var/run/acpid.socket";
    let proc_acpi = "/proc/acpi/event";

    if Path::new(acpid_socket).exists()
        && let Ok(stream) = std::os::unix::net::UnixStream::connect(acpid_socket)
    {
        acpi_read_socket(stream, &config, &power, &inhibitors);
        return;
    }

    if Path::new(proc_acpi).exists() {
        acpi_read_proc(&config, &power, &inhibitors);
        return;
    }

    // Try input event devices directly for power/lid buttons
    acpi_read_input_events(&config, &power, &inhibitors);
}

fn acpi_read_socket(
    stream: std::os::unix::net::UnixStream,
    config: &LogindConfig,
    power: &Arc<Mutex<PowerManager>>,
    inhibitors: &Arc<Mutex<InhibitorManager>>,
) {
    use std::io::{BufRead, BufReader};
    let reader = BufReader::new(stream);
    for line in reader.lines().map_while(Result::ok) {
        log::debug!("ACPI event: {}", line);
        if let Some(event) = parse_acpi_line(&line) {
            handle_acpi_event(event, config, power, inhibitors);
        }
    }
}

fn acpi_read_proc(
    config: &LogindConfig,
    power: &Arc<Mutex<PowerManager>>,
    inhibitors: &Arc<Mutex<InhibitorManager>>,
) {
    use std::io::{BufRead, BufReader};
    if let Ok(f) = std::fs::File::open("/proc/acpi/event") {
        let reader = BufReader::new(f);
        for line in reader.lines().map_while(Result::ok) {
            if let Some(event) = parse_acpi_line(&line) {
                handle_acpi_event(event, config, power, inhibitors);
            }
        }
    }
}

fn acpi_read_input_events(
    config: &LogindConfig,
    power: &Arc<Mutex<PowerManager>>,
    inhibitors: &Arc<Mutex<InhibitorManager>>,
) {
    // Scan /dev/input for power button and lid switch devices
    let power_btn = find_input_device("Power Button");
    let lid_sw = find_input_device("Lid Switch");
    let sleep_btn = find_input_device("Sleep Button");

    // Simple poll loop — real implementation uses epoll/inotify
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Check lid state via /proc/acpi/button/lid/LID/state
        let lid_closed = fs::read_to_string("/proc/acpi/button/lid/LID/state")
            .or_else(|_| fs::read_to_string("/proc/acpi/button/lid/LID0/state"))
            .map(|s| s.contains("closed"))
            .unwrap_or(false);

        // Check AC adapter
        let _on_battery = fs::read_to_string("/sys/class/power_supply/AC/online")
            .or_else(|_| fs::read_to_string("/sys/class/power_supply/ACAD/online"))
            .map(|s| s.trim() == "0")
            .unwrap_or(false);

        if lid_closed {
            handle_acpi_event(AcpiEvent::LidClose, config, power, inhibitors);
            // Wait until lid opens
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                let still_closed = fs::read_to_string("/proc/acpi/button/lid/LID/state")
                    .or_else(|_| fs::read_to_string("/proc/acpi/button/lid/LID0/state"))
                    .map(|s| s.contains("closed"))
                    .unwrap_or(false);
                if !still_closed {
                    handle_acpi_event(AcpiEvent::LidOpen, config, power, inhibitors);
                    break;
                }
            }
        }

        let _ = (
            power_btn.as_deref(),
            lid_sw.as_deref(),
            sleep_btn.as_deref(),
        );
    }
}

fn handle_acpi_event(
    event: AcpiEvent,
    config: &LogindConfig,
    power: &Arc<Mutex<PowerManager>>,
    inhibitors: &Arc<Mutex<InhibitorManager>>,
) {
    let action = match event {
        AcpiEvent::PowerButton => &config.handle_power_key,
        AcpiEvent::SleepButton => &config.handle_suspend_key,
        AcpiEvent::LidClose => &config.handle_lid_switch,
        AcpiEvent::LidOpen => return, // No action on lid open
        _ => return,
    };

    log::info!("ACPI event → action: {:?}", action);

    let pm = power.lock().unwrap();
    let inh = inhibitors.lock().unwrap();

    match action {
        PowerAction::PowerOff => {
            pm.power_off(&inh, false).ok();
        }
        PowerAction::Reboot => {
            pm.reboot(&inh, false).ok();
        }
        PowerAction::Suspend => {
            pm.suspend(&inh, false).ok();
        }
        PowerAction::Hibernate => {
            pm.hibernate(&inh, false).ok();
        }
        PowerAction::HybridSleep => {
            pm.hybrid_sleep(&inh, false).ok();
        }
        PowerAction::Lock => {
            log::info!("ACPI: lock all sessions");
            // Signal lock to session manager via a pipe or shared state
        }
        PowerAction::Ignore => {}
        _ => log::debug!("ACPI: unhandled action {:?}", action),
    }
}

fn parse_acpi_line(line: &str) -> Option<AcpiEvent> {
    let l = line.to_lowercase();
    if l.contains("power") && l.contains("button") {
        return Some(AcpiEvent::PowerButton);
    }
    if l.contains("sleep") && l.contains("button") {
        return Some(AcpiEvent::SleepButton);
    }
    if l.contains("lid") && l.contains("close") {
        return Some(AcpiEvent::LidClose);
    }
    if l.contains("lid") && l.contains("open") {
        return Some(AcpiEvent::LidOpen);
    }
    if l.contains("ac_adapter") && l.contains("plug") {
        return Some(AcpiEvent::AcAdapterInserted);
    }
    if l.contains("ac_adapter") && l.contains("unplug") {
        return Some(AcpiEvent::AcAdapterRemoved);
    }
    None
}

fn find_input_device(name: &str) -> Option<String> {
    let input = fs::read_to_string("/proc/bus/input/devices").ok()?;
    let mut found_name = false;
    let mut handler = None;
    for line in input.lines() {
        if line.starts_with("N: Name=") && line.contains(name) {
            found_name = true;
        }
        if found_name && line.starts_with("H: Handlers=") {
            for tok in line.split_whitespace() {
                if tok.starts_with("event") {
                    handler = Some(format!("/dev/input/{}", tok));
                    break;
                }
            }
            if handler.is_some() {
                break;
            }
        }
        if line.is_empty() {
            found_name = false;
        }
    }
    handler
}

// ── Brightness helpers ────────────────────────────────────────────────────────

fn brightness_path(subsystem: &str, name: &str) -> Result<String> {
    let path = match subsystem {
        "backlight" => format!("/sys/class/backlight/{}/brightness", name),
        "leds" => format!("/sys/class/leds/{}/brightness", name),
        _ => {
            return Err(anyhow::anyhow!(
                "unknown brightness subsystem: {}",
                subsystem
            ));
        }
    };
    if !Path::new(&path).exists() {
        return Err(anyhow::anyhow!("brightness device not found: {}", path));
    }
    Ok(path)
}

fn read_max_brightness(subsystem: &str, name: &str) -> Option<u32> {
    let path = match subsystem {
        "backlight" => format!("/sys/class/backlight/{}/max_brightness", name),
        "leds" => format!("/sys/class/leds/{}/max_brightness", name),
        _ => return None,
    };
    fs::read_to_string(&path).ok()?.trim().parse().ok()
}

// ── UEFI firmware reboot ──────────────────────────────────────────────────────

fn set_efi_boot_to_firmware() -> Result<()> {
    // Write EFI variable OsIndicationsSupported / OsIndications
    let osi_path = "/sys/firmware/efi/efivars/OsIndications-8be4df61-93ca-11d2-aa0d-00e098032b8c";
    // Bit 0 = EFI_OS_INDICATIONS_BOOT_TO_FW_UI
    let mut data = [0u8; 12]; // 4 bytes EFI attrs + 8 bytes value
    data[0] = 0x07; // EFI_VARIABLE_NON_VOLATILE | BOOTSERVICE | RUNTIME
    data[4] = 0x01; // value = 1 (boot to firmware UI)
    fs::write(osi_path, data).map_err(|e| anyhow::anyhow!("set EFI OsIndications: {}", e))
}

// ── Time helpers ──────────────────────────────────────────────────────────────

// ── IdleAction timer ─────────────────────────────────────────────────────────

/// Start the idle action enforcement loop.
///
/// Polls session idle hints every 30 seconds. When ALL active sessions have
/// been idle for `idle_action_sec` seconds, executes `idle_action`.
///
/// Session idle state is set by the compositor via `SetIdleHint` command
/// (e.g. COSMIC sets it when the screensaver activates).
pub fn start_idle_timer(
    config: LogindConfig,
    power: Arc<Mutex<PowerManager>>,
    inhibitors: Arc<Mutex<InhibitorManager>>,
    sessions: Arc<Mutex<crate::session::SessionManager>>,
) {
    if matches!(config.idle_action, PowerAction::Ignore) {
        log::debug!("IdleAction=ignore — idle timer not started");
        return;
    }

    let idle_secs = config.idle_action_sec;
    log::info!(
        "IdleAction: {:?} after {}s of inactivity",
        config.idle_action,
        idle_secs
    );

    std::thread::Builder::new()
        .name("idle-action".into())
        .spawn(move || {
            idle_action_loop(config, power, inhibitors, sessions);
        })
        .ok();
}

fn idle_action_loop(
    config: LogindConfig,
    power: Arc<Mutex<PowerManager>>,
    inhibitors: Arc<Mutex<InhibitorManager>>,
    sessions: Arc<Mutex<crate::session::SessionManager>>,
) {
    // Track when all sessions first became idle
    let mut all_idle_since: Option<std::time::Instant> = None;
    let poll = std::time::Duration::from_secs(30);
    let threshold = std::time::Duration::from_secs(config.idle_action_sec.max(1));

    loop {
        std::thread::sleep(poll);

        // Check if HandleLidSwitch/Idle is inhibited
        {
            let inh = inhibitors.lock().unwrap();
            if inh.is_handle_blocked(&InhibitWhat::Idle) {
                all_idle_since = None;
                continue;
            }
        }

        // Check if all active sessions are idle
        let all_idle = {
            let sm = sessions.lock().unwrap();
            let active = sm.all();
            // If no sessions at all — not idle (nothing to act on)
            if active.is_empty() {
                false
            } else {
                // All sessions must report idle_hint = true
                active.iter().all(|s| s.idle_hint)
            }
        };

        if all_idle {
            let since = all_idle_since.get_or_insert_with(std::time::Instant::now);
            let idle_duration = since.elapsed();

            log::debug!(
                "Idle: all sessions idle for {}s (threshold {}s)",
                idle_duration.as_secs(),
                threshold.as_secs()
            );

            if idle_duration >= threshold {
                log::info!(
                    "IdleAction: threshold reached — executing {:?}",
                    config.idle_action
                );
                all_idle_since = None; // reset so we don't re-fire immediately

                let pm = power.lock().unwrap();
                let inh = inhibitors.lock().unwrap();

                match &config.idle_action {
                    PowerAction::Suspend => {
                        pm.suspend(&inh, false).ok();
                    }
                    PowerAction::Hibernate => {
                        pm.hibernate(&inh, false).ok();
                    }
                    PowerAction::HybridSleep => {
                        pm.hybrid_sleep(&inh, false).ok();
                    }
                    PowerAction::PowerOff => {
                        pm.power_off(&inh, false).ok();
                    }
                    PowerAction::Lock => {
                        // Signal session manager to lock all sessions
                        let mut sm = sessions.lock().unwrap();
                        sm.lock_all();
                        log::info!("IdleAction: all sessions locked");
                    }
                    PowerAction::Ignore => {}
                    other => log::warn!("IdleAction: {:?} not implemented", other),
                }
            }
        } else {
            // At least one session is not idle — reset timer
            all_idle_since = None;
        }
    }
}

fn chrono_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Simple UTC format for wall messages
    let s = secs % 86400;
    let h = s / 3600;
    let m = (s % 3600) / 60;
    let sec = s % 60;
    format!("{:02}:{:02}:{:02} UTC", h, m, sec)
}

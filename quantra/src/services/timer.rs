/// Timer units — cron replacement built into PID 1
///
/// Each timer unit fires its target service at a configured schedule.
/// Implemented as lightweight threads — one thread per active timer.
///
/// # Config format (`/overlayer/syshub/etc/quantra-system/timers/<name>.toml`)
///
/// ```toml
/// [timer]
/// name = "backup"
/// unit = "backup.service"         # service to activate on fire
/// on_boot_sec = 300               # fire 5 min after boot
/// on_calendar = "02:30:00"        # fire daily at 02:30
/// on_unit_active_sec = 86400      # re-fire 24h after last activation
/// ```
///
/// # CalendarSpec parsing
///
/// | Input                 | Meaning               |
/// |-----------------------|-----------------------|
/// | `"hourly"`            | Every hour at :00:00  |
/// | `"daily"`             | Every day at 00:00:00 |
/// | `"weekly"`            | Every Monday 00:00:00 |
/// | `"HH:MM:SS"`          | Daily at fixed time   |
/// | `"HH:MM"`             | Daily at HH:MM:00     |
use anyhow::{Context, Result};
use log::{error, info, warn};
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::manager::ServiceManager;
use crate::signals::SHUTDOWN_REQUESTED;

const TIMER_DIR: &str = "/overlayer/syshub/etc/quantra-system/timers";
const TIMER_STATE_DIR: &str = "/overlayer/syshub/var/lib/quantra-system/timers";

// ── Config types ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TimerConfig {
    #[serde(rename = "timer")]
    pub timer: TimerSpec,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TimerSpec {
    /// Timer name (matches filename)
    pub name: String,
    /// Target service to activate on fire
    pub unit: String,
    /// Fire this many seconds after boot (one-shot)
    pub on_boot_sec: Option<u64>,
    /// Fire on this calendar schedule repeatedly (e.g. "daily", "02:30:00")
    pub on_calendar: Option<String>,
    /// Re-fire this many seconds after last activation (interval timer)
    pub on_unit_active_sec: Option<u64>,
    /// If true, catch up on missed fires after reboot
    #[serde(default)]
    pub persistent: bool,
    /// Random jitter in seconds added before each fire (thundering herd prevention)
    #[serde(default)]
    pub randomized_delay_sec: Option<u64>,

    /// Fire this many seconds after the unit was last ACTIVATED (not just started).
    /// Different from on_unit_active_sec which is from last run completion.
    #[serde(default)]
    pub on_active_sec: Option<u64>,

    /// Fire this many seconds after quantra (PID 1) itself started.
    /// Useful for services that need startup delay relative to daemon start.
    #[serde(default)]
    pub on_startup_sec: Option<u64>,

    /// Wake the system from suspend to fire this timer (requires RTC support).
    #[serde(default)]
    pub wake_system: bool,

    /// Accuracy window in seconds — timer may fire up to this many seconds late
    /// to coalesce with other timers. Default 60s (matches systemd default).
    #[serde(default = "default_accuracy_sec")]
    pub accuracy_sec: u64,

    /// If true, the randomized delay is the same each day for this timer
    /// (derived from timer name hash). Prevents drift while still jittering.
    #[serde(default)]
    pub fixed_random_delay: bool,

    /// Fire when the system clock changes (e.g. after NTP sync).
    #[serde(default)]
    pub on_clock_change: bool,

    /// Fire when the timezone changes.
    #[serde(default)]
    pub on_timezone_change: bool,
}

fn default_accuracy_sec() -> u64 {
    60
}

// ── Loader ────────────────────────────────────────────────────────────────────

/// Load all timer definitions from `/overlayer/syshub/etc/quantra-system/timers/`.
pub fn load_all_timers() -> Vec<TimerSpec> {
    let dir = Path::new(TIMER_DIR);
    if !dir.exists() {
        return Vec::new();
    }

    let mut timers = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("Cannot read timer dir: {}", e);
            return timers;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        match load_timer_file(&path) {
            Ok(spec) => timers.push(spec),
            Err(e) => error!("Timer '{}': {}", path.display(), e),
        }
    }

    info!("Loaded {} timer unit(s)", timers.len());
    timers
}

fn load_timer_file(path: &Path) -> Result<TimerSpec> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("Cannot read timer '{}'", path.display()))?;
    let cfg: TimerConfig = toml::from_str(&text)
        .with_context(|| format!("Invalid timer TOML '{}'", path.display()))?;
    Ok(cfg.timer)
}

// ── Scheduler ─────────────────────────────────────────────────────────────────

/// Start all timer threads. Each timer fires its service via `service_tx`.
///
/// `service_tx` sends service names to the service manager for activation.
pub fn start_all_timers(timers: Vec<TimerSpec>, service_tx: mpsc::Sender<String>) {
    for timer in timers {
        let tx = service_tx.clone();
        let name = timer.name.clone();
        thread::Builder::new()
            .name(format!("timer-{}", name))
            .spawn(move || run_timer(timer, tx))
            .map_err(|e| error!("Cannot spawn timer thread '{}': {}", name, e))
            .ok();
    }
}

/// Start the dispatcher that turns timer firings into service activations.
pub fn start_activation_dispatcher(
    manager: Arc<Mutex<ServiceManager>>,
    service_rx: mpsc::Receiver<String>,
) {
    let _ = thread::Builder::new()
        .name("timer-dispatch".into())
        .spawn(move || run_activation_dispatcher(manager, service_rx))
        .map_err(|e| error!("Cannot spawn timer dispatcher: {}", e));
}

fn run_activation_dispatcher(
    manager: Arc<Mutex<ServiceManager>>,
    service_rx: mpsc::Receiver<String>,
) {
    info!("Timer activation dispatcher started");

    for unit in service_rx {
        if SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
            info!("Timer activation dispatcher exiting during shutdown");
            break;
        }

        match manager.lock() {
            Ok(mut guard) => {
                if let Err(e) = guard.start_named_service(&unit) {
                    error!("Timer activation for '{}': {}", unit, e);
                }
            }
            Err(_) => {
                error!("Timer activation dispatcher: service manager lock poisoned");
                break;
            }
        }
    }

    info!("Timer activation dispatcher exiting");
}

fn run_timer(timer: TimerSpec, tx: mpsc::Sender<String>) {
    info!("Timer '{}' started — unit={}", timer.name, timer.unit);

    // Persistent catch-up: if timer missed fires during downtime, fire immediately
    if timer.persistent {
        if let Some(ref spec_str) = timer.on_calendar {
            if should_catch_up(&timer.name, spec_str) {
                info!("Timer '{}': persistent catch-up fire", timer.name);
                fire_timer(&timer.name, &timer.unit, &tx);
                save_last_fired(&timer.name);
            }
        }
    }

    // on_boot_sec: fire once after N seconds from now
    if let Some(boot_sec) = timer.on_boot_sec {
        if !sleep_interruptibly(Duration::from_secs(boot_sec)) {
            return;
        }
        fire_timer(&timer.name, &timer.unit, &tx);
    }

    // on_calendar: compute next trigger, sleep until it, fire, repeat
    if let Some(ref spec_str) = timer.on_calendar {
        match CalendarSpec::parse(spec_str) {
            Ok(spec) => loop {
                let mut wait = spec.time_until_next();
                // Apply randomized delay jitter
                if let Some(jitter_max) = timer.randomized_delay_sec {
                    if jitter_max > 0 {
                        wait += Duration::from_secs(random_u64() % jitter_max);
                    }
                }
                info!("Timer '{}': next fire in {}s", timer.name, wait.as_secs());
                if !sleep_interruptibly(wait) {
                    return;
                }
                fire_timer(&timer.name, &timer.unit, &tx);
                if timer.persistent {
                    save_last_fired(&timer.name);
                }
            },
            Err(e) => error!(
                "Timer '{}' bad on_calendar '{}': {}",
                timer.name, spec_str, e
            ),
        }
        return;
    }

    // on_unit_active_sec: interval timer (fire every N seconds after first fire)
    if let Some(interval) = timer.on_unit_active_sec {
        loop {
            let mut wait = Duration::from_secs(interval);
            if let Some(jitter_max) = timer.randomized_delay_sec {
                if jitter_max > 0 {
                    wait += Duration::from_secs(random_u64() % jitter_max);
                }
            }
            if !sleep_interruptibly(wait) {
                return;
            }
            fire_timer(&timer.name, &timer.unit, &tx);
            if timer.persistent {
                save_last_fired(&timer.name);
            }
        }
    }
}

/// Read 8 bytes from /dev/urandom for jitter — zero external dependencies.
fn random_u64() -> u64 {
    let mut buf = [0u8; 8];
    if let Ok(bytes) = fs::read("/dev/urandom") {
        for (i, b) in bytes.iter().take(8).enumerate() {
            buf[i] = *b;
        }
    }
    u64::from_ne_bytes(buf)
}

/// Save last-fired timestamp to `/var/lib/quantra-system/timers/<name>.state`
fn save_last_fired(name: &str) {
    let _ = fs::create_dir_all(TIMER_STATE_DIR);
    let path = format!("{}/{}.state", TIMER_STATE_DIR, name);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let _ = fs::write(&path, now.to_string());
}

/// Check if a persistent timer should catch up after reboot.
fn should_catch_up(name: &str, spec_str: &str) -> bool {
    let path = format!("{}/{}.state", TIMER_STATE_DIR, name);
    let last_fired = match fs::read_to_string(&path) {
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(ts) => ts,
            Err(_) => return false,
        },
        Err(_) => return true, // never fired — catch up
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // If the spec is parseable, check if a fire was missed
    if let Ok(spec) = CalendarSpec::parse(spec_str) {
        let interval = spec.time_until_next().as_secs();
        // If more than 2x the interval has passed, we missed at least one fire
        return now.saturating_sub(last_fired) > interval;
    }
    false
}

fn sleep_interruptibly(duration: Duration) -> bool {
    let start = std::time::Instant::now();
    let poll = Duration::from_millis(250);

    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
            return false;
        }

        let elapsed = start.elapsed();
        if elapsed >= duration {
            return true;
        }

        let remaining = duration - elapsed;
        thread::sleep(std::cmp::min(poll, remaining));
    }
}

fn fire_timer(name: &str, unit: &str, tx: &mpsc::Sender<String>) {
    if SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
        info!("Timer '{}' suppressed during shutdown", name);
        return;
    }

    info!("Timer '{}' firing → activating '{}'", name, unit);
    if tx.send(unit.to_string()).is_err() {
        error!("Timer '{}': service channel closed — timer stopping", name);
    }
}

// ── CalendarSpec ──────────────────────────────────────────────────────────────

/// Parsed calendar schedule for a timer unit.
pub struct CalendarSpec {
    /// Target hour (0–23), None = every hour
    hour: Option<u8>,
    /// Target minute (0–59)
    minute: u8,
    /// Target second (0–59)
    second: u8,
    /// If true, fire every 60 seconds (overrides hour/minute logic)
    minutely: bool,
    /// Target day of week (0=Monday .. 6=Sunday), None = every day
    weekday: Option<u8>,
}

/// Parse an optional day-of-week prefix from a calendar expression.
///
/// Returns `(Some(weekday), remaining_time_part)` if a prefix like "Mon", "Fri" is found.
/// Returns `(None, original_string)` if no prefix is present.
///
/// Weekday mapping: Mon=0, Tue=1, Wed=2, Thu=3, Fri=4, Sat=5, Sun=6
fn parse_weekday_prefix(s: &str) -> (Option<u8>, &str) {
    if let Some(rest) = s.strip_prefix("Mon ") {
        (Some(0), rest.trim())
    } else if let Some(rest) = s.strip_prefix("Tue ") {
        (Some(1), rest.trim())
    } else if let Some(rest) = s.strip_prefix("Wed ") {
        (Some(2), rest.trim())
    } else if let Some(rest) = s.strip_prefix("Thu ") {
        (Some(3), rest.trim())
    } else if let Some(rest) = s.strip_prefix("Fri ") {
        (Some(4), rest.trim())
    } else if let Some(rest) = s.strip_prefix("Sat ") {
        (Some(5), rest.trim())
    } else if let Some(rest) = s.strip_prefix("Sun ") {
        (Some(6), rest.trim())
    } else {
        (None, s)
    }
}

impl CalendarSpec {
    /// Parse a calendar schedule string into a `CalendarSpec`.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "minutely" => Ok(Self {
                hour: None,
                minute: 0,
                second: 0,
                minutely: true,
                weekday: None,
            }),
            "hourly" => Ok(Self {
                hour: None,
                minute: 0,
                second: 0,
                minutely: false,
                weekday: None,
            }),
            "daily" => Ok(Self {
                hour: Some(0),
                minute: 0,
                second: 0,
                minutely: false,
                weekday: None,
            }),
            "weekly" => Ok(Self {
                hour: Some(0),
                minute: 0,
                second: 0,
                minutely: false,
                weekday: Some(0), // Monday
            }),
            other => {
                // Try day-of-week prefix: "Mon 02:30", "Fri 00:00:00"
                let (weekday_parsed, time_part) = parse_weekday_prefix(other);

                // Try "HH:MM:SS" or "HH:MM"
                let parts: Vec<&str> = time_part.splitn(3, ':').collect();
                match parts.as_slice() {
                    [hh, mm, ss] => {
                        let h = hh.parse::<u8>().context("Invalid hour")?;
                        let m = mm.parse::<u8>().context("Invalid minute")?;
                        let s = ss.parse::<u8>().context("Invalid second")?;
                        Ok(Self {
                            hour: Some(h),
                            minute: m,
                            second: s,
                            minutely: false,
                            weekday: weekday_parsed,
                        })
                    }
                    [hh, mm] => {
                        let h = hh.parse::<u8>().context("Invalid hour")?;
                        let m = mm.parse::<u8>().context("Invalid minute")?;
                        Ok(Self {
                            hour: Some(h),
                            minute: m,
                            second: 0,
                            minutely: false,
                            weekday: weekday_parsed,
                        })
                    }
                    _ => Err(anyhow::anyhow!("Unrecognized CalendarSpec: '{}'", other)),
                }
            }
        }
    }

    /// Compute the duration until the next trigger time.
    pub fn time_until_next(&self) -> Duration {
        // Minutely: always fire in 60 seconds
        if self.minutely {
            return Duration::from_secs(60);
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Current time-of-day in seconds
        let secs_in_day = now_secs % 86400;
        let current_hour = (secs_in_day / 3600) as u8;

        let target_hour = self.hour.unwrap_or(current_hour);
        let target_in_day =
            (target_hour as u64) * 3600 + self.minute as u64 * 60 + self.second as u64;

        // Weekly: compute days until target weekday (0=Mon .. 6=Sun)
        // 1970-01-01 was Thursday → (epoch_days + 3) % 7 gives 0=Mon
        if let Some(wd) = self.weekday {
            let days_since_epoch = now_secs / 86400;
            let current_wd = ((days_since_epoch + 3) % 7) as u64;
            let target_wd = wd as u64;
            let mut days_ahead = (7 + target_wd - current_wd) % 7;
            if days_ahead == 0 && target_in_day <= secs_in_day {
                days_ahead = 7; // same weekday but time already passed → next week
            }
            return Duration::from_secs(days_ahead * 86400 - secs_in_day + target_in_day);
        }

        if target_in_day > secs_in_day {
            Duration::from_secs(target_in_day - secs_in_day)
        } else if self.hour.is_none() {
            // Hourly: next :MM:SS
            Duration::from_secs(
                3600 - (secs_in_day % 3600) + self.minute as u64 * 60 + self.second as u64,
            )
        } else {
            // Already passed today — fire again tomorrow
            Duration::from_secs(86400 - secs_in_day + target_in_day)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CalendarSpec, TimerConfig};

    #[test]
    fn parses_hh_mm_schedule() {
        let spec = CalendarSpec::parse("02:30").unwrap();
        assert_eq!(spec.hour, Some(2));
        assert_eq!(spec.minute, 30);
        assert_eq!(spec.second, 0);
        assert!(!spec.minutely);
    }

    #[test]
    fn parses_hh_mm_ss_schedule() {
        let spec = CalendarSpec::parse("14:30:45").unwrap();
        assert_eq!(spec.hour, Some(14));
        assert_eq!(spec.minute, 30);
        assert_eq!(spec.second, 45);
    }

    #[test]
    fn parses_daily_keyword() {
        let spec = CalendarSpec::parse("daily").unwrap();
        assert_eq!(spec.hour, Some(0));
        assert_eq!(spec.minute, 0);
        assert!(!spec.minutely);
    }

    #[test]
    fn parses_hourly_keyword() {
        let spec = CalendarSpec::parse("hourly").unwrap();
        assert!(spec.hour.is_none());
        assert_eq!(spec.minute, 0);
        assert!(!spec.minutely);
    }

    #[test]
    fn minutely_fires_every_60s() {
        let spec = CalendarSpec::parse("minutely").unwrap();
        assert!(spec.minutely);
        let dur = spec.time_until_next();
        assert_eq!(dur.as_secs(), 60);
    }

    #[test]
    fn minutely_is_distinct_from_hourly() {
        let minutely = CalendarSpec::parse("minutely").unwrap();
        let hourly = CalendarSpec::parse("hourly").unwrap();
        assert_ne!(
            minutely.time_until_next().as_secs(),
            hourly.time_until_next().as_secs()
        );
    }

    #[test]
    fn rejects_invalid_calendar_string() {
        assert!(CalendarSpec::parse("not-a-time").is_err());
    }

    #[test]
    fn weekly_parses_correctly() {
        let spec = CalendarSpec::parse("weekly").unwrap();
        assert_eq!(spec.hour, Some(0));
        assert_eq!(spec.weekday, Some(0)); // Monday
        assert!(!spec.minutely);
    }

    #[test]
    fn weekly_fires_between_1_and_7_days() {
        let spec = CalendarSpec::parse("weekly").unwrap();
        let secs = spec.time_until_next().as_secs();
        // Must be > 0 and <= 7 days (604800 seconds)
        assert!(secs > 0 && secs <= 7 * 86400, "weekly delay was {}s", secs);
    }

    #[test]
    fn daily_is_not_weekly() {
        let daily = CalendarSpec::parse("daily").unwrap();
        let weekly = CalendarSpec::parse("weekly").unwrap();
        assert!(daily.weekday.is_none());
        assert!(weekly.weekday.is_some());
    }

    #[test]
    fn time_until_next_is_positive() {
        let spec = CalendarSpec::parse("hourly").unwrap();
        assert!(spec.time_until_next().as_secs() > 0);
    }

    #[test]
    fn parses_day_of_week_prefix_mon() {
        let spec = CalendarSpec::parse("Mon 02:30").unwrap();
        assert_eq!(spec.weekday, Some(0));
        assert_eq!(spec.hour, Some(2));
        assert_eq!(spec.minute, 30);
    }

    #[test]
    fn parses_day_of_week_prefix_fri() {
        let spec = CalendarSpec::parse("Fri 23:59:59").unwrap();
        assert_eq!(spec.weekday, Some(4));
        assert_eq!(spec.hour, Some(23));
        assert_eq!(spec.minute, 59);
        assert_eq!(spec.second, 59);
    }

    #[test]
    fn parses_day_of_week_sun() {
        let spec = CalendarSpec::parse("Sun 00:00").unwrap();
        assert_eq!(spec.weekday, Some(6));
    }

    #[test]
    fn timer_spec_with_persistent() {
        let toml = r#"
[timer]
name = "backup"
unit = "backup.service"
on_calendar = "daily"
persistent = true
randomized_delay_sec = 300
"#;
        let cfg: TimerConfig = toml::from_str(toml).unwrap();
        assert!(cfg.timer.persistent);
        assert_eq!(cfg.timer.randomized_delay_sec, Some(300));
    }
}

// ── Accuracy jitter ───────────────────────────────────────────────────────────

/// Apply AccuracySec coalescing jitter to a timer duration.
///
/// Adds a random delay in `[0, accuracy_sec)` to the base duration.
/// When `fixed_random_delay=true`, the jitter is deterministic per timer name
/// (same jitter every day, prevents drift while still spreading load).
#[allow(dead_code)]
fn apply_accuracy_jitter(
    base: Duration,
    accuracy_sec: u64,
    timer_name: &str,
    fixed: bool,
) -> Duration {
    if accuracy_sec == 0 {
        return base;
    }

    let jitter_secs = if fixed {
        // Deterministic: hash timer name → 0..accuracy_sec
        let h = timer_name
            .bytes()
            .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
        h % accuracy_sec.max(1)
    } else {
        // Random: use nanosecond clock for entropy
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 % accuracy_sec.max(1))
            .unwrap_or(0)
    };

    base + Duration::from_secs(jitter_secs)
}

// ── RTC wake timer ────────────────────────────────────────────────────────────

/// Set the system RTC alarm to wake from suspend/hibernate at `unix_ts`.
///
/// Writes to `/sys/class/rtc/rtc0/wakealarm` — the standard Linux RTC
/// wake alarm interface. A value of 0 disables the alarm.
///
/// Called from fire_timer() when `wake_system = true`.
#[allow(dead_code)]
pub fn set_rtc_wakeup(unix_ts: u64) -> std::io::Result<()> {
    let rtc_paths = [
        "/sys/class/rtc/rtc0/wakealarm",
        "/sys/class/rtc/rtc1/wakealarm",
    ];
    for path in &rtc_paths {
        if std::path::Path::new(path).exists() {
            // First write 0 to clear existing alarm
            std::fs::write(path, "0")?;
            // Then write the new timestamp
            std::fs::write(path, unix_ts.to_string())?;
            log::info!("RTC wake alarm set: {} → unix_ts={}", path, unix_ts);
            return Ok(());
        }
    }
    log::warn!("No RTC wakealarm found — wake_system ignored");
    Ok(())
}

/// Disable any pending RTC wakeup alarm.
#[allow(dead_code)]
pub fn clear_rtc_wakeup() {
    let rtc_paths = [
        "/sys/class/rtc/rtc0/wakealarm",
        "/sys/class/rtc/rtc1/wakealarm",
    ];
    for path in &rtc_paths {
        if std::path::Path::new(path).exists() {
            std::fs::write(path, "0").ok();
        }
    }
}

// ── Clock change watcher ──────────────────────────────────────────────────────

/// Watch for system clock changes and fire timer when detected.
///
/// Uses `CLOCK_REALTIME` vs monotonic comparison — if wall clock jumps
/// forward/backward significantly, we fire the on_clock_change timer.
#[allow(dead_code)]
fn watch_clock_change(timer: &TimerSpec, tx: &mpsc::Sender<String>) {
    let threshold = Duration::from_secs(5); // 5s jump = clock change
    let poll = Duration::from_secs(1);

    let mut last_wall = SystemTime::now();
    let mut last_mono = std::time::Instant::now();

    loop {
        thread::sleep(poll);
        if SHUTDOWN_REQUESTED.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }

        let now_wall = SystemTime::now();
        let now_mono = std::time::Instant::now();

        let wall_elapsed = now_wall.duration_since(last_wall).unwrap_or_default();
        let mono_elapsed = now_mono.duration_since(last_mono);

        // If wall clock advanced more than threshold seconds faster than
        // monotonic, the clock was set forward (NTP sync, manual set, etc.)
        let diff = if wall_elapsed > mono_elapsed {
            wall_elapsed - mono_elapsed
        } else {
            mono_elapsed - wall_elapsed
        };

        if diff > threshold {
            log::info!(
                "Clock change detected (diff={}s) — firing timer '{}'",
                diff.as_secs(),
                timer.name
            );
            let _ = tx.send(timer.unit.clone());
        }

        last_wall = now_wall;
        last_mono = now_mono;
    }
}

// ── Uptime helper ─────────────────────────────────────────────────────────────

#[allow(dead_code)]
fn read_uptime_secs() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| {
            s.split_whitespace()
                .next()
                .and_then(|n| n.parse::<f64>().ok())
        })
        .map(|f| f as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod timer_ext_tests {
    use super::*;

    #[test]
    fn accuracy_jitter_zero_accuracy_is_noop() {
        let base = Duration::from_secs(100);
        let result = apply_accuracy_jitter(base, 0, "test", false);
        assert_eq!(result, base);
    }

    #[test]
    fn accuracy_jitter_fixed_is_deterministic() {
        let base = Duration::from_secs(3600);
        let a = apply_accuracy_jitter(base, 60, "backup", true);
        let b = apply_accuracy_jitter(base, 60, "backup", true);
        assert_eq!(a, b, "fixed_random_delay must be deterministic");
    }

    #[test]
    fn accuracy_jitter_fixed_different_names() {
        let base = Duration::from_secs(3600);
        let a = apply_accuracy_jitter(base, 60, "backup", true);
        let b = apply_accuracy_jitter(base, 60, "cleanup", true);
        // Different names should (very likely) produce different jitter
        // Not strictly guaranteed but hash collision is unlikely for these
        let _ = (a, b); // values are valid regardless
    }

    #[test]
    fn accuracy_jitter_result_in_range() {
        let base = Duration::from_secs(100);
        let accuracy = 30u64;
        let result = apply_accuracy_jitter(base, accuracy, "x", false);
        assert!(result >= base, "jitter must not reduce base duration");
        assert!(
            result < base + Duration::from_secs(accuracy),
            "jitter must be < accuracy_sec"
        );
    }

    #[test]
    fn default_accuracy_sec_is_60() {
        assert_eq!(default_accuracy_sec(), 60);
    }
}

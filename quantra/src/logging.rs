use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use log::{LevelFilter, Log, Metadata, Record};

use crate::config::InitConfig;

/// Log output format.
#[derive(Debug, Clone, PartialEq)]
pub enum LogFormat {
    /// `[LEVEL] target: message\n` — human-readable
    Plain,
    /// `{"ts":"...","level":"...","target":"...","msg":"..."}\n` — machine-parseable
    /// Parseable by Grafana Loki, ELK, journald compat tools.
    Json,
}

/// Zainium Boot Logger
///
/// Writes structured log entries to stderr (always) and optionally to a log file.
/// Supports both plain-text and JSON output format (Phase 5A).
///
/// # Plain format (default)
/// `[LEVEL] module: message`
///
/// # JSON format (set `logging.format = "json"` in init.toml)
/// `{"ts":"2026-04-27T00:00:00Z","level":"INFO","target":"quantra::services","msg":"..."}`
struct ZaiLogger {
    file: Option<Mutex<File>>,
    format: LogFormat,
}

impl Log for ZaiLogger {
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let line = match self.format {
            LogFormat::Plain => {
                format!(
                    "[{}] {}: {}\n",
                    record.level(),
                    record.target(),
                    record.args()
                )
            }
            LogFormat::Json => {
                // Produce RFC 3339 timestamp (seconds precision, UTC)
                let ts = rfc3339_now();
                // Escape the message string for JSON safety
                let msg = format!("{}", record.args())
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', "\\n")
                    .replace('\r', "\\r");
                format!(
                    "{{\"ts\":\"{}\",\"level\":\"{}\",\"target\":\"{}\",\"msg\":\"{}\"}}\n",
                    ts,
                    record.level(),
                    record.target(),
                    msg,
                )
            }
        };

        // Always write to stderr (guaranteed output even before /var is mounted)
        let _ = std::io::stderr().write_all(line.as_bytes());

        // Also write to log file if one is open
        if let Some(ref mtx) = self.file
            && let Ok(mut f) = mtx.lock()
        {
            let _ = f.write_all(line.as_bytes());
        }
    }

    fn flush(&self) {
        if let Some(ref mtx) = self.file
            && let Ok(mut f) = mtx.lock()
        {
            let _ = f.flush();
        }
    }
}

/// **Y2100 NOTE:** Manual calendar math below is valid through 2099.
/// The leap-year check `(year % 100 != 0) || (year % 400 == 0)` correctly
/// handles century boundaries, but the overall day-counting algorithm has
/// not been validated beyond 2100. Schedule review before next century.
///
/// Build an RFC 3339 UTC timestamp string (seconds precision).
/// No external crate required — computes from UNIX_EPOCH.
fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Convert unix timestamp to calendar date/time (Gregorian calendar, UTC)
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;

    // Approximate year/month/day from days since epoch (good until 2100)
    let mut year = 1970u64;
    let mut remaining_days = days;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }
    let month_days: [u64; 12] = [
        31,
        if is_leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for &md in &month_days {
        if remaining_days < md {
            break;
        }
        remaining_days -= md;
        month += 1;
    }
    let day = remaining_days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, h, m, s
    )
}

#[inline]
fn is_leap(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Initialise the global logger and connect it to stderr + optional log file.
///
/// MUST be called before any `log::*` macro. After this returns, all log output
/// is routed to stderr and (if configured) to `cfg.logging.file`.
///
/// Set `logging.format = "json"` in `/overlayer/syshub/etc/quantra-system/init.toml` to switch to
/// machine-readable JSON output (Grafana Loki / ELK compatible).
#[inline]
pub fn setup(cfg: &InitConfig) -> Result<(), Box<dyn std::error::Error>> {
    let format = match cfg.logging.format.as_deref().unwrap_or("plain") {
        "json" => LogFormat::Json,
        _ => LogFormat::Plain,
    };

    // Open the log file if a path is configured and non-empty
    let log_file = if !cfg.logging.file.is_empty() {
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&cfg.logging.file)
        {
            Ok(f) => Some(Mutex::new(f)),
            Err(e) => {
                eprintln!(
                    "[WARN] Cannot open log file '{}': {} — stderr only",
                    cfg.logging.file, e
                );
                None
            }
        }
    } else {
        None
    };

    let logger = Box::new(ZaiLogger {
        file: log_file,
        format,
    });

    // Register as the global logger — this activates all log::* macros
    log::set_boxed_logger(logger)?;
    log::set_max_level(LevelFilter::Debug);

    log::info!("Zainium logger initialized (stderr + file logging active)");
    Ok(())
}

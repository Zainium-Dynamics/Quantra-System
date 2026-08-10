/// quantra-journald — Structured log aggregator
///
/// Collects service logs from per-service pipes and writes structured
/// JSON-line records to `/var/log/quantra-system/journal.jsonl`.
///
/// # Log record format (JSON Lines)
/// ```json
/// {"ts":1720000000,"unit":"nginx","pid":1234,"priority":6,"msg":"Started"}
/// ```
///
/// # Priority levels (syslog compatible)
/// 0=EMERG 1=ALERT 2=CRIT 3=ERR 4=WARN 5=NOTICE 6=INFO 7=DEBUG
///
/// # Journal file
/// `/var/log/quantra-system/journal.jsonl` — append-only, rotated at 50MB.
/// Symlink `/run/quantra-system/journal` → current journal file.
///
/// # sd_journal_sendv compat
/// Services that call `sd_journal_sendv()` send to JOURNAL_STREAM socket.
/// This module listens on `/run/quantra-system/journal.socket`.
///
/// # Log query via control socket
/// `quantra-ctl logs <service> [--lines N] [--since N]` sends `Logs` command
/// to control socket which calls `journal::query()`.
use anyhow::{Context, Result};
use log::warn;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const JOURNAL_PATH: &str = "/overlayer/syshub/var/log/quantra-system/journal.jsonl";
const JOURNAL_SOCKET: &str = "/run/quantra-system/journal.socket";
const MAX_JOURNAL_BYTES: u64 = 50 * 1024 * 1024; // 50 MB rotation threshold

/// Priority levels — syslog compatible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl Priority {
    #[allow(dead_code)]
    pub fn from_prefix(line: &str) -> (Self, &str) {
        // Syslog-style prefix: <N> where N is priority (0-7)
        if line.starts_with('<') {
            if let Some(end) = line.find('>') {
                if let Ok(n) = line[1..end].parse::<u8>() {
                    let rest = &line[end + 1..];
                    return (Self::from_u8(n & 7), rest);
                }
            }
        }
        // Keyword prefixes
        if line.starts_with("ERROR") || line.starts_with("ERRO") || line.starts_with("[error]") {
            return (Self::Error, line);
        }
        if line.starts_with("WARN") || line.starts_with("[warn]") {
            return (Self::Warning, line);
        }
        if line.starts_with("DEBUG") || line.starts_with("[debug]") {
            return (Self::Debug, line);
        }
        (Self::Info, line)
    }

    fn from_u8(n: u8) -> Self {
        match n {
            0 => Self::Emergency,
            1 => Self::Alert,
            2 => Self::Critical,
            3 => Self::Error,
            4 => Self::Warning,
            5 => Self::Notice,
            6 => Self::Info,
            _ => Self::Debug,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Emergency => "EMERG",
            Self::Alert => "ALERT",
            Self::Critical => "CRIT",
            Self::Error => "ERR",
            Self::Warning => "WARN",
            Self::Notice => "NOTICE",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
        }
    }
}

/// A single structured log entry.
#[derive(Debug)]
pub struct JournalEntry {
    pub timestamp_us: u64,
    pub unit: String,
    pub pid: i32,
    pub priority: Priority,
    pub message: String,
}

impl JournalEntry {
    pub fn to_json_line(&self) -> String {
        // Escape message for JSON
        let msg = self
            .message
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r");

        format!(
            "{{\"ts\":{},\"unit\":\"{}\",\"pid\":{},\"priority\":{},\"level\":\"{}\",\"msg\":\"{}\"}}\n",
            self.timestamp_us / 1_000_000,
            self.unit,
            self.pid,
            self.priority as u8,
            self.priority.as_str(),
            msg,
        )
    }
}

/// Thread-safe journal writer.
#[derive(Clone)]
pub struct JournalWriter {
    path: Arc<String>,
    lock: Arc<Mutex<()>>,
}

impl JournalWriter {
    pub fn new() -> Result<Self> {
        fs::create_dir_all(Path::new(JOURNAL_PATH).parent().unwrap())
            .context("create journal dir")?;

        Ok(Self {
            path: Arc::new(JOURNAL_PATH.to_string()),
            lock: Arc::new(Mutex::new(())),
        })
    }

    /// Write a log entry to the journal file.
    pub fn write(&self, entry: &JournalEntry) -> Result<()> {
        let _guard = self.lock.lock().unwrap();

        // Rotate if over size limit
        if let Ok(meta) = fs::metadata(self.path.as_str()) {
            if meta.len() > MAX_JOURNAL_BYTES {
                self.rotate()?;
            }
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path.as_str())
            .context("open journal file")?;

        file.write_all(entry.to_json_line().as_bytes())
            .context("write journal entry")?;

        Ok(())
    }

    fn rotate(&self) -> Result<()> {
        let ts = unix_micros() / 1_000_000;
        let rotated = format!("{}.{}", self.path, ts);
        fs::rename(self.path.as_str(), &rotated).context("rotate journal file")?;
        log::info!("journald: rotated → {}", rotated);
        Ok(())
    }

    /// Log a line from a service pipe (called by logger threads).
    #[allow(dead_code)]
    pub fn log_line(&self, unit: &str, pid: i32, line: &str) {
        let (priority, msg) = Priority::from_prefix(line);
        let entry = JournalEntry {
            timestamp_us: unix_micros(),
            unit: unit.to_string(),
            pid,
            priority,
            message: msg.to_string(),
        };
        if let Err(e) = self.write(&entry) {
            warn!("journald: write failed: {}", e);
        }
    }
}

impl Default for JournalWriter {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            path: Arc::new(JOURNAL_PATH.to_string()),
            lock: Arc::new(Mutex::new(())),
        })
    }
}

/// Start the journal socket listener.
///
/// Accepts connections from services using `sd_journal_sendv()` compatible API.
/// Each line received is: `KEY=value\n` — we extract PRIORITY, MESSAGE, SYSLOG_IDENTIFIER.
pub fn start_socket_listener(writer: JournalWriter) {
    let socket_path = Path::new(JOURNAL_SOCKET);
    if socket_path.exists() {
        let _ = fs::remove_file(socket_path);
    }

    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) => {
            warn!(
                "journald: socket bind failed: {} (sd_journal_sendv not available)",
                e
            );
            return;
        }
    };

    // Set socket permissions
    use std::os::unix::fs::PermissionsExt;
    if let Ok(mut perms) = fs::metadata(socket_path).map(|m| m.permissions()) {
        perms.set_mode(0o666);
        let _ = fs::set_permissions(socket_path, perms);
    }

    // Set JOURNAL_STREAM env for child processes
    log::info!("journald: listening on {}", JOURNAL_SOCKET);

    thread::Builder::new()
        .name("journald-socket".into())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let w = writer.clone();
                        thread::Builder::new()
                            .name("journald-client".into())
                            .spawn(move || handle_journal_client(stream, w))
                            .ok();
                    }
                    Err(e) => warn!("journald: accept error: {}", e),
                }
            }
        })
        .ok();
}

fn handle_journal_client(stream: std::os::unix::net::UnixStream, writer: JournalWriter) {
    let reader = BufReader::new(stream);
    let mut unit = "unknown".to_string();
    let mut priority = Priority::Info;
    let mut message = String::new();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.is_empty() {
            // Empty line = end of log entry — flush
            if !message.is_empty() {
                let entry = JournalEntry {
                    timestamp_us: unix_micros(),
                    unit: unit.clone(),
                    pid: 0,
                    priority,
                    message: message.clone(),
                };
                writer.write(&entry).ok();
                message.clear();
            }
            continue;
        }

        // KEY=VALUE format
        if let Some((key, val)) = line.split_once('=') {
            match key {
                "SYSLOG_IDENTIFIER" | "_SYSTEMD_UNIT" => unit = val.to_string(),
                "PRIORITY" => {
                    if let Ok(n) = val.parse::<u8>() {
                        priority = Priority::from_u8(n);
                    }
                }
                "MESSAGE" => message = val.to_string(),
                _ => {}
            }
        }
    }
}

/// Query journal entries for a specific unit.
///
/// Returns up to `max_lines` most recent lines as JSON strings.
#[allow(dead_code)]
pub fn query(unit: &str, max_lines: usize) -> Vec<String> {
    let content = match fs::read_to_string(JOURNAL_PATH) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    content
        .lines()
        .filter(|line| line.contains(&format!("\"unit\":\"{}\"", unit)))
        .rev()
        .take(max_lines)
        .map(String::from)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

fn unix_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

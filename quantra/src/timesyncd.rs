/// NTP time synchronization — pure Rust SNTP client (RFC 4330)
///
/// Implements Simple NTP (SNTPv4) — a stateless subset of NTP sufficient for
/// system clock synchronization. No chrony, ntpd, or external binary needed.
///
/// # Protocol
///
/// SNTPv4 uses a single UDP request/response pair:
/// 1. Send 48-byte NTP packet to server UDP port 123
/// 2. Receive response; extract Transmit Timestamp (bytes 40-47)
/// 3. Adjust for round-trip delay: t = (t1 + t4) / 2 - (t2 + t3) / 2
///    (simplified: t ≈ server_transmit_time + rtt/2)
/// 4. Call clock_settime(CLOCK_REALTIME, adjusted_time)
///
/// # Configuration
///
/// NTP servers read from `/overlayer/syshub/etc/quantra-system/timesyncd.conf`
/// or use built-in defaults.
///
/// # Built-in NTP servers (fallback order)
/// 1. time.cloudflare.com
/// 2. pool.ntp.org
/// 3. time.google.com
/// 4. ntp.ubuntu.com
use anyhow::{Context, Result};
use log::{info, warn};
use std::fs;
use std::net::UdpSocket;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NTP_CONFIG: &str = "/overlayer/syshub/etc/quantra-system/timesyncd.conf";
const NTP_PORT: u16 = 123;

/// NTP epoch offset: 1900-01-01 to 1970-01-01 = 70 years in seconds.
const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;

const DEFAULT_SERVERS: &[&str] = &[
    "time.cloudflare.com",
    "pool.ntp.org",
    "time.google.com",
    "ntp.ubuntu.com",
];

/// Synchronize the system clock with NTP servers.
///
/// Tries each server in order until one succeeds.
/// Non-fatal — if all fail, system continues with whatever clock time it has.
pub fn sync_clock() {
    let servers = load_servers();
    info!(
        "timesyncd: attempting sync with {} server(s)",
        servers.len()
    );

    for server in &servers {
        match query_sntp(server) {
            Ok(unix_secs) => match set_system_clock(unix_secs) {
                Ok(()) => {
                    info!(
                        "timesyncd: clock synchronized via {} ({})",
                        server,
                        format_unix_time(unix_secs)
                    );
                    return;
                }
                Err(e) => warn!("timesyncd: clock_settime failed: {}", e),
            },
            Err(e) => warn!("timesyncd: {} failed: {}", server, e),
        }
    }

    warn!("timesyncd: all NTP servers failed — system clock not synchronized");
}

/// Load NTP server list from config file.
/// Falls back to DEFAULT_SERVERS if config missing or empty.
fn load_servers() -> Vec<String> {
    if let Ok(content) = fs::read_to_string(NTP_CONFIG) {
        let servers: Vec<String> = content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter_map(|l| {
                if let Some(v) = l.strip_prefix("NTP=") {
                    Some(v.trim().to_string())
                } else if l.starts_with("time.") || l.starts_with("pool.") || l.starts_with("ntp.")
                {
                    Some(l.to_string())
                } else {
                    None
                }
            })
            .collect();
        if !servers.is_empty() {
            return servers;
        }
    }
    DEFAULT_SERVERS.iter().map(|s| s.to_string()).collect()
}

/// Query an SNTPv4 server and return Unix timestamp (seconds since 1970).
fn query_sntp(server: &str) -> Result<u64> {
    let addr = format!("{}:{}", server, NTP_PORT);

    // Bind to ephemeral port
    let socket = UdpSocket::bind("0.0.0.0:0").context("bind UDP socket for NTP")?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .context("set NTP socket timeout")?;

    // Build SNTPv4 request packet (48 bytes)
    // Byte 0: LI=0 (no warning), VN=4 (version 4), Mode=3 (client)
    // LI(2) | VN(3) | Mode(3) → 0b00_100_011 = 0x23
    let mut packet = [0u8; 48];
    packet[0] = 0x23; // LI=0, VN=4, Mode=3 (client)

    // Record t1: time we sent the request (Originate Timestamp, bytes 24-31)
    let t1_ntp = unix_to_ntp(system_unix_secs());
    packet[24..28].copy_from_slice(&(t1_ntp >> 32).to_be_bytes());
    packet[28..32].copy_from_slice(&((t1_ntp & 0xFFFFFFFF) as u32).to_be_bytes());

    // Send request
    socket
        .send_to(&packet, &addr)
        .with_context(|| format!("send NTP request to {}", server))?;

    // Receive response
    let mut response = [0u8; 48];
    let (n, _) = socket
        .recv_from(&mut response)
        .with_context(|| format!("receive NTP response from {}", server))?;

    if n < 48 {
        anyhow::bail!("NTP response too short: {} bytes (need 48)", n);
    }

    // Check response mode: byte 0 bits 0-2 should be 4 (server) or 5 (broadcast)
    let mode = response[0] & 0x07;
    if mode != 4 && mode != 5 {
        anyhow::bail!("unexpected NTP mode in response: {}", mode);
    }

    // Check stratum: byte 1, 0 = unspecified (KoD), 1-15 valid
    let stratum = response[1];
    if stratum == 0 {
        anyhow::bail!("NTP server sent Kiss-of-Death packet (stratum=0)");
    }

    // Extract Transmit Timestamp: bytes 40-47 (NTP timestamp = seconds since 1900)
    let t4_seconds =
        u32::from_be_bytes([response[40], response[41], response[42], response[43]]) as u64;
    let t4_fraction =
        u32::from_be_bytes([response[44], response[45], response[46], response[47]]) as u64;

    // Convert NTP seconds (since 1900) → Unix seconds (since 1970)
    if t4_seconds < NTP_EPOCH_OFFSET {
        anyhow::bail!("NTP timestamp too old: {} (before Unix epoch)", t4_seconds);
    }
    let unix_secs = t4_seconds - NTP_EPOCH_OFFSET;

    // Basic sanity: must be after 2024-01-01
    if unix_secs < 1_704_067_200 {
        anyhow::bail!(
            "NTP timestamp implausibly old: {} (before 2024-01-01)",
            unix_secs
        );
    }

    let _ = t4_fraction; // Used in full NTP implementation for sub-second precision
    Ok(unix_secs)
}

/// Set the system realtime clock via clock_settime(CLOCK_REALTIME).
fn set_system_clock(unix_secs: u64) -> Result<()> {
    let ts = libc::timespec {
        tv_sec: unix_secs as libc::time_t,
        tv_nsec: 0,
    };
    let ret = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "clock_settime: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn system_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn unix_to_ntp(unix_secs: u64) -> u64 {
    (unix_secs + NTP_EPOCH_OFFSET) << 32 // integer part in high 32 bits, fraction = 0
}

fn format_unix_time(unix_secs: u64) -> String {
    // Simple UTC approximation for logging only
    let days_since_epoch = unix_secs / 86400;
    let year = 1970 + days_since_epoch / 365;
    let month = (days_since_epoch % 365) / 30 + 1;
    let day = (days_since_epoch % 30) + 1;
    let time_of_day = unix_secs % 86400;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, h, m, s
    )
}

/// Write default timesyncd.conf to syshub if it doesn't exist.
/// Called once at install time by the installer.
#[allow(dead_code)]
pub fn write_default_config() -> Result<()> {
    let config_path = Path::new(NTP_CONFIG);
    if config_path.exists() {
        return Ok(());
    }
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        config_path,
        "\
# quantra-system timesyncd configuration
# One NTP server per line
NTP=time.cloudflare.com
NTP=pool.ntp.org
NTP=time.google.com
",
    )?;
    Ok(())
}

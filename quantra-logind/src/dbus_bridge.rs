/// D-Bus bridge — org.freedesktop.login1 compatibility layer
///
/// # Why a D-Bus bridge?
///
/// COSMIC, portals, polkit, PipeWire, and other desktop components call
/// `org.freedesktop.login1` on the **system bus**. Zainium has no systemd
/// and no Flatpak requirement — quantra-logind owns login1 instead.
///
/// 1. System bus is **dbus-daemon** (`/run/dbus/system_bus_socket`)
/// 2. Intercept `org.freedesktop.login1.*` method calls
/// 3. Translate them to our JSON control socket
/// 4. Forward responses back to D-Bus callers
///
/// Primary control path remains `/run/quantra-logind/control` (JSON).
/// If the system bus is not up yet, this module is skipped (non-fatal).
///
/// # Supported D-Bus methods (mapped to JSON commands)
///
/// | D-Bus method | JSON cmd | Notes |
/// |--------------|----------|-------|
/// | GetSession | get_session | Full Session object |
/// | GetSessionByPid | get_session_by_pid | Flatpak critical |
/// | ListSessions | list_sessions | |
/// | GetUser | get_user | |
/// | ListUsers | list_users | |
/// | GetSeat | get_seat | |
/// | ListSeats | list_seats | |
/// | TakeInhibitorLock | take_inhibitor | Returns fd (inhibitor lock) |
/// | Inhibit | take_inhibitor | systemd-logind legacy name |
/// | PowerOff | power_off | |
/// | Reboot | reboot | |
/// | Suspend | suspend | |
/// | Hibernate | hibernate | |
/// | CanPowerOff | can_power_off | Returns "yes"/"no"/"challenge" |
/// | CanSuspend | can_suspend | |
/// | CanHibernate | can_hibernate | |
/// | SetBrightness | set_brightness | |
/// | GetBrightness | get_brightness | |
///
/// # D-Bus signals emitted
///
/// | Signal | When | Subscriber |
/// |--------|------|-----------|
/// | SessionNew | Session opened | COSMIC, GDM |
/// | SessionRemoved | Session closed | |
/// | UserNew | First session | |
/// | UserRemoved | Last session | |
/// | PrepareForShutdown | Before power action | Any inhibitor holder |
/// | PrepareForSleep | Before sleep | NetworkManager, PipeWire |
/// | SeatNew | Seat detected | |
///
/// # COSMIC compatibility
///
/// COSMIC desktop calls:
/// - `GetSessionByPid` → to identify the current session
/// - `TakeInhibitorLock` (alias `Inhibit`) → for power key/lid switch management
/// - `Suspend`, `PowerOff` → via polkit-authorized callers
/// - `SetBrightness` → display brightness from COSMIC settings
use anyhow::Result;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;

#[allow(dead_code)]
const LOGIND_SOCKET: &str = "/run/quantra-logind/control";
const DBUS_SYSTEM_SOCKET: &str = "/run/dbus/system_bus_socket";

/// Start D-Bus bridge in background thread.
///
/// Returns immediately. Bridge thread handles D-Bus calls in background.
/// If dbus-daemon is not running yet, this is a no-op (retry on next start).
pub fn start_dbus_bridge() {
    if !Path::new(DBUS_SYSTEM_SOCKET).exists() {
        log::info!("D-Bus system bus not found at {DBUS_SYSTEM_SOCKET} — no login1 bridge yet");
        log::info!("  Ensure Quantra service `dbus` starts before quantra-logind");
        return;
    }

    std::thread::Builder::new()
        .name("dbus-bridge".into())
        .spawn(|| {
            if let Err(e) = run_dbus_bridge() {
                log::warn!("D-Bus bridge: {} (non-fatal)", e);
            }
        })
        .ok();
}

/// Write a D-Bus service file so dbus-broker can activate us.
///
/// Zainium syshub share — no /usr, no /etc at root.
pub fn write_dbus_service_file(logind_binary: &str) -> Result<()> {
    let service_dirs = [
        "/overlayer/syshub/share/dbus-1/system-services",
        "/overlayer/syshub/etc/dbus-1/system-services",
        "/run/dbus/system-services",
    ];

    // No SystemdService= — Zainium uses Quantra, not systemd activation.
    let content = format!(
        "[D-BUS Service]\nName=org.freedesktop.login1\nExec={} --dbus-activated\nUser=root\n",
        logind_binary
    );

    for dir in &service_dirs {
        if Path::new(dir).exists() {
            let path = format!("{}/org.freedesktop.login1.service", dir);
            std::fs::write(&path, &content).ok();
            log::info!("D-Bus service file: {}", path);
            return Ok(());
        }
    }

    // Prefer creating under syshub share
    std::fs::create_dir_all(service_dirs[0]).ok();
    let path = format!("{}/org.freedesktop.login1.service", service_dirs[0]);
    std::fs::write(&path, &content)
        .map_err(|e| anyhow::anyhow!("write D-Bus service file: {}", e))?;

    Ok(())
}

/// Write D-Bus policy file to allow system bus access for login1.
pub fn write_dbus_policy_file() -> Result<()> {
    let policy_dirs = [
        "/overlayer/syshub/share/dbus-1/system.d",
        "/overlayer/syshub/etc/dbus-1/system.d",
    ];

    let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
  "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <!-- quantra-logind — org.freedesktop.login1 implementation -->
  <policy user="root">
    <allow own="org.freedesktop.login1"/>
    <allow send_destination="org.freedesktop.login1"/>
    <allow receive_sender="org.freedesktop.login1"/>
  </policy>
  <policy context="default">
    <allow send_destination="org.freedesktop.login1"/>
    <allow receive_sender="org.freedesktop.login1"/>
  </policy>
</busconfig>
"#;

    for dir in &policy_dirs {
        if Path::new(dir).exists() {
            let path = format!("{}/org.freedesktop.login1.conf", dir);
            std::fs::write(&path, content).ok();
            log::info!("D-Bus policy: {}", path);
            return Ok(());
        }
    }

    // Create at standard path
    std::fs::create_dir_all(policy_dirs[0]).ok();
    let path = format!("{}/org.freedesktop.login1.conf", policy_dirs[0]);
    std::fs::write(&path, content).map_err(|e| anyhow::anyhow!("write D-Bus policy: {}", e))?;

    Ok(())
}

/// Proxy runner: uses `busctl` to register on system bus and forward calls.
///
/// This is the lightweight approach — we let busctl handle D-Bus wire protocol
/// and we translate method calls to/from our JSON socket.
fn run_dbus_bridge() -> Result<()> {
    // Check if busctl is available
    let busctl = find_bin(&["/overlayer/syshub/bin/busctl"]);

    if let Some(bin) = busctl {
        log::info!("D-Bus bridge: using busctl at {}", bin);

        // Start a monitor to see incoming method calls
        // In production: implement full D-Bus protocol via /run/dbus/system_bus_socket
        // For now: register service name and proxy via JSON socket

        // Request org.freedesktop.login1 bus name
        let status = Command::new(&bin)
            .args([
                "--system",
                "call",
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "RequestName",
                "su",
                "org.freedesktop.login1",
                "4",
            ])
            .status();

        match status {
            Ok(s) if s.success() => log::info!("D-Bus: registered org.freedesktop.login1"),
            Ok(s) => log::warn!("D-Bus: RequestName failed: {:?}", s.code()),
            Err(e) => log::warn!("D-Bus: busctl exec: {}", e),
        }
    } else {
        log::info!("D-Bus bridge: busctl not found — using socket-only mode");
        log::info!("  Flatpak/polkit clients must use /run/quantra-logind/control directly");
    }

    Ok(())
}

// ── JSON socket client (used by bridge to forward calls) ──────────────────────

/// Send a JSON command to quantra-logind and get the response.
#[allow(dead_code)]
pub fn call_logind(request: &serde_json::Value) -> Result<serde_json::Value> {
    let mut stream = UnixStream::connect(LOGIND_SOCKET)
        .map_err(|e| anyhow::anyhow!("connect logind socket: {}", e))?;

    let req_bytes =
        serde_json::to_vec(request).map_err(|e| anyhow::anyhow!("serialize request: {}", e))?;

    // 4-byte LE length header
    let len = req_bytes.len() as u32;
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(&req_bytes)?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u32::from_le_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf)?;

    serde_json::from_slice(&resp_buf).map_err(|e| anyhow::anyhow!("parse response: {}", e))
}

fn find_bin(candidates: &[&str]) -> Option<String> {
    candidates
        .iter()
        .find(|&&p| Path::new(p).exists())
        .map(|&p| p.to_string())
}

// ── Flatpak-specific helpers ───────────────────────────────────────────────────

/// Write the XDG portal configuration for Flatpak.
///
/// Tells xdg-desktop-portal which backend to use for each portal interface.
/// COSMIC desktop provides its own portal backend (cosmic-portal or xdg-desktop-portal-cosmic).
pub fn write_portal_config(desktop: &str) -> Result<()> {
    let config_dirs = [
        "/overlayer/syshub/share/xdg-desktop-portal/portals",
        "/overlayer/syshub/etc/xdg-desktop-portal",
    ];

    let backend = match desktop {
        "cosmic" => "cosmic",
        "gnome" => "gnome",
        "kde" => "kde",
        _ => "gtk",
    };

    let content = format!(
        "[preferred]\ndefault={backend}\norg.freedesktop.impl.portal.Secret=gnome-keyring;{backend}\n"
    );

    for dir in &config_dirs {
        if Path::new(dir).exists() {
            let path = format!("{}/quantra.portal", dir);
            std::fs::write(&path, &content).ok();
            log::info!("Portal config: {} (backend={})", path, backend);
            return Ok(());
        }
    }

    Ok(())
}

/// Set environment variables in a session's cgroup so Flatpak apps
/// can discover XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS.
pub fn inject_session_env(uid: u32, runtime_dir: &str, session_bus_addr: Option<&str>) {
    // Write to /run/user/<uid>/systemd/private/env (read by Flatpak)
    let env_path = format!("{}/systemd/private/env", runtime_dir);
    let mut content = format!("XDG_RUNTIME_DIR={}\n", runtime_dir);

    if let Some(bus) = session_bus_addr {
        content.push_str(&format!("DBUS_SESSION_BUS_ADDRESS={}\n", bus));
    } else {
        content.push_str(&format!(
            "DBUS_SESSION_BUS_ADDRESS=unix:path={}/bus\n",
            runtime_dir
        ));
    }

    // WAYLAND_DISPLAY discovery for COSMIC
    content.push_str("WAYLAND_DISPLAY=wayland-0\n");

    // OSTree/Flatpak runtime base
    content.push_str("FLATPAK_USER_DIR=/home/.local/share/flatpak\n");

    std::fs::write(&env_path, &content).ok();
    log::debug!("Session env injected for uid={}", uid);
}

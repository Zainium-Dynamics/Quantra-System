//! Shared types — Session, User, Seat, Inhibitor, Request, Response, Events
//!
//! # JSON Control Protocol
//!
//! Same framing as PID 1 `/run/quantra/control`:
//!   `[4 bytes LE length][JSON payload]`
//!
//! # Compatibility
//!
//! All response fields mirror systemd-logind D-Bus property names so that
//! elevate-pam, Flatpak, polkit, COSMIC desktop, and xdg-desktop-portal
//! can use the JSON socket as a drop-in source of truth.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub type SessionId = u64;
pub type InhibitorId = u64;

// ── Session ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionType {
    Tty,
    X11,
    Wayland,
    Mir,        // Ubuntu Mir / COSMIC mir-based compositors
    Remote,
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum SessionClass {
    #[default]
    User,
    Greeter,    // Login manager (e.g. cosmic-greeter)
    LockScreen, // Screen locker
    Background, // System background session
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionState {
    /// Session opening — elevate/greeter setup in progress
    Opening,
    /// Session is the active foreground session on its seat
    Active,
    /// Session exists but is not the active foreground session
    Online,
    /// Session being torn down
    Closing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id:             SessionId,
    pub uid:            u32,
    pub username:       String,
    pub seat:           Option<String>,
    pub vt_number:      Option<u32>,      // Virtual terminal number (1–63)
    pub tty:            Option<String>,    // e.g. "/dev/tty1"
    pub display:        Option<String>,    // e.g. ":0" for X11, "" for Wayland
    pub session_type:   SessionType,
    pub session_class:  SessionClass,
    pub state:          SessionState,
    pub leader_pid:     u32,
    pub audit_id:       Option<u32>,
    pub service:        Option<String>,   // elevate-pam service name (e.g. "cosmic-greeter", "login")
    pub scope:          String,           // cgroup scope: "session-N.scope"
    pub created_at:     u64,
    pub remote:         bool,
    pub remote_host:    Option<String>,
    pub remote_user:    Option<String>,
    /// XDG_RUNTIME_DIR for this session
    pub runtime_dir:    String,
    /// Idle hint — set by compositor/screensaver
    pub idle_hint:      bool,
    pub idle_since:     Option<u64>,
    /// Lock hint — set by lock screen
    pub locked_hint:    bool,
}

impl Session {
    pub fn new(
        id: SessionId, uid: u32, username: String,
        leader_pid: u32, session_type: SessionType,
        session_class: SessionClass,
    ) -> Self {
        Self {
            id, uid, username: username.clone(), leader_pid, session_type, session_class,
            seat: None, vt_number: None, tty: None, display: None, remote_host: None,
            remote_user: None, remote: false, audit_id: None, service: None,
            state: SessionState::Online,
            scope: format!("session-{}.scope", id),
            runtime_dir: format!("/run/user/{}", uid),
            created_at: now_unix(),
            idle_hint: false, idle_since: None, locked_hint: false,
        }
    }
}

// ── User ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub uid:              u32,
    pub username:         String,
    pub session_ids:      Vec<SessionId>,
    pub linger:           bool,
    pub runtime_dir:      String,
    pub runtime_dir_size: u64,         // bytes, default 500 MB
    pub state:            UserState,
    pub first_login:      u64,
    pub last_login:       u64,
    /// Slice in which user services run: "user-UID.slice"
    pub slice:            String,
    /// Display manager session (greeter)
    pub display_session:  Option<SessionId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserState {
    Offline,    // No sessions, no linger
    Lingering,  // No sessions, linger=true
    Online,     // Has sessions, none active
    Active,     // Has active session on a seat
    Closing,    // Last session closing
}

impl UserRecord {
    pub fn new(uid: u32, username: String) -> Self {
        let now = now_unix();
        Self {
            uid, username,
            session_ids: Vec::new(),
            linger: false,
            runtime_dir: format!("/run/user/{}", uid),
            runtime_dir_size: 500 * 1024 * 1024,
            state: UserState::Offline,
            first_login: now,
            last_login: now,
            slice: format!("user-{}.slice", uid),
            display_session: None,
        }
    }
}

// ── Seat ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Seat {
    pub id:             String,
    pub active_session: Option<SessionId>,
    pub sessions:       Vec<SessionId>,
    pub devices:        Vec<SeatDevice>,
    pub can_graphical:  bool,  // Has DRM device
    pub can_tty:        bool,  // Has VT
    pub idle_hint:      bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeatDevice {
    pub path:     String,    // e.g. "/dev/dri/card0"
    pub kind:     DeviceKind,
    pub fd:       Option<i32>, // Open fd for TakeDevice
    pub paused:   bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind { Drm, Evdev, Sound, Other }

impl Seat {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            active_session: None,
            sessions: Vec::new(),
            devices: Vec::new(),
            can_graphical: false,
            can_tty: true,
            idle_hint: false,
        }
    }
}

// ── Inhibitor ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InhibitWhat {
    Shutdown,
    Sleep,
    Idle,
    HandlePowerKey,
    HandleSuspendKey,
    HandleHibernateKey,
    HandleLidSwitch,
    HandleRebootKey,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InhibitMode {
    /// Block: action is completely prevented while inhibitor is held
    Block,
    /// Delay: action is delayed by up to InhibitDelayMaxSec seconds
    Delay,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inhibitor {
    pub id:      InhibitorId,
    pub what:    Vec<InhibitWhat>,
    pub who:     String,
    pub why:     String,
    pub mode:    InhibitMode,
    pub uid:     u32,
    pub pid:     u32,
    pub created: u64,
}

// ── Power / Sleep actions ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PowerAction {
    PowerOff,
    Reboot,
    RebootToBootloaderMenu,
    RebootToBootloaderEntry,
    RebootToFirmwareSetup,
    Halt,
    Kexec,
    Suspend,
    Hibernate,
    HybridSleep,
    SuspendThenHibernate,
    Ignore,
    Lock,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CanDo {
    Yes,
    No,
    Challenge, // Requires polkit auth
    Na,        // Not applicable
}

// ── Configuration ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogindConfig {
    pub n_autovts:               u32,
    pub reserve_vt:              u32,
    pub kill_user_processes:     bool,
    pub kill_only_users:         Vec<String>,
    pub kill_exclude_users:      Vec<String>,
    pub idle_action:             PowerAction,
    pub idle_action_sec:         u64,
    pub inhibit_delay_max_sec:   u64,
    pub inhibit_max_delay_sec:   u64,
    pub user_stop_delay_sec:     u64,
    pub handle_power_key:        PowerAction,
    pub handle_power_key_long_press: PowerAction,
    pub handle_suspend_key:      PowerAction,
    pub handle_hibernate_key:    PowerAction,
    pub handle_lid_switch:       PowerAction,
    pub handle_lid_switch_docked: PowerAction,
    pub handle_lid_switch_external_power: PowerAction,
    pub handle_reboot_key:       PowerAction,
    pub power_key_ignore_inhibited: bool,
    pub suspend_key_ignore_inhibited: bool,
    pub hibernate_key_ignore_inhibited: bool,
    pub lid_switch_ignore_inhibited: bool,
    pub runtime_directory_size:  Option<String>,   // "500M" / "10%"
    pub runtime_directory_inodes: Option<u64>,
    pub remove_ipc:              bool,
    pub holdoff_timeout_sec:     u64,
    pub stop_timeout_sec:        u64,
}

impl Default for LogindConfig {
    fn default() -> Self {
        Self {
            n_autovts:               6,
            reserve_vt:              6,
            kill_user_processes:     false,
            kill_only_users:         Vec::new(),
            kill_exclude_users:      vec!["root".to_string()],
            idle_action:             PowerAction::Ignore,
            idle_action_sec:         1800,
            inhibit_delay_max_sec:   5,
            inhibit_max_delay_sec:   5,
            user_stop_delay_sec:     10,
            handle_power_key:        PowerAction::PowerOff,
            handle_power_key_long_press: PowerAction::Ignore,
            handle_suspend_key:      PowerAction::Suspend,
            handle_hibernate_key:    PowerAction::Hibernate,
            handle_lid_switch:       PowerAction::Suspend,
            handle_lid_switch_docked: PowerAction::Ignore,
            handle_lid_switch_external_power: PowerAction::Ignore,
            handle_reboot_key:       PowerAction::Reboot,
            power_key_ignore_inhibited:     false,
            suspend_key_ignore_inhibited:   false,
            hibernate_key_ignore_inhibited: false,
            lid_switch_ignore_inhibited:    true,
            runtime_directory_size:  Some("10%".to_string()),
            runtime_directory_inodes: None,
            remove_ipc:              true,
            holdoff_timeout_sec:     30,
            stop_timeout_sec:        10,
        }
    }
}

impl LogindConfig {
    pub fn load(path: &str) -> Self {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Self::default(),
        };
        toml::from_str(&content).unwrap_or_else(|e| {
            log::warn!("logind.conf parse: {} (using defaults)", e);
            Self::default()
        })
    }
}

// ── Control protocol ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    // ── Session management ────────────────────────────────────────────────────
    OpenSession {
        uid: u32, username: String, leader_pid: u32,
        session_type: SessionType,
        #[serde(default)]
        session_class: SessionClass,
        tty: Option<String>, display: Option<String>,
        remote_host: Option<String>, remote_user: Option<String>,
        service: Option<String>,
        vt: Option<u32>,
    },
    CloseSession     { session_id: SessionId },
    ActivateSession  { session_id: SessionId },
    LockSession      { session_id: SessionId },
    UnlockSession    { session_id: SessionId },
    LockSessions,
    UnlockSessions,
    ListSessions,
    GetSession       { session_id: SessionId },
    GetSessionByPid  { pid: u32 },
    SetIdleHint      { session_id: SessionId, idle: bool },
    SetLockedHint    { session_id: SessionId, locked: bool },

    // ── User management ───────────────────────────────────────────────────────
    SetLinger       { uid: u32, enable: bool },
    GetUser         { uid: u32 },
    ListUsers,
    TerminateUser   { uid: u32 },

    // ── Seat management ───────────────────────────────────────────────────────
    ListSeats,
    GetSeat             { seat_id: String },
    ActivateSessionOnSeat { session_id: SessionId, seat_id: String },
    SwitchTo            { vt_number: u32 },            // VT switch
    TakeDevice          { seat_id: String, devpath: String }, // DRM/evdev fd
    ReleaseDevice       { seat_id: String, devpath: String },

    // ── Inhibitors ────────────────────────────────────────────────────────────
    TakeInhibitor {
        what: Vec<InhibitWhat>, who: String, why: String,
        mode: InhibitMode, uid: u32, pid: u32,
    },
    ReleaseInhibitor { inhibitor_id: InhibitorId },
    ListInhibitors,

    // ── Power ─────────────────────────────────────────────────────────────────
    PowerOff                 { interactive: bool },
    Reboot                   { interactive: bool },
    RebootToFirmwareSetup    { interactive: bool },
    Halt                     { interactive: bool },
    Suspend                  { interactive: bool },
    Hibernate                { interactive: bool },
    HybridSleep              { interactive: bool },
    SuspendThenHibernate     { interactive: bool },
    CanPowerOff,
    CanReboot,
    CanSuspend,
    CanHibernate,
    CanHybridSleep,
    CanSuspendThenHibernate,

    // ── Brightness / backlight ────────────────────────────────────────────────
    SetBrightness   { subsystem: String, name: String, value: u32 },
    GetBrightness   { subsystem: String, name: String },

    // ── Wall message ──────────────────────────────────────────────────────────
    ScheduleShutdown { action: String, usec: u64 },
    CancelScheduledShutdown,

    // ── Events (subscribe) ────────────────────────────────────────────────────
    Subscribe,

    // ── Diagnostics ──────────────────────────────────────────────────────────
    Status,
    Version,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum LogindEvent {
    SessionNew    { session_id: SessionId, uid: u32, username: String },
    SessionRemoved { session_id: SessionId, uid: u32 },
    SessionLocked { session_id: SessionId },
    SessionUnlocked { session_id: SessionId },
    UserNew       { uid: u32, username: String },
    UserRemoved   { uid: u32 },
    SeatNew       { seat_id: String },
    SeatRemoved   { seat_id: String },
    PrepareForShutdown { active: bool },
    PrepareForSleep    { active: bool },
    VtSwitched    { vt_number: u32 },
    BrightnessChanged { name: String, value: u32 },
    ShutdownScheduled { action: String, time_usec: u64 },
}

#[derive(Debug, Serialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl Response {
    pub fn ok(data: impl serde::Serialize) -> Self {
        Self { ok: true, error: None,
               data: Some(serde_json::to_value(data).unwrap_or_default()) }
    }
    pub fn ok_empty() -> Self { Self { ok: true, error: None, data: None } }
    pub fn err(msg: impl Into<String>) -> Self {
        Self { ok: false, error: Some(msg.into()), data: None }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub fn now_usec() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_micros() as u64
}

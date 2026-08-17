//! D-Bus bridge — org.freedesktop.login1 compatibility layer using native OxiBus
//!
//! COSMIC, portals, polkit, PipeWire, and other desktop components call
//! `org.freedesktop.login1` on the system bus.
//!
//! 1. Connect to system bus (/run/dbus/system_bus_socket)
//! 2. Handle org.freedesktop.login1.* method calls
//! 3. Translate D-Bus methods to JSON control socket and return D-Bus replies
//! 4. Monitor logind events and emit corresponding D-Bus signals

use anyhow::Result;
use serde_json::json;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use tokio::io::AsyncReadExt;

use oxibus_client::{BoxFuture, Connection, Interface, MethodError, MethodResult, ObjectServer};
use oxibus_core::{Address, ArrayValue, ObjectPath, Type, Value};

use crate::types::{InhibitMode, InhibitWhat};

const LOGIND_SOCKET: &str = "/run/quantra-logind/control";
const DBUS_SYSTEM_SOCKET: &str = "/run/dbus/system_bus_socket";

/// Start D-Bus bridge in background thread.
pub fn start_dbus_bridge() {
    if !Path::new(DBUS_SYSTEM_SOCKET).exists() {
        log::info!("D-Bus system bus not found at {DBUS_SYSTEM_SOCKET} — no login1 bridge yet");
        log::info!("  Ensure Quantra service `dbus` starts before quantra-logind");
        return;
    }

    std::thread::Builder::new()
        .name("dbus-bridge".into())
        .spawn(|| {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => {
                    log::error!("D-Bus bridge: failed to build tokio runtime: {:?}", e);
                    return;
                }
            };
            rt.block_on(async {
                if let Err(e) = run_dbus_bridge().await {
                    log::warn!("D-Bus bridge: {} (non-fatal)", e);
                }
            });
        })
        .ok();
}

/// Write a D-Bus service file so dbus-broker can activate us.
pub fn write_dbus_service_file(logind_binary: &str) -> Result<()> {
    let service_dirs = [
        "/overlayer/syshub/share/dbus-1/system-services",
        "/overlayer/syshub/etc/dbus-1/system-services",
        "/usr/share/dbus-1/system-services",
        "/run/dbus/system-services",
    ];

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
        "/etc/dbus-1/system.d",
        "/usr/share/dbus-1/system.d",
    ];

    let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
  "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
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

    std::fs::create_dir_all(policy_dirs[0]).ok();
    let path = format!("{}/org.freedesktop.login1.conf", policy_dirs[0]);
    std::fs::write(&path, content).map_err(|e| anyhow::anyhow!("write D-Bus policy: {}", e))?;

    Ok(())
}

/// Run native D-Bus bridge using oxibus-client.
async fn run_dbus_bridge() -> Result<()> {
    log::info!("D-Bus bridge: starting native oxibus-client bridge");
    let addr = Address::UnixPath(DBUS_SYSTEM_SOCKET.to_string());

    let conn = Connection::connect(&addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to system bus: {:?}", e))?;

    conn.bus_hello()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to say hello to D-Bus daemon: {:?}", e))?;

    conn.request_name("org.freedesktop.login1", 4)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to request org.freedesktop.login1 name: {:?}", e))?;

    log::info!("D-Bus bridge: claimed org.freedesktop.login1 name");

    let server = conn.object_server();
    let manager = Arc::new(Login1Manager);

    let path = ObjectPath::new("/org/freedesktop/login1").unwrap();
    server.register(&path, manager.clone());
    register_helpers(server, &path);

    // Register initial objects
    if let Err(e) = register_initial_objects(server).await {
        log::warn!("D-Bus bridge: failed to register initial objects: {:?}", e);
    }

    // Start subscription loop
    let conn_cloned = conn.clone();
    let server_cloned = server.clone();
    tokio::spawn(async move {
        if let Err(e) = handle_events(conn_cloned, server_cloned).await {
            log::warn!("D-Bus bridge event handler exited: {:?}", e);
        }
    });

    // Keep connection alive
    let mut sig_rx = conn.subscribe_signals();
    loop {
        let _ = sig_rx.recv().await;
    }
}

async fn register_initial_objects(server: &Arc<ObjectServer>) -> Result<()> {
    // Register seats
    if let Ok(resp) = call_logind(&json!({"cmd": "list_seats"}))
        && let Some(seats) = resp.get("data").and_then(|v| v.as_array())
    {
        for seat in seats {
            if let Some(seat_id) = seat.as_str() {
                let path = format!("/org/freedesktop/login1/seat/{}", seat_id);
                if let Ok(op) = ObjectPath::new(&path) {
                    server.register(
                        &op,
                        Arc::new(Login1Seat {
                            seat_id: seat_id.to_string(),
                        }),
                    );
                    register_helpers(server, &op);
                }
            }
        }
    }
    // Register users
    if let Ok(resp) = call_logind(&json!({"cmd": "list_users"}))
        && let Some(users) = resp.get("data").and_then(|v| v.as_array())
    {
        for user in users {
            if let Some(uid) = user.get("uid").and_then(|v| v.as_u64()) {
                let path = format!("/org/freedesktop/login1/user/_{}", uid);
                if let Ok(op) = ObjectPath::new(&path) {
                    server.register(&op, Arc::new(Login1User { uid: uid as u32 }));
                    register_helpers(server, &op);
                }
            }
        }
    }
    // Register sessions
    if let Ok(resp) = call_logind(&json!({"cmd": "list_sessions"}))
        && let Some(sessions) = resp.get("data").and_then(|v| v.as_array())
    {
        for session in sessions {
            if let Some(id) = session.get("id").and_then(|v| v.as_u64()) {
                let path = format!("/org/freedesktop/login1/session/_{}", id);
                if let Ok(op) = ObjectPath::new(&path) {
                    server.register(&op, Arc::new(Login1Session { session_id: id }));
                    register_helpers(server, &op);
                }
            }
        }
    }
    Ok(())
}

async fn handle_events(conn: Connection, server: Arc<ObjectServer>) -> Result<()> {
    log::info!("D-Bus bridge: starting subscription event listener loop");
    let mut stream = tokio::net::UnixStream::connect(LOGIND_SOCKET).await?;

    // Send subscribe request
    let subscribe_cmd = json!({"cmd": "subscribe"});
    let req_bytes = serde_json::to_vec(&subscribe_cmd)?;
    let len = req_bytes.len() as u32;
    use tokio::io::AsyncWriteExt;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&req_bytes).await?;

    // Read subscribe response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u32::from_le_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await?;

    // Now enter loop to read broadcast events
    loop {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let event_len = u32::from_le_bytes(len_buf) as usize;
        if event_len == 0 {
            continue;
        }
        if event_len > 1024 * 1024 {
            return Err(anyhow::anyhow!("Event payload too large: {}", event_len));
        }

        let mut event_buf = vec![0u8; event_len];
        stream.read_exact(&mut event_buf).await?;

        let event: crate::types::LogindEvent = match serde_json::from_slice(&event_buf) {
            Ok(ev) => ev,
            Err(e) => {
                log::warn!("D-Bus bridge event deserialization failed: {:?}", e);
                continue;
            }
        };

        log::debug!("D-Bus bridge: received event: {:?}", event);

        match event {
            crate::types::LogindEvent::SessionNew {
                session_id,
                uid: _,
                username: _,
            } => {
                let path = format!("/org/freedesktop/login1/session/_{}", session_id);
                if let Ok(op) = ObjectPath::new(&path) {
                    server.register(&op, Arc::new(Login1Session { session_id }));
                    register_helpers(&server, &op);

                    let _ = conn
                        .emit_signal(
                            ObjectPath::new("/org/freedesktop/login1").unwrap(),
                            "org.freedesktop.login1.Manager",
                            "SessionNew",
                            vec![Value::string(session_id.to_string()), Value::ObjectPath(op)],
                        )
                        .await;
                }
            }
            crate::types::LogindEvent::SessionRemoved { session_id, uid: _ } => {
                let path = format!("/org/freedesktop/login1/session/_{}", session_id);
                server.unregister(&path, "org.freedesktop.login1.Session");
                server.unregister(&path, "org.freedesktop.DBus.Properties");
                server.unregister(&path, "org.freedesktop.DBus.Introspectable");

                if let Ok(op) = ObjectPath::new(&path) {
                    let _ = conn
                        .emit_signal(
                            ObjectPath::new("/org/freedesktop/login1").unwrap(),
                            "org.freedesktop.login1.Manager",
                            "SessionRemoved",
                            vec![Value::string(session_id.to_string()), Value::ObjectPath(op)],
                        )
                        .await;
                }
            }
            crate::types::LogindEvent::UserNew { uid, username: _ } => {
                let path = format!("/org/freedesktop/login1/user/_{}", uid);
                if let Ok(op) = ObjectPath::new(&path) {
                    server.register(&op, Arc::new(Login1User { uid }));
                    register_helpers(&server, &op);

                    let _ = conn
                        .emit_signal(
                            ObjectPath::new("/org/freedesktop/login1").unwrap(),
                            "org.freedesktop.login1.Manager",
                            "UserNew",
                            vec![Value::UInt32(uid), Value::ObjectPath(op)],
                        )
                        .await;
                }
            }
            crate::types::LogindEvent::UserRemoved { uid } => {
                let path = format!("/org/freedesktop/login1/user/_{}", uid);
                server.unregister(&path, "org.freedesktop.login1.User");
                server.unregister(&path, "org.freedesktop.DBus.Properties");
                server.unregister(&path, "org.freedesktop.DBus.Introspectable");

                if let Ok(op) = ObjectPath::new(&path) {
                    let _ = conn
                        .emit_signal(
                            ObjectPath::new("/org/freedesktop/login1").unwrap(),
                            "org.freedesktop.login1.Manager",
                            "UserRemoved",
                            vec![Value::UInt32(uid), Value::ObjectPath(op)],
                        )
                        .await;
                }
            }
            crate::types::LogindEvent::SeatNew { seat_id } => {
                let path = format!("/org/freedesktop/login1/seat/{}", seat_id);
                if let Ok(op) = ObjectPath::new(&path) {
                    server.register(
                        &op,
                        Arc::new(Login1Seat {
                            seat_id: seat_id.clone(),
                        }),
                    );
                    register_helpers(&server, &op);

                    let _ = conn
                        .emit_signal(
                            ObjectPath::new("/org/freedesktop/login1").unwrap(),
                            "org.freedesktop.login1.Manager",
                            "SeatNew",
                            vec![Value::string(seat_id), Value::ObjectPath(op)],
                        )
                        .await;
                }
            }
            crate::types::LogindEvent::SeatRemoved { seat_id } => {
                let path = format!("/org/freedesktop/login1/seat/{}", seat_id);
                server.unregister(&path, "org.freedesktop.login1.Seat");
                server.unregister(&path, "org.freedesktop.DBus.Properties");
                server.unregister(&path, "org.freedesktop.DBus.Introspectable");

                if let Ok(op) = ObjectPath::new(&path) {
                    let _ = conn
                        .emit_signal(
                            ObjectPath::new("/org/freedesktop/login1").unwrap(),
                            "org.freedesktop.login1.Manager",
                            "SeatRemoved",
                            vec![Value::string(seat_id), Value::ObjectPath(op)],
                        )
                        .await;
                }
            }
            crate::types::LogindEvent::PrepareForShutdown { active } => {
                let _ = conn
                    .emit_signal(
                        ObjectPath::new("/org/freedesktop/login1").unwrap(),
                        "org.freedesktop.login1.Manager",
                        "PrepareForShutdown",
                        vec![Value::Boolean(active)],
                    )
                    .await;
            }
            crate::types::LogindEvent::PrepareForSleep { active } => {
                let _ = conn
                    .emit_signal(
                        ObjectPath::new("/org/freedesktop/login1").unwrap(),
                        "org.freedesktop.login1.Manager",
                        "PrepareForSleep",
                        vec![Value::Boolean(active)],
                    )
                    .await;
            }
            _ => {}
        }
    }
}

// ── JSON socket client (used by bridge to forward calls) ──────────────────────

/// Send a JSON command to quantra-logind and get the response.
pub fn call_logind(request: &serde_json::Value) -> Result<serde_json::Value> {
    let mut stream = UnixStream::connect(LOGIND_SOCKET)
        .map_err(|e| anyhow::anyhow!("connect logind socket: {}", e))?;

    let req_bytes =
        serde_json::to_vec(request).map_err(|e| anyhow::anyhow!("serialize request: {}", e))?;

    let len = req_bytes.len() as u32;
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(&req_bytes)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u32::from_le_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf)?;

    serde_json::from_slice(&resp_buf).map_err(|e| anyhow::anyhow!("parse response: {}", e))
}

// ── D-Bus Interfaces ──────────────────────────────────────────────────────────

struct Login1Manager;

impl Interface for Login1Manager {
    fn name(&self) -> &str {
        "org.freedesktop.login1.Manager"
    }

    fn introspection_xml(&self) -> String {
        r#"<interface name="org.freedesktop.login1.Manager">
            <method name="GetSession">
                <arg type="s" direction="in"/>
                <arg type="o" direction="out"/>
            </method>
            <method name="GetSessionByPid">
                <arg type="u" direction="in"/>
                <arg type="o" direction="out"/>
            </method>
            <method name="ListSessions">
                <arg type="a(susso)" direction="out"/>
            </method>
            <method name="GetUser">
                <arg type="u" direction="in"/>
                <arg type="o" direction="out"/>
            </method>
            <method name="ListUsers">
                <arg type="a(suso)" direction="out"/>
            </method>
            <method name="GetSeat">
                <arg type="s" direction="in"/>
                <arg type="o" direction="out"/>
            </method>
            <method name="ListSeats">
                <arg type="a(so)" direction="out"/>
            </method>
            <method name="PowerOff">
                <arg type="b" direction="in"/>
            </method>
            <method name="Reboot">
                <arg type="b" direction="in"/>
            </method>
            <method name="Suspend">
                <arg type="b" direction="in"/>
            </method>
            <method name="Hibernate">
                <arg type="b" direction="in"/>
            </method>
            <method name="CanPowerOff">
                <arg type="s" direction="out"/>
            </method>
            <method name="CanSuspend">
                <arg type="s" direction="out"/>
            </method>
            <method name="CanHibernate">
                <arg type="s" direction="out"/>
            </method>
            <method name="Inhibit">
                <arg type="s" direction="in"/>
                <arg type="s" direction="in"/>
                <arg type="s" direction="in"/>
                <arg type="s" direction="in"/>
                <arg type="h" direction="out"/>
            </method>
            <method name="TakeInhibitorLock">
                <arg type="s" direction="in"/>
                <arg type="s" direction="in"/>
                <arg type="s" direction="in"/>
                <arg type="s" direction="in"/>
                <arg type="h" direction="out"/>
            </method>
            <property name="NAutoVTs" type="u" access="read"/>
            <property name="KillUserProcesses" type="b" access="read"/>
            <property name="PreparingForShutdown" type="b" access="read"/>
            <property name="PreparingForSleep" type="b" access="read"/>
            <property name="IdleHint" type="b" access="read"/>
        </interface>"#
            .to_string()
    }

    fn call<'a>(&'a self, member: &'a str, args: &'a [Value]) -> BoxFuture<'a, MethodResult> {
        Box::pin(async move {
            match member {
                "GetSession" => {
                    let sid = match args.first().and_then(|v| v.as_str()) {
                        Some(s) => s,
                        None => {
                            return Err(MethodError::invalid_args(
                                "Expected a single string argument",
                            ));
                        }
                    };

                    let session_id_u64: u64 = sid
                        .parse()
                        .map_err(|_| MethodError::invalid_args("Invalid session ID"))?;

                    let resp = call_logind(&json!({
                        "cmd": "get_session",
                        "session_id": session_id_u64
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;

                    if !resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        return Err(MethodError::new(
                            oxibus_core::errors::FILE_NOT_FOUND,
                            "No such session",
                        ));
                    }

                    let path = format!("/org/freedesktop/login1/session/_{}", session_id_u64);
                    let op = ObjectPath::new(path).map_err(|e| {
                        MethodError::new(oxibus_core::errors::FAILED, format!("{:?}", e))
                    })?;
                    Ok(vec![Value::ObjectPath(op)])
                }
                "GetSessionByPid" => {
                    let pid = match args.first().and_then(|v| v.as_u32()) {
                        Some(p) => p,
                        None => {
                            return Err(MethodError::invalid_args(
                                "Expected a single u32 argument",
                            ));
                        }
                    };

                    let resp = call_logind(&json!({
                        "cmd": "get_session_by_pid",
                        "pid": pid
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;

                    if !resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        return Err(MethodError::new(
                            oxibus_core::errors::FILE_NOT_FOUND,
                            "No session for this PID",
                        ));
                    }

                    let data = resp.get("data").ok_or_else(|| {
                        MethodError::new(oxibus_core::errors::FAILED, "Missing response data")
                    })?;
                    let sid = data.get("id").and_then(|v| v.as_u64()).ok_or_else(|| {
                        MethodError::new(oxibus_core::errors::FAILED, "Missing session ID")
                    })?;

                    let path = format!("/org/freedesktop/login1/session/_{}", sid);
                    let op = ObjectPath::new(path).map_err(|e| {
                        MethodError::new(oxibus_core::errors::FAILED, format!("{:?}", e))
                    })?;
                    Ok(vec![Value::ObjectPath(op)])
                }
                "ListSessions" => {
                    let resp = call_logind(&json!({
                        "cmd": "list_sessions"
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;

                    let data = resp.get("data").and_then(|v| v.as_array()).ok_or_else(|| {
                        MethodError::new(oxibus_core::errors::FAILED, "Invalid response format")
                    })?;

                    let mut elements = Vec::new();
                    for s in data {
                        let sid = s.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                        let uid = s.get("uid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                        let username = s
                            .get("username")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let seat = s
                            .get("seat")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let path = format!("/org/freedesktop/login1/session/_{}", sid);
                        let op = ObjectPath::new(path).map_err(|e| {
                            MethodError::new(oxibus_core::errors::FAILED, format!("{:?}", e))
                        })?;

                        elements.push(Value::Struct(vec![
                            Value::string(sid.to_string()),
                            Value::UInt32(uid),
                            Value::string(username),
                            Value::string(seat),
                            Value::ObjectPath(op),
                        ]));
                    }

                    let struct_type = Type::Struct(vec![
                        Type::String,
                        Type::UInt32,
                        Type::String,
                        Type::String,
                        Type::ObjectPath,
                    ]);
                    Ok(vec![Value::Array(ArrayValue::new(struct_type, elements))])
                }
                "GetUser" => {
                    let uid = match args.first().and_then(|v| v.as_u32()) {
                        Some(u) => u,
                        None => {
                            return Err(MethodError::invalid_args(
                                "Expected a single u32 argument",
                            ));
                        }
                    };

                    let resp = call_logind(&json!({
                        "cmd": "get_user",
                        "uid": uid
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;

                    if !resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        return Err(MethodError::new(
                            oxibus_core::errors::FILE_NOT_FOUND,
                            "No such user",
                        ));
                    }

                    let path = format!("/org/freedesktop/login1/user/_{}", uid);
                    let op = ObjectPath::new(path).map_err(|e| {
                        MethodError::new(oxibus_core::errors::FAILED, format!("{:?}", e))
                    })?;
                    Ok(vec![Value::ObjectPath(op)])
                }
                "ListUsers" => {
                    let resp = call_logind(&json!({
                        "cmd": "list_users"
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;

                    let data = resp.get("data").and_then(|v| v.as_array()).ok_or_else(|| {
                        MethodError::new(oxibus_core::errors::FAILED, "Invalid response format")
                    })?;

                    let mut elements = Vec::new();
                    for u in data {
                        let uid = u.get("uid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                        let username = u
                            .get("username")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let path = format!("/org/freedesktop/login1/user/_{}", uid);
                        let op = ObjectPath::new(path).map_err(|e| {
                            MethodError::new(oxibus_core::errors::FAILED, format!("{:?}", e))
                        })?;

                        elements.push(Value::Struct(vec![
                            Value::UInt32(uid),
                            Value::string(username),
                            Value::ObjectPath(op),
                        ]));
                    }

                    let struct_type =
                        Type::Struct(vec![Type::UInt32, Type::String, Type::ObjectPath]);
                    Ok(vec![Value::Array(ArrayValue::new(struct_type, elements))])
                }
                "GetSeat" => {
                    let seat_id = match args.first().and_then(|v| v.as_str()) {
                        Some(s) => s,
                        None => {
                            return Err(MethodError::invalid_args(
                                "Expected a single string argument",
                            ));
                        }
                    };

                    let resp = call_logind(&json!({
                        "cmd": "get_seat",
                        "seat_id": seat_id
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;

                    if !resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        return Err(MethodError::new(
                            oxibus_core::errors::FILE_NOT_FOUND,
                            "No such seat",
                        ));
                    }

                    let path = format!("/org/freedesktop/login1/seat/{}", seat_id);
                    let op = ObjectPath::new(path).map_err(|e| {
                        MethodError::new(oxibus_core::errors::FAILED, format!("{:?}", e))
                    })?;
                    Ok(vec![Value::ObjectPath(op)])
                }
                "ListSeats" => {
                    let resp = call_logind(&json!({
                        "cmd": "list_seats"
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;

                    let data = resp.get("data").and_then(|v| v.as_array()).ok_or_else(|| {
                        MethodError::new(oxibus_core::errors::FAILED, "Invalid response format")
                    })?;

                    let mut elements = Vec::new();
                    for seat_val in data {
                        let seat_id = seat_val.as_str().unwrap_or("").to_string();
                        let path = format!("/org/freedesktop/login1/seat/{}", seat_id);
                        let op = ObjectPath::new(path).map_err(|e| {
                            MethodError::new(oxibus_core::errors::FAILED, format!("{:?}", e))
                        })?;

                        elements.push(Value::Struct(vec![
                            Value::string(seat_id),
                            Value::ObjectPath(op),
                        ]));
                    }

                    let struct_type = Type::Struct(vec![Type::String, Type::ObjectPath]);
                    Ok(vec![Value::Array(ArrayValue::new(struct_type, elements))])
                }
                "PowerOff" => {
                    let interactive = args
                        .first()
                        .and_then(|v| match v {
                            Value::Boolean(b) => Some(*b),
                            _ => None,
                        })
                        .unwrap_or(false);
                    let resp = call_logind(&json!({
                        "cmd": "power_off",
                        "interactive": interactive
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;
                    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        Ok(Vec::new())
                    } else {
                        let err_msg = resp
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        Err(MethodError::new(
                            oxibus_core::errors::FAILED,
                            err_msg.to_string(),
                        ))
                    }
                }
                "Reboot" => {
                    let interactive = args
                        .first()
                        .and_then(|v| match v {
                            Value::Boolean(b) => Some(*b),
                            _ => None,
                        })
                        .unwrap_or(false);
                    let resp = call_logind(&json!({
                        "cmd": "reboot",
                        "interactive": interactive
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;
                    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        Ok(Vec::new())
                    } else {
                        let err_msg = resp
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        Err(MethodError::new(
                            oxibus_core::errors::FAILED,
                            err_msg.to_string(),
                        ))
                    }
                }
                "Suspend" => {
                    let interactive = args
                        .first()
                        .and_then(|v| match v {
                            Value::Boolean(b) => Some(*b),
                            _ => None,
                        })
                        .unwrap_or(false);
                    let resp = call_logind(&json!({
                        "cmd": "suspend",
                        "interactive": interactive
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;
                    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        Ok(Vec::new())
                    } else {
                        let err_msg = resp
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        Err(MethodError::new(
                            oxibus_core::errors::FAILED,
                            err_msg.to_string(),
                        ))
                    }
                }
                "Hibernate" => {
                    let interactive = args
                        .first()
                        .and_then(|v| match v {
                            Value::Boolean(b) => Some(*b),
                            _ => None,
                        })
                        .unwrap_or(false);
                    let resp = call_logind(&json!({
                        "cmd": "hibernate",
                        "interactive": interactive
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;
                    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        Ok(Vec::new())
                    } else {
                        let err_msg = resp
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        Err(MethodError::new(
                            oxibus_core::errors::FAILED,
                            err_msg.to_string(),
                        ))
                    }
                }
                "CanPowerOff" => {
                    let resp = call_logind(&json!({"cmd": "can_power_off"})).map_err(|e| {
                        MethodError::new(oxibus_core::errors::FAILED, e.to_string())
                    })?;
                    let res = resp.get("data").and_then(|v| v.as_str()).unwrap_or("yes");
                    Ok(vec![Value::string(res.to_string())])
                }
                "CanSuspend" => {
                    let resp = call_logind(&json!({"cmd": "can_suspend"})).map_err(|e| {
                        MethodError::new(oxibus_core::errors::FAILED, e.to_string())
                    })?;
                    let res = resp.get("data").and_then(|v| v.as_str()).unwrap_or("yes");
                    Ok(vec![Value::string(res.to_string())])
                }
                "CanHibernate" => {
                    let resp = call_logind(&json!({"cmd": "can_hibernate"})).map_err(|e| {
                        MethodError::new(oxibus_core::errors::FAILED, e.to_string())
                    })?;
                    let res = resp.get("data").and_then(|v| v.as_str()).unwrap_or("yes");
                    Ok(vec![Value::string(res.to_string())])
                }
                "Inhibit" | "TakeInhibitorLock" => {
                    if args.len() < 4 {
                        return Err(MethodError::invalid_args("Expected 4 string arguments"));
                    }
                    let what_str = args[0]
                        .as_str()
                        .ok_or_else(|| MethodError::invalid_args("what must be string"))?;
                    let who = args[1]
                        .as_str()
                        .ok_or_else(|| MethodError::invalid_args("who must be string"))?;
                    let why = args[2]
                        .as_str()
                        .ok_or_else(|| MethodError::invalid_args("why must be string"))?;
                    let mode_str = args[3]
                        .as_str()
                        .ok_or_else(|| MethodError::invalid_args("mode must be string"))?;

                    let mut what = Vec::new();
                    for part in what_str.split(':') {
                        let w = match part {
                            "shutdown" => InhibitWhat::Shutdown,
                            "sleep" => InhibitWhat::Sleep,
                            "idle" => InhibitWhat::Idle,
                            "handle-power-key" => InhibitWhat::HandlePowerKey,
                            "handle-suspend-key" => InhibitWhat::HandleSuspendKey,
                            "handle-hibernate-key" => InhibitWhat::HandleHibernateKey,
                            "handle-lid-switch" => InhibitWhat::HandleLidSwitch,
                            "handle-reboot-key" => InhibitWhat::HandleRebootKey,
                            _ => continue,
                        };
                        what.push(w);
                    }
                    if what.is_empty() {
                        return Err(MethodError::invalid_args("Invalid 'what' inhibitors"));
                    }

                    let mode = match mode_str {
                        "delay" => InhibitMode::Delay,
                        _ => InhibitMode::Block,
                    };

                    let (stream_bridge, stream_client) = std::os::unix::net::UnixStream::pair()
                        .map_err(|e| {
                            MethodError::new(
                                oxibus_core::errors::FAILED,
                                format!("socketpair: {}", e),
                            )
                        })?;

                    let resp = call_logind(&json!({
                        "cmd": "take_inhibitor",
                        "what": what,
                        "who": who,
                        "why": why,
                        "mode": mode,
                        "uid": 0,
                        "pid": std::process::id()
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;

                    if !resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        let err_msg = resp
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        return Err(MethodError::new(
                            oxibus_core::errors::FAILED,
                            err_msg.to_string(),
                        ));
                    }

                    let inhibitor_id =
                        resp.get("data").and_then(|v| v.as_u64()).ok_or_else(|| {
                            MethodError::new(
                                oxibus_core::errors::FAILED,
                                "Missing inhibitor ID in response",
                            )
                        })?;

                    tokio::spawn(async move {
                        if let Ok(mut async_stream) =
                            tokio::net::UnixStream::from_std(stream_bridge)
                        {
                            let mut buf = [0u8; 1];
                            let _ = async_stream.read(&mut buf).await;
                            log::info!(
                                "D-Bus inhibitor {} pipe closed, releasing inhibitor",
                                inhibitor_id
                            );
                            let _ = call_logind(&json!({
                                "cmd": "release_inhibitor",
                                "inhibitor_id": inhibitor_id
                            }));
                        }
                    });

                    use std::os::unix::io::IntoRawFd;
                    let fd = stream_client.into_raw_fd();

                    Ok(vec![Value::UnixFd(fd as u32)])
                }
                _ => Err(MethodError::unknown_method(member, self.name())),
            }
        })
    }

    fn get_property(&self, name: &str) -> Option<Value> {
        match name {
            "NAutoVTs" => Some(Value::UInt32(6)),
            "KillUserProcesses" => Some(Value::Boolean(false)),
            "PreparingForShutdown" => Some(Value::Boolean(false)),
            "PreparingForSleep" => Some(Value::Boolean(false)),
            "IdleHint" => Some(Value::Boolean(false)),
            _ => None,
        }
    }

    fn list_properties(&self) -> Vec<(String, Value)> {
        let keys = [
            "NAutoVTs",
            "KillUserProcesses",
            "PreparingForShutdown",
            "PreparingForSleep",
            "IdleHint",
        ];
        keys.iter()
            .filter_map(|&k| self.get_property(k).map(|v| (k.to_string(), v)))
            .collect()
    }
}

struct Login1Session {
    session_id: u64,
}

impl Login1Session {
    fn query(&self) -> Option<serde_json::Value> {
        let resp = call_logind(&json!({
            "cmd": "get_session",
            "session_id": self.session_id
        }))
        .ok()?;
        if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
            resp.get("data").cloned()
        } else {
            None
        }
    }
}

impl Interface for Login1Session {
    fn name(&self) -> &str {
        "org.freedesktop.login1.Session"
    }

    fn introspection_xml(&self) -> String {
        r#"<interface name="org.freedesktop.login1.Session">
            <method name="Activate"/>
            <method name="Lock"/>
            <method name="Unlock"/>
            <method name="Terminate"/>
            <method name="SetLockedHint">
                <arg type="b" direction="in"/>
            </method>
            <method name="SetIdleHint">
                <arg type="b" direction="in"/>
            </method>
            <property name="Id" type="s" access="read"/>
            <property name="User" type="(uo)" access="read"/>
            <property name="Name" type="s" access="read"/>
            <property name="Active" type="b" access="read"/>
            <property name="State" type="s" access="read"/>
            <property name="Type" type="s" access="read"/>
            <property name="Class" type="s" access="read"/>
            <property name="Seat" type="(so)" access="read"/>
            <property name="TTY" type="s" access="read"/>
            <property name="Display" type="s" access="read"/>
            <property name="Remote" type="b" access="read"/>
            <property name="RemoteHost" type="s" access="read"/>
            <property name="RemoteUser" type="s" access="read"/>
            <property name="Leader" type="u" access="read"/>
            <property name="Audit" type="u" access="read"/>
            <property name="VTNr" type="u" access="read"/>
            <property name="Scope" type="s" access="read"/>
        </interface>"#
            .to_string()
    }

    fn call<'a>(&'a self, member: &'a str, args: &'a [Value]) -> BoxFuture<'a, MethodResult> {
        Box::pin(async move {
            match member {
                "Activate" => {
                    let resp = call_logind(&json!({
                        "cmd": "activate_session",
                        "session_id": self.session_id
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;
                    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        Ok(Vec::new())
                    } else {
                        let err_msg = resp
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        Err(MethodError::new(
                            oxibus_core::errors::FAILED,
                            err_msg.to_string(),
                        ))
                    }
                }
                "Lock" => {
                    let resp = call_logind(&json!({
                        "cmd": "lock_session",
                        "session_id": self.session_id
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;
                    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        Ok(Vec::new())
                    } else {
                        let err_msg = resp
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        Err(MethodError::new(
                            oxibus_core::errors::FAILED,
                            err_msg.to_string(),
                        ))
                    }
                }
                "Unlock" => {
                    let resp = call_logind(&json!({
                        "cmd": "unlock_session",
                        "session_id": self.session_id
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;
                    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        Ok(Vec::new())
                    } else {
                        let err_msg = resp
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        Err(MethodError::new(
                            oxibus_core::errors::FAILED,
                            err_msg.to_string(),
                        ))
                    }
                }
                "Terminate" => {
                    let resp = call_logind(&json!({
                        "cmd": "close_session",
                        "session_id": self.session_id
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;
                    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        Ok(Vec::new())
                    } else {
                        let err_msg = resp
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        Err(MethodError::new(
                            oxibus_core::errors::FAILED,
                            err_msg.to_string(),
                        ))
                    }
                }
                "SetLockedHint" => {
                    let locked = args
                        .first()
                        .and_then(|v| match v {
                            Value::Boolean(b) => Some(*b),
                            _ => None,
                        })
                        .ok_or_else(|| {
                            MethodError::invalid_args("Expected a boolean locked hint")
                        })?;
                    let resp = call_logind(&json!({
                        "cmd": "set_locked_hint",
                        "session_id": self.session_id,
                        "locked": locked
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;
                    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        Ok(Vec::new())
                    } else {
                        let err_msg = resp
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        Err(MethodError::new(
                            oxibus_core::errors::FAILED,
                            err_msg.to_string(),
                        ))
                    }
                }
                "SetIdleHint" => {
                    let idle = args
                        .first()
                        .and_then(|v| match v {
                            Value::Boolean(b) => Some(*b),
                            _ => None,
                        })
                        .ok_or_else(|| MethodError::invalid_args("Expected a boolean idle hint"))?;
                    let resp = call_logind(&json!({
                        "cmd": "set_idle_hint",
                        "session_id": self.session_id,
                        "idle": idle
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;
                    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        Ok(Vec::new())
                    } else {
                        let err_msg = resp
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        Err(MethodError::new(
                            oxibus_core::errors::FAILED,
                            err_msg.to_string(),
                        ))
                    }
                }
                _ => Err(MethodError::unknown_method(member, self.name())),
            }
        })
    }

    fn get_property(&self, name: &str) -> Option<Value> {
        let q = self.query()?;
        match name {
            "Id" => Some(Value::string(self.session_id.to_string())),
            "User" => {
                let uid = q.get("uid")?.as_u64()? as u32;
                let path = format!("/org/freedesktop/login1/user/_{}", uid);
                let op = ObjectPath::new(path).ok()?;
                Some(Value::Struct(vec![
                    Value::UInt32(uid),
                    Value::ObjectPath(op),
                ]))
            }
            "Name" => Some(Value::string(q.get("username")?.as_str()?.to_string())),
            "Active" => {
                let state = q.get("state")?.as_str()?;
                Some(Value::Boolean(state == "active"))
            }
            "State" => Some(Value::string(q.get("state")?.as_str()?.to_string())),
            "Type" => Some(Value::string(q.get("session_type")?.as_str()?.to_string())),
            "Class" => Some(Value::string(q.get("session_class")?.as_str()?.to_string())),
            "Seat" => {
                let seat_id = q.get("seat")?.as_str()?.to_string();
                let path = format!("/org/freedesktop/login1/seat/{}", seat_id);
                let op = ObjectPath::new(path).ok()?;
                Some(Value::Struct(vec![
                    Value::string(seat_id),
                    Value::ObjectPath(op),
                ]))
            }
            "TTY" => Some(Value::string(
                q.get("tty")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            )),
            "Display" => Some(Value::string(
                q.get("display")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            )),
            "Remote" => Some(Value::Boolean(q.get("remote")?.as_bool()?)),
            "RemoteHost" => Some(Value::string(
                q.get("remote_host")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            )),
            "RemoteUser" => Some(Value::string(
                q.get("remote_user")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            )),
            "Leader" => Some(Value::UInt32(q.get("leader_pid")?.as_u64()? as u32)),
            "Audit" => Some(Value::UInt32(
                q.get("audit_id").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            )),
            "VTNr" => Some(Value::UInt32(
                q.get("vt_number").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            )),
            "Scope" => Some(Value::string(q.get("scope")?.as_str()?.to_string())),
            _ => None,
        }
    }

    fn list_properties(&self) -> Vec<(String, Value)> {
        let keys = [
            "Id",
            "User",
            "Name",
            "Active",
            "State",
            "Type",
            "Class",
            "Seat",
            "TTY",
            "Display",
            "Remote",
            "RemoteHost",
            "RemoteUser",
            "Leader",
            "Audit",
            "VTNr",
            "Scope",
        ];
        keys.iter()
            .filter_map(|&k| self.get_property(k).map(|v| (k.to_string(), v)))
            .collect()
    }
}

struct Login1User {
    uid: u32,
}

impl Login1User {
    fn query(&self) -> Option<serde_json::Value> {
        let resp = call_logind(&json!({
            "cmd": "get_user",
            "uid": self.uid
        }))
        .ok()?;
        if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
            resp.get("data").cloned()
        } else {
            None
        }
    }
}

impl Interface for Login1User {
    fn name(&self) -> &str {
        "org.freedesktop.login1.User"
    }

    fn introspection_xml(&self) -> String {
        r#"<interface name="org.freedesktop.login1.User">
            <method name="Terminate"/>
            <property name="UID" type="u" access="read"/>
            <property name="Name" type="s" access="read"/>
            <property name="RuntimePath" type="s" access="read"/>
            <property name="State" type="s" access="read"/>
            <property name="Display" type="(so)" access="read"/>
            <property name="Sessions" type="a(so)" access="read"/>
            <property name="Linger" type="b" access="read"/>
        </interface>"#
            .to_string()
    }

    fn call<'a>(&'a self, member: &'a str, _args: &'a [Value]) -> BoxFuture<'a, MethodResult> {
        Box::pin(async move {
            match member {
                "Terminate" => {
                    let resp = call_logind(&json!({
                        "cmd": "terminate_user",
                        "uid": self.uid
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;
                    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        Ok(Vec::new())
                    } else {
                        let err_msg = resp
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        Err(MethodError::new(
                            oxibus_core::errors::FAILED,
                            err_msg.to_string(),
                        ))
                    }
                }
                _ => Err(MethodError::unknown_method(member, self.name())),
            }
        })
    }

    fn get_property(&self, name: &str) -> Option<Value> {
        let q = self.query()?;
        match name {
            "UID" => Some(Value::UInt32(self.uid)),
            "Name" => Some(Value::string(q.get("username")?.as_str()?.to_string())),
            "RuntimePath" => Some(Value::string(q.get("runtime_dir")?.as_str()?.to_string())),
            "State" => Some(Value::string(q.get("state")?.as_str()?.to_string())),
            "Display" => {
                let ds = q.get("display_session").and_then(|v| v.as_u64());
                let (ds_str, ds_path) = match ds {
                    Some(id) => (
                        id.to_string(),
                        format!("/org/freedesktop/login1/session/_{}", id),
                    ),
                    None => ("".to_string(), "/".to_string()),
                };
                let op = ObjectPath::new(ds_path).ok()?;
                Some(Value::Struct(vec![
                    Value::string(ds_str),
                    Value::ObjectPath(op),
                ]))
            }
            "Sessions" => {
                let sids = q.get("session_ids")?.as_array()?;
                let mut elements = Vec::new();
                for s in sids {
                    let sid = s.as_u64()?;
                    let path = format!("/org/freedesktop/login1/session/_{}", sid);
                    let op = ObjectPath::new(path).ok()?;
                    elements.push(Value::Struct(vec![
                        Value::string(sid.to_string()),
                        Value::ObjectPath(op),
                    ]));
                }
                let struct_type = Type::Struct(vec![Type::String, Type::ObjectPath]);
                Some(Value::Array(ArrayValue::new(struct_type, elements)))
            }
            "Linger" => Some(Value::Boolean(q.get("linger")?.as_bool()?)),
            _ => None,
        }
    }

    fn list_properties(&self) -> Vec<(String, Value)> {
        let keys = [
            "UID",
            "Name",
            "RuntimePath",
            "State",
            "Display",
            "Sessions",
            "Linger",
        ];
        keys.iter()
            .filter_map(|&k| self.get_property(k).map(|v| (k.to_string(), v)))
            .collect()
    }
}

struct Login1Seat {
    seat_id: String,
}

impl Login1Seat {
    fn query(&self) -> Option<serde_json::Value> {
        let resp = call_logind(&json!({
            "cmd": "get_seat",
            "seat_id": self.seat_id
        }))
        .ok()?;
        if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
            resp.get("data").cloned()
        } else {
            None
        }
    }
}

impl Interface for Login1Seat {
    fn name(&self) -> &str {
        "org.freedesktop.login1.Seat"
    }

    fn introspection_xml(&self) -> String {
        r#"<interface name="org.freedesktop.login1.Seat">
            <method name="ActivateSession">
                <arg type="s" direction="in"/>
            </method>
            <method name="SwitchTo">
                <arg type="u" direction="in"/>
            </method>
            <property name="Id" type="s" access="read"/>
            <property name="ActiveSession" type="(so)" access="read"/>
            <property name="Sessions" type="a(so)" access="read"/>
            <property name="CanTTY" type="b" access="read"/>
            <property name="CanGraphical" type="b" access="read"/>
        </interface>"#
            .to_string()
    }

    fn call<'a>(&'a self, member: &'a str, args: &'a [Value]) -> BoxFuture<'a, MethodResult> {
        Box::pin(async move {
            match member {
                "ActivateSession" => {
                    let sid_str = args
                        .first()
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| MethodError::invalid_args("Expected a string session ID"))?;
                    let sid: u64 = sid_str
                        .parse()
                        .map_err(|_| MethodError::invalid_args("Invalid session ID"))?;

                    let resp = call_logind(&json!({
                        "cmd": "activate_session",
                        "session_id": sid
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;
                    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        Ok(Vec::new())
                    } else {
                        let err_msg = resp
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        Err(MethodError::new(
                            oxibus_core::errors::FAILED,
                            err_msg.to_string(),
                        ))
                    }
                }
                "SwitchTo" => {
                    let vt = args
                        .first()
                        .and_then(|v| v.as_u32())
                        .ok_or_else(|| MethodError::invalid_args("Expected a u32 VT number"))?;

                    let resp = call_logind(&json!({
                        "cmd": "switch_to",
                        "vt_number": vt
                    }))
                    .map_err(|e| MethodError::new(oxibus_core::errors::FAILED, e.to_string()))?;
                    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        Ok(Vec::new())
                    } else {
                        let err_msg = resp
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        Err(MethodError::new(
                            oxibus_core::errors::FAILED,
                            err_msg.to_string(),
                        ))
                    }
                }
                _ => Err(MethodError::unknown_method(member, self.name())),
            }
        })
    }

    fn get_property(&self, name: &str) -> Option<Value> {
        let q = self.query()?;
        match name {
            "Id" => Some(Value::string(self.seat_id.clone())),
            "ActiveSession" => {
                let active = q.get("active_session").and_then(|v| v.as_u64());
                let (act_str, act_path) = match active {
                    Some(id) => (
                        id.to_string(),
                        format!("/org/freedesktop/login1/session/_{}", id),
                    ),
                    None => ("".to_string(), "/".to_string()),
                };
                let op = ObjectPath::new(act_path).ok()?;
                Some(Value::Struct(vec![
                    Value::string(act_str),
                    Value::ObjectPath(op),
                ]))
            }
            "Sessions" => {
                let sids = q.get("sessions")?.as_array()?;
                let mut elements = Vec::new();
                for s in sids {
                    let sid = s.as_u64()?;
                    let path = format!("/org/freedesktop/login1/session/_{}", sid);
                    let op = ObjectPath::new(path).ok()?;
                    elements.push(Value::Struct(vec![
                        Value::string(sid.to_string()),
                        Value::ObjectPath(op),
                    ]));
                }
                let struct_type = Type::Struct(vec![Type::String, Type::ObjectPath]);
                Some(Value::Array(ArrayValue::new(struct_type, elements)))
            }
            "CanTTY" => Some(Value::Boolean(q.get("can_tty")?.as_bool()?)),
            "CanGraphical" => Some(Value::Boolean(q.get("can_graphical")?.as_bool()?)),
            _ => None,
        }
    }

    fn list_properties(&self) -> Vec<(String, Value)> {
        let keys = ["Id", "ActiveSession", "Sessions", "CanTTY", "CanGraphical"];
        keys.iter()
            .filter_map(|&k| self.get_property(k).map(|v| (k.to_string(), v)))
            .collect()
    }
}

// ── Generic Introspection and Properties helper interfaces ───────────────────

struct IntrospectableInterface {
    path: String,
    server: Arc<ObjectServer>,
}

impl Interface for IntrospectableInterface {
    fn name(&self) -> &str {
        "org.freedesktop.DBus.Introspectable"
    }

    fn introspection_xml(&self) -> String {
        r#"<interface name="org.freedesktop.DBus.Introspectable">
            <method name="Introspect">
                <arg type="s" direction="out"/>
            </method>
        </interface>"#
            .to_string()
    }

    fn call<'a>(&'a self, member: &'a str, _args: &'a [Value]) -> BoxFuture<'a, MethodResult> {
        Box::pin(async move {
            match member {
                "Introspect" => {
                    let xml = self.server.introspect(&self.path);
                    Ok(vec![Value::string(xml)])
                }
                _ => Err(MethodError::unknown_method(member, self.name())),
            }
        })
    }
}

struct PropertiesInterface {
    path: String,
    server: Arc<ObjectServer>,
}

impl Interface for PropertiesInterface {
    fn name(&self) -> &str {
        "org.freedesktop.DBus.Properties"
    }

    fn introspection_xml(&self) -> String {
        r#"<interface name="org.freedesktop.DBus.Properties">
            <method name="Get">
                <arg type="s" direction="in"/>
                <arg type="s" direction="in"/>
                <arg type="v" direction="out"/>
            </method>
            <method name="Set">
                <arg type="s" direction="in"/>
                <arg type="s" direction="in"/>
                <arg type="v" direction="in"/>
            </method>
            <method name="GetAll">
                <arg type="s" direction="in"/>
                <arg type="a{sv}" direction="out"/>
            </method>
        </interface>"#
            .to_string()
    }

    fn call<'a>(&'a self, member: &'a str, args: &'a [Value]) -> BoxFuture<'a, MethodResult> {
        Box::pin(async move {
            match member {
                "Get" => {
                    if args.len() < 2 {
                        return Err(MethodError::invalid_args(
                            "Expected interface and property name",
                        ));
                    }
                    let iface_name = args[0]
                        .as_str()
                        .ok_or_else(|| MethodError::invalid_args("interface must be string"))?;
                    let prop_name = args[1]
                        .as_str()
                        .ok_or_else(|| MethodError::invalid_args("property must be string"))?;

                    let iface = self
                        .server
                        .get_interface(&self.path, iface_name)
                        .ok_or_else(|| MethodError::unknown_interface(iface_name))?;

                    let val = iface.get_property(prop_name).ok_or_else(|| {
                        MethodError::new(
                            oxibus_core::errors::UNKNOWN_PROPERTY,
                            format!("No such property \"{prop_name}\""),
                        )
                    })?;

                    Ok(vec![Value::Variant(Box::new(val))])
                }
                "Set" => {
                    if args.len() < 3 {
                        return Err(MethodError::invalid_args(
                            "Expected interface, property name, and value",
                        ));
                    }
                    let iface_name = args[0]
                        .as_str()
                        .ok_or_else(|| MethodError::invalid_args("interface must be string"))?;
                    let prop_name = args[1]
                        .as_str()
                        .ok_or_else(|| MethodError::invalid_args("property must be string"))?;
                    let val = match &args[2] {
                        Value::Variant(v) => *v.clone(),
                        other => other.clone(),
                    };

                    let iface = self
                        .server
                        .get_interface(&self.path, iface_name)
                        .ok_or_else(|| MethodError::unknown_interface(iface_name))?;

                    iface.set_property(prop_name, val)?;
                    Ok(Vec::new())
                }
                "GetAll" => {
                    if args.is_empty() {
                        return Err(MethodError::invalid_args("Expected interface name"));
                    }
                    let iface_name = args[0]
                        .as_str()
                        .ok_or_else(|| MethodError::invalid_args("interface must be string"))?;

                    let iface = self
                        .server
                        .get_interface(&self.path, iface_name)
                        .ok_or_else(|| MethodError::unknown_interface(iface_name))?;

                    let props = iface.list_properties();

                    let mut elements = Vec::new();
                    for (k, v) in props {
                        elements.push(Value::DictEntry(
                            Box::new(Value::string(k)),
                            Box::new(Value::Variant(Box::new(v))),
                        ));
                    }
                    let dict_type =
                        Type::DictEntry(Box::new(Type::String), Box::new(Type::Variant));
                    Ok(vec![Value::Array(ArrayValue::new(dict_type, elements))])
                }
                _ => Err(MethodError::unknown_method(member, self.name())),
            }
        })
    }
}

fn register_helpers(server: &Arc<ObjectServer>, path: &ObjectPath) {
    let path_str = path.as_str().to_string();
    server.register(
        path,
        Arc::new(IntrospectableInterface {
            path: path_str.clone(),
            server: server.clone(),
        }),
    );
    server.register(
        path,
        Arc::new(PropertiesInterface {
            path: path_str,
            server: server.clone(),
        }),
    );
}

// ── Flatpak-specific helpers ───────────────────────────────────────────────────

/// Write the XDG portal configuration for Flatpak.
pub fn write_portal_config(desktop: &str) -> Result<()> {
    let config_dirs = [
        "/overlayer/syshub/share/xdg-desktop-portal/portals",
        "/overlayer/syshub/etc/xdg-desktop-portal",
        "/usr/share/xdg-desktop-portal/portals",
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

    content.push_str("WAYLAND_DISPLAY=wayland-0\n");
    content.push_str("FLATPAK_USER_DIR=/home/.local/share/flatpak\n");

    std::fs::write(&env_path, &content).ok();
    log::debug!("Session env injected for uid={}", uid);
}

//! quantra-logindctl — CLI tool for quantra-logind
//!
//! Usage:
//!   quantra-logindctl status
//!   quantra-logindctl list-sessions
//!   quantra-logindctl list-users
//!   quantra-logindctl list-seats
//!   quantra-logindctl list-inhibitors
//!   quantra-logindctl session-status <id>
//!   quantra-logindctl activate-session <id>
//!   quantra-logindctl lock-session <id>
//!   quantra-logindctl unlock-session <id>
//!   quantra-logindctl lock-sessions
//!   quantra-logindctl terminate-user <uid>
//!   quantra-logindctl set-linger <uid> <yes|no>
//!   quantra-logindctl switch-to <vt>
//!   quantra-logindctl poweroff [--force]
//!   quantra-logindctl reboot [--force]
//!   quantra-logindctl suspend
//!   quantra-logindctl hibernate
//!   quantra-logindctl hybrid-sleep
//!   quantra-logindctl cancel-shutdown
//!   quantra-logindctl get-brightness <subsystem> <name>
//!   quantra-logindctl set-brightness <subsystem> <name> <value>

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

const SOCKET: &str = "/run/quantra-logind/control";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: quantra-logindctl <command> [args...]");
        eprintln!("Commands: status, list-sessions, list-users, list-seats, list-inhibitors,");
        eprintln!("          session-status <id>, activate-session <id>, lock-session <id>,");
        eprintln!("          unlock-session <id>, lock-sessions, unlock-sessions,");
        eprintln!("          terminate-user <uid>, set-linger <uid> <yes|no>,");
        eprintln!("          switch-to <vt>, poweroff, reboot, suspend, hibernate,");
        eprintln!("          hybrid-sleep, cancel-shutdown,");
        eprintln!("          get-brightness <subsystem> <name>,");
        eprintln!("          set-brightness <subsystem> <name> <value>");
        std::process::exit(1);
    }

    let cmd = args[1].as_str();
    let req: serde_json::Value = match cmd {
        "status" => serde_json::json!({"cmd": "status"}),
        "version" => serde_json::json!({"cmd": "version"}),

        "list-sessions" => serde_json::json!({"cmd": "list_sessions"}),
        "list-users" => serde_json::json!({"cmd": "list_users"}),
        "list-seats" => serde_json::json!({"cmd": "list_seats"}),
        "list-inhibitors" => serde_json::json!({"cmd": "list_inhibitors"}),

        "session-status" => {
            let id: u64 = arg(&args, 2, "session id");
            serde_json::json!({"cmd": "get_session", "session_id": id})
        }
        "activate-session" => {
            let id: u64 = arg(&args, 2, "session id");
            serde_json::json!({"cmd": "activate_session", "session_id": id})
        }
        "lock-session" => {
            let id: u64 = arg(&args, 2, "session id");
            serde_json::json!({"cmd": "lock_session", "session_id": id})
        }
        "unlock-session" => {
            let id: u64 = arg(&args, 2, "session id");
            serde_json::json!({"cmd": "unlock_session", "session_id": id})
        }
        "lock-sessions" => serde_json::json!({"cmd": "lock_sessions"}),
        "unlock-sessions" => serde_json::json!({"cmd": "unlock_sessions"}),

        "terminate-user" => {
            let uid: u32 = arg(&args, 2, "uid");
            serde_json::json!({"cmd": "terminate_user", "uid": uid})
        }
        "set-linger" => {
            let uid: u32 = arg(&args, 2, "uid");
            let enable = args
                .get(3)
                .map(|s| s == "yes" || s == "1" || s == "true")
                .unwrap_or(false);
            serde_json::json!({"cmd": "set_linger", "uid": uid, "enable": enable})
        }

        "switch-to" => {
            let vt: u32 = arg(&args, 2, "vt number");
            serde_json::json!({"cmd": "switch_to", "vt_number": vt})
        }

        "poweroff" => {
            let force = args.iter().any(|a| a == "--force");
            serde_json::json!({"cmd": "power_off", "interactive": !force})
        }
        "reboot" => {
            let force = args.iter().any(|a| a == "--force");
            serde_json::json!({"cmd": "reboot", "interactive": !force})
        }
        "halt" => serde_json::json!({"cmd": "halt", "interactive": false}),
        "suspend" => serde_json::json!({"cmd": "suspend", "interactive": false}),
        "hibernate" => serde_json::json!({"cmd": "hibernate", "interactive": false}),
        "hybrid-sleep" => serde_json::json!({"cmd": "hybrid_sleep", "interactive": false}),
        "suspend-then-hibernate" => {
            serde_json::json!({"cmd": "suspend_then_hibernate", "interactive": false})
        }
        "cancel-shutdown" => serde_json::json!({"cmd": "cancel_scheduled_shutdown"}),

        "can-poweroff" => serde_json::json!({"cmd": "can_power_off"}),
        "can-suspend" => serde_json::json!({"cmd": "can_suspend"}),
        "can-hibernate" => serde_json::json!({"cmd": "can_hibernate"}),
        "can-hybrid-sleep" => serde_json::json!({"cmd": "can_hybrid_sleep"}),

        "get-brightness" => {
            let subsystem = args
                .get(2)
                .cloned()
                .unwrap_or_else(|| "backlight".to_string());
            let name = args
                .get(3)
                .cloned()
                .unwrap_or_else(|| usage("get-brightness <subsystem> <name>"));
            serde_json::json!({"cmd": "get_brightness", "subsystem": subsystem, "name": name})
        }
        "set-brightness" => {
            let subsystem = args
                .get(2)
                .cloned()
                .unwrap_or_else(|| "backlight".to_string());
            let name = args
                .get(3)
                .cloned()
                .unwrap_or_else(|| usage("set-brightness <subsystem> <name> <value>"));
            let value: u32 = arg(&args, 4, "brightness value");
            serde_json::json!({"cmd": "set_brightness", "subsystem": subsystem, "name": name, "value": value})
        }

        other => {
            eprintln!("Unknown command: {}", other);
            std::process::exit(1);
        }
    };

    match call(req) {
        Ok(resp) => {
            let ok = resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            if !ok {
                let err = resp
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown error");
                eprintln!("Error: {}", err);
                std::process::exit(1);
            }
            if let Some(data) = resp.get("data") {
                println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
            } else {
                println!("OK");
            }
        }
        Err(e) => {
            eprintln!("Failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn call(req: serde_json::Value) -> Result<serde_json::Value, String> {
    let mut stream =
        UnixStream::connect(SOCKET).map_err(|e| format!("connect {}: {}", SOCKET, e))?;

    let bytes = serde_json::to_vec(&req).map_err(|e| format!("serialize: {}", e))?;
    let len = (bytes.len() as u32).to_le_bytes();

    stream
        .write_all(&len)
        .map_err(|e| format!("write: {}", e))?;
    stream
        .write_all(&bytes)
        .map_err(|e| format!("write: {}", e))?;

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("read len: {}", e))?;
    let resp_len = u32::from_le_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_buf)
        .map_err(|e| format!("read resp: {}", e))?;

    serde_json::from_slice(&resp_buf).map_err(|e| format!("parse: {}", e))
}

fn arg<T: std::str::FromStr>(args: &[String], idx: usize, name: &str) -> T
where
    T::Err: std::fmt::Display,
{
    args.get(idx)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| usage(&format!("missing or invalid <{}>", name)))
}

fn usage(msg: &str) -> ! {
    eprintln!("Usage error: {}", msg);
    std::process::exit(1);
}

// Bring in serde_json for the ctl binary

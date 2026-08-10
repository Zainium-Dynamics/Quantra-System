/// quantra-ctl — Zainium OS service controller
///
/// Talks directly to the PID 1 control socket (`/run/quantra/control`).
/// Protocol: 4-byte LE u32 length prefix + JSON payload (both directions).
///
/// Install: `/overlayer/syshub/bin/quantra-ctl`
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

// ── Shared protocol types (mirrors control.rs, kept in sync manually) ────────

const SOCKET_PATH: &str = "/run/quantra/control";

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", content = "args")]
enum ControlCommand {
    Start {
        service: String,
    },
    Stop {
        service: String,
    },
    Restart {
        service: String,
    },
    Reload {
        service: String,
    },
    Kill {
        service: String,
    },
    Enable {
        service: String,
    },
    Disable {
        service: String,
    },
    Status {
        service: String,
    },
    Assay {
        service: String,
    },
    Tree,
    List,
    Metrics,
    Isolate {
        service: String,
        exit_isolation: bool,
    },
    Shutdown {
        reboot: bool,
    },
    Signal {
        service: String,
        signal: String,
    },
    IsStarted {
        service: String,
    },
    IsFailed {
        service: String,
    },
    Setenv {
        name: String,
        value: Option<String>,
    },
    AddDep {
        from: String,
        to: String,
        dep_type: String,
    },
    RmDep {
        from: String,
        to: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct CtlResponse {
    ok: bool,
    message: String,
    data: Option<serde_json::Value>,
}

// ── CLI Definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "quantra-ctl",
    version = env!("CARGO_PKG_VERSION"),
    author = "Ali Zain <alizain.x404@gmail.com>",
    about = "Zainium OS service controller — speaks directly to PID 1",
    after_help = "Tip: run as root. quantra-ctl talks to /run/quantra/control via JSON."
)]
struct Cli {
    /// Path to quantra control socket
    #[arg(long, default_value = SOCKET_PATH, global = true)]
    socket: String,

    /// Output raw JSON instead of styled text
    #[arg(long, short = 'j', global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start a service immediately
    Start {
        /// Service name (as defined in /overlayer/syshub/etc/quantra-system/services/)
        service: String,
    },
    /// Stop a service gracefully (SIGTERM → timeout → SIGKILL)
    Stop {
        /// Service name
        service: String,
    },
    /// Stop then restart a service
    Restart {
        /// Service name
        service: String,
    },
    /// Reload service config without stopping
    /// (sends reload_signal or runs reload_command from service definition)
    Reload {
        /// Service name
        service: String,
    },
    /// Force-kill a service immediately (SIGKILL + cgroup.kill)
    Kill {
        /// Service name
        service: String,
    },
    /// Enable a service to auto-start on boot
    Enable {
        /// Service name
        service: String,
    },
    /// Disable a service from auto-starting on boot
    Disable {
        /// Service name
        service: String,
    },
    /// Show status of a service (PID, RSS, uptime, AppArmor, log tail)
    Status {
        /// Service name
        service: String,
    },
    /// Deep health check (process, OOM score, AppArmor, log errors, RSS)
    Assay {
        /// Service name
        service: String,
    },
    /// Show dependency tree of all services
    Tree,
    /// List all services with state
    List,
    /// Show Prometheus-format metrics from /run/quantra/metrics
    Metrics,
    /// Isolate: stop all services except target and its dependencies
    Isolate {
        /// Service to keep running
        service: String,
        /// Exit isolation mode and restore all services
        #[arg(long)]
        exit: bool,
    },
    /// Initiate system shutdown or reboot
    Shutdown {
        /// Reboot instead of power off
        #[arg(long)]
        reboot: bool,
    },
    // ── New Phase D commands ─────────────────────────────────────────────────
    /// Send an arbitrary signal to a service process
    Signal {
        /// Signal name: HUP, USR1, USR2, QUIT, KILL, TERM, CONT, STOP, ALRM, INT
        signal: String,
        /// Service name
        service: String,
    },
    /// Exit 0 if service is running, 1 if not (for shell scripts and CI)
    #[command(name = "is-started")]
    IsStarted {
        /// Service name
        service: String,
    },
    /// Exit 0 if service has stopped/failed, 1 if running (for health checks)
    #[command(name = "is-failed")]
    IsFailed {
        /// Service name
        service: String,
    },
    /// Inject or remove an environment variable for future service spawns
    Setenv {
        /// Variable in NAME=VALUE format (omit value to unset: just NAME)
        assignment: String,
    },
    /// Add a runtime dependency edge between two services
    #[command(name = "add-dep")]
    AddDep {
        /// Dependency type: need | milestone | after
        dep_type: String,
        /// Service that gains the dependency
        from: String,
        /// Target service (the dependency)
        to: String,
    },
    /// Remove a runtime dependency edge between two services
    #[command(name = "rm-dep")]
    RmDep {
        /// Service to remove the dependency from
        from: String,
        /// Target service to remove
        to: String,
    },
    /// Show the resolved environment (environment.toml + environment.d) —
    /// the same one PID 1 sets on itself at boot. Reads straight from disk;
    /// does not talk to the control socket, so it works even if quantra
    /// isn't running (e.g. inspecting a mounted install target).
    Env {
        /// Root to resolve against (default: the live system)
        #[arg(long, env = oxidized_environment::ROOT_OVERRIDE_ENV, default_value = SYSHUB_ROOT)]
        root: std::path::PathBuf,
    },
}

/// The live syshub root on a booted Zainium system. quantra-ctl-owned —
/// oxidized-environment-core has no compiled-in root of its own.
const SYSHUB_ROOT: &str = "/overlayer/syshub";

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    if let Cmd::Env { root } = &cli.cmd {
        run_env(root, cli.json);
        return;
    }

    if !cli.json {
        print_banner();
    }

    let command = build_command(&cli.cmd);

    match send_command(&cli.socket, &command) {
        Ok(response) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&response).unwrap_or_default()
                );
            } else {
                render_response(&response, &cli.cmd);
            }
            if !response.ok {
                std::process::exit(1);
            }
        }
        Err(e) => {
            render_error(&e);
            std::process::exit(1);
        }
    }
}

fn build_command(cmd: &Cmd) -> ControlCommand {
    match cmd {
        Cmd::Start { service } => ControlCommand::Start {
            service: service.clone(),
        },
        Cmd::Stop { service } => ControlCommand::Stop {
            service: service.clone(),
        },
        Cmd::Restart { service } => ControlCommand::Restart {
            service: service.clone(),
        },
        Cmd::Reload { service } => ControlCommand::Reload {
            service: service.clone(),
        },
        Cmd::Kill { service } => ControlCommand::Kill {
            service: service.clone(),
        },
        Cmd::Enable { service } => ControlCommand::Enable {
            service: service.clone(),
        },
        Cmd::Disable { service } => ControlCommand::Disable {
            service: service.clone(),
        },
        Cmd::Status { service } => ControlCommand::Status {
            service: service.clone(),
        },
        Cmd::Assay { service } => ControlCommand::Assay {
            service: service.clone(),
        },
        Cmd::Tree => ControlCommand::Tree,
        Cmd::List => ControlCommand::List,
        Cmd::Metrics => ControlCommand::Metrics,
        Cmd::Isolate { service, exit } => ControlCommand::Isolate {
            service: service.clone(),
            exit_isolation: *exit,
        },
        Cmd::Shutdown { reboot } => ControlCommand::Shutdown { reboot: *reboot },
        Cmd::Signal { signal, service } => ControlCommand::Signal {
            service: service.clone(),
            signal: signal.clone(),
        },
        Cmd::IsStarted { service } => ControlCommand::IsStarted {
            service: service.clone(),
        },
        Cmd::IsFailed { service } => ControlCommand::IsFailed {
            service: service.clone(),
        },
        Cmd::Setenv { assignment } => {
            if let Some((name, value)) = assignment.split_once('=') {
                ControlCommand::Setenv {
                    name: name.to_string(),
                    value: Some(value.to_string()),
                }
            } else {
                ControlCommand::Setenv {
                    name: assignment.clone(),
                    value: None,
                }
            }
        }
        Cmd::AddDep { dep_type, from, to } => ControlCommand::AddDep {
            from: from.clone(),
            to: to.clone(),
            dep_type: dep_type.clone(),
        },
        Cmd::RmDep { from, to } => ControlCommand::RmDep {
            from: from.clone(),
            to: to.clone(),
        },
        Cmd::Env { .. } => unreachable!("Cmd::Env is handled locally in main() before this"),
    }
}

/// `quantra-ctl env` — resolve and print the environment straight from disk,
/// no socket round-trip. See oxidized-environment-core for the schema.
fn run_env(root: &Path, json: bool) {
    let env = oxidized_environment::resolve(root);
    let mut keys: Vec<_> = env.keys().collect();
    keys.sort();

    if json {
        let map: serde_json::Map<String, serde_json::Value> = keys
            .iter()
            .map(|k| ((*k).clone(), serde_json::Value::String(env[*k].clone())))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::Value::Object(map)).unwrap_or_default()
        );
    } else {
        print_banner();
        for k in keys {
            println!("  {k}={}", env[k]);
        }
    }
}

// ── Socket communication ──────────────────────────────────────────────────────

fn send_command(socket_path: &str, cmd: &ControlCommand) -> Result<CtlResponse> {
    if !Path::new(socket_path).exists() {
        anyhow::bail!(
            "Control socket not found at '{}'.\n\
             Is quantra (PID 1) running? Try: ls -la {}",
            socket_path,
            socket_path
        );
    }

    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("Cannot connect to control socket at '{}'", socket_path))?;

    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

    // Send: 4-byte LE length + JSON payload
    let payload = serde_json::to_vec(cmd).context("Failed to serialize command")?;
    let len = (payload.len() as u32).to_le_bytes();
    stream
        .write_all(&len)
        .context("Failed to send command length")?;
    stream
        .write_all(&payload)
        .context("Failed to send command payload")?;
    stream.flush().ok();

    // Receive: 4-byte LE length + JSON payload
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .context("Failed to read response length")?;
    let resp_len = u32::from_le_bytes(len_buf) as usize;
    if resp_len > 8 * 1024 * 1024 {
        anyhow::bail!("Response too large: {} bytes", resp_len);
    }
    let mut resp_buf = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_buf)
        .context("Failed to read response")?;

    serde_json::from_slice::<CtlResponse>(&resp_buf).context("Failed to parse response")
}

// ── Terminal rendering ────────────────────────────────────────────────────────

fn print_banner() {
    eprintln!("\x1b[38;5;39m ▄▀▀▀ ▄▀▀▄ ▄▀▀▄ ▄▀▀▄ ▀▄▀▀ ▄▀▀▄ \x1b[0m");
    eprintln!("\x1b[38;5;33m  ▀▀▄ ▀▄▄▀ █▄▄█ █  █  █  █▄▄▀ \x1b[0m");
    eprintln!(
        "\x1b[38;5;27m quantra-ctl\x1b[0m \x1b[38;5;244mv{}\x1b[0m — \x1b[38;5;39mZainium OS service controller\x1b[0m\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn render_response(resp: &CtlResponse, cmd: &Cmd) {
    let icon = if resp.ok {
        "\x1b[32m✓\x1b[0m"
    } else {
        "\x1b[31m✗\x1b[0m"
    };

    match cmd {
        Cmd::Status { .. } => render_status(resp),
        Cmd::Assay { .. } => render_assay(resp),
        Cmd::Tree => render_tree(resp),
        Cmd::List => render_list(resp),
        Cmd::Metrics => render_metrics(resp),
        Cmd::IsStarted { .. } => {
            // The daemon sends back exit_code in data; mirror that as process exit
            println!("{} {}", icon, resp.message);
            if let Some(data) = &resp.data {
                if let Some(code) = data["exit_code"].as_i64() {
                    std::process::exit(code as i32);
                }
            }
        }
        Cmd::IsFailed { .. } => {
            println!("{} {}", icon, resp.message);
            if let Some(data) = &resp.data {
                if let Some(code) = data["exit_code"].as_i64() {
                    std::process::exit(code as i32);
                }
            }
        }
        _ => {
            println!("{} {}", icon, resp.message);
        }
    }
}

fn render_status(resp: &CtlResponse) {
    if !resp.ok {
        println!("\x1b[31m✗\x1b[0m {}", resp.message);
        return;
    }
    let Some(data) = &resp.data else {
        println!("{}", resp.message);
        return;
    };

    // Header
    let name = data["name"].as_str().unwrap_or("?");
    let state = data["state"].as_str().unwrap_or("?");
    let state_color = if state == "running" {
        "\x1b[32m"
    } else {
        "\x1b[90m"
    };

    println!(
        "\n\x1b[1m● {}\x1b[0m   {}{}\x1b[0m",
        name, state_color, state
    );
    println!("  \x1b[38;5;244m─────────────────────────────────────────\x1b[0m");

    let pid = data["pid"].as_i64().unwrap_or(-1);
    let rss = data["rss_kb"].as_u64().unwrap_or(0);
    let uptime = data["uptime_seconds"].as_u64().unwrap_or(0);
    let enabled = data["enabled"].as_bool().unwrap_or(false);
    let apparmor = data["apparmor_profile"].as_str().unwrap_or("?");
    let cgroup = data["cgroup_path"].as_str().unwrap_or("?");

    println!(
        "  \x1b[38;5;39mPID\x1b[0m        {}",
        if pid > 0 {
            pid.to_string()
        } else {
            "—".into()
        }
    );
    println!(
        "  \x1b[38;5;39mUptime\x1b[0m     {}",
        format_duration(uptime)
    );
    println!("  \x1b[38;5;39mMemory\x1b[0m     {} KB", rss);
    println!("  \x1b[38;5;39mAppArmor\x1b[0m   {}", apparmor);
    println!("  \x1b[38;5;39mCgroup\x1b[0m     {}", cgroup);
    println!(
        "  \x1b[38;5;39mEnabled\x1b[0m    {}",
        if enabled {
            "\x1b[32myes\x1b[0m"
        } else {
            "\x1b[90mno\x1b[0m"
        }
    );

    if let Some(log_lines) = data["log_tail"].as_array() {
        if !log_lines.is_empty() {
            println!(
                "\n  \x1b[38;5;244m── Last {} log lines ──────────────────────\x1b[0m",
                log_lines.len()
            );
            for line in log_lines {
                let l = line.as_str().unwrap_or("");
                let color = if l.contains("ERROR") {
                    "\x1b[31m"
                } else if l.contains("WARN") {
                    "\x1b[33m"
                } else {
                    "\x1b[38;5;244m"
                };
                println!("  {}{}\x1b[0m", color, l);
            }
        }
    }
    println!();
}

fn render_assay(resp: &CtlResponse) {
    if !resp.ok {
        println!("\x1b[31m✗\x1b[0m {}", resp.message);
        return;
    }
    let Some(data) = &resp.data else {
        return;
    };

    let service = data["service"].as_str().unwrap_or("?");
    let overall = data["overall"].as_str().unwrap_or("?");
    let overall_color = match overall {
        "HEALTHY" => "\x1b[32m",
        "WARN" => "\x1b[33m",
        _ => "\x1b[31m",
    };

    println!(
        "\n\x1b[1m⚕  Assay: {}\x1b[0m   {}[{}]\x1b[0m\n",
        service, overall_color, overall
    );

    if let Some(checks) = data["checks"].as_object() {
        for (name, check) in checks {
            let ok = check["ok"].as_bool().unwrap_or(false);
            let detail = check["detail"].as_str().unwrap_or("");
            let icon = if ok {
                "\x1b[32m✓\x1b[0m"
            } else {
                "\x1b[31m✗\x1b[0m"
            };
            println!("  {} \x1b[38;5;39m{:<22}\x1b[0m  {}", icon, name, detail);
        }
    }
    println!();
}

fn render_tree(resp: &CtlResponse) {
    if !resp.ok {
        println!("\x1b[31m✗\x1b[0m {}", resp.message);
        return;
    }
    if let Some(data) = &resp.data {
        if let Some(tree) = data["tree"].as_str() {
            println!("\n\x1b[1;38;5;39m{}\x1b[0m\n", tree);
        }
    }
}

fn render_list(resp: &CtlResponse) {
    if !resp.ok {
        println!("\x1b[31m✗\x1b[0m {}", resp.message);
        return;
    }
    println!(
        "\n  \x1b[1m{:<24} {:<10} {}\x1b[0m",
        "SERVICE", "STATE", "PID"
    );
    println!("  \x1b[38;5;244m{}\x1b[0m", "─".repeat(44));
    if let Some(data) = &resp.data {
        if let Some(services) = data["services"].as_array() {
            for svc in services {
                let name = svc["name"].as_str().unwrap_or("?");
                let running = svc["running"].as_bool().unwrap_or(false);
                let pid = svc["pid"].as_i64().unwrap_or(-1);
                let state_str = if running {
                    "\x1b[32mrunning\x1b[0m"
                } else {
                    "\x1b[90mstopped\x1b[0m"
                };
                let pid_str = if pid > 0 {
                    pid.to_string()
                } else {
                    "—".into()
                };
                println!("  {:<24} {:<18} {}", name, state_str, pid_str);
            }
        }
    }
    println!();
}

fn render_metrics(resp: &CtlResponse) {
    if !resp.ok {
        println!("\x1b[31m✗\x1b[0m {}", resp.message);
        return;
    }
    if let Some(data) = &resp.data {
        if let Some(prom) = data["prometheus"].as_str() {
            println!("\n\x1b[38;5;39m{}\x1b[0m", prom);
        }
    }
}

fn render_error(e: &anyhow::Error) {
    eprintln!("\n\x1b[1;31m  ✗ quantra-ctl error\x1b[0m");
    eprintln!("  \x1b[38;5;244m─────────────────────────────────\x1b[0m");
    eprintln!("  \x1b[31m{}\x1b[0m", e);

    if e.to_string().contains("No such file") || e.to_string().contains("not found") {
        eprintln!("\n  \x1b[38;5;244mIs quantra (PID 1) running?");
        eprintln!("  Check: ls -la /run/quantra/control\x1b[0m");
    }
    eprintln!();
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

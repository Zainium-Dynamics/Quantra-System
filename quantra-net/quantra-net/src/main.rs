//! # quantra-net
//!
//! The Zainium OS network management CLI.
// Author: Ali-Zain <alizain.x404@gmail.com>

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use common::{
    EventType, FirewallPreset, FirewallZone, InterfaceDetail, InterfaceInfo, LinkState, NetCommand,
    NetEvent, NetResponse, NetworkConfig, OpenVpnConfig, RouteInfo, SOCKET_PATH, VpnConfig,
    VpnType, WifiSecurity, WireGuardConfig, WireGuardPeer, recv_message_sync, send_message_sync,
};
use serde_json::json;
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::str::FromStr;
use std::time::{Duration, Instant};

// ── CLI Definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "quantra-net",
    version = env!("CARGO_PKG_VERSION"),
    author = "Ali - Zain ",
    about = "Ultra-fast network management for Zainium OS",
    after_help = "Zainium tip: quantra-net talks directly to the kernel via quantra-netd daemon. Lightning fast."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::ValueEnum, Clone)]
enum ModeArg {
    Balanced,
    Performance,
    Powersave,
}

#[derive(Subcommand)]
enum Commands {
    /// List all network interfaces with their index, MAC address, IP addresses, and state
    Status {
        /// Show detailed information for a specific interface
        #[arg(long)]
        detail: Option<String>,
        /// Show verbose status including daemon connection counters
        #[arg(long)]
        verbose: bool,
        /// Output in machine-readable JSON format
        #[arg(long)]
        json: bool,
    },
    /// Scan and list network interfaces with connection status
    Scan,

    /// Get or set operation mode (`balanced`, `performance`, `powersave`)
    Mode {
        #[command(subcommand)]
        subcommand: ModeCommands,
    },

    /// Manage network links (up/down, add/remove IPs)
    #[command(subcommand)]
    Link(LinkCommands),
    /// Manage routing table entries
    #[command(subcommand)]
    Route(RouteCommands),
    /// Persist and inspect network configuration
    #[command(subcommand)]
    Config(ConfigCommands),
    /// WiFi management
    #[command(subcommand)]
    Wifi(WifiCommands),
    /// VPN management (WireGuard/OpenVPN)
    #[command(subcommand)]
    Vpn(VpnCommands),
    /// Firewall management (nftables backend)
    #[command(subcommand)]
    Firewall(FirewallCommands),
    /// Link quality and speed measurements
    #[command(subcommand)]
    Quality(QualityCommands),
    /// Auto-configure networking on first boot (DHCP + saved WiFi)
    Setup,
    /// Run network diagnostics (connectivity, routes, DNS, interfaces)
    Diagnose {
        /// Optional interface filter (e.g. eth0, wlp2s0)
        interface: Option<String>,
    },
    /// Read interface events once
    Monitor {
        /// Optional interface filter (e.g. eth0)
        interface: Option<String>,
    },
    /// Continuously watch for interface events
    Watch {
        /// Interface filter (e.g. eth0)
        #[arg(long)]
        interface: Option<String>,
    },
}

#[derive(Subcommand)]
enum ModeCommands {
    /// Print current mode
    Get,
    /// Set mode to Balanced/Performance/PowerSave
    Set {
        /// Mode name
        mode: ModeArg,
    },
}

#[derive(Subcommand)]
enum QualityCommands {
    Monitor {
        interface: String,
        #[arg(long)]
        duration: Option<u64>,
    },
    Speed {
        #[arg(long)]
        interface: Option<String>,
    },
    Bandwidth {
        interface: String,
        #[arg(long, default_value_t = 5)]
        duration: u64,
    },
}

#[derive(clap::ValueEnum, Clone)]
enum FirewallPresetArg {
    Home,
    Work,
    Public,
    Gaming,
}

impl From<FirewallPresetArg> for FirewallPreset {
    fn from(value: FirewallPresetArg) -> Self {
        match value {
            FirewallPresetArg::Home => FirewallPreset::Home,
            FirewallPresetArg::Work => FirewallPreset::Work,
            FirewallPresetArg::Public => FirewallPreset::Public,
            FirewallPresetArg::Gaming => FirewallPreset::Gaming,
        }
    }
}

#[derive(clap::ValueEnum, Clone)]
enum VpnTypeArg {
    Wireguard,
    Openvpn,
}

#[derive(Subcommand)]
enum VpnCommands {
    /// Create a WireGuard profile
    CreateWireguard {
        name: String,
        #[arg(long)]
        private_key: String,
        #[arg(long, default_value_t = 51820)]
        listen_port: u16,
        #[arg(long)]
        address: Option<String>,
        /// Peer format: public_key|allowed_ips_csv|endpoint(optional)|keepalive(optional)
        #[arg(long = "peer")]
        peers: Vec<String>,
    },
    /// Create an OpenVPN profile from a .ovpn file
    CreateOpenvpn {
        name: String,
        #[arg(long)]
        config_file: String,
    },
    Up {
        name: String,
    },
    Down {
        name: String,
    },
    Status,
    Show {
        name: String,
    },
    KillSwitch {
        enable: bool,
        #[arg(long)]
        interface: Option<String>,
    },
    /// Generic profile create helper (currently validates only)
    Create {
        name: String,
        #[arg(long)]
        vpn_type: VpnTypeArg,
    },
}

#[derive(Subcommand)]
enum FirewallCommands {
    Status,
    Preset {
        preset: FirewallPresetArg,
    },
    Allow {
        service: String,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        port: Option<u16>,
    },
    Block {
        port: u16,
        #[arg(long)]
        from: Option<String>,
    },
    Zone {
        interface: String,
        zone: String,
    },
    Nat {
        enable: bool,
        interface: String,
    },
}

#[derive(Subcommand)]
enum LinkCommands {
    /// Bring a network interface administratively UP
    Up {
        /// Name of the interface to bring up (e.g. eth0, wlan0, ens3)
        interface: String,
    },

    /// Bring a network interface administratively DOWN
    Down {
        /// Name of the interface to bring down (e.g. eth0, wlan0, ens3)
        interface: String,
    },
    /// Restart a network interface (down then up)
    Restart {
        /// Name of the interface to restart (e.g. eth0, wlan0, ens3)
        interface: String,
    },

    /// Add an IP address to a network interface
    Add {
        /// Name of the interface (e.g. eth0, wlan0)
        interface: String,

        /// IP address with CIDR notation (e.g., 192.168.1.100/24)
        ip_address: String,
    },

    /// Remove an IP address from a network interface
    Remove {
        /// Name of the interface (e.g. eth0, wlan0)
        interface: String,

        /// IP address with CIDR notation (e.g., 192.168.1.100/24)
        ip_address: String,
    },
    /// Acquire DHCP lease on an interface
    Dhcp {
        /// Interface to request lease on (e.g. eth0)
        interface: String,
    },
    /// Renew existing DHCP lease on an interface
    DhcpRenew {
        /// Interface to renew lease on (e.g. eth0)
        interface: String,
    },
    /// Release DHCP lease on an interface
    DhcpRelease {
        /// Interface to release lease from (e.g. eth0)
        interface: String,
    },
}

#[derive(clap::ValueEnum, Clone)]
enum WifiSecurityArg {
    Open,
    Wpa2Psk,
    Wpa3Psk,
    Wpa2Enterprise,
    Wpa3Enterprise,
}

impl From<WifiSecurityArg> for WifiSecurity {
    fn from(value: WifiSecurityArg) -> Self {
        match value {
            WifiSecurityArg::Open => WifiSecurity::Open,
            WifiSecurityArg::Wpa2Psk => WifiSecurity::Wpa2Psk,
            WifiSecurityArg::Wpa3Psk => WifiSecurity::Wpa3Psk,
            WifiSecurityArg::Wpa2Enterprise => WifiSecurity::Wpa2Enterprise,
            WifiSecurityArg::Wpa3Enterprise => WifiSecurity::Wpa3Enterprise,
        }
    }
}

#[derive(Subcommand)]
enum WifiCommands {
    /// Scan for available WiFi networks
    Scan {
        /// WiFi interface (e.g. wlp2s0)
        interface: String,
    },
    /// Connect to a WiFi network (saves the profile)
    Connect {
        /// WiFi interface (e.g. wlp2s0)
        interface: String,
        /// SSID to connect to
        ssid: String,
        /// Optional WiFi password (required for WPA/WPA2/WPA3 PSK)
        #[arg(long)]
        password: Option<String>,
        /// Security type (defaults to Open)
        #[arg(long, default_value = "Open")]
        security: WifiSecurityArg,
        /// Hidden SSID
        #[arg(long, default_value_t = false)]
        hidden: bool,
    },
    /// Disconnect from current WiFi
    Disconnect {
        /// WiFi interface (e.g. wlp2s0)
        interface: String,
    },
    /// List saved WiFi networks
    Saved,
    /// Forget a saved WiFi network (by SSID)
    Forget {
        /// SSID to forget
        ssid: String,
    },
    /// Enable/disable WiFi autoconnect for this interface
    AutoConnect {
        /// WiFi interface (e.g. wlp2s0)
        interface: String,
        /// true to enable, false to disable
        enable: bool,
    },
    /// Quick WiFi connectivity check
    Diagnose {
        /// WiFi interface (e.g. wlp2s0)
        interface: String,
    },
}

#[derive(Subcommand)]
enum RouteCommands {
    /// Add a route, for example: default via 192.168.1.1
    Add {
        destination: String,
        #[arg(long, short = 'v')]
        via: String,
        #[arg(long)]
        interface: Option<String>,
    },
    /// Delete a route
    Del {
        destination: String,
        #[arg(long, short = 'v')]
        via: Option<String>,
    },
    /// Show current kernel routes
    Show,
}

#[derive(Subcommand)]
enum ConfigCommands {
    Save,
    Load,
    Show,
}

// ── Entry Point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();
    print_zainium_header();

    if matches!(cli.command, Commands::Watch { .. }) {
        render_watch_banner(&cli.command);
        loop {
            let net_command = build_command(&cli.command)?;
            let response = send_command(net_command)?;
            render_response(response, &cli.command);
            std::thread::sleep(Duration::from_secs(2));
        }
    } else {
        let net_command = build_command(&cli.command)?;
        let response = send_command(net_command)?;
        render_response(response, &cli.command);
    }
    Ok(())
}

fn send_command(net_command: NetCommand) -> Result<NetResponse> {
    let deadline = Instant::now() + Duration::from_secs(10);

    let mut stream = loop {
        match UnixStream::connect(SOCKET_PATH) {
            Ok(stream) => break stream,
            Err(e) => {
                if Instant::now() >= deadline {
                    let connect_error: anyhow::Error = e.into();
                    render_daemon_not_running_error(&connect_error);
                    std::process::exit(1);
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    };

    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .context("Failed to set read timeout")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .context("Failed to set write timeout")?;

    if let Err(e) = send_message_sync(&mut stream, &net_command)
        .map_err(|e| anyhow::anyhow!("Failed to send command: {e}"))
    {
        render_connection_error(&e);
        std::process::exit(1);
    }
    match recv_message_sync(&mut stream)
        .map_err(|e| anyhow::anyhow!("Failed to parse response: {e}"))
    {
        Ok(resp) => Ok(resp),
        Err(e) => {
            render_connection_error(&e);
            std::process::exit(1);
        }
    }
}

// ── Command Builder ───────────────────────────────────────────────────────────

fn build_command(cmd: &Commands) -> Result<NetCommand> {
    match cmd {
        Commands::Status {
            detail,
            verbose,
            json,
        } => {
            if let Some(iface) = detail {
                validate_interface_name(iface)?;
                Ok(NetCommand::StatusDetail(iface.clone()))
            } else {
                Ok(NetCommand::Status {
                    verbose: *verbose || *json,
                })
            }
        }
        Commands::Scan => Ok(NetCommand::Status { verbose: false }),
        Commands::Mode { subcommand } => match subcommand {
            ModeCommands::Get => Ok(NetCommand::ModeGet),
            ModeCommands::Set { mode } => {
                let run_mode = match mode {
                    ModeArg::Balanced => common::RunMode::Balanced,
                    ModeArg::Performance => common::RunMode::Performance,
                    ModeArg::Powersave => common::RunMode::PowerSave,
                };
                Ok(NetCommand::ModeSet(run_mode))
            }
        },
        Commands::Link(link_cmd) => match link_cmd {
            LinkCommands::Up { interface } => {
                validate_interface_name(interface)?;
                Ok(NetCommand::LinkUp(interface.clone()))
            }
            LinkCommands::Down { interface } => {
                validate_interface_name(interface)?;
                Ok(NetCommand::LinkDown(interface.clone()))
            }
            LinkCommands::Restart { interface } => {
                validate_interface_name(interface)?;
                Ok(NetCommand::LinkRestart(interface.clone()))
            }
            LinkCommands::Add {
                interface,
                ip_address,
            } => {
                validate_interface_name(interface)?;
                validate_ip_address(ip_address)?;
                Ok(NetCommand::LinkAdd(interface.clone(), ip_address.clone()))
            }
            LinkCommands::Remove {
                interface,
                ip_address,
            } => {
                validate_interface_name(interface)?;
                validate_ip_address(ip_address)?;
                Ok(NetCommand::LinkRemove(
                    interface.clone(),
                    ip_address.clone(),
                ))
            }
            LinkCommands::Dhcp { interface } => {
                validate_interface_name(interface)?;
                Ok(NetCommand::DhcpAcquire(interface.clone()))
            }
            LinkCommands::DhcpRenew { interface } => {
                validate_interface_name(interface)?;
                Ok(NetCommand::DhcpRenew(interface.clone()))
            }
            LinkCommands::DhcpRelease { interface } => {
                validate_interface_name(interface)?;
                Ok(NetCommand::DhcpRelease(interface.clone()))
            }
        },
        Commands::Route(route_cmd) => match route_cmd {
            RouteCommands::Add {
                destination,
                via,
                interface,
            } => {
                validate_destination(destination)?;
                validate_gateway(via)?;
                if let Some(iface) = interface {
                    validate_interface_name(iface)?;
                }
                Ok(NetCommand::RouteAdd {
                    destination: destination.clone(),
                    gateway: via.clone(),
                    interface: interface.clone(),
                })
            }
            RouteCommands::Del { destination, via } => {
                validate_destination(destination)?;
                if let Some(gw) = via {
                    validate_gateway(gw)?;
                }
                Ok(NetCommand::RouteDel {
                    destination: destination.clone(),
                    gateway: via.clone(),
                })
            }
            RouteCommands::Show => Ok(NetCommand::RouteShow),
        },
        Commands::Config(config_cmd) => match config_cmd {
            ConfigCommands::Save => Ok(NetCommand::ConfigSave),
            ConfigCommands::Load => Ok(NetCommand::ConfigLoad),
            ConfigCommands::Show => Ok(NetCommand::ConfigShow),
        },
        Commands::Wifi(wifi_cmd) => match wifi_cmd {
            WifiCommands::Scan { interface } => {
                validate_interface_name(interface)?;
                Ok(NetCommand::WifiScan {
                    interface: interface.clone(),
                })
            }
            WifiCommands::Connect {
                interface,
                ssid,
                password,
                security,
                hidden,
            } => {
                validate_interface_name(interface)?;
                validate_ssid(ssid)?;
                if matches!(
                    security,
                    WifiSecurityArg::Wpa2Psk
                        | WifiSecurityArg::Wpa3Psk
                        | WifiSecurityArg::Wpa2Enterprise
                        | WifiSecurityArg::Wpa3Enterprise
                ) && password.is_none()
                {
                    anyhow::bail!("Password is required for this security mode");
                }
                Ok(NetCommand::WifiConnect {
                    interface: interface.clone(),
                    ssid: ssid.clone(),
                    password: password.clone(),
                    security: WifiSecurity::from(security.clone()),
                    hidden: *hidden,
                })
            }
            WifiCommands::Disconnect { interface } => {
                validate_interface_name(interface)?;
                Ok(NetCommand::WifiDisconnect {
                    interface: interface.clone(),
                })
            }
            WifiCommands::Saved => Ok(NetCommand::WifiSaved),
            WifiCommands::Forget { ssid } => {
                validate_ssid(ssid)?;
                Ok(NetCommand::WifiForget { ssid: ssid.clone() })
            }
            WifiCommands::AutoConnect { interface, enable } => {
                validate_interface_name(interface)?;
                Ok(NetCommand::WifiAutoConnect {
                    enable: *enable,
                    interface: interface.clone(),
                })
            }
            WifiCommands::Diagnose { interface } => {
                validate_interface_name(interface)?;
                Ok(NetCommand::WifiDiagnose {
                    interface: interface.clone(),
                })
            }
        },
        Commands::Setup => Ok(NetCommand::AutoConfigure),
        Commands::Diagnose { interface } => Ok(NetCommand::Diagnose {
            interface: interface.clone(),
        }),
        Commands::Quality(q) => match q {
            QualityCommands::Monitor {
                interface,
                duration,
            } => {
                validate_interface_name(interface)?;
                Ok(NetCommand::QualityMonitor {
                    interface: interface.clone(),
                    duration: *duration,
                })
            }
            QualityCommands::Speed { interface } => Ok(NetCommand::SpeedTest {
                interface: interface.clone(),
            }),
            QualityCommands::Bandwidth {
                interface,
                duration,
            } => {
                validate_interface_name(interface)?;
                Ok(NetCommand::BandwidthTest {
                    interface: interface.clone(),
                    duration: *duration,
                })
            }
        },
        Commands::Vpn(vpn) => match vpn {
            VpnCommands::CreateWireguard {
                name,
                private_key,
                listen_port,
                address,
                peers,
            } => {
                let parsed_peers = parse_wireguard_peers(peers)?;
                Ok(NetCommand::VpnCreate {
                    name: name.clone(),
                    vpn_type: VpnType::WireGuard,
                    config: VpnConfig::WireGuard(WireGuardConfig {
                        private_key: private_key.clone(),
                        peers: parsed_peers,
                        listen_port: *listen_port,
                        address: address.clone(),
                    }),
                })
            }
            VpnCommands::CreateOpenvpn { name, config_file } => {
                let ovpn = std::fs::read_to_string(config_file).with_context(|| {
                    format!("Failed to read OpenVPN config file '{}'", config_file)
                })?;
                Ok(NetCommand::VpnCreate {
                    name: name.clone(),
                    vpn_type: VpnType::OpenVPN,
                    config: VpnConfig::OpenVPN(OpenVpnConfig { ovpn }),
                })
            }
            VpnCommands::Up { name } => Ok(NetCommand::VpnUp { name: name.clone() }),
            VpnCommands::Down { name } => Ok(NetCommand::VpnDown { name: name.clone() }),
            VpnCommands::Status => Ok(NetCommand::VpnStatus),
            VpnCommands::Show { name } => Ok(NetCommand::VpnShow { name: name.clone() }),
            VpnCommands::KillSwitch { enable, interface } => Ok(NetCommand::VpnKillSwitch {
                enable: *enable,
                interface: interface.clone(),
            }),
            VpnCommands::Create { name, vpn_type } => {
                let cfg = match vpn_type {
                    VpnTypeArg::Wireguard => VpnConfig::WireGuard(WireGuardConfig {
                        private_key: String::new(),
                        peers: Vec::new(),
                        listen_port: 51820,
                        address: None,
                    }),
                    VpnTypeArg::Openvpn => VpnConfig::OpenVPN(OpenVpnConfig {
                        ovpn: String::new(),
                    }),
                };
                Ok(NetCommand::VpnCreate {
                    name: name.clone(),
                    vpn_type: match vpn_type {
                        VpnTypeArg::Wireguard => VpnType::WireGuard,
                        VpnTypeArg::Openvpn => VpnType::OpenVPN,
                    },
                    config: cfg,
                })
            }
        },
        Commands::Firewall(f) => match f {
            FirewallCommands::Status => Ok(NetCommand::FirewallStatus),
            FirewallCommands::Preset { preset } => Ok(NetCommand::FirewallPreset {
                preset: FirewallPreset::from(preset.clone()),
            }),
            FirewallCommands::Allow {
                service,
                from,
                port,
            } => Ok(NetCommand::FirewallAllow {
                service: service.clone(),
                from: from.clone(),
                port: *port,
            }),
            FirewallCommands::Block { port, from } => Ok(NetCommand::FirewallBlock {
                port: *port,
                from: from.clone(),
            }),
            FirewallCommands::Zone { interface, zone } => {
                validate_interface_name(interface)?;
                let z = parse_zone(zone)?;
                Ok(NetCommand::FirewallZoneAdd {
                    interface: interface.clone(),
                    zone: z,
                })
            }
            FirewallCommands::Nat { enable, interface } => {
                validate_interface_name(interface)?;
                Ok(NetCommand::FirewallNat {
                    enable: *enable,
                    interface: interface.clone(),
                })
            }
        },
        Commands::Monitor { interface } | Commands::Watch { interface } => {
            if let Some(iface) = interface {
                validate_interface_name(iface)?;
            }
            Ok(NetCommand::Monitor {
                interface: interface.clone(),
            })
        }
    }
}

// ── Validation ────────────────────────────────────────────────────────────────

fn validate_interface_name(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("Interface name cannot be empty");
    }
    if name.len() > 16 {
        anyhow::bail!("Interface name too long (max 16 characters)");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!("Interface name contains invalid characters (use alphanumeric, -, or _)");
    }
    Ok(())
}

fn validate_ip_address(ip_cidr: &str) -> Result<()> {
    let parts: Vec<&str> = ip_cidr.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid CIDR format. Expected: <ip>/<prefix> (e.g., 192.168.1.100/24)");
    }

    let ip = IpAddr::from_str(parts[0])
        .map_err(|_| anyhow::anyhow!("Invalid IP address: {}", parts[0]))?;

    let prefix: u8 = parts[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid prefix length: {}", parts[1]))?;

    match ip {
        IpAddr::V4(_) => {
            if prefix > 32 {
                anyhow::bail!("IPv4 prefix must be between 0 and 32");
            }
        }
        IpAddr::V6(_) => {
            if prefix > 128 {
                anyhow::bail!("IPv6 prefix must be between 0 and 128");
            }
        }
    }

    Ok(())
}

fn validate_ssid(ssid: &str) -> Result<()> {
    if ssid.trim().is_empty() {
        anyhow::bail!("SSID cannot be empty");
    }
    // SSID max length is 32 bytes for WiFi. Keep it simple for CLI validation.
    if ssid.len() > 32 {
        anyhow::bail!("SSID too long (max 32 characters)");
    }
    Ok(())
}

fn parse_wireguard_peers(peers: &[String]) -> Result<Vec<WireGuardPeer>> {
    let mut out = Vec::new();
    for p in peers {
        let parts: Vec<&str> = p.split('|').collect();
        if parts.len() < 2 {
            anyhow::bail!(
                "Invalid --peer format '{}'. Expected public_key|allowed_ips_csv|endpoint(optional)|keepalive(optional)",
                p
            );
        }
        let public_key = parts[0].to_string();
        let allowed_ips = parts[1]
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        let endpoint = parts
            .get(2)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let persistent_keepalive = parts
            .get(3)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .and_then(|s| s.parse::<u16>().ok());
        out.push(WireGuardPeer {
            public_key,
            allowed_ips,
            endpoint,
            persistent_keepalive,
        });
    }
    Ok(out)
}

fn parse_zone(zone: &str) -> Result<FirewallZone> {
    match zone.to_ascii_lowercase().as_str() {
        "public" => Ok(FirewallZone::Public),
        "home" => Ok(FirewallZone::Home),
        "work" => Ok(FirewallZone::Work),
        "trusted" => Ok(FirewallZone::Trusted),
        _ => anyhow::bail!("Invalid zone '{}'. Use: public|home|work|trusted", zone),
    }
}

fn validate_destination(destination: &str) -> Result<()> {
    if destination == "default" {
        return Ok(());
    }
    validate_ip_address(destination)
}

fn validate_gateway(gateway: &str) -> Result<()> {
    let ip = IpAddr::from_str(gateway)
        .map_err(|_| anyhow::anyhow!("Invalid gateway IP address: {gateway}"))?;
    if matches!(ip, IpAddr::V6(_)) {
        anyhow::bail!("IPv6 gateway is not supported yet");
    }
    Ok(())
}

// ── Terminal Renderer ─────────────────────────────────────────────────────────

mod ansi {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const GREEN: &str = "\x1b[32m";
    pub const RED: &str = "\x1b[31m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const CYAN: &str = "\x1b[36m";
    pub const WHITE: &str = "\x1b[37m";
}

fn print_zainium_header() {
    use ansi::*;
    println!();
    println!(
        "{}{}{}Zainium is on the case...{}{}",
        BOLD, CYAN, WHITE, RESET, BOLD
    );
    println!("{}{}", RESET, DIM);
}

fn render_response(response: NetResponse, cmd: &Commands) {
    match response {
        NetResponse::Status(interfaces, mode, daemon_status) => {
            if let Commands::Status { json: true, .. } = cmd {
                render_status_json(&interfaces, mode, daemon_status);
            } else if matches!(cmd, Commands::Scan) {
                render_scan_view(&interfaces);
            } else {
                if let Some(st) = daemon_status {
                    println!("Daemon status (verbose):");
                    println!("  Mode             : {:?}", st.mode);
                    println!("  Active clients   : {}", st.active_connections);
                    println!("  Total clients    : {}", st.total_connections);
                    println!("  Interfaces       : {}", st.interface_count);
                    println!("  Uptime           : {} seconds", st.uptime_seconds);
                    println!("  Firewall enabled : {}", st.firewall_enabled);
                    println!("  DNS cache entries: {}", st.dns_cache_entries);
                    println!();
                }
                render_status_table(&interfaces, mode);
                print_tip("Use `quantra-net link up <interface>` to bring any interface online.");
            }
        }
        NetResponse::StatusDetail(detail) => {
            render_detail_view(&detail);
            print_tip(&format!(
                "Use `quantra-net link down {}` to disconnect this interface.",
                detail.name
            ));
        }
        NetResponse::DhcpLease(lease) => {
            render_dhcp_lease(
                &lease.interface,
                lease.ip_cidr.as_deref(),
                lease.gateway.as_deref(),
                &lease.dns_servers,
            );
            print_tip("Use `quantra-net config save` to make this permanent.");
        }
        NetResponse::Routes(routes) => {
            render_routes(&routes);
            print_tip("Use `quantra-net route add` to add custom routes.");
        }
        NetResponse::Config(config) => {
            render_config(&config);
            print_tip("Use `quanta-net config load` to apply the saved config.");
        }
        NetResponse::Events(events) => {
            render_events(&events);
            if matches!(cmd, Commands::Monitor { .. }) {
                print_tip("Use `quantra-net watch --interface <iface>` for continuous updates.");
            }
        }
        NetResponse::WifiNetworks(networks) => {
            println!("→ WiFi networks found: {}\n", networks.len());
            for n in networks {
                println!(
                    "  - {}  [{}]  signal={}dBm  freq={}MHz  {}",
                    n.ssid,
                    n.bssid,
                    n.signal,
                    n.frequency,
                    if n.connected { "(connected)" } else { "" }
                );
            }
            println!();
        }
        NetResponse::WifiSaved(saved) => {
            println!("→ Saved WiFi networks:\n");
            for s in saved {
                println!(
                    "  - {}  security={:?}  autoconnect={}",
                    s.ssid, s.security, s.autoconnect
                );
            }
            println!();
        }
        NetResponse::Quality(metrics) => {
            println!("→ Connection quality:\n");
            println!("  signal: {} dBm", metrics.signal_strength);
            println!("  bitrate: {} Mbps", metrics.bitrate);
            println!("  packet_loss: {:.2}%", metrics.packet_loss * 100.0);
            println!("  stability: {:.2}", metrics.stability);
            if let Some(rec) = metrics.recommendation {
                println!("\n  recommendation: {rec}");
            }
            println!();
        }
        NetResponse::VpnStatus(status) => {
            println!("→ VPN status:\n");
            for s in status {
                println!(
                    "  - {}  type={:?}  up={}  iface={}",
                    s.name,
                    s.vpn_type,
                    s.up,
                    s.interface.as_deref().unwrap_or("-")
                );
            }
            println!();
        }
        NetResponse::VpnProfile(p) => {
            println!("→ VPN profile: {}\n", p.name);
            println!("  type: {:?}", p.vpn_type);
            println!("  up: {}", p.up);
            println!("  {}", p.summary);
            println!();
        }
        NetResponse::FirewallStatus(status) => {
            println!("→ Firewall status:\n");
            println!(
                "  preset: {}",
                status
                    .active_preset
                    .as_ref()
                    .map(|p| format!("{p:?}"))
                    .unwrap_or_else(|| "none".to_string())
            );
            println!("  nat_enabled: {}", status.nat_enabled);
            if !status.zones.is_empty() {
                println!("  zones:");
                for (iface, zone) in status.zones {
                    println!("    - {iface}: {zone:?}");
                }
            }
            println!();
        }
        NetResponse::NetnsList(names) => {
            println!("→ Network namespaces:\n");
            for n in names {
                println!("  - {n}");
            }
            println!();
        }
        NetResponse::Batch(responses) => {
            println!("→ Batch results: {}\n", responses.len());
            for r in responses {
                match r {
                    NetResponse::Success(m) => println!("  ✓ {m}"),
                    NetResponse::Error(m) => println!("  ✗ {m}"),
                    other => println!("  - {other:?}"),
                }
            }
            println!();
        }
        NetResponse::Success(message) => {
            if message.contains("restarted") {
                // Extract interface name from message
                if let Some(start) = message.find("'")
                    && let Some(end) = message[start + 1..].find("'")
                {
                    let iface = &message[start + 1..start + 1 + end];
                    render_link_restart_feedback(iface);
                    return;
                }
            }
            render_success(&message);
            if message.contains("UP") {
                print_tip("Network changes take effect instantly. No reboot needed.");
            } else if message.contains("DOWN") {
                print_tip("Use `quantra-net link up` to bring the interface back online.");
            } else if message.contains("added") {
                print_tip("Use `quantra-net link remove` to remove this IP address.");
            } else if message.contains("removed") {
                print_tip("The interface remains UP even without this IP address.");
            }
        }
        // New response types from v2
        NetResponse::Ipv6Lease(lease) => {
            println!("IPv6 Lease:");
            println!("  Interface : {}", lease.interface);
            if let Some(ip) = &lease.ip_cidr {
                println!("  Address   : {}", ip);
            }
            if let Some(gw) = &lease.gateway {
                println!("  Gateway   : {}", gw);
            }
            if !lease.dns_servers.is_empty() {
                println!("  DNS       : {}", lease.dns_servers.join(", "));
            }
        }
        NetResponse::VlanInfo(info) | NetResponse::BridgeInfo(info) => {
            println!("{}", info);
        }
        NetResponse::DnsResult(addrs) => {
            for addr in &addrs {
                println!("{}", addr);
            }
        }
        NetResponse::DnsStatus(status) => {
            println!("DNS Status:");
            println!("  Servers   : {}", status.servers.join(", "));
            println!(
                "  DoT       : {}",
                if status.dot_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!("  DoT servers: {}", status.dot_servers.join(", "));
            println!("  Cache     : {} entries", status.cache_entries);
        }
        NetResponse::Error(message) => render_error(&message),
        NetResponse::Mode(mode) => {
            println!("Current mode: {:?}", mode);
        }
        NetResponse::DaemonStatus(st) => {
            println!("Zainium Network Daemon");
            println!("\n  Status           : Running");
            println!("  Mode             : {:?}", st.mode);
            println!("  Uptime           : {} seconds", st.uptime_seconds);
            println!("  Interfaces       : {}", st.interface_count);
            println!("  Active clients   : {}", st.active_connections);
            println!("  Total clients    : {}", st.total_connections);
            println!(
                "  Firewall         : {}",
                if st.firewall_enabled {
                    "Enabled"
                } else {
                    "Disabled"
                }
            );
            println!("  DNS Cache        : {} entries", st.dns_cache_entries);
            println!("\n[ OK ] quantra-netd is healthy and protecting the network.");
        }
    }
}

fn render_status_json(
    interfaces: &[InterfaceInfo],
    mode: common::RunMode,
    daemon_status: Option<common::DaemonStatus>,
) {
    let mut interfaces_json = Vec::new();
    for iface in interfaces {
        let mut iface_json = json!({
            "name": &iface.name,
            "index": iface.index,
            "mac": &iface.mac,
            "state": format!("{:?}", iface.state),
            "ip_addresses": &iface.ip_addresses,
        });
        if let Some(speed) = iface.speed_mbps {
            iface_json["speed_mbps"] = json!(speed);
        }
        if let Some(stats) = &iface.statistics {
            iface_json["statistics"] = json!({
                "rx_bytes": stats.rx_bytes,
                "tx_bytes": stats.tx_bytes,
                "rx_packets": stats.rx_packets,
                "tx_packets": stats.tx_packets,
                "rx_errors": stats.rx_errors,
                "tx_errors": stats.tx_errors,
                "rx_dropped": stats.rx_dropped,
                "tx_dropped": stats.tx_dropped,
            });
        }
        interfaces_json.push(iface_json);
    }

    let mut result = json!({
        "mode": format!("{:?}", mode),
        "interface_count": interfaces.len(),
        "interfaces": interfaces_json,
    });

    if let Some(st) = daemon_status {
        result["daemon"] = json!({
            "mode": format!("{:?}", st.mode),
            "uptime_seconds": st.uptime_seconds,
            "active_connections": st.active_connections,
            "total_connections": st.total_connections,
            "firewall_enabled": st.firewall_enabled,
            "dns_cache_entries": st.dns_cache_entries,
            "interface_count": st.interface_count,
        });
    }

    if let Ok(output) = serde_json::to_string_pretty(&result) {
        println!("{}", output);
    }
}

fn render_watch_banner(cmd: &Commands) {
    use ansi::*;
    if let Commands::Watch { interface } = cmd {
        println!(
            "{}→ Monitoring {} for changes... (Ctrl+C to stop){}",
            DIM,
            interface.as_deref().unwrap_or("all interfaces"),
            RESET
        );
        println!();
    }
}

fn render_scan_view(interfaces: &[InterfaceInfo]) {
    println!("Scanning network interfaces...");
    println!();

    let active_count = interfaces
        .iter()
        .filter(|i| i.state == LinkState::Up)
        .count();

    for iface in interfaces {
        let status = match iface.state {
            LinkState::Up => {
                if iface.name == "lo" {
                    "Local loopback"
                } else {
                    "Connected"
                }
            }
            LinkState::Down => "Disconnected",
            LinkState::Unknown => "Unknown",
        };

        let speed = iface
            .speed_mbps
            .map(|s| format!(" ({:.0} Mbps)", s))
            .unwrap_or_default();

        println!("  {}   → {} {}", iface.name, status, speed);
    }

    println!();
    println!("Found {} active interfaces.", active_count);
}

fn render_status_table(interfaces: &[InterfaceInfo], mode: common::RunMode) {
    println!("Network Status");
    println!();
    println!("Current Mode: {:?}", mode);
    println!();
    println!("  Interface     Status     IP Address          Speed     Traffic");
    println!("  ───────────────────────────────────────────────────────────────");

    for iface in interfaces {
        let status = match iface.state {
            LinkState::Up => "Up",
            LinkState::Down => "Down",
            LinkState::Unknown => "Unknown",
        };

        let ip = if iface.ip_addresses.is_empty() {
            "-".to_string()
        } else {
            iface.ip_addresses[0].clone()
        };

        // Placeholder for speed and traffic
        let speed = iface
            .speed_mbps
            .map(|s| format!("{:.2} Mbps", s))
            .unwrap_or_else(|| "-".to_string());

        let traffic = iface
            .statistics
            .as_ref()
            .map(|s| format!("RX: {} B | TX: {} B", s.rx_bytes, s.tx_bytes))
            .unwrap_or_else(|| "-".to_string());

        println!(
            "  {:<12}  {:<8}  {:<18}  {:<8}  {}",
            iface.name, status, ip, speed, traffic
        );
    }

    println!();
}

fn render_link_restart_feedback(interface: &str) {
    use ansi::*;
    println!("{}→ Restarting interface {}...{}", DIM, interface, RESET);
    println!();
    println!("  → Bringing down {}...", interface);
    println!("  → Releasing DHCP lease...");
    println!("  → Bringing up {}...", interface);
    println!("  → Renewing IP address...");
    println!();
    println!(
        "{}{}✓ {} restarted successfully.{}",
        BOLD, GREEN, interface, RESET
    );
}

fn render_detail_view(detail: &InterfaceDetail) {
    use ansi::*;

    println!("{}→ Analyzing interface {}...{}", DIM, detail.name, RESET);
    println!();
    println!(
        "{}{}Interface Details: {}{}",
        BOLD, CYAN, detail.name, RESET
    );
    println!("{}", "═".repeat(60));
    println!();

    println!("  {}Basic Information:{}", BOLD, RESET);
    let (state_icon, state_colour) = match detail.state {
        LinkState::Up => ("● UP", GREEN),
        LinkState::Down => ("○ DOWN", RED),
        LinkState::Unknown => ("? UNKNOWN", YELLOW),
    };
    println!("  ├─ Index: {}{}", DIM, detail.index);
    println!("  ├─ MAC Address: {}{}", DIM, detail.mac);
    println!("  ├─ State: {}{}{}{}", state_colour, state_icon, RESET, DIM);
    if let Some(mtu) = detail.mtu {
        println!("  ├─ MTU: {}{}", DIM, mtu);
    }
    if let Some(iface_type) = &detail.iface_type {
        println!("  ├─ Type: {}{}", DIM, iface_type);
    }
    if let Some(qdisc) = &detail.qdisc {
        println!("  ├─ QDisc: {}{}", DIM, qdisc);
    }
    if let Some(group) = detail.group {
        println!("  └─ Group: {}{}", DIM, group);
    }
    println!();

    if !detail.flags.is_empty() {
        println!("  {}Flags:{}", BOLD, RESET);
        for (i, flag) in detail.flags.iter().enumerate() {
            let prefix = if i == detail.flags.len() - 1 {
                "  └─"
            } else {
                "  ├─"
            };
            println!("{} {}{}", prefix, DIM, flag);
        }
        println!();
    }

    if !detail.ip_addresses.is_empty() {
        println!("  {}IP Addresses:{}", BOLD, RESET);
        for (i, ip) in detail.ip_addresses.iter().enumerate() {
            let prefix = if i == detail.ip_addresses.len() - 1 {
                "  └─"
            } else {
                "  ├─"
            };
            let ip_type = if ip.contains(':') { "IPv6" } else { "IPv4" };
            println!("{} {}{} ({})", prefix, DIM, ip, ip_type);
        }
        println!();
    }

    if let Some(stats) = &detail.statistics {
        println!("  {}Statistics:{}", BOLD, RESET);
        println!("  ├─ RX Packets: {}{}", DIM, stats.rx_packets);
        println!("  ├─ TX Packets: {}{}", DIM, stats.tx_packets);
        println!("  ├─ RX Bytes: {}{} MB", DIM, stats.rx_bytes / 1_000_000);
        println!("  ├─ TX Bytes: {}{} MB", DIM, stats.tx_bytes / 1_000_000);
        println!("  ├─ RX Errors: {}{}", DIM, stats.rx_errors);
        println!("  ├─ TX Errors: {}{}", DIM, stats.tx_errors);
        println!("  ├─ RX Dropped: {}{}", DIM, stats.rx_dropped);
        println!("  └─ TX Dropped: {}{}", DIM, stats.tx_dropped);
        println!();
    }

    if let Some(wireless) = &detail.wireless {
        println!("  {}Wireless Information:{}", BOLD, RESET);
        println!("  ├─ SSID: {}{}", DIM, wireless.ssid);
        println!(
            "  ├─ Signal Strength: {}{} dBm",
            DIM, wireless.signal_strength
        );
        println!("  ├─ Quality: {}{}%", DIM, wireless.quality);
        println!("  ├─ Frequency: {}{} GHz", DIM, wireless.frequency);
        println!("  └─ Channel: {}{}", DIM, wireless.channel);
        println!();
    }
}

fn render_dhcp_lease(
    interface: &str,
    ip_cidr: Option<&str>,
    gateway: Option<&str>,
    dns: &[String],
) {
    use ansi::*;
    println!(
        "{}→ Acquiring IP via DHCP on {}...{}",
        DIM, interface, RESET
    );
    println!();
    println!("  DHCPDISCOVER ................................ {}", GREEN);
    println!("  DHCPOFFER ................................... {}", GREEN);
    println!("  DHCPREQUEST ................................. {}", GREEN);
    println!(
        "  DHCPACK ..................................... {}✓{}",
        GREEN, RESET
    );
    println!();
    if let Some(ip) = ip_cidr {
        println!("{}✓ Obtained IP:{} {}", GREEN, RESET, ip);
    }
    if let Some(gw) = gateway {
        println!("{}✓ Gateway:{} {}", GREEN, RESET, gw);
    }
    if !dns.is_empty() {
        println!("{}✓ DNS:{} {}", GREEN, RESET, dns.join(", "));
    }
    println!();
}

fn render_routes(routes: &[RouteInfo]) {
    use ansi::*;
    println!("{}→ Kernel IP routing table:{}\n", DIM, RESET);
    println!(
        "{}{:<18} {:<16} {:<10}{}",
        BOLD, "Destination", "Gateway", "Iface", RESET
    );
    println!("{}", "─".repeat(52));
    for route in routes {
        println!(
            "{:<18} {:<16} {:<10}",
            route.destination,
            route.gateway.as_deref().unwrap_or("0.0.0.0"),
            route.interface.as_deref().unwrap_or("-")
        );
    }
    println!();
}

fn render_config(config: &NetworkConfig) {
    use ansi::*;
    println!("{}Saved configuration:{}\n", BOLD, RESET);
    for (name, iface) in &config.interfaces {
        println!("{}{}{} ({})", CYAN, name, RESET, iface.state);
        for addr in &iface.addresses {
            println!("  - {}", addr);
        }
        if let Some(gw) = &iface.gateway {
            println!("  gateway: {}", gw);
        }
        if !iface.dns.is_empty() {
            println!("  dns: {}", iface.dns.join(", "));
        }
    }
    if !config.routes.is_empty() {
        println!("\n{}Routes:{} ", BOLD, RESET);
        for r in &config.routes {
            println!(
                "  - {} via {} ({})",
                r.destination,
                r.gateway.as_deref().unwrap_or("-"),
                r.interface.as_deref().unwrap_or("-")
            );
        }
    }
    println!();
}

fn render_events(events: &[NetEvent]) {
    use ansi::*;
    if events.is_empty() {
        println!(
            "{}No interface changes detected in the last interval.{}",
            DIM, RESET
        );
        return;
    }
    for event in events {
        let icon = match event.event_type {
            EventType::LinkUp => "●",
            EventType::LinkDown => "○",
            EventType::AddressAdded => "➕",
            EventType::AddressRemoved => "➖",
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        println!("[{}] {} {} {}", now, icon, event.interface, event.details);
    }
    println!();
}

fn render_success(message: &str) {
    use ansi::*;
    println!();
    println!("  {}{}✓  {}{}", BOLD, GREEN, message, RESET);
    println!();
}

fn render_error(message: &str) {
    use ansi::*;
    eprintln!();
    eprintln!("  {}{}✗  {}{}", BOLD, RED, message, RESET);
    eprintln!();

    if message.contains("not found") {
        eprintln!(
            "{}Zainium tip: Use `quantra-net status` to see available interfaces.{}",
            DIM, RESET
        );
        eprintln!();
    } else if message.contains("Permission denied") || message.contains("CAP_NET_ADMIN") {
        eprintln!(
            "{}Zainium tip: Run with sudo or grant capabilities using:{}",
            DIM, RESET
        );
        eprintln!("  sudo setcap cap_net_admin+ep /usr/bin/quantra-net");
        eprintln!();
    } else if message.contains("Invalid IP") {
        eprintln!(
            "{}Zainium tip: Use standard CIDR notation for IP addresses.{}",
            DIM, RESET
        );
        eprintln!();
    }

    std::process::exit(1);
}

fn render_daemon_not_running_error(e: &anyhow::Error) {
    use ansi::*;
    eprintln!();
    eprintln!(
        "  {}{}✗  quantra-netd daemon is not running{}",
        BOLD, RED, RESET
    );
    eprintln!("  {}", DIM);
    eprintln!("  Could not connect to quantra-netd at '{}'", SOCKET_PATH);
    eprintln!("  Error: {}", e);
    eprintln!("  {}", RESET);
    eprintln!();
    eprintln!(
        "{}Zainium tip: Please start it with: systemctl start quantra-netd{}",
        DIM, RESET
    );
    eprintln!();
    eprintln!("  sudo systemctl start quantra-netd");
    eprintln!("  # or run it directly:");
    eprintln!("  sudo quantra-netd");
    eprintln!();
}

fn render_connection_error(e: &anyhow::Error) {
    use ansi::*;
    eprintln!();
    eprintln!("  {}{}✗  Connection error: {}{}", BOLD, RED, e, RESET);
    eprintln!();
    eprintln!(
        "{}Zainium tip: Make sure quantra-netd is running and the socket exists.{}",
        DIM, RESET
    );
    eprintln!();
    std::process::exit(1);
}

fn print_tip(tip: &str) {
    use ansi::*;
    println!("{}{}Zainium tip: {}{}{}", DIM, YELLOW, tip, RESET, DIM);
    println!("{}", RESET);
}

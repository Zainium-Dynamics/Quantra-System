//! # common
//!
//! Shared types and utilities for quantra-net and quantra-netd.

use serde::{Deserialize, Serialize};
use std::io::{Read as StdRead, Write as StdWrite};
#[cfg(feature = "async-io")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "async-io")]
use tokio::net::UnixStream;

/// quantra-netd IPC (length-prefixed JSON). Not zai-net naming.
pub const SOCKET_PATH: &str = "/run/quantra-system/quantra-netd.sock";

// ── Network Commands ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub enum NetCommand {
    Status {
        verbose: bool,
    },
    StatusDetail(String),
    LinkUp(String),
    LinkDown(String),
    LinkRestart(String),
    LinkAdd(String, String),
    LinkRemove(String, String),
    DhcpAcquire(String),
    DhcpRenew(String),
    DhcpRelease(String),
    RouteAdd {
        destination: String,
        gateway: String,
        interface: Option<String>,
    },
    RouteDel {
        destination: String,
        gateway: Option<String>,
    },
    RouteShow,
    ConfigSave,
    ConfigLoad,
    ConfigShow,
    Monitor {
        interface: Option<String>,
    },
    ModeGet,
    ModeSet(RunMode),
    DaemonStatus,

    // ── WiFi ────────────────────────────────────────────────────────────────
    WifiScan {
        interface: String,
    },
    WifiConnect {
        interface: String,
        ssid: String,
        password: Option<String>,
        security: WifiSecurity,
        hidden: bool,
    },
    WifiDisconnect {
        interface: String,
    },
    WifiSaved,
    WifiForget {
        ssid: String,
    },
    WifiAutoConnect {
        enable: bool,
        interface: String,
    },
    WifiDiagnose {
        interface: String,
    },

    // ── Quality / Diagnostics ───────────────────────────────────────────────
    QualityMonitor {
        interface: String,
        duration: Option<u64>,
    },
    SpeedTest {
        interface: Option<String>,
    },
    BandwidthTest {
        interface: String,
        duration: u64,
    },

    // ── VPN ────────────────────────────────────────────────────────────────
    VpnCreate {
        name: String,
        vpn_type: VpnType,
        config: VpnConfig,
    },
    VpnUp {
        name: String,
    },
    VpnDown {
        name: String,
    },
    VpnStatus,
    VpnShow {
        name: String,
    },
    VpnKillSwitch {
        enable: bool,
        interface: Option<String>,
    },

    // ── Firewall ───────────────────────────────────────────────────────────
    FirewallAllow {
        service: String,
        from: Option<String>,
        port: Option<u16>,
    },
    FirewallBlock {
        port: u16,
        from: Option<String>,
    },
    FirewallZoneAdd {
        interface: String,
        zone: FirewallZone,
    },
    FirewallPreset {
        preset: FirewallPreset,
    },
    FirewallNat {
        enable: bool,
        interface: String,
    },
    FirewallStatus,

    // ── Namespaces / Containers ────────────────────────────────────────────
    NetnsCreate {
        name: String,
    },
    NetnsList,
    NetnsExec {
        name: String,
        command: String,
    },
    NetnsDelete {
        name: String,
    },
    LinkSetNetns {
        interface: String,
        netns: String,
    },
    VethCreate {
        name: String,
        peer: String,
    },

    // ── Smart setup ────────────────────────────────────────────────────────
    AutoConfigure,
    Diagnose {
        interface: Option<String>,
    },

    // ── Performance ─────────────────────────────────────────────────────────
    // ── IPv6 ────────────────────────────────────────────────────────────────────
    Ipv6DhcpAcquire {
        interface: String,
    },
    Ipv6DhcpRelease {
        interface: String,
    },
    Ipv6SlaacEnable {
        interface: String,
    },
    Ipv6Status {
        interface: String,
    },

    // ── Bridge / VLAN / Bond / MACVLAN ──────────────────────────────────────
    BridgeCreate {
        name: String,
    },
    BridgeDelete {
        name: String,
    },
    BridgeAddMember {
        bridge: String,
        member: String,
    },
    BridgeRemoveMember {
        member: String,
    },
    BridgeShow {
        name: String,
    },
    VlanCreate {
        name: String,
        parent: String,
        vlan_id: u16,
    },
    VlanDelete {
        name: String,
    },
    BondCreate {
        name: String,
        mode: String,
    },
    BondDelete {
        name: String,
    },
    BondAddMember {
        bond: String,
        slave: String,
    },
    BondRemoveMember {
        slave: String,
    },
    MacvlanCreate {
        name: String,
        parent: String,
        mode: String,
    },
    MacvlanDelete {
        name: String,
    },

    // ── WireGuard native ────────────────────────────────────────────────────
    WireGuardUp {
        name: String,
    },
    WireGuardDown {
        name: String,
    },
    WireGuardStatus,
    WireGuardShow {
        name: String,
    },

    // ── DNS ─────────────────────────────────────────────────────────────────
    DnsSetServers {
        servers: Vec<String>,
    },
    DnsSetDot {
        enable: bool,
        servers: Vec<String>,
    },
    DnsQuery {
        name: String,
        record_type: String,
    },
    DnsFlushCache,
    DnsStatus,

    // ── Batch ────────────────────────────────────────────────────────────────
    Batch {
        commands: Vec<NetCommand>,
    },
}

// ── Network Responses ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub enum NetResponse {
    Status(Vec<InterfaceInfo>, RunMode, Option<DaemonStatus>),
    StatusDetail(InterfaceDetail),
    DhcpLease(DhcpLeaseInfo),
    Routes(Vec<RouteInfo>),
    Config(NetworkConfig),
    Events(Vec<NetEvent>),
    WifiNetworks(Vec<WifiNetwork>),
    WifiSaved(Vec<WifiSavedNetwork>),
    Quality(QualityMetrics),
    VpnStatus(Vec<VpnStatusInfo>),
    VpnProfile(VpnProfileView),
    FirewallStatus(FirewallStatus),
    NetnsList(Vec<String>),
    DaemonStatus(DaemonStatus),
    Mode(RunMode),
    Batch(Vec<NetResponse>),
    Ipv6Lease(DhcpLeaseInfo),
    VlanInfo(String),
    BridgeInfo(String),
    DnsResult(Vec<String>),
    DnsStatus(DnsStatusInfo),
    Success(String),
    Error(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VpnProfileView {
    pub name: String,
    pub vpn_type: VpnType,
    pub up: bool,
    pub summary: String,
}

// ── Interface Information ────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InterfaceInfo {
    pub index: u32,
    pub name: String,
    pub mac: String,
    pub state: LinkState,
    pub ip_addresses: Vec<String>,
    pub statistics: Option<InterfaceStats>,
    pub speed_mbps: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InterfaceDetail {
    pub index: u32,
    pub name: String,
    pub mac: String,
    pub state: LinkState,
    pub ip_addresses: Vec<String>,
    pub mtu: Option<u32>,
    pub iface_type: Option<String>,
    pub statistics: Option<InterfaceStats>,
    pub wireless: Option<WirelessInfo>,
    pub flags: Vec<String>,
    pub qdisc: Option<String>,
    pub group: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InterfaceStats {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WirelessInfo {
    pub ssid: String,
    pub signal_strength: i32,
    pub frequency: f32,
    pub channel: u32,
    pub quality: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DhcpLeaseInfo {
    pub interface: String,
    pub ip_cidr: Option<String>,
    pub gateway: Option<String>,
    pub dns_servers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RouteInfo {
    pub destination: String,
    pub gateway: Option<String>,
    pub interface: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RunMode {
    #[default]
    Balanced,
    Performance,
    PowerSave,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct NetworkConfig {
    pub interfaces: std::collections::BTreeMap<String, InterfaceConfig>,
    pub routes: Vec<RouteInfo>,
    #[serde(default)]
    pub wifi: Vec<WifiProfile>,
    #[serde(default)]
    pub wifi_autoconnect: std::collections::BTreeMap<String, bool>,
    #[serde(default)]
    pub mode: RunMode,
    #[serde(default)]
    pub total_connections: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DaemonStatus {
    pub mode: RunMode,
    pub uptime_seconds: u64,
    pub active_connections: usize,
    pub total_connections: u64,
    pub firewall_enabled: bool,
    pub dns_cache_entries: usize,
    pub interface_count: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct InterfaceConfig {
    pub state: String,
    pub addresses: Vec<String>,
    pub gateway: Option<String>,
    pub dns: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetEvent {
    pub event_type: EventType,
    pub interface: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum EventType {
    LinkUp,
    LinkDown,
    AddressAdded,
    AddressRemoved,
}

// ── WiFi Types ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum WifiSecurity {
    Open,
    Wpa2Psk,
    Wpa3Psk,
    Wpa2Enterprise,
    Wpa3Enterprise,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WifiNetwork {
    pub ssid: String,
    pub bssid: String,
    pub security: WifiSecurity,
    pub signal: i32,
    pub channel: u32,
    pub frequency: u32,
    pub connected: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WifiSavedNetwork {
    pub ssid: String,
    pub security: WifiSecurity,
    pub autoconnect: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WifiProfile {
    pub ssid: String,
    pub security: WifiSecurity,
    pub password: Option<String>,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub autoconnect: bool,
}

// ── Quality / Metrics ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QualityMetrics {
    pub signal_strength: i32,
    pub snr: f32,
    pub bitrate: u32,
    pub retry_rate: f32,
    pub latency_ms: Vec<f32>,
    pub packet_loss: f32,
    pub stability: f32,
    pub recommendation: Option<String>,
}

/// Proper return type for bandwidth measurement — avoids misusing QualityMetrics fields.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BandwidthResult {
    pub rx_mbps: f64,
    pub tx_mbps: f64,
    pub combined_mbps: f64,
    pub duration_secs: u64,
    pub interface: String,
}

// ── VPN ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum VpnType {
    WireGuard,
    OpenVPN,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum VpnConfig {
    WireGuard(WireGuardConfig),
    OpenVPN(OpenVpnConfig),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WireGuardConfig {
    pub private_key: String,
    pub peers: Vec<WireGuardPeer>,
    pub listen_port: u16,
    pub address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WireGuardPeer {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpenVpnConfig {
    pub ovpn: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VpnStatusInfo {
    pub name: String,
    pub vpn_type: VpnType,
    pub up: bool,
    pub interface: Option<String>,
}

// ── Firewall ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum FirewallZone {
    Public,
    Home,
    Work,
    Trusted,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum FirewallPreset {
    Home,
    Work,
    Public,
    Gaming,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FirewallStatus {
    pub active_preset: Option<FirewallPreset>,
    pub nat_enabled: bool,
    pub zones: std::collections::BTreeMap<String, FirewallZone>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum LinkState {
    Up,
    Down,
    Unknown,
}

// ── Socket Communication Helpers ────────────────────────────────────────────

/// Send a message over a Unix stream with length prefix (async, requires `async-io` feature)
#[cfg(feature = "async-io")]
pub async fn send_message<T: Serialize>(
    stream: &mut UnixStream,
    msg: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = serde_json::to_vec(msg)?;
    let len = data.len() as u32;

    let len_buf = len.to_le_bytes();
    stream.write_all(&len_buf).await?;
    stream.write_all(&data).await?;

    Ok(())
}

/// Receive a message from a Unix stream with length prefix (async, requires `async-io` feature)
#[cfg(feature = "async-io")]
pub async fn recv_message<T: for<'de> Deserialize<'de>>(
    stream: &mut UnixStream,
) -> Result<T, Box<dyn std::error::Error>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;

    if len > 4 * 1024 * 1024 {
        return Err(format!("Frame too large ({len} bytes, max 4MB)").into());
    }

    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;

    let msg = serde_json::from_slice(&data)?;
    Ok(msg)
}

/// Synchronous version for testing
pub fn send_message_sync<T: Serialize>(
    stream: &mut std::os::unix::net::UnixStream,
    msg: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = serde_json::to_vec(msg)?;
    let len = data.len() as u32;

    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(&data)?;

    Ok(())
}

pub fn recv_message_sync<T: for<'de> Deserialize<'de>>(
    stream: &mut std::os::unix::net::UnixStream,
) -> Result<T, Box<dyn std::error::Error>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;

    if len > 4 * 1024 * 1024 {
        return Err(format!("Frame too large ({len} bytes, max 4MB)").into());
    }

    let mut data = vec![0u8; len];
    stream.read_exact(&mut data)?;

    let msg = serde_json::from_slice(&data)?;
    Ok(msg)
}

/// Generic reader-based recv for testing (works with Cursor, etc.)
pub fn recv_message_from_reader<T: for<'de> Deserialize<'de>>(
    reader: &mut impl StdRead,
) -> Result<T, Box<dyn std::error::Error>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 4 * 1024 * 1024 {
        return Err(format!("Frame too large ({len} bytes, max 4MB)").into());
    }
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data)?;
    let msg = serde_json::from_slice(&data)?;
    Ok(msg)
}

// ── DNS status ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsStatusInfo {
    pub servers: Vec<String>,
    pub dot_enabled: bool,
    pub dot_servers: Vec<String>,
    pub cache_entries: usize,
}

// ── IPv6 info ─────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Ipv6Info {
    pub interface: String,
    pub addresses: Vec<String>,
    pub method: String, // "slaac" / "dhcpv6" / "static"
    pub dns: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_serialization_roundtrip_for_new_commands() {
        let cmd = NetCommand::RouteAdd {
            destination: "default".to_string(),
            gateway: "192.168.1.1".to_string(),
            interface: Some("eth0".to_string()),
        };
        let encoded = serde_json::to_vec(&cmd).expect("serialize command");
        let decoded: NetCommand = serde_json::from_slice(&encoded).expect("deserialize command");
        match decoded {
            NetCommand::RouteAdd {
                destination,
                gateway,
                interface,
            } => {
                assert_eq!(destination, "default");
                assert_eq!(gateway, "192.168.1.1");
                assert_eq!(interface.as_deref(), Some("eth0"));
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn runmode_serialization_roundtrip() {
        let mode = RunMode::Performance;
        let encoded = serde_json::to_vec(&mode).expect("serialize mode");
        let decoded: RunMode = serde_json::from_slice(&encoded).expect("deserialize mode");
        assert_eq!(decoded, RunMode::Performance);
    }

    #[test]
    fn network_config_serialization_roundtrip() {
        let mut interfaces = std::collections::BTreeMap::new();
        interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                state: "up".to_string(),
                addresses: vec!["192.168.1.100/24".to_string()],
                gateway: Some("192.168.1.1".to_string()),
                dns: vec!["8.8.8.8".to_string()],
            },
        );

        let config = NetworkConfig {
            interfaces,
            routes: vec![RouteInfo {
                destination: "default".to_string(),
                gateway: Some("192.168.1.1".to_string()),
                interface: Some("eth0".to_string()),
            }],
            wifi: Vec::new(),
            wifi_autoconnect: std::collections::BTreeMap::new(),
            mode: RunMode::PowerSave,
            total_connections: 1234,
        };

        let encoded = serde_yaml::to_string(&config).expect("serialize config");
        let decoded: NetworkConfig = serde_yaml::from_str(&encoded).expect("deserialize config");

        assert_eq!(decoded.mode, RunMode::PowerSave);
        assert_eq!(decoded.total_connections, 1234);
        assert_eq!(decoded.interfaces.get("eth0").unwrap().state, "up");
        assert_eq!(decoded.routes[0].destination, "default");
    }

    #[test]
    fn frame_size_overflow_rejected_sync() {
        use std::io::Cursor;
        // Craft a 5MB frame header
        let len: u32 = 5 * 1024 * 1024;
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&[0u8; 64]); // some payload bytes
        let mut cursor = Cursor::new(buf);
        let result: Result<NetCommand, _> = recv_message_from_reader(&mut cursor);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("too large"),
            "Expected 'too large' error, got: {err}"
        );
    }

    #[test]
    fn net_command_status_roundtrip() {
        let cmd = NetCommand::Status { verbose: true };
        let json = serde_json::to_string(&cmd).expect("serialize");
        let decoded: NetCommand = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(decoded, NetCommand::Status { verbose: true }));
    }

    #[test]
    fn wifi_security_roundtrip() {
        for sec in &[
            WifiSecurity::Open,
            WifiSecurity::Wpa2Psk,
            WifiSecurity::Wpa3Psk,
            WifiSecurity::Wpa2Enterprise,
            WifiSecurity::Wpa3Enterprise,
        ] {
            let json = serde_json::to_string(sec).expect("serialize");
            let decoded: WifiSecurity = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, sec);
        }
    }

    #[test]
    fn vpn_config_wireguard_roundtrip() {
        let cfg = VpnConfig::WireGuard(WireGuardConfig {
            private_key: "test_key".into(),
            listen_port: 51820,
            address: Some("10.0.0.1/24".into()),
            peers: vec![WireGuardPeer {
                public_key: "peer_key".into(),
                allowed_ips: vec!["0.0.0.0/0".into()],
                endpoint: Some("1.2.3.4:51820".into()),
                persistent_keepalive: Some(25),
            }],
        });
        let json = serde_json::to_string(&cfg).expect("serialize");
        let decoded: VpnConfig = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(decoded, VpnConfig::WireGuard(_)));
    }

    #[test]
    fn vpn_config_openvpn_roundtrip() {
        let cfg = VpnConfig::OpenVPN(OpenVpnConfig {
            ovpn: "client\nremote 1.2.3.4".into(),
        });
        let json = serde_json::to_string(&cfg).expect("serialize");
        let decoded: VpnConfig = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(decoded, VpnConfig::OpenVPN(_)));
    }

    #[test]
    fn runmode_default_is_balanced() {
        assert_eq!(RunMode::default(), RunMode::Balanced);
    }

    #[test]
    fn network_config_default_is_empty() {
        let cfg = NetworkConfig::default();
        assert!(cfg.interfaces.is_empty());
        assert!(cfg.routes.is_empty());
        assert!(cfg.wifi.is_empty());
        assert_eq!(cfg.total_connections, 0);
    }

    #[test]
    fn link_state_serializes() {
        assert_eq!(serde_json::to_string(&LinkState::Up).unwrap(), "\"Up\"");
        assert_eq!(serde_json::to_string(&LinkState::Down).unwrap(), "\"Down\"");
    }

    #[test]
    fn interface_stats_roundtrip() {
        let stats = InterfaceStats {
            rx_packets: 100,
            tx_packets: 200,
            rx_bytes: 1000,
            tx_bytes: 2000,
            rx_errors: 1,
            tx_errors: 2,
            rx_dropped: 3,
            tx_dropped: 4,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let decoded: InterfaceStats = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.rx_packets, 100);
        assert_eq!(decoded.tx_bytes, 2000);
        assert_eq!(decoded.tx_dropped, 4);
    }

    #[test]
    fn firewall_zone_variants_serialize() {
        for zone in &[
            FirewallZone::Public,
            FirewallZone::Home,
            FirewallZone::Work,
            FirewallZone::Trusted,
        ] {
            let json = serde_json::to_string(zone).unwrap();
            let _: FirewallZone = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn firewall_preset_variants_serialize() {
        for p in &[
            FirewallPreset::Home,
            FirewallPreset::Work,
            FirewallPreset::Public,
            FirewallPreset::Gaming,
        ] {
            let json = serde_json::to_string(p).unwrap();
            let _: FirewallPreset = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn net_command_batch_roundtrip() {
        let batch = NetCommand::Batch {
            commands: vec![
                NetCommand::Status { verbose: false },
                NetCommand::RouteShow,
                NetCommand::DaemonStatus,
            ],
        };
        let json = serde_json::to_string(&batch).unwrap();
        let decoded: NetCommand = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, NetCommand::Batch { .. }));
    }

    #[test]
    fn net_response_success_error_roundtrip() {
        let ok = NetResponse::Success("done".into());
        let err = NetResponse::Error("fail".into());
        assert!(serde_json::to_string(&ok).is_ok());
        assert!(serde_json::to_string(&err).is_ok());
    }

    #[test]
    fn wifi_profile_defaults() {
        let json = r#"{"ssid":"test","security":"Wpa2Psk","password":null}"#;
        let profile: WifiProfile = serde_json::from_str(json).unwrap();
        assert!(!profile.hidden);
        assert!(!profile.autoconnect);
    }

    #[test]
    fn quality_metrics_roundtrip() {
        let qm = QualityMetrics {
            signal_strength: -55,
            snr: 20.0,
            bitrate: 300,
            retry_rate: 0.01,
            latency_ms: vec![1.5, 2.3],
            packet_loss: 0.0,
            stability: 0.99,
            recommendation: Some("Good".into()),
        };
        let json = serde_json::to_string(&qm).unwrap();
        let decoded: QualityMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.latency_ms.len(), 2);
    }

    #[test]
    fn sync_frame_roundtrip() {
        use std::io::Cursor;
        let cmd = NetCommand::Status { verbose: false };
        let data = serde_json::to_vec(&cmd).unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&data);
        let mut cursor = Cursor::new(buf);
        let decoded: NetCommand = recv_message_from_reader(&mut cursor).unwrap();
        assert!(matches!(decoded, NetCommand::Status { verbose: false }));
    }

    #[test]
    fn dhcp_lease_info_roundtrip() {
        let lease = DhcpLeaseInfo {
            interface: "eth0".into(),
            ip_cidr: Some("192.168.1.100/24".into()),
            gateway: Some("192.168.1.1".into()),
            dns_servers: vec!["8.8.8.8".into()],
        };
        let json = serde_json::to_string(&lease).unwrap();
        let decoded: DhcpLeaseInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.dns_servers.len(), 1);
    }
}

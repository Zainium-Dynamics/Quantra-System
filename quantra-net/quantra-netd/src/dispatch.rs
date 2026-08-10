//! Command dispatch — routes NetCommand variants to module handlers.
use crate::exec::Exec;
use crate::{
    bridge, config, dhcp, firewall, ipv6, netlink, netns, quality, resolver, routing, vpn, wifi,
};
use anyhow::Result;
use common::*;
use once_cell::sync::Lazy;
use rtnetlink::Handle;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tokio::time::Duration;
use tracing::error;

pub static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
pub static DAEMON_START: Lazy<Instant> = Lazy::new(Instant::now);

pub async fn execute_command(handle: &Handle, exec: &dyn Exec, command: NetCommand) -> NetResponse {
    match command {
        NetCommand::Batch { commands } => match batch_execute(handle, exec, commands).await {
            Ok(r) => NetResponse::Batch(r),
            Err(e) => NetResponse::Error(format!("Batch failed: {e:#}")),
        },
        other => execute_inner(handle, exec, other).await,
    }
}

async fn batch_execute(
    handle: &Handle,
    exec: &dyn Exec,
    commands: Vec<NetCommand>,
) -> Result<Vec<NetResponse>> {
    let mut out = Vec::new();
    for cmd in commands {
        if matches!(cmd, NetCommand::Batch { .. }) {
            return Err(anyhow::anyhow!("Nested batch not allowed"));
        }
        out.push(execute_inner(handle, exec, cmd).await);
    }
    Ok(out)
}

async fn restart_interface(handle: &Handle, name: &str) -> Result<()> {
    netlink::set_link_state(handle, name, false).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    netlink::set_link_state(handle, name, true).await
}

async fn execute_inner(handle: &Handle, exec: &dyn Exec, command: NetCommand) -> NetResponse {
    match command {
        NetCommand::Status { verbose } => match netlink::get_all_links(handle).await {
            Ok(interfaces) => {
                let ds = if verbose {
                    let fw = firewall::read_firewall_state();
                    let dns = dhcp::read_dns_servers().unwrap_or_default().len();
                    let up = DAEMON_START.elapsed().as_secs();
                    let tc = config::read_config().unwrap_or_default().total_connections;
                    Some(DaemonStatus {
                        mode: config::current_mode(),
                        uptime_seconds: up,
                        active_connections: ACTIVE_CONNECTIONS.load(Ordering::SeqCst),
                        total_connections: tc,
                        firewall_enabled: fw.active_preset.is_some(),
                        dns_cache_entries: dns,
                        interface_count: interfaces.len(),
                    })
                } else {
                    None
                };
                NetResponse::Status(interfaces, config::current_mode(), ds)
            }
            Err(e) => {
                error!("Status failed: {e:#}");
                NetResponse::Error(format!("{e:#}"))
            }
        },
        NetCommand::ModeGet => NetResponse::Mode(config::current_mode()),
        NetCommand::ModeSet(mode) => match config::set_mode(mode) {
            Ok(_) => NetResponse::Success("✓ Mode updated".into()),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::DaemonStatus => {
            let ifaces = netlink::get_all_links(handle).await.unwrap_or_default();
            let fw = firewall::read_firewall_state();
            let dns = dhcp::read_dns_servers().unwrap_or_default().len();
            let up = DAEMON_START.elapsed().as_secs();
            let tc = config::read_config().unwrap_or_default().total_connections;
            NetResponse::DaemonStatus(DaemonStatus {
                mode: config::current_mode(),
                uptime_seconds: up,
                active_connections: ACTIVE_CONNECTIONS.load(Ordering::SeqCst),
                total_connections: tc,
                firewall_enabled: fw.active_preset.is_some(),
                dns_cache_entries: dns,
                interface_count: ifaces.len(),
            })
        }
        NetCommand::StatusDetail(ref name) => {
            match netlink::get_interface_detail(handle, name).await {
                Ok(Some(d)) => NetResponse::StatusDetail(d),
                Ok(None) => NetResponse::Error(format!("Interface '{}' not found", name)),
                Err(e) => NetResponse::Error(format!("{e:#}")),
            }
        }
        NetCommand::LinkUp(ref n) => match netlink::set_link_state(handle, n, true).await {
            Ok(()) => NetResponse::Success(format!("✓ Interface '{}' is now UP", n)),
            Err(e) => NetResponse::Error(format!("Cannot bring '{}' up: {e:#}", n)),
        },
        NetCommand::LinkDown(ref n) => match netlink::set_link_state(handle, n, false).await {
            Ok(()) => NetResponse::Success(format!("✓ Interface '{}' is now DOWN", n)),
            Err(e) => NetResponse::Error(format!("Cannot bring '{}' down: {e:#}", n)),
        },
        NetCommand::LinkRestart(ref n) => match restart_interface(handle, n).await {
            Ok(()) => NetResponse::Success(format!("✓ Interface '{}' restarted", n)),
            Err(e) => NetResponse::Error(format!("Cannot restart '{}': {e:#}", n)),
        },
        NetCommand::LinkAdd(ref n, ref ip) => match netlink::add_ip_address(handle, n, ip).await {
            Ok(()) => NetResponse::Success(format!("✓ IP '{}' added to '{}'", ip, n)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::LinkRemove(ref n, ref ip) => {
            match netlink::remove_ip_address(handle, n, ip).await {
                Ok(()) => NetResponse::Success(format!("✓ IP '{}' removed from '{}'", ip, n)),
                Err(e) => NetResponse::Error(format!("{e:#}")),
            }
        }
        NetCommand::DhcpAcquire(ref n) => match dhcp::dhcp_acquire(handle, n).await {
            Ok(lease) => NetResponse::DhcpLease(lease),
            Err(e) => NetResponse::Error(format!("DHCP acquire failed: {e:#}")),
        },
        NetCommand::DhcpRenew(ref n) => match dhcp::dhcp_renew(handle, n).await {
            Ok(lease) => NetResponse::DhcpLease(lease),
            Err(e) => NetResponse::Error(format!("DHCP renew failed: {e:#}")),
        },
        NetCommand::DhcpRelease(ref n) => match dhcp::dhcp_release(n).await {
            Ok(()) => NetResponse::Success(format!("✓ DHCP released for '{n}'")),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::RouteAdd {
            ref destination,
            ref gateway,
            ref interface,
        } => match routing::add_route(handle, destination, gateway, interface.as_deref()).await {
            Ok(()) => {
                NetResponse::Success(format!("✓ Route '{}' via '{}' added", destination, gateway))
            }
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::RouteDel {
            ref destination,
            ref gateway,
        } => match routing::delete_route(handle, destination, gateway.as_deref()).await {
            Ok(()) => NetResponse::Success(format!("✓ Route '{}' removed", destination)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::RouteShow => match routing::list_routes(handle).await {
            Ok(r) => NetResponse::Routes(r),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::ConfigSave => match config::save_config(handle).await {
            Ok(()) => NetResponse::Success(format!("✓ Config saved to {}", config::CONFIG_PATH)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::ConfigLoad => match config::load_config_into_kernel(handle).await {
            Ok(()) => NetResponse::Success(format!("✓ Config loaded from {}", config::CONFIG_PATH)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::ConfigShow => match config::read_config() {
            Ok(c) => NetResponse::Config(c),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::Monitor { ref interface } => {
            match quality::monitor_interface_events(handle, interface.as_deref()).await {
                Ok(ev) => NetResponse::Events(ev),
                Err(e) => NetResponse::Error(format!("{e:#}")),
            }
        }
        // WiFi
        NetCommand::WifiScan { ref interface } => match wifi::wifi_scan(interface).await {
            Ok(nets) => NetResponse::WifiNetworks(nets),
            Err(e) => NetResponse::Error(format!("WiFi scan failed: {e:#}")),
        },
        NetCommand::WifiConnect {
            ref interface,
            ref ssid,
            ref password,
            ref security,
            hidden,
        } => {
            match wifi::wifi_connect(
                interface,
                ssid,
                password.as_deref(),
                security.clone(),
                hidden,
            )
            .await
            {
                Ok(()) => match dhcp::dhcp_acquire(handle, interface).await {
                    Ok(lease) => {
                        let _ = config::save_wifi_profile(
                            ssid,
                            password.as_deref(),
                            security.clone(),
                            hidden,
                            true,
                        );
                        NetResponse::DhcpLease(lease)
                    }
                    Err(e) => NetResponse::Error(format!("WiFi connected but DHCP failed: {e:#}")),
                },
                Err(e) => NetResponse::Error(format!("WiFi connect failed: {e:#}")),
            }
        }
        NetCommand::WifiDisconnect { ref interface } => {
            match wifi::wifi_disconnect(interface).await {
                Ok(()) => NetResponse::Success(format!("✓ WiFi disconnected on {}", interface)),
                Err(e) => NetResponse::Error(format!("{e:#}")),
            }
        }
        NetCommand::WifiSaved => match config::read_config() {
            Ok(cfg) => NetResponse::WifiSaved(wifi::profiles_to_saved(&cfg.wifi)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::WifiForget { ref ssid } => match config::forget_wifi_profile(ssid) {
            Ok(()) => NetResponse::Success(format!("✓ Forgot WiFi '{}'", ssid)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::WifiAutoConnect {
            enable,
            ref interface,
        } => match config::set_wifi_autoconnect(interface, enable) {
            Ok(()) => NetResponse::Success(format!(
                "✓ WiFi autoconnect {} for {}",
                if enable { "enabled" } else { "disabled" },
                interface
            )),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::WifiDiagnose { ref interface } => match wifi::current_link(interface).await {
            Ok(Some((bssid, _))) => {
                NetResponse::Success(format!("✓ WiFi link OK on {} (BSSID {})", interface, bssid))
            }
            Ok(None) => NetResponse::Error(format!("WiFi not connected on {}", interface)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::AutoConfigure => match crate::autoconfig::auto_configure_once(handle).await {
            Ok(()) => {
                crate::autoconfig::ensure_self_heal_started(handle.clone());
                NetResponse::Success("✓ Auto-configuration complete".into())
            }
            Err(e) => NetResponse::Error(format!("Auto-config failed: {e:#}")),
        },
        NetCommand::Diagnose { ref interface } => {
            match quality::diagnose_interface(handle, interface.as_deref()).await {
                Ok(msg) => NetResponse::Success(msg),
                Err(e) => NetResponse::Error(format!("{e:#}")),
            }
        }
        NetCommand::Batch { .. } => NetResponse::Error("Batch must use outer wrapper".into()),
        // Quality
        NetCommand::QualityMonitor {
            ref interface,
            duration,
        } => match quality::measure_quality(handle, exec, interface, duration.unwrap_or(5)).await {
            Ok(m) => NetResponse::Quality(m),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::SpeedTest { ref interface } => {
            let iface = if let Some(i) = interface {
                i.clone()
            } else {
                routing::default_interface(handle)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "eth0".into())
            };
            match quality::measure_quality(handle, exec, &iface, 5).await {
                Ok(m) => NetResponse::Quality(m),
                Err(e) => NetResponse::Error(format!("{e:#}")),
            }
        }
        NetCommand::BandwidthTest {
            ref interface,
            duration,
        } => match quality::bandwidth_test(exec, interface, duration).await {
            Ok(bw) => NetResponse::Success(format!(
                "RX {:.1} Mbps, TX {:.1} Mbps (combined {:.1} Mbps over {}s)",
                bw.rx_mbps, bw.tx_mbps, bw.combined_mbps, bw.duration_secs
            )),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        // VPN
        NetCommand::VpnCreate {
            ref name,
            ref vpn_type,
            ref config,
        } => match vpn::save_vpn_profile(name, vpn_type.clone(), config.clone()) {
            Ok(()) => NetResponse::Success(format!("✓ VPN profile '{}' saved", name)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::VpnUp { ref name } => match vpn::vpn_up(exec, name).await {
            Ok(()) => NetResponse::Success(format!("✓ VPN '{}' is UP", name)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::VpnDown { ref name } => match vpn::vpn_down(exec, name).await {
            Ok(()) => NetResponse::Success(format!("✓ VPN '{}' is DOWN", name)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::VpnStatus => match vpn::vpn_status(exec).await {
            Ok(s) => NetResponse::VpnStatus(s),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::VpnShow { ref name } => match vpn::vpn_show(exec, name).await {
            Ok(v) => NetResponse::VpnProfile(v),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::VpnKillSwitch {
            enable,
            ref interface,
        } => match vpn::set_vpn_killswitch(exec, enable, interface.as_deref()).await {
            Ok(()) => NetResponse::Success(format!(
                "✓ Kill-switch {}",
                if enable { "enabled" } else { "disabled" }
            )),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        // Firewall
        NetCommand::FirewallPreset { ref preset } => {
            match firewall::apply_firewall_preset(exec, preset.clone()).await {
                Ok(()) => NetResponse::Success(format!("✓ Firewall preset '{preset:?}' applied")),
                Err(e) => NetResponse::Error(format!("{e:#}")),
            }
        }
        NetCommand::FirewallStatus => NetResponse::FirewallStatus(firewall::read_firewall_state()),
        NetCommand::FirewallAllow {
            ref service,
            ref from,
            port,
        } => match firewall::firewall_allow(exec, service, from.as_deref(), port).await {
            Ok(()) => NetResponse::Success("✓ Allow rule applied".into()),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::FirewallBlock { port, ref from } => {
            match firewall::firewall_block(exec, port, from.as_deref()).await {
                Ok(()) => NetResponse::Success("✓ Block rule applied".into()),
                Err(e) => NetResponse::Error(format!("{e:#}")),
            }
        }
        NetCommand::FirewallZoneAdd {
            ref interface,
            ref zone,
        } => match firewall::firewall_zone_add(interface, zone.clone()) {
            Ok(()) => NetResponse::Success(format!("✓ Zone {:?} set on '{}'", zone, interface)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::FirewallNat {
            enable,
            ref interface,
        } => match firewall::firewall_nat(exec, enable, interface).await {
            Ok(()) => NetResponse::Success(format!(
                "✓ NAT {} on {}",
                if enable { "enabled" } else { "disabled" },
                interface
            )),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        // Namespaces
        NetCommand::NetnsCreate { name } => match netns::netns_create(&name).await {
            Ok(()) => NetResponse::Success(format!("Namespace '{}' created", name)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::NetnsList => match netns::netns_list().await {
            Ok(n) => NetResponse::NetnsList(n),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::NetnsExec { name, command } => match netns::netns_exec(&name, &command).await {
            Ok(out) => NetResponse::Success(out),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::NetnsDelete { name } => match netns::netns_delete(&name).await {
            Ok(()) => NetResponse::Success(format!("Namespace '{}' deleted", name)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::LinkSetNetns {
            interface,
            netns: ns,
        } => match netns::link_set_netns(&interface, &ns).await {
            Ok(()) => NetResponse::Success(format!("'{}' moved to namespace '{}'", interface, ns)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::VethCreate { name, peer } => match netns::veth_create(&name, &peer).await {
            Ok(()) => NetResponse::Success(format!("Veth pair '{}'<->'{}' created", name, peer)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },

        // ── IPv6 ─────────────────────────────────────────────────────────────
        NetCommand::Ipv6DhcpAcquire { interface } => {
            match ipv6::dhcp6_acquire(handle, &interface).await {
                Ok(l) => NetResponse::Ipv6Lease(l),
                Err(e) => NetResponse::Error(format!("DHCPv6 acquire failed: {e:#}")),
            }
        }
        NetCommand::Ipv6DhcpRelease { interface } => match ipv6::dhcp6_release(&interface).await {
            Ok(()) => NetResponse::Success(format!("✓ DHCPv6 released on {}", interface)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::Ipv6SlaacEnable { interface } => match ipv6::slaac_enable(&interface).await {
            Ok(l) => NetResponse::Ipv6Lease(l),
            Err(e) => NetResponse::Error(format!("SLAAC enable failed: {e:#}")),
        },
        NetCommand::Ipv6Status { interface } => {
            let addr = ipv6::read_global_ipv6(&interface)
                .unwrap_or_else(|| "no global IPv6 address".to_string());
            NetResponse::Success(format!("{}: {}", interface, addr))
        }

        // ── Bridge ────────────────────────────────────────────────────────────
        NetCommand::BridgeCreate { name } => match bridge::bridge_create(exec, &name).await {
            Ok(()) => NetResponse::Success(format!("✓ Bridge '{}' created", name)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::BridgeDelete { name } => match bridge::bridge_delete(exec, &name).await {
            Ok(()) => NetResponse::Success(format!("✓ Bridge '{}' deleted", name)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::BridgeAddMember { bridge, member } => {
            match bridge::bridge_add_member(exec, &bridge, &member).await {
                Ok(()) => {
                    NetResponse::Success(format!("✓ '{}' added to bridge '{}'", member, bridge))
                }
                Err(e) => NetResponse::Error(format!("{e:#}")),
            }
        }
        NetCommand::BridgeRemoveMember { member } => {
            match bridge::bridge_remove_member(exec, &member).await {
                Ok(()) => NetResponse::Success(format!("✓ '{}' removed from bridge", member)),
                Err(e) => NetResponse::Error(format!("{e:#}")),
            }
        }
        NetCommand::BridgeShow { name } => match bridge::bridge_show(exec, &name).await {
            Ok(s) => NetResponse::BridgeInfo(s),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },

        // ── VLAN ──────────────────────────────────────────────────────────────
        NetCommand::VlanCreate {
            name,
            parent,
            vlan_id,
        } => match bridge::vlan_create(exec, &name, &parent, vlan_id).await {
            Ok(()) => NetResponse::Success(format!(
                "✓ VLAN '{}' (id={}) on '{}'",
                name, vlan_id, parent
            )),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::VlanDelete { name } => match bridge::vlan_delete(exec, &name).await {
            Ok(()) => NetResponse::Success(format!("✓ VLAN '{}' deleted", name)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },

        // ── Bond ──────────────────────────────────────────────────────────────
        NetCommand::BondCreate { name, mode } => {
            use bridge::BondMode;
            let bond_mode: BondMode = match mode.as_str() {
                "active-backup" | "backup"    => BondMode::ActiveBackup,
                "balance-xor"  | "xor"       => BondMode::BalanceXor,
                "broadcast"                   => BondMode::Broadcast,
                "802.3ad"      | "lacp"       => BondMode::Ieee8023ad,
                "balance-tlb"  | "tlb"        => BondMode::BalanceTlb,
                "balance-alb"  | "alb"        => BondMode::BalanceAlb,
                _ /* balance-rr default */    => BondMode::BalanceRr,
            };
            match bridge::bond_create(exec, &name, bond_mode).await {
                Ok(()) => {
                    NetResponse::Success(format!("✓ Bond '{}' created (mode={})", name, mode))
                }
                Err(e) => NetResponse::Error(format!("{e:#}")),
            }
        }
        NetCommand::BondDelete { name } => match bridge::bond_delete(exec, &name).await {
            Ok(()) => NetResponse::Success(format!("✓ Bond '{}' deleted", name)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::BondAddMember { bond, slave } => {
            match bridge::bond_add_member(exec, &bond, &slave).await {
                Ok(()) => {
                    NetResponse::Success(format!("✓ '{}' enslaved to bond '{}'", slave, bond))
                }
                Err(e) => NetResponse::Error(format!("{e:#}")),
            }
        }
        NetCommand::BondRemoveMember { slave } => {
            match bridge::bond_remove_member(exec, &slave).await {
                Ok(()) => NetResponse::Success(format!("✓ '{}' freed from bond", slave)),
                Err(e) => NetResponse::Error(format!("{e:#}")),
            }
        }

        // ── MACVLAN ───────────────────────────────────────────────────────────
        NetCommand::MacvlanCreate { name, parent, mode } => {
            use bridge::MacvlanMode;
            let mv_mode: MacvlanMode = match mode.as_str() {
                "vepa" => MacvlanMode::Vepa,
                "private" => MacvlanMode::Private,
                "passthrough" => MacvlanMode::Passthrough,
                _ => MacvlanMode::Bridge,
            };
            match bridge::macvlan_create(exec, &name, &parent, mv_mode).await {
                Ok(()) => {
                    NetResponse::Success(format!("✓ MACVLAN '{}' on '{}' ({})", name, parent, mode))
                }
                Err(e) => NetResponse::Error(format!("{e:#}")),
            }
        }
        NetCommand::MacvlanDelete { name } => match bridge::macvlan_delete(exec, &name).await {
            Ok(()) => NetResponse::Success(format!("✓ MACVLAN '{}' deleted", name)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },

        // ── WireGuard native ──────────────────────────────────────────────────
        NetCommand::WireGuardUp { name } => match vpn::vpn_up(exec, &name).await {
            Ok(()) => NetResponse::Success(format!("✓ WireGuard '{}' UP (native GENL)", name)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::WireGuardDown { name } => match vpn::vpn_down(exec, &name).await {
            Ok(()) => NetResponse::Success(format!("✓ WireGuard '{}' DOWN", name)),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::WireGuardStatus => match vpn::vpn_status(exec).await {
            Ok(s) => NetResponse::VpnStatus(s),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },
        NetCommand::WireGuardShow { name } => match vpn::vpn_show(exec, &name).await {
            Ok(v) => NetResponse::VpnProfile(v),
            Err(e) => NetResponse::Error(format!("{e:#}")),
        },

        // ── DNS ───────────────────────────────────────────────────────────────
        NetCommand::DnsSetServers { servers } => {
            resolver::update_from_dhcp(&servers);
            NetResponse::Success(format!("✓ DNS servers updated: {:?}", servers))
        }
        NetCommand::DnsSetDot { enable, servers: _ } => {
            if let Ok(mut r) = resolver::global_resolver().write() {
                r.set_dot_enabled(enable);
            }
            NetResponse::Success(format!(
                "✓ DoT {}",
                if enable { "enabled" } else { "disabled" }
            ))
        }
        NetCommand::DnsQuery {
            name,
            record_type: _,
        } => {
            let resolver = resolver::global_resolver().read().unwrap().clone();
            match resolver.resolve(&name).await {
                Ok(addrs) => NetResponse::DnsResult(addrs.iter().map(|a| a.to_string()).collect()),
                Err(e) => NetResponse::Error(format!("DNS query '{}': {e:#}", name)),
            }
        }
        NetCommand::DnsFlushCache => {
            resolver::global_resolver().read().unwrap().flush_cache();
            NetResponse::Success("✓ DNS cache flushed".into())
        }
        NetCommand::DnsStatus => {
            let cache_len = resolver::global_resolver().read().unwrap().cache_len();
            let cfg = resolver::ResolverConfig::default();
            NetResponse::DnsStatus(common::DnsStatusInfo {
                servers: cfg.servers.iter().map(|s| s.to_string()).collect(),
                dot_enabled: cfg.dot_enabled,
                dot_servers: cfg.dot_servers,
                cache_entries: cache_len,
            })
        }
    }
}

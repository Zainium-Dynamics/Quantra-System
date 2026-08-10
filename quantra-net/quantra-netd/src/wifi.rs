use anyhow::{Context, Result};
use common::{WifiNetwork, WifiProfile, WifiSavedNetwork, WifiSecurity};
use tokio::process::Command;

fn parse_security(block: &str) -> WifiSecurity {
    let b = block.to_ascii_lowercase();
    if b.contains("rsn:") || b.contains("wpa2") || b.contains("wpa3") {
        if b.contains("sae") || b.contains("wpa3") {
            WifiSecurity::Wpa3Psk
        } else {
            WifiSecurity::Wpa2Psk
        }
    } else if b.contains("wpa:") {
        WifiSecurity::Wpa2Psk
    } else {
        WifiSecurity::Open
    }
}

pub async fn wifi_scan(interface: &str) -> Result<Vec<WifiNetwork>> {
    let output = Command::new("iw")
        .args(["dev", interface, "scan"])
        .output()
        .await
        .with_context(|| format!("Failed to execute iw scan on {interface}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "WiFi scan failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);

    let mut networks: Vec<WifiNetwork> = Vec::new();
    let mut cur_bssid = String::new();
    let mut cur_ssid: Option<String> = None;
    let mut cur_freq: Option<u32> = None;
    let mut cur_signal: Option<i32> = None;
    let mut cur_block = String::new();

    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("BSS ") {
            if !cur_bssid.is_empty() {
                let ssid = cur_ssid.take().unwrap_or_else(|| "<hidden>".to_string());
                networks.push(WifiNetwork {
                    ssid,
                    bssid: cur_bssid.clone(),
                    security: parse_security(&cur_block),
                    signal: cur_signal.unwrap_or(-100),
                    channel: 0,
                    frequency: cur_freq.unwrap_or(0),
                    connected: false,
                });
            }
            cur_block.clear();
            cur_ssid = None;
            cur_freq = None;
            cur_signal = None;
            cur_bssid = rest
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string();
            continue;
        }
        cur_block.push_str(line);
        cur_block.push('\n');
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("SSID: ") {
            cur_ssid = Some(rest.to_string());
        } else if let Some(rest) = t.strip_prefix("freq: ") {
            cur_freq = rest.parse::<u32>().ok();
        } else if let Some(rest) = t.strip_prefix("signal: ") {
            let n = rest.split_whitespace().next().unwrap_or("");
            cur_signal = n.parse::<f32>().ok().map(|v| v as i32);
        }
    }
    if !cur_bssid.is_empty() {
        let ssid = cur_ssid.take().unwrap_or_else(|| "<hidden>".to_string());
        networks.push(WifiNetwork {
            ssid,
            bssid: cur_bssid,
            security: parse_security(&cur_block),
            signal: cur_signal.unwrap_or(-100),
            channel: 0,
            frequency: cur_freq.unwrap_or(0),
            connected: false,
        });
    }

    if let Ok(Some((bssid, _ssid))) = current_link(interface).await {
        for n in &mut networks {
            if n.bssid.eq_ignore_ascii_case(&bssid) {
                n.connected = true;
            }
        }
    }

    networks.sort_by_key(|n| -n.signal);
    Ok(networks)
}

pub async fn current_link(interface: &str) -> Result<Option<(String, Option<String>)>> {
    let output = Command::new("iw")
        .args(["dev", interface, "link"])
        .output()
        .await
        .context("Failed to execute iw link")?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    if text.contains("Not connected") {
        return Ok(None);
    }
    let mut bssid: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Connected to ") {
            bssid = Some(rest.split_whitespace().next().unwrap_or("").to_string());
        }
    }
    Ok(bssid.map(|b| (b, None)))
}

async fn ensure_wpa_supplicant(interface: &str) -> Result<String> {
    let run_dir = "/run/quantra-system";
    tokio::fs::create_dir_all(run_dir)
        .await
        .context("Failed to create /run/quantra-system")?;
    let conf_path = format!("{run_dir}/wpa_supplicant-{interface}.conf");
    if tokio::fs::metadata(&conf_path).await.is_err() {
        let base = "ctrl_interface=/run/wpa_supplicant\nupdate_config=1\n";
        tokio::fs::write(&conf_path, base)
            .await
            .context("Failed to write wpa_supplicant base config")?;
    }

    let status = Command::new("wpa_cli")
        .args(["-i", interface, "ping"])
        .output()
        .await;
    let ok = status
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("PONG"))
        .unwrap_or(false);
    if ok {
        return Ok(conf_path);
    }

    let output = Command::new("wpa_supplicant")
        .args(["-B", "-i", interface, "-c", &conf_path])
        .output()
        .await
        .context("Failed to start wpa_supplicant")?;
    if !output.status.success() {
        anyhow::bail!(
            "wpa_supplicant failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(conf_path)
}

pub async fn wifi_connect(
    interface: &str,
    ssid: &str,
    password: Option<&str>,
    security: WifiSecurity,
    hidden: bool,
) -> Result<()> {
    let _conf = ensure_wpa_supplicant(interface).await?;

    let add = Command::new("wpa_cli")
        .args(["-i", interface, "add_network"])
        .output()
        .await
        .context("wpa_cli add_network failed")?;
    if !add.status.success() {
        anyhow::bail!(
            "wpa_cli add_network failed: {}",
            String::from_utf8_lossy(&add.stderr)
        );
    }
    let net_id = String::from_utf8_lossy(&add.stdout).trim().to_string();

    run_wpa(
        interface,
        &["set_network", &net_id, "ssid", &format!("\"{ssid}\"")],
    )
    .await?;
    if hidden {
        let _ = run_wpa(interface, &["set_network", &net_id, "scan_ssid", "1"]).await;
    }

    match security {
        WifiSecurity::Open => {
            run_wpa(interface, &["set_network", &net_id, "key_mgmt", "NONE"]).await?;
        }
        WifiSecurity::Wpa2Psk | WifiSecurity::Wpa3Psk => {
            let pw = password.context("Password required for secured WiFi")?;
            run_wpa(
                interface,
                &["set_network", &net_id, "psk", &format!("\"{pw}\"")],
            )
            .await?;
        }
        WifiSecurity::Wpa2Enterprise | WifiSecurity::Wpa3Enterprise => {
            anyhow::bail!("Enterprise WiFi is not supported yet");
        }
    }

    run_wpa(interface, &["enable_network", &net_id]).await?;
    run_wpa(interface, &["select_network", &net_id]).await?;
    let _ = run_wpa(interface, &["save_config"]).await;

    for _ in 0..30 {
        let status = Command::new("wpa_cli")
            .args(["-i", interface, "status"])
            .output()
            .await
            .context("wpa_cli status failed")?;
        let text = String::from_utf8_lossy(&status.stdout);
        if text.contains("wpa_state=COMPLETED") {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }

    anyhow::bail!(
        "WiFi connection timed out. Tip: check `wpa_cli -i <iface> log_level DEBUG` and try again."
    )
}

pub async fn wifi_disconnect(interface: &str) -> Result<()> {
    let _conf = ensure_wpa_supplicant(interface).await?;
    run_wpa(interface, &["disconnect"]).await?;
    Ok(())
}

async fn run_wpa(interface: &str, args: &[&str]) -> Result<()> {
    let output = Command::new("wpa_cli")
        .arg("-i")
        .arg(interface)
        .args(args)
        .output()
        .await
        .context("Failed to run wpa_cli")?;
    if !output.status.success() {
        anyhow::bail!(
            "wpa_cli failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

pub fn profiles_to_saved(profiles: &[WifiProfile]) -> Vec<WifiSavedNetwork> {
    profiles
        .iter()
        .map(|p| WifiSavedNetwork {
            ssid: p.ssid.clone(),
            security: p.security.clone(),
            autoconnect: p.autoconnect,
        })
        .collect()
}

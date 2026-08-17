use anyhow::{Context, Result};
use async_trait::async_trait;
use std::collections::VecDeque;
use std::io;
use std::process::Output;
use tokio::process::Command;

fn zx_tip_for_binary(bin: &str) -> Option<&'static str> {
    match bin {
        "nft" => Some("sudo zex infuse nftables"),
        "wg-quick" | "wg" => Some("sudo zex infuse wireguard-tools"),
        "openvpn" => Some("sudo zex infuse openvpn"),
        "iw" => Some("sudo zex infuse iw"),
        "wpa_supplicant" | "wpa_cli" => Some("sudo zex infuse wpa_supplicant"),
        "dhcpcd" => Some("sudo zex infuse dhcpcd"),
        "ping" => Some("sudo zex infuse iputils"),
        "ip" => Some("sudo zex infuse iproute2"),
        "kill" => None,
        _ => None,
    }
}

pub fn missing_binary_error(bin: &str) -> anyhow::Error {
    if let Some(tip) = zx_tip_for_binary(bin) {
        anyhow::anyhow!(
            "Error: '{}' command not found. Please install it by running: {}",
            bin,
            tip
        )
    } else {
        anyhow::anyhow!("Error: '{}' command not found.", bin)
    }
}

#[async_trait]
pub trait Exec: Send + Sync {
    async fn output(&self, bin: &str, args: &[&str]) -> Result<Output>;
}

pub struct RealExec;

#[async_trait]
impl Exec for RealExec {
    async fn output(&self, bin: &str, args: &[&str]) -> Result<Output> {
        let out = Command::new(bin).args(args).output().await;
        match out {
            Ok(o) => Ok(o),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(missing_binary_error(bin)),
            Err(e) => {
                Err(anyhow::Error::new(e)).with_context(|| format!("Failed to execute {}", bin))
            }
        }
    }
}

type ScriptedCall = (String, Vec<String>, Result<Output>);

#[derive(Default)]
pub struct MockExec {
    pub calls: tokio::sync::Mutex<Vec<(String, Vec<String>)>>,
    pub scripted: tokio::sync::Mutex<VecDeque<ScriptedCall>>,
}

impl MockExec {
    #[allow(dead_code)]
    pub fn push(&self, bin: &str, args: &[&str], result: Result<Output>) {
        let mut guard = futures::executor::block_on(self.scripted.lock());
        guard.push_back((
            bin.to_string(),
            args.iter().map(|s| s.to_string()).collect(),
            result,
        ));
    }
}

#[async_trait]
impl Exec for MockExec {
    async fn output(&self, bin: &str, args: &[&str]) -> Result<Output> {
        self.calls.lock().await.push((
            bin.to_string(),
            args.iter().map(|s| s.to_string()).collect(),
        ));

        let mut scripted = self.scripted.lock().await;
        if let Some((b, a, res)) = scripted.pop_front() {
            if b != bin || a != args.iter().map(|s| s.to_string()).collect::<Vec<_>>() {
                return Err(anyhow::anyhow!(
                    "MockExec expected {} {:?} but got {} {:?}",
                    b,
                    a,
                    bin,
                    args
                ));
            }
            res
        } else {
            Err(anyhow::anyhow!(
                "MockExec has no scripted result for {} {:?}",
                bin,
                args
            ))
        }
    }
}

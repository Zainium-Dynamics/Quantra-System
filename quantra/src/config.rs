use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct InitConfig {
    pub logging: LoggingConfig,
    pub services_dir: String,
    pub enabled_dir: String,
    pub hostname: Option<String>,
    #[serde(default)]
    pub strict_service_validation: bool,
    #[serde(default)]
    pub system: SystemConfig,
    #[serde(default)]
    pub features: FeaturesConfig,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct LoggingConfig {
    pub level: String,
    pub file: String,
    #[serde(default)]
    pub console_output: bool,
    #[serde(default)]
    pub format: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct SystemConfig {
    #[serde(default = "default_max_open_files")]
    pub max_open_files: u64,
    #[serde(default = "default_oom_score")]
    pub oom_score_adj: i32,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct FeaturesConfig {
    #[serde(default = "bool_true")]
    pub cgroups_support: bool,
    #[serde(default = "bool_true")]
    pub vt_support: bool,
}

// Referenced by #[serde(default = "...")] on SystemConfig/FeaturesConfig
// above (both #[allow(dead_code)] themselves — same not-yet-wired-up config
// schema situation, serde's derive calls these by name so they're not
// actually dead, just unreachable from rustc's conservative dead-code walk
// while nothing reads InitConfig::system/features yet).
#[allow(dead_code)]
fn default_max_open_files() -> u64 {
    65535
}
#[allow(dead_code)]
fn default_oom_score() -> i32 {
    -1000
}
#[allow(dead_code)]
fn bool_true() -> bool {
    true
}

impl Default for InitConfig {
    fn default() -> Self {
        Self {
            logging: LoggingConfig {
                level: "info".to_string(),
                // /overlayer/syshub/var → zexlib/union/var (writable) — OverlayFS COW ke baad
                file: "/overlayer/syshub/var/log/quantra-system/init.log".to_string(),
                console_output: true,
                format: None,
            },
            // OverlayFS ke baad yeh paths seedha accessible hain
            // /overlayer/syshub/etc/quantra-system/ = physical syshub/etc/quantra-system/
            services_dir: "/overlayer/syshub/etc/quantra-system/services".to_string(),
            enabled_dir: "/overlayer/syshub/etc/quantra-system/enabled".to_string(),
            hostname: Some("zainium".to_string()),
            strict_service_validation: false,
            system: SystemConfig::default(),
            features: FeaturesConfig::default(),
        }
    }
}

pub fn load(path: &str) -> Result<InitConfig> {
    let p = Path::new(path);
    if !p.exists() {
        log::warn!("Config '{}' not found — using defaults", path);
        return Ok(InitConfig::default());
    }
    let content = fs::read_to_string(p).with_context(|| format!("read {}", path))?;
    let cfg: InitConfig = toml::from_str(&content).with_context(|| format!("parse {}", path))?;
    log::info!("Config loaded: {}", path);
    Ok(cfg)
}

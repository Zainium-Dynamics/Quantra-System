/// Virtual console setup — font and keymap configuration
///
/// Applies console font and keyboard layout at boot.
/// Equivalent to systemd-vconsole-setup.
///
/// Config file: `/overlayer/syshub/etc/quantra-system/vconsole.conf`
///
/// ```ini
/// KEYMAP=us
/// KEYMAP_TOGGLE=
/// FONT=Lat2-Terminus16
/// FONT_MAP=
/// FONT_UNIMAP=
/// ```
///
/// # Implementation
///
/// Uses `loadkeys` for keymap and `setfont` for console font.
/// Falls back silently if the tools or font files are not present
/// (headless/embedded systems have no VT).
use anyhow::{Context, Result};
use log::{info, warn};
use std::fs;
use std::process::Command;

const VCONSOLE_CONF: &str = "/overlayer/syshub/etc/quantra-system/vconsole.conf";

#[allow(dead_code)]
const KEYMAP_PATHS: &[&str] = &[
    "/overlayer/syshub/share/keymaps",
    "/overlayer/syshub/lib/kbd/keymaps",
];

#[allow(dead_code)]
const FONT_PATHS: &[&str] = &[
    "/overlayer/syshub/share/consolefonts",
    "/overlayer/syshub/lib/kbd/consolefonts",
];

const LOADKEYS_BINS: &[&str] = &["/overlayer/syshub/bin/loadkeys"];
const SETFONT_BINS: &[&str] = &["/overlayer/syshub/bin/setfont"];

/// Console configuration parsed from vconsole.conf.
#[derive(Debug, Default)]
pub struct VconsoleConfig {
    pub keymap: Option<String>,
    pub keymap_toggle: Option<String>,
    pub font: Option<String>,
    pub font_map: Option<String>,
    pub font_unimap: Option<String>,
}

/// Load and apply vconsole configuration at boot.
///
/// Non-fatal — headless systems don't have VT tools.
pub fn setup() {
    match setup_inner() {
        Ok(()) => info!("vconsole: setup complete"),
        Err(e) => warn!("vconsole: {} (non-fatal — headless?)", e),
    }
}

fn setup_inner() -> Result<()> {
    let cfg = load_config()?;

    if let Some(ref keymap) = cfg.keymap {
        apply_keymap(keymap, cfg.keymap_toggle.as_deref())?;
    }

    if let Some(ref font) = cfg.font {
        apply_font(font, cfg.font_map.as_deref(), cfg.font_unimap.as_deref())?;
    }

    Ok(())
}

fn load_config() -> Result<VconsoleConfig> {
    let content = fs::read_to_string(VCONSOLE_CONF).unwrap_or_default(); // Missing config = use defaults

    let mut cfg = VconsoleConfig::default();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((key, val)) = line.split_once('=') {
            let val = val.trim().trim_matches('"').to_string();
            if val.is_empty() {
                continue;
            }
            match key.trim() {
                "KEYMAP" => cfg.keymap = Some(val),
                "KEYMAP_TOGGLE" => cfg.keymap_toggle = Some(val),
                "FONT" => cfg.font = Some(val),
                "FONT_MAP" => cfg.font_map = Some(val),
                "FONT_UNIMAP" => cfg.font_unimap = Some(val),
                _ => {}
            }
        }
    }

    // Default keymap if not configured
    if cfg.keymap.is_none() {
        cfg.keymap = Some("us".to_string());
    }

    Ok(cfg)
}

fn apply_keymap(keymap: &str, toggle: Option<&str>) -> Result<()> {
    let loadkeys = find_bin(LOADKEYS_BINS)
        .ok_or_else(|| anyhow::anyhow!("loadkeys not found in {:?}", LOADKEYS_BINS))?;

    let mut cmd = Command::new(&loadkeys);
    cmd.arg(keymap);

    if let Some(t) = toggle {
        cmd.arg("-T").arg(t);
    }

    let status = cmd
        .status()
        .with_context(|| format!("exec loadkeys {}", keymap))?;

    if status.success() {
        info!("vconsole: keymap '{}' loaded", keymap);
    } else {
        warn!("vconsole: loadkeys '{}' exit {:?}", keymap, status.code());
    }
    Ok(())
}

fn apply_font(font: &str, font_map: Option<&str>, unimap: Option<&str>) -> Result<()> {
    let setfont = find_bin(SETFONT_BINS)
        .ok_or_else(|| anyhow::anyhow!("setfont not found in {:?}", SETFONT_BINS))?;

    let mut cmd = Command::new(&setfont);
    cmd.arg(font);

    if let Some(m) = font_map {
        cmd.arg("-m").arg(m);
    }
    if let Some(u) = unimap {
        cmd.arg("-u").arg(u);
    }

    let status = cmd
        .status()
        .with_context(|| format!("exec setfont {}", font))?;

    if status.success() {
        info!("vconsole: font '{}' loaded", font);
    } else {
        warn!("vconsole: setfont '{}' exit {:?}", font, status.code());
    }
    Ok(())
}

fn find_bin(candidates: &[&str]) -> Option<String> {
    candidates
        .iter()
        .find(|&&p| std::path::Path::new(p).exists())
        .map(|&p| p.to_string())
}

/// Write default vconsole.conf if absent.
pub fn write_default_config() -> Result<()> {
    let path = std::path::Path::new(VCONSOLE_CONF);
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, "KEYMAP=us\nFONT=Lat2-Terminus16\n")?;
    Ok(())
}

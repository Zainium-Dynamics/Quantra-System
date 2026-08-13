/// Kernel command line parser
///
/// Parses `/proc/cmdline` to extract all boot parameters used by quantra-ramfs.
/// Must be called AFTER `/proc` is mounted (Phase 1).
///
/// # Supported parameters
///
/// | Parameter | Example | Description |
/// |-----------|---------|-------------|
/// | `root=` | `UUID=abc` / `LABEL=x` / `/dev/sda2` | Root device |
/// | `rootfstype=` | `ext4` | Filesystem type |
/// | `rootflags=` | `subvol=@,compress=zstd` | Extra mount options (Btrfs etc.) |
/// | `rootwait` | bare | Wait indefinitely for root device |
/// | `rootwait=N` | `rootwait=100` | Wait N×50ms for root device |
/// | `init=` | `/sbin/init` | Override init binary |
/// | `loop=` | `/zaisys/zairoot.squashfs` | Image path inside root device |
/// | `loopfstype=` | `squashfs` | Filesystem type of loop image |
/// | `luks=` | `luks-root` | LUKS dm-crypt mapping name |
/// | `luks_keyfile=` | `/dev/sdb1:/key.bin` | LUKS keyfile (`dev:path` or path) |
/// | `zainium.overlay=off` | bare | Disable OverlayFS (rescue mode) |
/// | `rd.verity=1` | bare | Enable dm-verity rootfs integrity |
/// | `rd.verity.data=` | `/dev/sda2` | Verity data device |
/// | `rd.verity.hash=` | `/dev/sda3` | Verity hash device |
/// | `rd.verity.roothash=` | `<64 hex chars>` | Expected root hash |
/// | `rd.verity.hashoffset=` | `0` | Hash tree byte offset on hash device |
/// | `rd.break=` | `pre-mount` / `pre-overlay` / `pre-pivot` | Drop to shell at phase |
/// | `rd.shell` | bare | Always drop to emergency shell before boot |
/// | `rd.rescue` | bare | Alias for `single` — boot to rescue target |
/// | `rd.fsck=0` | bare | Disable fsck (default: enabled) |
/// | `rd.tpm2=0` | bare | Disable TPM2 unseal (default: auto) |
/// | `rd.udev=0` | bare | Disable netlink udev (default: enabled) |
/// | `quiet` | bare | Suppress non-fatal output |
use std::fs;

/// All parsed boot parameters.
#[derive(Debug)]
#[allow(dead_code)]
pub struct Cmdline {
    // ── Root device ───────────────────────────────────────────────────────────
    /// Root device spec (UUID=..., LABEL=..., /dev/..., or NFS host:path)
    pub root: Option<String>,
    /// Filesystem type hint for the root device
    pub root_fstype: Option<String>,
    /// Extra mount options (e.g. `subvol=@,compress=zstd` for Btrfs)
    pub root_flags: Option<String>,
    /// rootwait=N retries × 50ms; Some(0) = infinite; None = default 20
    pub rootwait: Option<u32>,

    // ── Init ──────────────────────────────────────────────────────────────────
    /// Custom init binary (overrides discovery order in switch.rs).
    /// `None` means no `init=` was given — switch.rs always auto-discovers via
    /// `INIT_FALLBACKS` in that case rather than checking a hardcoded default.
    pub init: Option<String>,

    // ── Loop mount ───────────────────────────────────────────────────────────
    /// Path to squashfs/rootfs image inside root device
    pub loop_image: Option<String>,
    /// Filesystem type of the loop image (default: squashfs)
    pub loop_fstype: Option<String>,

    // ── LUKS ─────────────────────────────────────────────────────────────────
    /// dm-crypt mapping name (e.g. `luks-root`)
    pub luks_name: Option<String>,
    /// Keyfile spec: `<dev>:<path>` or direct path
    pub luks_keyfile: Option<String>,

    // ── dm-verity ─────────────────────────────────────────────────────────────
    /// Enable dm-verity rootfs integrity check
    pub verity_enabled: bool,
    /// Full raw cmdline string (used by verity::parse_verity_cmdline)
    pub raw: String,

    // ── Debug / rescue ────────────────────────────────────────────────────────
    /// Drop to emergency shell at this phase (pre-mount / pre-overlay / pre-pivot)
    pub rd_break: Option<RdBreak>,
    /// Drop to emergency shell unconditionally before boot
    pub rd_shell: bool,
    /// Boot to rescue/single-user mode
    pub rd_rescue: bool,

    // ── Feature flags ─────────────────────────────────────────────────────────
    /// Run fsck before mounting root (default: true)
    pub fsck_enabled: bool,
    /// Use TPM2 unseal for LUKS (default: true if blob present)
    pub tpm2_enabled: bool,
    /// Use netlink udev uevent processing (default: true)
    pub udev_enabled: bool,
    /// Suppress non-fatal boot output
    pub quiet: bool,

    // ── MEDIUM: Storage stacking ──────────────────────────────────────────
    /// Enable MD RAID assembly (rd.md=1)
    pub rd_md: bool,
    /// Specific MD RAID UUID to assemble (rd.md.uuid=)
    pub rd_md_uuid: Option<String>,
    /// Enable LVM activation (rd.lvm=1)
    pub rd_lvm: bool,
    /// Specific LVM volume group (rd.lvm.vg=)
    pub rd_lvm_vg: Option<String>,
    /// Enable device-mapper multipath (rd.multipath=1)
    pub rd_multipath: bool,
    /// Enable DHCP in initrd (ip=dhcp or ip=<iface>:dhcp)
    pub ip_dhcp: bool,
    /// Specific interface for DHCP
    pub ip_iface: Option<String>,
    /// Static IP spec (ip=<ip>::<gw>:<mask>:<host>:<iface>:none)
    pub ip_static: Option<String>,

    // ── MEDIUM: Security ──────────────────────────────────────────────────
    /// PKCS#11 URI for LUKS unlock (rd.luks.pkcs11-uri=)
    pub luks_pkcs11_uri: Option<String>,
    /// Enable Secure Boot UKI check
    pub secure_boot_check: bool,

    // ── LOW: Boot methods ─────────────────────────────────────────────────
    /// iSCSI initiator IQN
    pub iscsi_initiator: Option<String>,
    /// iSCSI target IQN
    pub iscsi_target_name: Option<String>,
    /// iSCSI target IP
    pub iscsi_target_ip: Option<String>,
    /// iSCSI target port (default 3260)
    pub iscsi_target_port: u16,
    /// NBD server "host:port"
    pub nbd: Option<String>,
    /// HTTP URL to fetch rootfs image
    pub rd_http_url: Option<String>,
    /// Enable IPv6 SLAAC (ipv6=dhcpv6 or ipv6=slaac)
    pub ipv6_slaac: bool,
    /// ZFS pool name for root
    pub zfs_pool: Option<String>,
    /// Enable Plymouth splash
    pub splash: bool,
    /// Plymouth theme override
    pub plymouth_theme: Option<String>,
    /// Console keymap override for initrd (rd.vconsole.keymap=)
    pub rd_vconsole_keymap: Option<String>,
    /// Stratis pool UUID (rd.stratis.unlock.type=)
    pub stratis_pool_uuid: Option<String>,
}

/// Phase at which `rd.break=` drops to emergency shell.
// "Pre" is load-bearing here (each variant means "right before phase X"),
// not accidental redundancy -- dropping it (clippy's suggestion) would
// lose that "before" semantic.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, PartialEq)]
pub enum RdBreak {
    /// Before Phase 4 (root mount)
    PreMount,
    /// Before Phase 4.5 (OverlayFS)
    PreOverlay,
    /// Before Phase 6 (pivot_root)
    PrePivot,
}

/// Parse `/proc/cmdline` and return a `Cmdline`.
///
/// Missing parameters use safe defaults. Never returns `Err` for absent
/// optional parameters — only returns `Err` if `/proc/cmdline` cannot be read.
pub fn parse() -> Result<Cmdline, String> {
    let raw = fs::read_to_string("/proc/cmdline")
        .map_err(|_| "cannot read /proc/cmdline — is /proc mounted?".to_string())?;

    let mut root = None;
    let mut root_fstype = None;
    let mut root_flags = None;
    let mut rootwait = None;
    let mut init = None;
    let mut loop_image = None;
    let mut loop_fstype = None;
    let mut luks_name = None;
    let mut luks_keyfile = None;
    let mut verity_enabled = false;
    let mut rd_break = None;
    let mut rd_shell = false;
    let mut rd_rescue = false;
    let mut fsck_enabled = true;
    let mut tpm2_enabled = true;
    let mut udev_enabled = true;
    let mut quiet = false;

    for tok in raw.split_whitespace() {
        if let Some(v) = tok.strip_prefix("root=") {
            root = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("rootfstype=") {
            root_fstype = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("rootflags=") {
            root_flags = Some(v.to_string());
        } else if tok == "rootwait" {
            rootwait = Some(0); // bare = infinite
        } else if let Some(v) = tok.strip_prefix("rootwait=") {
            rootwait = v.parse::<u32>().ok();
        } else if let Some(v) = tok.strip_prefix("init=") {
            init = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("loop=") {
            loop_image = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("loopfstype=") {
            loop_fstype = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("luks=") {
            luks_name = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("luks_keyfile=") {
            luks_keyfile = Some(v.to_string());
        } else if tok == "rd.verity=1" {
            verity_enabled = true;
        } else if let Some(v) = tok.strip_prefix("rd.break=") {
            rd_break = Some(match v {
                "pre-mount" => RdBreak::PreMount,
                "pre-overlay" => RdBreak::PreOverlay,
                "pre-pivot" => RdBreak::PrePivot,
                other => {
                    eprintln!("  WARN: unknown rd.break value '{}' — ignoring", other);
                    continue;
                }
            });
        } else if tok == "rd.shell" {
            rd_shell = true;
        } else if tok == "rd.rescue" || tok == "single" || tok == "s" {
            rd_rescue = true;
        } else if tok == "rd.fsck=0" {
            fsck_enabled = false;
        } else if tok == "rd.tpm2=0" {
            tpm2_enabled = false;
        } else if tok == "rd.udev=0" {
            udev_enabled = false;
        } else if tok == "quiet" {
            quiet = true;
        }
    }

    Ok(Cmdline {
        root,
        root_fstype,
        root_flags,
        rootwait,
        init,
        loop_image,
        loop_fstype,
        luks_name,
        luks_keyfile,
        verity_enabled,
        raw: raw.trim().to_string(),
        rd_break,
        rd_shell,
        rd_rescue,
        fsck_enabled,
        tpm2_enabled,
        udev_enabled,
        quiet,
        // Medium/Low — parsed below
        rd_md: raw.split_whitespace().any(|t| t == "rd.md=1"),
        rd_md_uuid: raw
            .split_whitespace()
            .find_map(|t| t.strip_prefix("rd.md.uuid=").map(str::to_string)),
        rd_lvm: raw.split_whitespace().any(|t| t == "rd.lvm=1"),
        rd_lvm_vg: raw
            .split_whitespace()
            .find_map(|t| t.strip_prefix("rd.lvm.vg=").map(str::to_string)),
        rd_multipath: raw.split_whitespace().any(|t| t == "rd.multipath=1"),
        ip_dhcp: raw
            .split_whitespace()
            .any(|t| t == "ip=dhcp" || t.ends_with(":dhcp")),
        ip_iface: raw.split_whitespace().find_map(|t| {
            if t.contains(":dhcp") && t != "ip=dhcp" {
                t.strip_prefix("ip=")
                    .map(|s| s.trim_end_matches(":dhcp").to_string())
            } else {
                None
            }
        }),
        ip_static: raw.split_whitespace().find_map(|t| {
            let v = t.strip_prefix("ip=")?;
            if !v.contains("dhcp") && v.contains(':') {
                Some(v.to_string())
            } else {
                None
            }
        }),
        luks_pkcs11_uri: raw
            .split_whitespace()
            .find_map(|t| t.strip_prefix("rd.luks.pkcs11-uri=").map(str::to_string)),
        secure_boot_check: raw.split_whitespace().any(|t| t == "rd.secure-boot=1"),
        iscsi_initiator: raw
            .split_whitespace()
            .find_map(|t| t.strip_prefix("rd.iscsi.initiator=").map(str::to_string)),
        iscsi_target_name: raw
            .split_whitespace()
            .find_map(|t| t.strip_prefix("rd.iscsi.target.name=").map(str::to_string)),
        iscsi_target_ip: raw
            .split_whitespace()
            .find_map(|t| t.strip_prefix("rd.iscsi.target.ip=").map(str::to_string)),
        iscsi_target_port: raw
            .split_whitespace()
            .find_map(|t| {
                t.strip_prefix("rd.iscsi.target.port=")
                    .and_then(|v| v.parse().ok())
            })
            .unwrap_or(3260),
        nbd: raw
            .split_whitespace()
            .find_map(|t| t.strip_prefix("nbd=").map(str::to_string)),
        rd_http_url: raw
            .split_whitespace()
            .find_map(|t| t.strip_prefix("rd.http.url=").map(str::to_string)),
        ipv6_slaac: raw
            .split_whitespace()
            .any(|t| t == "ipv6=dhcpv6" || t == "ipv6=slaac"),
        zfs_pool: raw
            .split_whitespace()
            .find_map(|t| t.strip_prefix("zfs.pool=").map(str::to_string)),
        splash: raw.split_whitespace().any(|t| t == "splash"),
        plymouth_theme: raw
            .split_whitespace()
            .find_map(|t| t.strip_prefix("plymouth.theme=").map(str::to_string)),
        rd_vconsole_keymap: raw
            .split_whitespace()
            .find_map(|t| t.strip_prefix("rd.vconsole.keymap=").map(str::to_string)),
        stratis_pool_uuid: raw
            .split_whitespace()
            .find_map(|t| t.strip_prefix("rd.stratis.uuid=").map(str::to_string)),
    })
}

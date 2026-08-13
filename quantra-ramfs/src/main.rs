mod cmdline;
mod emergency;
mod fsck;
mod measured_boot;
mod mounts;
mod network_boot;
mod overlay;
mod phases;
mod plymouth;
mod raid;
mod rootfs;
mod switch;
mod tpm2;
mod udev;
mod verity;

use cmdline::RdBreak;
use phases::{BootPhase, set_phase};
use std::time::{Duration, Instant};

/// Zainium Initramfs — Stage-1 Boot Orchestrator
///
/// # Boot Flow
///
/// ```text
/// [0] INIT          — binary started
/// [1] MOUNTS        — /proc /sys /dev /run + loop nodes + netlink udev
/// [2] CMDLINE       — /proc/cmdline parsed; rd.shell / rd.break checks
/// [3] ROOTFS_DETECT — resolve root= → block device path; udev settle
/// [4] ROOTFS_MOUNT  — fsck + LUKS/TPM2 unseal + dm-verity + mount → /zairoot
/// [4.5] OVERLAY     — OverlayFS: syshub:zaisys + zexlib → /new_root
/// [5] (implicit)    — init binary discovery in /new_root
/// [6] PIVOT         — measure init + MS_MOVE + pivot_root + execv quantra
/// [7] COMPLETE      — execv issued; initramfs done
/// ```
///
/// Every phase extends TPM2 PCR[8] for measured boot (non-fatal if no TPM2).
/// Any fatal error drops to the built-in emergency shell.
fn main() -> ! {
    let boot_start = Instant::now();

    set_phase(BootPhase::INIT);

    eprintln!();
    eprintln!(
        "      Quantra Initramfs  v{}{}",
        env!("ZAINIUM_VERSION"),
        " ".repeat(20usize.saturating_sub(env!("ZAINIUM_VERSION").len()))
    );

    eprintln!(
        "  Build:  {} ({})",
        env!("BUILD_COMMIT"),
        env!("BUILD_TARGET")
    );
    eprintln!("  Opt:    {}", env!("OPTIMIZATION"));
    eprintln!();

    // ── Plymouth splash (start early, before mounts) ──────────────────────
    // Reads /proc/cmdline — requires /proc to be mounted first, so we do a
    // minimal proc mount here, then let mounts::mount_early() handle the rest.
    // Non-fatal — plymouth absent = silent boot.
    // Note: /proc not yet mounted; Plymouth check done after mounts.

    // ── Phase 1: Early mounts ─────────────────────────────────────────────────
    set_phase(BootPhase::MOUNTS);
    let t = Instant::now();
    if let Err(e) = mounts::mount_early() {
        eprintln!("FATAL: Early mounts failed: {}", e);
        emergency::shell("early mount failed");
    }
    eprintln!("  [{}ms] /proc /sys /dev /run OK", t.elapsed().as_millis());

    // Plymouth splash — start after /proc is mounted
    let t = Instant::now();
    if plymouth::is_enabled() {
        plymouth::setup_kms_framebuffer();
        plymouth::start(None);
        eprintln!("  [{}ms] plymouth", t.elapsed().as_millis());
    }

    // vconsole keymap in initrd
    plymouth::setup_initrd_vconsole();

    // Secure Boot check
    let _sb_status = plymouth::check_secure_boot();

    // Measure cmdline now that /proc is available
    measured_boot::measure_cmdline();

    // ── udev: process existing + incoming block device uevents ────────────────
    // Run briefly here so that devices present at boot time get /dev nodes
    // before we try to access them in Phase 3.
    let t = Instant::now();
    let udev_pre_count = udev::settle(Duration::from_millis(500));
    if udev_pre_count > 0 {
        eprintln!(
            "  [{}ms] udev: {} device(s) from sysfs",
            t.elapsed().as_millis(),
            udev_pre_count
        );
    }

    // ── Live medium probe ─────────────────────────────────────────────────────
    let t = Instant::now();
    match rootfs::prepare_live_medium_bridge() {
        Ok(Some(path)) => eprintln!(
            "  [{}ms] Live medium: {}",
            t.elapsed().as_millis(),
            path.display()
        ),
        Ok(None) => eprintln!(
            "  [{}ms] Live medium: not found (installed mode)",
            t.elapsed().as_millis()
        ),
        Err(e) => eprintln!(
            "  [{}ms] Live probe: {} (non-fatal)",
            t.elapsed().as_millis(),
            e
        ),
    }

    // ── Phase 2: Parse cmdline ────────────────────────────────────────────────
    set_phase(BootPhase::CMDLINE);
    let t = Instant::now();
    let cmdline = match cmdline::parse() {
        Ok(c) => {
            eprintln!("  [{}ms] Cmdline OK", t.elapsed().as_millis());
            c
        }
        Err(e) => {
            eprintln!("FATAL: Cmdline parse failed: {}", e);
            emergency::shell("cmdline parse");
        }
    };

    // rd.shell — unconditional emergency shell (useful for debugging)
    if cmdline.rd_shell {
        eprintln!("  rd.shell: dropping to emergency shell (cmdline request)");
        emergency::shell("rd.shell");
    }

    // rd.rescue / single — set init to rescue target
    if cmdline.rd_rescue {
        eprintln!(
            "  rd.rescue: rescue mode — will exec a rescue shell under /overlayer/syshub/bin"
        );
    }

    // ── Phase 3: Detect root device ───────────────────────────────────────────
    set_phase(BootPhase::ROOTFS_DETECT);
    let t = Instant::now();

    // rd.break=pre-mount — drop to shell before we touch the disk
    if cmdline.rd_break == Some(RdBreak::PreMount) {
        eprintln!("  rd.break=pre-mount: dropping to emergency shell");
        emergency::shell("rd.break=pre-mount");
    }

    // Extra udev settle if udev is enabled — wait for slow devices
    if cmdline.udev_enabled {
        let rootwait_ms = match cmdline.rootwait {
            Some(0) => 10_000, // bare rootwait — give udev 10s
            Some(n) => n as u64 * 50,
            None => 1_000, // default 1s
        };
        let extra = udev::settle(Duration::from_millis(rootwait_ms.min(3_000)));
        if extra > 0 {
            eprintln!("  udev: +{} device(s) after settle", extra);
        }
        // Build /dev/disk/by-uuid and /dev/disk/by-label symlinks
        let sym_count = udev::create_disk_symlinks();
        if sym_count > 0 {
            eprintln!("  udev: {} disk symlinks created", sym_count);
        }
    }

    // DHCP in initrd (for NFS root, iSCSI, NBD, HTTP boot)
    if cmdline.ip_dhcp {
        let t = Instant::now();
        let iface = cmdline.ip_iface.as_deref();
        let lease = if let Some(iface) = iface {
            network_boot::dhcp_acquire(iface, std::time::Duration::from_secs(10))
                .map_err(|e| {
                    eprintln!("  dhcp: {}", e);
                    e
                })
                .ok()
        } else {
            network_boot::dhcp_any_interface(std::time::Duration::from_secs(10))
        };
        if lease.is_some() {
            eprintln!("  [{}ms] dhcp OK", t.elapsed().as_millis());
        } else {
            eprintln!("  [{}ms] dhcp failed (non-fatal)", t.elapsed().as_millis());
        }
    }

    // IPv6 SLAAC
    if cmdline.ipv6_slaac {
        for iface in network_boot::list_interfaces() {
            network_boot::enable_ipv6_slaac(&iface).ok();
        }
    }

    // MD RAID assembly
    if cmdline.rd_md {
        let t = Instant::now();
        match raid::assemble_raid(cmdline.rd_md_uuid.as_deref()) {
            Ok(n) => eprintln!("  [{}ms] MD RAID: {} array(s)", t.elapsed().as_millis(), n),
            Err(e) => eprintln!("  WARN: MD RAID: {} (non-fatal)", e),
        }
        raid::wait_for_raid_sync(std::time::Duration::from_secs(30));
    }

    // LVM activation
    if cmdline.rd_lvm {
        let t = Instant::now();
        match raid::activate_lvm(cmdline.rd_lvm_vg.as_deref()) {
            Ok(n) => eprintln!("  [{}ms] LVM: {} volume(s)", t.elapsed().as_millis(), n),
            Err(e) => eprintln!("  WARN: LVM: {} (non-fatal)", e),
        }
    }

    // Device multipath
    if cmdline.rd_multipath {
        let t = Instant::now();
        match raid::activate_multipath() {
            Ok(()) => eprintln!("  [{}ms] multipath OK", t.elapsed().as_millis()),
            Err(e) => eprintln!("  WARN: multipath: {} (non-fatal)", e),
        }
    }

    // Stratis pool unlock
    if let Some(ref uuid) = cmdline.stratis_pool_uuid {
        raid::unlock_stratis_pool(Some(uuid.as_str())).ok();
    }

    // iSCSI root
    if let Some(ref target_name) = cmdline.iscsi_target_name {
        if let Some(ref target_ip) = cmdline.iscsi_target_ip {
            let iscsi = network_boot::IscsiTarget {
                initiator_iqn: cmdline
                    .iscsi_initiator
                    .clone()
                    .unwrap_or_else(|| "iqn.2026-01.os.zainium:initrd".to_string()),
                target_iqn: target_name.clone(),
                target_ip: target_ip.clone(),
                target_port: cmdline.iscsi_target_port,
            };
            match network_boot::connect_iscsi(&iscsi) {
                Ok(dev) => eprintln!("  iSCSI: device = {}", dev),
                Err(e) => eprintln!("  WARN: iSCSI: {} (non-fatal)", e),
            }
        }
    }

    // NBD root
    if let Some(ref nbd_spec) = cmdline.nbd {
        let parts: Vec<&str> = nbd_spec.splitn(2, ':').collect();
        if parts.len() == 2 {
            if let Ok(port) = parts[1].parse::<u16>() {
                match network_boot::connect_nbd(parts[0], port, None) {
                    Ok(dev) => eprintln!("  NBD: device = {}", dev),
                    Err(e) => eprintln!("  WARN: NBD: {} (non-fatal)", e),
                }
            }
        }
    }

    let root_device = match rootfs::find_root(&cmdline) {
        Ok(dev) => {
            eprintln!("  [{}ms] Root: {:?}", t.elapsed().as_millis(), dev);
            dev
        }
        Err(e) => {
            eprintln!("FATAL: Root device not found: {}", e);
            emergency::shell("root detect");
        }
    };

    // ── Phase 4: Mount root filesystem ───────────────────────────────────────
    set_phase(BootPhase::ROOTFS_MOUNT);
    let t = Instant::now();

    let zairoot = switch::find_mount_target(&cmdline).unwrap_or_else(|| {
        eprintln!("FATAL: No usable mount target found");
        emergency::shell("no mount target");
    });

    // fsck before mounting (skipped for squashfs/iso/loop/NFS)
    if cmdline.fsck_enabled {
        let fstype_ref = cmdline.root_fstype.as_deref();
        if let Err(e) = fsck::check_root(&root_device, fstype_ref) {
            if e.contains("REBOOT REQUIRED") {
                eprintln!("  fsck: reboot required — rebooting in 3s...");
                std::thread::sleep(Duration::from_secs(3));
                unsafe {
                    libc::sync();
                    libc::reboot(libc::RB_AUTOBOOT);
                }
                // reboot(2) does not return on success; this only runs if it
                // somehow did anyway. Sleep instead of a busy-spin while the
                // kernel actually reboots.
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                }
            } else {
                eprintln!(
                    "  WARN: fsck: {} — continuing (manual check recommended)",
                    e
                );
            }
        }
    }

    // dm-verity: set up verified device before mounting
    let actual_root_device = if cmdline.verity_enabled {
        match setup_verity_device(&cmdline, &root_device) {
            Ok(verified_dev) => {
                eprintln!(
                    "  [{}ms] dm-verity: using {}",
                    t.elapsed().as_millis(),
                    verified_dev
                );
                verified_dev
            }
            Err(e) => {
                eprintln!("FATAL: dm-verity setup failed: {}", e);
                emergency::shell("dm-verity failed");
            }
        }
    } else {
        root_device.clone()
    };

    // Mount root
    if let Err(e) = rootfs::mount_root_at(&actual_root_device, &cmdline, zairoot) {
        eprintln!("FATAL: Root mount failed: {}", e);
        emergency::shell("root mount");
    }
    eprintln!("  [{}ms] Disk → {}", t.elapsed().as_millis(), zairoot);

    // rd.break=pre-overlay — shell after disk mount, before OverlayFS
    if cmdline.rd_break == Some(RdBreak::PreOverlay) {
        eprintln!("  rd.break=pre-overlay: dropping to emergency shell");
        emergency::shell("rd.break=pre-overlay");
    }

    // ── Phase 4.5: OverlayFS → /new_root ─────────────────────────────────────
    set_phase(BootPhase::OVERLAY);
    let t = Instant::now();

    let overlay_enabled = !overlay::overlay_disabled_by_cmdline();
    measured_boot::measure_overlay_mode(overlay_enabled);

    let new_root = if !overlay_enabled {
        eprintln!(
            "  [{}ms] OverlayFS DISABLED (zainium.overlay=off) — syshub only",
            t.elapsed().as_millis()
        );
        zairoot.to_string()
    } else {
        match overlay::mount_overlay(zairoot) {
            Ok(r) => {
                eprintln!("  [{}ms] OverlayFS → {}", t.elapsed().as_millis(), r);
                r
            }
            Err(e) => {
                eprintln!(
                    "  WARN: OverlayFS failed: {} — read-only fallback to {}",
                    e, zairoot
                );
                zairoot.to_string()
            }
        }
    };

    // ── Phase 5: Discover init binary ────────────────────────────────────────
    // In rescue mode, override init discovery to /bin/sh
    let boot_target = if cmdline.rd_rescue {
        switch::rescue_boot_target()
    } else {
        switch::discover_boot_target(&cmdline, &new_root)
    };

    eprintln!(
        "  Init: {} ({}{})",
        boot_target.init_path, new_root, boot_target.init_path
    );

    // rd.break=pre-pivot — last chance before we hand over to PID 1
    if cmdline.rd_break == Some(RdBreak::PrePivot) {
        eprintln!("  rd.break=pre-pivot: dropping to emergency shell");
        emergency::shell("rd.break=pre-pivot");
    }

    // ── Measured boot: record the exact init binary ───────────────────────────
    measured_boot::measure_init_binary(&new_root, boot_target.init_path);

    // ── Plymouth: signal root mounted before pivot ────────────────────────────
    plymouth::root_mounted();
    plymouth::update_status("initrd-done");

    // ── Phase 6: pivot_root → execv quantra ──────────────────────────────────
    set_phase(BootPhase::PIVOT);
    let t = Instant::now();
    if let Err(e) = switch::pivot_to_root(&boot_target) {
        eprintln!("FATAL: switch_root failed: {}", e);
        emergency::shell("switch_root");
    }
    eprintln!("  [{}ms] switch_root complete", t.elapsed().as_millis());
    plymouth::handoff_to_init();

    // ── Complete ──────────────────────────────────────────────────────────────
    set_phase(BootPhase::COMPLETE);
    eprintln!();
    eprintln!("  Initramfs total: {}ms", boot_start.elapsed().as_millis());

    emergency::shell("execv returned unexpectedly");
}

// ── dm-verity setup helper ────────────────────────────────────────────────────

/// Parse verity config from cmdline and set up the dm-verity device.
/// Returns the path to the verified device (`/dev/mapper/zainium-verity`).
fn setup_verity_device(cmdline: &cmdline::Cmdline, root_device: &str) -> Result<String, String> {
    match verity::parse_verity_cmdline(&cmdline.raw) {
        None => Err("rd.verity=1 set but no verity params found in cmdline".to_string()),
        Some(Err(e)) => Err(format!("verity cmdline parse: {}", e)),
        Some(Ok(mut cfg)) => {
            // If data device not specified in verity params, use root device
            if cfg.data_device.is_empty() {
                cfg.data_device = root_device.to_string();
            }
            let dev = verity::setup_verity(&cfg)?;
            Ok(dev.path)
        }
    }
}

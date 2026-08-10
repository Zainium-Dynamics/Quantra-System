/// Root filesystem switching — OverlayFS-aware pivot_root + init discovery
///
/// # Architecture
///
/// Boot flow as seen by this module:
///
/// ```text
///   /zairoot           ← physical disk partition (Phase 4)
///   /new_root          ← OverlayFS merged view  (Phase 4.5)
///   pivot_root         ← /new_root becomes /     (Phase 6)
///   execv quantra      ← PID 1 takes over
/// ```
///
/// After OverlayFS is mounted, `discover_boot_target` searches `/new_root`
/// for the init binary. `pivot_to_root` then hard-wires to `/new_root` as the
/// switch target regardless of where the physical disk was mounted.
///
/// # Mount Target Priority  (physical disk, Phase 4)
///
/// ```
/// /zairoot    ← Zainium OS preferred
/// /mnt/root   ← Standard Linux initramfs (Arch, Gentoo, …)
/// /sysroot    ← systemd initrd compat (Fedora, RHEL, …)
/// /newroot    ← BusyBox-style initramfs
/// ```
///
/// # Init Binary Priority  (inside /new_root, Phase 5)
///
/// Paths below are relative to `/new_root`. Under Zainium's "Option B"
/// architecture (see `overlay.rs`), the OverlayFS merge of `overlayer/syshub`
/// + `overlayer/zaisys` lands at `/new_root/overlayer/syshub`, **not** at
/// `/new_root` itself — there is no flattened `/bin`, `/sbin`, `/usr` at the
/// tmpfs root. Zainium-native candidates (Phase 1, Phase 3) are therefore
/// prefixed with `/overlayer/syshub`. Phase 2 is the exception: it exists to
/// chainload a *foreign* Linux disk that never went through
/// `overlay::mount_overlay` at all (its `overlayer/syshub` sanity check
/// failed, so `new_root` falls back to the raw physical mount with a normal
/// FHS layout) — those candidates stay unprefixed on purpose.
///
/// ```
/// Phase 1 — Zainium OS Core  (highest priority):
///   /overlayer/syshub/engine/quantra        ← Zainium PID 1 (normal boot)
///   /overlayer/syshub/engine/s6-quantra     ← Zainium s6-based fallback
///
/// Phase 2 — Standard Linux compatibility (foreign disk, no overlayer/syshub):
///   /sbin/init                              ← Debian/Ubuntu/Arch/Gentoo
///   /usr/lib/systemd/systemd               ← Fedora/RHEL/openSUSE
///   /lib/systemd/systemd                   ← Debian systemd alternate path
///   /usr/sbin/init                         ← Some BSDs / older distros
///
/// Phase 3 — Emergency rescue shells (ship inside syshub):
///   /overlayer/syshub/bin/fish    ← Advanced rescue (colours, autocompletion)
///   /overlayer/syshub/bin/bash    ← Standard rescue shell
///   /overlayer/syshub/bin/zsh     ← Alternative rescue shell
///   /overlayer/syshub/bin/sh      ← Absolute last resort (dash / busybox sh)
/// ```
///
/// This same prefixing makes the `zainium.overlay=off` / OverlayFS-mount-
/// failure fallback work for free: in both cases `new_root` becomes
/// `/zairoot` directly, which — being the real Zainium disk — already has
/// `overlayer/syshub` as a genuine subdirectory, so `{new_root}/overlayer/syshub/engine/quantra`
/// resolves correctly without any special-casing here.
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::unistd::{chdir, chroot, execv, pivot_root};
use std::ffi::CString;
use std::fs;
use std::path::Path;

use crate::cmdline::Cmdline;

// ── Constants ────────────────────────────────────────────────────────────────

/// Physical disk mount targets tried in priority order.
/// The first directory that can be created (or already exists) is used.
const MOUNT_TARGETS: &[&str] = &[
    "/zairoot",  // Zainium OS preferred
    "/mnt/root", // Standard Linux initramfs (Arch, Gentoo, …)
    "/sysroot",  // systemd initrd compatibility (Fedora, RHEL, …)
    "/newroot",  // BusyBox-style initramfs
];

/// Init binaries searched inside the merged `/new_root`, in priority order.
/// Zainium-native candidates (Phase 1, Phase 3) are relative to `/new_root`
/// but carry an explicit `/overlayer/syshub` prefix, since under "Option B"
/// (see `overlay.rs`) that is where the OverlayFS merge actually lands — the
/// tmpfs root itself has no `bin/`, `sbin/`, `usr/`. Phase 2 candidates stay
/// unprefixed: they only ever match when `new_root` is a foreign, non-Zainium
/// disk mounted with a plain FHS layout (see module doc comment above).
const INIT_FALLBACKS: &[&str] = &[
    // ── Phase 1: Zainium OS Core ─────────────────────────────────────────────
    "/overlayer/syshub/engine/quantra", // Zainium PID 1 (normal boot)
    "/overlayer/syshub/engine/s6-quantra", // Zainium s6-based fallback
    // ── Phase 2: Standard Linux compatibility (foreign disk only) ─────────────
    "/sbin/init",               // Debian / Ubuntu / Arch / Gentoo
    "/usr/lib/systemd/systemd", // Fedora / RHEL / openSUSE
    "/lib/systemd/systemd",     // Debian systemd alternate path
    "/usr/sbin/init",           // Some BSDs / older distros
    // ── Phase 3: Emergency rescue shells (ship inside syshub) ─────────────────
    "/overlayer/syshub/bin/fish", // Advanced rescue (colours, autocompletion)
    "/overlayer/syshub/bin/bash", // Standard rescue shell
    "/overlayer/syshub/bin/zsh",  // Alternative rescue shell
    "/overlayer/syshub/bin/sh",   // Absolute last resort (dash / busybox sh)
];

/// Pseudo-filesystem mount points to MS_MOVE into the new root before pivoting.
/// Order matters: /dev must move before /proc and /sys on some kernels.
const MOUNT_MOVE_ORDER: &[&str] = &["/dev", "/proc", "/sys", "/run"];

// ── Data types ───────────────────────────────────────────────────────────────

/// Result of the mount + init-discovery phase.
///
/// Passed from `discover_boot_target` into `pivot_to_root`.
#[derive(Debug)]
pub struct BootTarget {
    /// Physical disk mount point (e.g. `/zairoot`).
    /// Used by `pivot_to_root` only for diagnostics; the actual pivot target
    /// is always `/new_root` (the OverlayFS merged view).
    pub mount_point: &'static str,
    /// Init binary path relative to root (e.g. `/engine/quantra`).
    pub init_path: &'static str,
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Select the physical disk mount point.
///
/// Iterates `MOUNT_TARGETS` and returns the first entry whose directory can be
/// created (or already exists). The directory is created here so the caller can
/// immediately call `rootfs::mount_root_at` against it.
///
/// Returns `None` only if the filesystem is completely read-only and none of
/// the candidates already exist (pathological initramfs configuration).
pub fn find_mount_target(_cmdline: &Cmdline) -> Option<&'static str> {
    for &target in MOUNT_TARGETS {
        if fs::create_dir_all(target).is_ok() {
            eprintln!("  Mount target: {}", target);
            return Some(target);
        }
    }
    // All create_dir_all calls failed (read-only tmpfs?) — fall back to
    // any candidate that already exists.
    MOUNT_TARGETS
        .iter()
        .find(|&&t| Path::new(t).exists())
        .copied()
}

/// Discover the init binary inside the merged `/new_root`.
///
/// Iterates `INIT_FALLBACKS` and returns the relative path of the first entry
/// that exists at `{new_root}{candidate}`.
pub fn find_init_binary(new_root: &str) -> Option<&'static str> {
    for &candidate in INIT_FALLBACKS {
        let full = format!("{}{}", new_root, candidate);
        if Path::new(&full).exists() {
            eprintln!("  Init binary: {}{}", new_root, candidate);
            return Some(candidate);
        }
    }
    None
}

/// Build a `BootTarget` by auto-discovering or honouring the `init=` cmdline override.
///
/// Called after OverlayFS is mounted at `new_root`. At this point `new_root` is
/// typically `/new_root` (the OverlayFS merged view) or `/zairoot` when overlay
/// is disabled by cmdline.
pub fn discover_boot_target(cmdline: &Cmdline, new_root: &str) -> BootTarget {
    // Honour an explicit `init=` cmdline override when the binary exists.
    // Only taken when the user actually passed init= — with no override,
    // we always run the full INIT_FALLBACKS auto-discovery below instead of
    // silently trusting a single hardcoded path.
    if let Some(cmdline_init) = cmdline.init.as_deref() {
        let full = format!("{}{}", new_root, cmdline_init);
        if Path::new(&full).exists() {
            eprintln!("  Using cmdline init=: {}", cmdline_init);
            let mount = MOUNT_TARGETS
                .iter()
                .find(|&&t| Path::new(t).exists())
                .copied()
                .unwrap_or(MOUNT_TARGETS[0]);
            // Map the user-supplied path to a static str from INIT_FALLBACKS if
            // it matches a known candidate; otherwise fall back to the first entry
            // so BootTarget keeps its &'static str invariant.
            let init = INIT_FALLBACKS
                .iter()
                .find(|&&i| i == cmdline_init)
                .copied()
                .unwrap_or(INIT_FALLBACKS[0]);
            return BootTarget {
                mount_point: mount,
                init_path: init,
            };
        }
        eprintln!(
            "  WARNING: cmdline init={} not found — falling back to auto-discovery",
            cmdline_init
        );
    }

    // Auto-discover from priority list
    let init_path = find_init_binary(new_root).unwrap_or_else(|| {
        eprintln!("  WARNING: No init binary found — rescue shell");
        "/bin/sh"
    });

    let mount_point = MOUNT_TARGETS
        .iter()
        .find(|&&t| Path::new(t).exists())
        .copied()
        .unwrap_or(MOUNT_TARGETS[0]);

    BootTarget {
        mount_point,
        init_path,
    }
}

/// Perform the final `pivot_root` + `execv` transition.
///
/// # Steps
/// 1. MS_MOVE `/dev`, `/proc`, `/sys`, `/run` into `/new_root/`.
/// 2. `pivot_root("/new_root", "/new_root/.old_root")` — makes `/new_root` the new `/`.
/// 3. `umount2("/.old_root", MNT_DETACH)` — detaches the physical disk;
///    `/zairoot` becomes invisible to all new processes.
/// 4. `execv(init_path, …)` — hands control to Quantra (or the discovered init).
///
/// If `pivot_root` fails (e.g. live ISO with read-only squashfs as initramfs root),
/// `chroot` is used as a fallback — this covers `zainium.overlay=off` + live ISO.
///
/// # Errors
/// Returns `Err` only if MS_MOVE, chdir, or execv fails. Never returns on success.
pub fn pivot_to_root(target: &BootTarget) -> Result<(), String> {
    // The OverlayFS layer always mounts at /new_root. When overlay is disabled,
    // main.rs sets new_root = zairoot (string), but pivot_to_root must still pivot
    // to /new_root if it was created, else fall through to chroot on target.mount_point.
    //
    // Strategy: prefer /new_root if it exists (OverlayFS case), otherwise use
    // the physical mount_point directly (overlay-disabled case).
    let new_root = if Path::new("/new_root").exists() {
        "/new_root"
    } else {
        target.mount_point
    };
    let init_rel = target.init_path;

    eprintln!("  switch_root: {} → exec {}", new_root, init_rel);

    // Step 1: MS_MOVE pseudo-filesystems into new root
    for &mp in MOUNT_MOVE_ORDER {
        let dest = format!("{}{}", new_root, mp);
        // Directory may already exist inside the OverlayFS; ok if create fails.
        fs::create_dir_all(&dest).ok();

        mount(
            Some(mp),
            dest.as_str(),
            None::<&str>,
            MsFlags::MS_MOVE,
            None::<&str>,
        )
        .map_err(|e| format!("MS_MOVE {} → {}: {}", mp, dest, e))?;
    }

    // Step 2: chdir into new root
    chdir(new_root).map_err(|e| format!("chdir {}: {}", new_root, e))?;

    // Step 3: pivot_root(2)
    let old_root = format!("{}/.old_root", new_root);
    fs::create_dir_all(&old_root).ok();

    let pivot_ok = match pivot_root(new_root, old_root.as_str()) {
        Ok(()) => {
            chdir("/").map_err(|e| format!("chdir / post-pivot: {}", e))?;
            // Detach the physical disk — /zairoot is now invisible
            let _ = umount2("/.old_root", MntFlags::MNT_DETACH);
            let _ = fs::remove_dir("/.old_root");
            eprintln!("  ✓ pivot_root OK — /zairoot detached");
            true
        }
        Err(e) => {
            eprintln!("  pivot_root failed ({}) — chroot fallback", e);
            false
        }
    };

    // Step 3 fallback: chroot (live ISO / overlay-off boot on squashfs)
    if !pivot_ok {
        chroot(new_root).map_err(|e| format!("chroot {}: {}", new_root, e))?;
        chdir("/").map_err(|e| format!("chdir / post-chroot: {}", e))?;
        eprintln!("  ✓ chroot fallback OK");
    }

    // Step 4: execv — never returns on success
    let cs = CString::new(init_rel).map_err(|e| format!("CString '{}': {}", init_rel, e))?;
    let args = vec![cs.clone()];
    execv(&cs, &args).map_err(|e| format!("execv '{}': {}", init_rel, e))?;

    unreachable!("execv returned — kernel bug");
}

/// Return a `BootTarget` that boots to rescue shell (`/bin/sh`).
/// Used when `rd.rescue` or `single` is present on the cmdline.
pub fn rescue_boot_target() -> BootTarget {
    let mount_point = MOUNT_TARGETS
        .iter()
        .find(|&&t| Path::new(t).exists())
        .copied()
        .unwrap_or(MOUNT_TARGETS[0]);

    // Pick the best available rescue shell (Zainium's own, under syshub)
    let shells = [
        "/overlayer/syshub/bin/bash",
        "/overlayer/syshub/bin/sh",
        "/overlayer/syshub/bin/fish",
        "/overlayer/syshub/bin/zsh",
    ];
    let init_path = INIT_FALLBACKS
        .iter()
        .filter(|&&p| shells.contains(&p))
        .find(|&&p| {
            let full = format!("{}{}", "/new_root", p);
            Path::new(&full).exists()
        })
        .copied()
        .unwrap_or("/overlayer/syshub/bin/sh");

    eprintln!("  rescue mode: init → {}", init_path);
    BootTarget {
        mount_point,
        init_path,
    }
}

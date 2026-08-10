/// OverlayFS — Zainium "Immutable Merge"
///
/// # Purpose
///
/// After the physical disk is mounted at `/zairoot`, this module constructs
/// the live root filesystem that Quantra (PID 1) will see by merging three
/// layers via the Linux OverlayFS kernel driver.
///
/// # Architecture — "Option B" (no flattened FHS at root)
///
/// Unlike a traditional initramfs `switch_root`, Zainium does **not** flatten
/// syshub's own top level (bin/, lib/, etc/, engine/, …) onto `/`. Packages
/// (e.g. GCC) are built with `--prefix=/overlayer/syshub` — see
/// `zex-env/src/paths.rs` — so that prefix must be a real, live path after
/// pivot, not just before it on the physical disk.
///
/// ```text
/// /new_root                        (tmpfs — becomes / after pivot_root)
///   ├── overlayer/syshub/          (OverlayFS merge target — see below)
///   ├── home/                      (bind-mounted from /zairoot/home)
///   ├── root/                      (bind-mounted from /zairoot/root)
///   ├── dev/ proc/ sys/ run/       (MS_MOVE'd from initramfs in switch.rs)
///   └── tmp/                       (empty mountpoint; tmpfs mounted later by PID 1)
///
/// /new_root/overlayer/syshub       (merged view — the real syshub prefix)
///   ├── lowerdir[0]: /zairoot/overlayer/syshub   (immutable OS base, read-only)
///   ├── lowerdir[1]: /zairoot/overlayer/zaisys   (kernel/early-boot assets, read-only)
///   ├── upperdir:    /zairoot/overlayer/zexlib/union  (user-installed packages, writable)
///   └── workdir:     /zairoot/overlayer/zexlib/work   (OverlayFS internal scratch)
/// ```
///
/// There is deliberately **no** `/bin`, `/sbin`, `/usr`, `/lib`, `/etc` or
/// `/var` at the root of `/new_root` — `zex-env/src/paths.rs::FORBIDDEN_FHS`
/// enforces this same rule for the toolchain side. `ls /` after boot shows
/// only `overlayer`, `home`, `root`, `dev`, `proc`, `sys`, `run`, `tmp`.
///
/// **No compatibility symlink for `/etc` (or anything else).** An earlier
/// version of this module recreated `/etc -> /overlayer/syshub/etc` in
/// `/new_root` on every boot; that has been deliberately removed. Every
/// piece of Zainium-owned code (`quantra`, `quantra-logind`, …) references
/// `/overlayer/syshub/etc/...`, `/overlayer/syshub/var/...` etc. by its full
/// explicit path — there is no root-level shim of any kind. `/var` merges
/// into the overlay the same way `/etc` does (COW into `zexlib/union`); it
/// is **not** a third bind mount alongside `/home` and `/root`.
///
/// # OverlayFS Semantics
///
/// | Operation | Result                                                      |
/// |-----------|-------------------------------------------------------------|
/// | READ      | Served from upperdir if present, otherwise from lowerdir   |
/// | ADD       | Written to upperdir (zexlib/union)                          |
/// | DELETE    | Whiteout file created in upperdir; lowerdir unchanged       |
/// | MODIFY    | Copy-on-write into upperdir; original in syshub preserved  |
///
/// The syshub (lowerdir[0]) is listed first → it takes priority over zaisys.
/// This means any file present in both syshub and zaisys is served from syshub.
///
/// Note: because upperdir/workdir (`zexlib/union`, `zexlib/work`) cannot live
/// inside the merge they contribute to, they stay physically under
/// `/zairoot/overlayer/zexlib/...` — a package installed by `zex` therefore
/// appears at `/overlayer/syshub/bin/foo` in the live view while physically
/// landing at `/zairoot/overlayer/zexlib/union/bin/foo` on disk. This is
/// expected OverlayFS behaviour, not a bug.
///
/// # /home Bind Mount
///
/// `/zairoot/home` is bind-mounted to `/new_root/home` separately.
/// This ensures user data survives a full zexlib rollback (resetting upperdir)
/// without being affected by the overlay layer mechanism.
///
/// # Rescue Mode
///
/// If the kernel cmdline contains `zainium.overlay=off`, `overlay_disabled_by_cmdline()`
/// returns `true` and main.rs skips this module entirely, booting the physical
/// /zairoot mount point directly (syshub read-only, no zexlib packages). In
/// that case `new_root` becomes `/zairoot` itself, which already has
/// `overlayer/syshub` as a real subdirectory — `switch.rs`'s init-fallback
/// paths are prefixed with `/overlayer/syshub` precisely so this case keeps
/// working without a separate code path.
use nix::mount::{MsFlags, mount};
use std::fs;

/// Mount the Zainium OverlayFS at `/new_root/overlayer/syshub`.
///
/// Caller must have already mounted the physical disk partition at `zairoot`
/// (e.g. `/zairoot`). After this function returns `Ok`, the process should
/// search for and exec the init binary from `/new_root/overlayer/syshub/...`
/// (see `switch.rs`, whose `INIT_FALLBACKS` already carry that prefix).
///
/// # Arguments
/// * `zairoot` — Path where the physical disk is mounted (e.g. `"/zairoot"`)
///
/// # Returns
/// The path of the tmpfs root (`"/new_root"`) on success — i.e. the
/// mountpoint that will become `/` after `pivot_root`, **not** the overlay
/// merge subdirectory itself.
pub fn mount_overlay(zairoot: &str) -> Result<String, String> {
    // OverlayFS lowerdir: colon-separated, leftmost = highest priority
    // syshub (base OS) overrides zaisys (kernel/early-boot) when files collide.
    let lower = format!("{z}/overlayer/syshub:{z}/overlayer/zaisys", z = zairoot);
    let upper = format!("{}/overlayer/zexlib/union", zairoot);
    let work = format!("{}/overlayer/zexlib/work", zairoot);
    let root = "/new_root".to_string();
    let merged = format!("{}/overlayer/syshub", root);

    // Sanity check — ensure the Zainium disk layout is present
    if !std::path::Path::new(&format!("{}/overlayer/syshub", zairoot)).exists() {
        return Err(format!(
            "syshub not found in '{}' — not a Zainium disk (overlayer/syshub missing)",
            zairoot
        ));
    }

    // upperdir + workdir may not exist on first boot — create them now.
    // syshub and zaisys are read-only lowerdirs; no setup needed there.
    // NOTE: upperdir/workdir physically stay under /zairoot/overlayer/zexlib —
    // the kernel forbids upperdir from being inside the mountpoint it feeds,
    // so they cannot themselves live under /new_root/overlayer/syshub.
    for dir in [&upper, &work] {
        fs::create_dir_all(dir).map_err(|e| format!("create overlay dir '{}': {}", dir, e))?;
    }

    // Base tmpfs root layout: only overlayer/syshub, home, root, and the
    // standard virtual filesystem mountpoints live at the true root.
    // No bin/sbin/usr/lib/etc/var.
    fs::create_dir_all(&merged).map_err(|e| format!("create {}: {}", merged, e))?;
    for name in ["home", "root", "dev", "proc", "sys", "tmp"] {
        let dir = format!("{}/{}", root, name);
        fs::create_dir_all(&dir).map_err(|e| format!("create {}: {}", dir, e))?;
    }

    let opts = format!("lowerdir={},upperdir={},workdir={}", lower, upper, work);

    eprintln!("  OverlayFS (Immutable Merge):");
    eprintln!("    lower[0] = {}/overlayer/syshub  (priority)", zairoot);
    eprintln!("    lower[1] = {}/overlayer/zaisys", zairoot);
    eprintln!(
        "    upper    = {}/overlayer/zexlib/union  (writable)",
        zairoot
    );
    eprintln!("    merged   = {}", merged);

    mount(
        Some("overlay"),
        merged.as_str(),
        Some("overlay"),
        MsFlags::empty(),
        Some(opts.as_str()),
    )
    .map_err(|e| {
        format!(
            "OverlayFS mount failed: {} — is the 'overlay' kernel module loaded?",
            e
        )
    })?;

    eprintln!("  ✓ OverlayFS → {}", merged);

    // Bind mount /home and /root separately so user data is not part of the
    // writable overlay — both must survive a zexlib rollback untouched.
    bind_persistent_dir(zairoot, "home")?;
    bind_persistent_dir(zairoot, "root")?;

    Ok(root)
}

/// Bind mount `/zairoot/{name}` → `/new_root/{name}` (used for `home` and `root`).
///
/// These directories must survive a zexlib rollback (which resets upperdir).
/// Keeping them outside the overlay layer guarantees that: a rollback wipes
/// installed packages but never touches user data.
fn bind_persistent_dir(zairoot: &str, name: &str) -> Result<(), String> {
    let src = format!("{}/{}", zairoot, name);
    let dest = format!("/new_root/{}", name);

    if !std::path::Path::new(&src).exists() {
        eprintln!("  /{}: '{}' not found — skipping bind mount", name, src);
        return Ok(());
    }

    // Destination directory must already exist inside /new_root (created by
    // mount_overlay's base-dirs pass above); create_dir_all is idempotent.
    fs::create_dir_all(&dest).ok();

    mount(
        Some(src.as_str()),
        dest.as_str(),
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|e| format!("bind mount /{}: '{}' → '{}': {}", name, src, dest, e))?;

    eprintln!("  ✓ /{} bind mounted (persistent, survives rollback)", name);
    Ok(())
}

/// Check whether the kernel cmdline contains `zainium.overlay=off`.
///
/// This is the rescue boot mechanism: add `zainium.overlay=off` to the
/// bootloader entry (Limine, GRUB) to skip the OverlayFS layer and boot
/// directly from the immutable syshub inside /zairoot.
///
/// Returns `true` if overlay should be skipped, `false` otherwise.
/// If `/proc/cmdline` cannot be read (pre-Phase1 call), returns `false`.
pub fn overlay_disabled_by_cmdline() -> bool {
    std::fs::read_to_string("/proc/cmdline")
        .map(|s| s.split_whitespace().any(|tok| tok == "zainium.overlay=off"))
        .unwrap_or(false)
}

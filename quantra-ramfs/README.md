# quantra-ramfs — Zainium OS Stage-1 Initramfs Orchestrator

**Version:** 6.0.0  
**Language:** Rust 2024 (100% — zero shell scripts in the boot path)  
**Target:** `x86_64-unknown-linux-musl` (matches the pinned target in `quantra/.cargo/config.toml`; this crate has no per-crate `.cargo/config.toml` of its own, so pass `--target x86_64-unknown-linux-musl` explicitly)  
**MSRV:** 1.87

---

## What Is quantra-ramfs?

`quantra-ramfs` is the Stage-1 early userspace boot orchestrator for Zainium OS.
It is the **first userspace process** the kernel executes (PID 1 inside the initramfs).
Its sole job is to prepare the environment, assemble the live root filesystem via
OverlayFS, and hand control to `quantra` — the real PID 1 init daemon.

### Design Principles

| Principle | Implementation |
|-----------|---------------|
| Zero external binaries | No `mount`, `losetup`, `mknod`, `blkid`, `busybox`, or shell |
| Raw Linux ioctls | Loop devices via `LOOP_CTL_GET_FREE` / `LOOP_SET_FD` / `LOOP_SET_STATUS64` |
| Immutable merge | OverlayFS assembles syshub + zaisys + zexlib into `/new_root` at boot time |
| Rescue mode | `zainium.overlay=off` on cmdline → boot syshub directly, skip zexlib |
| Graceful fallback | OverlayFS failure → read-only syshub boot; pivot_root failure → chroot |
| LUKS support | Full-disk encryption with interactive passphrase or keyfile |
| Memory safety | 100% Rust; no unsafe outside of required libc ioctl / mknod calls |

---

## Boot Flow

```
Linux Kernel
  │  loads initramfs image
  └─ execv("/init")  →  quantra-ramfs (this binary)

[0] INIT          — binary starts, boot timer begins

[1] MOUNTS        — mount /proc /sys /dev /run
                    create /dev/loop-control + /dev/loop0-7 (mknod)

[2] CMDLINE       — parse /proc/cmdline
                    root=  rootfstype=  loop=  luks=  rootwait=  init=
                    zainium.overlay=off  (rescue flag)

[3] ROOTFS_DETECT — resolve root= to block device path
                    UUID= → /dev/disk/by-uuid/
                    LABEL= → /dev/disk/by-label/
                    retry loop (50ms × rootwait= retries)

[4] ROOTFS_MOUNT  — mount physical partition → /zairoot
                    supports: ext4 xfs btrfs f2fs squashfs iso9660 vfat
                    supports: loop image inside ISO (loop= cmdline)
                    supports: LUKS encryption (cryptsetup luksOpen)
                    supports: NFS root

[4.5] OVERLAY     — build merged root at /new_root/overlayer/syshub (NOT /new_root
                    itself — see "OverlayFS Architecture" below)
                    lowerdir = /zairoot/overlayer/syshub   (immutable OS base)
                              :/zairoot/overlayer/zaisys   (kernel/early-boot)
                    upperdir = /zairoot/overlayer/zexlib/union  (installed packages)
                    workdir  = /zairoot/overlayer/zexlib/work
                    bind /zairoot/home → /new_root/home    (persistent user data)
                    bind /zairoot/root → /new_root/root    (persistent root home)

[5] (implicit)    — discover init binary inside /new_root
                    /overlayer/syshub/engine/quantra       (Zainium PID 1)
                    /overlayer/syshub/engine/s6-quantra    (s6 fallback)
                    /sbin/init  /usr/lib/systemd/systemd   (foreign-disk compat only)
                    /overlayer/syshub/bin/bash  .../bin/sh (rescue)

[6] PIVOT         — MS_MOVE /dev /proc /sys /run → /new_root/
                    pivot_root /new_root → execv quantra
                    (chroot fallback for live ISO / overlay-off mode)

[7] COMPLETE      — quantra PID 1 takes over
```

---

## OverlayFS Architecture

Zainium does **not** flatten the OS onto `/` the way a traditional
`switch_root` would. Packages are compiled with `--prefix=/overlayer/syshub`
(see `zex-env/src/paths.rs`), so that prefix has to be a real, live path after
boot — not just on the physical disk before it.

```
Physical disk (/zairoot)
  overlayer/
    syshub/              ← IMMUTABLE — OS binaries, configs, quantra engine
    zaisys/              ← IMMUTABLE — kernel modules, firmware
    zexlib/
      union/             ← WRITABLE  — user-installed packages land here
      work/              ← OverlayFS scratch (internal use)
  home/                  ← PERSISTENT — bind-mounted, survives rollback
  root/                  ← PERSISTENT — bind-mounted, survives rollback

/new_root                          (tmpfs — becomes / after pivot_root)
  ├── overlayer/syshub/            ← merged view lands HERE, not at /new_root
  │     ├── Files from zexlib/union override syshub/zaisys   (add/modify)
  │     ├── Whiteout files in zexlib/union shadow lowerdir    (delete)
  │     ├── Reads fall through to syshub if not in zexlib     (immutable base)
  │     └── etc/, var/, bin/, lib/, …  ← the entire traditional FHS tree lives
  │           here and ONLY here — never flattened onto /new_root itself
  ├── home/ → bind from /zairoot/home  (never overlaid)
  ├── root/ → bind from /zairoot/root  (never overlaid)
  └── dev/ proc/ sys/ run/ tmp/        (virtual filesystems, see Boot Flow)
```

**`ls /` on a booted system shows only:** `overlayer`, `home`, `root`, `dev`,
`proc`, `sys`, `run`, `tmp` — no `bin`, `usr`, `etc`, or `var`. There is
deliberately no compatibility symlink for any of these; `quantra` (PID 1) and
`quantra-logind` reference `/overlayer/syshub/etc/...`,
`/overlayer/syshub/var/...` etc. explicitly.

**Rollback:** reset `zexlib/union/` → system returns to clean syshub state,
including `/overlayer/syshub/var` (runtime logs/state reset along with
packages — this is intentional). `/home` and `/root` are untouched because
they are bind-mounted outside the overlay entirely.

---

## Rescue Mode

Add `zainium.overlay=off` to the bootloader cmdline (Limine / GRUB):

```
# Limine limine.conf
CMDLINE=root=UUID=... zainium.overlay=off
```

Effect: OverlayFS is skipped. The system boots from `/zairoot` directly using the
immutable syshub. No zexlib packages are visible. Useful for recovering from a
broken package installation without needing a live ISO.

---

## Source Layout

```
src/
  main.rs           Boot orchestrator — phase sequencing and timing
  phases.rs         BootPhase constants + atomic BOOT_PHASE tracker
  mounts.rs         Early filesystem mounts + loop device node creation
  cmdline.rs        /proc/cmdline parser (root= loop= luks= rootwait= init=)
  rootfs.rs         Root device detection, loop ioctl, LUKS, live medium scan
  overlay.rs        OverlayFS assembly (syshub + zaisys + zexlib → /new_root)
  switch.rs         pivot_root + chroot fallback + init binary discovery
  emergency.rs      Built-in emergency shell (reboot/poweroff/ls/cat/mount)
  fsck.rs           Filesystem check before mount
  raid.rs           Software RAID (mdadm-equivalent) assembly
  udev.rs           Netlink-based device discovery (no external udev/mdev)
  network_boot.rs   Network root support (NFS/iSCSI-style boot)
  plymouth.rs       Boot splash integration
  tpm2.rs           TPM2 unseal for LUKS key material
  verity.rs         dm-verity integrity verification
  measured_boot.rs  TPM2-backed measured boot (PCR extension)
```

---

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `nix` | =0.29.0 | POSIX wrappers — mount, pivot_root, chroot, execv |
| `libc` | =0.2.155 | Raw ioctls — LOOP_CTL_GET_FREE, LOOP_SET_FD, mknod |

No other dependencies. The binary is statically linked against musl libc.

---

## Build

```sh
cargo build --release --target x86_64-unknown-linux-musl

# Output (already stripped -- the workspace [profile.release] sets strip = true)
target/x86_64-unknown-linux-musl/release/quantra-ramfs
```

---

## Initramfs Integration

```
initramfs/
  init                   ← symlink or copy of quantra-ramfs binary
  bin/
    quantra-ramfs        ← Stage-1 static binary
  dev/                   ← empty (devtmpfs mounted at runtime)
  proc/                  ← empty (procfs mounted at runtime)
  sys/                   ← empty (sysfs mounted at runtime)
  run/                   ← empty (tmpfs mounted at runtime)
  new_root/              ← empty (OverlayFS mounted here at Phase 4.5)
  zairoot/               ← empty (physical disk mounted here at Phase 4)
```

The kernel executes `/init` as PID 1 inside the initramfs — which is this binary.

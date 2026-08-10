# quantra-ramfs — Architecture Reference

> **Version:** 6.0.0  
> **Language:** Rust 2021, MSRV 1.82  
> **Dependencies:** 2 (`nix` =0.29.0, `libc` =0.2.155)

---

## 0. Installed System Filesystem Layout ("Option B")

This is what a user sees on a real, installed (or booted-live) Zainium machine —
the end state all the phases below are building toward.

```
/                                    (tmpfs — /new_root before pivot_root)
├── overlayer/
│   └── syshub/                      ← OverlayFS merge target (see §3)
│       ├── bin/  sbin/  lib/  include/   ← the real FHS-shaped tree, syshub-prefixed
│       ├── etc/                     ← config (passwd, machine-id, resolv.conf, …)
│       ├── var/                     ← runtime state (log, lib, cache) — see §3
│       ├── engine/quantra           ← PID 1
│       └── x86_64-zainium-linux-musl/   ← musl+GCC sysroot triple (hybrid toolchain)
├── home/                            ← bind-mounted from /zairoot/home (persistent)
├── root/                            ← bind-mounted from /zairoot/root (persistent)
├── dev/ proc/ sys/ run/             ← MS_MOVE'd from the initramfs (see §7)
└── tmp/                             ← tmpfs, mounted by quantra at runtime

Physical disk (/zairoot):
  overlayer/
    syshub/     immutable — OS base, built by the toolchain with --prefix=/overlayer/syshub
    zaisys/     immutable — kernel modules, firmware, early-boot assets
    zexlib/
      union/    writable  — zex package manager writes here (upperdir)
      work/     internal  — OverlayFS bookkeeping scratch
  home/         persistent — user home directories
  root/         persistent — root user's home directory
```

**There is no `/bin`, `/sbin`, `/usr`, `/lib`, `/etc`, or `/var` at the true root.**
`ls /` on a booted system shows exactly: `overlayer`, `home`, `root`, `dev`, `proc`,
`sys`, `run`, `tmp`. Every traditional FHS path — including `/etc/passwd` and
`/var/log/...` — lives under `/overlayer/syshub/...` and is reached by explicit
absolute paths in code (`quantra`, `quantra-logind`, …); there is deliberately
**no** compatibility symlink at root. This mirrors `zex-env/src/paths.rs`
(`FORBIDDEN_FHS`, `build_path()`), which enforces the identical rule on the
toolchain/build side — a package is compiled once with `--prefix=/overlayer/syshub`
and that prefix is real both at build time and at boot time.

`/home` and `/root` are the only two bind mounts — both hold irreplaceable,
per-machine user data that must survive a `zexlib` rollback untouched. `/var`
(logs, service state, coredumps) is **not** bind-mounted: it lives inside the
OverlayFS merge at `/overlayer/syshub/var/...` exactly like `/etc` and everything
else, so writes there are copy-on-write into `zexlib/union` the same way an
installed package would be, and a full rollback resets runtime state along with
packages — this is intentional, not an oversight.

A package installed by `zex` therefore appears at `/overlayer/syshub/bin/foo` in
the live view while physically landing at
`/zairoot/overlayer/zexlib/union/bin/foo` on disk — expected OverlayFS behaviour
(the kernel forbids `upperdir` from living inside the mount it feeds, so it can't
itself be under `/overlayer/syshub`).

---

## 1. Module Dependency Graph

```
main.rs
  ├── phases.rs      (set_phase, BootPhase, BOOT_PHASE)
  ├── mounts.rs      (mount_early)
  ├── cmdline.rs     (parse → Cmdline)
  ├── rootfs.rs      (prepare_live_medium_bridge, find_root, mount_root_at)
  ├── overlay.rs     (overlay_disabled_by_cmdline, mount_overlay)
  ├── switch.rs      (find_mount_target, discover_boot_target, pivot_to_root)
  └── emergency.rs   (shell)
```

No module imports another module except `switch.rs` and `rootfs.rs` importing
`cmdline::Cmdline`. All control flow is top-down through `main.rs`.

---

## 2. Boot Phase State Machine

```
┌─────────┐
│  INIT   │  Phase 0 — binary started
└────┬────┘
     │
┌────▼──────┐
│  MOUNTS   │  Phase 1 — /proc /sys /dev /run + loop nodes
└────┬──────┘
     │
┌────▼──────┐
│  CMDLINE  │  Phase 2 — parse /proc/cmdline
└────┬──────┘
     │
┌────▼────────────┐
│  ROOTFS_DETECT  │  Phase 3 — resolve root= to /dev/... path
└────┬────────────┘
     │
┌────▼────────────┐
│  ROOTFS_MOUNT   │  Phase 4 — mount disk → /zairoot
└────┬────────────┘
     │
┌────▼────────┐
│   OVERLAY   │  Phase 5 — OverlayFS → /new_root
└────┬────────┘
     │
┌────▼──────┐
│   PIVOT   │  Phase 6 — pivot_root + execv quantra
└────┬──────┘
     │
┌────▼─────────┐
│   COMPLETE   │  Phase 7 — execv issued (unreachable in practice)
└──────────────┘
```

Each transition calls `set_phase()` which atomically stores the phase number
into `BOOT_PHASE: AtomicU32` with `SeqCst` ordering before logging.

---

## 3. OverlayFS Layer Model

```
/new_root/overlayer/syshub  (the merge — real syshub prefix, NOT /new_root itself)
─────────────────────────────────────────────────────
 READ:   zexlib/union  →  syshub  →  zaisys
         (first match wins, left = highest priority)

 WRITE:  always → zexlib/union  (copy-on-write from lowerdir)

 DELETE: whiteout file in zexlib/union masks lowerdir entry

/new_root/home, /new_root/root: bind-mounted from /zairoot/{home,root}
       outside the overlay — survive any zexlib reset
─────────────────────────────────────────────────────

Physical disk layout (/zairoot):
  overlayer/
    syshub/        immutable  — OS base (quantra engine, libs, etc, var, configs)
    zaisys/        immutable  — kernel modules, firmware, early assets
    zexlib/
      union/       writable   — zex package manager writes here
      work/        internal   — OverlayFS bookkeeping scratch
  home/            persistent — user home directories
  root/            persistent — root user's home directory
```

Unlike a traditional `switch_root`, the merge target is `/new_root/overlayer/syshub`,
not `/new_root` itself — see §0. `mount_overlay()` in `overlay.rs` also creates the
base tmpfs-root directories (`home`, `root`, `dev`, `proc`, `sys`, `tmp`) before
mounting, since nothing else populates them.

### Rollback Mechanism

```sh
# Full rollback: wipe all installed packages, restore pristine syshub
rm -rf /zairoot/overlayer/zexlib/union/*

# Partial rollback: remove specific package overlay
rm -rf /zairoot/overlayer/zexlib/union/lib/mypackage
```

After rollback the system will boot into a clean syshub state. `/home` and
`/root` are never affected because they are bind mounts, not part of the overlay.

---

## 4. Loop Device Ioctl Sequence

Used for mounting squashfs images inside ISO/CDROM media. No `losetup` binary.

```
open("/dev/loop-control", O_RDWR | O_CLOEXEC)
  │
  └─ ioctl(fd, LOOP_CTL_GET_FREE)
       │  returns free loop index N
       │
  open("/dev/loopN", O_RDWR | O_CLOEXEC)
  │  [mknod /dev/loopN S_IFBLK major=7 minor=N if missing]
  │
  open("path/to/image.squashfs", O_RDONLY | O_CLOEXEC)
  │
  ioctl(loop_fd, LOOP_SET_FD, image_fd)
  │
  ioctl(loop_fd, LOOP_SET_STATUS64, &LoopInfo64 {
  │    lo_flags: LO_FLAGS_READ_ONLY,
  │    lo_file_name: "...squashfs",
  │    ...
  │  })
  │
  mount("/dev/loopN", target, "squashfs", MS_RDONLY, "")
```

`FdGuard(RawFd)` wraps every file descriptor and closes it on drop, ensuring
no fd leak on any error path.

---

## 5. Root Device Resolution

```
cmdline root= value
        │
        ├─ UUID=<uuid>   →  /dev/disk/by-uuid/<uuid>
        ├─ LABEL=<label> →  /dev/disk/by-label/<label>
        ├─ /dev/...      →  used directly
        └─ NFS (host:/)  →  passed directly to mount(nfs)

Retry loop (50ms intervals):
  rootwait (bare)  →  infinite retries (slow USB)
  rootwait=N       →  N retries
  (absent)         →  20 retries = 1 second

Fallback scan:
  /dev/sda1  /dev/sr0  /dev/ram0  /dev/sda2  /dev/vda1
```

---

## 6. Mount Strategy per Device Type

| Device Type | Strategy |
|-------------|----------|
| `NFS` (host:path) | `mount(nfs)` directly |
| `/dev/sr*`, `/dev/cdrom` | ISO9660 → loop ioctl → squashfs |
| `/dev/ram*` | ext4 / squashfs / tmpfs candidates |
| `/dev/sd*`, `/dev/nvme*`, `/dev/vd*`, `/dev/mmcblk*` | rootfstype= or candidate scan |
| LUKS (magic `LUKS\xba\xbe`) | `cryptsetup luksOpen` → mapped device |

---

## 7. pivot_root Sequence

```
for mp in [/dev, /proc, /sys, /run]:
    mount(mp, /new_root/mp, MS_MOVE)

chdir("/new_root")

mkdir /new_root/.old_root
pivot_root("/new_root", "/new_root/.old_root")
  ├─ OK  → chdir("/")
  │        umount2("/.old_root", MNT_DETACH)   # /zairoot invisible
  │        rmdir("/.old_root")
  └─ FAIL → chroot("/new_root")                # live ISO fallback
             chdir("/")

execv("/overlayer/syshub/engine/quantra", ["quantra"])
  → never returns
```

---

## 8. Emergency Shell

Activated on any fatal error. Zero external binary dependencies.

Built-in commands (always available):

| Command | Implementation |
|---------|----------------|
| `reboot` | `libc::reboot(RB_AUTOBOOT)` |
| `poweroff` / `halt` | `libc::reboot(RB_POWER_OFF)` |
| `ls [path]` | `fs::read_dir()` |
| `bat <file>` | `fs::read_to_string()` |
| `mount` | `fs::read_to_string("/proc/mounts")` |
| any other | delegated to `/overlayer/syshub/bin/{fish,bash,zsh,sh}` in that order (see `switch.rs::rescue_boot_target`) |

On entry, the shell prints diagnostic status for `/proc`, `/sys`, `/dev`,
and `/proc/cmdline` before accepting input.

---

## 9. Security Properties

| Property | Mechanism |
|----------|-----------|
| No SUID in initramfs | `MS_NOSUID` on `/run`; `/dev` has no exec flag |
| No executable `/dev` | `DEV_FLAGS = MsFlags::empty()` (devtmpfs safe mode) |
| RAII fd management | `FdGuard` closes all raw fds on drop |
| No heap in hot path | Stack-only buffer for `/dev/loopN` path construction |
| LUKS passphrase | Read via `termios` echo-off; piped to cryptsetup stdin; never in argv/env |
| OverlayFS rescue | `zainium.overlay=off` → skip writable layer entirely |

---

## 10. Binary Size Budget

| Build | Size |
|-------|------|
| debug | ~3–4 MB |
| release | ~400–600 KB |
| release + strip | ~60–80 KB |

Target initramfs image total: < 2 MB (binary + `/new_root` mountpoint dirs only).

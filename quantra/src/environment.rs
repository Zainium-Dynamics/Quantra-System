/// Native environment — thin wrapper around the `oxidized-environment` crate,
/// Zainium's replacement for `/etc/profile.d`.
///
/// # Why not profile.d
///
/// Traditional `/etc/profile.d/*.sh` only reaches *interactive login shells*
/// (bash/zsh source it, nothing else does), so every other process tree —
/// services, non-login shells, graphical sessions launched some other way —
/// has to re-derive the same PATH/LD_LIBRARY_PATH/hybrid-toolchain vars by
/// hand. This repo already hit that: `console-shell.toml` and
/// `services/manager.rs`'s built-in bootstrap fallback both hardcoded their
/// own copy of the PATH string, and drifted out of sync with each other.
///
/// Instead, PID 1 sets the canonical environment on **itself**, once, before
/// anything is spawned, resolved from the single schema `oxidized-environment`
/// owns (see that crate's docs for the full design — `environment.toml` +
/// `environment.d/*.toml`, also readable by `zainium-installer` and
/// `quantra-ctl` without linking Rust at all). Every child process inherits
/// it for free through normal `fork`/`exec` unless a spawn path deliberately
/// builds an isolated environment (see `process.rs::BASE_PATH` — background
/// services still get a minimal, explicit env on purpose, for isolation, not
/// because the full env isn't available).
///
/// # Where the Zainium-ness lives
///
/// `oxidized-environment-core` is a generic library — it has no compiled-in
/// root and no compiled-in fallback content; `resolve()` returns an empty
/// map if `environment.toml` doesn't exist yet. That's correct for a library
/// any distro's init could link, but PID 1 must never actually boot with an
/// empty `PATH`. So the Zainium-specific root path and the minimal boot
/// safety-net table both live *here*, in quantra's own source — not in the
/// generic crate.
use std::collections::HashMap;
use std::path::Path;

/// The live syshub root on a booted Zainium system. Quantra-owned, not part
/// of `oxidized-environment-core` (which has no compiled-in root at all).
const SYSHUB_ROOT: &str = "/overlayer/syshub";

/// Minimal boot safety net: only used if `environment.toml` doesn't exist
/// yet (fresh/broken install) or fails to parse. Real content lives in
/// `environment.toml`, seeded by `zainium-installer` at install time — this
/// is not that file's replacement, just enough to get a shell with a
/// working PATH so someone can fix the real file.
const BOOT_FALLBACK: &[(&str, &str)] = &[
    (
        "PATH",
        "/overlayer/syshub/bin:/overlayer/syshub/sbin:/overlayer/syshub/x86_64-zainium-linux-musl/bin:/overlayer/zexlib/union/bin",
    ),
    (
        "LD_LIBRARY_PATH",
        "/overlayer/syshub/lib:/overlayer/syshub/x86_64-zainium-linux-musl/lib:/overlayer/zexlib/union/lib",
    ),
];

/// [`oxidized_environment::resolve`] against [`SYSHUB_ROOT`], with
/// [`BOOT_FALLBACK`] filled in for any of its keys that came back missing
/// (not overridden if `environment.toml` already set them — only fills
/// gaps).
fn resolve() -> HashMap<String, String> {
    let mut env = oxidized_environment::resolve(Path::new(SYSHUB_ROOT));
    for (key, value) in BOOT_FALLBACK {
        env.entry((*key).to_string())
            .or_insert_with(|| (*value).to_string());
    }
    env
}

/// Set the canonical hybrid environment on PID 1's own process environment.
/// Called once, very early in `main()`, before anything is spawned — every
/// child inherits this through normal `fork`/`exec` unless it explicitly
/// builds its own isolated env.
///
/// # Safety
/// `std::env::set_var` is only unsound if called concurrently with reads of
/// the environment from another thread; this runs single-threaded, before
/// any thread is spawned and before any service exec's a child.
pub fn apply_to_process_env() {
    for (key, value) in resolve() {
        unsafe {
            std::env::set_var(key, value);
        }
    }
}

/// The resolved environment as an owned map — for spawn paths that build an
/// explicit env (services, login shells) instead of relying on inheritance.
pub fn base_map() -> HashMap<String, String> {
    resolve()
}

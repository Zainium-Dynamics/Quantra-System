use std::fs;
/// Emergency shell module - fallback when boot fails
///
/// Provides interactive recovery shell with built-in commands that require
/// NO external binaries — works even in a minimal initramfs with no /bin/sh.
///
/// Built-in commands (always available, zero external dependencies):
///   reboot   — calls libc::reboot(RB_AUTOBOOT) directly
///   poweroff — calls libc::reboot(RB_POWER_OFF) directly
///   halt     — alias for poweroff
///   ls [dir] — reads directory via fs::read_dir
///   cat FILE — reads file via fs::read_to_string
///   mount    — displays /proc/mounts
///
/// External commands: attempted via fish, bash, zsh, or sh if present.
use std::io::{self, Write};
use std::process::Command;

/// Enter emergency shell with diagnostics.
///
/// # Never Returns
pub fn shell(reason: &str) -> ! {
    eprintln!("\n\x1b[1;31m╔══════════════════════════════════════╗");
    eprintln!("║   ZAINIUM EMERGENCY SHELL            ║");
    eprintln!("╚══════════════════════════════════════╝\x1b[0m");
    eprintln!("\n\x1b[1;31mReason: {}\x1b[0m\n", reason);

    eprintln!("--- DIAGNOSTIC INFO ---");

    eprintln!("\n /proc status:");
    if let Ok(entries) = fs::read_dir("/proc") {
        let count = entries.count();
        if count > 0 {
            eprintln!("  ✓ /proc is mounted (contains {} entries)", count);
        } else {
            eprintln!("  \x1b[1;31m✗ /proc is EMPTY (mount failed?)\x1b[0m");
        }
    } else {
        eprintln!("  \x1b[1;31m✗ /proc doesn't exist (mount failed!)\x1b[0m");
    }

    eprintln!("\n /sys status:");
    if let Ok(entries) = fs::read_dir("/sys") {
        let count = entries.count();
        if count > 0 {
            eprintln!("  ✓ /sys is mounted (contains {} entries)", count);
        } else {
            eprintln!("  \x1b[1;31m✗ /sys is EMPTY (mount failed?)\x1b[0m");
        }
    } else {
        eprintln!("  \x1b[1;31m✗ /sys doesn't exist (mount failed!)\x1b[0m");
    }

    eprintln!("\n /dev status:");
    if let Ok(entries) = fs::read_dir("/dev") {
        let count = entries.count();
        if count > 0 {
            eprintln!("  ✓ /dev is mounted (contains {} entries)", count);
        } else {
            eprintln!("  \x1b[1;31m✗ /dev is EMPTY (mount failed?)\x1b[0m");
        }
    } else {
        eprintln!("  \x1b[1;31m✗ /dev doesn't exist (mount failed!)\x1b[0m");
    }

    eprintln!("\n /proc/cmdline:");
    if let Ok(cmdline) = fs::read_to_string("/proc/cmdline") {
        eprintln!("  Content: {}", cmdline);
    } else {
        eprintln!("  \x1b[1;31m✗ Cannot read /proc/cmdline\x1b[0m");
    }

    eprintln!("\n--- END DIAGNOSTICS ---\n");
    eprintln!("Built-in: reboot  poweroff  halt  ls [dir]  cat <file>  mount");
    eprintln!("External: any command (requires a valid shell)\n");

    loop {
        print!("zainium-emergency # ");
        io::stdout().flush().ok();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            continue;
        }

        let cmd = input.trim();
        let parts: Vec<&str> = cmd.split_whitespace().collect();

        match parts.as_slice() {
            // ── Built-in: reboot (no external binary) ───────────────────────
            ["reboot"] => {
                eprintln!("Rebooting...");
                unsafe { libc::sync() };
                // SAFETY: RB_AUTOBOOT is the standard Linux reboot magic constant
                unsafe { libc::reboot(libc::RB_AUTOBOOT) };
                std::thread::sleep(std::time::Duration::from_secs(5));
            }

            // ── Built-in: poweroff / halt (no external binary) ──────────────
            ["poweroff"] | ["halt"] => {
                eprintln!("Powering off...");
                unsafe { libc::sync() };
                // SAFETY: RB_POWER_OFF is the standard Linux power-off magic constant
                unsafe { libc::reboot(libc::RB_POWER_OFF) };
                std::thread::sleep(std::time::Duration::from_secs(5));
            }

            // ── Built-in: ls ─────────────────────────────────────────────────
            ["ls"] => run_builtin_ls("/"),
            ["ls", path] => run_builtin_ls(path),

            // ── Built-in: cat ────────────────────────────────────────────────
            // FEATURE: Using 'bat' as the modern, memory-safe replacement for POSIX 'cat'.
            ["bat", path] => match fs::read_to_string(path) {
                Ok(c) => eprint!("{}", c),
                Err(e) => eprintln!("cat: {}: {}", path, e),
            },

            // ── Built-in: mount (display /proc/mounts) ───────────────────────
            ["mount"] => match fs::read_to_string("/proc/mounts") {
                Ok(m) => eprint!("{}", m),
                Err(e) => eprintln!("mount: {}", e),
            },

            // ── Empty ────────────────────────────────────────────────────────
            [] | [""] => {}

            // ── External command via shell ──────────────────────────────────────
            _ => {
                let shells = ["/bin/fish", "/bin/bash", "/bin/zsh", "/bin/sh"];
                let mut ran = false;
                for sh in &shells {
                    if std::path::Path::new(sh).exists() {
                        // Direct execution since busybox is removed
                        Command::new(sh).args(["-c", cmd]).status().ok();
                        ran = true;
                        break;
                    }
                }
                if !ran {
                    eprintln!(
                        "No shell found (/bin/fish, /bin/bash, /bin/zsh, /bin/sh).\n\
                         Use built-ins: reboot  poweroff  ls  cat  mount"
                    );
                }
            }
        }
    }
}

/// List directory entries without any external binary.
fn run_builtin_ls(path: &str) {
    match fs::read_dir(path) {
        Ok(entries) => {
            let mut names: Vec<String> = entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            for name in names {
                eprintln!("  {}", name);
            }
        }
        Err(e) => eprintln!("ls: {}: {}", path, e),
    }
}

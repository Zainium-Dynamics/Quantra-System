use crate::process::{ServiceLaunch, start_service_as};
use std::collections::HashMap;
use std::panic;

pub fn setup() {
    panic::set_hook(Box::new(|info| {
        log::error!("Zainium Init PANIC: {}", info);
        emergency_shell();
    }));
}

pub fn emergency_shell() -> ! {
    print_emergency_banner();

    // Try to launch the same tty-aware Fish path used by the normal console.
    // Fall back to bash/sh if fish is missing in the emergency image.
    let shells: [(&str, &[&str], &str); 3] = [
        (
            "/overlayer/syshub/bin/fish",
            &["-il"],
            "/overlayer/syshub/bin/fish",
        ),
        (
            "/overlayer/syshub/bin/bash",
            &["-i"],
            "/overlayer/syshub/bin/bash",
        ),
        (
            "/overlayer/syshub/bin/sh",
            &["-i"],
            "/overlayer/syshub/bin/sh",
        ),
    ];

    for (cmd, args, shell_name) in shells {
        let mut env = HashMap::new();
        env.insert("TERM".into(), "linux".into());
        env.insert("HOME".into(), "/root".into());
        env.insert(
            "PATH".into(),
            "/overlayer/syshub/bin:/overlayer/syshub/sbin:/overlayer/syshub/x86_64-zainium-linux-musl/bin:/overlayer/zexlib/union/bin".into(),
        );
        env.insert("SHELL".into(), shell_name.into());

        let launch = ServiceLaunch {
            cmd,
            args,
            uid: None,
            gid: None,
            working_dir: Some("/"),
            tty_path: Some("/dev/tty1"),
            env: Some(&env),
            log_write_fd: None,
            activation_fds: &[],
            apparmor_profile: None,
            no_new_privileges: true,
            non_dumpable: true,
            clear_ambient_caps: false,
            drop_capabilities: &[],
            ambient_capabilities: &[],
            capability_bounding_set: &[],
            seccomp_allowlist: &[],
            seccomp_profile_denylist: &[],
            service_for_sandbox: None,
            seccomp_strict: false,
            rlimit: None,
            private_tmp: false,
            protect_system: false,
            landlock_paths: &[],
        };

        if start_service_as(&launch).is_ok() {
            println!("\nEmergency shell started on /dev/tty1: {}", cmd);
            loop {
                std::thread::park();
            }
        }
    }

    println!("\nNo shell available. System halted.");
    loop {
        std::thread::park();
    }
}

fn print_emergency_banner() {
    println!("\n\x1b[1;31m╔════════════════════════════════════════════╗");
    println!("║       ZAINIUM OS EMERGENCY SHELL           ║");
    println!("╚════════════════════════════════════════════╝\x1b[0m");
    println!("Root: zairoot | Boot: zaisys\n");
}

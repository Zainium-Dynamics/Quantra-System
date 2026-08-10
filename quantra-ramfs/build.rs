// build.rs — Generate build metadata at compile time
//
// # Module: build
// # Purpose: Compile-time metadata injection (version, git hash, target, LTS date)
// # Dependencies: None (build script)
// # LTS Stability: stable
use std::env;
use std::process::Command;

fn main() {
    // Read version from Cargo.toml — single source of truth (no hardcoded strings)
    let version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_string());
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown-target".to_string());
    let profile = env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());

    println!("cargo:rustc-env=ZAINIUM_VERSION={}", version);
    println!("cargo:rustc-env=BUILD_TARGET={}", target);
    if profile == "release" {
        println!("cargo:rustc-env=OPTIMIZATION=release-lto");
    } else {
        println!("cargo:rustc-env=OPTIMIZATION={}", profile);
    }

    // LTS support date — matches [package.metadata.lts] in Cargo.toml
    println!("cargo:rustc-env=LTS_UNTIL=2028-04-27");

    // Git commit hash
    let commit = git_short_hash().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=BUILD_COMMIT={}", commit);

    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=.git/HEAD");
}

fn git_short_hash() -> Option<String> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(manifest_dir)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if commit.is_empty() {
        None
    } else {
        Some(commit)
    }
}

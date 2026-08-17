//! `qlogind` — C-ABI compat surface for quantra-logind.
//!
//! Not the daemon itself (see `main.rs`/`ctl.rs` for that) — this is the
//! `libqlogind.so` client library that other processes link against
//! directly (not over D-Bus) for session/seat/user lookups and service
//! readiness notification. See `ffi/` for the exported symbols.

pub mod ffi;

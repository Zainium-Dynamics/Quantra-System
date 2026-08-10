/// D-Bus compatibility layer — REMOVED (v4.0.4 architectural decision)
///
/// # Why Quantra does NOT implement D-Bus
///
/// Quantra uses a purpose-built JSON-over-Unix-socket control protocol
/// (`/run/quantra/control`) with 4-byte LE length-prefix framing. This was a
/// deliberate architectural choice over D-Bus for the following reasons:
///
/// 1. **Zero-dependency**: D-Bus wire protocol requires either `libdbus` or a
///    full Rust reimplementation (~5000+ lines). Both add binary size and
///    attack surface to PID 1.
///
/// 2. **Simplicity**: JSON-over-Unix-socket is debuggable with `socat` and
///    `jq`. D-Bus binary format requires specialised tools (`busctl`, `dbus-monitor`).
///
/// 3. **Security**: The control socket uses `SO_PEERCRED` for uid=0 verification.
///    D-Bus relies on its own auth handshake which is another attack surface.
///
/// 4. **Performance**: For a PID 1 control plane handling <100 requests/boot,
///    JSON serialisation overhead is irrelevant. D-Bus marshalling adds complexity
///    for zero practical benefit.
///
/// # Compatibility
///
/// Tools expecting `org.freedesktop.systemd1` (e.g. `systemctl`) will not work.
/// Use `quantra-ctl` instead — it speaks the native JSON protocol and provides
/// full feature parity including `status`, `assay`, `metrics`, and `tree`.
///
/// If D-Bus compatibility is required for third-party software, run `dbus-broker`
/// as a supervised service and register a D-Bus activation entry that proxies
/// to the Quantra control socket.

/// No-op service state registration — called by supervisor lifecycle hooks.
///
/// Previously updated a D-Bus registry. Now a no-op since the D-Bus server
/// has been removed. The control socket (`/run/quantra/control`) handles all
/// service state queries directly from the `ServiceManager`.
#[inline]
pub fn register_service_global(_name: &str, _pid: i32, _active: bool) {
    // Intentional no-op — service state is queried live from ServiceManager
}

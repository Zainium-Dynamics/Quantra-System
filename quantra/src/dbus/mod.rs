/// D-Bus compatibility layer — architectural decision: NOT IMPLEMENTED
///
/// Quantra uses JSON-over-Unix-socket (`/run/quantra/control`) exclusively.
/// See `server.rs` module documentation for the full rationale.
///
/// Only `register_service_global()` is exported as a no-op so supervisor
/// lifecycle hooks compile without changes.
pub mod server;

pub use server::register_service_global;

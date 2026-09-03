//! Tokio runtime for Snell sessions.
//!
//! Owns sockets, tasks, timeouts, reuse, UDP, and outbound. Session, TCP
//! relay, reuse, and UDP implementations start in later phases. This crate
//! currently exists to lock the workspace dependency direction:
//!
//! ```text
//! snell -> snell-config + snell-runtime -> snell-protocol
//! ```

pub use snell_protocol as protocol;

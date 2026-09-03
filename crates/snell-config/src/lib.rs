//! Two-stage configuration: raw text → validated config → runtime config.
//!
//! Parsing, unknown-key rejection, and secret redaction start in a later
//! phase. This crate currently exists to lock the workspace dependency
//! direction.

pub use snell_protocol as protocol;

//! Cryptographic primitives for Snell record codecs.
//!
//! All constants and algorithms here are part of the Snell wire protocol.
//! Every function documents its role so the implementation can be cross-checked
//! against the protocol specification.
//!
//! ## Layout
//!
//! | Module | Role |
//! |---|---|
//! | [`splitmix`] | SplitMix64 finalizer |
//! | [`prf`] | PRF32 fold + entry points |
//! | [`expand`] | `expand_stream` keystream |
//! | [`kdf`] | BLAKE2b profile secret, Argon2id AEAD key |
//!
//! Namespace derivation and the full profile live in `snell::profile`.

// Canonical SplitMix64 stream increment, also reused as a protocol PRF coefficient.
pub(crate) const GOLDEN_GAMMA: u64 = 0x9E3779B97F4A7C15;

pub(crate) mod expand;
pub(crate) mod kdf;
pub(crate) mod prf;
pub(crate) mod splitmix;

//! V6 Snell codec family: raw, unshaped, and shaped variants.
//!
//! Shared frame header layout (all three):
//!
//! ```text
//!   HEADER_PLAIN = [4][0][0][PADDING_HI LO][PAYLOAD_HI LO]
//!                 (byte 1-2 are reserved and must be zero)
//! ```
//!
//! | Variant | KDF          | Padding | AAD          | Encrypted | Max payload |
//! |---------|--------------|---------|--------------|-----------|-------------|
//! | raw     | none         | none    | none         | **no**    | u16::MAX    |
//! | unshaped| HKDF→AES-128 | forced 0| empty        | yes       | 0x3fff      |
//! | shaped  | HKDF→AES-128 | profile | prefix/pad   | yes       | u16::MAX    |
//!
//! Each sub-module exposes a pair of encoder/decoder structs and a `new` constructor.

mod raw;
mod shaped;
mod unshaped;

pub use raw::{V6UnsafeRawDecoder, V6UnsafeRawEncoder};
pub use shaped::{V6ShapedDecoder, V6ShapedEncoder};
pub use unshaped::{V6UnshapedDecoder, V6UnshapedEncoder};

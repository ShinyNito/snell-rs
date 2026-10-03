//! v6 record codecs: shaped (default), unshaped, and feature-gated unsafe-raw.

mod prf;
pub(crate) mod profile;
#[cfg(feature = "unsafe-raw")]
mod raw;
mod salt;
mod shaped;
mod unshaped;

#[cfg(feature = "unsafe-raw")]
pub use raw::{V6UnsafeRawDecoder, V6UnsafeRawEncoder};
pub use shaped::{V6ShapedDecoder, V6ShapedEncoder};
pub use unshaped::{V6UnshapedDecoder, V6UnshapedEncoder};

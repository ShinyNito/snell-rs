//! v6 record codecs: shaped (default), unshaped, and feature-gated unsafe-raw.

pub use crate::v6_shaped::{V6ShapedDecoder, V6ShapedEncoder, V6ShapedReservation};
pub use crate::v6_unshaped::{V6UnshapedDecoder, V6UnshapedEncoder, V6UnshapedReservation};

#[cfg(feature = "unsafe-raw")]
pub use crate::v6_raw::{V6UnsafeRawDecoder, V6UnsafeRawEncoder, V6UnsafeRawReservation};

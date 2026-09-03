//! v6 record codecs: shaped (default), unshaped, and feature-gated unsafe-raw.

use crate::{Clock, Entropy, Psk, Result};

pub use crate::v6_shaped::{V6ShapedDecoder, V6ShapedEncoder, V6ShapedReservation};
pub use crate::v6_unshaped::{V6UnshapedDecoder, V6UnshapedEncoder, V6UnshapedReservation};

#[cfg(feature = "unsafe-raw")]
pub use crate::v6_raw::{V6UnsafeRawDecoder, V6UnsafeRawEncoder, V6UnsafeRawReservation};

/// Marker for v6 shaped (default) records.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct V6Shaped;

/// Marker for v6 unshaped records.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct V6Unshaped;

/// Marker for v6 unsafe-raw records. Type exists only with `--features unsafe-raw`.
#[cfg(feature = "unsafe-raw")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct V6UnsafeRaw;

impl V6Shaped {
    pub fn encoder<E: Entropy, C: Clock>(
        psk: &Psk,
        entropy: E,
        clock: C,
    ) -> Result<V6ShapedEncoder<E, C>> {
        V6ShapedEncoder::new(psk, entropy, clock)
    }

    pub fn decoder(psk: Psk) -> Result<V6ShapedDecoder> {
        V6ShapedDecoder::new(psk)
    }
}

impl V6Unshaped {
    pub fn encoder<E: Entropy, C: Clock>(
        psk: &Psk,
        entropy: E,
        clock: C,
    ) -> Result<V6UnshapedEncoder<E, C>> {
        V6UnshapedEncoder::new(psk, entropy, clock)
    }

    pub fn decoder(psk: Psk) -> V6UnshapedDecoder {
        V6UnshapedDecoder::new(psk)
    }
}

#[cfg(feature = "unsafe-raw")]
impl V6UnsafeRaw {
    pub fn encoder() -> V6UnsafeRawEncoder {
        V6UnsafeRawEncoder::new()
    }

    pub fn decoder() -> V6UnsafeRawDecoder {
        V6UnsafeRawDecoder::new()
    }
}

use snell_protocol::{
    V4Decoder, V4Encoder, V6ShapedDecoder, V6ShapedEncoder, V6UnshapedDecoder, V6UnshapedEncoder,
};

/// One session's record codec pair, chosen per connection.
pub(crate) enum Codec {
    V4 {
        encoder: V4Encoder,
        decoder: V4Decoder,
    },
    V6Shaped {
        encoder: V6ShapedEncoder,
        decoder: V6ShapedDecoder,
    },
    V6Unshaped {
        encoder: V6UnshapedEncoder,
        decoder: V6UnshapedDecoder,
    },
}

// Dispatch once around setup/relay while each record loop remains monomorphized.
// An enum-backed trait implementation would dispatch again on every record.
macro_rules! with_codec {
    ($codec:expr, |$encoder:ident, $decoder:ident| $body:block) => {
        match $codec {
            $crate::codec::Codec::V4 {
                encoder: $encoder,
                decoder: $decoder,
            } => $body,
            $crate::codec::Codec::V6Shaped {
                encoder: $encoder,
                decoder: $decoder,
            } => $body,
            $crate::codec::Codec::V6Unshaped {
                encoder: $encoder,
                decoder: $decoder,
            } => $body,
        }
    };
}
pub(crate) use with_codec;

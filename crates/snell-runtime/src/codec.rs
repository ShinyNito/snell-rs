use crate::buffer::PooledBuffer;
use crate::bufio::TcpReservation;

// Dispatch once around setup/relay while each record loop remains monomorphized.
// An enum-backed trait implementation would dispatch again on every record.
macro_rules! with_codec {
    ($codec:expr, |$encoder:ident, $decoder:ident| $body:block) => {
        match $codec {
            $crate::pool::PooledCodec::V4 {
                encoder: $encoder,
                decoder: $decoder,
            } => $body,
            $crate::pool::PooledCodec::V6Shaped {
                encoder: $encoder,
                decoder: $decoder,
            } => $body,
            $crate::pool::PooledCodec::V6Unshaped {
                encoder: $encoder,
                decoder: $decoder,
            } => $body,
        }
    };
}
pub(crate) use with_codec;

use snell_protocol::{
    AES_128_KEY_LEN, Buffer, DecodeStatus, DecodedRecord, Result, SALT_LEN, V4Decoder, V4Encoder,
    V6ShapedDecoder, V6ShapedEncoder, V6UnshapedDecoder, V6UnshapedEncoder,
};

pub(crate) trait TcpEncoder {
    fn reserve<'a>(
        &'a mut self,
        buf: &'a mut Buffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<impl TcpReservation + 'a>;
}

pub(crate) trait TcpDecoder {
    fn decode(&mut self, buf: &mut Buffer) -> Result<DecodeStatus>;
    fn consume(&mut self, buf: &mut PooledBuffer, record: &DecodedRecord) -> Result<()>;
    fn replay_identity(&self) -> Option<[u8; SALT_LEN]>;
    fn has_unconsumed_plaintext(&self) -> bool;
    fn kdf_need(&self) -> usize;
    fn kdf_salt(&self, buf: &Buffer) -> Result<[u8; SALT_LEN]>;
    fn install_aead(&mut self, salt: [u8; SALT_LEN], key: [u8; AES_128_KEY_LEN]) -> Result<()>;
}

// Forward to the inherent codec methods; `reserve` picks the reservation mode
// (v6-shaped reserves scattered records so payloads stay in place).
macro_rules! impl_tcp_codec {
    ($encoder:ident::$reserve:ident, $decoder:ident, |$d:ident, $salt:ident, $key:ident| $install:expr) => {
        impl TcpEncoder for $encoder {
            fn reserve<'a>(
                &'a mut self,
                buf: &'a mut Buffer,
                prefix: &[u8],
                hint: usize,
            ) -> Result<impl TcpReservation + 'a> {
                $encoder::$reserve(self, buf, prefix, hint)
            }
        }

        impl TcpDecoder for $decoder {
            fn decode(&mut self, buf: &mut Buffer) -> Result<DecodeStatus> {
                $decoder::decode(self, buf)
            }

            fn consume(&mut self, buf: &mut PooledBuffer, record: &DecodedRecord) -> Result<()> {
                $decoder::consume(self, buf, record)
            }

            fn replay_identity(&self) -> Option<[u8; SALT_LEN]> {
                $decoder::replay_identity(self)
            }

            fn has_unconsumed_plaintext(&self) -> bool {
                $decoder::has_unconsumed_plaintext(self)
            }

            fn kdf_need(&self) -> usize {
                $decoder::kdf_need(self)
            }

            fn kdf_salt(&self, buf: &Buffer) -> Result<[u8; SALT_LEN]> {
                $decoder::kdf_salt(self, buf)
            }

            fn install_aead(
                &mut self,
                $salt: [u8; SALT_LEN],
                $key: [u8; AES_128_KEY_LEN],
            ) -> Result<()> {
                let $d = self;
                $install
            }
        }
    };
}

// v4 has no replay identity, so its key install ignores the salt.
impl_tcp_codec!(V4Encoder::reserve, V4Decoder, |d, _salt, key| d
    .install_aead(key));
impl_tcp_codec!(
    V6ShapedEncoder::reserve_scattered,
    V6ShapedDecoder,
    |d, salt, key| d.install_aead(salt, key)
);
impl_tcp_codec!(
    V6UnshapedEncoder::reserve,
    V6UnshapedDecoder,
    |d, salt, key| d.install_aead(salt, key)
);

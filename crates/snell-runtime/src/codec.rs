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

impl TcpEncoder for V4Encoder {
    fn reserve<'a>(
        &'a mut self,
        buf: &'a mut Buffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<impl TcpReservation + 'a> {
        V4Encoder::reserve(self, buf, prefix, hint)
    }
}

impl TcpDecoder for V4Decoder {
    fn decode(&mut self, buf: &mut Buffer) -> Result<DecodeStatus> {
        V4Decoder::decode(self, buf)
    }

    fn consume(&mut self, buf: &mut PooledBuffer, record: &DecodedRecord) -> Result<()> {
        V4Decoder::consume(self, buf, record)?;
        buf.release_empty();
        Ok(())
    }

    fn replay_identity(&self) -> Option<[u8; SALT_LEN]> {
        V4Decoder::replay_identity(self)
    }

    fn has_unconsumed_plaintext(&self) -> bool {
        V4Decoder::has_unconsumed_plaintext(self)
    }

    fn kdf_need(&self) -> usize {
        V4Decoder::kdf_need(self)
    }

    fn kdf_salt(&self, buf: &Buffer) -> Result<[u8; SALT_LEN]> {
        V4Decoder::kdf_salt(self, buf)
    }

    fn install_aead(&mut self, _salt: [u8; SALT_LEN], key: [u8; AES_128_KEY_LEN]) -> Result<()> {
        V4Decoder::install_aead(self, key)
    }
}

impl TcpEncoder for V6ShapedEncoder {
    fn reserve<'a>(
        &'a mut self,
        buf: &'a mut Buffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<impl TcpReservation + 'a> {
        V6ShapedEncoder::reserve(self, buf, prefix, hint)
    }
}

impl TcpDecoder for V6ShapedDecoder {
    fn decode(&mut self, buf: &mut Buffer) -> Result<DecodeStatus> {
        V6ShapedDecoder::decode(self, buf)
    }

    fn consume(&mut self, buf: &mut PooledBuffer, record: &DecodedRecord) -> Result<()> {
        V6ShapedDecoder::consume(self, buf, record)?;
        buf.release_empty();
        Ok(())
    }

    fn replay_identity(&self) -> Option<[u8; SALT_LEN]> {
        V6ShapedDecoder::replay_identity(self)
    }

    fn has_unconsumed_plaintext(&self) -> bool {
        V6ShapedDecoder::has_unconsumed_plaintext(self)
    }

    fn kdf_need(&self) -> usize {
        V6ShapedDecoder::kdf_need(self)
    }

    fn kdf_salt(&self, buf: &Buffer) -> Result<[u8; SALT_LEN]> {
        V6ShapedDecoder::kdf_salt(self, buf)
    }

    fn install_aead(&mut self, salt: [u8; SALT_LEN], key: [u8; AES_128_KEY_LEN]) -> Result<()> {
        V6ShapedDecoder::install_aead(self, salt, key)
    }
}

impl TcpEncoder for V6UnshapedEncoder {
    fn reserve<'a>(
        &'a mut self,
        buf: &'a mut Buffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<impl TcpReservation + 'a> {
        V6UnshapedEncoder::reserve(self, buf, prefix, hint)
    }
}

impl TcpDecoder for V6UnshapedDecoder {
    fn decode(&mut self, buf: &mut Buffer) -> Result<DecodeStatus> {
        V6UnshapedDecoder::decode(self, buf)
    }

    fn consume(&mut self, buf: &mut PooledBuffer, record: &DecodedRecord) -> Result<()> {
        V6UnshapedDecoder::consume(self, buf, record)?;
        buf.release_empty();
        Ok(())
    }

    fn replay_identity(&self) -> Option<[u8; SALT_LEN]> {
        V6UnshapedDecoder::replay_identity(self)
    }

    fn has_unconsumed_plaintext(&self) -> bool {
        V6UnshapedDecoder::has_unconsumed_plaintext(self)
    }

    fn kdf_need(&self) -> usize {
        V6UnshapedDecoder::kdf_need(self)
    }

    fn kdf_salt(&self, buf: &Buffer) -> Result<[u8; SALT_LEN]> {
        V6UnshapedDecoder::kdf_salt(self, buf)
    }

    fn install_aead(&mut self, salt: [u8; SALT_LEN], key: [u8; AES_128_KEY_LEN]) -> Result<()> {
        V6UnshapedDecoder::install_aead(self, salt, key)
    }
}

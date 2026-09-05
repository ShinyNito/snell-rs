use snell_protocol::PayloadBuffer;

use snell_protocol::{
    AES_128_KEY_LEN, DecodeStatus, DecodedRecord, EncodeBuffer, RecvBuffer, Result, SALT_LEN,
    V4Decoder, V4Encoder, V4Reservation, V6ShapedDecoder, V6ShapedEncoder, V6ShapedReservation,
    V6UnshapedDecoder, V6UnshapedEncoder, V6UnshapedReservation,
};

pub(crate) trait TcpReservation {
    fn payload_mut(&mut self) -> &mut [u8];
    fn payload_buf(&mut self) -> PayloadBuffer<'_>;
    fn capacity(&self) -> usize;
    fn seal(self, written: usize) -> Result<()>;
}

pub(crate) trait TcpEncoder {
    fn reserve<'a>(
        &'a mut self,
        buf: &'a mut EncodeBuffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<impl TcpReservation + 'a>;
}

pub(crate) trait TcpDecoder {
    fn decode(&mut self, buf: &mut RecvBuffer) -> Result<DecodeStatus>;
    fn consume(&mut self, buf: &mut RecvBuffer, record: &DecodedRecord) -> Result<()>;
    fn replay_identity(&self) -> Option<[u8; SALT_LEN]>;
    fn has_unconsumed_plaintext(&self) -> bool;
    fn kdf_need(&self) -> usize;
    fn kdf_salt(&self, buf: &RecvBuffer) -> Result<[u8; SALT_LEN]>;
    fn install_aead(&mut self, salt: [u8; SALT_LEN], key: [u8; AES_128_KEY_LEN]) -> Result<()>;
}

impl TcpReservation for V4Reservation<'_> {
    fn payload_mut(&mut self) -> &mut [u8] {
        V4Reservation::payload_mut(self)
    }

    fn payload_buf(&mut self) -> PayloadBuffer<'_> {
        V4Reservation::payload_buf(self)
    }

    fn capacity(&self) -> usize {
        V4Reservation::capacity(self)
    }

    fn seal(self, written: usize) -> Result<()> {
        V4Reservation::seal(self, written)
    }
}

impl TcpEncoder for V4Encoder {
    fn reserve<'a>(
        &'a mut self,
        buf: &'a mut EncodeBuffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<impl TcpReservation + 'a> {
        V4Encoder::reserve(self, buf, prefix, hint)
    }
}

impl TcpDecoder for V4Decoder {
    fn decode(&mut self, buf: &mut RecvBuffer) -> Result<DecodeStatus> {
        V4Decoder::decode(self, buf)
    }

    fn consume(&mut self, buf: &mut RecvBuffer, record: &DecodedRecord) -> Result<()> {
        V4Decoder::consume(self, buf, record)
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

    fn kdf_salt(&self, buf: &RecvBuffer) -> Result<[u8; SALT_LEN]> {
        V4Decoder::kdf_salt(self, buf)
    }

    fn install_aead(&mut self, _salt: [u8; SALT_LEN], key: [u8; AES_128_KEY_LEN]) -> Result<()> {
        V4Decoder::install_aead(self, key)
    }
}

impl TcpReservation for V6ShapedReservation<'_> {
    fn payload_mut(&mut self) -> &mut [u8] {
        V6ShapedReservation::payload_mut(self)
    }

    fn payload_buf(&mut self) -> PayloadBuffer<'_> {
        V6ShapedReservation::payload_buf(self)
    }

    fn capacity(&self) -> usize {
        V6ShapedReservation::capacity(self)
    }

    fn seal(self, written: usize) -> Result<()> {
        V6ShapedReservation::seal(self, written)
    }
}

impl TcpEncoder for V6ShapedEncoder {
    fn reserve<'a>(
        &'a mut self,
        buf: &'a mut EncodeBuffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<impl TcpReservation + 'a> {
        V6ShapedEncoder::reserve(self, buf, prefix, hint)
    }
}

impl TcpDecoder for V6ShapedDecoder {
    fn decode(&mut self, buf: &mut RecvBuffer) -> Result<DecodeStatus> {
        V6ShapedDecoder::decode(self, buf)
    }

    fn consume(&mut self, buf: &mut RecvBuffer, record: &DecodedRecord) -> Result<()> {
        V6ShapedDecoder::consume(self, buf, record)
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

    fn kdf_salt(&self, buf: &RecvBuffer) -> Result<[u8; SALT_LEN]> {
        V6ShapedDecoder::kdf_salt(self, buf)
    }

    fn install_aead(&mut self, salt: [u8; SALT_LEN], key: [u8; AES_128_KEY_LEN]) -> Result<()> {
        V6ShapedDecoder::install_aead(self, salt, key)
    }
}

impl TcpReservation for V6UnshapedReservation<'_> {
    fn payload_mut(&mut self) -> &mut [u8] {
        V6UnshapedReservation::payload_mut(self)
    }

    fn payload_buf(&mut self) -> PayloadBuffer<'_> {
        V6UnshapedReservation::payload_buf(self)
    }

    fn capacity(&self) -> usize {
        V6UnshapedReservation::capacity(self)
    }

    fn seal(self, written: usize) -> Result<()> {
        V6UnshapedReservation::seal(self, written)
    }
}

impl TcpEncoder for V6UnshapedEncoder {
    fn reserve<'a>(
        &'a mut self,
        buf: &'a mut EncodeBuffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<impl TcpReservation + 'a> {
        V6UnshapedEncoder::reserve(self, buf, prefix, hint)
    }
}

impl TcpDecoder for V6UnshapedDecoder {
    fn decode(&mut self, buf: &mut RecvBuffer) -> Result<DecodeStatus> {
        V6UnshapedDecoder::decode(self, buf)
    }

    fn consume(&mut self, buf: &mut RecvBuffer, record: &DecodedRecord) -> Result<()> {
        V6UnshapedDecoder::consume(self, buf, record)
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

    fn kdf_salt(&self, buf: &RecvBuffer) -> Result<[u8; SALT_LEN]> {
        V6UnshapedDecoder::kdf_salt(self, buf)
    }

    fn install_aead(&mut self, salt: [u8; SALT_LEN], key: [u8; AES_128_KEY_LEN]) -> Result<()> {
        V6UnshapedDecoder::install_aead(self, salt, key)
    }
}

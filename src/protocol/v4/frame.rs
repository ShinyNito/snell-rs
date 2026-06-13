use bytes::BytesMut;
use rand::RngExt;

use crate::MAX_PACKET_SIZE;
use crate::error::{Error, Result};
use crate::protocol::crypto::{AEAD_TAG_SIZE, Aes128GcmCrypto, SALT_SIZE};
use crate::protocol::nonce::Nonce12;
use crate::protocol::random::fill_random;

pub const V4_HEADER_PLAIN_SIZE: usize = 7;
pub const V4_HEADER_CIPHER_SIZE: usize = V4_HEADER_PLAIN_SIZE + AEAD_TAG_SIZE;
pub const V4_INITIAL_PADDING_MIN: usize = 0x100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedHeader {
    pub padding_len: usize,
    pub payload_len: usize,
}

impl DecodedHeader {
    pub fn body_len(self) -> Result<usize> {
        if self.payload_len == 0 {
            if self.padding_len != 0 {
                return Err(Error::ZeroChunkWithPadding);
            }
            return Ok(0);
        }
        Ok(self.padding_len + self.payload_len + AEAD_TAG_SIZE)
    }
}

pub struct V4FrameEncoder {
    crypto: Aes128GcmCrypto,
    nonce: Nonce12,
    salt: [u8; SALT_SIZE],
    salt_sent: bool,
    initial_padding_len: usize,
}

impl V4FrameEncoder {
    pub fn new(psk: &[u8]) -> Result<Self> {
        let mut salt = [0; SALT_SIZE];
        fill_random(&mut salt)?;

        let mut padding_delta = [0u8; 1];
        fill_random(&mut padding_delta)?;
        Self::with_salt_and_initial_padding(
            psk,
            salt,
            V4_INITIAL_PADDING_MIN + usize::from(padding_delta[0]),
        )
    }

    #[doc(hidden)]
    pub fn with_salt_and_initial_padding(
        psk: &[u8],
        salt: [u8; SALT_SIZE],
        initial_padding_len: usize,
    ) -> Result<Self> {
        if initial_padding_len > MAX_PACKET_SIZE {
            return Err(Error::PayloadTooLarge);
        }
        Ok(Self {
            crypto: Aes128GcmCrypto::from_psk_and_salt(psk, &salt)?,
            nonce: Nonce12::new(),
            salt,
            salt_sent: false,
            initial_padding_len,
        })
    }

    #[must_use]
    pub const fn salt(&self) -> &[u8; SALT_SIZE] {
        &self.salt
    }

    #[must_use]
    pub const fn initial_padding_len(&self) -> usize {
        self.initial_padding_len
    }

    pub fn encode_empty_frame(&mut self, head: &mut BytesMut) -> Result<usize> {
        let start_len = head.len();
        let salt_len = if self.salt_sent { 0 } else { SALT_SIZE };
        head.reserve(salt_len + V4_HEADER_CIPHER_SIZE);

        if !self.salt_sent {
            head.extend_from_slice(&self.salt);
            self.salt_sent = true;
        }

        self.write_encrypted_header(0, 0, head)?;
        Ok(head.len() - start_len)
    }

    pub fn encode_payload_in_place(
        &mut self,
        payload: &mut BytesMut,
        payload_len: usize,
        head: &mut BytesMut,
    ) -> Result<usize> {
        let padding_len = self.next_padding_len(payload_len);
        if payload_len == 0 || payload_len > MAX_PACKET_SIZE || padding_len > MAX_PACKET_SIZE {
            return Err(Error::PayloadTooLarge);
        }
        if payload.len() != payload_len {
            return Err(Error::FrameLengthMismatch);
        }

        let start_len = head.len();
        let salt_len = if self.salt_sent { 0 } else { SALT_SIZE };
        head.reserve(salt_len + V4_HEADER_CIPHER_SIZE + padding_len);

        if !self.salt_sent {
            head.extend_from_slice(&self.salt);
            self.salt_sent = true;
        }

        self.write_encrypted_header(padding_len, payload_len, head)?;
        let padding_start = head.len();
        head.resize(padding_start + padding_len, 0);

        let tag = self
            .crypto
            .encrypt_detached(self.nonce.as_bytes(), &mut payload[..payload_len])?;
        self.nonce.increment();
        payload.extend_from_slice(&tag);

        if padding_len > 0 {
            let padding = &mut head[padding_start..];
            make_v4_padding(padding, payload)?;
            swap_padding(padding, payload);
        }

        Ok(head.len() - start_len + payload.len())
    }

    fn next_padding_len(&self, payload_len: usize) -> usize {
        if self.salt_sent || payload_len == 0 {
            0
        } else {
            self.initial_padding_len
        }
    }

    fn write_encrypted_header(
        &mut self,
        padding_len: usize,
        payload_len: usize,
        out: &mut BytesMut,
    ) -> Result<()> {
        let mut header = [0u8; V4_HEADER_PLAIN_SIZE];
        header[0] = 4;
        header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
        header[5..7].copy_from_slice(&(payload_len as u16).to_be_bytes());

        let tag = self
            .crypto
            .encrypt_detached(self.nonce.as_bytes(), &mut header)?;
        self.nonce.increment();
        out.extend_from_slice(&header);
        out.extend_from_slice(&tag);
        Ok(())
    }
}

pub struct V4FrameDecoder {
    crypto: Aes128GcmCrypto,
    nonce: Nonce12,
}

impl V4FrameDecoder {
    pub fn new(psk: &[u8], salt: [u8; SALT_SIZE]) -> Result<Self> {
        Ok(Self {
            crypto: Aes128GcmCrypto::from_psk_and_salt(psk, &salt)?,
            nonce: Nonce12::new(),
        })
    }

    pub fn decode_header(
        &mut self,
        header_cipher: &mut [u8; V4_HEADER_CIPHER_SIZE],
    ) -> Result<DecodedHeader> {
        let decrypt_result = self
            .crypto
            .decrypt_within(self.nonce.as_bytes(), header_cipher, 0..);
        self.nonce.increment();
        let header = decrypt_result?;

        if header[0] != 4 {
            return Err(Error::InvalidV4Header);
        }

        let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
        if padding_len > MAX_PACKET_SIZE || payload_len > MAX_PACKET_SIZE {
            return Err(Error::PayloadTooLarge);
        }
        Ok(DecodedHeader {
            padding_len,
            payload_len,
        })
    }

    pub fn decode_payload_in_place<'a>(
        &mut self,
        header: DecodedHeader,
        body: &'a mut [u8],
    ) -> Result<&'a mut [u8]> {
        let expected_body_len = header.body_len()?;
        if header.payload_len == 0 {
            if body.is_empty() {
                return Err(Error::ZeroChunk);
            }
            return Err(Error::FrameLengthMismatch);
        }
        if body.len() != expected_body_len {
            return Err(Error::FrameLengthMismatch);
        }

        let (padding, payload_cipher_and_tag) = body.split_at_mut(header.padding_len);
        if !padding.is_empty() {
            swap_padding(padding, payload_cipher_and_tag);
        }

        let decrypt_result =
            self.crypto
                .decrypt_within(self.nonce.as_bytes(), body, header.padding_len..);
        self.nonce.increment();
        let payload = decrypt_result?;

        Ok(payload)
    }
}

#[doc(hidden)]
pub fn split_salt(frame: &[u8]) -> Result<([u8; SALT_SIZE], &[u8])> {
    if frame.len() < SALT_SIZE {
        return Err(Error::FrameTooShort);
    }
    let mut salt = [0; SALT_SIZE];
    salt.copy_from_slice(&frame[..SALT_SIZE]);
    Ok((salt, &frame[SALT_SIZE..]))
}

#[inline]
fn swap_padding(padding: &mut [u8], payload_cipher: &mut [u8]) {
    let limit = padding.len().min(payload_cipher.len());
    for index in (0..limit).step_by(2) {
        std::mem::swap(&mut padding[index], &mut payload_cipher[index]);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum V4PaddingMode {
    NoPadding,
    Random,
    BitRatio,
}

fn make_v4_padding(padding: &mut [u8], payload_cipher: &[u8]) -> Result<V4PaddingMode> {
    if padding.is_empty() {
        return Ok(V4PaddingMode::NoPadding);
    }

    let Some(target_ones) = select_v4_padding_target_ones(padding.len(), payload_cipher)? else {
        fill_random(padding)?;
        return Ok(V4PaddingMode::Random);
    };

    fill_padding_with_sampled_bits(padding, target_ones)?;
    Ok(V4PaddingMode::BitRatio)
}

fn select_v4_padding_target_ones(
    padding_len: usize,
    payload_cipher: &[u8],
) -> Result<Option<usize>> {
    let payload_ones = count_v4_payload_ones(payload_cipher);
    let payload_zeros = payload_cipher.len() * 8 - payload_ones;
    if payload_zeros == 0 {
        return Ok(None);
    }

    let ratio = payload_ones as f64 / payload_zeros as f64;
    if ratio <= 0.5 || ratio >= 1.6 {
        return Ok(None);
    }

    let target_ratio_base = if payload_zeros < payload_ones {
        0.4
    } else {
        1.6
    };
    let target_ratio = target_ratio_base + random_unit_f64()? / 10.0;
    Ok(v4_padding_target_ones_for_ratio(
        padding_len,
        payload_cipher.len(),
        payload_ones,
        target_ratio,
    ))
}

fn v4_padding_target_ones_for_ratio(
    padding_len: usize,
    payload_cipher_len: usize,
    payload_ones: usize,
    target_ratio: f64,
) -> Option<usize> {
    let total_bits = (padding_len + payload_cipher_len) * 8;
    let padding_bits = padding_len * 8;
    let target_ones = (total_bits as f64 * (target_ratio / (target_ratio + 1.0))
        - payload_ones as f64)
        .trunc() as isize;

    if target_ones < 0 {
        return None;
    }

    let target_ones = target_ones as usize;
    if target_ones > padding_bits {
        return None;
    }
    Some(target_ones)
}

fn fill_padding_with_sampled_bits(padding: &mut [u8], target_ones: usize) -> Result<()> {
    let padding_bits = padding.len() * 8;
    debug_assert!(target_ones <= padding_bits);

    if target_ones == 0 {
        padding.fill(0);
        return Ok(());
    }

    if target_ones == padding_bits {
        padding.fill(0xff);
        return Ok(());
    }

    let target_zeros = padding_bits - target_ones;
    let mut rng = rand::rng();

    if target_ones <= target_zeros {
        padding.fill(0);

        for j in padding_bits - target_ones..padding_bits {
            let candidate = rng.random_range(0..j + 1);
            let candidate_mask = 1u8 << (candidate & 7);
            let candidate_is_selected = padding[candidate >> 3] & candidate_mask != 0;

            let index = if candidate_is_selected { j } else { candidate };
            padding[index >> 3] |= 1u8 << (index & 7);
        }
    } else {
        padding.fill(0xff);

        for j in padding_bits - target_zeros..padding_bits {
            let candidate = rng.random_range(0..j + 1);
            let candidate_mask = 1u8 << (candidate & 7);
            let candidate_is_selected = padding[candidate >> 3] & candidate_mask == 0;

            let index = if candidate_is_selected { j } else { candidate };
            padding[index >> 3] &= !(1u8 << (index & 7));
        }
    }

    Ok(())
}

fn count_v4_payload_ones(payload_cipher: &[u8]) -> usize {
    count_one_bits(&payload_cipher[..payload_cipher.len() & !3])
}

fn count_one_bits(bytes: &[u8]) -> usize {
    let (chunks, tail) = bytes.as_chunks::<8>();
    let word_ones = chunks
        .iter()
        .map(|chunk| u64::from_ne_bytes(*chunk).count_ones() as usize)
        .sum::<usize>();
    let tail_ones = tail
        .iter()
        .map(|byte| byte.count_ones() as usize)
        .sum::<usize>();

    word_ones + tail_ones
}

fn random_unit_f64() -> Result<f64> {
    let mut bytes = [0; 8];
    fill_random(&mut bytes)?;
    let value = u64::from_le_bytes(bytes) >> 11;
    Ok(value as f64 / ((1u64 << 53) as f64))
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::{
        V4_HEADER_CIPHER_SIZE, V4FrameDecoder, V4FrameEncoder, V4PaddingMode, count_one_bits,
        count_v4_payload_ones, fill_padding_with_sampled_bits, make_v4_padding, split_salt,
        swap_padding, v4_padding_target_ones_for_ratio,
    };
    use crate::error::Error;
    use crate::test_support::TEST_PSK;

    fn encode_test_frame(
        encoder: &mut V4FrameEncoder,
        payload: &[u8],
        wire: &mut BytesMut,
    ) -> usize {
        let start_len = wire.len();
        let mut head = BytesMut::new();
        if payload.is_empty() {
            encoder.encode_empty_frame(&mut head).unwrap();
            wire.extend_from_slice(&head);
        } else {
            let mut body = BytesMut::from(payload);
            encoder
                .encode_payload_in_place(&mut body, payload.len(), &mut head)
                .unwrap();
            wire.extend_from_slice(&head);
            wire.extend_from_slice(&body);
        }
        wire.len() - start_len
    }

    #[test]
    fn swaps_every_other_byte_until_shorter_side() {
        let mut padding = [1, 2, 3, 4, 5];
        let mut payload = [10, 20, 30];
        swap_padding(&mut padding, &mut payload);
        assert_eq!(padding, [10, 2, 30, 4, 5]);
        assert_eq!(payload, [1, 20, 3]);
    }

    #[test]
    fn counts_payload_ones_on_four_byte_aligned_prefix() {
        let payload_cipher = [0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff];

        assert_eq!(count_v4_payload_ones(&payload_cipher), 8);
    }

    #[test]
    fn counts_one_bits_with_word_chunks_and_tail() {
        let bytes = [
            0xff, 0x0f, 0x00, 0x80, 0x55, 0xaa, 0x33, 0xcc, 0x01, 0x03, 0x07,
        ];

        assert_eq!(count_one_bits(&bytes), 35);
    }

    #[test]
    fn target_ones_uses_target_ratio_over_padding_and_payload_bits() {
        let target = v4_padding_target_ones_for_ratio(8, 16, 48, 0.4);

        assert_eq!(target, Some(6));
    }

    #[test]
    fn target_ones_rejects_impossible_padding_bit_count() {
        let target = v4_padding_target_ones_for_ratio(1, 16, 120, 0.4);

        assert_eq!(target, None);
    }

    #[test]
    fn sampled_padding_has_exact_target_ones() {
        let mut padding = [0; 32];

        fill_padding_with_sampled_bits(&mut padding, 101).unwrap();

        assert_eq!(count_one_bits(&padding), 101);
    }

    #[test]
    fn make_padding_uses_bit_ratio_inside_payload_ratio_window() {
        let mut padding = [0; 8];
        let payload_cipher = [0xff, 0x00, 0xff, 0x00];

        let mode = make_v4_padding(&mut padding, &payload_cipher).unwrap();
        let padding_ones = count_one_bits(&padding);
        let min_target =
            v4_padding_target_ones_for_ratio(padding.len(), payload_cipher.len(), 16, 1.6).unwrap();
        let max_target =
            v4_padding_target_ones_for_ratio(padding.len(), payload_cipher.len(), 16, 1.7).unwrap();

        assert_eq!(mode, V4PaddingMode::BitRatio);
        assert!(padding_ones >= min_target);
        assert!(padding_ones <= max_target);
    }

    #[test]
    fn make_padding_falls_back_to_random_outside_payload_ratio_window() {
        let mut padding = [0; 8];
        let payload_cipher = [0; 4];

        let mode = make_v4_padding(&mut padding, &payload_cipher).unwrap();

        assert_eq!(mode, V4PaddingMode::Random);
    }

    #[test]
    fn encodes_and_decodes_payload_frame() {
        let psk = TEST_PSK;
        let salt = [3u8; 16];
        let payload = b"GET / HTTP/1.1\r\n\r\n";
        let mut encoder = V4FrameEncoder::with_salt_and_initial_padding(psk, salt, 8).unwrap();
        let mut wire = BytesMut::with_capacity(128);

        let written = encode_test_frame(&mut encoder, payload, &mut wire);
        assert_eq!(written, wire.len());
        assert_eq!(&wire[..16], &salt);
        assert!(wire.len() > 16 + V4_HEADER_CIPHER_SIZE + payload.len());

        let (decoded_salt, frame) = split_salt(&wire).unwrap();
        let mut frame = BytesMut::from(frame);
        let mut decoder = V4FrameDecoder::new(psk, decoded_salt).unwrap();
        let mut header_cipher = [0; V4_HEADER_CIPHER_SIZE];
        header_cipher.copy_from_slice(&frame[..V4_HEADER_CIPHER_SIZE]);
        let header = decoder.decode_header(&mut header_cipher).unwrap();
        let mut body = frame.split_off(V4_HEADER_CIPHER_SIZE);

        let out = decoder.decode_payload_in_place(header, &mut body).unwrap();
        assert_eq!(out.len(), payload.len());
        assert_eq!(out, payload);
    }

    #[test]
    fn encoded_padding_biases_unmixed_body_bit_ratio() {
        let psk = TEST_PSK;
        let salt = [7u8; 16];
        let payload = [0x51; 128];
        let initial_padding_len = 256;
        let mut encoder =
            V4FrameEncoder::with_salt_and_initial_padding(psk, salt, initial_padding_len).unwrap();
        let mut wire = BytesMut::with_capacity(512);

        encode_test_frame(&mut encoder, &payload, &mut wire);

        let (decoded_salt, frame) = split_salt(&wire).unwrap();
        let mut header_cipher = [0; V4_HEADER_CIPHER_SIZE];
        header_cipher.copy_from_slice(&frame[..V4_HEADER_CIPHER_SIZE]);
        let mut decoder = V4FrameDecoder::new(psk, decoded_salt).unwrap();
        let header = decoder.decode_header(&mut header_cipher).unwrap();
        assert_eq!(header.padding_len, initial_padding_len);

        let mut body = BytesMut::from(&frame[V4_HEADER_CIPHER_SIZE..]);
        let (padding, payload_cipher) = body.split_at_mut(header.padding_len);
        swap_padding(padding, payload_cipher);

        let payload_ones = count_v4_payload_ones(payload_cipher);
        let payload_zeros = payload_cipher.len() * 8 - payload_ones;
        let payload_ratio = payload_ones as f64 / payload_zeros as f64;
        assert!(payload_ratio > 0.5);
        assert!(payload_ratio < 1.6);

        let total_bits = (padding.len() + payload_cipher.len()) * 8;
        let mixed_ones = count_one_bits(padding) + payload_ones;
        let mixed_zeros = total_bits - mixed_ones;
        let mixed_ratio = mixed_ones as f64 / mixed_zeros as f64;
        if payload_zeros < payload_ones {
            assert!(mixed_ratio >= 0.39);
            assert!(mixed_ratio < 0.50);
        } else {
            assert!(mixed_ratio >= 1.59);
            assert!(mixed_ratio < 1.70);
        }
    }

    #[test]
    fn payload_in_place_path_appends_to_non_empty_output() {
        let psk = TEST_PSK;
        let salt = [9u8; 16];
        let payload = b"streamed payload";
        let mut encoder = V4FrameEncoder::with_salt_and_initial_padding(psk, salt, 8).unwrap();
        let mut wire = BytesMut::from(&b"prefix"[..]);

        let start_len = wire.len();
        let mut head = BytesMut::new();
        let mut body = BytesMut::from(&payload[..]);
        let written = encoder
            .encode_payload_in_place(&mut body, payload.len(), &mut head)
            .unwrap();
        wire.extend_from_slice(&head);
        wire.extend_from_slice(&body);

        assert_eq!(written, wire.len() - start_len);
        assert_eq!(&wire[..start_len], b"prefix");

        let (decoded_salt, frame) = split_salt(&wire[start_len..]).unwrap();
        let mut frame = BytesMut::from(frame);
        let mut decoder = V4FrameDecoder::new(psk, decoded_salt).unwrap();
        let mut header_cipher = [0; V4_HEADER_CIPHER_SIZE];
        header_cipher.copy_from_slice(&frame[..V4_HEADER_CIPHER_SIZE]);
        let header = decoder.decode_header(&mut header_cipher).unwrap();
        let decoded = decoder
            .decode_payload_in_place(header, &mut frame[V4_HEADER_CIPHER_SIZE..])
            .unwrap();

        assert_eq!(decoded, payload);
    }

    #[test]
    fn encodes_zero_chunk() {
        let psk = TEST_PSK;
        let salt = [4u8; 16];
        let mut encoder = V4FrameEncoder::with_salt_and_initial_padding(psk, salt, 8).unwrap();
        let mut wire = BytesMut::new();

        encode_test_frame(&mut encoder, &[], &mut wire);
        let (decoded_salt, frame) = split_salt(&wire).unwrap();
        let mut frame = BytesMut::from(frame);
        let mut decoder = V4FrameDecoder::new(psk, decoded_salt).unwrap();
        let mut header_cipher = [0; V4_HEADER_CIPHER_SIZE];
        header_cipher.copy_from_slice(&frame[..V4_HEADER_CIPHER_SIZE]);
        let header = decoder.decode_header(&mut header_cipher).unwrap();

        assert!(matches!(
            decoder.decode_payload_in_place(header, &mut frame[V4_HEADER_CIPHER_SIZE..]),
            Err(Error::ZeroChunk)
        ));
    }
}

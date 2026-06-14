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
    /// Returns the encrypted body length described by this decoded header.
    ///
    /// # Errors
    ///
    /// Returns an error for the invalid zero-payload-with-padding header shape.
    pub const fn body_len(self) -> Result<usize> {
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
    /// Creates a v4 frame encoder using a random salt and initial padding.
    ///
    /// # Errors
    ///
    /// Returns an error if random generation or key derivation fails.
    pub fn new(psk: &[u8]) -> Result<Self> {
        let mut salt = [0; SALT_SIZE];
        fill_random(&mut salt)?;

        let mut padding_delta = [0u8; 1];
        fill_random(&mut padding_delta)?;
        Self::from_salt_and_initial_padding(
            psk,
            salt,
            V4_INITIAL_PADDING_MIN + usize::from(padding_delta[0]),
        )
    }

    #[cfg(test)]
    pub(crate) fn with_salt_and_initial_padding(
        psk: &[u8],
        salt: [u8; SALT_SIZE],
        initial_padding_len: usize,
    ) -> Result<Self> {
        Self::from_salt_and_initial_padding(psk, salt, initial_padding_len)
    }

    fn from_salt_and_initial_padding(
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

    /// Encodes an empty v4 frame into `head`.
    ///
    /// # Errors
    ///
    /// Returns an error if header encryption fails.
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

    /// Encodes a payload frame using `payload` as the in-place payload buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload length is invalid, the frame would be too
    /// large, or encryption fails.
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

    /// Encodes prefix and payload slices into `out` as one v4 frame.
    ///
    /// # Errors
    ///
    /// Returns an error if the combined payload is empty or too large, or if
    /// encryption fails.
    pub fn encode_payload_parts_into(
        &mut self,
        prefix: &[u8],
        payload: &[u8],
        out: &mut BytesMut,
    ) -> Result<usize> {
        let payload_len = prefix.len() + payload.len();
        let padding_len = self.next_padding_len(payload_len);
        if payload_len == 0 || payload_len > MAX_PACKET_SIZE || padding_len > MAX_PACKET_SIZE {
            return Err(Error::PayloadTooLarge);
        }

        let start_len = out.len();
        let salt_len = if self.salt_sent { 0 } else { SALT_SIZE };
        out.reserve(salt_len + V4_HEADER_CIPHER_SIZE + padding_len + payload_len + AEAD_TAG_SIZE);

        if !self.salt_sent {
            out.extend_from_slice(&self.salt);
            self.salt_sent = true;
        }

        self.write_encrypted_header(padding_len, payload_len, out)?;
        let padding_start = out.len();
        out.resize(padding_start + padding_len, 0);
        out.extend_from_slice(prefix);
        out.extend_from_slice(payload);

        let payload_start = padding_start + padding_len;
        let payload_end = payload_start + payload_len;
        let tag = self
            .crypto
            .encrypt_detached(self.nonce.as_bytes(), &mut out[payload_start..payload_end])?;
        self.nonce.increment();
        out.extend_from_slice(&tag);

        if padding_len > 0 {
            let body = &mut out[padding_start..payload_end + AEAD_TAG_SIZE];
            let (padding, payload_cipher) = body.split_at_mut(padding_len);
            make_v4_padding(padding, payload_cipher)?;
            swap_padding(padding, payload_cipher);
        }

        Ok(out.len() - start_len)
    }

    const fn next_padding_len(&self, payload_len: usize) -> usize {
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
        header[3..5].copy_from_slice(
            &u16::try_from(padding_len)
                .map_err(|_| Error::PayloadTooLarge)?
                .to_be_bytes(),
        );
        header[5..7].copy_from_slice(
            &u16::try_from(payload_len)
                .map_err(|_| Error::PayloadTooLarge)?
                .to_be_bytes(),
        );

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
    /// Creates a v4 frame decoder for a PSK and peer salt.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn new(psk: &[u8], salt: [u8; SALT_SIZE]) -> Result<Self> {
        Ok(Self {
            crypto: Aes128GcmCrypto::from_psk_and_salt(psk, &salt)?,
            nonce: Nonce12::new(),
        })
    }

    /// Decrypts and validates a v4 frame header.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails, the header marker is invalid,
    /// or decoded lengths exceed the protocol maximum.
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

    /// Decrypts a v4 frame body in place.
    ///
    /// # Errors
    ///
    /// Returns an error if the body length does not match the header, the frame
    /// is a malformed zero chunk, or authentication fails.
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

#[cfg(test)]
pub(crate) fn split_salt(frame: &[u8]) -> Result<([u8; SALT_SIZE], &[u8])> {
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

    fill_padding_with_sampled_bits(padding, target_ones);
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

    let ratio = f64_from_usize(payload_ones) / f64_from_usize(payload_zeros);
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
    let target_ones = f64_from_usize(total_bits) * (target_ratio / (target_ratio + 1.0))
        - f64_from_usize(payload_ones);
    floor_f64_with_upper_bound(target_ones, padding_bits)
}

fn fill_padding_with_sampled_bits(padding: &mut [u8], target_ones: usize) {
    let padding_bits = padding.len() * 8;
    debug_assert!(target_ones <= padding_bits);

    if target_ones == 0 {
        padding.fill(0);
        return;
    }

    if target_ones == padding_bits {
        padding.fill(0xff);
        return;
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
    let high = u32::try_from(value >> 32).expect("shifted 53-bit random value fits u32");
    let low = low_u32(value);
    Ok((f64::from(high) * 4_294_967_296.0 + f64::from(low)) / 9_007_199_254_740_992.0)
}

fn floor_f64_with_upper_bound(value: f64, upper: usize) -> Option<usize> {
    if !value.is_finite() || value < 0.0 || value > f64_from_usize(upper) {
        return None;
    }

    let mut lo = 0;
    let mut hi = upper;
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if f64_from_usize(mid) <= value {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    Some(lo)
}

fn f64_from_usize(value: usize) -> f64 {
    f64::from(u32::try_from(value).expect("v4 frame bit count fits u32"))
}

fn low_u32(value: u64) -> u32 {
    let bytes = value.to_le_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[cfg(test)]
mod tests;

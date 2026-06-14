use super::{
    AEAD_TAG_SIZE, Aes128GcmCrypto, BytesMut, Error, MAX_V6_RECORD_PAYLOAD_LEN, Nonce12, Result,
    SALT_SIZE, V6_HEADER_CIPHER_SIZE, V6_HEADER_PLAIN_SIZE, V6Profile, fill_random,
    mix_padding_payload,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct V6DecodedHeader {
    pub padding_len: usize,
    pub payload_len: usize,
}

impl V6DecodedHeader {
    /// Returns the encrypted body length described by this decoded header.
    ///
    /// # Errors
    ///
    /// Returns an error if decoded padding or payload lengths exceed the v6
    /// record payload limit.
    pub const fn body_len(self) -> Result<usize> {
        if self.padding_len > MAX_V6_RECORD_PAYLOAD_LEN
            || self.payload_len > MAX_V6_RECORD_PAYLOAD_LEN
        {
            return Err(Error::PayloadTooLarge);
        }
        Ok(self.padding_len
            + if self.payload_len > 0 {
                self.payload_len + AEAD_TAG_SIZE
            } else {
                0
            })
    }
}

pub struct V6FrameEncoder {
    crypto: Aes128GcmCrypto,
    nonce: Nonce12,
    salt: [u8; SALT_SIZE],
    salt_sent: bool,
    seq: u32,
}

impl V6FrameEncoder {
    /// Creates a v6 frame encoder using a random salt.
    ///
    /// # Errors
    ///
    /// Returns an error if random generation or key derivation fails.
    pub fn new(psk: &[u8]) -> Result<Self> {
        let mut salt = [0; SALT_SIZE];
        fill_random(&mut salt)?;
        Self::from_salt(psk, salt)
    }

    #[cfg(test)]
    pub(crate) fn with_salt(psk: &[u8], salt: [u8; SALT_SIZE]) -> Result<Self> {
        Self::from_salt(psk, salt)
    }

    fn from_salt(psk: &[u8], salt: [u8; SALT_SIZE]) -> Result<Self> {
        let crypto = Aes128GcmCrypto::from_psk_and_salt(psk, &salt)?;
        Ok(Self {
            crypto,
            nonce: Nonce12::new(),
            salt,
            salt_sent: false,
            seq: 0,
        })
    }

    #[must_use]
    pub const fn salt(&self) -> &[u8; SALT_SIZE] {
        &self.salt
    }

    #[must_use]
    pub const fn seq(&self) -> u32 {
        self.seq
    }

    /// Encodes an empty v6 frame into `head`.
    ///
    /// # Errors
    ///
    /// Returns an error if header encryption fails.
    pub fn encode_empty_frame(
        &mut self,
        profile: &V6Profile,
        head: &mut BytesMut,
    ) -> Result<usize> {
        self.encode_payload_in_place(profile, &mut BytesMut::new(), 0, head)
    }

    /// Encodes a payload frame using `payload` as the in-place payload buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload length is invalid, the frame would be too
    /// large, or encryption fails.
    pub fn encode_payload_in_place(
        &mut self,
        profile: &V6Profile,
        payload: &mut BytesMut,
        payload_len: usize,
        head: &mut BytesMut,
    ) -> Result<usize> {
        if payload_len > MAX_V6_RECORD_PAYLOAD_LEN {
            return Err(Error::PayloadTooLarge);
        }
        if payload.len() != payload_len {
            return Err(Error::FrameLengthMismatch);
        }

        let start_len = head.len();
        let first_frame = !self.salt_sent;
        let prefix_len = profile.record_prefix_len(self.seq);
        let padding_len = profile.final_padding_len(self.seq, payload_len, first_frame);
        if padding_len > u16::MAX as usize || payload_len > u16::MAX as usize {
            return Err(Error::PayloadTooLarge);
        }

        head.reserve(
            usize::from(first_frame) * profile.salt_block_len()
                + prefix_len
                + V6_HEADER_CIPHER_SIZE
                + padding_len,
        );
        if first_frame {
            profile.append_salt_block(&self.salt, head);
            self.salt_sent = true;
        }

        let prefix = profile.append_official_fill(self.seq, prefix_len, head);

        let mut header = [0u8; V6_HEADER_PLAIN_SIZE];
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
        let header_tag = self.crypto.encrypt_detached_with_aad(
            self.nonce.as_bytes(),
            &mut header,
            &head[prefix],
        )?;
        self.nonce.increment();
        head.extend_from_slice(&header);
        head.extend_from_slice(&header_tag);

        let padding = profile.append_official_fill(self.seq, padding_len, head);
        let padding = &mut head[padding];

        if payload_len > 0 {
            let payload_tag = self.crypto.encrypt_detached_with_aad(
                self.nonce.as_bytes(),
                &mut payload[..payload_len],
                padding,
            )?;
            self.nonce.increment();
            payload.extend_from_slice(&payload_tag);
            mix_padding_payload(profile, self.seq, padding, payload);
        }

        self.seq = self.seq.wrapping_add(1);
        Ok(head.len() - start_len + payload.len())
    }

    /// Encodes prefix and payload slices into `out` as one v6 frame.
    ///
    /// # Errors
    ///
    /// Returns an error if the combined payload is empty or too large, or if
    /// encryption fails.
    pub fn encode_payload_parts_into(
        &mut self,
        profile: &V6Profile,
        prefix_payload: &[u8],
        payload: &[u8],
        out: &mut BytesMut,
    ) -> Result<usize> {
        let payload_len = prefix_payload.len() + payload.len();
        if payload_len > MAX_V6_RECORD_PAYLOAD_LEN {
            return Err(Error::PayloadTooLarge);
        }

        let start_len = out.len();
        let first_frame = !self.salt_sent;
        let prefix_len = profile.record_prefix_len(self.seq);
        let padding_len = profile.final_padding_len(self.seq, payload_len, first_frame);
        if padding_len > u16::MAX as usize || payload_len > u16::MAX as usize {
            return Err(Error::PayloadTooLarge);
        }

        out.reserve(
            usize::from(first_frame) * profile.salt_block_len()
                + prefix_len
                + V6_HEADER_CIPHER_SIZE
                + padding_len
                + payload_len
                + usize::from(payload_len > 0) * AEAD_TAG_SIZE,
        );
        if first_frame {
            profile.append_salt_block(&self.salt, out);
            self.salt_sent = true;
        }

        let prefix = profile.append_official_fill(self.seq, prefix_len, out);

        let mut header = [0u8; V6_HEADER_PLAIN_SIZE];
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
        let header_tag = self.crypto.encrypt_detached_with_aad(
            self.nonce.as_bytes(),
            &mut header,
            &out[prefix],
        )?;
        self.nonce.increment();
        out.extend_from_slice(&header);
        out.extend_from_slice(&header_tag);

        let padding = profile.append_official_fill(self.seq, padding_len, out);
        let payload_start = out.len();
        out.extend_from_slice(prefix_payload);
        out.extend_from_slice(payload);

        if payload_len > 0 {
            let payload_end = payload_start + payload_len;
            let (before_payload, payload_and_tag) = out.split_at_mut(payload_start);
            let padding_aad = &before_payload[padding.clone()];
            let payload_tag = self.crypto.encrypt_detached_with_aad(
                self.nonce.as_bytes(),
                &mut payload_and_tag[..payload_len],
                padding_aad,
            )?;
            self.nonce.increment();
            out.extend_from_slice(&payload_tag);

            let body = &mut out[padding.start..payload_end + AEAD_TAG_SIZE];
            let padding_len = padding.end - padding.start;
            let (padding, payload_cipher) = body.split_at_mut(padding_len);
            mix_padding_payload(profile, self.seq, padding, payload_cipher);
        }

        self.seq = self.seq.wrapping_add(1);
        Ok(out.len() - start_len)
    }
}

pub struct V6FrameDecoder {
    crypto: Aes128GcmCrypto,
    nonce: Nonce12,
    seq: u32,
}

impl V6FrameDecoder {
    /// Creates a v6 frame decoder for a PSK and peer salt.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn new(psk: &[u8], salt: [u8; SALT_SIZE]) -> Result<Self> {
        Ok(Self {
            crypto: Aes128GcmCrypto::from_psk_and_salt(psk, &salt)?,
            nonce: Nonce12::new(),
            seq: 0,
        })
    }

    #[must_use]
    pub const fn seq(&self) -> u32 {
        self.seq
    }

    #[must_use]
    pub fn next_prefix_len(&self, profile: &V6Profile) -> usize {
        profile.record_prefix_len(self.seq)
    }

    /// Decrypts and validates a v6 frame header using the record prefix as AAD.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails, the header marker is invalid,
    /// or decoded lengths exceed the protocol maximum.
    pub fn decode_header(
        &mut self,
        prefix: &[u8],
        header_cipher: &mut [u8; V6_HEADER_CIPHER_SIZE],
    ) -> Result<V6DecodedHeader> {
        let decrypt_result =
            self.crypto
                .decrypt_within_with_aad(self.nonce.as_bytes(), header_cipher, 0.., prefix);
        self.nonce.increment();
        let header = decrypt_result?;

        if header[0] != 4 || header[1] != 0 || header[2] != 0 {
            return Err(Error::InvalidV4Header);
        }

        let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
        if padding_len > MAX_V6_RECORD_PAYLOAD_LEN || payload_len > MAX_V6_RECORD_PAYLOAD_LEN {
            return Err(Error::PayloadTooLarge);
        }
        Ok(V6DecodedHeader {
            padding_len,
            payload_len,
        })
    }

    /// Decrypts a v6 frame body in place.
    ///
    /// # Errors
    ///
    /// Returns an error if the body length does not match the header, the frame
    /// is malformed, or authentication fails.
    pub fn decode_payload_in_place<'a>(
        &mut self,
        profile: &V6Profile,
        header: V6DecodedHeader,
        body: &'a mut [u8],
    ) -> Result<&'a mut [u8]> {
        let expected_body_len = header.body_len()?;
        if body.len() != expected_body_len {
            return Err(Error::FrameLengthMismatch);
        }

        if header.payload_len == 0 {
            self.seq = self.seq.wrapping_add(1);
            return Err(Error::ZeroChunk);
        }

        let (padding, payload_cipher_and_tag) = body.split_at_mut(header.padding_len);
        mix_padding_payload(profile, self.seq, padding, payload_cipher_and_tag);
        let decrypt_result = self.crypto.decrypt_within_with_aad(
            self.nonce.as_bytes(),
            payload_cipher_and_tag,
            0..,
            padding,
        );
        self.nonce.increment();
        let payload = decrypt_result?;
        self.seq = self.seq.wrapping_add(1);

        Ok(payload)
    }
}

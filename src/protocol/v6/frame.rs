use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct V6DecodedHeader {
    pub padding_len: usize,
    pub payload_len: usize,
}

impl V6DecodedHeader {
    pub fn body_len(self) -> Result<usize> {
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
    profile: V6Profile,
    crypto: Aes128GcmCrypto,
    nonce: Nonce12,
    salt: [u8; SALT_SIZE],
    salt_sent: bool,
    seq: u32,
}

impl V6FrameEncoder {
    pub fn new(psk: &[u8]) -> Result<Self> {
        let mut salt = [0; SALT_SIZE];
        fill_random(&mut salt)?;
        Self::with_salt(psk, salt)
    }

    #[doc(hidden)]
    pub fn with_salt(psk: &[u8], salt: [u8; SALT_SIZE]) -> Result<Self> {
        let profile = V6Profile::derive(psk);
        let crypto = Aes128GcmCrypto::from_psk_and_salt(psk, &salt)?;
        Ok(Self {
            profile,
            crypto,
            nonce: Nonce12::new(),
            salt,
            salt_sent: false,
            seq: 0,
        })
    }

    pub const fn salt(&self) -> &[u8; SALT_SIZE] {
        &self.salt
    }

    pub const fn profile(&self) -> &V6Profile {
        &self.profile
    }

    pub const fn seq(&self) -> u32 {
        self.seq
    }

    pub fn encode_empty_frame(&mut self, head: &mut BytesMut) -> Result<usize> {
        self.encode_payload_in_place(&mut BytesMut::new(), 0, head)
    }

    pub fn encode_payload_in_place(
        &mut self,
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
        let prefix_len = self.profile.record_prefix_len(self.seq);
        let padding_len = self
            .profile
            .final_padding_len(self.seq, payload_len, first_frame);
        if padding_len > u16::MAX as usize || payload_len > u16::MAX as usize {
            return Err(Error::PayloadTooLarge);
        }

        head.reserve(
            usize::from(first_frame) * self.profile.salt_block_len()
                + prefix_len
                + V6_HEADER_CIPHER_SIZE
                + padding_len,
        );
        if first_frame {
            self.profile.append_salt_block(&self.salt, head);
            self.salt_sent = true;
        }

        let prefix = self
            .profile
            .append_official_fill(self.seq, prefix_len, head);

        let mut header = [0u8; V6_HEADER_PLAIN_SIZE];
        header[0] = 4;
        header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
        header[5..7].copy_from_slice(&(payload_len as u16).to_be_bytes());
        let header_tag = self.crypto.encrypt_detached_with_aad(
            self.nonce.as_bytes(),
            &mut header,
            &head[prefix],
        )?;
        self.nonce.increment();
        head.extend_from_slice(&header);
        head.extend_from_slice(&header_tag);

        let padding = self
            .profile
            .append_official_fill(self.seq, padding_len, head);
        let padding = &mut head[padding];

        if payload_len > 0 {
            let payload_tag = self.crypto.encrypt_detached_with_aad(
                self.nonce.as_bytes(),
                &mut payload[..payload_len],
                padding,
            )?;
            self.nonce.increment();
            payload.extend_from_slice(&payload_tag);
            mix_padding_payload(&self.profile, self.seq, padding, payload);
        }

        self.seq = self.seq.wrapping_add(1);
        Ok(head.len() - start_len + payload.len())
    }
}

pub struct V6FrameDecoder {
    profile: V6Profile,
    crypto: Aes128GcmCrypto,
    nonce: Nonce12,
    seq: u32,
}

impl V6FrameDecoder {
    pub fn new(psk: &[u8], salt: [u8; SALT_SIZE]) -> Result<Self> {
        let profile = V6Profile::derive(psk);
        Ok(Self {
            profile,
            crypto: Aes128GcmCrypto::from_psk_and_salt(psk, &salt)?,
            nonce: Nonce12::new(),
            seq: 0,
        })
    }

    pub const fn profile(&self) -> &V6Profile {
        &self.profile
    }

    pub const fn seq(&self) -> u32 {
        self.seq
    }

    pub fn next_prefix_len(&self) -> usize {
        self.profile.record_prefix_len(self.seq)
    }

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

    pub fn decode_payload_in_place<'a>(
        &mut self,
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
        mix_padding_payload(&self.profile, self.seq, padding, payload_cipher_and_tag);
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

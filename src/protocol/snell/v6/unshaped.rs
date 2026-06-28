//! V6 unshaped codec: AEAD-protected frames without traffic shaping.
//!
//! Same framing and KDF (HKDF → AES-128-GCM) as V4, but:
//! - **No padding** — `padding_len` is forced to zero.
//! - **No congestion window** — the encoder writes up to [`MAX_PACKET_SIZE`] per record.
//! - First record carries a 16-byte salt; subsequent records are header+body only.
//!
//! # Wire layout
//!
//! ```text
//!   first record:   SALT(16) | HEADER_CIPHER(23) | BODY?
//!   subsequent:               HEADER_CIPHER(23) | BODY?
//!
//!   HEADER_CIPHER = HEADER_PLAIN(7) || TAG(16)
//!   HEADER_PLAIN  = [4][0][0][0][0][PAYLOAD_HI][PAYLOAD_LO]
//!   BODY          = PAYLOAD_CIPHER || TAG          (payload_len > 0)
//!                 = (omitted)                      (payload_len == 0, zero chunk)
//!
//!   AEAD AAD = empty (no associated data)
//!   max payload per record = MAX_PACKET_SIZE (0x3fff)
//! ```
//!
//! # Encode / Decode flow
//!
//! Same as V4 minus padding interleave and congestion window:
//! - Encoder: `seal_plain(SnellBuffer) → SnellWire`
//! - Decoder: `Salt → Header (decrypt) → Body (swap_padding is a no-op) → plaintext`

use std::{fmt, io, sync::Arc};

use bytes::{Bytes, BytesMut};
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Tag};

use super::super::{
    DecodeEvent, DecodedHeader, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN, MAX_PACKET_SIZE, NONCE_LEN,
    SALT_LEN, SnellBuffer, SnellTcpDecoder, SnellTcpEncoder, SnellWire,
    common::{
        ReadStep, decode_v6_unshaped_header, invalid_data, invalid_input, next_nonce, seal_header,
        seal_payload_detached, v6_key, write_v6_plain_header,
    },
};

/// V6 unshaped encoder — AEAD frames, no shaping.
///
/// Holds the session key derived from the salt and a monotonic nonce. The first
/// record carries a random salt; subsequent records are header + body only.
pub struct V6UnshapedEncoder {
    key: LessSafeKey,
    nonce: [u8; NONCE_LEN],
    salt: [u8; SALT_LEN],
    salt_sent: bool,
}

impl fmt::Debug for V6UnshapedEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6UnshapedEncoder")
            .field("salt_sent", &self.salt_sent)
            .finish()
    }
}

/// V6 unshaped decoder — AEAD frames, no shaping.
///
/// The PSK is kept (cloned) so the session key can be derived lazily once the
/// peer's salt arrives. `read_step` drives the salt → header → body state machine.
#[derive(Debug)]
pub struct V6UnshapedDecoder {
    psk: Arc<[u8]>,
    key: Option<LessSafeKey>,
    nonce: [u8; NONCE_LEN],
    read_step: ReadStep,
    buf: BytesMut,
    plain: SnellBuffer,
}

impl V6UnshapedEncoder {
    /// Create an encoder with a random salt.
    pub fn new(psk: &[u8]) -> io::Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        Self::with_salt(psk, salt)
    }

    fn with_salt(psk: &[u8], salt: [u8; SALT_LEN]) -> io::Result<Self> {
        Ok(Self {
            key: v6_key(psk, &salt)?,
            nonce: [0; NONCE_LEN],
            salt,
            salt_sent: false,
        })
    }

    fn seal_payload(&mut self, mut payload: SnellBuffer) -> io::Result<SnellWire> {
        let payload_len = payload.len();
        if payload_len > MAX_PACKET_SIZE {
            return Err(invalid_input("snell payload exceeds record capacity"));
        }
        let first_record = !self.salt_sent;

        // head segment: [salt?][header_cipher]
        let mut head =
            BytesMut::with_capacity((first_record as usize) * SALT_LEN + HEADER_CIPHER_LEN);
        if first_record {
            head.extend_from_slice(&self.salt);
        }
        let header_start = head.len();
        head.resize(header_start + HEADER_CIPHER_LEN, 0);
        write_v6_plain_header(
            &mut head[header_start..header_start + HEADER_PLAIN_LEN],
            0,
            payload_len,
        )?;
        seal_header(
            &self.key,
            &mut self.nonce,
            &[],
            &mut head[header_start..header_start + HEADER_CIPHER_LEN],
            "snell v6 unshaped header encrypt failed",
        )?;

        let mut wire =
            SnellWire::with_capacity(1 + (payload_len > 0) as usize + (payload_len > 0) as usize);
        wire.push_bytes(head.freeze());

        if payload_len > 0 {
            // payload_cipher is the caller's buffer, encrypted in place.
            let tag = seal_payload_detached(
                &self.key,
                &mut self.nonce,
                &[],
                payload.as_mut_slice(),
                "snell v6 unshaped payload encrypt failed",
            )?;
            wire.push_buffer(payload);
            wire.push_bytes(Bytes::from(tag.to_vec()));
        }

        self.salt_sent = true;
        Ok(wire)
    }
}

impl V6UnshapedDecoder {
    /// Create a decoder holding the PSK; the session key is derived lazily.
    pub fn new(psk: impl Into<Arc<[u8]>>) -> Self {
        Self {
            psk: psk.into(),
            key: None,
            nonce: [0; NONCE_LEN],
            read_step: ReadStep::Salt { filled: 0 },
            buf: BytesMut::new(),
            plain: SnellBuffer::empty(),
        }
    }

    /// Seed the session key from the peer's salt: `key = HKDF(psk, salt)`.
    fn init_salt(&mut self, salt: [u8; SALT_LEN]) -> io::Result<()> {
        self.key = Some(v6_key(&self.psk, &salt)?);
        Ok(())
    }

    /// Decrypt the header currently buffered in `read_buf`.
    ///
    /// Steps: `AEAD open(HEADER_PLAIN, TAG, nonce++, AAD empty)`.
    fn decode_header_in_place(&mut self, header_cipher: &mut [u8]) -> io::Result<DecodedHeader> {
        let nonce = next_nonce(&mut self.nonce);
        let (cipher, tag) = header_cipher.split_at_mut(HEADER_PLAIN_LEN);
        let tag = Tag::try_from(&tag[..]).map_err(|_| invalid_data("snell v6 invalid tag"))?;
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| invalid_data("snell v6 unshaped reader key not initialized"))?;
        let header = key
            .open_in_place_separate_tag(nonce, Aad::empty(), tag, cipher, 0..)
            .map_err(|_| invalid_data("snell v6 unshaped header decrypt failed"))?;
        decode_v6_unshaped_header(header)
    }

    /// Decrypt the body, copying plaintext into the `self.plain` range.
    ///
    /// Steps: `AEAD open(payload_cipher, tag, nonce++)`, no padding to swap.
    fn finish_body(&mut self, mut body: SnellBuffer, header: DecodedHeader) -> io::Result<bool> {
        self.plain = SnellBuffer::empty();
        if header.payload_len == 0 {
            return Ok(false);
        }

        let key = self
            .key
            .as_ref()
            .ok_or_else(|| invalid_data("snell v6 unshaped reader key not initialized"))?;
        if body.len() != header.body_len {
            return Err(invalid_data("snell v6 unshaped body length mismatch"));
        }
        let (payload_cipher, tag) = body.as_mut_slice().split_at_mut(header.payload_len);
        let tag = Tag::try_from(&tag[..]).map_err(|_| invalid_data("snell v6 invalid tag"))?;
        let nonce = next_nonce(&mut self.nonce);
        key.open_in_place_separate_tag(nonce, Aad::empty(), tag, payload_cipher, 0..)
            .map_err(|_| invalid_data("snell v6 unshaped payload decrypt failed"))?;
        body.truncate(header.payload_len);
        self.plain = body;
        Ok(true)
    }

    /// Borrow the decrypted plaintext region from the current record.
    pub fn pending_plain(&self) -> &[u8] {
        self.plain.as_slice()
    }

    /// Mark `n` bytes from [`V6UnshapedDecoder::pending_plain`] as consumed.
    pub fn consume_plain(&mut self, n: usize) {
        let n = n.min(self.plain.len());
        self.plain.advance(n);
        if self.plain.is_empty() {
            self.plain = SnellBuffer::empty();
        }
    }

    fn try_drain(&mut self) -> io::Result<DecodeEvent<'_>> {
        if !self.pending_plain().is_empty() {
            return Ok(DecodeEvent::PlainData);
        }

        loop {
            match self.read_step {
                ReadStep::Salt { .. } => {
                    if self.buf.len() < SALT_LEN {
                        self.read_step = ReadStep::Salt {
                            filled: self.buf.len(),
                        };
                        return Ok(DecodeEvent::NeedMore);
                    }
                    let salt_bytes = self.buf.split_to(SALT_LEN);
                    let salt: [u8; SALT_LEN] =
                        salt_bytes[..].try_into().expect("salt buffer filled");
                    self.init_salt(salt)?;
                    self.read_step = ReadStep::Header { filled: 0 };
                }
                ReadStep::Header { .. } => {
                    if self.buf.len() < HEADER_CIPHER_LEN {
                        self.read_step = ReadStep::Header {
                            filled: self.buf.len(),
                        };
                        return Ok(DecodeEvent::NeedMore);
                    }
                    let mut header_cipher = self.buf.split_to(HEADER_CIPHER_LEN);
                    let header = self.decode_header_in_place(&mut header_cipher)?;
                    if header.body_len == 0 {
                        self.read_step = ReadStep::Header { filled: 0 };
                        return if self.finish_body(SnellBuffer::empty(), header)? {
                            Ok(DecodeEvent::PlainData)
                        } else {
                            Ok(DecodeEvent::ZeroChunk)
                        };
                    }
                    self.read_step = ReadStep::Body { header, filled: 0 };
                }
                ReadStep::Body { header, .. } => {
                    if self.buf.len() < header.body_len {
                        self.read_step = ReadStep::Body {
                            header,
                            filled: self.buf.len(),
                        };
                        return Ok(DecodeEvent::NeedMore);
                    }
                    let body = self.buf.split_to(header.body_len);
                    self.read_step = ReadStep::Header { filled: 0 };
                    return if self.finish_body(SnellBuffer::from(body), header)? {
                        Ok(DecodeEvent::PlainData)
                    } else {
                        Ok(DecodeEvent::ZeroChunk)
                    };
                }
            }
        }
    }

    fn try_feed_direct(
        &mut self,
        mut chunk: SnellBuffer,
    ) -> io::Result<Result<DecodeEvent<'static>, SnellBuffer>> {
        if !self.buf.is_empty() || !self.plain.is_empty() {
            return Ok(Err(chunk));
        }

        match self.read_step {
            ReadStep::Salt { filled: 0 } if chunk.len() == SALT_LEN => {
                let salt: [u8; SALT_LEN] = chunk.as_slice().try_into().expect("salt buffer filled");
                self.init_salt(salt)?;
                self.read_step = ReadStep::Header { filled: 0 };
                Ok(Ok(DecodeEvent::NeedMore))
            }
            ReadStep::Header { filled: 0 } if chunk.len() == HEADER_CIPHER_LEN => {
                let header = self.decode_header_in_place(chunk.as_mut_slice())?;
                if header.body_len == 0 {
                    self.read_step = ReadStep::Header { filled: 0 };
                    return if self.finish_body(SnellBuffer::empty(), header)? {
                        Ok(Ok(DecodeEvent::PlainData))
                    } else {
                        Ok(Ok(DecodeEvent::ZeroChunk))
                    };
                }
                self.read_step = ReadStep::Body { header, filled: 0 };
                Ok(Ok(DecodeEvent::NeedMore))
            }
            ReadStep::Body { header, filled: 0 } if chunk.len() == header.body_len => {
                self.read_step = ReadStep::Header { filled: 0 };
                if self.finish_body(chunk, header)? {
                    Ok(Ok(DecodeEvent::PlainData))
                } else {
                    Ok(Ok(DecodeEvent::ZeroChunk))
                }
            }
            _ => Ok(Err(chunk)),
        }
    }
}

impl SnellTcpEncoder for V6UnshapedEncoder {
    fn next_plain_capacity(&self) -> usize {
        MAX_PACKET_SIZE
    }

    fn seal_plain(&mut self, payload: SnellBuffer) -> io::Result<SnellWire> {
        self.seal_payload(payload)
    }
}

impl SnellTcpDecoder for V6UnshapedDecoder {
    fn next_ciphertext_read_len(&self) -> usize {
        if !self.plain.is_empty() {
            return 0;
        }
        match self.read_step {
            ReadStep::Salt { filled } => SALT_LEN.saturating_sub(filled),
            ReadStep::Header { filled } => HEADER_CIPHER_LEN.saturating_sub(filled),
            ReadStep::Body { header, filled } => header.body_len.saturating_sub(filled),
        }
    }

    fn feed_owned(&mut self, chunk: SnellBuffer) -> io::Result<DecodeEvent<'_>> {
        let chunk = match self.try_feed_direct(chunk)? {
            Ok(event) => return Ok(event),
            Err(chunk) => chunk,
        };
        let chunk = chunk.into_bytes_mut();
        if self.buf.is_empty() {
            self.buf = chunk;
        } else if !chunk.is_empty() {
            self.buf.extend_from_slice(&chunk);
        }
        self.try_drain()
    }

    fn pending_plain(&self) -> &[u8] {
        V6UnshapedDecoder::pending_plain(self)
    }

    fn consume_plain(&mut self, n: usize) {
        V6UnshapedDecoder::consume_plain(self, n);
    }

    fn take_plain(&mut self) -> SnellBuffer {
        std::mem::replace(&mut self.plain, SnellBuffer::empty())
    }
}

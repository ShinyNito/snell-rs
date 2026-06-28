//! V6 shaped codec: profile-driven AEAD transport with traffic shaping.
//!
//! The most sophisticated Snell transport mode. A [`Profile`] derived from the
//! PSK governs:
//! - **Salt block**: a profile-sized region that hides the 16-byte salt among
//!   obfuscation bytes.
//! - **Per-record prefix**: a deterministic (but profile-determined) prefix
//!   placed before each AEAD header.
//! - **Padding**: profile-determined padding length, filled with official-looking
//!   bytes and used as AAD for payload AEAD.
//! - **Chunk size**: a dynamic limit that grows/shrinks per the profile,
//!   emulating a congestion window.
//!
//! # Wire layout
//!
//! ```text
//!   first record:
//!     SALT_BLOCK(sb_len) | PREFIX(plen) | HEADER_CIPHER | PADDING | PAYLOAD_CIPHER + TAG
//!
//!   subsequent:
//!     PREFIX(plen) | HEADER_CIPHER | PADDING | PAYLOAD_CIPHER + TAG
//!
//!   HEADER_CIPHER  = HEADER_PLAIN(7) || TAG(16)
//!   AEAD AAD for header = PREFIX bytes
//!   AEAD AAD for payload = PADDING bytes
//! ```
//!
//! # Encode flow
//!
//! ```text
//!   next_plain_capacity()
//!      |  profile-driven chunk_size
//!      v
//!   seal_plain(SnellBuffer, SnellWire)
//!      |  write_v6_plain_header(padding_len, payload_len)
//!      |  seal header   (nonce++, AAD = prefix)
//!      |  fill padding  (profile.fill_official)
//!      |  seal payload  (nonce++, AAD = padding) -> detached TAG
//!      |  mix_padding_payload (bit-interleave)
//!      v
//!   reusable SnellWire -> vectored flush
//! ```
//!
//! # Decode flow (state machine)
//!
//! ```text
//!   SaltBlock(sb_len) --extract salt, derive key--> Header
//!        |
//!        v
//!   Header(prefix_len + HEADER_CIPHER_LEN)
//!        |  AEAD open(HEADER_PLAIN, TAG, nonce, AAD=prefix)
//!        v
//!   DecodedHeader -> body_len == 0 ? emit event : Body
//!        |
//!        v
//!   Body(body_len)
//!        |  mix_padding_payload (undo interleave)
//!        |  AEAD open(payload, TAG, nonce++, AAD=padding)
//!        v
//!   emit PlainData -> Header (next seq)
//! ```

use std::{fmt, io, rc::Rc, sync::Arc, time::Instant};

use aws_lc_rs::aead::LessSafeKey;
use rand::RngCore;

use super::super::{
    DecodeEvent, DecodedHeader, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN, MAX_PACKET_SIZE_V6, NONCE_LEN,
    SALT_LEN, SnellBuffer, SnellTcpDecoder, SnellTcpEncoder, SnellWire,
    common::{
        current_nonce, decode_v6_shaped_header, increment_nonce, invalid_data, invalid_input,
        next_nonce, open_header, open_payload, seal_header, seal_payload, v6_key,
        write_v6_plain_header,
    },
    profile::{Profile, mix_padding_payload, mix_padding_payload_split},
};

/// V6 shaped encoder — profile-driven obfuscation and shaping.
///
/// Session key derived via Argon2id. The [`Profile`] controls salt block size,
/// prefix length, padding length, and chunk size for each record sequence
/// number.
pub struct V6ShapedEncoder {
    key: LessSafeKey,
    nonce: [u8; NONCE_LEN],
    salt: [u8; SALT_LEN],
    salt_sent: bool,
    seq: u32,
    profile: Rc<Profile>,
    chunk_size: usize,
    last_write: Option<Instant>,
}

impl fmt::Debug for V6ShapedEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6ShapedEncoder")
            .field("salt_sent", &self.salt_sent)
            .field("seq", &self.seq)
            .field("chunk_size", &self.chunk_size)
            .finish()
    }
}

/// V6 shaped decoder — profile-driven obfuscation and shaping.
///
/// The decoder derives the [`Profile`] from the PSK at construction time and
/// uses it to extract the salt from the salt block, determine per-record prefix
/// lengths, and undo the padding interleave.
#[derive(Debug)]
pub struct V6ShapedDecoder {
    psk: Arc<[u8]>,
    profile: Rc<Profile>,
    key: Option<LessSafeKey>,
    nonce: [u8; NONCE_LEN],
    seq: u32,
    read_step: ShapedReadStep,
    plain: SnellBuffer,
}

/// Decoder state machine arms for the shaped variant.
#[derive(Clone, Copy, Debug)]
enum ShapedReadStep {
    /// Reading the profile-sized salt block.
    Salt,
    /// Reading the per-record prefix + AEAD header.
    Header { prefix_len: usize },
    /// Reading the frame body (padding + ciphertext payload + tag).
    Body { header: DecodedHeader },
}

impl V6ShapedEncoder {
    /// Create an encoder with a random salt and a profile derived from the PSK.
    pub fn new(psk: &[u8]) -> io::Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        Self::with_salt_and_profile(psk, salt, Rc::new(Profile::derive(psk)))
    }

    fn with_salt_and_profile(
        psk: &[u8],
        salt: [u8; SALT_LEN],
        profile: Rc<Profile>,
    ) -> io::Result<Self> {
        Ok(Self {
            key: v6_key(psk, &salt)?,
            nonce: [0; NONCE_LEN],
            salt,
            salt_sent: false,
            seq: 0,
            profile,
            chunk_size: 0,
            last_write: None,
        })
    }

    fn seal_payload(&mut self, mut payload: SnellBuffer, wire: &mut SnellWire) -> io::Result<()> {
        wire.clear();
        let now = Instant::now();
        let base_chunk_size = self.base_chunk_size(now);
        let max_payload_len = self.chunk_limit_for(base_chunk_size);
        let payload_len = payload.len();
        if payload_len > max_payload_len {
            return Err(invalid_input("snell payload exceeds record capacity"));
        }

        let first_record = !self.salt_sent;
        let salt_block_len = if first_record {
            self.profile.salt_block_len()
        } else {
            0
        };
        let prefix_len = self.profile.record_prefix_len(self.seq);
        let prefix_start = salt_block_len;
        let header_start = prefix_start + prefix_len;
        let padding_len =
            self.profile
                .final_padding_len(self.seq, prefix_len, payload_len, first_record);

        // head segment: [salt_block?][prefix][header_cipher]
        let head_len = salt_block_len + prefix_len + HEADER_CIPHER_LEN;
        {
            let head = wire.push_head_zeroed(head_len);
            if first_record {
                self.profile
                    .write_salt_block(&self.salt, &mut head[..salt_block_len])
                    .map_err(|_| invalid_data("snell v6 shaped salt block failed"))?;
            }
            self.profile
                .fill_official(self.seq, &mut head[prefix_start..prefix_start + prefix_len]);

            write_v6_plain_header(
                &mut head[header_start..header_start + HEADER_PLAIN_LEN],
                padding_len,
                payload_len,
            )?;
            {
                let (before_header, header_and_after) = head.split_at_mut(header_start);
                seal_header(
                    &self.key,
                    &mut self.nonce,
                    &before_header[prefix_start..prefix_start + prefix_len],
                    &mut header_and_after[..HEADER_CIPHER_LEN],
                    "snell v6 shaped header encrypt failed",
                )?;
            }
        }

        // padding segment (independent of payload so the payload buffer can stay
        // the caller's, encrypted in place).
        if payload_len > 0 {
            let (padding, payload_tag) = wire.prepare_padding_and_tag(padding_len);
            self.profile.fill_official(self.seq, &mut *padding);

            // payload_cipher is the caller's buffer, encrypted in place.
            seal_payload(
                &self.key,
                &mut self.nonce,
                &*padding,
                payload.as_mut_slice(),
                payload_tag,
                "snell v6 shaped payload encrypt failed",
            )?;
            mix_padding_payload_split(
                &self.profile,
                self.seq,
                &mut *padding,
                payload.as_mut_slice(),
                payload_tag,
            );
        } else {
            let padding = wire.prepare_padding(padding_len);
            self.profile.fill_official(self.seq, &mut *padding);
        }

        if padding_len > 0 {
            wire.push_padding();
        }
        if payload_len > 0 {
            wire.push_buffer(payload);
            wire.push_tag();
        }

        self.salt_sent = true;
        self.chunk_size = self.profile.advance_chunk_size(base_chunk_size, None);
        self.last_write = Some(now);
        self.seq = self.seq.wrapping_add(1);
        Ok(())
    }

    fn base_chunk_size(&self, now: Instant) -> usize {
        let idle = self.last_write.map(|last| now.duration_since(last));
        if self.chunk_size == 0 || idle.is_some_and(|idle| idle > self.profile.idle_reset()) {
            self.profile.chunk_initial()
        } else {
            self.chunk_size
        }
    }

    fn chunk_limit_for(&self, chunk_size: usize) -> usize {
        let mut limit = self
            .profile
            .chunk_limit(self.seq, chunk_size, None)
            .min(MAX_PACKET_SIZE_V6);
        if self.seq == 0 {
            limit = limit.min(self.profile.first_record_cap());
        }
        limit
    }

    fn plain_capacity(&self) -> usize {
        self.chunk_limit_for(self.base_chunk_size(Instant::now()))
    }
}

impl V6ShapedDecoder {
    /// Create a decoder that derives its [`Profile`] from the PSK at construction.
    ///
    /// The session key is derived lazily after reading the salt block.
    pub fn new(psk: impl Into<Arc<[u8]>>) -> Self {
        let psk = psk.into();
        Self {
            profile: Rc::new(Profile::derive(&psk)),
            psk,
            key: None,
            nonce: [0; NONCE_LEN],
            seq: 0,
            read_step: ShapedReadStep::Salt,
            plain: SnellBuffer::empty(),
        }
    }

    /// Extract the salt from the profile's `salt_block_len` bytes and derive
    /// the session key.
    fn init_salt_block(&mut self, salt_block: &[u8]) -> io::Result<()> {
        let salt = self
            .profile
            .extract_salt(salt_block)
            .map_err(|_| invalid_data("snell v6 shaped salt block failed"))?;
        self.key = Some(v6_key(&self.psk, &salt)?);
        Ok(())
    }

    /// Per-record prefix length for the current sequence number.
    fn next_prefix_len(&self) -> usize {
        self.profile.record_prefix_len(self.seq)
    }

    /// Decrypt an exact prefix + header chunk in place, using the prefix as AAD.
    ///
    /// Layout: `header_buf = [PREFIX(plen) | HEADER_CIPHER(23)]`.
    fn decode_header_in_place(
        &mut self,
        prefix_len: usize,
        header_buf: &mut [u8],
    ) -> io::Result<DecodedHeader> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| invalid_data("snell v6 shaped reader key not initialized"))?;
        let (prefix, header_cipher) = header_buf.split_at_mut(prefix_len);
        let header = open_header(
            key,
            current_nonce(&self.nonce),
            &*prefix,
            header_cipher,
            "snell v6 shaped header decrypt failed",
        )?;
        decode_v6_shaped_header(header)
    }

    /// Decrypt the body, undoing the padding interleave.
    ///
    /// Steps:
    /// ```text
    ///   1. increment_nonce (header used the previous nonce)
    ///   2. mix_padding_payload(padding, payload_cipher_and_tag) — undo interleave
    ///   3. AEAD open(payload_cipher, tag, nonce++, AAD = padding)
    ///   4. self.plain = padding_len .. padding_len + payload_len
    ///   5. seq++
    /// ```
    fn finish_body(&mut self, mut body: SnellBuffer, header: DecodedHeader) -> io::Result<bool> {
        self.plain = SnellBuffer::empty();
        increment_nonce(&mut self.nonce);
        if header.payload_len == 0 {
            self.seq = self.seq.wrapping_add(1);
            return Ok(false);
        }

        let seq = self.seq;
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| invalid_data("snell v6 shaped reader key not initialized"))?;
        if body.len() != header.body_len {
            return Err(invalid_data("snell v6 shaped body length mismatch"));
        }
        let (padding, payload_cipher_and_tag) =
            body.as_mut_slice().split_at_mut(header.padding_len);
        mix_padding_payload(&self.profile, seq, padding, payload_cipher_and_tag);
        let (payload_cipher, tag) = payload_cipher_and_tag.split_at_mut(header.payload_len);
        let nonce = next_nonce(&mut self.nonce);
        open_payload(
            key,
            nonce,
            &*padding,
            payload_cipher,
            tag,
            "snell v6 shaped payload decrypt failed",
        )?;
        body.advance(header.padding_len);
        body.truncate(header.payload_len);
        self.plain = body;
        self.seq = self.seq.wrapping_add(1);
        Ok(true)
    }

    /// Borrow the decrypted plaintext region from the current record.
    pub fn pending_plain(&self) -> &[u8] {
        self.plain.as_slice()
    }

    /// Mark `n` bytes from [`V6ShapedDecoder::pending_plain`] as consumed.
    pub fn consume_plain(&mut self, n: usize) {
        let n = n.min(self.plain.len());
        self.plain.advance(n);
        if self.plain.is_empty() {
            self.plain = SnellBuffer::empty();
        }
    }

    fn exact_chunk_mismatch(&self) -> io::Error {
        invalid_input(match self.read_step {
            ShapedReadStep::Salt => "snell v6 shaped salt chunk length mismatch",
            ShapedReadStep::Header { .. } => "snell v6 shaped header chunk length mismatch",
            ShapedReadStep::Body { .. } => "snell v6 shaped body chunk length mismatch",
        })
    }
}

impl SnellTcpEncoder for V6ShapedEncoder {
    fn next_plain_capacity(&self) -> usize {
        self.plain_capacity()
    }

    fn seal_plain(&mut self, payload: SnellBuffer, wire: &mut SnellWire) -> io::Result<()> {
        self.seal_payload(payload, wire)
    }
}

impl SnellTcpDecoder for V6ShapedDecoder {
    fn next_ciphertext_read_len(&self) -> usize {
        if !self.plain.is_empty() {
            return 0;
        }
        match self.read_step {
            ShapedReadStep::Salt => self.profile.salt_block_len(),
            ShapedReadStep::Header { prefix_len } => prefix_len + HEADER_CIPHER_LEN,
            ShapedReadStep::Body { header } => header.body_len,
        }
    }

    fn feed_owned(&mut self, chunk: SnellBuffer) -> io::Result<DecodeEvent<'_>> {
        if !self.pending_plain().is_empty() {
            if chunk.is_empty() {
                return Ok(DecodeEvent::PlainData);
            }
            return Err(self.exact_chunk_mismatch());
        }

        let expected = self.next_ciphertext_read_len();
        if chunk.len() != expected {
            return Err(self.exact_chunk_mismatch());
        }

        match self.read_step {
            ShapedReadStep::Salt => {
                self.init_salt_block(chunk.as_slice())?;
                self.read_step = ShapedReadStep::Header {
                    prefix_len: self.next_prefix_len(),
                };
                Ok(DecodeEvent::NeedMore)
            }
            ShapedReadStep::Header { prefix_len } => {
                let mut chunk = chunk;
                let header = self.decode_header_in_place(prefix_len, chunk.as_mut_slice())?;
                if header.body_len == 0 {
                    let event = if self.finish_body(SnellBuffer::empty(), header)? {
                        DecodeEvent::PlainData
                    } else {
                        DecodeEvent::ZeroChunk
                    };
                    self.read_step = ShapedReadStep::Header {
                        prefix_len: self.next_prefix_len(),
                    };
                    Ok(event)
                } else {
                    self.read_step = ShapedReadStep::Body { header };
                    Ok(DecodeEvent::NeedMore)
                }
            }
            ShapedReadStep::Body { header } => {
                let event = if self.finish_body(chunk, header)? {
                    DecodeEvent::PlainData
                } else {
                    DecodeEvent::ZeroChunk
                };
                self.read_step = ShapedReadStep::Header {
                    prefix_len: self.next_prefix_len(),
                };
                Ok(event)
            }
        }
    }

    fn pending_plain(&self) -> &[u8] {
        V6ShapedDecoder::pending_plain(self)
    }

    fn consume_plain(&mut self, n: usize) {
        V6ShapedDecoder::consume_plain(self, n);
    }

    fn take_plain(&mut self) -> SnellBuffer {
        std::mem::replace(&mut self.plain, SnellBuffer::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    const PSK: &[u8] = b"0123456789abcdef";

    fn flatten_wire(wire: SnellWire) -> Vec<u8> {
        let mut out = Vec::new();
        for s in wire.into_bytes_vec() {
            out.extend_from_slice(&s);
        }
        out
    }

    fn flatten_sealed(encoder: &mut V6ShapedEncoder, payload: SnellBuffer) -> Vec<u8> {
        let mut wire = SnellWire::new();
        encoder.seal_plain(payload, &mut wire).unwrap();
        flatten_wire(wire)
    }

    #[test]
    fn owned_payload_round_trips() {
        let mut encoder = V6ShapedEncoder::new(PSK).unwrap();
        let payload = b"owned shaped payload";
        let wire = flatten_sealed(
            &mut encoder,
            SnellBuffer::from(BytesMut::from(&payload[..])),
        );

        let mut decoder = V6ShapedDecoder::new(Arc::<[u8]>::from(PSK));
        let mut src = wire.as_slice();
        assert_eq!(
            decode_until_record(&mut decoder, &mut src),
            DecodeEvent::PlainData
        );
        assert_eq!(decoder.pending_plain(), payload);
    }

    #[test]
    fn zero_chunk_can_carry_profile_padding() {
        let mut encoder = V6ShapedEncoder::new(PSK).unwrap();
        let wire = flatten_sealed(&mut encoder, SnellBuffer::empty());

        let mut decoder = V6ShapedDecoder::new(Arc::<[u8]>::from(PSK));
        let mut src = wire.as_slice();
        assert_eq!(
            decode_until_record(&mut decoder, &mut src),
            DecodeEvent::ZeroChunk
        );
        assert!(src.is_empty());
    }

    fn decode_until_record(decoder: &mut V6ShapedDecoder, src: &mut &[u8]) -> DecodeEvent<'static> {
        loop {
            match decode_next(decoder, src) {
                DecodeEvent::NeedMore => assert!(
                    !src.is_empty(),
                    "decoder needs more bytes than encoder emitted"
                ),
                DecodeEvent::PlainData => return DecodeEvent::PlainData,
                DecodeEvent::ZeroChunk => return DecodeEvent::ZeroChunk,
                event => panic!("unexpected decode event: {event:?}"),
            }
        }
    }

    fn decode_next<'a>(decoder: &'a mut V6ShapedDecoder, src: &mut &[u8]) -> DecodeEvent<'a> {
        if src.is_empty() {
            return decoder.feed_owned(SnellBuffer::empty()).unwrap();
        }
        let n = decoder.next_ciphertext_read_len();
        assert!(n <= src.len(), "decoder asked for bytes past encoded input");
        let chunk = BytesMut::from(&src[..n]);
        *src = &src[n..];
        decoder.feed_owned(SnellBuffer::from(chunk)).unwrap()
    }
}

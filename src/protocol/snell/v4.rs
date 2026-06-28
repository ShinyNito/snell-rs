//! V4 Snell codec: legacy AEAD transport with Argon2id, padding, and shaping.
//!
//! # Wire layout
//!
//! V4 streams records. The first record seeds the session key with a random
//! salt; subsequent records are header + optional body only.
//!
//! ```text
//!   first record      subsequent record
//!  +----------+       +---------------+
//!  | SALT(16) |       | HEADER_CIPHER |
//!  +----------+       +---------------+
//!  | HEADER_  |       | BODY?         |
//!  | CIPHER   |       +---------------+
//!  +----------+
//!  | BODY?    |
//!  +----------+
//!
//!   HEADER_CIPHER = HEADER_PLAIN(7) || TAG(16)      // AES-128-GCM, AAD empty
//!   HEADER_PLAIN  = [4][RSV][RSV][PADDING_HI LO][PAYLOAD_HI LO]
//!   BODY          = PADDING || PAYLOAD_CIPHER || TAG (payload_len > 0)
//!                 = (omitted)                       (payload_len == 0, zero chunk)
//! ```
//!
//! # Body obfuscation (padding interleave)
//!
//! To hide where padding ends and payload begins, V4 interleaves the two
//! ciphertext regions by swapping byte pairs across the boundary:
//!
//! ```text
//!   before swap:  [ P A D D I N G ][ P A Y L O A D || TAG ]
//!                         swap pairs across the boundary ->
//!   on wire:      [ pad[0] pay[0] pad[1] pay[1] ... ]
//!
//!   make_padding(): pick padding bits so the whole BODY's 0/1 ratio
//!                   stays near a target, leaking no payload entropy profile.
//!   swap_padding(): reverse the swap on decode before AEAD open.
//! ```
//!
//! # Encode flow
//!
//! ```text
//!   next_plain_capacity()
//!      |  budget = chunk_limit(now)  (MSS - overhead, grows each record)
//!      v
//!   seal_plain(SnellBuffer, SnellWire)
//!      |  write HEADER_PLAIN (padding_len, payload_len)
//!      |  seal header  (AEAD, nonce++, AAD empty)
//!      |  seal payload (AEAD, nonce++, AAD empty) -> detached TAG
//!      |  if padding > 0: make_padding() then swap_padding()
//!      v
//!   reusable SnellWire -> flush SALT? + HEADER_CIPHER + BODY
//! ```
//!
//! # Decode flow (state machine)
//!
//! ```text
//!   Salt(16) --init_salt(psk,salt)--> Header
//!        |
//!        v
//!   Header(HEADER_CIPHER_LEN) --decrypt--> DecodedHeader
//!        |
//!        +-- body_len == 0 ?  emit ZeroChunk / PlainData, -> Header
//!        |
//!        v
//!   Body(body_len)
//!        |  swap_padding()  (undo interleave)
//!        |  open payload (AEAD, nonce++, AAD empty)
//!        v
//!   emit PlainData, expose [padding_len .. padding_len+payload_len] -> Header
//! ```
//!
//! The encoder also emulates a small congestion window: a per-record MSS-based
//! chunk limit that grows toward [`MAX_PACKET_SIZE`] and resets after idle.

use std::{
    fmt, io,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::BytesMut;
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Tag};

use super::{
    DecodeEvent, DecodedHeader, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN, MAX_PACKET_SIZE, NONCE_LEN,
    SALT_LEN, SnellBuffer, SnellTcpDecoder, SnellTcpEncoder, SnellWire,
    common::{
        ReadStep, decode_plain_header, invalid_data, invalid_input, make_padding_split, next_nonce,
        seal_header, seal_payload_detached, swap_padding, swap_padding_split, v4_key,
        write_plain_header,
    },
};

/// Reference MSS used by the V4 congestion emulation.
pub(super) const V4_MSS_BASE: usize = 0x05b4;
/// Bytes subtracted from the MSS for the first record (salt + header + padding).
pub(super) const V4_FIRST_RECORD_OVERHEAD: usize = 0x37;
/// Minimum initial padding injected into the first record.
const INITIAL_PADDING_MIN: usize = 0x100;
/// Additional random spread added on top of [`INITIAL_PADDING_MIN`].
const INITIAL_PADDING_SPAN: u32 = 0x100;
/// Overhead subtracted from the MSS after an idle reset.
const V4_RESET_OVERHEAD: usize = 0x27;
/// Idle interval after which the chunk limit is reset to the MSS baseline.
const V4_IDLE_RESET: Duration = Duration::from_secs(30);

/// Streaming V4 encoder.
///
/// Holds the session key derived from the salt, a monotonically increasing
/// nonce, and the congestion window state.
pub struct V4Encoder {
    key: LessSafeKey,
    nonce: [u8; NONCE_LEN],
    salt: [u8; SALT_LEN],
    salt_sent: bool,
    initial_padding_len: usize,
    chunk_limit: usize,
    last_write: Option<Instant>,
}

impl fmt::Debug for V4Encoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V4Encoder")
            .field("salt_sent", &self.salt_sent)
            .field("chunk_limit", &self.chunk_limit)
            .finish()
    }
}

/// Streaming V4 decoder.
///
/// The PSK is kept (cloned) so the session key can be derived lazily once the
/// peer's salt arrives. `read_step` drives the salt → header → body state machine.
#[derive(Debug)]
pub struct V4Decoder {
    psk: Arc<[u8]>,
    key: Option<LessSafeKey>,
    nonce: [u8; NONCE_LEN],
    read_step: ReadStep,
    buf: BytesMut,
    plain: SnellBuffer,
}

impl V4Encoder {
    /// Create an encoder with a random salt and randomized initial padding.
    pub fn new(psk: &[u8]) -> io::Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let initial_padding_len =
            INITIAL_PADDING_MIN + (rand::thread_rng().next_u32() % INITIAL_PADDING_SPAN) as usize;
        Self::with_salt_and_initial_padding(psk, salt, initial_padding_len)
    }

    /// Create an encoder with an explicit salt and initial padding length.
    ///
    /// Exposed for tests that need deterministic salt/padding values.
    pub(super) fn with_salt_and_initial_padding(
        psk: &[u8],
        salt: [u8; SALT_LEN],
        initial_padding_len: usize,
    ) -> io::Result<Self> {
        if initial_padding_len > MAX_PACKET_SIZE {
            return Err(invalid_input("snell v4 initial padding too large"));
        }
        Ok(Self {
            key: v4_key(psk, &salt)?,
            nonce: [0; NONCE_LEN],
            salt,
            salt_sent: false,
            initial_padding_len,
            chunk_limit: 0,
            last_write: None,
        })
    }

    fn seal_payload(&mut self, mut payload: SnellBuffer, wire: &mut SnellWire) -> io::Result<()> {
        wire.clear();
        let now = Instant::now();
        let max_payload_len = self.budget_for(now).min(MAX_PACKET_SIZE);
        let payload_len = payload.len();
        if payload_len > max_payload_len {
            return Err(invalid_input("snell payload exceeds record capacity"));
        }
        let first_record = !self.salt_sent;
        let padding_len = if first_record && payload_len > 0 {
            self.initial_padding_len
        } else {
            0
        };

        // head segment: [salt?][header_cipher]
        let head_len = (first_record as usize) * SALT_LEN + HEADER_CIPHER_LEN;
        {
            let head = wire.push_head_zeroed(head_len);
            if first_record {
                head[..SALT_LEN].copy_from_slice(&self.salt);
            }
            let header_start = (first_record as usize) * SALT_LEN;
            write_plain_header(
                &mut head[header_start..header_start + HEADER_PLAIN_LEN],
                padding_len,
                payload_len,
            )?;
            seal_header(
                &self.key,
                &mut self.nonce,
                &[],
                &mut head[header_start..header_start + HEADER_CIPHER_LEN],
                "snell v4 header encrypt failed",
            )?;
        }

        if payload_len > 0 {
            // payload_cipher is the caller's buffer, encrypted in place.
            let mut payload_tag = seal_payload_detached(
                &self.key,
                &mut self.nonce,
                &[],
                payload.as_mut_slice(),
                "snell v4 payload encrypt failed",
            )?;

            if padding_len > 0 {
                let padding = wire.prepare_padding(padding_len);
                make_padding_split(&mut *padding, payload.as_slice(), &payload_tag);
                swap_padding_split(&mut *padding, payload.as_mut_slice(), &mut payload_tag);
                wire.push_padding();
            }
            wire.push_buffer(payload);
            wire.push_tag(payload_tag);
        }

        self.salt_sent = true;
        self.chunk_limit = next_v4_chunk_limit(max_payload_len);
        self.last_write = Some(now);
        Ok(())
    }

    fn plain_capacity(&self) -> usize {
        self.budget_for(Instant::now()).min(MAX_PACKET_SIZE)
    }

    /// Payload budget for the next record, by phase:
    /// ```text
    ///   first record : MSS - FIRST_RECORD_OVERHEAD - initial_padding_len
    ///   after idle   : MSS - RESET_OVERHEAD                 (idle > 30s)
    ///   steady state : previous chunk_limit
    ///   fallback     : MSS - RESET_OVERHEAD
    /// ```
    fn budget_for(&self, now: Instant) -> usize {
        if !self.salt_sent {
            V4_MSS_BASE.saturating_sub(V4_FIRST_RECORD_OVERHEAD + self.initial_padding_len)
        } else if self
            .last_write
            .is_some_and(|last| now.duration_since(last) > V4_IDLE_RESET)
        {
            V4_MSS_BASE.saturating_sub(V4_RESET_OVERHEAD)
        } else if self.chunk_limit != 0 {
            self.chunk_limit
        } else {
            V4_MSS_BASE.saturating_sub(V4_RESET_OVERHEAD)
        }
    }
}

/// Advance the congestion window by one record.
///
/// Each record grows the allowed payload by another MSS minus reset overhead,
/// clamped to [`MAX_PACKET_SIZE`] — emulating slow-start growth toward the MTU.
pub(super) fn next_v4_chunk_limit(current_limit: usize) -> usize {
    if current_limit > MAX_PACKET_SIZE - 1 {
        current_limit.min(MAX_PACKET_SIZE)
    } else {
        current_limit
            .saturating_add(V4_MSS_BASE)
            .saturating_sub(V4_RESET_OVERHEAD)
            .min(MAX_PACKET_SIZE)
    }
}

impl V4Decoder {
    /// Create a decoder holding the PSK; the session key is derived lazily once
    /// the peer's salt arrives via [`V4Decoder::init_salt`].
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

    /// Whether the session key is still waiting for the peer's salt.
    pub fn needs_salt(&self) -> bool {
        self.key.is_none()
    }

    /// Seed the session key from the peer's salt: `key = Argon2id(psk, salt)`.
    pub fn init_salt(&mut self, salt: [u8; SALT_LEN]) -> io::Result<()> {
        self.key = Some(v4_key(&self.psk, &salt)?);
        Ok(())
    }

    /// Decrypt an out-of-band header buffer (used by the trait-driven tests).
    ///
    /// Layout in `header_cipher`: `[ HEADER_CIPHER(7) ][ TAG(16) ]`.
    pub fn decode_header(
        &mut self,
        header_cipher: &mut [u8; HEADER_CIPHER_LEN],
    ) -> io::Result<DecodedHeader> {
        let nonce = next_nonce(&mut self.nonce);
        let (cipher, tag) = header_cipher.split_at_mut(HEADER_PLAIN_LEN);
        let tag = Tag::try_from(&tag[..]).map_err(|_| invalid_data("snell v4 invalid tag"))?;
        let header = self
            .key()?
            .open_in_place_separate_tag(nonce, Aad::empty(), tag, cipher, 0..)
            .map_err(|_| invalid_data("snell v4 header decrypt failed"))?;
        decode_plain_header(header)
    }

    /// Decrypt the header currently buffered in `read_buf` (streaming path).
    fn decode_header_in_place(&mut self, header_cipher: &mut [u8]) -> io::Result<DecodedHeader> {
        let nonce = next_nonce(&mut self.nonce);
        let (cipher, tag) = header_cipher.split_at_mut(HEADER_PLAIN_LEN);
        let tag = Tag::try_from(&tag[..]).map_err(|_| invalid_data("snell v4 invalid tag"))?;
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| invalid_data("snell v4 reader key not initialized"))?;
        let header = key
            .open_in_place_separate_tag(nonce, Aad::empty(), tag, cipher, 0..)
            .map_err(|_| invalid_data("snell v4 header decrypt failed"))?;
        decode_plain_header(header)
    }

    /// Decrypt the body, returning `Ok(true)` if plaintext is available, `Ok(false)` for
    /// a zero chunk.
    ///
    /// Steps:
    /// ```text
    ///   1. swap_padding(padding, payload_cipher)   -- undo byte interleave
    ///   2. AEAD open(payload_cipher, tag, nonce++)  -- decrypt
    ///   3. self.plain = padding_len .. padding_len + payload_len
    /// ```
    pub fn finish_body(
        &mut self,
        mut body: SnellBuffer,
        header: DecodedHeader,
    ) -> io::Result<bool> {
        self.plain = SnellBuffer::empty();
        if header.payload_len == 0 {
            if header.padding_len != 0 {
                return Err(invalid_data("snell v4 zero chunk with padding"));
            }
            return Ok(false);
        }

        let key = self
            .key
            .as_ref()
            .ok_or_else(|| invalid_data("snell v4 reader key not initialized"))?;
        if body.len() != header.body_len {
            return Err(invalid_data("snell v4 body length mismatch"));
        }
        let (padding, payload_cipher_and_tag) =
            body.as_mut_slice().split_at_mut(header.padding_len);
        swap_padding(padding, payload_cipher_and_tag);
        let (payload_cipher, tag) = payload_cipher_and_tag.split_at_mut(header.payload_len);
        let tag = Tag::try_from(&tag[..]).map_err(|_| invalid_data("snell v4 invalid tag"))?;
        let nonce = next_nonce(&mut self.nonce);
        key.open_in_place_separate_tag(nonce, Aad::empty(), tag, payload_cipher, 0..)
            .map_err(|_| invalid_data("snell v4 payload decrypt failed"))?;
        body.advance(header.padding_len);
        body.truncate(header.payload_len);
        self.plain = body;
        Ok(true)
    }

    /// Borrow the decrypted plaintext region from the current record.
    pub fn pending_plain(&self) -> &[u8] {
        self.plain.as_slice()
    }

    /// Mark `n` bytes from [`V4Decoder::pending_plain`] as consumed.
    pub fn consume_plain(&mut self, n: usize) {
        let n = n.min(self.plain.len());
        self.plain.advance(n);
        if self.plain.is_empty() {
            self.plain = SnellBuffer::empty();
        }
    }

    fn key(&self) -> io::Result<&LessSafeKey> {
        self.key
            .as_ref()
            .ok_or_else(|| invalid_data("snell v4 reader key not initialized"))
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

impl SnellTcpEncoder for V4Encoder {
    fn next_plain_capacity(&self) -> usize {
        self.plain_capacity()
    }

    fn seal_plain(&mut self, payload: SnellBuffer, wire: &mut SnellWire) -> io::Result<()> {
        self.seal_payload(payload, wire)
    }
}

impl SnellTcpDecoder for V4Decoder {
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
        chunk.append_to_bytes_mut(&mut self.buf);
        self.try_drain()
    }

    fn pending_plain(&self) -> &[u8] {
        V4Decoder::pending_plain(self)
    }

    fn consume_plain(&mut self, n: usize) {
        V4Decoder::consume_plain(self, n);
    }

    fn take_plain(&mut self) -> SnellBuffer {
        std::mem::replace(&mut self.plain, SnellBuffer::empty())
    }
}

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
//!   begin_write(hint)
//!      |  budget = chunk_limit(now)  (MSS - overhead, grows each record)
//!      |  slot   = min(hint, budget)
//!      |  first? -> prepend SALT, set padding = initial_padding_len
//!      v
//!   plain_slot(reservation) ----> caller writes payload
//!      v
//!   finish_write(reservation, payload_len)
//!      |  write HEADER_PLAIN (padding_len, payload_len)
//!      |  seal header  (AEAD, nonce++, AAD empty)
//!      |  seal payload (AEAD, nonce++, AAD empty) -> append TAG
//!      |  if padding > 0: make_padding() then swap_padding()
//!      v
//!   pending_wire() / advance_wire(n) -> flush SALT? + HEADER_CIPHER + BODY
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
    fmt,
    io::{self, IoSlice},
    ops::Range,
    sync::Arc,
    time::{Duration, Instant},
};

use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Tag};

use crate::protocol::ParseState;

use super::{
    DecodeEvent, DecodeSlot, DecodedHeader, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN, MAX_PACKET_SIZE,
    NONCE_LEN, PlainPrefix, SALT_LEN, SnellTcpDecoder, SnellTcpEncoder, TAG_LEN, WriteReservation,
    common::{
        ReadStep, apply_plain_prefix, decode_plain_header, finish_len_with_prefix, invalid_data,
        invalid_input, make_padding, need_filled, next_nonce, pending_plaintext_slice,
        plain_slot_with_prefix, push_pending, swap_padding, v4_key, write_plain_header,
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
/// nonce, the congestion window state, and the pending wire bytes awaiting flush.
pub struct V4Encoder {
    key: LessSafeKey,
    nonce: [u8; NONCE_LEN],
    salt: [u8; SALT_LEN],
    salt_sent: bool,
    initial_padding_len: usize,
    chunk_limit: usize,
    last_write: Option<Instant>,
    wire: Vec<u8>,
    pending_salt: bool,
    header_tag: Option<Tag>,
    wire_pos: usize,
}

impl fmt::Debug for V4Encoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V4Encoder")
            .field("salt_sent", &self.salt_sent)
            .field("chunk_limit", &self.chunk_limit)
            .field("wire_len", &self.wire.len())
            .field("wire_pos", &self.wire_pos)
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
    read_buf: Vec<u8>,
    body: Vec<u8>,
    plain: Range<usize>,
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
            wire: Vec::new(),
            pending_salt: false,
            header_tag: None,
            wire_pos: 0,
        })
    }

    /// Reserve a record sized for up to `hint` payload bytes.
    ///
    /// Sizes the payload slot by the congestion window, prepends initial padding
    /// for the first record, and lays out header/padding/payload regions in
    /// `wire`. The caller writes plaintext into [`V4Encoder::plain_slot`] then
    /// calls [`V4Encoder::finish_write`].
    pub fn begin_write(&mut self, hint: usize) -> io::Result<WriteReservation> {
        if !self.pending_empty() {
            return Err(invalid_input("snell pending wire not fully written"));
        }

        let max_payload_len = hint.min(self.next_chunk_limit(Instant::now()));
        let first_record = !self.salt_sent;
        let padding_len = if first_record && max_payload_len > 0 {
            self.initial_padding_len
        } else {
            0
        };

        self.wire.clear();
        self.wire_pos = 0;
        self.pending_salt = first_record;
        self.header_tag = None;

        let header_start = self.wire.len();
        self.wire.resize(header_start + HEADER_PLAIN_LEN, 0);

        let padding_start = self.wire.len();
        self.wire.resize(padding_start + padding_len, 0);

        let payload_start = self.wire.len();
        self.wire
            .resize(payload_start + max_payload_len + TAG_LEN, 0);

        Ok(WriteReservation {
            plain_prefix_len: 0,
            head_start: header_start,
            prefix_start: header_start,
            prefix_len: 0,
            header_start,
            padding_start,
            padding_len,
            payload_start,
            max_payload_len,
        })
    }

    /// Borrow the plaintext payload slot for this reservation.
    ///
    /// Layout in `wire`: `[ ..header.. | ..padding.. | PAYLOAD SLOT | TAG ]`.
    pub fn plain_slot(&mut self, reservation: WriteReservation) -> &mut [u8] {
        &mut self.wire
            [reservation.payload_start..reservation.payload_start + reservation.max_payload_len]
    }

    /// Seal the record after the caller wrote `payload_len` bytes.
    ///
    /// Layout produced in `wire` (first record shown):
    /// ```text
    ///   [SALT?][ HEADER_PLAIN ][ HEADER_TAG ][ PADDING ][ PAYLOAD_CIPHER ][ TAG ]
    ///           ^-- write_plain_header      ^-- seal header (nonce++)          ^-- seal payload (nonce++)
    ///                                                   padding<->payload swapped when padding > 0
    /// ```
    /// A zero-length `payload_len` drops the body entirely and emits a zero chunk.
    pub fn finish_write(
        &mut self,
        reservation: WriteReservation,
        payload_len: usize,
    ) -> io::Result<()> {
        if payload_len > reservation.max_payload_len {
            return Err(invalid_input("snell payload exceeds reservation"));
        }

        let padding_len = if payload_len == 0 {
            0
        } else {
            reservation.padding_len
        };
        let body_start = reservation.header_start + HEADER_PLAIN_LEN;

        if payload_len == 0 {
            self.wire.truncate(body_start);
        } else {
            self.wire
                .truncate(reservation.payload_start + payload_len + TAG_LEN);
        }

        let header = reservation.header_start..reservation.header_start + HEADER_PLAIN_LEN;
        write_plain_header(&mut self.wire[header.clone()], padding_len, payload_len)?;
        self.header_tag = Some(
            self.key
                .seal_in_place_separate_tag(
                    next_nonce(&mut self.nonce),
                    Aad::empty(),
                    &mut self.wire[header],
                )
                .map_err(|_| invalid_data("snell v4 header encrypt failed"))?,
        );

        if payload_len > 0 {
            let payload = reservation.payload_start..reservation.payload_start + payload_len;
            let tag = self
                .key
                .seal_in_place_separate_tag(
                    next_nonce(&mut self.nonce),
                    Aad::empty(),
                    &mut self.wire[payload.clone()],
                )
                .map_err(|_| invalid_data("snell v4 payload encrypt failed"))?;
            let tag_start = payload.end;
            self.wire[tag_start..tag_start + TAG_LEN].copy_from_slice(tag.as_ref());

            if padding_len > 0 {
                let (_, body) = self.wire.split_at_mut(reservation.padding_start);
                let (padding, payload_cipher_and_tag) = body.split_at_mut(padding_len);
                make_padding(padding, payload_cipher_and_tag);
                swap_padding(padding, payload_cipher_and_tag);
            }
        }

        self.salt_sent = true;
        self.wire_pos = 0;
        Ok(())
    }

    /// Whether all sealed bytes have been flushed.
    pub fn pending_empty(&self) -> bool {
        self.wire_pos >= self.pending_len()
    }

    /// Collect sealed bytes pending flush as vectored slices, honoring a partial
    /// write offset.
    ///
    /// Emission order:
    /// ```text
    ///   [SALT?] [HEADER_PLAIN][HEADER_TAG] [BODY: PADDING + PAYLOAD_CIPHER + TAG]
    /// ```
    pub fn pending_wire<'a>(&'a self, out: &mut [IoSlice<'a>]) -> usize {
        let mut len = 0;
        let mut skip = self.wire_pos;

        if self.pending_salt {
            push_pending(out, &mut len, &mut skip, &self.salt);
        }
        push_pending(
            out,
            &mut len,
            &mut skip,
            &self.wire[..HEADER_PLAIN_LEN.min(self.wire.len())],
        );
        if let Some(tag) = &self.header_tag {
            push_pending(out, &mut len, &mut skip, tag.as_ref());
        }
        if self.wire.len() > HEADER_PLAIN_LEN {
            push_pending(out, &mut len, &mut skip, &self.wire[HEADER_PLAIN_LEN..]);
        }

        len
    }

    /// Mark `written` sealed bytes as flushed, clearing the record when drained.
    pub fn advance_wire(&mut self, written: usize) {
        self.wire_pos = (self.wire_pos + written).min(self.pending_len());
        if self.pending_empty() {
            self.wire.clear();
            self.pending_salt = false;
            self.header_tag = None;
            self.wire_pos = 0;
        }
    }

    /// Total sealed bytes pending flush: `SALT? + wire + HEADER_TAG?`.
    fn pending_len(&self) -> usize {
        usize::from(self.pending_salt) * SALT_LEN
            + self.wire.len()
            + self.header_tag.as_ref().map_or(0, |_| TAG_LEN)
    }

    /// Compute this record's payload budget and roll the congestion window forward.
    fn next_chunk_limit(&mut self, now: Instant) -> usize {
        let limit = self.budget_for(now).min(MAX_PACKET_SIZE);
        self.chunk_limit = next_v4_chunk_limit(limit);
        self.last_write = Some(now);
        limit
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
            read_buf: Vec::new(),
            body: Vec::new(),
            plain: 0..0,
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
    fn decode_header_in_place(&mut self) -> io::Result<DecodedHeader> {
        let nonce = next_nonce(&mut self.nonce);
        let (cipher, tag) = self.read_buf[..HEADER_CIPHER_LEN].split_at_mut(HEADER_PLAIN_LEN);
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

    /// Borrow the fill slot for a record's body (padding + ciphertext + tag).
    pub fn body_slot(&mut self, header: DecodedHeader) -> &mut [u8] {
        self.body.resize(header.body_len, 0);
        &mut self.body[..header.body_len]
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
    pub fn finish_body(&mut self, header: DecodedHeader) -> io::Result<bool> {
        self.plain = 0..0;
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
        let body = &mut self.body[..header.body_len];
        let (padding, payload_cipher_and_tag) = body.split_at_mut(header.padding_len);
        swap_padding(padding, payload_cipher_and_tag);
        let (payload_cipher, tag) = payload_cipher_and_tag.split_at_mut(header.payload_len);
        let tag = Tag::try_from(&tag[..]).map_err(|_| invalid_data("snell v4 invalid tag"))?;
        let nonce = next_nonce(&mut self.nonce);
        key.open_in_place_separate_tag(nonce, Aad::empty(), tag, payload_cipher, 0..)
            .map_err(|_| invalid_data("snell v4 payload decrypt failed"))?;
        self.plain = header.padding_len..header.padding_len + header.payload_len;
        Ok(true)
    }

    /// Borrow the decrypted plaintext region from the current record.
    pub fn pending_plain(&self) -> &[u8] {
        &self.body[self.plain.clone()]
    }

    /// Mark `n` bytes from [`V4Decoder::pending_plain`] as consumed.
    pub fn consume_plain(&mut self, n: usize) {
        let take = n.min(self.plain.len());
        self.plain.start += take;
        if self.plain.is_empty() {
            self.body.clear();
            self.plain = 0..0;
        }
    }

    fn key(&self) -> io::Result<&LessSafeKey> {
        self.key
            .as_ref()
            .ok_or_else(|| invalid_data("snell v4 reader key not initialized"))
    }
}

impl SnellTcpEncoder for V4Encoder {
    type Reservation = WriteReservation;

    fn begin_plain_reservation(
        &mut self,
        prefix: PlainPrefix<'_>,
        payload_hint: usize,
    ) -> io::Result<Self::Reservation> {
        let mut reservation =
            V4Encoder::begin_write(self, prefix.len().saturating_add(payload_hint))?;
        apply_plain_prefix(&mut self.wire, &mut reservation, prefix)?;
        Ok(reservation)
    }

    fn plain_slot(&mut self, reservation: &Self::Reservation) -> &mut [u8] {
        plain_slot_with_prefix(&mut self.wire, reservation)
    }

    fn finish_plain_reservation(
        &mut self,
        reservation: Self::Reservation,
        payload_len: usize,
    ) -> io::Result<()> {
        let payload_len = finish_len_with_prefix(&reservation, payload_len)?;
        V4Encoder::finish_write(self, reservation, payload_len)
    }

    fn cancel_plain_reservation(&mut self, _reservation: Self::Reservation) {
        self.wire.clear();
        self.pending_salt = false;
        self.header_tag = None;
        self.wire_pos = 0;
    }

    fn pending_wire<'a>(&'a self, out: &mut [IoSlice<'a>]) -> usize {
        V4Encoder::pending_wire(self, out)
    }

    fn advance_wire(&mut self, written: usize) {
        V4Encoder::advance_wire(self, written);
    }
}

impl SnellTcpDecoder for V4Decoder {
    fn next_ciphertext_slot(&mut self) -> DecodeSlot<'_> {
        if !self.pending_plain().is_empty() {
            return DecodeSlot::BlockedByPlaintext;
        }

        match self.read_step {
            ReadStep::Salt { filled } => {
                self.read_buf.resize(SALT_LEN, 0);
                DecodeSlot::Read(&mut self.read_buf[filled..])
            }
            ReadStep::Header { filled } => {
                self.read_buf.resize(HEADER_CIPHER_LEN, 0);
                DecodeSlot::Read(&mut self.read_buf[filled..])
            }
            ReadStep::Body { header, filled } => {
                self.body.resize(header.body_len, 0);
                DecodeSlot::Read(&mut self.body[filled..])
            }
        }
    }

    fn commit_ciphertext(&mut self, n: usize) -> io::Result<DecodeEvent<'_>> {
        match self.read_step {
            ReadStep::Salt { filled } => {
                let filled = filled + n;
                match need_filled(filled, SALT_LEN) {
                    ParseState::Need(_) => {
                        self.read_step = ReadStep::Salt { filled };
                        return Ok(DecodeEvent::NeedMore);
                    }
                    ParseState::Done(()) => {}
                }
                let salt: [u8; SALT_LEN] = self.read_buf[..SALT_LEN]
                    .try_into()
                    .expect("salt buffer filled");
                self.init_salt(salt)?;
                self.read_step = ReadStep::Header { filled: 0 };
                Ok(DecodeEvent::NeedMore)
            }
            ReadStep::Header { filled } => {
                let filled = filled + n;
                match need_filled(filled, HEADER_CIPHER_LEN) {
                    ParseState::Need(_) => {
                        self.read_step = ReadStep::Header { filled };
                        return Ok(DecodeEvent::NeedMore);
                    }
                    ParseState::Done(()) => {}
                }
                let header = self.decode_header_in_place()?;
                if header.body_len == 0 {
                    self.read_step = ReadStep::Header { filled: 0 };
                    return if self.finish_body(header)? {
                        Ok(DecodeEvent::PlainData)
                    } else {
                        Ok(DecodeEvent::ZeroChunk)
                    };
                }
                self.read_step = ReadStep::Body { header, filled: 0 };
                Ok(DecodeEvent::NeedMore)
            }
            ReadStep::Body { header, filled } => {
                let filled = filled + n;
                match need_filled(filled, header.body_len) {
                    ParseState::Need(_) => {
                        self.read_step = ReadStep::Body { header, filled };
                        return Ok(DecodeEvent::NeedMore);
                    }
                    ParseState::Done(()) => {}
                }
                self.read_step = ReadStep::Header { filled: 0 };
                if self.finish_body(header)? {
                    Ok(DecodeEvent::PlainData)
                } else {
                    Ok(DecodeEvent::ZeroChunk)
                }
            }
        }
    }

    fn pending_plaintext<'a>(&'a self, out: &mut [IoSlice<'a>]) -> usize {
        pending_plaintext_slice(self.pending_plain(), out)
    }

    fn advance_plaintext(&mut self, n: usize) {
        V4Decoder::consume_plain(self, n);
    }
}

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
//!   begin_write(hint)
//!      |  profile-driven chunk_size and padding_len
//!      |  first? -> write salt block, fill prefix
//!      v
//!   plain_slot -> caller writes payload
//!      v
//!   finish_write(reservation, payload_len)
//!      |  write_v6_plain_header(padding_len, payload_len)
//!      |  seal header   (nonce++, AAD = prefix)
//!      |  fill padding  (profile.fill_official)
//!      |  seal payload  (nonce++, AAD = padding)
//!      |  mix_padding_payload (bit-interleave)
//!      v
//!   pending_wire / advance_wire -> flush
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

use std::{
    fmt,
    io::{self, IoSlice},
    ops::Range,
    sync::Arc,
    time::Instant,
};

use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Tag};

use crate::protocol::ParseState;

use super::super::{
    DecodeEvent, DecodeSlot, DecodedHeader, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN,
    MAX_PACKET_SIZE_V6, NONCE_LEN, PlainPrefix, SALT_LEN, SnellTcpDecoder, SnellTcpEncoder,
    TAG_LEN, WriteReservation,
    common::{
        apply_plain_prefix, current_nonce, decode_v6_shaped_header, finish_len_with_prefix,
        increment_nonce, invalid_data, invalid_input, need_filled, next_nonce,
        pending_plaintext_slice, plain_slot_with_prefix, push_pending_range, seal_header,
        seal_payload, v6_key, write_v6_plain_header,
    },
    profile::{Profile, mix_padding_payload},
};

/// V6 shaped encoder — profile-driven obfuscation and shaping.
///
/// Session key derived via HKDF. The [`Profile`] controls salt block size,
/// prefix length, padding length, and chunk size for each record sequence
/// number.
pub struct V6ShapedEncoder {
    key: LessSafeKey,
    nonce: [u8; NONCE_LEN],
    salt: [u8; SALT_LEN],
    salt_sent: bool,
    seq: u32,
    profile: Arc<Profile>,
    chunk_size: usize,
    last_write: Option<Instant>,
    wire: Vec<u8>,
    pending: Option<ShapedPending>,
    wire_pos: usize,
}

impl fmt::Debug for V6ShapedEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6ShapedEncoder")
            .field("salt_sent", &self.salt_sent)
            .field("seq", &self.seq)
            .field("chunk_size", &self.chunk_size)
            .field("wire_len", &self.wire.len())
            .field("wire_pos", &self.wire_pos)
            .finish()
    }
}

/// A pending record's wire region ranges, used for vectored flush in the
/// correct emission order.
#[derive(Clone, Debug)]
struct ShapedPending {
    salt_block: Range<usize>,
    prefix: Range<usize>,
    header: Range<usize>,
    padding: Range<usize>,
    payload: Range<usize>,
}

/// V6 shaped decoder — profile-driven obfuscation and shaping.
///
/// The decoder derives the [`Profile`] from the PSK at construction time and
/// uses it to extract the salt from the salt block, determine per-record prefix
/// lengths, and undo the padding interleave.
#[derive(Debug)]
pub struct V6ShapedDecoder {
    psk: Arc<[u8]>,
    profile: Arc<Profile>,
    key: Option<LessSafeKey>,
    nonce: [u8; NONCE_LEN],
    seq: u32,
    read_step: ShapedReadStep,
    read_buf: Vec<u8>,
    body: Vec<u8>,
    plain: Range<usize>,
}

/// Decoder state machine arms for the shaped variant.
#[derive(Clone, Copy, Debug)]
enum ShapedReadStep {
    /// Reading the profile-sized salt block.
    Salt { filled: usize },
    /// Reading the per-record prefix + AEAD header.
    Header { prefix_len: usize, filled: usize },
    /// Reading the frame body (padding + ciphertext payload + tag).
    Body {
        header: DecodedHeader,
        filled: usize,
    },
}

impl V6ShapedEncoder {
    /// Create an encoder with a random salt and a profile derived from the PSK.
    pub fn new(psk: &[u8]) -> io::Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        Self::with_salt_and_profile(psk, salt, Arc::new(Profile::derive(psk)))
    }

    fn with_salt_and_profile(
        psk: &[u8],
        salt: [u8; SALT_LEN],
        profile: Arc<Profile>,
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
            wire: Vec::new(),
            pending: None,
            wire_pos: 0,
        })
    }

    pub fn begin_write(&mut self, hint: usize) -> io::Result<WriteReservation> {
        if !self.pending_empty() {
            return Err(invalid_input("snell pending wire not fully written"));
        }

        let first_record = !self.salt_sent;
        let max_payload_len = hint.min(self.next_chunk_limit(Instant::now()));
        let salt_block_len = if first_record {
            self.profile.salt_block_len()
        } else {
            0
        };
        let prefix_len = self.profile.record_prefix_len(self.seq);
        let max_padding_len = self.profile.max_padding_len();
        let head_start = 0;
        let prefix_start = head_start + salt_block_len;
        let header_start = prefix_start + prefix_len;
        let padding_start = header_start + HEADER_CIPHER_LEN;
        let payload_start = padding_start + max_padding_len;

        self.wire.clear();
        self.wire_pos = 0;
        self.pending = None;
        self.wire
            .resize(payload_start + max_payload_len + TAG_LEN, 0);

        if first_record {
            self.profile
                .write_salt_block(&self.salt, &mut self.wire[..salt_block_len])
                .map_err(|_| invalid_data("snell v6 shaped salt block failed"))?;
        }
        self.profile.fill_official(
            self.seq,
            &mut self.wire[prefix_start..prefix_start + prefix_len],
        );

        Ok(WriteReservation {
            plain_prefix_len: 0,
            head_start,
            prefix_start,
            prefix_len,
            header_start,
            padding_start,
            padding_len: max_padding_len,
            payload_start,
            max_payload_len,
        })
    }

    /// Borrow the plaintext payload slot for this reservation.
    ///
    /// The slot starts at `payload_start` and has `max_payload_len` writable bytes.
    pub fn plain_slot(&mut self, reservation: WriteReservation) -> &mut [u8] {
        &mut self.wire
            [reservation.payload_start..reservation.payload_start + reservation.max_payload_len]
    }

    /// Seal the record after the caller wrote `payload_len` bytes.
    ///
    /// Steps:
    /// ```text
    ///   1. Determine padding_len from profile::final_padding_len(...)
    ///   2. write_v6_plain_header(padding_len, payload_len)
    ///   3. seal header (AEAD, nonce++, AAD = prefix bytes)
    ///   4. fill padding region with profile::fill_official(...)
    ///   5. seal payload (AEAD, nonce++, AAD = padding bytes)
    ///   6. mix_padding_payload (bit-interleave padding ↔ payload cipher)
    ///   7. Record ShapedPending for vectored flush order
    /// ```
    pub fn finish_write(
        &mut self,
        reservation: WriteReservation,
        payload_len: usize,
    ) -> io::Result<()> {
        if payload_len > reservation.max_payload_len {
            return Err(invalid_input("snell payload exceeds reservation"));
        }

        let first_record = !self.salt_sent;
        let padding_len = self.profile.final_padding_len(
            self.seq,
            reservation.prefix_len,
            payload_len,
            first_record,
        );
        if padding_len > reservation.padding_len {
            return Err(invalid_data("snell v6 shaped padding exceeds reservation"));
        }

        let salt_block_len = reservation
            .prefix_start
            .saturating_sub(reservation.head_start);
        let salt_block = reservation.head_start..reservation.head_start + salt_block_len;
        let prefix = reservation.prefix_start..reservation.prefix_start + reservation.prefix_len;
        let header = reservation.header_start..reservation.header_start + HEADER_CIPHER_LEN;
        let padding = reservation.padding_start..reservation.padding_start + padding_len;
        let payload_wire_len = if payload_len == 0 {
            0
        } else {
            payload_len + TAG_LEN
        };
        let payload = reservation.payload_start..reservation.payload_start + payload_wire_len;

        write_v6_plain_header(
            &mut self.wire[reservation.header_start..reservation.header_start + HEADER_PLAIN_LEN],
            padding_len,
            payload_len,
        )?;
        {
            let (before_header, header_and_after) = self.wire.split_at_mut(header.start);
            seal_header(
                &self.key,
                &mut self.nonce,
                &before_header[prefix.clone()],
                &mut header_and_after[..HEADER_CIPHER_LEN],
                "snell v6 shaped header encrypt failed",
            )?;
        }

        self.profile
            .fill_official(self.seq, &mut self.wire[padding.clone()]);

        if payload_len > 0 {
            let (left, right) = self.wire.split_at_mut(reservation.payload_start);
            let padding_slice = &mut left[padding.clone()];
            let payload_slice = &mut right[..payload_wire_len];
            seal_payload(
                &self.key,
                &mut self.nonce,
                padding_slice,
                payload_slice,
                payload_len,
                "snell v6 shaped payload encrypt failed",
            )?;
            mix_padding_payload(&self.profile, self.seq, padding_slice, payload_slice);
        }

        self.pending = Some(ShapedPending {
            salt_block,
            prefix,
            header,
            padding,
            payload,
        });
        self.salt_sent = true;
        self.chunk_size = self.profile.advance_chunk_size(self.chunk_size, None);
        self.seq = self.seq.wrapping_add(1);
        self.wire_pos = 0;
        Ok(())
    }

    /// Whether all sealed bytes have been flushed.
    pub fn pending_empty(&self) -> bool {
        self.wire_pos >= self.pending_len()
    }

    /// Collect pending wire bytes for vectored flush, in emission order:
    /// ```text
    ///   [SALT_BLOCK?][PREFIX][HEADER_CIPHER][PADDING][PAYLOAD_CIPHER + TAG]
    /// ```
    pub fn pending_wire<'a>(&'a self, out: &mut [IoSlice<'a>]) -> usize {
        let mut len = 0;
        let mut skip = self.wire_pos;
        if let Some(layout) = &self.pending {
            push_pending_range(
                out,
                &mut len,
                &mut skip,
                &self.wire,
                layout.salt_block.clone(),
            );
            push_pending_range(out, &mut len, &mut skip, &self.wire, layout.prefix.clone());
            push_pending_range(out, &mut len, &mut skip, &self.wire, layout.header.clone());
            push_pending_range(out, &mut len, &mut skip, &self.wire, layout.padding.clone());
            push_pending_range(out, &mut len, &mut skip, &self.wire, layout.payload.clone());
        }
        len
    }

    /// Mark `written` sealed bytes as flushed, clearing the record when drained.
    pub fn advance_wire(&mut self, written: usize) {
        self.wire_pos = (self.wire_pos + written).min(self.pending_len());
        if self.pending_empty() {
            self.wire.clear();
            self.pending = None;
            self.wire_pos = 0;
        }
    }

    /// Total pending bytes: all five regions summed.
    fn pending_len(&self) -> usize {
        self.pending.as_ref().map_or(0, |layout| {
            layout.salt_block.len()
                + layout.prefix.len()
                + layout.header.len()
                + layout.padding.len()
                + layout.payload.len()
        })
    }

    /// Compute the next record's payload budget from the profile's congestion
    /// window, resetting after idle.
    fn next_chunk_limit(&mut self, now: Instant) -> usize {
        let idle = self.last_write.map(|last| now.duration_since(last));
        if self.chunk_size == 0 || idle.is_some_and(|idle| idle > self.profile.idle_reset()) {
            self.chunk_size = self.profile.chunk_initial();
        }
        let mut limit = self
            .profile
            .chunk_limit(self.seq, self.chunk_size, None)
            .min(MAX_PACKET_SIZE_V6);
        if self.seq == 0 {
            limit = limit.min(self.profile.first_record_cap());
        }
        self.last_write = Some(now);
        limit
    }
}

impl V6ShapedDecoder {
    /// Create a decoder that derives its [`Profile`] from the PSK at construction.
    ///
    /// The session key is derived lazily after reading the salt block.
    pub fn new(psk: impl Into<Arc<[u8]>>) -> Self {
        let psk = psk.into();
        Self {
            profile: Arc::new(Profile::derive(&psk)),
            psk,
            key: None,
            nonce: [0; NONCE_LEN],
            seq: 0,
            read_step: ShapedReadStep::Salt { filled: 0 },
            read_buf: Vec::new(),
            body: Vec::new(),
            plain: 0..0,
        }
    }

    /// Extract the salt from the profile's `salt_block_len` bytes and derive
    /// the session key.
    fn init_salt_block(&mut self) -> io::Result<()> {
        let salt = self
            .profile
            .extract_salt(&self.read_buf[..self.profile.salt_block_len()])
            .map_err(|_| invalid_data("snell v6 shaped salt block failed"))?;
        self.key = Some(v6_key(&self.psk, &salt)?);
        Ok(())
    }

    /// Per-record prefix length for the current sequence number.
    fn next_prefix_len(&self) -> usize {
        self.profile.record_prefix_len(self.seq)
    }

    /// Decrypt the header in-place using the buffered prefix as AAD.
    ///
    /// Layout: `read_buf = [PREFIX(plen) | HEADER_CIPHER(23)]`.
    fn decode_header_in_place(&mut self, prefix_len: usize) -> io::Result<DecodedHeader> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| invalid_data("snell v6 shaped reader key not initialized"))?;
        let (prefix, header_cipher) =
            self.read_buf[..prefix_len + HEADER_CIPHER_LEN].split_at_mut(prefix_len);
        let (cipher, tag) = header_cipher.split_at_mut(HEADER_PLAIN_LEN);
        let tag = Tag::try_from(&tag[..]).map_err(|_| invalid_data("snell v6 invalid tag"))?;
        let header = key
            .open_in_place_separate_tag(
                current_nonce(&self.nonce),
                Aad::from(&*prefix),
                tag,
                cipher,
                0..,
            )
            .map_err(|_| invalid_data("snell v6 shaped header decrypt failed"))?;
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
    fn finish_body(&mut self, header: DecodedHeader) -> io::Result<bool> {
        self.plain = 0..0;
        if self.body.len() != header.body_len {
            return Err(invalid_data("snell v6 shaped body length mismatch"));
        }

        increment_nonce(&mut self.nonce);
        if header.payload_len == 0 {
            self.seq = self.seq.wrapping_add(1);
            return Ok(false);
        }

        let seq = self.seq;
        let profile = self.profile.clone();
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| invalid_data("snell v6 shaped reader key not initialized"))?;
        let body = &mut self.body[..header.body_len];
        let (padding, payload_cipher_and_tag) = body.split_at_mut(header.padding_len);
        mix_padding_payload(&profile, seq, padding, payload_cipher_and_tag);
        let (payload_cipher, tag) = payload_cipher_and_tag.split_at_mut(header.payload_len);
        let tag = Tag::try_from(&tag[..]).map_err(|_| invalid_data("snell v6 invalid tag"))?;
        let nonce = next_nonce(&mut self.nonce);
        key.open_in_place_separate_tag(nonce, Aad::from(&*padding), tag, payload_cipher, 0..)
            .map_err(|_| invalid_data("snell v6 shaped payload decrypt failed"))?;
        self.plain = header.padding_len..header.padding_len + header.payload_len;
        self.seq = self.seq.wrapping_add(1);
        Ok(true)
    }

    /// Borrow the decrypted plaintext region from the current record.
    pub fn pending_plain(&self) -> &[u8] {
        &self.body[self.plain.clone()]
    }

    /// Mark `n` bytes from [`V6ShapedDecoder::pending_plain`] as consumed.
    pub fn consume_plain(&mut self, n: usize) {
        let take = n.min(self.plain.len());
        self.plain.start += take;
        if self.plain.is_empty() {
            self.body.clear();
            self.plain = 0..0;
        }
    }
}

impl SnellTcpEncoder for V6ShapedEncoder {
    type Reservation = WriteReservation;

    fn begin_plain_reservation(
        &mut self,
        prefix: PlainPrefix<'_>,
        payload_hint: usize,
    ) -> io::Result<Self::Reservation> {
        let mut reservation =
            V6ShapedEncoder::begin_write(self, prefix.len().saturating_add(payload_hint))?;
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
        V6ShapedEncoder::finish_write(self, reservation, payload_len)
    }

    fn cancel_plain_reservation(&mut self, _reservation: Self::Reservation) {
        self.wire.clear();
        self.pending = None;
        self.wire_pos = 0;
    }

    fn pending_wire<'a>(&'a self, out: &mut [IoSlice<'a>]) -> usize {
        V6ShapedEncoder::pending_wire(self, out)
    }

    fn advance_wire(&mut self, written: usize) {
        V6ShapedEncoder::advance_wire(self, written);
    }
}

impl SnellTcpDecoder for V6ShapedDecoder {
    fn next_ciphertext_slot(&mut self) -> DecodeSlot<'_> {
        if !self.pending_plain().is_empty() {
            return DecodeSlot::BlockedByPlaintext;
        }

        match self.read_step {
            ShapedReadStep::Salt { filled } => {
                self.read_buf.resize(self.profile.salt_block_len(), 0);
                DecodeSlot::Read(&mut self.read_buf[filled..])
            }
            ShapedReadStep::Header { prefix_len, filled } => {
                self.read_buf.resize(prefix_len + HEADER_CIPHER_LEN, 0);
                DecodeSlot::Read(&mut self.read_buf[filled..])
            }
            ShapedReadStep::Body { header, filled } => {
                self.body.resize(header.body_len, 0);
                DecodeSlot::Read(&mut self.body[filled..])
            }
        }
    }

    fn commit_ciphertext(&mut self, n: usize) -> io::Result<DecodeEvent<'_>> {
        match self.read_step {
            ShapedReadStep::Salt { filled } => {
                let filled = filled + n;
                let salt_block_len = self.profile.salt_block_len();
                match need_filled(filled, salt_block_len) {
                    ParseState::Need(_) => {
                        self.read_step = ShapedReadStep::Salt { filled };
                        return Ok(DecodeEvent::NeedMore);
                    }
                    ParseState::Done(()) => {}
                }
                self.init_salt_block()?;
                self.read_step = ShapedReadStep::Header {
                    prefix_len: self.next_prefix_len(),
                    filled: 0,
                };
                Ok(DecodeEvent::NeedMore)
            }
            ShapedReadStep::Header { prefix_len, filled } => {
                let filled = filled + n;
                match need_filled(filled, prefix_len + HEADER_CIPHER_LEN) {
                    ParseState::Need(_) => {
                        self.read_step = ShapedReadStep::Header { prefix_len, filled };
                        return Ok(DecodeEvent::NeedMore);
                    }
                    ParseState::Done(()) => {}
                }
                let header = self.decode_header_in_place(prefix_len)?;
                if header.body_len == 0 {
                    self.read_step = ShapedReadStep::Header {
                        prefix_len: self.next_prefix_len(),
                        filled: 0,
                    };
                    return if self.finish_body(header)? {
                        Ok(DecodeEvent::PlainData)
                    } else {
                        Ok(DecodeEvent::ZeroChunk)
                    };
                }
                self.read_step = ShapedReadStep::Body { header, filled: 0 };
                Ok(DecodeEvent::NeedMore)
            }
            ShapedReadStep::Body { header, filled } => {
                let filled = filled + n;
                match need_filled(filled, header.body_len) {
                    ParseState::Need(_) => {
                        self.read_step = ShapedReadStep::Body { header, filled };
                        return Ok(DecodeEvent::NeedMore);
                    }
                    ParseState::Done(()) => {}
                }
                if self.finish_body(header)? {
                    self.read_step = ShapedReadStep::Header {
                        prefix_len: self.next_prefix_len(),
                        filled: 0,
                    };
                    Ok(DecodeEvent::PlainData)
                } else {
                    self.read_step = ShapedReadStep::Header {
                        prefix_len: self.next_prefix_len(),
                        filled: 0,
                    };
                    Ok(DecodeEvent::ZeroChunk)
                }
            }
        }
    }

    fn pending_plaintext<'a>(&'a self, out: &mut [IoSlice<'a>]) -> usize {
        pending_plaintext_slice(self.pending_plain(), out)
    }

    fn advance_plaintext(&mut self, n: usize) {
        V6ShapedDecoder::consume_plain(self, n);
    }
}

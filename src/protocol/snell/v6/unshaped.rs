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
//! - Encoder: `begin_write → plain_slot → finish_write (seal header + payload) → pending_wire`
//! - Decoder: `Salt → Header (decrypt) → Body (swap_padding is a no-op) → plaintext`

use std::{
    fmt,
    io::{self, IoSlice},
    ops::Range,
    sync::Arc,
};

use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Tag};

use crate::protocol::ParseState;

use super::super::{
    DecodeEvent, DecodeSlot, DecodedHeader, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN, MAX_PACKET_SIZE,
    NONCE_LEN, PlainPrefix, SALT_LEN, SnellTcpDecoder, SnellTcpEncoder, TAG_LEN, WriteReservation,
    common::{
        ReadStep, apply_plain_prefix, decode_v6_unshaped_header, finish_len_with_prefix,
        invalid_data, invalid_input, need_filled, next_nonce, pending_plaintext_slice,
        plain_slot_with_prefix, push_pending, seal_header, seal_payload, v6_key,
        write_v6_plain_header,
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
    wire: Vec<u8>,
    pending_salt: bool,
    wire_pos: usize,
}

impl fmt::Debug for V6UnshapedEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6UnshapedEncoder")
            .field("salt_sent", &self.salt_sent)
            .field("wire_len", &self.wire.len())
            .field("wire_pos", &self.wire_pos)
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
    read_buf: Vec<u8>,
    body: Vec<u8>,
    plain: Range<usize>,
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
            wire: Vec::new(),
            pending_salt: false,
            wire_pos: 0,
        })
    }

    /// Reserve a record sized for up to `hint` payload bytes (clamped to
    /// [`MAX_PACKET_SIZE`]).
    ///
    /// Wire: `SALT? | HEADER_CIPHER(23) | [PAYLOAD_CIPHER + TAG]`.
    pub fn begin_write(&mut self, hint: usize) -> io::Result<WriteReservation> {
        if !self.pending_empty() {
            return Err(invalid_input("snell pending wire not fully written"));
        }

        let max_payload_len = hint.min(MAX_PACKET_SIZE);
        let first_record = !self.salt_sent;
        self.wire.clear();
        self.wire_pos = 0;
        self.pending_salt = first_record;
        self.wire.resize(
            HEADER_CIPHER_LEN + max_payload_len + usize::from(max_payload_len > 0) * TAG_LEN,
            0,
        );
        Ok(WriteReservation {
            plain_prefix_len: 0,
            head_start: 0,
            prefix_start: 0,
            prefix_len: 0,
            header_start: 0,
            padding_start: HEADER_CIPHER_LEN,
            padding_len: 0,
            payload_start: HEADER_CIPHER_LEN,
            max_payload_len,
        })
    }

    /// Borrow the plaintext payload slot for this reservation.
    pub fn plain_slot(&mut self, reservation: WriteReservation) -> &mut [u8] {
        &mut self.wire
            [reservation.payload_start..reservation.payload_start + reservation.max_payload_len]
    }

    /// Seal the record after the caller wrote `payload_len` bytes.
    ///
    /// Steps:
    /// ```text
    ///   1. write_v6_plain_header(0, payload_len)
    ///   2. seal header  (AEAD, nonce++, AAD empty)
    ///   3. seal payload (AEAD, nonce++, AAD empty)  if payload_len > 0
    /// ```
    pub fn finish_write(
        &mut self,
        reservation: WriteReservation,
        payload_len: usize,
    ) -> io::Result<()> {
        if payload_len > reservation.max_payload_len {
            return Err(invalid_input("snell payload exceeds reservation"));
        }

        let body_len = if payload_len == 0 {
            0
        } else {
            payload_len + TAG_LEN
        };
        self.wire.truncate(HEADER_CIPHER_LEN + body_len);
        write_v6_plain_header(&mut self.wire[..HEADER_PLAIN_LEN], 0, payload_len)?;
        seal_header(
            &self.key,
            &mut self.nonce,
            &[],
            &mut self.wire[..HEADER_CIPHER_LEN],
            "snell v6 unshaped header encrypt failed",
        )?;

        if payload_len > 0 {
            seal_payload(
                &self.key,
                &mut self.nonce,
                &[],
                &mut self.wire[reservation.payload_start..reservation.payload_start + body_len],
                payload_len,
                "snell v6 unshaped payload encrypt failed",
            )?;
        }

        self.salt_sent = true;
        self.wire_pos = 0;
        Ok(())
    }

    /// Whether all sealed bytes have been flushed.
    pub fn pending_empty(&self) -> bool {
        self.wire_pos >= self.pending_len()
    }

    /// Collect sealed bytes pending flush as vectored slices.
    ///
    /// Emission order: `[SALT?][HEADER_CIPHER][PAYLOAD_CIPHER + TAG]`.
    pub fn pending_wire<'a>(&'a self, out: &mut [IoSlice<'a>]) -> usize {
        let mut len = 0;
        let mut skip = self.wire_pos;
        if self.pending_salt {
            push_pending(out, &mut len, &mut skip, &self.salt);
        }
        push_pending(out, &mut len, &mut skip, &self.wire);
        len
    }

    /// Mark `written` sealed bytes as flushed, clearing the record when drained.
    pub fn advance_wire(&mut self, written: usize) {
        self.wire_pos = (self.wire_pos + written).min(self.pending_len());
        if self.pending_empty() {
            self.wire.clear();
            self.pending_salt = false;
            self.wire_pos = 0;
        }
    }

    /// Total pending bytes: `SALT? + HEADER_CIPHER + BODY`.
    fn pending_len(&self) -> usize {
        usize::from(self.pending_salt) * SALT_LEN + self.wire.len()
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
            read_buf: Vec::new(),
            body: Vec::new(),
            plain: 0..0,
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
    fn decode_header_in_place(&mut self) -> io::Result<DecodedHeader> {
        let nonce = next_nonce(&mut self.nonce);
        let (cipher, tag) = self.read_buf[..HEADER_CIPHER_LEN].split_at_mut(HEADER_PLAIN_LEN);
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
    fn finish_body(&mut self, header: DecodedHeader) -> io::Result<bool> {
        self.plain = 0..0;
        if header.payload_len == 0 {
            return Ok(false);
        }

        let key = self
            .key
            .as_ref()
            .ok_or_else(|| invalid_data("snell v6 unshaped reader key not initialized"))?;
        let body = &mut self.body[..header.body_len];
        let (payload_cipher, tag) = body.split_at_mut(header.payload_len);
        let tag = Tag::try_from(&tag[..]).map_err(|_| invalid_data("snell v6 invalid tag"))?;
        let nonce = next_nonce(&mut self.nonce);
        key.open_in_place_separate_tag(nonce, Aad::empty(), tag, payload_cipher, 0..)
            .map_err(|_| invalid_data("snell v6 unshaped payload decrypt failed"))?;
        self.plain = 0..header.payload_len;
        Ok(true)
    }

    /// Borrow the decrypted plaintext region from the current record.
    pub fn pending_plain(&self) -> &[u8] {
        &self.body[self.plain.clone()]
    }

    /// Mark `n` bytes from [`V6UnshapedDecoder::pending_plain`] as consumed.
    pub fn consume_plain(&mut self, n: usize) {
        let take = n.min(self.plain.len());
        self.plain.start += take;
        if self.plain.is_empty() {
            self.body.clear();
            self.plain = 0..0;
        }
    }
}

impl SnellTcpEncoder for V6UnshapedEncoder {
    type Reservation = WriteReservation;

    fn begin_plain_reservation(
        &mut self,
        prefix: PlainPrefix<'_>,
        payload_hint: usize,
    ) -> io::Result<Self::Reservation> {
        let mut reservation =
            V6UnshapedEncoder::begin_write(self, prefix.len().saturating_add(payload_hint))?;
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
        V6UnshapedEncoder::finish_write(self, reservation, payload_len)
    }

    fn cancel_plain_reservation(&mut self, _reservation: Self::Reservation) {
        self.wire.clear();
        self.pending_salt = false;
        self.wire_pos = 0;
    }

    fn pending_wire<'a>(&'a self, out: &mut [IoSlice<'a>]) -> usize {
        V6UnshapedEncoder::pending_wire(self, out)
    }

    fn advance_wire(&mut self, written: usize) {
        V6UnshapedEncoder::advance_wire(self, written);
    }
}

impl SnellTcpDecoder for V6UnshapedDecoder {
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
        V6UnshapedDecoder::consume_plain(self, n);
    }
}

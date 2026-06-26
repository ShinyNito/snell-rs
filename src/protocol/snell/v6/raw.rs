//! V6 unsafe-raw codec: unencrypted plaintext pass-through.
//!
//! No KDF, no AEAD, no padding. Every record is a plain header followed by
//! plaintext payload. **Only for local debugging** — never use this mode on
//! an untrusted network.
//!
//! # Wire layout
//!
//! ```text
//!   each record:   HEADER_PLAIN(7) | PAYLOAD
//!
//!   HEADER_PLAIN = [4][0][0][0][0][PAYLOAD_HI][PAYLOAD_LO]
//!   PAYLOAD      = application bytes (up to u16::MAX)
//!
//!   No salt, no AEAD tag, no padding.
//! ```

use std::{
    fmt,
    io::{self, IoSlice},
    ops::Range,
};

use crate::protocol::ParseState;

use super::super::{
    DecodeEvent, DecodedHeader, HEADER_PLAIN_LEN, MAX_PACKET_SIZE_V6, PendingWire, PlainPrefix,
    SnellTcpDecoder, SnellTcpEncoder, WriteReservation,
    common::{
        apply_plain_prefix, fill_from_input, finish_len_with_prefix, invalid_input, need_filled,
        parse_v6_raw_header_need, pending_plaintext_slice, plain_slot_with_prefix,
        write_v6_plain_header,
    },
};

/// V6 unsafe-raw encoder — plaintext frames, no crypto.
///
/// Wire state: `wire` buffers the current record until the runtime takes it.
pub struct V6UnsafeRawEncoder {
    wire: Vec<u8>,
}

impl fmt::Debug for V6UnsafeRawEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6UnsafeRawEncoder")
            .field("wire_len", &self.wire.len())
            .finish()
    }
}

/// V6 unsafe-raw decoder — plaintext frames, no crypto.
///
/// Read state machine: `Header → Body → Header → ...`
#[derive(Debug)]
pub struct V6UnsafeRawDecoder {
    read_step: RawReadStep,
    read_buf: Vec<u8>,
    body: Vec<u8>,
    plain: Range<usize>,
}

/// Decoder state machine arms.
#[derive(Clone, Copy, Debug)]
enum RawReadStep {
    /// Reading the 7-byte plaintext frame header.
    Header { filled: usize },
    /// Reading the frame body (plaintext payload).
    Body {
        header: DecodedHeader,
        filled: usize,
    },
}

impl V6UnsafeRawEncoder {
    /// Create an encoder with no crypto state.
    pub fn new() -> Self {
        Self { wire: Vec::new() }
    }

    /// Reserve a record sized for up to `hint` payload bytes.
    ///
    /// Sizes the payload slot by `min(hint, MAX_PACKET_SIZE_V6)`; no padding,
    /// no salt, no AEAD — the header is written in plaintext.
    pub fn begin_write(&mut self, hint: usize) -> io::Result<WriteReservation> {
        if !self.pending_empty() {
            return Err(invalid_input("snell pending wire not fully written"));
        }

        let max_payload_len = hint.min(MAX_PACKET_SIZE_V6);
        self.wire.clear();
        self.wire.resize(HEADER_PLAIN_LEN + max_payload_len, 0);
        Ok(WriteReservation {
            plain_prefix_len: 0,
            prefix_start: 0,
            prefix_len: 0,
            header_start: 0,
            padding_start: HEADER_PLAIN_LEN,
            padding_len: 0,
            payload_start: HEADER_PLAIN_LEN,
            max_payload_len,
        })
    }

    /// Borrow the plaintext payload slot for this reservation.
    pub fn plain_slot(&mut self, reservation: WriteReservation) -> &mut [u8] {
        &mut self.wire
            [reservation.payload_start..reservation.payload_start + reservation.max_payload_len]
    }

    /// Write the plaintext header and finalize the record.
    ///
    /// Layout: `HEADER_PLAIN(7) | PAYLOAD`.
    pub fn finish_write(
        &mut self,
        reservation: WriteReservation,
        payload_len: usize,
    ) -> io::Result<()> {
        if payload_len > reservation.max_payload_len {
            return Err(invalid_input("snell payload exceeds reservation"));
        }
        self.wire.truncate(HEADER_PLAIN_LEN + payload_len);
        write_v6_plain_header(&mut self.wire[..HEADER_PLAIN_LEN], 0, payload_len)?;
        Ok(())
    }

    /// Whether all pending wire bytes have been flushed.
    pub fn pending_empty(&self) -> bool {
        self.wire.is_empty()
    }

    pub fn take_pending_wire(&mut self) -> PendingWire {
        PendingWire::from_frame(std::mem::take(&mut self.wire))
    }

    pub fn restore_pending_wire(&mut self, wire: PendingWire) {
        let (_, frame) = wire.into_parts();
        self.wire = frame;
    }
}

impl Default for V6UnsafeRawEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl V6UnsafeRawDecoder {
    /// Create a decoder with no crypto state.
    pub fn new() -> Self {
        Self {
            read_step: RawReadStep::Header { filled: 0 },
            read_buf: Vec::new(),
            body: Vec::new(),
            plain: 0..0,
        }
    }

    /// Borrow the decrypted plaintext region from the current record.
    pub fn pending_plain(&self) -> &[u8] {
        &self.body[self.plain.clone()]
    }

    /// Mark `n` bytes from [`V6UnsafeRawDecoder::pending_plain`] as consumed.
    pub fn consume_plain(&mut self, n: usize) {
        let take = n.min(self.plain.len());
        self.plain.start += take;
        if self.plain.is_empty() {
            self.body.clear();
            self.plain = 0..0;
        }
    }
}

impl Default for V6UnsafeRawDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl SnellTcpEncoder for V6UnsafeRawEncoder {
    type Reservation = WriteReservation;

    fn begin_plain_reservation(
        &mut self,
        prefix: PlainPrefix<'_>,
        payload_hint: usize,
    ) -> io::Result<Self::Reservation> {
        let mut reservation =
            V6UnsafeRawEncoder::begin_write(self, prefix.len().saturating_add(payload_hint))?;
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
        V6UnsafeRawEncoder::finish_write(self, reservation, payload_len)
    }

    fn cancel_plain_reservation(&mut self, _reservation: Self::Reservation) {
        self.wire.clear();
    }

    fn take_pending_wire(&mut self) -> PendingWire {
        V6UnsafeRawEncoder::take_pending_wire(self)
    }

    fn restore_pending_wire(&mut self, wire: PendingWire) {
        V6UnsafeRawEncoder::restore_pending_wire(self, wire);
    }

    fn has_pending_wire(&self) -> bool {
        !self.pending_empty()
    }
}

impl SnellTcpDecoder for V6UnsafeRawDecoder {
    fn decode_ciphertext(&mut self, src: &mut &[u8]) -> io::Result<DecodeEvent<'_>> {
        if !self.pending_plain().is_empty() {
            return Ok(DecodeEvent::PlainData);
        }

        loop {
            match self.read_step {
                RawReadStep::Header { filled } => {
                    self.read_buf.resize(HEADER_PLAIN_LEN, 0);
                    let filled = fill_from_input(src, &mut self.read_buf, filled);
                    let header = match parse_v6_raw_header_need(&self.read_buf[..filled])? {
                        ParseState::Need(_) => {
                            self.read_step = RawReadStep::Header { filled };
                            return Ok(DecodeEvent::NeedMore);
                        }
                        ParseState::Done(header) => header,
                    };
                    if header.body_len == 0 {
                        self.read_step = RawReadStep::Header { filled: 0 };
                        return Ok(DecodeEvent::ZeroChunk);
                    }
                    self.read_step = RawReadStep::Body { header, filled: 0 };
                }
                RawReadStep::Body { header, filled } => {
                    self.body.resize(header.body_len, 0);
                    let filled = fill_from_input(src, &mut self.body, filled);
                    match need_filled(filled, header.body_len) {
                        ParseState::Need(_) => {
                            self.read_step = RawReadStep::Body { header, filled };
                            return Ok(DecodeEvent::NeedMore);
                        }
                        ParseState::Done(()) => {}
                    }
                    self.plain = 0..header.payload_len;
                    self.read_step = RawReadStep::Header { filled: 0 };
                    return Ok(DecodeEvent::PlainData);
                }
            }
        }
    }

    fn pending_plaintext<'a>(&'a self, out: &mut [IoSlice<'a>]) -> usize {
        pending_plaintext_slice(self.pending_plain(), out)
    }

    fn advance_plaintext(&mut self, n: usize) {
        V6UnsafeRawDecoder::consume_plain(self, n);
    }
}

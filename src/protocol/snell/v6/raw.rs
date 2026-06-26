//! V6 unsafe-raw codec: unencrypted plaintext pass-through.
//!
//! No KDF, no AEAD, no padding. Every record is a plain header followed by
//! an owned plaintext payload buffer. **Only for local debugging** — never use
//! this mode on an untrusted network.
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
};

use compio::buf::{IoBuf, IoBufMut};

use super::super::{
    DecodeEvent, DecodedHeader, HEADER_PLAIN_LEN, MAX_PACKET_SIZE_V6, PendingWire,
    PendingWireSegment, PlaintextFrame, PlaintextSegment, SnellTcpDecoder, SnellTcpEncoder,
    common::{
        invalid_data, invalid_input, parse_done, parse_v6_raw_header_need, pending_plaintext_slice,
        write_v6_plain_header,
    },
};

/// V6 unsafe-raw encoder — plaintext frames, no crypto.
///
/// Wire state: `pending` owns sealed record segments until the runtime takes it.
pub struct V6UnsafeRawEncoder {
    pending: PendingWire,
}

impl fmt::Debug for V6UnsafeRawEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6UnsafeRawEncoder")
            .field("pending_len", &self.pending.total_len())
            .finish()
    }
}

/// V6 unsafe-raw decoder — plaintext frames, no crypto.
///
/// Read state machine: `Header → Body → Header → ...`
#[derive(Debug)]
pub struct V6UnsafeRawDecoder {
    read_step: RawReadStep,
    plain: PlaintextFrame,
}

/// Decoder state machine arms.
#[derive(Clone, Copy, Debug)]
enum RawReadStep {
    /// Reading the 7-byte plaintext frame header.
    Header,
    /// Reading the frame body (plaintext payload).
    Body { header: DecodedHeader },
}

impl V6UnsafeRawEncoder {
    /// Create an encoder with no crypto state.
    pub fn new() -> Self {
        Self {
            pending: PendingWire::default(),
        }
    }

    fn seal_owned_payload<B>(&mut self, payload: B) -> io::Result<()>
    where
        B: IoBufMut + Into<PendingWireSegment>,
    {
        if !self.pending_empty() {
            return Err(invalid_input("snell pending wire not fully written"));
        }
        let payload_len = payload.as_init().len();
        if payload_len > MAX_PACKET_SIZE_V6 {
            return Err(invalid_input("snell payload exceeds record capacity"));
        }

        let mut header = [0; HEADER_PLAIN_LEN];
        write_v6_plain_header(&mut header, 0, payload_len)?;

        let mut pending = PendingWire::default();
        pending.push(header);
        pending.push(payload);
        self.pending = pending;
        Ok(())
    }

    /// Whether all pending wire bytes have been flushed.
    pub fn pending_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn take_pending_wire(&mut self) -> PendingWire {
        std::mem::take(&mut self.pending)
    }

    pub fn restore_pending_wire(&mut self, wire: PendingWire) {
        self.pending = wire;
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
            read_step: RawReadStep::Header,
            plain: PlaintextFrame::default(),
        }
    }

    /// Borrow the decrypted plaintext region from the current record.
    pub fn pending_plain(&self) -> &[u8] {
        self.plain.as_init()
    }

    /// Mark `n` bytes from [`V6UnsafeRawDecoder::pending_plain`] as consumed.
    pub fn consume_plain(&mut self, n: usize) {
        self.plain.advance(n);
    }

    pub fn take_pending_plain(&mut self) -> Option<PlaintextFrame> {
        if self.plain.is_empty() {
            return None;
        }
        Some(std::mem::take(&mut self.plain))
    }
}

impl Default for V6UnsafeRawDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl SnellTcpEncoder for V6UnsafeRawEncoder {
    fn next_plain_capacity(&self) -> usize {
        MAX_PACKET_SIZE_V6
    }

    fn seal_plain<B>(&mut self, payload: B) -> io::Result<()>
    where
        B: IoBufMut + Into<PendingWireSegment>,
    {
        self.seal_owned_payload(payload)
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
    fn next_cipher_len(&self) -> usize {
        if !self.pending_plain().is_empty() {
            return 0;
        }
        match self.read_step {
            RawReadStep::Header => HEADER_PLAIN_LEN,
            RawReadStep::Body { header } => header.body_len,
        }
    }

    fn decode_ciphertext<B>(&mut self, input: B) -> io::Result<DecodeEvent<'_>>
    where
        B: IoBufMut + Into<PlaintextSegment>,
    {
        if !self.pending_plain().is_empty() {
            return Ok(DecodeEvent::PlainData);
        }

        match self.read_step {
            RawReadStep::Header => {
                if input.as_init().len() != HEADER_PLAIN_LEN {
                    return Err(invalid_data("snell v6 raw header length mismatch"));
                }
                let header = parse_done(
                    parse_v6_raw_header_need(input.as_init())?,
                    "snell v6 raw short header",
                )?;
                if header.body_len == 0 {
                    self.read_step = RawReadStep::Header;
                    return Ok(DecodeEvent::ZeroChunk);
                }
                self.read_step = RawReadStep::Body { header };
                Ok(DecodeEvent::NeedMore)
            }
            RawReadStep::Body { header } => {
                if input.as_init().len() != header.body_len {
                    return Err(invalid_data("snell v6 raw body length mismatch"));
                }
                self.plain = PlaintextFrame::from_segment(input, 0..header.payload_len);
                self.read_step = RawReadStep::Header;
                Ok(DecodeEvent::PlainData)
            }
        }
    }

    fn pending_plaintext<'a>(&'a self, out: &mut [IoSlice<'a>]) -> usize {
        pending_plaintext_slice(self.pending_plain(), out)
    }

    fn advance_plaintext(&mut self, n: usize) {
        V6UnsafeRawDecoder::consume_plain(self, n);
    }

    fn take_pending_plaintext(&mut self) -> Option<PlaintextFrame> {
        V6UnsafeRawDecoder::take_pending_plain(self)
    }
}

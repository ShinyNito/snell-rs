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

use std::{fmt, io};

use bytes::{Buf, Bytes, BytesMut};

use super::super::{
    DecodeEvent, DecodedHeader, HEADER_PLAIN_LEN, MAX_PACKET_SIZE_V6, SnellTcpDecoder,
    SnellTcpEncoder,
    common::{invalid_input, parse_done, parse_v6_raw_header_need, write_v6_plain_header},
};

/// V6 unsafe-raw encoder — plaintext frames, no crypto.
///
/// Stateless beyond record framing: each [`SnellTcpEncoder::seal_plain`] call
/// produces one owned [`Bytes`] record.
pub struct V6UnsafeRawEncoder;

impl Default for V6UnsafeRawEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for V6UnsafeRawEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6UnsafeRawEncoder").finish()
    }
}

/// V6 unsafe-raw decoder — plaintext frames, no crypto.
///
/// Read state machine: `Header → Body → Header → ...`. Partial records are
/// accumulated in `buf`; each completed body is decrypted (a no-op here) in
/// place and exposed via `plain`.
#[derive(Debug)]
pub struct V6UnsafeRawDecoder {
    step: RawReadStep,
    buf: BytesMut,
    plain: BytesMut,
}

/// Decoder state machine arms.
#[derive(Clone, Copy, Debug)]
enum RawReadStep {
    /// Reading the 7-byte plaintext frame header; `filled` bytes already consumed from `buf`.
    Header { filled: usize },
    /// Reading the frame body; `filled` bytes of `header.body_len` already consumed from `buf`.
    Body {
        header: DecodedHeader,
        filled: usize,
    },
}

impl V6UnsafeRawEncoder {
    /// Create an encoder with no crypto state.
    pub fn new() -> Self {
        Self
    }
}

impl V6UnsafeRawDecoder {
    /// Create a decoder with no crypto state.
    pub fn new() -> Self {
        Self {
            step: RawReadStep::Header { filled: 0 },
            buf: BytesMut::new(),
            plain: BytesMut::new(),
        }
    }

    /// The decrypted plaintext region of the current record (the sole source).
    pub fn pending_plain(&self) -> &[u8] {
        &self.plain
    }

    /// Mark `n` bytes from [`pending_plain`](Self::pending_plain) as consumed.
    pub fn consume_plain(&mut self, n: usize) {
        let n = n.min(self.plain.len());
        self.plain.advance(n);
    }

    /// Advance the decode state machine as far as `buf` allows.
    ///
    /// Emits a non-`NeedMore` event as soon as one record finishes; the caller
    /// drains plaintext (or handles a control frame) before feeding again.
    /// Raw mode never produces a borrowed `ServerError`, so the event borrows
    /// nothing.
    fn try_drain(&mut self) -> io::Result<DecodeEvent<'static>> {
        if !self.pending_plain().is_empty() {
            return Ok(DecodeEvent::PlainData);
        }

        loop {
            match self.step {
                RawReadStep::Header { filled } => {
                    if filled >= HEADER_PLAIN_LEN {
                        let header = parse_done(
                            parse_v6_raw_header_need(&self.buf[..HEADER_PLAIN_LEN])?,
                            "snell v6 raw short header",
                        )?;
                        self.buf.advance(HEADER_PLAIN_LEN);
                        if header.body_len == 0 {
                            self.step = RawReadStep::Header { filled: 0 };
                            return Ok(DecodeEvent::ZeroChunk);
                        }
                        self.step = RawReadStep::Body { header, filled: 0 };
                        continue;
                    }
                    return Ok(DecodeEvent::NeedMore);
                }
                RawReadStep::Body { header, filled } => {
                    if filled >= header.body_len {
                        // Raw mode has no crypto: the plaintext is the body.
                        self.plain = self.buf.split_to(header.payload_len);
                        self.step = RawReadStep::Header { filled: 0 };
                        return Ok(DecodeEvent::PlainData);
                    }
                    return Ok(DecodeEvent::NeedMore);
                }
            }
        }
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

    fn seal_plain(&mut self, payload: BytesMut) -> io::Result<Vec<Bytes>> {
        let payload_len = payload.len();
        if payload_len > MAX_PACKET_SIZE_V6 {
            return Err(invalid_input("snell payload exceeds record capacity"));
        }

        let mut header = [0u8; HEADER_PLAIN_LEN];
        write_v6_plain_header(&mut header, 0, payload_len)?;
        // Two segments: plaintext header, then the payload buffer moved as-is.
        Ok(vec![Bytes::from(header.to_vec()), payload.freeze()])
    }
}

impl SnellTcpDecoder for V6UnsafeRawDecoder {
    fn feed_owned(&mut self, chunk: BytesMut) -> io::Result<DecodeEvent<'_>> {
        // The `filled` cursor counts bytes consumed from `buf` for the current
        // step. Feeding a new chunk grows `buf`; recompute how many bytes of
        // the current step's target are now available and clamp the cursor.
        let target = match self.step {
            RawReadStep::Header { .. } => HEADER_PLAIN_LEN,
            RawReadStep::Body { header, .. } => header.body_len,
        };
        let available = self.buf.len() + chunk.len();
        let filled = target.min(available);
        if self.buf.is_empty() {
            self.buf = chunk;
        } else if !chunk.is_empty() {
            self.buf.extend_from_slice(&chunk);
        }
        self.step = match self.step {
            RawReadStep::Header { .. } => RawReadStep::Header { filled },
            RawReadStep::Body { header, .. } => RawReadStep::Body { header, filled },
        };

        self.try_drain()
    }

    fn pending_plain(&self) -> &[u8] {
        V6UnsafeRawDecoder::pending_plain(self)
    }

    fn consume_plain(&mut self, n: usize) {
        V6UnsafeRawDecoder::consume_plain(self, n);
    }

    fn take_plain(&mut self) -> BytesMut {
        std::mem::take(&mut self.plain)
    }
}

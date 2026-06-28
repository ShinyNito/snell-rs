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

use super::super::{
    DecodeEvent, DecodedHeader, HEADER_PLAIN_LEN, MAX_PACKET_SIZE_V6, SnellBuffer, SnellTcpDecoder,
    SnellTcpEncoder, SnellWire,
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
/// Read state machine: `Header → Body → Header → ...`. The reader feeds exact
/// chunks; completed bodies are exposed through `plain`.
#[derive(Debug)]
pub struct V6UnsafeRawDecoder {
    step: RawReadStep,
    plain: SnellBuffer,
}

/// Decoder state machine arms.
#[derive(Clone, Copy, Debug)]
enum RawReadStep {
    /// Reading the 7-byte plaintext frame header.
    Header,
    /// Reading the frame body described by `header`.
    Body { header: DecodedHeader },
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
            step: RawReadStep::Header,
            plain: SnellBuffer::empty(),
        }
    }

    /// The decrypted plaintext region of the current record (the sole source).
    pub fn pending_plain(&self) -> &[u8] {
        self.plain.as_slice()
    }

    /// Mark `n` bytes from [`pending_plain`](Self::pending_plain) as consumed.
    pub fn consume_plain(&mut self, n: usize) {
        let n = n.min(self.plain.len());
        self.plain.advance(n);
        if self.plain.is_empty() {
            self.plain = SnellBuffer::empty();
        }
    }

    fn exact_chunk_mismatch(&self) -> io::Error {
        invalid_input(match self.step {
            RawReadStep::Header => "snell v6 raw header chunk length mismatch",
            RawReadStep::Body { .. } => "snell v6 raw body chunk length mismatch",
        })
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

    fn seal_plain(&mut self, payload: SnellBuffer, wire: &mut SnellWire) -> io::Result<()> {
        wire.clear();
        let payload_len = payload.len();
        if payload_len > MAX_PACKET_SIZE_V6 {
            return Err(invalid_input("snell payload exceeds record capacity"));
        }

        let mut header = [0u8; HEADER_PLAIN_LEN];
        write_v6_plain_header(&mut header, 0, payload_len)?;
        wire.push_head_zeroed(HEADER_PLAIN_LEN)
            .copy_from_slice(&header);
        wire.push_buffer(payload);
        Ok(())
    }
}

impl SnellTcpDecoder for V6UnsafeRawDecoder {
    fn next_ciphertext_read_len(&self) -> usize {
        if !self.plain.is_empty() {
            return 0;
        }
        match self.step {
            RawReadStep::Header => HEADER_PLAIN_LEN,
            RawReadStep::Body { header } => header.body_len,
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

        match self.step {
            RawReadStep::Header => {
                let header = parse_done(
                    parse_v6_raw_header_need(chunk.as_slice())?,
                    "snell v6 raw short header",
                )?;
                if header.body_len == 0 {
                    self.step = RawReadStep::Header;
                    Ok(DecodeEvent::ZeroChunk)
                } else {
                    self.step = RawReadStep::Body { header };
                    Ok(DecodeEvent::NeedMore)
                }
            }
            RawReadStep::Body { header } => {
                let mut chunk = chunk;
                chunk.truncate(header.payload_len);
                self.plain = chunk;
                self.step = RawReadStep::Header;
                Ok(DecodeEvent::PlainData)
            }
        }
    }

    fn pending_plain(&self) -> &[u8] {
        V6UnsafeRawDecoder::pending_plain(self)
    }

    fn consume_plain(&mut self, n: usize) {
        V6UnsafeRawDecoder::consume_plain(self, n);
    }

    fn take_plain(&mut self) -> SnellBuffer {
        std::mem::replace(&mut self.plain, SnellBuffer::empty())
    }
}

//! v6 unsafe-raw: plaintext header + payload. Compiled only with `unsafe-raw`.

use core::fmt;

use crate::buffer::{Reservation, Slot};
use crate::codec::RecordEncoder;
use crate::codec::header::{parse_v6_plain_header, plain_header};
use crate::codec::record::{DecodeStatus, DecodedRecord, EncoderState, Pending};
use crate::codec::sealed::Seal;
use crate::{Buffer, Error, HEADER_PLAIN_LEN, MAX_PACKET_SIZE_V6, Result};

#[derive(Default)]
pub struct V6UnsafeRawEncoder {
    state: EncoderState,
}

impl V6UnsafeRawEncoder {
    pub fn new() -> Self {
        Self::default()
    }
}

impl RecordEncoder for V6UnsafeRawEncoder {
    fn reserve<'a>(
        &'a mut self,
        buf: &'a mut Buffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<Reservation<'a, Self>> {
        self.state.ensure_ready()?;
        let max_payload = prefix.len().saturating_add(hint).min(MAX_PACKET_SIZE_V6);
        if prefix.len() > max_payload {
            return Err(Error::PayloadTooLarge);
        }
        let record_start = buf.reserve_record(HEADER_PLAIN_LEN + max_payload, HEADER_PLAIN_LEN)?;
        buf.extend_from_slice(prefix)?;
        let slot = Slot {
            record_start,
            payload_start: record_start + HEADER_PLAIN_LEN,
            prefix_len: prefix.len(),
            max_payload,
        };
        Ok(Reservation::new(self, buf, slot, ()))
    }
}

impl Seal for V6UnsafeRawEncoder {
    type Record = ();

    fn state(&mut self) -> &mut EncoderState {
        &mut self.state
    }

    fn finish(
        &mut self,
        buf: &mut Buffer,
        slot: &Slot,
        _: &(),
        payload_len: usize,
    ) -> Result<usize> {
        buf.set_record_end(slot.payload_start + payload_len);
        buf.range_mut(slot.record_start, slot.payload_start)
            .copy_from_slice(&plain_header(0, payload_len));
        self.state = EncoderState::Ready;
        Ok(0)
    }
}

impl fmt::Debug for V6UnsafeRawEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6UnsafeRawEncoder")
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Clone, Copy, Debug)]
enum ReadStep {
    Header,
    Body { len: usize },
}

pub struct V6UnsafeRawDecoder {
    step: ReadStep,
    pending: Pending,
}

impl V6UnsafeRawDecoder {
    pub fn new() -> Self {
        Self {
            step: ReadStep::Header,
            pending: Pending::default(),
        }
    }

    pub fn replay_identity(&self) -> Option<[u8; crate::SALT_LEN]> {
        None
    }

    pub fn decode(&mut self, buf: &mut Buffer) -> Result<DecodeStatus> {
        loop {
            match self.step {
                ReadStep::Header => {
                    let off = self.pending.offset();
                    let header_end = off + HEADER_PLAIN_LEN;
                    if let Some(need) = self.pending.need(buf, header_end)? {
                        return Ok(need);
                    }
                    let header = buf.filled()[off..].first_chunk().ok_or(Error::Truncated)?;
                    let len = parse_v6_plain_header(header)?.body_len_v6_raw()?;
                    if len == 0 {
                        return Ok(self.pending.zero_chunk(header_end));
                    }
                    self.step = ReadStep::Body { len };
                }
                ReadStep::Body { len } => {
                    let body_off = self.pending.offset() + HEADER_PLAIN_LEN;
                    let body_end = body_off + len;
                    if let Some(need) = self.pending.need(buf, body_end)? {
                        return Ok(need);
                    }
                    self.step = ReadStep::Header;
                    return Ok(self.pending.data(body_end, body_off..body_end));
                }
            }
        }
    }

    pub fn consume(&mut self, buf: &mut Buffer, record: &DecodedRecord) -> Result<()> {
        self.pending.consume(buf, record)
    }
}

impl Default for V6UnsafeRawDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for V6UnsafeRawDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6UnsafeRawDecoder")
            .field("pending", &self.pending.offset())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::header::RecordHeader;

    fn seal(encoder: &mut V6UnsafeRawEncoder, out: &mut Buffer, payload: &[u8]) {
        let mut rec = encoder.reserve(out, &[], payload.len()).unwrap();
        rec.payload_mut()[..payload.len()].copy_from_slice(payload);
        rec.seal(payload.len()).unwrap();
    }

    #[test]
    fn records_are_plain_header_plus_payload_and_decode_ahead() {
        let mut enc = V6UnsafeRawEncoder::new();
        let mut out = Buffer::new(64);
        seal(&mut enc, &mut out, b"hello");
        assert_eq!(out.filled(), b"\x04\x00\x00\x00\x00\x00\x05hello");
        seal(&mut enc, &mut out, b"world");
        let wire = out.filled().to_vec();

        let mut decoder = V6UnsafeRawDecoder::new();
        let mut buf = Buffer::new(64);
        buf.extend_from_slice(&wire).unwrap();
        let DecodeStatus::Record(first) = decoder.decode(&mut buf).unwrap() else {
            panic!("first record not ready");
        };
        let DecodeStatus::Record(second) = decoder.decode(&mut buf).unwrap() else {
            panic!("second record not ready");
        };
        assert_eq!(first.plaintext(buf.filled()), b"hello");
        assert_eq!(second.plaintext(buf.filled()), b"world");
        assert_eq!(first.consumed + second.consumed, wire.len());
        decoder.consume(&mut buf, &first).unwrap();
        decoder.consume(&mut buf, &second).unwrap();
        assert!(buf.is_empty());
        assert_eq!(
            decoder.consume(&mut buf, &second),
            Err(Error::PlaintextNotDrained)
        );
        assert!(decoder.replay_identity().is_none());
    }

    #[test]
    fn dropped_reservation_cancels_and_padding_is_rejected() {
        let mut enc = V6UnsafeRawEncoder::new();
        let mut out = Buffer::new(64);
        drop(enc.reserve(&mut out, b"pfx", 8).unwrap());
        assert!(out.is_empty());
        seal(&mut enc, &mut out, b"x");
        assert_eq!(out.len(), HEADER_PLAIN_LEN + 1);

        let padded = RecordHeader {
            padding_len: 1,
            payload_len: 1,
        };
        assert_eq!(padded.body_len_v6_raw(), Err(Error::InvalidHeader));
    }
}

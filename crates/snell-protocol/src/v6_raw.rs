//! v6 unsafe-raw: plaintext header + payload. Compiled only with `unsafe-raw`.

use core::fmt;

use crate::buffer::Slot;
use crate::header::{parse_v6_plain_header, plain_header};
use crate::record::{DecodeStatus, DecodedRecord, EncoderState, Pending};
use crate::{Buffer, Error, HEADER_PLAIN_LEN, MAX_PACKET_SIZE_V6, Result};

#[derive(Default)]
pub struct V6UnsafeRawEncoder {
    state: EncoderState,
}

#[must_use = "unsealed reservations are cancelled on drop"]
pub struct V6UnsafeRawReservation<'a> {
    encoder: &'a mut V6UnsafeRawEncoder,
    buf: &'a mut Buffer,
    slot: Slot,
}

impl V6UnsafeRawEncoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reserve<'buf>(
        &'buf mut self,
        buf: &'buf mut Buffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<V6UnsafeRawReservation<'buf>> {
        self.state.ensure_ready()?;
        let max_payload = prefix.len().saturating_add(hint).min(MAX_PACKET_SIZE_V6);
        if prefix.len() > max_payload {
            return Err(Error::PayloadTooLarge);
        }
        let record_start = buf.reserve_zeroed(HEADER_PLAIN_LEN + max_payload)?;
        let payload_start = record_start + HEADER_PLAIN_LEN;
        buf.range_mut(payload_start, payload_start + prefix.len())
            .copy_from_slice(prefix);
        self.state = EncoderState::Reserving;
        Ok(V6UnsafeRawReservation {
            encoder: self,
            buf,
            slot: Slot {
                record_start,
                payload_start,
                prefix_len: prefix.len(),
                max_payload,
            },
        })
    }
}

impl V6UnsafeRawReservation<'_> {
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let slot = &self.slot;
        self.buf.range_mut(
            slot.payload_start + slot.prefix_len,
            slot.payload_start + slot.max_payload,
        )
    }

    pub fn capacity(&self) -> usize {
        self.slot.capacity()
    }

    pub fn seal(self, written: usize) -> Result<()> {
        let total = self.slot.total(written)?;
        self.buf.set_record_end(self.slot.payload_start + total);
        self.buf
            .range_mut(self.slot.record_start, self.slot.payload_start)
            .copy_from_slice(&plain_header(0, total));
        self.encoder.state = EncoderState::Ready;
        Ok(())
    }
}

impl Drop for V6UnsafeRawReservation<'_> {
    fn drop(&mut self) {
        if self.encoder.state == EncoderState::Reserving {
            let _ = self.buf.truncate(self.slot.record_start);
            self.encoder.state = EncoderState::Ready;
        }
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
    use crate::header::RecordHeader;

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

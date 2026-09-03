//! v6 unsafe-raw: plaintext header + payload. Compiled only with `unsafe-raw`.

use core::fmt;

use crate::header::{parse_v6_plain_header, write_v6_plain_header};
use crate::record::{DecodeStatus, DecodedRecord, RecordKind};
use crate::{EncodeBuffer, Error, HEADER_PLAIN_LEN, MAX_PACKET_SIZE_V6, RecvBuffer, Result};

pub struct V6UnsafeRawEncoder {
    reserving: bool,
    prefix_len: usize,
    max_payload: usize,
    payload_start: usize,
    header_start: usize,
    record_start: usize,
}

#[must_use = "unsealed reservations are cancelled on drop"]
pub struct V6UnsafeRawReservation<'a> {
    encoder: &'a mut V6UnsafeRawEncoder,
    buf: &'a mut EncodeBuffer,
    sealed: bool,
}

impl V6UnsafeRawEncoder {
    pub fn new() -> Self {
        Self {
            reserving: false,
            prefix_len: 0,
            max_payload: 0,
            payload_start: 0,
            header_start: 0,
            record_start: 0,
        }
    }

    pub fn reserve<'buf>(
        &'buf mut self,
        buf: &'buf mut EncodeBuffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<V6UnsafeRawReservation<'buf>> {
        if self.reserving {
            return Err(Error::PendingWire);
        }
        let needed = prefix.len().saturating_add(hint);
        let max_payload = needed.min(MAX_PACKET_SIZE_V6);
        if prefix.len() > max_payload {
            return Err(Error::PayloadTooLarge);
        }
        let record_cap = HEADER_PLAIN_LEN + max_payload;
        let record_start = buf.reserve_zeroed(record_cap)?;
        let header_start = record_start;
        let payload_start = header_start + HEADER_PLAIN_LEN;
        if !prefix.is_empty() {
            buf.range_mut(payload_start, payload_start + prefix.len())
                .copy_from_slice(prefix);
        }
        self.prefix_len = prefix.len();
        self.max_payload = max_payload;
        self.payload_start = payload_start;
        self.header_start = header_start;
        self.record_start = record_start;
        self.reserving = true;
        Ok(V6UnsafeRawReservation {
            encoder: self,
            buf,
            sealed: false,
        })
    }

    fn finish(&mut self, buf: &mut EncodeBuffer, payload_len: usize) -> Result<()> {
        if payload_len > self.max_payload {
            self.reserving = false;
            buf.truncate(self.record_start)?;
            return Err(Error::PayloadTooLarge);
        }
        buf.truncate(self.payload_start + payload_len)?;
        write_v6_plain_header(
            buf.range_mut(self.header_start, self.header_start + HEADER_PLAIN_LEN),
            0,
            payload_len,
        )?;
        self.reserving = false;
        Ok(())
    }
}

impl Default for V6UnsafeRawEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl V6UnsafeRawReservation<'_> {
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let start = self.encoder.payload_start + self.encoder.prefix_len;
        let end = self.encoder.payload_start + self.encoder.max_payload;
        self.buf.range_mut(start, end)
    }

    pub fn capacity(&self) -> usize {
        self.encoder.max_payload - self.encoder.prefix_len
    }

    pub fn seal(mut self, written: usize) -> Result<()> {
        let total = self
            .encoder
            .prefix_len
            .checked_add(written)
            .ok_or(Error::PayloadTooLarge)?;
        if total > self.encoder.max_payload {
            return Err(Error::PayloadTooLarge);
        }
        self.sealed = true;
        self.encoder.finish(self.buf, total)
    }
}

impl Drop for V6UnsafeRawReservation<'_> {
    fn drop(&mut self) {
        if !self.sealed {
            let _ = self.buf.truncate(self.encoder.record_start);
            self.encoder.reserving = false;
        }
    }
}

impl fmt::Debug for V6UnsafeRawEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6UnsafeRawEncoder")
            .field("reserving", &self.reserving)
            .finish()
    }
}

#[derive(Clone, Copy, Debug)]
enum ReadStep {
    Header,
    Body(crate::RecordHeader),
}

pub struct V6UnsafeRawDecoder {
    step: ReadStep,
    busy: bool,
}

impl V6UnsafeRawDecoder {
    pub fn new() -> Self {
        Self {
            step: ReadStep::Header,
            busy: false,
        }
    }

    pub fn replay_identity(&self) -> Option<[u8; crate::SALT_LEN]> {
        None
    }

    pub fn decode(&mut self, buf: &mut RecvBuffer) -> Result<DecodeStatus> {
        if self.busy {
            return Err(Error::PlaintextNotDrained);
        }
        loop {
            match self.step {
                ReadStep::Header => {
                    if let Some(need) = Self::decode_need(buf, HEADER_PLAIN_LEN)? {
                        return Ok(need);
                    }
                    let header = parse_v6_plain_header(&buf.filled()[..HEADER_PLAIN_LEN])?;
                    let body_len = header.body_len_v6_raw()?;
                    if body_len == 0 {
                        self.step = ReadStep::Header;
                        self.busy = true;
                        return Ok(DecodeStatus::Record(DecodedRecord {
                            consumed: HEADER_PLAIN_LEN,
                            plaintext: 0..0,
                            kind: RecordKind::ZeroChunk,
                        }));
                    }
                    self.step = ReadStep::Body(header);
                }
                ReadStep::Body(header) => {
                    let body_len = header.body_len_v6_raw()?;
                    let needed = HEADER_PLAIN_LEN + body_len;
                    if let Some(need) = Self::decode_need(buf, needed)? {
                        return Ok(need);
                    }
                    self.step = ReadStep::Header;
                    self.busy = true;
                    return Ok(DecodeStatus::Record(DecodedRecord {
                        consumed: needed,
                        plaintext: HEADER_PLAIN_LEN..needed,
                        kind: RecordKind::Data,
                    }));
                }
            }
        }
    }

    pub fn consume(&mut self, buf: &mut RecvBuffer, record: &DecodedRecord) -> Result<()> {
        buf.consume(record.consumed)?;
        self.busy = false;
        Ok(())
    }

    fn decode_need(buf: &RecvBuffer, minimum: usize) -> Result<Option<DecodeStatus>> {
        if minimum > buf.max() {
            Err(Error::PayloadTooLarge)
        } else if buf.len() < minimum {
            Ok(Some(DecodeStatus::NeedMore { minimum }))
        } else {
            Ok(None)
        }
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
            .field("busy", &self.busy)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EncodeBuffer;

    fn collect(buf: &EncodeBuffer) -> Vec<u8> {
        buf.pending().to_vec()
    }

    #[test]
    fn hello_is_plain_header_plus_payload() {
        let mut enc = V6UnsafeRawEncoder::new();
        let mut out = EncodeBuffer::new(64);
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"hello");
            rec.seal(5).unwrap();
        }
        let wire = collect(&out);
        assert_eq!(wire[0], 4);
        assert_eq!(&wire[1..5], &[0, 0, 0, 0]);
        assert_eq!(&wire[5..7], &5u16.to_be_bytes());
        assert_eq!(&wire[7..], b"hello");

        let mut decoder = V6UnsafeRawDecoder::new();
        let mut buf = RecvBuffer::new(64);
        buf.extend_from_slice(&wire).unwrap();
        match decoder.decode(&mut buf).unwrap() {
            DecodeStatus::Record(record) => {
                assert_eq!(record.plaintext(buf.filled()), b"hello");
                decoder.consume(&mut buf, &record).unwrap();
            }
            other => panic!("{other:?}"),
        }
        assert!(decoder.replay_identity().is_none());
    }

    #[test]
    fn two_records_concat() {
        let mut enc = V6UnsafeRawEncoder::new();
        let mut out = EncodeBuffer::new(64);
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"hello");
            rec.seal(5).unwrap();
        }
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"world");
            rec.seal(5).unwrap();
        }
        let wire = collect(&out);
        let mut decoder = V6UnsafeRawDecoder::new();
        let mut buf = RecvBuffer::new(64);
        buf.extend_from_slice(&wire).unwrap();
        let mut plain = Vec::new();
        loop {
            match decoder.decode(&mut buf).unwrap() {
                DecodeStatus::NeedMore { .. } => break,
                DecodeStatus::Record(record) => {
                    if record.kind == RecordKind::Data {
                        plain.extend_from_slice(record.plaintext(buf.filled()));
                    }
                    decoder.consume(&mut buf, &record).unwrap();
                }
            }
        }
        assert_eq!(plain, b"helloworld");
    }

    #[test]
    fn padding_nonzero_rejected() {
        let mut header = [4, 0, 0, 0, 1, 0, 1];
        header[3] = 0;
        header[4] = 1;
        let parsed = parse_v6_plain_header(&header).unwrap();
        assert!(parsed.body_len_v6_raw().is_err());
    }
}

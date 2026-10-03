//! v6 shaped record codec: profile salt-block, prefix, padding mix, AAD.

use core::fmt;

use crate::buffer::{Reservation, Slot};
use crate::codec::header::{RecordHeader, opened_header, parse_v6_plain_header, plain_header};
use crate::codec::record::{DecodeStatus, DecodedRecord, EncoderState, Pending};
use crate::codec::sealed::Seal;
use crate::codec::v6::profile::mix_padding_payload;
use crate::codec::{RecordDecoder, RecordEncoder};
use crate::crypto::aead::Aes128Gcm;
use crate::{
    AES_128_KEY_LEN, Buffer, Clock, Entropy, Error, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN,
    MAX_PACKET_SIZE_V6, MonotonicClock, Nonce, OsEntropy, Psk, Result, SALT_LEN, TAG_LEN,
};

/// v6 shaped record encoder.
///
/// Records are sealed with the payload left where the caller wrote it, at
/// the record start: `[payload+tag][salt block][prefix][header][padding]`.
/// The split [`Reservation::seal`] returns puts them back in wire order.
pub struct V6ShapedEncoder<C = MonotonicClock> {
    aead: Aes128Gcm,
    nonce: Nonce,
    salt: [u8; SALT_LEN],
    seq: u32,
    /// Shared key; its derived profile shapes every record.
    psk: Psk,
    chunk_size: usize,
    /// `None` until the first record, which carries the salt block, is sealed.
    last_write_secs: Option<u64>,
    clock: C,
    state: EncoderState,
}

/// Per-record layout decided by [`V6ShapedEncoder::reserve`].
#[derive(Clone, Copy, Debug)]
pub struct ShapedRecord {
    salt_block_len: usize,
    /// Length of the profile's record prefix, the header's AAD.
    prefix_len: usize,
}

impl<C: Clock> V6ShapedEncoder<C> {
    pub fn new(psk: &Psk, mut entropy: impl Entropy, clock: C) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        entropy.fill(&mut salt)?;
        Self::with_salt(psk, salt, clock)
    }

    pub fn with_salt(psk: &Psk, salt: [u8; SALT_LEN], clock: C) -> Result<Self> {
        Ok(Self {
            aead: Aes128Gcm::derive(psk, &salt)?,
            nonce: Nonce::new(),
            salt,
            seq: 0,
            psk: psk.clone(),
            chunk_size: 0,
            last_write_secs: None,
            clock,
            state: EncoderState::Ready,
        })
    }

    fn payload_budget(&mut self, now: u64) -> usize {
        if self.chunk_size == 0
            || self
                .last_write_secs
                .is_some_and(|last| now.saturating_sub(last) > self.psk.profile().idle_reset_secs())
        {
            self.chunk_size = self.psk.profile().chunk_initial();
        }
        let limit = self
            .psk
            .profile()
            .chunk_limit(self.seq, self.chunk_size)
            .min(MAX_PACKET_SIZE_V6);
        if self.seq == 0 {
            limit.min(self.psk.profile().first_record_cap())
        } else {
            limit
        }
    }

    /// Returns the record's split: the payload and tag length.
    fn seal_record(
        &mut self,
        buf: &mut Buffer,
        slot: &Slot,
        record: &ShapedRecord,
        padding_len: usize,
        payload_len: usize,
    ) -> Result<usize> {
        let profile = self.psk.profile();
        let body_len = if payload_len == 0 {
            0
        } else {
            payload_len + TAG_LEN
        };
        let prefix_start = slot.record_start + body_len + record.salt_block_len;
        let header_start = prefix_start + record.prefix_len;
        let padding_start = header_start + HEADER_CIPHER_LEN;
        let record_end = padding_start + padding_len;
        // Drop unused payload capacity so records pack with no holes, then
        // commit the tag and everything after it.
        buf.set_record_end(slot.payload_start + payload_len);
        buf.zero_extend_to(record_end);

        if record.salt_block_len > 0 {
            profile.write_salt_block(
                &self.salt,
                buf.range_mut(prefix_start - record.salt_block_len, prefix_start),
            );
        }
        let (prefix, header) = buf
            .range_mut(prefix_start, padding_start)
            .split_at_mut(record.prefix_len);
        profile.fill_official(self.seq, prefix);
        header[..HEADER_PLAIN_LEN].copy_from_slice(&plain_header(padding_len, payload_len));
        self.aead.seal(&mut self.nonce, prefix, header)?;
        profile.fill_official(
            self.seq,
            buf.range_mut(padding_start, padding_start + padding_len),
        );

        if payload_len > 0 {
            let (body, rest) = buf
                .range_mut(slot.record_start, record_end)
                .split_at_mut(body_len);
            let padding = &mut rest[padding_start - slot.record_start - body_len..];
            self.aead.seal(&mut self.nonce, padding, body)?;
            mix_padding_payload(profile, self.seq, padding, body);
        }
        Ok(body_len)
    }
}

impl V6ShapedEncoder {
    pub fn os(psk: &Psk) -> Result<Self> {
        Self::new(psk, OsEntropy, MonotonicClock::new())
    }
}

impl<C: Clock> RecordEncoder for V6ShapedEncoder<C> {
    fn reserve<'a>(
        &'a mut self,
        buf: &'a mut Buffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<Reservation<'a, Self>> {
        self.state.ensure_ready()?;
        let now = self.clock.monotonic_secs();
        let max_payload = prefix
            .len()
            .saturating_add(hint)
            .min(self.payload_budget(now));
        if prefix.len() > max_payload {
            return Err(Error::PayloadTooLarge);
        }

        let profile = self.psk.profile();
        let salt_block_len = if self.last_write_secs.is_none() {
            profile.salt_block_len()
        } else {
            0
        };
        let prefix_len = profile.record_prefix_len(self.seq);
        let fixed = salt_block_len + prefix_len + HEADER_CIPHER_LEN + profile.max_padding_len();
        let record_start = buf.reserve_record(fixed + max_payload + TAG_LEN, 0)?;
        buf.extend_from_slice(prefix)?;
        let slot = Slot {
            record_start,
            payload_start: record_start,
            prefix_len: prefix.len(),
            max_payload,
        };
        let record = ShapedRecord {
            salt_block_len,
            prefix_len,
        };
        Ok(Reservation::new(self, buf, slot, record))
    }
}

impl<C: Clock> Seal for V6ShapedEncoder<C> {
    type Record = ShapedRecord;

    fn state(&mut self) -> &mut EncoderState {
        &mut self.state
    }

    fn finish(
        &mut self,
        buf: &mut Buffer,
        slot: &Slot,
        record: &ShapedRecord,
        payload_len: usize,
    ) -> Result<usize> {
        let padding_len = self.psk.profile().final_padding_len(
            self.seq,
            record.prefix_len,
            payload_len,
            self.last_write_secs.is_none(),
        );
        debug_assert!(padding_len <= self.psk.profile().max_padding_len());

        let nonce_before = self.nonce;
        let result = self.seal_record(buf, slot, record, padding_len, payload_len);
        self.state = EncoderState::after_seal(result.is_err() && self.nonce != nonce_before);
        match result {
            Ok(_) => {
                self.chunk_size = self.psk.profile().advance_chunk_size(self.chunk_size);
                self.seq = self.seq.wrapping_add(1);
                self.last_write_secs = Some(self.clock.monotonic_secs());
            }
            Err(_) => buf.truncate(slot.record_start)?,
        }
        result
    }
}

impl<C> fmt::Debug for V6ShapedEncoder<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6ShapedEncoder")
            .field("salt_sent", &self.last_write_secs.is_some())
            .field("seq", &self.seq)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug)]
enum ReadStep {
    Salt,
    Header {
        prefix_len: usize,
    },
    Body {
        header: RecordHeader,
        prefix_len: usize,
    },
}

pub struct V6ShapedDecoder {
    psk: Psk,
    /// Session cipher and the salt it was derived from (the replay identity).
    key: Option<(Aes128Gcm, [u8; SALT_LEN])>,
    nonce: Nonce,
    seq: u32,
    include_salt: bool,
    step: ReadStep,
    pending: Pending,
}

impl V6ShapedDecoder {
    pub fn new(psk: Psk) -> Self {
        Self {
            psk,
            key: None,
            nonce: Nonce::new(),
            seq: 0,
            include_salt: true,
            step: ReadStep::Salt,
            pending: Pending::default(),
        }
    }

    fn header_step(&self) -> ReadStep {
        ReadStep::Header {
            prefix_len: self.psk.profile().record_prefix_len(self.seq),
        }
    }

    fn next_record(&mut self) {
        self.include_salt = false;
        self.seq = self.seq.wrapping_add(1);
        self.step = self.header_step();
    }

    fn header_offset(&self) -> usize {
        let salt = if self.include_salt {
            self.psk.profile().salt_block_len()
        } else {
            0
        };
        self.pending.offset() + salt
    }
}

impl RecordDecoder for V6ShapedDecoder {
    fn decode(&mut self, buf: &mut Buffer) -> Result<DecodeStatus> {
        loop {
            match self.step {
                ReadStep::Salt => {
                    if let Some(need) = self
                        .pending
                        .need(buf, self.psk.profile().salt_block_len())?
                    {
                        return Ok(need);
                    }
                    if self.key.is_none() {
                        let salt = self.kdf_salt(buf)?;
                        self.key = Some((Aes128Gcm::derive(&self.psk, &salt)?, salt));
                    }
                    self.step = self.header_step();
                }
                ReadStep::Header { prefix_len } => {
                    let header_start = self.header_offset() + prefix_len;
                    let header_end = header_start + HEADER_CIPHER_LEN;
                    if let Some(need) = self.pending.need(buf, header_end)? {
                        return Ok(need);
                    }
                    // The prefix is AAD and stays in place; only the header is copied.
                    let filled = buf.filled();
                    let prefix = &filled[header_start - prefix_len..header_start];
                    let mut hdr = *filled[header_start..]
                        .first_chunk::<HEADER_CIPHER_LEN>()
                        .ok_or(Error::Truncated)?;
                    let (aead, _) = self.key.as_ref().ok_or(Error::Aead)?;
                    aead.open(&mut self.nonce, prefix, &mut hdr)?;
                    let header = parse_v6_plain_header(opened_header(&hdr))?;
                    if header.body_len_v6_shaped() == 0 {
                        self.next_record();
                        return Ok(self.pending.zero_chunk(header_end));
                    }
                    self.step = ReadStep::Body { header, prefix_len };
                }
                ReadStep::Body { header, prefix_len } => {
                    let body_off = self.header_offset() + prefix_len + HEADER_CIPHER_LEN;
                    let body_end = body_off + header.body_len_v6_shaped();
                    if let Some(need) = self.pending.need(buf, body_end)? {
                        return Ok(need);
                    }
                    if header.payload_len == 0 {
                        self.next_record();
                        return Ok(self.pending.zero_chunk(body_end));
                    }
                    let body = &mut buf.filled_mut()[body_off..body_end];
                    let (padding, cipher_and_tag) = body.split_at_mut(header.padding_len);
                    mix_padding_payload(self.psk.profile(), self.seq, padding, cipher_and_tag);
                    let (aead, _) = self.key.as_ref().ok_or(Error::Aead)?;
                    aead.open(&mut self.nonce, padding, cipher_and_tag)?;
                    self.next_record();
                    let start = body_off + header.padding_len;
                    return Ok(self
                        .pending
                        .data(body_end, start..start + header.payload_len));
                }
            }
        }
    }

    fn consume(&mut self, buf: &mut Buffer, record: &DecodedRecord) -> Result<()> {
        self.pending.consume(buf, record)
    }

    fn has_unconsumed_plaintext(&self) -> bool {
        !self.pending.is_empty()
    }

    /// The AEAD salt carried by the first record's salt block.
    fn replay_identity(&self) -> Option<[u8; SALT_LEN]> {
        self.key.as_ref().map(|(_, salt)| *salt)
    }

    fn kdf_need(&self) -> usize {
        if self.key.is_none() && matches!(self.step, ReadStep::Salt) {
            self.psk.profile().salt_block_len()
        } else {
            0
        }
    }

    fn kdf_salt(&self, buf: &Buffer) -> Result<[u8; SALT_LEN]> {
        let block = buf
            .filled()
            .get(..self.psk.profile().salt_block_len())
            .ok_or(Error::Truncated)?;
        Ok(self.psk.profile().extract_salt(block))
    }

    fn install_aead(&mut self, salt: [u8; SALT_LEN], key: [u8; AES_128_KEY_LEN]) -> Result<()> {
        self.key = Some((Aes128Gcm::new(&key)?, salt));
        Ok(())
    }
}

impl fmt::Debug for V6ShapedDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6ShapedDecoder")
            .field("include_salt", &self.include_salt)
            .field("seq", &self.seq)
            .field("pending", &self.pending.offset())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FixedClock, V6_WIRE_CAP};

    fn psk() -> Psk {
        Psk::new(b"0123456789abcdef").unwrap()
    }

    fn encoder() -> V6ShapedEncoder<FixedClock> {
        V6ShapedEncoder::with_salt(&psk(), [7; SALT_LEN], FixedClock::new(0)).unwrap()
    }

    /// FNV-1a, to pin long wire output in a constant.
    fn fnv1a(hash: u64, bytes: &[u8]) -> u64 {
        bytes.iter().fold(hash, |hash, &byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
        })
    }

    /// Short reads, zero chunks, and prefixes across four profiles, with
    /// earlier records still pending in the buffer. The digests were recorded
    /// from the 0.1.2 encoder.
    #[test]
    fn records_match_recorded_wire_and_pack_tightly() {
        for (key, digest) in [
            (b"0123456789abcdef", 0xa11f50e082b578b1),
            (b"another profile!", 0x8a55ef8151aefe35),
            (b"short psk padded", 0x72e298657e52f099),
            (b"shape test 12345", 0xbf8615d880192af1),
        ] {
            let psk = Psk::new(key).unwrap();
            let mut encoder =
                V6ShapedEncoder::with_salt(&psk, [7; SALT_LEN], FixedClock::new(0)).unwrap();
            let mut out = Buffer::new(V6_WIRE_CAP);
            let mut hash = 0xcbf29ce484222325;
            for seq in 0..32 {
                let hint = if seq < 4 { 1024 } else { MAX_PACKET_SIZE_V6 };
                let prefix = if seq % 3 == 0 { &b"prefix"[..] } else { &[] };
                let pending = out.len();
                let mut rec = encoder.reserve(&mut out, prefix, hint).unwrap();
                let n = match seq {
                    _ if seq % 5 == 0 => 0,
                    _ if seq % 2 == 0 => rec.capacity().min(211),
                    _ => rec.capacity(),
                };
                rec.payload_mut()[..n].fill(seq as u8);
                let split = rec.seal(n).unwrap();
                let total = prefix.len() + n;
                assert_eq!(split, if total == 0 { 0 } else { total + TAG_LEN });
                let record = &out.filled()[pending..];
                hash = fnv1a(hash, &record[split..]);
                hash = fnv1a(hash, &record[..split]);
                if seq % 4 == 3 {
                    out.consume(out.len()).unwrap();
                }
            }
            assert_eq!(hash, digest, "{}", core::str::from_utf8(key).unwrap());
        }
    }

    #[test]
    fn seal_requires_initialized_payload_and_cancels_on_error() {
        let mut enc = encoder();
        let mut out = Buffer::new(V6_WIRE_CAP);
        assert_eq!(
            enc.reserve(&mut out, &[], 5).unwrap().seal(5),
            Err(Error::PendingWire)
        );
        assert!(out.is_empty());
        assert_eq!(enc.seq, 0);
        assert!(enc.last_write_secs.is_none());
        let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
        rec.payload_mut()[..5].copy_from_slice(b"hello");
        let split = rec.seal(5).unwrap();
        let mut wire = Buffer::new(V6_WIRE_CAP);
        wire.extend_from_slice(&out.filled()[split..]).unwrap();
        wire.extend_from_slice(&out.filled()[..split]).unwrap();
        let mut decoder = V6ShapedDecoder::new(psk());
        let DecodeStatus::Record(record) = decoder.decode(&mut wire).unwrap() else {
            panic!("missing record");
        };
        assert_eq!(record.plaintext(wire.filled()), b"hello");
    }

    #[test]
    fn salt_block_is_not_a_bare_prefix() {
        let mut enc = encoder();
        let mut out = Buffer::new(V6_WIRE_CAP);
        let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
        rec.payload_mut()[..5].copy_from_slice(b"hello");
        let split = rec.seal(5).unwrap();
        let wire = [&out.filled()[split..], &out.filled()[..split]].concat();
        let psk = psk();
        let profile = psk.profile();
        assert_ne!(&wire[..SALT_LEN], &[7u8; SALT_LEN]);
        assert_eq!(
            profile.extract_salt(&wire[..profile.salt_block_len()]),
            [7u8; SALT_LEN]
        );
    }

    #[test]
    fn first_record_respects_cap() {
        let mut enc = encoder();
        let mut out = Buffer::new(V6_WIRE_CAP);
        let rec = enc.reserve(&mut out, &[], MAX_PACKET_SIZE_V6).unwrap();
        let psk = psk();
        let profile = psk.profile();
        assert!(rec.capacity() <= profile.first_record_cap());
    }
}

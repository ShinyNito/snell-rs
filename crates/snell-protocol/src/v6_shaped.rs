//! v6 shaped record codec: profile salt-block, prefix, padding mix, AAD.

use core::fmt;

use crate::aead::Aes128Gcm;
use crate::buffer::Slot;
use crate::header::{RecordHeader, opened_header, parse_v6_plain_header, plain_header};
use crate::profile::mix_padding_payload;
use crate::record::{DecodeStatus, DecodedRecord, EncoderState, Pending};
use crate::{
    AES_128_KEY_LEN, Buffer, Clock, Entropy, Error, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN,
    MAX_PACKET_SIZE_V6, MonotonicClock, Nonce, OsEntropy, Psk, Result, SALT_LEN, TAG_LEN,
};

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
///
/// Contiguous layout: `[salt block][prefix][header][padding][payload+tag]`.
/// Scattered layout keeps the payload in place at the record start:
/// `[payload+tag][salt block][prefix][header][padding]`.
#[derive(Clone, Copy, Debug)]
struct ShapedRecord {
    slot: Slot,
    salt_block_len: usize,
    prefix_len: usize,
    scattered: bool,
}

impl ShapedRecord {
    /// Padding start of the contiguous layout.
    const fn contiguous_padding_start(&self) -> usize {
        self.slot.record_start + self.salt_block_len + self.prefix_len + HEADER_CIPHER_LEN
    }
}

#[must_use = "unsealed reservations are cancelled on drop"]
pub struct V6ShapedReservation<'a, C: Clock = MonotonicClock> {
    encoder: &'a mut V6ShapedEncoder<C>,
    buf: &'a mut Buffer,
    record: ShapedRecord,
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

    pub fn reserve<'buf>(
        &'buf mut self,
        buf: &'buf mut Buffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<V6ShapedReservation<'buf, C>> {
        self.reserve_mode(buf, prefix, hint, false)
    }

    /// Reserve socket output with payload first, regardless of its size.
    /// Pair with `seal_scattered` or `seal_init_scattered`.
    pub fn reserve_scattered<'buf>(
        &'buf mut self,
        buf: &'buf mut Buffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<V6ShapedReservation<'buf, C>> {
        self.reserve_mode(buf, prefix, hint, true)
    }

    fn reserve_mode<'buf>(
        &'buf mut self,
        buf: &'buf mut Buffer,
        prefix: &[u8],
        hint: usize,
        scattered: bool,
    ) -> Result<V6ShapedReservation<'buf, C>> {
        self.state.ensure_ready()?;
        let now = self.clock.monotonic_secs();
        let max_payload = prefix
            .len()
            .saturating_add(hint)
            .min(self.payload_budget(now));
        if prefix.len() > max_payload {
            return Err(Error::PayloadTooLarge);
        }

        let first = self.last_write_secs.is_none();
        let salt_block_len = if first {
            self.psk.profile().salt_block_len()
        } else {
            0
        };
        let prefix_len = self.psk.profile().record_prefix_len(self.seq);
        let fixed =
            salt_block_len + prefix_len + HEADER_CIPHER_LEN + self.psk.profile().max_padding_len();
        // A contiguous record pads for the hint up front; a short write may
        // need more padding, which `seal_record` handles by moving the payload.
        let (initialized, payload_offset) = if scattered {
            (0, 0)
        } else {
            let padding =
                self.psk
                    .profile()
                    .final_padding_len(self.seq, prefix_len, max_payload, first);
            let offset = salt_block_len + prefix_len + HEADER_CIPHER_LEN + padding;
            (offset, offset)
        };
        let record_start = buf.reserve_record(fixed + max_payload + TAG_LEN, initialized)?;
        buf.extend_from_slice(prefix)?;
        self.state = EncoderState::Reserving;
        Ok(V6ShapedReservation {
            encoder: self,
            buf,
            record: ShapedRecord {
                slot: Slot {
                    record_start,
                    payload_start: record_start + payload_offset,
                    prefix_len: prefix.len(),
                    max_payload,
                },
                salt_block_len,
                prefix_len,
                scattered,
            },
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

    fn finish(
        &mut self,
        buf: &mut Buffer,
        record: &ShapedRecord,
        payload_len: usize,
    ) -> Result<usize> {
        let padding_len = if !record.scattered && payload_len == record.slot.max_payload {
            // The hint was exact; reuse the padding decision made by reserve.
            record.slot.payload_start - record.contiguous_padding_start()
        } else {
            self.psk.profile().final_padding_len(
                self.seq,
                record.prefix_len,
                payload_len,
                self.last_write_secs.is_none(),
            )
        };
        debug_assert!(padding_len <= self.psk.profile().max_padding_len());

        let nonce_before = self.nonce;
        let result = self.seal_record(buf, record, padding_len, payload_len);
        self.state = EncoderState::after_seal(result.is_err() && self.nonce != nonce_before);
        match result {
            Ok(_) => {
                self.chunk_size = self.psk.profile().advance_chunk_size(self.chunk_size);
                self.seq = self.seq.wrapping_add(1);
                self.last_write_secs = Some(self.clock.monotonic_secs());
            }
            Err(_) => buf.truncate(record.slot.record_start)?,
        }
        result
    }

    fn seal_record(
        &mut self,
        buf: &mut Buffer,
        record: &ShapedRecord,
        padding_len: usize,
        payload_len: usize,
    ) -> Result<usize> {
        let slot = &record.slot;
        let body_len = if payload_len == 0 {
            0
        } else {
            payload_len + TAG_LEN
        };
        let prefix_start = if record.scattered {
            slot.record_start + body_len + record.salt_block_len
        } else {
            slot.record_start + record.salt_block_len
        };
        let header_start = prefix_start + record.prefix_len;
        let padding_start = header_start + HEADER_CIPHER_LEN;
        let record_end = if record.scattered {
            // Discard unused materialized payload capacity. Commit only the tag
            // and actual header/padding: records pack tightly with no holes.
            let record_end = padding_start + padding_len;
            buf.set_record_end(slot.payload_start + payload_len);
            buf.zero_extend_to(record_end);
            record_end
        } else {
            let payload_start = padding_start + padding_len;
            if payload_len > 0 && payload_start != slot.payload_start {
                // A short read may need more padding than the hint predicted.
                buf.zero_extend_to(payload_start + payload_len);
                buf.copy_within(slot.payload_start, payload_start, payload_len);
            }
            let record_end = payload_start + body_len;
            buf.set_record_end(record_end);
            record_end
        };

        // Generate salt, prefix and header directly at their final addresses.
        if record.salt_block_len > 0 {
            self.psk.profile().write_salt_block(
                &self.salt,
                buf.range_mut(prefix_start - record.salt_block_len, prefix_start),
            );
        }
        let (prefix, header) = buf
            .range_mut(prefix_start, padding_start)
            .split_at_mut(record.prefix_len);
        self.psk.profile().fill_official(self.seq, prefix);
        header[..HEADER_PLAIN_LEN].copy_from_slice(&plain_header(padding_len, payload_len));
        self.aead.seal(&mut self.nonce, prefix, header)?;
        self.psk.profile().fill_official(
            self.seq,
            buf.range_mut(padding_start, padding_start + padding_len),
        );

        if payload_len > 0 {
            let (padding, cipher_and_tag) = if record.scattered {
                let (body, header) = buf
                    .range_mut(slot.record_start, record_end)
                    .split_at_mut(body_len);
                (
                    &mut header[padding_start - slot.record_start - body_len..],
                    body,
                )
            } else {
                buf.range_mut(padding_start, record_end)
                    .split_at_mut(padding_len)
            };
            self.aead.seal(&mut self.nonce, padding, cipher_and_tag)?;
            mix_padding_payload(self.psk.profile(), self.seq, padding, cipher_and_tag);
        }
        // Physical layout is [payload+tag][salt+prefix+header+padding]. Send
        // [split..end] followed by [start..split] to preserve the wire layout.
        Ok(if record.scattered { body_len } else { 0 })
    }
}

impl V6ShapedEncoder {
    pub fn os(psk: &Psk) -> Result<Self> {
        Self::new(psk, OsEntropy, MonotonicClock::new())
    }
}

impl<C: Clock> V6ShapedReservation<'_, C> {
    pub fn payload_mut(&mut self) -> &mut [u8] {
        self.record.slot.payload_mut(self.buf)
    }

    /// Uninitialized payload slot after the prefix. Fill a prefix of it (for
    /// example through Tokio `ReadBuf::uninit`), then call [`Self::seal_init`].
    /// Do not mix with [`Self::payload_mut`]. Empty once materialized.
    pub fn payload_uninit(&mut self) -> &mut [core::mem::MaybeUninit<u8>] {
        self.record.slot.payload_uninit(self.buf)
    }

    pub fn capacity(&self) -> usize {
        self.record.slot.capacity()
    }

    pub fn padding_len(&self) -> usize {
        self.encoder.psk.profile().max_padding_len()
    }

    pub fn seal(self, written: usize) -> Result<()> {
        self.seal_mode(written, false).map(|_| ())
    }

    /// Seal a `reserve_scattered` reservation without moving the payload.
    /// Returns a split offset relative to this record's start. Send the
    /// record's `[split..]` bytes followed by its `[..split]` bytes; both
    /// ranges are needed. Zero chunks return zero.
    pub fn seal_scattered(self, written: usize) -> Result<usize> {
        self.seal_mode(written, true)
    }

    fn seal_mode(self, written: usize, scattered: bool) -> Result<usize> {
        if scattered != self.record.scattered {
            return Err(Error::PendingWire);
        }
        let total = self.record.slot.total(written)?;
        if self.buf.end() < self.record.slot.payload_start + total {
            return Err(Error::PendingWire);
        }
        self.encoder.finish(self.buf, &self.record, total)
    }

    /// Seal after the caller initialized `written` bytes of
    /// [`Self::payload_uninit`]. Commits them without zero-filling first.
    pub(crate) fn seal_init_impl(self, written: usize) -> Result<()> {
        self.seal_init_mode(written, false).map(|_| ())
    }

    pub(crate) fn seal_init_scattered_impl(self, written: usize) -> Result<usize> {
        self.seal_init_mode(written, true)
    }

    fn seal_init_mode(self, written: usize, scattered: bool) -> Result<usize> {
        if scattered != self.record.scattered {
            return Err(Error::PendingWire);
        }
        let total = self.record.slot.commit_init(self.buf, written)?;
        self.encoder.finish(self.buf, &self.record, total)
    }
}

impl<C: Clock> Drop for V6ShapedReservation<'_, C> {
    fn drop(&mut self) {
        if self.encoder.state == EncoderState::Reserving {
            let _ = self.buf.truncate(self.record.slot.record_start);
            self.encoder.state = EncoderState::Ready;
        }
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

    /// 16-byte AEAD salt extracted from the first-record salt block.
    pub fn replay_identity(&self) -> Option<[u8; SALT_LEN]> {
        self.key.as_ref().map(|(_, salt)| *salt)
    }

    pub fn has_unconsumed_plaintext(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn kdf_need(&self) -> usize {
        if self.key.is_none() && matches!(self.step, ReadStep::Salt) {
            self.psk.profile().salt_block_len()
        } else {
            0
        }
    }

    pub fn kdf_salt(&self, buf: &Buffer) -> Result<[u8; SALT_LEN]> {
        let block = buf
            .filled()
            .get(..self.psk.profile().salt_block_len())
            .ok_or(Error::Truncated)?;
        Ok(self.psk.profile().extract_salt(block))
    }

    pub fn install_aead(&mut self, salt: [u8; SALT_LEN], key: [u8; AES_128_KEY_LEN]) -> Result<()> {
        self.key = Some((Aes128Gcm::new(&key)?, salt));
        Ok(())
    }

    pub fn decode(&mut self, buf: &mut Buffer) -> Result<DecodeStatus> {
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

    pub fn consume(&mut self, buf: &mut Buffer, record: &DecodedRecord) -> Result<()> {
        self.pending.consume(buf, record)
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

    #[test]
    fn socket_records_match_contiguous_wire_and_pack_tightly() {
        for key in [
            b"0123456789abcdef".as_slice(),
            b"another profile!",
            b"short psk padded",
            b"shape test 12345",
        ] {
            let psk = Psk::new(key).unwrap();
            let make =
                || V6ShapedEncoder::with_salt(&psk, [7; SALT_LEN], FixedClock::new(0)).unwrap();
            let mut contiguous = make();
            let mut scattered = make();
            let mut expected = Buffer::new(V6_WIRE_CAP);
            let mut actual = Buffer::new(V6_WIRE_CAP);
            // Keep multiple records pending, and exercise short reads, zero chunks,
            // prefixes, and both reservation initialization paths.
            for seq in 0..32 {
                let hint = if seq < 4 { 1024 } else { MAX_PACKET_SIZE_V6 };
                let prefix = if seq % 3 == 0 { &b"prefix"[..] } else { &[] };
                let mut a = contiguous.reserve(&mut expected, prefix, hint).unwrap();
                let mut b = scattered
                    .reserve_scattered(&mut actual, prefix, hint)
                    .unwrap();
                let n = if seq % 5 == 0 {
                    0
                } else {
                    if seq % 2 == 0 {
                        a.capacity().min(211)
                    } else {
                        a.capacity()
                    }
                };
                a.payload_mut()[..n].fill(seq as u8);
                a.seal(n).unwrap();
                let payload_start = b.record.slot.payload_start;
                let record_start = b.record.slot.record_start;
                let payload_ptr = b.payload_uninit().as_ptr();
                let split = if seq % 2 == 0 {
                    b.payload_uninit()[..n].fill(core::mem::MaybeUninit::new(seq as u8));
                    b.seal_init_scattered_impl(n).unwrap()
                } else {
                    b.payload_mut()[..n].fill(seq as u8);
                    b.seal_scattered(n).unwrap()
                };
                let total = prefix.len() + n;
                assert_eq!(
                    payload_start, record_start,
                    "all socket payloads start in place"
                );
                assert_eq!(split, if total == 0 { 0 } else { total + TAG_LEN });
                if split != 0 {
                    assert_eq!(
                        actual
                            .range_mut(payload_start + prefix.len(), payload_start + prefix.len())
                            .as_ptr()
                            .cast(),
                        payload_ptr
                    );
                }
                let physical = &actual.filled()[record_start..];
                let wire: Vec<u8> = physical[split..]
                    .iter()
                    .chain(&physical[..split])
                    .copied()
                    .collect();
                assert_eq!(wire, expected.filled());
                assert_eq!(
                    physical.len(),
                    expected.len(),
                    "no unused headroom between records"
                );
                expected.consume(expected.len()).unwrap();
                if seq % 4 == 3 {
                    actual.consume(actual.len()).unwrap();
                }
            }
        }
    }

    #[test]
    fn scattered_seal_requires_initialized_payload_and_cancels_on_error() {
        let mut enc = encoder();
        let mut out = Buffer::new(V6_WIRE_CAP);
        assert_eq!(
            enc.reserve_scattered(&mut out, &[], 5)
                .unwrap()
                .seal_scattered(5),
            Err(Error::PendingWire)
        );
        assert!(out.is_empty());
        assert_eq!(enc.seq, 0);
        assert!(enc.last_write_secs.is_none());
        let mut rec = enc.reserve_scattered(&mut out, &[], 5).unwrap();
        rec.payload_mut()[..5].copy_from_slice(b"hello");
        let split = rec.seal_scattered(5).unwrap();
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
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"hello");
            rec.seal(5).unwrap();
        }
        let wire = out.filled();
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

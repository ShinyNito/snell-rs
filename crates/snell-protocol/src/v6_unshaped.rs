//! v6 unshaped record codec: Argon2id + AES-128-GCM, no padding, no chunk window.

use core::fmt;
use core::marker::PhantomData;

use crate::aead::Aes128Gcm;
use crate::buffer::Slot;
use crate::header::{RecordHeader, parse_v6_plain_header, write_v6_plain_header};
use crate::record::{DecodeStatus, DecodedRecord, Pending};
use crate::{
    AES_128_KEY_LEN, Buffer, Clock, Entropy, Error, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN,
    MAX_PACKET_SIZE, Nonce, OsEntropy, Psk, Result, SALT_LEN, TAG_LEN, UnixClock,
};

pub struct V6UnshapedEncoder<E = OsEntropy, C = UnixClock> {
    aead: Aes128Gcm,
    nonce: Nonce,
    salt: [u8; SALT_LEN],
    salt_sent: bool,
    _codec: PhantomData<(E, C)>,
    /// Set while a reservation is outstanding, including one leaked with
    /// `mem::forget`, so a half-written record is never followed by another.
    reserving: bool,
    poisoned: bool,
}

#[must_use = "unsealed reservations are cancelled on drop"]
pub struct V6UnshapedReservation<'a, E: Entropy = OsEntropy, C: Clock = UnixClock> {
    encoder: &'a mut V6UnshapedEncoder<E, C>,
    buf: &'a mut Buffer,
    slot: Slot,
    sealed: bool,
}

impl<E: Entropy, C: Clock> V6UnshapedEncoder<E, C> {
    pub fn new(psk: &Psk, mut entropy: E, clock: C) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        entropy.fill(&mut salt)?;
        Self::with_salt(psk, salt, entropy, clock)
    }

    pub fn with_salt(psk: &Psk, salt: [u8; SALT_LEN], _entropy: E, _clock: C) -> Result<Self> {
        Ok(Self {
            aead: Aes128Gcm::derive(psk, &salt)?,
            nonce: Nonce::new(),
            salt,
            salt_sent: false,
            _codec: PhantomData,
            reserving: false,
            poisoned: false,
        })
    }

    pub fn reserve<'buf>(
        &'buf mut self,
        buf: &'buf mut Buffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<V6UnshapedReservation<'buf, E, C>> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.reserving {
            return Err(Error::PendingWire);
        }
        let max_payload = prefix.len().saturating_add(hint).min(MAX_PACKET_SIZE);
        if prefix.len() > max_payload {
            return Err(Error::PayloadTooLarge);
        }

        let first = !self.salt_sent;
        let fixed = usize::from(first) * SALT_LEN + HEADER_CIPHER_LEN;
        let record_start = buf.reserve_record(fixed + max_payload + TAG_LEN, fixed)?;
        if first {
            buf.range_mut(record_start, record_start + SALT_LEN)
                .copy_from_slice(&self.salt);
        }
        buf.extend_from_slice(prefix)?;
        self.reserving = true;
        Ok(V6UnshapedReservation {
            encoder: self,
            buf,
            slot: Slot {
                record_start,
                payload_start: record_start + fixed,
                prefix_len: prefix.len(),
                max_payload,
            },
            sealed: false,
        })
    }

    fn finish(&mut self, buf: &mut Buffer, slot: &Slot, payload_len: usize) -> Result<()> {
        self.reserving = false;
        let nonce_before = self.nonce;
        let result = self.seal_record(buf, slot, payload_len);
        match result {
            Ok(()) => self.salt_sent = true,
            Err(_) => {
                self.poisoned |= self.nonce != nonce_before;
                buf.truncate(slot.record_start)?;
            }
        }
        result
    }

    fn seal_record(&mut self, buf: &mut Buffer, slot: &Slot, payload_len: usize) -> Result<()> {
        let header_start = slot.payload_start - HEADER_CIPHER_LEN;
        let record_end = if payload_len == 0 {
            slot.payload_start
        } else {
            slot.payload_start + payload_len + TAG_LEN
        };
        if buf.end() < record_end {
            // Zero-commit through the tag slot; never touches committed payload.
            buf.reserve_zeroed(record_end - buf.end())?;
        } else {
            buf.truncate(record_end)?;
        }

        let header = buf.range_mut(header_start, slot.payload_start);
        write_v6_plain_header(header, 0, payload_len)?;
        self.aead.seal(&mut self.nonce, &[], header)?;
        if payload_len > 0 {
            let payload = buf.range_mut(slot.payload_start, record_end);
            self.aead.seal(&mut self.nonce, &[], payload)?;
        }
        Ok(())
    }
}

impl V6UnshapedEncoder<OsEntropy, UnixClock> {
    pub fn os(psk: &Psk) -> Result<Self> {
        Self::new(psk, OsEntropy, UnixClock::new())
    }
}

impl<E: Entropy, C: Clock> V6UnshapedReservation<'_, E, C> {
    pub fn payload_mut(&mut self) -> &mut [u8] {
        self.slot.payload_mut(self.buf)
    }

    /// Uninitialized payload slot after the prefix. Fill a prefix of it (for
    /// example through Tokio `ReadBuf::uninit`), then call [`Self::seal_init`].
    /// Do not mix with [`Self::payload_mut`]. Empty once materialized.
    pub fn payload_uninit(&mut self) -> &mut [core::mem::MaybeUninit<u8>] {
        self.slot.payload_uninit(self.buf)
    }

    pub fn capacity(&self) -> usize {
        self.slot.capacity()
    }

    pub fn seal(mut self, written: usize) -> Result<()> {
        let total = self.slot.total(written)?;
        self.sealed = true;
        self.encoder.finish(self.buf, &self.slot, total)
    }

    /// Seal after the caller initialized `written` bytes of
    /// [`Self::payload_uninit`]. Commits them without zero-filling first.
    pub(crate) fn seal_init_impl(mut self, written: usize) -> Result<()> {
        let total = self.slot.commit_init(self.buf, written)?;
        self.sealed = true;
        self.encoder.finish(self.buf, &self.slot, total)
    }
}

impl<E: Entropy, C: Clock> Drop for V6UnshapedReservation<'_, E, C> {
    fn drop(&mut self) {
        if !self.sealed {
            let _ = self.buf.truncate(self.slot.record_start);
            self.encoder.reserving = false;
        }
    }
}

impl<E, C> fmt::Debug for V6UnshapedEncoder<E, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6UnshapedEncoder")
            .field("salt_sent", &self.salt_sent)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug)]
enum ReadStep {
    Salt,
    Header,
    Body(RecordHeader),
}

pub struct V6UnshapedDecoder {
    psk: Psk,
    aead: Option<Aes128Gcm>,
    nonce: Nonce,
    include_salt: bool,
    replay: Option<[u8; SALT_LEN]>,
    step: ReadStep,
    pending: Pending,
}

impl V6UnshapedDecoder {
    pub fn new(psk: Psk) -> Self {
        Self {
            psk,
            aead: None,
            nonce: Nonce::new(),
            include_salt: true,
            replay: None,
            step: ReadStep::Salt,
            pending: Pending::default(),
        }
    }

    /// 16-byte AEAD salt, available after the first record's salt is parsed.
    pub fn replay_identity(&self) -> Option<[u8; SALT_LEN]> {
        self.replay
    }

    pub fn has_unconsumed_plaintext(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn kdf_need(&self) -> usize {
        if self.aead.is_none() && matches!(self.step, ReadStep::Salt) {
            SALT_LEN
        } else {
            0
        }
    }

    pub fn kdf_salt(&self, buf: &Buffer) -> Result<[u8; SALT_LEN]> {
        buf.filled().first_chunk().copied().ok_or(Error::Truncated)
    }

    pub fn install_aead(&mut self, salt: [u8; SALT_LEN], key: [u8; AES_128_KEY_LEN]) -> Result<()> {
        self.aead = Some(Aes128Gcm::new(&key)?);
        self.replay = Some(salt);
        Ok(())
    }

    pub fn decode(&mut self, buf: &mut Buffer) -> Result<DecodeStatus> {
        loop {
            match self.step {
                ReadStep::Salt => {
                    if let Some(need) = self.pending.need(buf, SALT_LEN)? {
                        return Ok(need);
                    }
                    if self.aead.is_none() {
                        let salt = self.kdf_salt(buf)?;
                        self.aead = Some(Aes128Gcm::derive(&self.psk, &salt)?);
                        self.replay = Some(salt);
                    }
                    self.step = ReadStep::Header;
                }
                ReadStep::Header => {
                    let off = self.header_offset();
                    let header_end = off + HEADER_CIPHER_LEN;
                    if let Some(need) = self.pending.need(buf, header_end)? {
                        return Ok(need);
                    }
                    let mut hdr = [0u8; HEADER_CIPHER_LEN];
                    hdr.copy_from_slice(&buf.filled()[off..header_end]);
                    let aead = self.aead.as_ref().ok_or(Error::Aead)?;
                    aead.open(&mut self.nonce, &[], &mut hdr)?;
                    let header = parse_v6_plain_header(&hdr[..HEADER_PLAIN_LEN])?;
                    let len = header.body_len_v6_unshaped()?;
                    if header.payload_len > MAX_PACKET_SIZE {
                        return Err(Error::PayloadTooLarge);
                    }
                    if len == 0 {
                        self.include_salt = false;
                        return Ok(self.pending.zero_chunk(header_end));
                    }
                    self.step = ReadStep::Body(header);
                }
                ReadStep::Body(header) => {
                    let body_off = self.header_offset() + HEADER_CIPHER_LEN;
                    let body_end = body_off + header.payload_len + TAG_LEN;
                    if let Some(need) = self.pending.need(buf, body_end)? {
                        return Ok(need);
                    }
                    let aead = self.aead.as_ref().ok_or(Error::Aead)?;
                    aead.open(
                        &mut self.nonce,
                        &[],
                        &mut buf.filled_mut()[body_off..body_end],
                    )?;
                    self.include_salt = false;
                    self.step = ReadStep::Header;
                    return Ok(self
                        .pending
                        .data(body_end, body_off..body_off + header.payload_len));
                }
            }
        }
    }

    pub fn consume(&mut self, buf: &mut Buffer, record: &DecodedRecord) -> Result<()> {
        self.pending.consume(buf, record)
    }

    fn header_offset(&self) -> usize {
        self.pending.offset() + usize::from(self.include_salt) * SALT_LEN
    }
}

impl fmt::Debug for V6UnshapedDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6UnshapedDecoder")
            .field("include_salt", &self.include_salt)
            .field("pending", &self.pending.offset())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FixedClock, RecordKind, RepeatEntropy, V4_WIRE_CAP};

    fn psk() -> Psk {
        Psk::new(b"0123456789abcdef").unwrap()
    }

    fn encoder() -> V6UnshapedEncoder<RepeatEntropy, FixedClock> {
        V6UnshapedEncoder::with_salt(
            &psk(),
            [7; SALT_LEN],
            RepeatEntropy { byte: 0x3c },
            FixedClock::new(0),
        )
        .unwrap()
    }

    fn collect(buf: &Buffer) -> Vec<u8> {
        buf.filled().to_vec()
    }

    fn decode_plain(decoder: &mut V6UnshapedDecoder, buf: &mut Buffer, wire: &[u8]) -> Vec<u8> {
        buf.extend_from_slice(wire).unwrap();
        let mut plain = Vec::new();
        loop {
            match decoder.decode(buf).unwrap() {
                DecodeStatus::NeedMore { .. } => break,
                DecodeStatus::Record(record) => {
                    if record.kind == RecordKind::Data {
                        plain.extend_from_slice(record.plaintext(buf.filled()));
                    }
                    decoder.consume(buf, &record).unwrap();
                }
            }
        }
        plain
    }

    #[test]
    fn hello_round_trips_and_matches_v4_no_padding_layout() {
        let mut enc = encoder();
        let mut out = Buffer::new(V4_WIRE_CAP);
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"hello");
            rec.seal(5).unwrap();
        }
        let wire = collect(&out);
        assert_eq!(&wire[..SALT_LEN], &[7u8; SALT_LEN]);
        let mut decoder = V6UnshapedDecoder::new(psk());
        let mut buf = Buffer::new(4096);
        assert_eq!(decode_plain(&mut decoder, &mut buf, &wire), b"hello");
        assert_eq!(decoder.replay_identity(), Some([7u8; SALT_LEN]));
    }

    #[test]
    fn seal_init_wire_matches_payload_mut() {
        let mut a_enc = encoder();
        let mut a = Buffer::new(V4_WIRE_CAP);
        let mut b_enc = encoder();
        let mut b = Buffer::new(V4_WIRE_CAP);
        for (msg, hint) in [(&b"hello"[..], 5), (b"steady", 6), (b"abc", 8)] {
            let mut rec = a_enc.reserve(&mut a, &[], hint).unwrap();
            rec.payload_mut()[..msg.len()].copy_from_slice(msg);
            rec.seal(msg.len()).unwrap();

            let mut rec = b_enc.reserve(&mut b, &[], hint).unwrap();
            rec.payload_uninit()[..msg.len()].write_copy_of_slice(msg);
            rec.seal_init_impl(msg.len()).unwrap();
        }
        assert_eq!(a.filled(), b.filled());
    }

    #[test]
    fn second_record_has_no_salt() {
        let mut enc = encoder();
        let mut out = Buffer::new(V4_WIRE_CAP);
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"hello");
            rec.seal(5).unwrap();
        }
        let first = collect(&out);
        out.consume(first.len()).unwrap();
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"world");
            rec.seal(5).unwrap();
        }
        let second = collect(&out);
        assert_eq!(second.len(), HEADER_CIPHER_LEN + 5 + TAG_LEN);
        let mut both = first;
        both.extend_from_slice(&second);
        let mut decoder = V6UnshapedDecoder::new(psk());
        let mut buf = Buffer::new(4096);
        assert_eq!(decode_plain(&mut decoder, &mut buf, &both), b"helloworld");
    }

    #[test]
    fn decode_ahead_batches_records_before_consume() {
        let mut enc = encoder();
        let mut out = Buffer::new(V4_WIRE_CAP);
        for msg in [&b"hello"[..], b"world"] {
            let mut rec = enc.reserve(&mut out, &[], msg.len()).unwrap();
            rec.payload_mut()[..msg.len()].copy_from_slice(msg);
            rec.seal(msg.len()).unwrap();
        }
        let wire = collect(&out);
        let mut decoder = V6UnshapedDecoder::new(psk());
        let mut buf = Buffer::new(4096);
        buf.extend_from_slice(&wire).unwrap();
        let DecodeStatus::Record(first) = decoder.decode(&mut buf).unwrap() else {
            panic!("first record not ready");
        };
        let DecodeStatus::Record(second) = decoder.decode(&mut buf).unwrap() else {
            panic!("second record not ready");
        };
        assert!(decoder.has_unconsumed_plaintext());
        assert_eq!(first.plaintext(buf.filled()), b"hello");
        assert_eq!(second.plaintext(buf.filled()), b"world");
        assert_eq!(first.consumed + second.consumed, wire.len());
        decoder.consume(&mut buf, &first).unwrap();
        decoder.consume(&mut buf, &second).unwrap();
        assert!(buf.is_empty());
        assert!(!decoder.has_unconsumed_plaintext());
        assert_eq!(
            decoder.consume(&mut buf, &second),
            Err(Error::PlaintextNotDrained)
        );
    }

    #[test]
    fn zero_chunk_is_header_only() {
        let mut enc = encoder();
        let mut out = Buffer::new(V4_WIRE_CAP);
        enc.reserve(&mut out, &[], 0).unwrap().seal(0).unwrap();
        let wire = collect(&out);
        assert_eq!(wire.len(), SALT_LEN + HEADER_CIPHER_LEN);
        let mut decoder = V6UnshapedDecoder::new(psk());
        let mut buf = Buffer::new(4096);
        buf.extend_from_slice(&wire).unwrap();
        match decoder.decode(&mut buf).unwrap() {
            DecodeStatus::Record(record) => {
                assert_eq!(record.kind, RecordKind::ZeroChunk);
                decoder.consume(&mut buf, &record).unwrap();
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn reserved_nonzero_fails() {
        let mut enc = encoder();
        let mut out = Buffer::new(V4_WIRE_CAP);
        {
            let mut rec = enc.reserve(&mut out, &[], 1).unwrap();
            rec.payload_mut()[0] = 1;
            rec.seal(1).unwrap();
        }
        let mut wire = collect(&out);
        wire[SALT_LEN] ^= 0; // header cipher; tamper reserved via full tag fail
        let last = wire.len() - 1;
        wire[last] ^= 1;
        let mut decoder = V6UnshapedDecoder::new(psk());
        let mut buf = Buffer::new(4096);
        buf.extend_from_slice(&wire).unwrap();
        assert_eq!(decoder.decode(&mut buf), Err(Error::Aead));
    }

    #[test]
    fn debug_hides_psk() {
        let enc = encoder();
        assert!(!format!("{enc:?}").contains("0123456789abcdef"));
        let dec = V6UnshapedDecoder::new(psk());
        assert!(!format!("{dec:?}").contains("0123456789abcdef"));
    }

    #[test]
    fn second_record_compacts_over_unsent_prefix() {
        let mut enc = encoder();
        let mut out = Buffer::new(100);
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"hello");
            rec.seal(5).unwrap();
        }
        let first = collect(&out);
        assert_eq!(first.len(), 60);
        out.consume(10).unwrap();
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"world");
            rec.seal(5).unwrap();
        }
        let pending = collect(&out);
        assert_eq!(&pending[..50], &first[10..]);
        assert_eq!(pending.len(), 50 + 44);
        let mut decoder = V6UnshapedDecoder::new(psk());
        let mut buf = Buffer::new(4096);
        assert_eq!(decode_plain(&mut decoder, &mut buf, &first), b"hello");
        assert_eq!(
            decode_plain(&mut decoder, &mut buf, &pending[50..]),
            b"world"
        );
    }

    #[test]
    fn drop_cancels_reservation() {
        let mut enc = encoder();
        let mut out = Buffer::new(V4_WIRE_CAP);
        {
            let mut rec = enc.reserve(&mut out, &[], 8).unwrap();
            rec.payload_mut()[0] = 1;
        }
        assert!(out.is_empty());
    }
}

//! v6 shaped record codec: profile salt-block, prefix, padding mix, AAD.

use core::fmt;

use zeroize::Zeroize;

use crate::aead::Aes128Gcm;
use crate::header::{parse_v6_plain_header, write_v6_plain_header};
use crate::kdf::aead_key;
use crate::profile::{Profile, mix_padding_payload};
use crate::record::{DecodeStatus, DecodedRecord, RecordKind};
use crate::{
    Clock, EncodeBuffer, Entropy, Error, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN, MAX_PACKET_SIZE_V6,
    Nonce, OsEntropy, Psk, RecvBuffer, Result, SALT_LEN, TAG_LEN, UnixClock,
};

pub struct V6ShapedEncoder<E = OsEntropy, C = UnixClock> {
    aead: Aes128Gcm,
    nonce: Nonce,
    salt: [u8; SALT_LEN],
    salt_sent: bool,
    seq: u32,
    profile: Profile,
    chunk_size: usize,
    last_write_secs: Option<u64>,
    _entropy: core::marker::PhantomData<E>,
    clock: C,
    reserving: bool,
    poisoned: bool,
    plain_prefix_len: usize,
    max_payload: usize,
    record_prefix_len: usize,
    max_padding_len: usize,
    payload_start: usize,
    header_start: usize,
    padding_start: usize,
    prefix_start: usize,
    record_start: usize,
}

#[must_use = "unsealed reservations are cancelled on drop"]
pub struct V6ShapedReservation<'a, E: Entropy = OsEntropy, C: Clock = UnixClock> {
    encoder: &'a mut V6ShapedEncoder<E, C>,
    buf: &'a mut EncodeBuffer,
    sealed: bool,
}

impl<E: Entropy, C: Clock> V6ShapedEncoder<E, C> {
    pub fn new(psk: &Psk, mut entropy: E, clock: C) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        entropy.fill(&mut salt)?;
        Self::with_salt(psk, salt, entropy, clock)
    }

    pub fn with_salt(psk: &Psk, salt: [u8; SALT_LEN], _entropy: E, clock: C) -> Result<Self> {
        let profile = Profile::derive(psk.as_bytes())?;
        let mut key = aead_key(psk.as_bytes(), &salt)?;
        let aead = Aes128Gcm::new(&key)?;
        key.zeroize();
        Ok(Self {
            aead,
            nonce: Nonce::new(),
            salt,
            salt_sent: false,
            seq: 0,
            profile,
            chunk_size: 0,
            last_write_secs: None,
            _entropy: core::marker::PhantomData,
            clock,
            reserving: false,
            poisoned: false,
            plain_prefix_len: 0,
            max_payload: 0,
            record_prefix_len: 0,
            max_padding_len: 0,
            payload_start: 0,
            header_start: 0,
            padding_start: 0,
            prefix_start: 0,
            record_start: 0,
        })
    }

    pub fn reserve<'buf>(
        &'buf mut self,
        buf: &'buf mut EncodeBuffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<V6ShapedReservation<'buf, E, C>> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.reserving {
            return Err(Error::PendingWire);
        }
        let now = self.clock.monotonic_secs();
        let max_payload = prefix
            .len()
            .saturating_add(hint)
            .min(self.payload_budget(now));
        if prefix.len() > max_payload {
            return Err(Error::PayloadTooLarge);
        }

        let first = !self.salt_sent;
        let salt_block_len = if first {
            self.profile.salt_block_len()
        } else {
            0
        };
        let record_prefix_len = self.profile.record_prefix_len(self.seq);
        let max_padding_len = self.profile.max_padding_len();
        let fixed = salt_block_len + record_prefix_len + HEADER_CIPHER_LEN + max_padding_len;
        let record_cap = fixed + max_payload + TAG_LEN;
        let record_start = buf.reserve_record(record_cap, fixed)?;
        if first {
            self.profile.write_salt_block(
                &self.salt,
                buf.range_mut(record_start, record_start + salt_block_len),
            )?;
        }
        let prefix_start = record_start + salt_block_len;
        let header_start = prefix_start + record_prefix_len;
        let padding_start = header_start + HEADER_CIPHER_LEN;
        let payload_start = padding_start + max_padding_len;
        self.profile
            .fill_official(self.seq, buf.range_mut(prefix_start, header_start));
        buf.extend_from_slice(prefix)?;

        self.plain_prefix_len = prefix.len();
        self.max_payload = max_payload;
        self.record_prefix_len = record_prefix_len;
        self.max_padding_len = max_padding_len;
        self.payload_start = payload_start;
        self.header_start = header_start;
        self.padding_start = padding_start;
        self.prefix_start = prefix_start;
        self.record_start = record_start;
        self.reserving = true;
        Ok(V6ShapedReservation {
            encoder: self,
            buf,
            sealed: false,
        })
    }

    fn payload_budget(&mut self, now: u64) -> usize {
        if self.chunk_size == 0
            || self
                .last_write_secs
                .is_some_and(|last| now.saturating_sub(last) > self.profile.idle_reset_secs())
        {
            self.chunk_size = self.profile.chunk_initial();
        }
        let mut limit = self
            .profile
            .chunk_limit(self.seq, self.chunk_size)
            .min(MAX_PACKET_SIZE_V6);
        if self.seq == 0 {
            limit = limit.min(self.profile.first_record_cap());
        }
        limit
    }

    fn finish(&mut self, buf: &mut EncodeBuffer, payload_len: usize) -> Result<()> {
        if payload_len > self.max_payload {
            self.reserving = false;
            buf.truncate(self.record_start)?;
            return Err(Error::PayloadTooLarge);
        }
        let first = !self.salt_sent;
        let padding_len =
            self.profile
                .final_padding_len(self.seq, self.record_prefix_len, payload_len, first);
        if padding_len > self.max_padding_len {
            self.reserving = false;
            buf.truncate(self.record_start)?;
            return Err(Error::PayloadTooLarge);
        }

        let nonce_before = self.nonce;
        let result = self.seal_record(buf, padding_len, payload_len);
        self.reserving = false;
        if result.is_err() {
            if self.nonce != nonce_before {
                self.poisoned = true;
            }
            buf.truncate(self.record_start)?;
        } else {
            self.salt_sent = true;
            self.chunk_size = self.profile.advance_chunk_size(self.chunk_size);
            self.seq = self.seq.wrapping_add(1);
            self.last_write_secs = Some(self.clock.monotonic_secs());
        }
        result
    }

    fn seal_record(
        &mut self,
        buf: &mut EncodeBuffer,
        padding_len: usize,
        payload_len: usize,
    ) -> Result<()> {
        write_v6_plain_header(
            buf.range_mut(self.header_start, self.header_start + HEADER_PLAIN_LEN),
            padding_len,
            payload_len,
        )?;

        {
            let block = buf.range_mut(self.prefix_start, self.header_start + HEADER_CIPHER_LEN);
            let (prefix, hdr) = block.split_at_mut(self.record_prefix_len);
            let (plain, tag_dst) = hdr.split_at_mut(HEADER_PLAIN_LEN);
            let tag = self.aead.seal(&self.nonce, prefix, plain)?;
            tag_dst.copy_from_slice(&tag);
        }
        self.nonce.increment();

        let mut payload_start = self.payload_start;
        if payload_len > 0 && padding_len < self.max_padding_len {
            buf.copy_within(payload_start, self.padding_start + padding_len, payload_len);
            payload_start = self.padding_start + padding_len;
        }
        let record_end = if payload_len == 0 {
            self.padding_start + padding_len
        } else {
            payload_start + payload_len + TAG_LEN
        };
        if buf.end() < record_end {
            // Zero-commit through the tag slot; never touches committed payload.
            buf.reserve_zeroed(record_end - buf.end())?;
        } else {
            buf.truncate(record_end)?;
        }
        self.profile.fill_official(
            self.seq,
            buf.range_mut(self.padding_start, self.padding_start + padding_len),
        );

        if payload_len > 0 {
            {
                let body = buf.range_mut(self.padding_start, record_end);
                let (padding, rest) = body.split_at_mut(padding_len);
                let (payload, tag_dst) = rest.split_at_mut(payload_len);
                let tag = self.aead.seal(&self.nonce, padding, payload)?;
                tag_dst.copy_from_slice(&tag);
            }
            self.nonce.increment();
            let body = buf.range_mut(self.padding_start, record_end);
            let (padding, cipher_and_tag) = body.split_at_mut(padding_len);
            mix_padding_payload(&self.profile, self.seq, padding, cipher_and_tag);
        }
        Ok(())
    }
}

impl V6ShapedEncoder<OsEntropy, UnixClock> {
    pub fn os(psk: &Psk) -> Result<Self> {
        Self::new(psk, OsEntropy, UnixClock::new())
    }
}

impl<E: Entropy, C: Clock> V6ShapedReservation<'_, E, C> {
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let start = self.encoder.payload_start + self.encoder.plain_prefix_len;
        let end = self.encoder.payload_start + self.encoder.max_payload;
        let record_end = end + TAG_LEN;
        if self.buf.end() < record_end {
            // Materialize the rest of the record for in-place writers.
            // Capacity was reserved by `reserve_record`; this cannot fail.
            self.buf
                .reserve_zeroed(record_end - self.buf.end())
                .expect("record capacity reserved");
        }
        self.buf.range_mut(start, end)
    }

    /// Uninitialized payload slot after the prefix. Fill a prefix of it (for
    /// example through Tokio `ReadBuf::uninit`), then call [`Self::seal_init`].
    /// Do not mix with [`Self::payload_mut`]. Empty once materialized.
    pub fn payload_uninit(&mut self) -> &mut [core::mem::MaybeUninit<u8>] {
        let cap = self.encoder.max_payload - self.encoder.plain_prefix_len;
        if self.buf.end() != self.encoder.payload_start + self.encoder.plain_prefix_len {
            return &mut [];
        }
        &mut self.buf.spare_uninit()[..cap]
    }

    pub fn capacity(&self) -> usize {
        self.encoder.max_payload - self.encoder.plain_prefix_len
    }

    pub fn padding_len(&self) -> usize {
        self.encoder.max_padding_len
    }

    pub fn seal(mut self, written: usize) -> Result<()> {
        let total = self
            .encoder
            .plain_prefix_len
            .checked_add(written)
            .ok_or(Error::PayloadTooLarge)?;
        if total > self.encoder.max_payload {
            return Err(Error::PayloadTooLarge);
        }
        self.sealed = true;
        self.encoder.finish(self.buf, total)
    }

    /// Seal after the caller initialized `written` bytes of
    /// [`Self::payload_uninit`]. Commits them without zero-filling first.
    pub fn seal_init(mut self, written: usize) -> Result<()> {
        let total = crate::buffer::commit_init_payload(
            self.buf,
            self.encoder.payload_start,
            self.encoder.plain_prefix_len,
            self.encoder.max_payload,
            written,
        )?;
        self.sealed = true;
        self.encoder.finish(self.buf, total)
    }
}

impl<E: Entropy, C: Clock> Drop for V6ShapedReservation<'_, E, C> {
    fn drop(&mut self) {
        if !self.sealed {
            let _ = self.buf.truncate(self.encoder.record_start);
            self.encoder.reserving = false;
        }
    }
}

impl<E, C> fmt::Debug for V6ShapedEncoder<E, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6ShapedEncoder")
            .field("salt_sent", &self.salt_sent)
            .field("seq", &self.seq)
            .field("poisoned", &self.poisoned)
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
        header: crate::RecordHeader,
        prefix_len: usize,
    },
}

pub struct V6ShapedDecoder {
    psk: Psk,
    profile: Profile,
    aead: Option<Aes128Gcm>,
    nonce: Nonce,
    seq: u32,
    include_salt: bool,
    replay: Option<[u8; SALT_LEN]>,
    step: ReadStep,
    busy: bool,
}

impl V6ShapedDecoder {
    pub fn new(psk: Psk) -> Result<Self> {
        let profile = Profile::derive(psk.as_bytes())?;
        Ok(Self {
            psk,
            profile,
            aead: None,
            nonce: Nonce::new(),
            seq: 0,
            include_salt: true,
            replay: None,
            step: ReadStep::Salt,
            busy: false,
        })
    }

    /// 16-byte AEAD salt extracted from the first-record salt block.
    pub fn replay_identity(&self) -> Option<[u8; SALT_LEN]> {
        self.replay
    }

    pub fn has_unconsumed_plaintext(&self) -> bool {
        self.busy
    }

    pub fn kdf_need(&self) -> usize {
        if self.aead.is_none() && matches!(self.step, ReadStep::Salt) {
            self.profile.salt_block_len()
        } else {
            0
        }
    }

    pub fn kdf_salt(&self, buf: &RecvBuffer) -> Result<[u8; SALT_LEN]> {
        let salt_len = self.profile.salt_block_len();
        if buf.len() < salt_len {
            return Err(Error::Truncated);
        }
        self.profile.extract_salt(&buf.filled()[..salt_len])
    }

    pub fn install_aead(
        &mut self,
        salt: [u8; SALT_LEN],
        key: [u8; crate::AES_128_KEY_LEN],
    ) -> Result<()> {
        self.aead = Some(Aes128Gcm::new(&key)?);
        self.replay = Some(salt);
        Ok(())
    }

    pub fn decode(&mut self, buf: &mut RecvBuffer) -> Result<DecodeStatus> {
        if self.busy {
            return Err(Error::PlaintextNotDrained);
        }
        loop {
            match self.step {
                ReadStep::Salt => {
                    let salt_len = self.profile.salt_block_len();
                    if let Some(need) = Self::decode_need(buf, salt_len)? {
                        return Ok(need);
                    }
                    if self.aead.is_none() {
                        let salt = self.profile.extract_salt(&buf.filled()[..salt_len])?;
                        let mut key = aead_key(self.psk.as_bytes(), &salt)?;
                        self.aead = Some(Aes128Gcm::new(&key)?);
                        key.zeroize();
                        self.replay = Some(salt);
                    }
                    self.step = ReadStep::Header {
                        prefix_len: self.profile.record_prefix_len(self.seq),
                    };
                }
                ReadStep::Header { prefix_len } => {
                    let off = self.header_offset();
                    let header_end = off + prefix_len + HEADER_CIPHER_LEN;
                    if let Some(need) = Self::decode_need(buf, header_end)? {
                        return Ok(need);
                    }
                    let mut scratch = [0u8; 128 + HEADER_CIPHER_LEN];
                    if prefix_len + HEADER_CIPHER_LEN > scratch.len() {
                        return Err(Error::PayloadTooLarge);
                    }
                    scratch[..prefix_len + HEADER_CIPHER_LEN]
                        .copy_from_slice(&buf.filled()[off..header_end]);
                    let (prefix, hdr) =
                        scratch[..prefix_len + HEADER_CIPHER_LEN].split_at_mut(prefix_len);
                    let (cipher, tag_bytes) = hdr.split_at_mut(HEADER_PLAIN_LEN);
                    let mut tag = [0u8; TAG_LEN];
                    tag.copy_from_slice(tag_bytes);
                    self.aead.as_ref().ok_or(Error::Aead)?.open(
                        &self.nonce,
                        prefix,
                        cipher,
                        &tag,
                    )?;
                    self.nonce.increment();
                    let header = parse_v6_plain_header(cipher)?;
                    let body_len = header.body_len_v6_shaped()?;
                    if body_len == 0 {
                        self.include_salt = false;
                        self.seq = self.seq.wrapping_add(1);
                        self.step = ReadStep::Header {
                            prefix_len: self.profile.record_prefix_len(self.seq),
                        };
                        self.busy = true;
                        return Ok(DecodeStatus::Record(DecodedRecord {
                            consumed: header_end,
                            plaintext: 0..0,
                            kind: RecordKind::ZeroChunk,
                        }));
                    }
                    self.step = ReadStep::Body { header, prefix_len };
                }
                ReadStep::Body { header, prefix_len } => {
                    let off = self.header_offset();
                    let body_off = off + prefix_len + HEADER_CIPHER_LEN;
                    let body_len = header.body_len_v6_shaped()?;
                    let needed = body_off + body_len;
                    if let Some(need) = Self::decode_need(buf, needed)? {
                        return Ok(need);
                    }
                    if header.payload_len == 0 {
                        self.include_salt = false;
                        self.seq = self.seq.wrapping_add(1);
                        self.step = ReadStep::Header {
                            prefix_len: self.profile.record_prefix_len(self.seq),
                        };
                        self.busy = true;
                        return Ok(DecodeStatus::Record(DecodedRecord {
                            consumed: needed,
                            plaintext: 0..0,
                            kind: RecordKind::ZeroChunk,
                        }));
                    }
                    let body = &mut buf.filled_mut()[body_off..needed];
                    let (padding, rest) = body.split_at_mut(header.padding_len);
                    mix_padding_payload(&self.profile, self.seq, padding, rest);
                    let (payload, tag_bytes) = rest.split_at_mut(header.payload_len);
                    let mut tag = [0u8; TAG_LEN];
                    tag.copy_from_slice(tag_bytes);
                    self.aead.as_ref().ok_or(Error::Aead)?.open(
                        &self.nonce,
                        padding,
                        payload,
                        &tag,
                    )?;
                    self.nonce.increment();
                    let start = body_off + header.padding_len;
                    self.include_salt = false;
                    self.seq = self.seq.wrapping_add(1);
                    self.step = ReadStep::Header {
                        prefix_len: self.profile.record_prefix_len(self.seq),
                    };
                    self.busy = true;
                    return Ok(DecodeStatus::Record(DecodedRecord {
                        consumed: needed,
                        plaintext: start..start + header.payload_len,
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

    fn header_offset(&self) -> usize {
        if self.include_salt {
            self.profile.salt_block_len()
        } else {
            0
        }
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

impl fmt::Debug for V6ShapedDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6ShapedDecoder")
            .field("include_salt", &self.include_salt)
            .field("seq", &self.seq)
            .field("busy", &self.busy)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncodeBuffer, FixedClock, RepeatEntropy, V6_WIRE_CAP};

    fn psk() -> Psk {
        Psk::new(b"0123456789abcdef").unwrap()
    }

    fn encoder() -> V6ShapedEncoder<RepeatEntropy, FixedClock> {
        V6ShapedEncoder::with_salt(
            &psk(),
            [7; SALT_LEN],
            RepeatEntropy { byte: 0x3c },
            FixedClock::new(0),
        )
        .unwrap()
    }

    fn collect(buf: &EncodeBuffer) -> Vec<u8> {
        buf.pending().to_vec()
    }

    fn decode_plain(decoder: &mut V6ShapedDecoder, buf: &mut RecvBuffer, wire: &[u8]) -> Vec<u8> {
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
    fn hello_round_trips() {
        let mut enc = encoder();
        let mut out = EncodeBuffer::new(V6_WIRE_CAP);
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"hello");
            rec.seal(5).unwrap();
        }
        let wire = collect(&out);
        assert!(wire.len() > SALT_LEN + HEADER_CIPHER_LEN + 5);
        let mut decoder = V6ShapedDecoder::new(psk()).unwrap();
        let mut buf = RecvBuffer::new(V6_WIRE_CAP);
        assert_eq!(decode_plain(&mut decoder, &mut buf, &wire), b"hello");
        assert_eq!(decoder.replay_identity(), Some([7u8; SALT_LEN]));
    }

    #[test]
    fn seal_init_wire_matches_payload_mut() {
        let mut a_enc = encoder();
        let mut a = EncodeBuffer::new(V6_WIRE_CAP);
        let mut b_enc = encoder();
        let mut b = EncodeBuffer::new(V6_WIRE_CAP);
        // First record (salt block + profile padding), steady record, and a
        // short write under the hint. Both paths must be byte-identical.
        for (msg, hint) in [(&b"hello"[..], 5), (b"steady", 6), (b"abc", 8)] {
            let mut rec = a_enc.reserve(&mut a, &[], hint).unwrap();
            rec.payload_mut()[..msg.len()].copy_from_slice(msg);
            rec.seal(msg.len()).unwrap();

            let mut rec = b_enc.reserve(&mut b, &[], hint).unwrap();
            rec.payload_uninit()[..msg.len()].write_copy_of_slice(msg);
            rec.seal_init(msg.len()).unwrap();
        }
        assert_eq!(a.pending(), b.pending());
    }

    #[test]
    fn two_records_and_seq_progression() {
        let mut enc = encoder();
        let mut out = EncodeBuffer::new(V6_WIRE_CAP);
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"hello");
            rec.seal(5).unwrap();
        }
        let first = collect(&out);
        out.advance(first.len()).unwrap();
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"world");
            rec.seal(5).unwrap();
        }
        let second = collect(&out);
        assert_ne!(first.len(), second.len());
        let mut both = first;
        both.extend_from_slice(&second);
        let mut decoder = V6ShapedDecoder::new(psk()).unwrap();
        let mut buf = RecvBuffer::new(V6_WIRE_CAP);
        assert_eq!(decode_plain(&mut decoder, &mut buf, &both), b"helloworld");
    }

    #[test]
    fn two_records_share_pending_without_advance() {
        let mut enc = encoder();
        let mut out = EncodeBuffer::new(V6_WIRE_CAP);
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"hello");
            rec.seal(5).unwrap();
        }
        let first_len = out.len();
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"world");
            rec.seal(5).unwrap();
        }
        let pending = collect(&out);
        let mut decoder = V6ShapedDecoder::new(psk()).unwrap();
        let mut buf = RecvBuffer::new(V6_WIRE_CAP);
        assert_eq!(
            decode_plain(&mut decoder, &mut buf, &pending),
            b"helloworld"
        );
        assert!(first_len < pending.len());
    }

    #[test]
    fn salt_block_is_not_a_bare_prefix() {
        let mut enc = encoder();
        let mut out = EncodeBuffer::new(V6_WIRE_CAP);
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"hello");
            rec.seal(5).unwrap();
        }
        let wire = collect(&out);
        let profile = Profile::derive(psk().as_bytes()).unwrap();
        assert_ne!(&wire[..SALT_LEN], &[7u8; SALT_LEN]);
        assert_eq!(
            profile
                .extract_salt(&wire[..profile.salt_block_len()])
                .unwrap(),
            [7u8; SALT_LEN]
        );
    }

    #[test]
    fn zero_chunk_round_trips() {
        let mut enc = encoder();
        let mut out = EncodeBuffer::new(V6_WIRE_CAP);
        enc.reserve(&mut out, &[], 0).unwrap().seal(0).unwrap();
        let wire = collect(&out);
        let mut decoder = V6ShapedDecoder::new(psk()).unwrap();
        let mut buf = RecvBuffer::new(V6_WIRE_CAP);
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
    fn tampered_tag_fails_closed() {
        let mut enc = encoder();
        let mut out = EncodeBuffer::new(V6_WIRE_CAP);
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"hello");
            rec.seal(5).unwrap();
        }
        let mut wire = collect(&out);
        let last = wire.len() - 1;
        wire[last] ^= 1;
        let mut decoder = V6ShapedDecoder::new(psk()).unwrap();
        let mut buf = RecvBuffer::new(V6_WIRE_CAP);
        buf.extend_from_slice(&wire).unwrap();
        assert_eq!(decoder.decode(&mut buf), Err(Error::Aead));
    }

    #[test]
    fn debug_hides_psk() {
        let enc = encoder();
        assert!(!format!("{enc:?}").contains("0123456789abcdef"));
        let dec = V6ShapedDecoder::new(psk()).unwrap();
        assert!(!format!("{dec:?}").contains("0123456789abcdef"));
    }

    #[test]
    fn drop_cancels_reservation() {
        let mut enc = encoder();
        let mut out = EncodeBuffer::new(V6_WIRE_CAP);
        {
            let mut rec = enc.reserve(&mut out, &[], 8).unwrap();
            rec.payload_mut()[0] = 1;
        }
        assert!(out.is_empty());
    }

    #[test]
    fn hello_byte_at_a_time() {
        let mut enc = encoder();
        let mut out = EncodeBuffer::new(V6_WIRE_CAP);
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"hello");
            rec.seal(5).unwrap();
        }
        let wire = collect(&out);
        let mut decoder = V6ShapedDecoder::new(psk()).unwrap();
        let mut buf = RecvBuffer::new(V6_WIRE_CAP);
        for (i, byte) in wire.iter().enumerate() {
            buf.extend_from_slice(&[*byte]).unwrap();
            match decoder.decode(&mut buf).unwrap() {
                DecodeStatus::NeedMore { minimum } => {
                    assert!(i + 1 < wire.len());
                    assert!(minimum > i + 1);
                }
                DecodeStatus::Record(record) => {
                    assert_eq!(i + 1, wire.len());
                    assert_eq!(record.plaintext(buf.filled()), b"hello");
                    decoder.consume(&mut buf, &record).unwrap();
                }
            }
        }
    }

    #[test]
    fn first_record_respects_cap() {
        let mut enc = encoder();
        let mut out = EncodeBuffer::new(V6_WIRE_CAP);
        let rec = enc.reserve(&mut out, &[], MAX_PACKET_SIZE_V6).unwrap();
        let profile = Profile::derive(psk().as_bytes()).unwrap();
        assert!(rec.capacity() <= profile.first_record_cap());
    }
}

//! v6 unshaped record codec: Argon2id + AES-128-GCM, no padding, no chunk window.

use core::fmt;

use zeroize::Zeroize;

use crate::aead::Aes128Gcm;
use crate::header::{parse_v6_plain_header, write_v6_plain_header};
use crate::kdf::aead_key;
use crate::record::{DecodeStatus, DecodedRecord, RecordKind};
use crate::{
    Clock, EncodeBuffer, Entropy, Error, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN, MAX_PACKET_SIZE,
    Nonce, OsEntropy, Psk, RecvBuffer, Result, SALT_LEN, TAG_LEN, UnixClock,
};

pub struct V6UnshapedEncoder<E = OsEntropy, C = UnixClock> {
    aead: Aes128Gcm,
    nonce: Nonce,
    salt: [u8; SALT_LEN],
    salt_sent: bool,
    _entropy: core::marker::PhantomData<E>,
    _clock: core::marker::PhantomData<C>,
    reserving: bool,
    poisoned: bool,
    prefix_len: usize,
    max_payload: usize,
    payload_start: usize,
    header_start: usize,
    record_start: usize,
}

#[must_use = "unsealed reservations are cancelled on drop"]
pub struct V6UnshapedReservation<'a, E: Entropy = OsEntropy, C: Clock = UnixClock> {
    encoder: &'a mut V6UnshapedEncoder<E, C>,
    buf: &'a mut EncodeBuffer,
    sealed: bool,
}

impl<E: Entropy, C: Clock> V6UnshapedEncoder<E, C> {
    pub fn new(psk: &Psk, mut entropy: E, clock: C) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        entropy.fill(&mut salt)?;
        Self::with_salt(psk, salt, entropy, clock)
    }

    pub fn with_salt(psk: &Psk, salt: [u8; SALT_LEN], _entropy: E, _clock: C) -> Result<Self> {
        let mut key = aead_key(psk.as_bytes(), &salt)?;
        let aead = Aes128Gcm::new(&key)?;
        key.zeroize();
        Ok(Self {
            aead,
            nonce: Nonce::new(),
            salt,
            salt_sent: false,
            _entropy: core::marker::PhantomData,
            _clock: core::marker::PhantomData,
            reserving: false,
            poisoned: false,
            prefix_len: 0,
            max_payload: 0,
            payload_start: 0,
            header_start: 0,
            record_start: 0,
        })
    }

    pub fn reserve<'buf>(
        &'buf mut self,
        buf: &'buf mut EncodeBuffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<V6UnshapedReservation<'buf, E, C>> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.reserving {
            return Err(Error::PendingWire);
        }
        let needed = prefix.len().saturating_add(hint);
        let max_payload = needed.min(MAX_PACKET_SIZE);
        if prefix.len() > max_payload {
            return Err(Error::PayloadTooLarge);
        }

        let first = !self.salt_sent;
        let salt_len = usize::from(first) * SALT_LEN;
        let record_cap = salt_len + HEADER_CIPHER_LEN + max_payload + TAG_LEN;
        let record_start = buf.reserve_zeroed(record_cap)?;
        if first {
            buf.range_mut(record_start, record_start + SALT_LEN)
                .copy_from_slice(&self.salt);
        }
        let header_start = record_start + salt_len;
        let payload_start = header_start + HEADER_CIPHER_LEN;
        if !prefix.is_empty() {
            buf.range_mut(payload_start, payload_start + prefix.len())
                .copy_from_slice(prefix);
        }
        self.prefix_len = prefix.len();
        self.max_payload = max_payload;
        self.header_start = header_start;
        self.payload_start = payload_start;
        self.record_start = record_start;
        self.reserving = true;
        Ok(V6UnshapedReservation {
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
        if payload_len == 0 {
            buf.truncate(self.header_start + HEADER_CIPHER_LEN)?;
        } else {
            buf.truncate(self.payload_start + payload_len + TAG_LEN)?;
        }

        let nonce_before = self.nonce;
        let result = self.seal_record(buf, payload_len);
        self.reserving = false;
        if result.is_err() {
            if self.nonce != nonce_before {
                self.poisoned = true;
            }
            buf.truncate(self.record_start)?;
        } else {
            self.salt_sent = true;
        }
        result
    }

    fn seal_record(&mut self, buf: &mut EncodeBuffer, payload_len: usize) -> Result<()> {
        write_v6_plain_header(
            buf.range_mut(self.header_start, self.header_start + HEADER_PLAIN_LEN),
            0,
            payload_len,
        )?;
        let header_tag = {
            let header = buf.range_mut(self.header_start, self.header_start + HEADER_PLAIN_LEN);
            self.aead.seal(&self.nonce, &[], header)?
        };
        self.nonce.increment();
        buf.range_mut(
            self.header_start + HEADER_PLAIN_LEN,
            self.header_start + HEADER_CIPHER_LEN,
        )
        .copy_from_slice(&header_tag);

        if payload_len > 0 {
            let payload_tag = {
                let payload = buf.range_mut(self.payload_start, self.payload_start + payload_len);
                self.aead.seal(&self.nonce, &[], payload)?
            };
            self.nonce.increment();
            buf.range_mut(
                self.payload_start + payload_len,
                self.payload_start + payload_len + TAG_LEN,
            )
            .copy_from_slice(&payload_tag);
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

impl<E: Entropy, C: Clock> Drop for V6UnshapedReservation<'_, E, C> {
    fn drop(&mut self) {
        if !self.sealed {
            let _ = self.buf.truncate(self.encoder.record_start);
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
    Body(crate::RecordHeader),
}

pub struct V6UnshapedDecoder {
    psk: Psk,
    aead: Option<Aes128Gcm>,
    nonce: Nonce,
    include_salt: bool,
    replay: Option<[u8; SALT_LEN]>,
    step: ReadStep,
    busy: bool,
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
            busy: false,
        }
    }

    /// 16-byte AEAD salt, available after the first record's salt is parsed.
    pub fn replay_identity(&self) -> Option<[u8; SALT_LEN]> {
        self.replay
    }

    pub fn has_unconsumed_plaintext(&self) -> bool {
        self.busy
    }

    pub fn kdf_need(&self) -> usize {
        if self.aead.is_none() && matches!(self.step, ReadStep::Salt) {
            SALT_LEN
        } else {
            0
        }
    }

    pub fn kdf_salt(&self, buf: &RecvBuffer) -> Result<[u8; SALT_LEN]> {
        if buf.len() < SALT_LEN {
            return Err(Error::Truncated);
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buf.filled()[..SALT_LEN]);
        Ok(salt)
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
                    if let Some(need) = Self::decode_need(buf, SALT_LEN)? {
                        return Ok(need);
                    }
                    if self.aead.is_none() {
                        let mut salt = [0u8; SALT_LEN];
                        salt.copy_from_slice(&buf.filled()[..SALT_LEN]);
                        let mut key = aead_key(self.psk.as_bytes(), &salt)?;
                        self.aead = Some(Aes128Gcm::new(&key)?);
                        key.zeroize();
                        self.replay = Some(salt);
                    }
                    self.step = ReadStep::Header;
                }
                ReadStep::Header => {
                    let off = self.header_offset();
                    let header_end = off + HEADER_CIPHER_LEN;
                    if let Some(need) = Self::decode_need(buf, header_end)? {
                        return Ok(need);
                    }
                    let mut hdr = [0u8; HEADER_CIPHER_LEN];
                    hdr.copy_from_slice(&buf.filled()[off..header_end]);
                    let (cipher, tag_bytes) = hdr.split_at_mut(HEADER_PLAIN_LEN);
                    let mut tag = [0u8; TAG_LEN];
                    tag.copy_from_slice(tag_bytes);
                    self.aead
                        .as_ref()
                        .ok_or(Error::Aead)?
                        .open(&self.nonce, &[], cipher, &tag)?;
                    self.nonce.increment();
                    let header = parse_v6_plain_header(cipher)?;
                    let body_len = header.body_len_v6_unshaped()?;
                    if header.payload_len > MAX_PACKET_SIZE {
                        return Err(Error::PayloadTooLarge);
                    }
                    if body_len == 0 {
                        self.include_salt = false;
                        self.step = ReadStep::Header;
                        self.busy = true;
                        return Ok(DecodeStatus::Record(DecodedRecord {
                            consumed: header_end,
                            plaintext: 0..0,
                            kind: RecordKind::ZeroChunk,
                        }));
                    }
                    self.step = ReadStep::Body(header);
                }
                ReadStep::Body(header) => {
                    let off = self.header_offset();
                    let body_off = off + HEADER_CIPHER_LEN;
                    let body_len = header.body_len_v6_unshaped()?;
                    let needed = body_off + body_len;
                    if let Some(need) = Self::decode_need(buf, needed)? {
                        return Ok(need);
                    }
                    let body = &mut buf.filled_mut()[body_off..needed];
                    let (payload, tag_bytes) = body.split_at_mut(header.payload_len);
                    let mut tag = [0u8; TAG_LEN];
                    tag.copy_from_slice(tag_bytes);
                    self.aead
                        .as_ref()
                        .ok_or(Error::Aead)?
                        .open(&self.nonce, &[], payload, &tag)?;
                    self.nonce.increment();
                    self.include_salt = false;
                    self.step = ReadStep::Header;
                    self.busy = true;
                    return Ok(DecodeStatus::Record(DecodedRecord {
                        consumed: needed,
                        plaintext: body_off..body_off + header.payload_len,
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
        if self.include_salt { SALT_LEN } else { 0 }
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

impl fmt::Debug for V6UnshapedDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6UnshapedDecoder")
            .field("include_salt", &self.include_salt)
            .field("busy", &self.busy)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncodeBuffer, FixedClock, RepeatEntropy, V4_WIRE_CAP};

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

    fn collect(buf: &EncodeBuffer) -> Vec<u8> {
        buf.pending().to_vec()
    }

    fn decode_plain(decoder: &mut V6UnshapedDecoder, buf: &mut RecvBuffer, wire: &[u8]) -> Vec<u8> {
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
        let mut out = EncodeBuffer::new(V4_WIRE_CAP);
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"hello");
            rec.seal(5).unwrap();
        }
        let wire = collect(&out);
        assert_eq!(&wire[..SALT_LEN], &[7u8; SALT_LEN]);
        let mut decoder = V6UnshapedDecoder::new(psk());
        let mut buf = RecvBuffer::new(4096);
        assert_eq!(decode_plain(&mut decoder, &mut buf, &wire), b"hello");
        assert_eq!(decoder.replay_identity(), Some([7u8; SALT_LEN]));
    }

    #[test]
    fn second_record_has_no_salt() {
        let mut enc = encoder();
        let mut out = EncodeBuffer::new(V4_WIRE_CAP);
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
        assert_eq!(second.len(), HEADER_CIPHER_LEN + 5 + TAG_LEN);
        let mut both = first;
        both.extend_from_slice(&second);
        let mut decoder = V6UnshapedDecoder::new(psk());
        let mut buf = RecvBuffer::new(4096);
        assert_eq!(decode_plain(&mut decoder, &mut buf, &both), b"helloworld");
    }

    #[test]
    fn two_records_share_pending_without_advance() {
        let mut enc = encoder();
        let mut out = EncodeBuffer::new(V4_WIRE_CAP);
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
        out.advance(first_len).unwrap();
        let rest = collect(&out);
        assert_eq!(&pending[first_len..], rest.as_slice());
        let mut decoder = V6UnshapedDecoder::new(psk());
        let mut buf = RecvBuffer::new(4096);
        assert_eq!(
            decode_plain(&mut decoder, &mut buf, &pending),
            b"helloworld"
        );
    }

    #[test]
    fn zero_chunk_is_header_only() {
        let mut enc = encoder();
        let mut out = EncodeBuffer::new(V4_WIRE_CAP);
        enc.reserve(&mut out, &[], 0).unwrap().seal(0).unwrap();
        let wire = collect(&out);
        assert_eq!(wire.len(), SALT_LEN + HEADER_CIPHER_LEN);
        let mut decoder = V6UnshapedDecoder::new(psk());
        let mut buf = RecvBuffer::new(4096);
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
        let mut out = EncodeBuffer::new(V4_WIRE_CAP);
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
        let mut buf = RecvBuffer::new(4096);
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
        let mut out = EncodeBuffer::new(100);
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"hello");
            rec.seal(5).unwrap();
        }
        let first = collect(&out);
        assert_eq!(first.len(), 60);
        out.advance(10).unwrap();
        {
            let mut rec = enc.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"world");
            rec.seal(5).unwrap();
        }
        let pending = collect(&out);
        assert_eq!(&pending[..50], &first[10..]);
        assert_eq!(pending.len(), 50 + 44);
        let mut decoder = V6UnshapedDecoder::new(psk());
        let mut buf = RecvBuffer::new(4096);
        assert_eq!(decode_plain(&mut decoder, &mut buf, &first), b"hello");
        assert_eq!(
            decode_plain(&mut decoder, &mut buf, &pending[50..]),
            b"world"
        );
    }

    #[test]
    fn drop_cancels_reservation() {
        let mut enc = encoder();
        let mut out = EncodeBuffer::new(V4_WIRE_CAP);
        {
            let mut rec = enc.reserve(&mut out, &[], 8).unwrap();
            rec.payload_mut()[0] = 1;
        }
        assert!(out.is_empty());
    }
}

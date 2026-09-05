//! v4 record codec. v5 TCP uses the same types.

use core::fmt;

use zeroize::Zeroize;

use crate::aead::Aes128Gcm;
use crate::chunk::V4ChunkState;
use crate::header::{parse_v4_plain_header, write_v4_plain_header};
use crate::kdf::aead_key;
use crate::padding::{fill_v4_padding, swap_even_indices};
use crate::record::{DecodeStatus, DecodedRecord, RecordKind};
use crate::{
    AES_128_KEY_LEN, Clock, EncodeBuffer, Entropy, Error, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN,
    MAX_PACKET_SIZE, Nonce, OsEntropy, Psk, RecvBuffer, Result, SALT_LEN, TAG_LEN, UnixClock,
    V4_INITIAL_PADDING_MIN, V4_INITIAL_PADDING_SPAN,
};

/// v4 TCP record encoder. v5 TCP uses the same type.
pub struct V4Encoder<E = OsEntropy, C = UnixClock> {
    aead: Aes128Gcm,
    nonce: Nonce,
    salt: [u8; SALT_LEN],
    entropy: E,
    clock: C,
    chunk: V4ChunkState,
    reserving: bool,
    poisoned: bool,
    prefix_len: usize,
    max_payload: usize,
    padding_len: usize,
    payload_start: usize,
    header_start: usize,
    record_start: usize,
    reserved_budget: usize,
    reserved_at: u64,
}

/// RAII payload slot. Drop without [`V4Reservation::seal`] cancels the record.
#[must_use = "unsealed reservations are cancelled on drop"]
pub struct V4Reservation<'a, E: Entropy = OsEntropy, C: Clock = UnixClock> {
    encoder: &'a mut V4Encoder<E, C>,
    buf: &'a mut EncodeBuffer,
    sealed: bool,
}

impl<E: Entropy, C: Clock> V4Encoder<E, C> {
    pub fn new(psk: &Psk, mut entropy: E, clock: C) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        entropy.fill(&mut salt)?;
        let mut span = [0u8; 4];
        entropy.fill(&mut span)?;
        let initial_padding_len =
            V4_INITIAL_PADDING_MIN + (u32::from_le_bytes(span) % V4_INITIAL_PADDING_SPAN) as usize;
        Self::with_salt(psk, salt, initial_padding_len, entropy, clock)
    }

    pub fn with_salt(
        psk: &Psk,
        salt: [u8; SALT_LEN],
        initial_padding_len: usize,
        entropy: E,
        clock: C,
    ) -> Result<Self> {
        if initial_padding_len > MAX_PACKET_SIZE {
            return Err(Error::PayloadTooLarge);
        }
        let mut key = aead_key(psk.as_bytes(), &salt)?;
        let aead = Aes128Gcm::new(&key)?;
        key.zeroize();
        Ok(Self {
            aead,
            nonce: Nonce::new(),
            salt,
            entropy,
            clock,
            chunk: V4ChunkState::new(initial_padding_len),
            reserving: false,
            poisoned: false,
            prefix_len: 0,
            max_payload: 0,
            padding_len: 0,
            payload_start: 0,
            header_start: 0,
            record_start: 0,
            reserved_budget: 0,
            reserved_at: 0,
        })
    }

    /// Reserve a record in `buf`. `prefix` is copied into the payload slot.
    pub fn reserve<'buf>(
        &'buf mut self,
        buf: &'buf mut EncodeBuffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<V4Reservation<'buf, E, C>> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.reserving {
            return Err(Error::PendingWire);
        }
        let needed = prefix.len().saturating_add(hint);
        let now = self.clock.monotonic_secs();
        let budget = self.chunk.record_budget(now);
        let max_payload = self.chunk.payload_limit(now, needed);
        if prefix.len() > max_payload {
            return Err(Error::PayloadTooLarge);
        }

        let first = !self.chunk.salt_sent();
        let padding_len = if first && max_payload > 0 {
            self.chunk.initial_padding_len()
        } else {
            0
        };
        let salt_len = usize::from(first) * SALT_LEN;
        let fixed = salt_len + HEADER_CIPHER_LEN + padding_len;
        let record_cap = fixed + max_payload + TAG_LEN;
        let record_start = buf.reserve_record(record_cap, fixed)?;
        if first {
            buf.range_mut(record_start, record_start + SALT_LEN)
                .copy_from_slice(&self.salt);
        }
        let header_start = record_start + salt_len;
        let payload_start = header_start + HEADER_CIPHER_LEN + padding_len;
        buf.extend_from_slice(prefix)?;
        self.prefix_len = prefix.len();
        self.max_payload = max_payload;
        self.padding_len = padding_len;
        self.header_start = header_start;
        self.payload_start = payload_start;
        self.record_start = record_start;
        self.reserved_budget = budget;
        self.reserved_at = now;
        self.reserving = true;
        Ok(V4Reservation {
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
        let padding_len = if payload_len == 0 {
            0
        } else {
            self.padding_len
        };
        if payload_len == 0 {
            buf.truncate(self.header_start + HEADER_CIPHER_LEN)?;
        } else {
            let body_end = self.payload_start + payload_len + TAG_LEN;
            if buf.end() < body_end {
                // Zero-commit through the tag slot; never touches committed payload.
                buf.reserve_zeroed(body_end - buf.end())?;
            } else {
                buf.truncate(body_end)?;
            }
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
            self.chunk.mark_salt_sent();
            self.chunk
                .commit_write(self.reserved_at, self.reserved_budget);
        }
        result
    }

    fn seal_record(
        &mut self,
        buf: &mut EncodeBuffer,
        padding_len: usize,
        payload_len: usize,
    ) -> Result<()> {
        write_v4_plain_header(
            buf.range_mut(self.header_start, self.header_start + HEADER_PLAIN_LEN),
            padding_len,
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
            if padding_len > 0 {
                let body = buf.range_mut(
                    self.header_start + HEADER_CIPHER_LEN,
                    self.payload_start + payload_len + TAG_LEN,
                );
                let (padding, cipher_and_tag) = body.split_at_mut(padding_len);
                fill_v4_padding(padding, cipher_and_tag, &mut self.entropy)?;
                swap_even_indices(padding, cipher_and_tag);
            }
        }
        Ok(())
    }
}

impl V4Encoder<OsEntropy, UnixClock> {
    pub fn os(psk: &Psk) -> Result<Self> {
        Self::new(psk, OsEntropy, UnixClock::new())
    }
}

impl<E: Entropy, C: Clock> V4Reservation<'_, E, C> {
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let start = self.encoder.payload_start + self.encoder.prefix_len;
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

    /// Append into the reserved payload without zero-filling unused capacity.
    pub fn payload_buf(&mut self) -> crate::PayloadBuffer<'_> {
        let end = self.encoder.payload_start + self.encoder.max_payload;
        crate::PayloadBuffer::new(self.buf, end)
    }

    pub fn capacity(&self) -> usize {
        self.encoder.max_payload - self.encoder.prefix_len
    }

    pub fn padding_len(&self) -> usize {
        self.encoder.padding_len
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

impl<E: Entropy, C: Clock> Drop for V4Reservation<'_, E, C> {
    fn drop(&mut self) {
        if !self.sealed {
            let _ = self.buf.truncate(self.encoder.record_start);
            self.encoder.reserving = false;
        }
    }
}

impl<E, C> fmt::Debug for V4Encoder<E, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V4Encoder")
            .field("salt_sent", &self.chunk.salt_sent())
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

/// v4 / v5 TCP record decoder. Decrypts in place inside a [`RecvBuffer`].
pub struct V4Decoder {
    psk: Psk,
    aead: Option<Aes128Gcm>,
    nonce: Nonce,
    include_salt: bool,
    step: ReadStep,
    /// Bytes of returned-but-unconsumed records at the front of `filled()`.
    /// Decode-ahead parses the next record at this offset; [`Self::consume`]
    /// drains records FIFO.
    pending: usize,
}

impl V4Decoder {
    pub fn new(psk: Psk) -> Self {
        Self {
            psk,
            aead: None,
            nonce: Nonce::new(),
            include_salt: true,
            step: ReadStep::Salt,
            pending: 0,
        }
    }

    pub fn replay_identity(&self) -> Option<[u8; SALT_LEN]> {
        None
    }

    pub fn has_unconsumed_plaintext(&self) -> bool {
        self.pending != 0
    }

    /// Bytes of salt required before Argon2id. Zero after the key is installed.
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

    /// Skip inline KDF in [`Self::decode`] after the runtime derived the key.
    pub fn install_aead(&mut self, key: [u8; AES_128_KEY_LEN]) -> Result<()> {
        self.aead = Some(Aes128Gcm::new(&key)?);
        Ok(())
    }

    pub fn decode(&mut self, buf: &mut RecvBuffer) -> Result<DecodeStatus> {
        loop {
            match self.step {
                ReadStep::Salt => {
                    if let Some(need) = self.decode_need(buf, SALT_LEN)? {
                        return Ok(need);
                    }
                    if self.aead.is_none() {
                        let mut salt = [0u8; SALT_LEN];
                        salt.copy_from_slice(&buf.filled()[..SALT_LEN]);
                        let mut key = aead_key(self.psk.as_bytes(), &salt)?;
                        self.aead = Some(Aes128Gcm::new(&key)?);
                        key.zeroize();
                    }
                    self.step = ReadStep::Header;
                }
                ReadStep::Header => {
                    let off = self.header_offset();
                    let header_end = off + HEADER_CIPHER_LEN;
                    if let Some(need) = self.decode_need(buf, header_end)? {
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
                    let header = parse_v4_plain_header(cipher)?;
                    let body_len = header.body_len_v4()?;
                    if body_len == 0 {
                        self.include_salt = false;
                        self.step = ReadStep::Header;
                        let consumed = header_end - self.pending;
                        self.pending = header_end;
                        return Ok(DecodeStatus::Record(DecodedRecord {
                            consumed,
                            plaintext: 0..0,
                            kind: RecordKind::ZeroChunk,
                        }));
                    }
                    self.step = ReadStep::Body(header);
                }
                ReadStep::Body(header) => {
                    let off = self.header_offset();
                    let body_off = off + HEADER_CIPHER_LEN;
                    let body_len = header.body_len_v4()?;
                    let needed = body_off + body_len;
                    if let Some(need) = self.decode_need(buf, needed)? {
                        return Ok(need);
                    }
                    let body = &mut buf.filled_mut()[body_off..needed];
                    let (padding, rest) = body.split_at_mut(header.padding_len);
                    swap_even_indices(padding, rest);
                    let (payload, tag_bytes) = rest.split_at_mut(header.payload_len);
                    let mut tag = [0u8; TAG_LEN];
                    tag.copy_from_slice(tag_bytes);
                    self.aead
                        .as_ref()
                        .ok_or(Error::Aead)?
                        .open(&self.nonce, &[], payload, &tag)?;
                    self.nonce.increment();
                    let start = body_off + header.padding_len;
                    self.include_salt = false;
                    self.step = ReadStep::Header;
                    let consumed = needed - self.pending;
                    self.pending = needed;
                    return Ok(DecodeStatus::Record(DecodedRecord {
                        consumed,
                        plaintext: start..start + header.payload_len,
                        kind: RecordKind::Data,
                    }));
                }
            }
        }
    }

    pub fn consume(&mut self, buf: &mut RecvBuffer, record: &DecodedRecord) -> Result<()> {
        self.pending = self
            .pending
            .checked_sub(record.consumed)
            .ok_or(Error::PlaintextNotDrained)?;
        buf.consume(record.consumed)?;
        Ok(())
    }

    fn header_offset(&self) -> usize {
        self.pending + if self.include_salt { SALT_LEN } else { 0 }
    }

    /// `minimum` is measured from the start of `filled()` and includes
    /// `pending`. A record must fit the buffer on its own; when outstanding
    /// records crowd it out, report `NeedMore` so the caller drains first.
    fn decode_need(&self, buf: &RecvBuffer, minimum: usize) -> Result<Option<DecodeStatus>> {
        if minimum - self.pending > buf.max() {
            Err(Error::PayloadTooLarge)
        } else if buf.len() < minimum {
            Ok(Some(DecodeStatus::NeedMore { minimum }))
        } else {
            Ok(None)
        }
    }
}

impl fmt::Debug for V4Decoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V4Decoder")
            .field("include_salt", &self.include_salt)
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::next_v4_chunk_limit;
    use crate::header::write_v4_plain_header;
    use crate::padding::{fill_v4_padding, swap_even_indices};
    use crate::{
        Address, COMMAND_CONNECT, DecodeStatus, EncodeBuffer, FixedClock, ParseState, PlainStream,
        RecordKind, RepeatEntropy, SequenceEntropy, V4_FIRST_RECORD_OVERHEAD, V4_MSS_BASE,
        V4_RESET_OVERHEAD, V4_WIRE_CAP, encode_connect_request,
    };
    use std::cell::Cell;
    use std::rc::Rc;

    #[derive(Clone)]
    struct SharedClock {
        unix: Rc<Cell<u64>>,
        mono: Rc<Cell<u64>>,
    }

    impl Clock for SharedClock {
        fn unix_secs(&self) -> u64 {
            self.unix.get()
        }

        fn monotonic_secs(&self) -> u64 {
            self.mono.get()
        }
    }

    fn psk() -> Psk {
        Psk::new(b"0123456789abcdef").unwrap()
    }

    fn encoder_no_padding() -> V4Encoder<RepeatEntropy, FixedClock> {
        V4Encoder::with_salt(
            &psk(),
            [7; SALT_LEN],
            0,
            RepeatEntropy { byte: 0x3c },
            FixedClock::new(0),
        )
        .unwrap()
    }

    fn encode_buf() -> EncodeBuffer {
        EncodeBuffer::new(V4_WIRE_CAP)
    }

    fn collect_pending(buf: &EncodeBuffer) -> Vec<u8> {
        buf.pending().to_vec()
    }

    fn expected_first_no_padding(payload: &[u8]) -> Vec<u8> {
        let salt = [7u8; SALT_LEN];
        let mut key = aead_key(psk().as_bytes(), &salt).unwrap();
        let aead = Aes128Gcm::new(&key).unwrap();
        key.zeroize();
        let mut nonce = Nonce::new();
        let mut header = [0u8; HEADER_PLAIN_LEN];
        write_v4_plain_header(&mut header, 0, payload.len()).unwrap();
        let header_tag = aead.seal(&nonce, &[], &mut header).unwrap();
        nonce.increment();
        let mut body = payload.to_vec();
        let payload_tag = aead.seal(&nonce, &[], &mut body).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&salt);
        out.extend_from_slice(&header);
        out.extend_from_slice(&header_tag);
        out.extend_from_slice(&body);
        out.extend_from_slice(&payload_tag);
        out
    }

    fn expected_first_padded(payload: &[u8], padding_len: usize, entropy_byte: u8) -> Vec<u8> {
        let salt = [7u8; SALT_LEN];
        let mut key = aead_key(psk().as_bytes(), &salt).unwrap();
        let aead = Aes128Gcm::new(&key).unwrap();
        key.zeroize();
        let mut nonce = Nonce::new();
        let mut header = [0u8; HEADER_PLAIN_LEN];
        write_v4_plain_header(&mut header, padding_len, payload.len()).unwrap();
        let header_tag = aead.seal(&nonce, &[], &mut header).unwrap();
        nonce.increment();
        let mut body = payload.to_vec();
        let payload_tag = aead.seal(&nonce, &[], &mut body).unwrap();
        let mut padding = vec![0u8; padding_len];
        let mut cipher_and_tag = body;
        cipher_and_tag.extend_from_slice(&payload_tag);
        fill_v4_padding(
            &mut padding,
            &cipher_and_tag,
            &mut RepeatEntropy { byte: entropy_byte },
        )
        .unwrap();
        swap_even_indices(&mut padding, &mut cipher_and_tag);
        let mut out = Vec::new();
        out.extend_from_slice(&salt);
        out.extend_from_slice(&header);
        out.extend_from_slice(&header_tag);
        out.extend_from_slice(&padding);
        out.extend_from_slice(&cipher_and_tag);
        out
    }

    fn push(buf: &mut RecvBuffer, bytes: &[u8]) {
        buf.extend_from_slice(bytes).unwrap();
    }

    fn decode_plain(decoder: &mut V4Decoder, buf: &mut RecvBuffer, wire: &[u8]) -> Vec<u8> {
        push(buf, wire);
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
            if buf.is_empty() {
                break;
            }
        }
        plain
    }

    fn seal_payload(
        encoder: &mut V4Encoder<RepeatEntropy, FixedClock>,
        buf: &mut EncodeBuffer,
        payload: &[u8],
    ) {
        let mut rec = encoder.reserve(buf, &[], payload.len()).unwrap();
        rec.payload_mut()[..payload.len()].copy_from_slice(payload);
        rec.seal(payload.len()).unwrap();
    }

    #[test]
    fn hello_matches_independent_aead() {
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        seal_payload(&mut encoder, &mut out, b"hello");
        let wire = collect_pending(&out);
        assert_eq!(wire, expected_first_no_padding(b"hello"));
        assert_eq!(&wire[..SALT_LEN], &[7u8; SALT_LEN]);
        let hex: String = wire.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "07070707070707070707070707070707c5366a60ea813e1a53f43bacabb9936e9e38bf6df491850327876c199373b01537bcdbe9295174b2b65661bb"
        );
    }

    #[test]
    fn round_trip_hello() {
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        seal_payload(&mut encoder, &mut out, b"hello");
        let wire = collect_pending(&out);
        let mut decoder = V4Decoder::new(psk());
        let mut buf = RecvBuffer::new(4096);
        assert_eq!(decode_plain(&mut decoder, &mut buf, &wire), b"hello");
    }

    #[test]
    fn zero_chunk_round_trips() {
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        encoder.reserve(&mut out, &[], 0).unwrap().seal(0).unwrap();
        let wire = collect_pending(&out);
        assert_eq!(wire.len(), SALT_LEN + HEADER_CIPHER_LEN);
        let mut decoder = V4Decoder::new(psk());
        let mut buf = RecvBuffer::new(4096);
        push(&mut buf, &wire);
        match decoder.decode(&mut buf).unwrap() {
            DecodeStatus::Record(record) => {
                assert_eq!(record.kind, RecordKind::ZeroChunk);
                assert!(record.plaintext(buf.filled()).is_empty());
                decoder.consume(&mut buf, &record).unwrap();
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn second_record_has_no_salt_or_padding() {
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        seal_payload(&mut encoder, &mut out, b"one");
        let first_len = collect_pending(&out).len();
        out.advance(first_len).unwrap();
        seal_payload(&mut encoder, &mut out, b"two");
        let second = collect_pending(&out);
        assert!(second.len() < first_len);
        assert_ne!(&second[..SALT_LEN], &[7u8; SALT_LEN]);

        let mut decoder = V4Decoder::new(psk());
        let mut buf = RecvBuffer::new(4096);
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        seal_payload(&mut encoder, &mut out, b"one");
        let mut all = collect_pending(&out);
        out.advance(all.len()).unwrap();
        seal_payload(&mut encoder, &mut out, b"two");
        all.extend_from_slice(&collect_pending(&out));
        assert_eq!(decode_plain(&mut decoder, &mut buf, &all), b"onetwo");
    }

    #[test]
    fn two_records_share_pending_without_advance() {
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        seal_payload(&mut encoder, &mut out, b"hello");
        let first = collect_pending(&out);
        seal_payload(&mut encoder, &mut out, b"world");
        let pending = collect_pending(&out);
        assert_eq!(&pending[..first.len()], first.as_slice());
        out.advance(first.len()).unwrap();
        let second = collect_pending(&out);
        assert_eq!(pending[first.len()..], second);
        let mut decoder = V4Decoder::new(psk());
        let mut buf = RecvBuffer::new(4096);
        assert_eq!(
            decode_plain(&mut decoder, &mut buf, &pending),
            b"helloworld"
        );
    }

    #[test]
    fn second_record_compacts_over_unsent_prefix() {
        let mut encoder = encoder_no_padding();
        let mut out = EncodeBuffer::new(100);
        seal_payload(&mut encoder, &mut out, b"hello");
        let first = collect_pending(&out);
        assert_eq!(first.len(), 60);
        out.advance(10).unwrap();
        seal_payload(&mut encoder, &mut out, b"world");
        let pending = collect_pending(&out);
        assert_eq!(&pending[..50], &first[10..]);
        let mut decoder = V4Decoder::new(psk());
        let mut buf = RecvBuffer::new(4096);
        assert_eq!(decode_plain(&mut decoder, &mut buf, &first), b"hello");
        assert_eq!(
            decode_plain(&mut decoder, &mut buf, &pending[50..]),
            b"world"
        );
    }

    #[test]
    fn drop_after_compact_keeps_unsent_prefix() {
        let mut encoder = encoder_no_padding();
        let mut out = EncodeBuffer::new(100);
        seal_payload(&mut encoder, &mut out, b"hello");
        let first = collect_pending(&out);
        out.advance(10).unwrap();
        {
            let mut rec = encoder.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"xxxxx");
        }
        assert_eq!(collect_pending(&out), first[10..]);
    }

    #[test]
    fn padding_and_chunk_size() {
        let mut encoder = V4Encoder::with_salt(
            &psk(),
            [7; SALT_LEN],
            8,
            RepeatEntropy { byte: 0x11 },
            FixedClock::new(0),
        )
        .unwrap();
        let first_limit = V4_MSS_BASE - V4_FIRST_RECORD_OVERHEAD - 8;
        let mut out = encode_buf();
        {
            let mut first = encoder.reserve(&mut out, &[], MAX_PACKET_SIZE).unwrap();
            assert_eq!(first.capacity(), first_limit);
            assert_eq!(first.padding_len(), 8);
            first.payload_mut().fill(0x42);
            first.seal(first_limit).unwrap();
        }
        let pending = collect_pending(&out).len();
        out.advance(pending).unwrap();
        let second = encoder.reserve(&mut out, &[], MAX_PACKET_SIZE).unwrap();
        assert_eq!(second.padding_len(), 0);
        assert_eq!(second.capacity(), next_v4_chunk_limit(first_limit));
    }

    #[test]
    fn padded_record_round_trips() {
        let mut encoder = V4Encoder::with_salt(
            &psk(),
            [7; SALT_LEN],
            8,
            RepeatEntropy { byte: 0x11 },
            FixedClock::new(0),
        )
        .unwrap();
        let mut out = encode_buf();
        seal_payload(&mut encoder, &mut out, b"padded");
        let wire = collect_pending(&out);
        let mut decoder = V4Decoder::new(psk());
        let mut buf = RecvBuffer::new(4096);
        assert_eq!(decode_plain(&mut decoder, &mut buf, &wire), b"padded");
    }

    #[test]
    fn idle_reset_after_30s() {
        let unix = Rc::new(Cell::new(0u64));
        let mono = Rc::new(Cell::new(100u64));
        let mut encoder = V4Encoder::with_salt(
            &psk(),
            [7; SALT_LEN],
            8,
            RepeatEntropy { byte: 0x11 },
            SharedClock {
                unix: unix.clone(),
                mono: mono.clone(),
            },
        )
        .unwrap();
        let mut out = encode_buf();
        {
            let rec = encoder.reserve(&mut out, &[], MAX_PACKET_SIZE).unwrap();
            rec.seal(0).unwrap();
        }
        out.advance(collect_pending(&out).len()).unwrap();
        mono.set(130);
        {
            let rec = encoder.reserve(&mut out, &[], MAX_PACKET_SIZE).unwrap();
            assert_eq!(
                rec.capacity(),
                next_v4_chunk_limit(V4_MSS_BASE - V4_FIRST_RECORD_OVERHEAD - 8)
            );
            rec.seal(0).unwrap();
        }
        out.advance(collect_pending(&out).len()).unwrap();
        unix.set(10_000);
        {
            let rec = encoder.reserve(&mut out, &[], MAX_PACKET_SIZE).unwrap();
            assert_eq!(
                rec.capacity(),
                next_v4_chunk_limit(next_v4_chunk_limit(
                    V4_MSS_BASE - V4_FIRST_RECORD_OVERHEAD - 8
                ))
            );
        }
        mono.set(161);
        let rec = encoder.reserve(&mut out, &[], MAX_PACKET_SIZE).unwrap();
        assert_eq!(rec.capacity(), V4_MSS_BASE - V4_RESET_OVERHEAD);
    }

    #[test]
    fn connect_prefix_and_early_payload() {
        let address = Address::domain("example.com", 443).unwrap();
        let mut prefix = [0u8; 32];
        let n = encode_connect_request(&mut prefix, address.as_view(), false).unwrap();
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        {
            let mut rec = encoder.reserve(&mut out, &prefix[..n], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"hello");
            rec.seal(5).unwrap();
        }
        let wire = collect_pending(&out);
        let mut decoder = V4Decoder::new(psk());
        let mut buf = RecvBuffer::new(4096);
        let plain = decode_plain(&mut decoder, &mut buf, &wire);
        assert_eq!(plain[0], COMMAND_CONNECT);
        let mut stream = PlainStream::new(4096);
        stream.push(&plain).unwrap();
        match stream.connect().unwrap() {
            ParseState::Done((request, consumed)) => {
                assert!(!request.reuse);
                assert_eq!(&plain[consumed..], b"hello");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn tampered_tag_fails_closed() {
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        seal_payload(&mut encoder, &mut out, b"hello");
        let mut wire = collect_pending(&out);
        let last = wire.len() - 1;
        wire[last] ^= 1;
        let mut decoder = V4Decoder::new(psk());
        let mut buf = RecvBuffer::new(4096);
        push(&mut buf, &wire);
        assert_eq!(decoder.decode(&mut buf), Err(Error::Aead));
    }

    #[test]
    fn decode_ahead_batches_records_before_consume() {
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        seal_payload(&mut encoder, &mut out, b"hello");
        seal_payload(&mut encoder, &mut out, b"world");
        let wire = collect_pending(&out);
        let mut decoder = V4Decoder::new(psk());
        let mut buf = RecvBuffer::new(4096);
        push(&mut buf, &wire);
        let DecodeStatus::Record(first) = decoder.decode(&mut buf).unwrap() else {
            panic!("first record not ready");
        };
        let DecodeStatus::Record(second) = decoder.decode(&mut buf).unwrap() else {
            panic!("second record not ready");
        };
        assert!(decoder.has_unconsumed_plaintext());
        // Both plaintexts stay valid against the same unmoved filled() view.
        assert_eq!(first.plaintext(buf.filled()), b"hello");
        assert_eq!(second.plaintext(buf.filled()), b"world");
        assert_eq!(first.consumed + second.consumed, wire.len());
        // Records drain FIFO; the buffer advances per record.
        decoder.consume(&mut buf, &first).unwrap();
        decoder.consume(&mut buf, &second).unwrap();
        assert!(buf.is_empty());
        assert!(!decoder.has_unconsumed_plaintext());
        // Over-consuming past the outstanding records fails closed.
        assert_eq!(
            decoder.consume(&mut buf, &second),
            Err(Error::PlaintextNotDrained)
        );
        assert!(matches!(
            decoder.decode(&mut buf).unwrap(),
            DecodeStatus::NeedMore { .. }
        ));
    }

    #[test]
    fn drop_cancels_reservation() {
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        {
            let mut rec = encoder.reserve(&mut out, &[], 8).unwrap();
            rec.payload_mut()[0] = 1;
        }
        assert!(out.is_empty());
        seal_payload(&mut encoder, &mut out, b"x");
        let wire = collect_pending(&out);
        assert_eq!(&wire[..SALT_LEN], &[7u8; SALT_LEN]);
    }

    #[test]
    fn partial_advance_wire() {
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        seal_payload(&mut encoder, &mut out, b"hello");
        let wire = collect_pending(&out);
        out.advance(3).unwrap();
        let rest = collect_pending(&out);
        assert_eq!(rest, wire[3..]);
        out.advance(rest.len()).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn steady_state_reuses_wire_capacity() {
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        seal_payload(&mut encoder, &mut out, &[0xab; 64]);
        out.advance(collect_pending(&out).len()).unwrap();
        let cap = out.capacity();
        for _ in 0..32 {
            seal_payload(&mut encoder, &mut out, &[0xab; 64]);
            out.advance(collect_pending(&out).len()).unwrap();
            assert_eq!(out.capacity(), cap);
        }
    }

    #[test]
    fn debug_does_not_contain_psk() {
        let encoder = encoder_no_padding();
        let text = format!("{encoder:?}");
        assert!(!text.contains("0123456789abcdef"));
        assert!(text.contains("V4Encoder"));
        let decoder = V4Decoder::new(psk());
        assert!(!format!("{decoder:?}").contains("0123456789abcdef"));
    }

    #[test]
    fn os_constructor_round_trips() {
        let mut encoder = V4Encoder::os(&psk()).unwrap();
        let mut out = encode_buf();
        {
            let mut rec = encoder.reserve(&mut out, &[], 4).unwrap();
            rec.payload_mut()[..4].copy_from_slice(b"osok");
            rec.seal(4).unwrap();
        }
        let wire = collect_pending(&out);
        let mut decoder = V4Decoder::new(psk());
        let mut buf = RecvBuffer::new(8192);
        assert_eq!(decode_plain(&mut decoder, &mut buf, &wire), b"osok");
    }

    #[test]
    fn entropy_failure_after_nonce_increment_poisons_encoder() {
        let mut encoder = V4Encoder::with_salt(
            &psk(),
            [7; SALT_LEN],
            8,
            SequenceEntropy::new(&[]),
            FixedClock::new(0),
        )
        .unwrap();
        let mut out = encode_buf();
        let err = {
            let mut rec = encoder.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"hello");
            rec.seal(5)
        };
        assert_eq!(err, Err(Error::EntropyExhausted));
        assert!(out.is_empty());
        assert_eq!(
            encoder.reserve(&mut out, &[], 1).err(),
            Some(Error::Poisoned)
        );
    }

    #[test]
    fn dropped_post_salt_reservation_does_not_advance_chunk() {
        let mut encoder = V4Encoder::with_salt(
            &psk(),
            [7; SALT_LEN],
            8,
            RepeatEntropy { byte: 0x11 },
            FixedClock::new(0),
        )
        .unwrap();
        let mut out = encode_buf();
        seal_payload(&mut encoder, &mut out, b"one");
        out.advance(collect_pending(&out).len()).unwrap();
        let cancelled_cap;
        {
            let rec = encoder.reserve(&mut out, &[], MAX_PACKET_SIZE).unwrap();
            cancelled_cap = rec.capacity();
        }
        let rec = encoder.reserve(&mut out, &[], MAX_PACKET_SIZE).unwrap();
        assert_eq!(rec.capacity(), cancelled_cap);
        assert_ne!(rec.capacity(), next_v4_chunk_limit(cancelled_cap));
    }

    #[test]
    fn undersized_recv_buffer_rejects_first_header() {
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        seal_payload(&mut encoder, &mut out, b"hello");
        let wire = collect_pending(&out);
        assert!(wire.len() > 39);
        let mut decoder = V4Decoder::new(psk());
        let mut buf = RecvBuffer::new(38);
        push(&mut buf, &wire[..38]);
        assert_eq!(decoder.decode(&mut buf), Err(Error::PayloadTooLarge));
        assert_eq!(V4_WIRE_CAP, 32821);
    }

    #[test]
    fn padded_hello_matches_independent_aead_including_tag_swap() {
        let mut encoder = V4Encoder::with_salt(
            &psk(),
            [7; SALT_LEN],
            8,
            RepeatEntropy { byte: 0x3c },
            FixedClock::new(0),
        )
        .unwrap();
        let mut out = encode_buf();
        seal_payload(&mut encoder, &mut out, b"hello");
        let wire = collect_pending(&out);
        let expected = expected_first_padded(b"hello", 8, 0x3c);
        assert_eq!(wire, expected);
        let hex: String = wire.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, PADDED_HELLO_HEX);
    }

    #[test]
    fn seal_init_wire_matches_payload_mut() {
        let mk = || {
            V4Encoder::with_salt(
                &psk(),
                [7; SALT_LEN],
                32,
                RepeatEntropy { byte: 0x3c },
                FixedClock::new(0),
            )
            .unwrap()
        };
        let mut a_enc = mk();
        let mut a = encode_buf();
        let mut b_enc = mk();
        let mut b = encode_buf();
        // Padded first record, steady second record, short write under the hint.
        for (msg, hint) in [(&b"hello"[..], 5), (b"steady", 6), (b"abc", 8)] {
            let mut rec = a_enc.reserve(&mut a, &[], hint).unwrap();
            rec.payload_mut()[..msg.len()].copy_from_slice(msg);
            rec.seal(msg.len()).unwrap();

            let mut rec = b_enc.reserve(&mut b, &[], hint).unwrap();
            bytes::BufMut::put_slice(&mut rec.payload_buf(), msg);
            rec.seal(msg.len()).unwrap();
        }
        assert_eq!(a.pending(), b.pending());
    }

    #[test]
    fn seal_init_wire_matches_payload_mut_with_prefix() {
        let mut a_enc = encoder_no_padding();
        let mut a = encode_buf();
        let mut b_enc = encoder_no_padding();
        let mut b = encode_buf();

        let mut rec = a_enc.reserve(&mut a, b"pfx", 5).unwrap();
        rec.payload_mut()[..5].copy_from_slice(b"hello");
        rec.seal(5).unwrap();

        let mut rec = b_enc.reserve(&mut b, b"pfx", 5).unwrap();
        bytes::BufMut::put_slice(&mut rec.payload_buf(), b"hello");
        rec.seal(5).unwrap();

        assert_eq!(a.pending(), b.pending());
    }

    #[test]
    fn seal_init_after_payload_mut_fails_closed() {
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        let mut rec = encoder.reserve(&mut out, &[], 5).unwrap();
        rec.payload_mut()[..5].copy_from_slice(b"hello");
        assert!(rec.payload_uninit().is_empty());
        assert_eq!(rec.seal(5), Err(Error::PendingWire));
        assert!(out.is_empty(), "failed seal cancels the record");
        // The encoder recovers: the next reservation seals normally.
        let mut rec = encoder.reserve(&mut out, &[], 5).unwrap();
        rec.payload_mut()[..5].copy_from_slice(b"hello");
        rec.seal(5).unwrap();
        assert!(!out.is_empty());
    }

    const PADDED_HELLO_HEX: &str = "07070707070707070707070707070707c5366a60e2813e6ee63b822b726e54d05a8627cf2ccff4033c873c193c733c3c273c6c3c933cb01537bcdbe9295174b2b65661bb";
}

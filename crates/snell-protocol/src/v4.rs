//! v4 record codec. v5 TCP uses the same types.

use core::fmt;

use crate::aead::Aes128Gcm;
use crate::buffer::Slot;
use crate::chunk::V4ChunkState;
use crate::header::{RecordHeader, parse_v4_plain_header, write_v4_plain_header};
use crate::padding::{fill_v4_padding, swap_even_indices};
use crate::record::{DecodeStatus, DecodedRecord, Pending};
use crate::{
    AES_128_KEY_LEN, Buffer, Clock, Entropy, Error, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN,
    MAX_PACKET_SIZE, Nonce, OsEntropy, Psk, Result, SALT_LEN, TAG_LEN, UnixClock,
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
    /// Set while a reservation is outstanding, including one leaked with
    /// `mem::forget`, so a half-written record is never followed by another.
    reserving: bool,
    poisoned: bool,
}

/// Per-record layout decided by [`V4Encoder::reserve`].
#[derive(Clone, Copy, Debug)]
struct V4Record {
    slot: Slot,
    header_start: usize,
    padding_len: usize,
    budget: usize,
    reserved_at: u64,
}

/// RAII payload slot. Drop without [`V4Reservation::seal`] cancels the record.
#[must_use = "unsealed reservations are cancelled on drop"]
pub struct V4Reservation<'a, E: Entropy = OsEntropy, C: Clock = UnixClock> {
    encoder: &'a mut V4Encoder<E, C>,
    buf: &'a mut Buffer,
    record: V4Record,
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
        Ok(Self {
            aead: Aes128Gcm::derive(psk, &salt)?,
            nonce: Nonce::new(),
            salt,
            entropy,
            clock,
            chunk: V4ChunkState::new(initial_padding_len),
            reserving: false,
            poisoned: false,
        })
    }

    /// Reserve a record in `buf`. `prefix` is copied into the payload slot.
    pub fn reserve<'buf>(
        &'buf mut self,
        buf: &'buf mut Buffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<V4Reservation<'buf, E, C>> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.reserving {
            return Err(Error::PendingWire);
        }
        let now = self.clock.monotonic_secs();
        let budget = self.chunk.record_budget(now);
        let max_payload = self
            .chunk
            .payload_limit(now, prefix.len().saturating_add(hint));
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
        let record_start = buf.reserve_record(fixed + max_payload + TAG_LEN, fixed)?;
        if first {
            buf.range_mut(record_start, record_start + SALT_LEN)
                .copy_from_slice(&self.salt);
        }
        buf.extend_from_slice(prefix)?;
        self.reserving = true;
        Ok(V4Reservation {
            encoder: self,
            buf,
            record: V4Record {
                slot: Slot {
                    record_start,
                    payload_start: record_start + fixed,
                    prefix_len: prefix.len(),
                    max_payload,
                },
                header_start: record_start + salt_len,
                padding_len,
                budget,
                reserved_at: now,
            },
            sealed: false,
        })
    }

    fn finish(&mut self, buf: &mut Buffer, record: &V4Record, payload_len: usize) -> Result<()> {
        self.reserving = false;
        let nonce_before = self.nonce;
        let result = self.seal_record(buf, record, payload_len);
        match result {
            Ok(()) => {
                self.chunk.mark_salt_sent();
                self.chunk.commit_write(record.reserved_at, record.budget);
            }
            Err(_) => {
                self.poisoned |= self.nonce != nonce_before;
                buf.truncate(record.slot.record_start)?;
            }
        }
        result
    }

    fn seal_record(
        &mut self,
        buf: &mut Buffer,
        record: &V4Record,
        payload_len: usize,
    ) -> Result<()> {
        let header_start = record.header_start;
        let padding_start = header_start + HEADER_CIPHER_LEN;
        let (padding_len, record_end) = if payload_len == 0 {
            (0, padding_start)
        } else {
            (
                record.padding_len,
                record.slot.payload_start + payload_len + TAG_LEN,
            )
        };
        if buf.end() < record_end {
            // Zero-commit through the tag slot; never touches committed payload.
            buf.reserve_zeroed(record_end - buf.end())?;
        } else {
            buf.truncate(record_end)?;
        }

        let header = buf.range_mut(header_start, padding_start);
        write_v4_plain_header(header, padding_len, payload_len)?;
        self.aead.seal(&mut self.nonce, &[], header)?;
        if payload_len > 0 {
            let body = buf.range_mut(padding_start, record_end);
            let (padding, cipher_and_tag) = body.split_at_mut(padding_len);
            self.aead.seal(&mut self.nonce, &[], cipher_and_tag)?;
            if padding_len > 0 {
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
        self.record.padding_len
    }

    pub fn seal(mut self, written: usize) -> Result<()> {
        let total = self.record.slot.total(written)?;
        self.sealed = true;
        self.encoder.finish(self.buf, &self.record, total)
    }

    /// Seal after the caller initialized `written` bytes of
    /// [`Self::payload_uninit`]. Commits them without zero-filling first.
    pub(crate) fn seal_init_impl(mut self, written: usize) -> Result<()> {
        let total = self.record.slot.commit_init(self.buf, written)?;
        self.sealed = true;
        self.encoder.finish(self.buf, &self.record, total)
    }
}

impl<E: Entropy, C: Clock> Drop for V4Reservation<'_, E, C> {
    fn drop(&mut self) {
        if !self.sealed {
            let _ = self.buf.truncate(self.record.slot.record_start);
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
    Body { header: RecordHeader, len: usize },
}

/// v4 / v5 TCP record decoder. Decrypts in place inside a [`Buffer`].
pub struct V4Decoder {
    psk: Psk,
    aead: Option<Aes128Gcm>,
    nonce: Nonce,
    include_salt: bool,
    step: ReadStep,
    pending: Pending,
}

impl V4Decoder {
    pub fn new(psk: Psk) -> Self {
        Self {
            psk,
            aead: None,
            nonce: Nonce::new(),
            include_salt: true,
            step: ReadStep::Salt,
            pending: Pending::default(),
        }
    }

    pub fn replay_identity(&self) -> Option<[u8; SALT_LEN]> {
        None
    }

    pub fn has_unconsumed_plaintext(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Bytes of salt required before Argon2id. Zero after the key is installed.
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

    /// Skip inline KDF in [`Self::decode`] after the runtime derived the key.
    pub fn install_aead(&mut self, key: [u8; AES_128_KEY_LEN]) -> Result<()> {
        self.aead = Some(Aes128Gcm::new(&key)?);
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
                        self.aead = Some(Aes128Gcm::derive(&self.psk, &self.kdf_salt(buf)?)?);
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
                    let header = parse_v4_plain_header(&hdr[..HEADER_PLAIN_LEN])?;
                    let len = header.body_len_v4()?;
                    if len == 0 {
                        self.include_salt = false;
                        return Ok(self.pending.zero_chunk(header_end));
                    }
                    self.step = ReadStep::Body { header, len };
                }
                ReadStep::Body { header, len } => {
                    let body_off = self.header_offset() + HEADER_CIPHER_LEN;
                    let body_end = body_off + len;
                    if let Some(need) = self.pending.need(buf, body_end)? {
                        return Ok(need);
                    }
                    let body = &mut buf.filled_mut()[body_off..body_end];
                    let (padding, cipher_and_tag) = body.split_at_mut(header.padding_len);
                    swap_even_indices(padding, cipher_and_tag);
                    let aead = self.aead.as_ref().ok_or(Error::Aead)?;
                    aead.open(&mut self.nonce, &[], cipher_and_tag)?;
                    self.include_salt = false;
                    self.step = ReadStep::Header;
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

    fn header_offset(&self) -> usize {
        self.pending.offset() + usize::from(self.include_salt) * SALT_LEN
    }
}

impl fmt::Debug for V4Decoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V4Decoder")
            .field("include_salt", &self.include_salt)
            .field("pending", &self.pending.offset())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::next_v4_chunk_limit;
    use crate::{
        Address, COMMAND_CONNECT, FixedClock, ParseState, PlainStream, RecordKind, RepeatEntropy,
        SequenceEntropy, V4_FIRST_RECORD_OVERHEAD, V4_MSS_BASE, V4_RESET_OVERHEAD, V4_WIRE_CAP,
        encode_connect_request,
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

    fn encode_buf() -> Buffer {
        Buffer::new(V4_WIRE_CAP)
    }

    fn collect_pending(buf: &Buffer) -> Vec<u8> {
        buf.filled().to_vec()
    }

    /// First record built independently of the encoder: salt, sealed header,
    /// then padding filled and swapped against the sealed payload.
    fn expected_first(payload: &[u8], padding_len: usize, entropy_byte: u8) -> Vec<u8> {
        let salt = [7u8; SALT_LEN];
        let aead = Aes128Gcm::derive(&psk(), &salt).unwrap();
        let mut nonce = Nonce::new();
        let mut header = [0u8; HEADER_CIPHER_LEN];
        write_v4_plain_header(&mut header, padding_len, payload.len()).unwrap();
        aead.seal(&mut nonce, &[], &mut header).unwrap();
        let mut body = payload.to_vec();
        body.resize(payload.len() + TAG_LEN, 0);
        aead.seal(&mut nonce, &[], &mut body).unwrap();
        let mut padding = vec![0u8; padding_len];
        fill_v4_padding(
            &mut padding,
            &body,
            &mut RepeatEntropy { byte: entropy_byte },
        )
        .unwrap();
        swap_even_indices(&mut padding, &mut body);
        [&salt[..], &header, &padding, &body].concat()
    }

    fn push(buf: &mut Buffer, bytes: &[u8]) {
        buf.extend_from_slice(bytes).unwrap();
    }

    fn decode_plain(decoder: &mut V4Decoder, buf: &mut Buffer, wire: &[u8]) -> Vec<u8> {
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
        buf: &mut Buffer,
        payload: &[u8],
    ) {
        let mut rec = encoder.reserve(buf, &[], payload.len()).unwrap();
        rec.payload_mut()[..payload.len()].copy_from_slice(payload);
        rec.seal(payload.len()).unwrap();
    }

    // Byte-exact wire for these records is pinned by tests/golden via snell-testkit.
    #[test]
    fn first_record_matches_independent_aead() {
        for (padding_len, entropy_byte) in [(0, 0x3c), (8, 0x3c), (8, 0x11)] {
            let mut encoder = V4Encoder::with_salt(
                &psk(),
                [7; SALT_LEN],
                padding_len,
                RepeatEntropy { byte: entropy_byte },
                FixedClock::new(0),
            )
            .unwrap();
            let mut out = encode_buf();
            seal_payload(&mut encoder, &mut out, b"hello");
            assert_eq!(
                out.filled(),
                expected_first(b"hello", padding_len, entropy_byte)
            );
        }
    }

    #[test]
    fn zero_chunk_round_trips() {
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        encoder.reserve(&mut out, &[], 0).unwrap().seal(0).unwrap();
        let wire = collect_pending(&out);
        assert_eq!(wire.len(), SALT_LEN + HEADER_CIPHER_LEN);
        let mut decoder = V4Decoder::new(psk());
        let mut buf = Buffer::new(4096);
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
        let mut all = collect_pending(&out);
        out.consume(all.len()).unwrap();
        seal_payload(&mut encoder, &mut out, b"two");
        let second = collect_pending(&out);
        assert_eq!(second.len(), HEADER_CIPHER_LEN + 3 + TAG_LEN);
        all.extend_from_slice(&second);

        let mut decoder = V4Decoder::new(psk());
        let mut buf = Buffer::new(4096);
        assert_eq!(decode_plain(&mut decoder, &mut buf, &all), b"onetwo");
    }

    #[test]
    fn second_record_compacts_over_unsent_prefix() {
        let mut encoder = encoder_no_padding();
        let mut out = Buffer::new(100);
        seal_payload(&mut encoder, &mut out, b"hello");
        let first = collect_pending(&out);
        assert_eq!(first.len(), 60);
        out.consume(10).unwrap();
        seal_payload(&mut encoder, &mut out, b"world");
        let pending = collect_pending(&out);
        assert_eq!(&pending[..50], &first[10..]);
        let mut decoder = V4Decoder::new(psk());
        let mut buf = Buffer::new(4096);
        assert_eq!(decode_plain(&mut decoder, &mut buf, &first), b"hello");
        assert_eq!(
            decode_plain(&mut decoder, &mut buf, &pending[50..]),
            b"world"
        );
    }

    #[test]
    fn drop_after_compact_keeps_unsent_prefix() {
        let mut encoder = encoder_no_padding();
        let mut out = Buffer::new(100);
        seal_payload(&mut encoder, &mut out, b"hello");
        let first = collect_pending(&out);
        out.consume(10).unwrap();
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
        out.consume(pending).unwrap();
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
        let mut buf = Buffer::new(4096);
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
        out.consume(collect_pending(&out).len()).unwrap();
        mono.set(130);
        {
            let rec = encoder.reserve(&mut out, &[], MAX_PACKET_SIZE).unwrap();
            assert_eq!(
                rec.capacity(),
                next_v4_chunk_limit(V4_MSS_BASE - V4_FIRST_RECORD_OVERHEAD - 8)
            );
            rec.seal(0).unwrap();
        }
        out.consume(collect_pending(&out).len()).unwrap();
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
        let mut buf = Buffer::new(4096);
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
        let mut buf = Buffer::new(4096);
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
        let mut buf = Buffer::new(4096);
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
    fn steady_state_reuses_wire_capacity() {
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        seal_payload(&mut encoder, &mut out, &[0xab; 64]);
        out.consume(collect_pending(&out).len()).unwrap();
        let cap = out.capacity();
        for _ in 0..32 {
            seal_payload(&mut encoder, &mut out, &[0xab; 64]);
            out.consume(collect_pending(&out).len()).unwrap();
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
        let mut buf = Buffer::new(8192);
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
        out.consume(collect_pending(&out).len()).unwrap();
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
        let mut buf = Buffer::new(38);
        push(&mut buf, &wire[..38]);
        assert_eq!(decoder.decode(&mut buf), Err(Error::PayloadTooLarge));
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
        // Padded first record, prefixed steady record, short write under the hint.
        for (prefix, msg, hint) in [
            (&b""[..], &b"hello"[..], 5),
            (b"pfx", b"steady", 6),
            (b"", b"abc", 8),
        ] {
            let mut rec = a_enc.reserve(&mut a, prefix, hint).unwrap();
            rec.payload_mut()[..msg.len()].copy_from_slice(msg);
            rec.seal(msg.len()).unwrap();

            let mut rec = b_enc.reserve(&mut b, prefix, hint).unwrap();
            rec.payload_uninit()[..msg.len()].write_copy_of_slice(msg);
            rec.seal_init_impl(msg.len()).unwrap();
        }
        assert_eq!(a.filled(), b.filled());
    }

    #[test]
    fn seal_init_after_payload_mut_fails_closed() {
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        let mut rec = encoder.reserve(&mut out, &[], 5).unwrap();
        rec.payload_mut()[..5].copy_from_slice(b"hello");
        assert!(rec.payload_uninit().is_empty());
        assert_eq!(rec.seal_init_impl(5), Err(Error::PendingWire));
        assert!(out.is_empty(), "failed seal cancels the record");
        // The encoder recovers: the next reservation seals normally.
        let mut rec = encoder.reserve(&mut out, &[], 5).unwrap();
        rec.payload_mut()[..5].copy_from_slice(b"hello");
        rec.seal(5).unwrap();
        assert!(!out.is_empty());
    }
}

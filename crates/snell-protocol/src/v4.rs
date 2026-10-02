//! v4 record codec. v5 TCP uses the same types.

use core::fmt;

use crate::aead::Aes128Gcm;
use crate::buffer::{Reservation, Slot};
use crate::chunk::V4ChunkState;
use crate::codec::sealed::Seal;
use crate::codec::{RecordDecoder, RecordEncoder};
use crate::header::{RecordHeader, opened_header, parse_v4_plain_header, plain_header};
use crate::padding::{fill_v4_padding, swap_even_indices};
use crate::record::{DecodeStatus, DecodedRecord, EncoderState, Pending};
use crate::{
    AES_128_KEY_LEN, Buffer, Clock, Entropy, Error, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN,
    MAX_PACKET_SIZE, MonotonicClock, Nonce, OsEntropy, Psk, Result, SALT_LEN, TAG_LEN,
    V4_INITIAL_PADDING_MIN, V4_INITIAL_PADDING_SPAN,
};

/// v4 TCP record encoder. v5 TCP uses the same type.
pub struct V4Encoder<E = OsEntropy, C = MonotonicClock> {
    aead: Aes128Gcm,
    nonce: Nonce,
    salt: [u8; SALT_LEN],
    entropy: E,
    clock: C,
    chunk: V4ChunkState,
    state: EncoderState,
}

/// Per-record layout decided by [`V4Encoder::reserve`].
#[derive(Clone, Copy, Debug)]
pub struct V4Record {
    header_start: usize,
    padding_len: usize,
    /// Chunk budget at reserve time; a sealed record grows the window from it.
    budget: usize,
    reserved_at: u64,
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
            state: EncoderState::Ready,
        })
    }

    fn seal_record(
        &mut self,
        buf: &mut Buffer,
        slot: &Slot,
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
                slot.payload_start + payload_len + TAG_LEN,
            )
        };
        // Zero-commit through the tag slot; never touches committed payload.
        buf.set_record_end(record_end);

        let header = buf.range_mut(header_start, padding_start);
        header[..HEADER_PLAIN_LEN].copy_from_slice(&plain_header(padding_len, payload_len));
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

impl<E: Entropy, C: Clock> RecordEncoder for V4Encoder<E, C> {
    fn reserve<'a>(
        &'a mut self,
        buf: &'a mut Buffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<Reservation<'a, Self>> {
        self.state.ensure_ready()?;
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
        let slot = Slot {
            record_start,
            payload_start: record_start + fixed,
            prefix_len: prefix.len(),
            max_payload,
        };
        let record = V4Record {
            header_start: record_start + salt_len,
            padding_len,
            budget,
            reserved_at: now,
        };
        Ok(Reservation::new(self, buf, slot, record))
    }
}

impl<E: Entropy, C: Clock> Seal for V4Encoder<E, C> {
    type Record = V4Record;

    fn state(&mut self) -> &mut EncoderState {
        &mut self.state
    }

    fn finish(
        &mut self,
        buf: &mut Buffer,
        slot: &Slot,
        record: &V4Record,
        payload_len: usize,
    ) -> Result<usize> {
        let nonce_before = self.nonce;
        let result = self.seal_record(buf, slot, record, payload_len);
        self.state = EncoderState::after_seal(result.is_err() && self.nonce != nonce_before);
        match result {
            Ok(()) => self.chunk.commit_write(record.reserved_at, record.budget),
            Err(_) => buf.truncate(slot.record_start)?,
        }
        result.map(|()| 0)
    }
}

impl V4Encoder {
    pub fn os(psk: &Psk) -> Result<Self> {
        Self::new(psk, OsEntropy, MonotonicClock::new())
    }
}

impl<E, C> fmt::Debug for V4Encoder<E, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V4Encoder")
            .field("salt_sent", &self.chunk.salt_sent())
            .field("state", &self.state)
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

    fn header_offset(&self) -> usize {
        self.pending.offset() + usize::from(self.include_salt) * SALT_LEN
    }
}

impl RecordDecoder for V4Decoder {
    fn decode(&mut self, buf: &mut Buffer) -> Result<DecodeStatus> {
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
                    let mut hdr = *buf.filled()[off..]
                        .first_chunk::<HEADER_CIPHER_LEN>()
                        .ok_or(Error::Truncated)?;
                    let aead = self.aead.as_ref().ok_or(Error::Aead)?;
                    aead.open(&mut self.nonce, &[], &mut hdr)?;
                    let header = parse_v4_plain_header(opened_header(&hdr))?;
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

    fn consume(&mut self, buf: &mut Buffer, record: &DecodedRecord) -> Result<()> {
        self.pending.consume(buf, record)
    }

    fn has_unconsumed_plaintext(&self) -> bool {
        !self.pending.is_empty()
    }

    /// v4 salts are not replay-checked.
    fn replay_identity(&self) -> Option<[u8; SALT_LEN]> {
        None
    }

    fn kdf_need(&self) -> usize {
        if self.aead.is_none() && matches!(self.step, ReadStep::Salt) {
            SALT_LEN
        } else {
            0
        }
    }

    fn kdf_salt(&self, buf: &Buffer) -> Result<[u8; SALT_LEN]> {
        buf.filled().first_chunk().copied().ok_or(Error::Truncated)
    }

    fn install_aead(&mut self, _salt: [u8; SALT_LEN], key: [u8; AES_128_KEY_LEN]) -> Result<()> {
        self.aead = Some(Aes128Gcm::new(&key)?);
        Ok(())
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

    /// Monotonic time the test advances while the encoder holds a clone.
    #[derive(Clone, Default)]
    struct SharedClock(Rc<Cell<u64>>);

    impl Clock for SharedClock {
        fn monotonic_secs(&self) -> u64 {
            self.0.get()
        }
    }

    fn psk() -> Psk {
        Psk::new(b"0123456789abcdef").unwrap()
    }

    fn encoder<C: Clock>(padding_len: usize, clock: C) -> V4Encoder<RepeatEntropy, C> {
        V4Encoder::with_salt(
            &psk(),
            [7; SALT_LEN],
            padding_len,
            RepeatEntropy { byte: 0x11 },
            clock,
        )
        .unwrap()
    }

    fn encoder_no_padding() -> V4Encoder<RepeatEntropy, FixedClock> {
        encoder(0, FixedClock::new(0))
    }

    fn encode_buf() -> Buffer {
        Buffer::new(V4_WIRE_CAP)
    }

    /// First record built independently of the encoder: salt, sealed header,
    /// then padding filled and swapped against the sealed payload.
    fn expected_first(payload: &[u8], padding_len: usize, entropy_byte: u8) -> Vec<u8> {
        let salt = [7u8; SALT_LEN];
        let aead = Aes128Gcm::derive(&psk(), &salt).unwrap();
        let mut nonce = Nonce::new();
        let mut header = [0u8; HEADER_CIPHER_LEN];
        header[..HEADER_PLAIN_LEN].copy_from_slice(&plain_header(padding_len, payload.len()));
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

    fn decode_plain(decoder: &mut V4Decoder, buf: &mut Buffer, wire: &[u8]) -> Vec<u8> {
        buf.extend_from_slice(wire).unwrap();
        let mut plain = Vec::new();
        while let DecodeStatus::Record(record) = decoder.decode(buf).unwrap() {
            if record.kind == RecordKind::Data {
                plain.extend_from_slice(record.plaintext(buf.filled()));
            }
            decoder.consume(buf, &record).unwrap();
        }
        plain
    }

    fn seal_payload<E: Entropy, C: Clock>(
        encoder: &mut V4Encoder<E, C>,
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
    fn second_record_compacts_over_unsent_prefix_without_salt() {
        let mut encoder = encoder_no_padding();
        let mut out = Buffer::new(100);
        seal_payload(&mut encoder, &mut out, b"hello");
        let first = out.filled().to_vec();
        assert_eq!(first.len(), SALT_LEN + HEADER_CIPHER_LEN + 5 + TAG_LEN);
        out.consume(10).unwrap();
        seal_payload(&mut encoder, &mut out, b"world");
        let pending = out.filled().to_vec();
        assert_eq!(&pending[..50], &first[10..]);
        assert_eq!(pending.len() - 50, HEADER_CIPHER_LEN + 5 + TAG_LEN);
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
        let first = out.filled().to_vec();
        out.consume(10).unwrap();
        {
            let mut rec = encoder.reserve(&mut out, &[], 5).unwrap();
            rec.payload_mut()[..5].copy_from_slice(b"xxxxx");
        }
        assert_eq!(out.filled(), &first[10..]);
    }

    #[test]
    fn padding_and_chunk_size() {
        let mut encoder = encoder(8, FixedClock::new(0));
        let first_limit = V4_MSS_BASE - V4_FIRST_RECORD_OVERHEAD - 8;
        let mut out = encode_buf();
        let mut first = encoder.reserve(&mut out, &[], MAX_PACKET_SIZE).unwrap();
        assert_eq!(first.capacity(), first_limit);
        first.payload_mut().fill(0x42);
        first.seal(first_limit).unwrap();
        let padded = SALT_LEN + HEADER_CIPHER_LEN + 8 + first_limit + TAG_LEN;
        assert_eq!(out.len(), padded, "only the first record is padded");
        out.consume(out.len()).unwrap();

        let second_limit = next_v4_chunk_limit(first_limit);
        let mut second = encoder.reserve(&mut out, &[], MAX_PACKET_SIZE).unwrap();
        assert_eq!(second.capacity(), second_limit);
        second.payload_mut().fill(0x42);
        second.seal(second_limit).unwrap();
        assert_eq!(out.len(), HEADER_CIPHER_LEN + second_limit + TAG_LEN);
    }

    #[test]
    fn idle_reset_after_30s() {
        let clock = SharedClock::default();
        clock.0.set(100);
        let mut encoder = encoder(8, clock.clone());
        let mut out = encode_buf();
        encoder
            .reserve(&mut out, &[], MAX_PACKET_SIZE)
            .unwrap()
            .seal(0)
            .unwrap();
        out.consume(out.len()).unwrap();
        clock.0.set(130);
        {
            let rec = encoder.reserve(&mut out, &[], MAX_PACKET_SIZE).unwrap();
            assert_eq!(
                rec.capacity(),
                next_v4_chunk_limit(V4_MSS_BASE - V4_FIRST_RECORD_OVERHEAD - 8)
            );
            rec.seal(0).unwrap();
        }
        out.consume(out.len()).unwrap();
        clock.0.set(161);
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
        let mut decoder = V4Decoder::new(psk());
        let mut buf = Buffer::new(4096);
        let plain = decode_plain(&mut decoder, &mut buf, out.filled());
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
    fn steady_state_reuses_wire_capacity() {
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        seal_payload(&mut encoder, &mut out, &[0xab; 64]);
        out.consume(out.len()).unwrap();
        let cap = out.capacity();
        for _ in 0..32 {
            seal_payload(&mut encoder, &mut out, &[0xab; 64]);
            out.consume(out.len()).unwrap();
            assert_eq!(out.capacity(), cap);
        }
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
        let mut encoder = encoder(8, FixedClock::new(0));
        let mut out = encode_buf();
        seal_payload(&mut encoder, &mut out, b"one");
        out.consume(out.len()).unwrap();
        let cancelled_cap = encoder
            .reserve(&mut out, &[], MAX_PACKET_SIZE)
            .unwrap()
            .capacity();
        let rec = encoder.reserve(&mut out, &[], MAX_PACKET_SIZE).unwrap();
        assert_eq!(rec.capacity(), cancelled_cap);
        assert_ne!(rec.capacity(), next_v4_chunk_limit(cancelled_cap));
    }

    #[test]
    fn undersized_recv_buffer_rejects_first_header() {
        let mut encoder = encoder_no_padding();
        let mut out = encode_buf();
        seal_payload(&mut encoder, &mut out, b"hello");
        assert!(out.len() > 39);
        let mut decoder = V4Decoder::new(psk());
        let mut buf = Buffer::new(38);
        buf.extend_from_slice(&out.filled()[..38]).unwrap();
        assert_eq!(decoder.decode(&mut buf), Err(Error::PayloadTooLarge));
    }
}

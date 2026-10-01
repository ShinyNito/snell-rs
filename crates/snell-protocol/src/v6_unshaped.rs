//! v6 unshaped record codec: Argon2id + AES-128-GCM, no padding, no chunk window.

use core::fmt;

use crate::aead::Aes128Gcm;
use crate::buffer::Slot;
use crate::header::{opened_header, parse_v6_plain_header, plain_header};
use crate::record::{DecodeStatus, DecodedRecord, EncoderState, Pending};
use crate::{
    AES_128_KEY_LEN, Buffer, Entropy, Error, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN, MAX_PACKET_SIZE,
    Nonce, OsEntropy, Psk, Result, SALT_LEN, TAG_LEN,
};

pub struct V6UnshapedEncoder {
    aead: Aes128Gcm,
    nonce: Nonce,
    salt: [u8; SALT_LEN],
    salt_sent: bool,
    state: EncoderState,
}

#[must_use = "unsealed reservations are cancelled on drop"]
pub struct V6UnshapedReservation<'a> {
    encoder: &'a mut V6UnshapedEncoder,
    buf: &'a mut Buffer,
    slot: Slot,
}

impl V6UnshapedEncoder {
    pub fn new(psk: &Psk, mut entropy: impl Entropy) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        entropy.fill(&mut salt)?;
        Self::with_salt(psk, salt)
    }

    pub fn with_salt(psk: &Psk, salt: [u8; SALT_LEN]) -> Result<Self> {
        Ok(Self {
            aead: Aes128Gcm::derive(psk, &salt)?,
            nonce: Nonce::new(),
            salt,
            salt_sent: false,
            state: EncoderState::Ready,
        })
    }

    pub fn os(psk: &Psk) -> Result<Self> {
        Self::new(psk, OsEntropy)
    }

    pub fn reserve<'buf>(
        &'buf mut self,
        buf: &'buf mut Buffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<V6UnshapedReservation<'buf>> {
        self.state.ensure_ready()?;
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
        self.state = EncoderState::Reserving;
        Ok(V6UnshapedReservation {
            encoder: self,
            buf,
            slot: Slot {
                record_start,
                payload_start: record_start + fixed,
                prefix_len: prefix.len(),
                max_payload,
            },
        })
    }

    fn finish(&mut self, buf: &mut Buffer, slot: &Slot, payload_len: usize) -> Result<()> {
        let nonce_before = self.nonce;
        let result = self.seal_record(buf, slot, payload_len);
        self.state = EncoderState::after_seal(result.is_err() && self.nonce != nonce_before);
        match result {
            Ok(()) => self.salt_sent = true,
            Err(_) => buf.truncate(slot.record_start)?,
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
        // Zero-commit through the tag slot; never touches committed payload.
        buf.set_record_end(record_end);

        let header = buf.range_mut(header_start, slot.payload_start);
        header[..HEADER_PLAIN_LEN].copy_from_slice(&plain_header(0, payload_len));
        self.aead.seal(&mut self.nonce, &[], header)?;
        if payload_len > 0 {
            let payload = buf.range_mut(slot.payload_start, record_end);
            self.aead.seal(&mut self.nonce, &[], payload)?;
        }
        Ok(())
    }
}

impl V6UnshapedReservation<'_> {
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

    pub fn seal(self, written: usize) -> Result<()> {
        let total = self.slot.total(written)?;
        self.encoder.finish(self.buf, &self.slot, total)
    }

    /// Seal after the caller initialized `written` bytes of
    /// [`Self::payload_uninit`]. Commits them without zero-filling first.
    pub(crate) fn seal_init_impl(self, written: usize) -> Result<()> {
        let total = self.slot.commit_init(self.buf, written)?;
        self.encoder.finish(self.buf, &self.slot, total)
    }
}

impl Drop for V6UnshapedReservation<'_> {
    fn drop(&mut self) {
        if self.encoder.state == EncoderState::Reserving {
            let _ = self.buf.truncate(self.slot.record_start);
            self.encoder.state = EncoderState::Ready;
        }
    }
}

impl fmt::Debug for V6UnshapedEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6UnshapedEncoder")
            .field("salt_sent", &self.salt_sent)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug)]
enum ReadStep {
    Salt,
    Header,
    Body { payload_len: usize, len: usize },
}

pub struct V6UnshapedDecoder {
    psk: Psk,
    /// Session cipher and the salt it was derived from (the replay identity).
    key: Option<(Aes128Gcm, [u8; SALT_LEN])>,
    nonce: Nonce,
    include_salt: bool,
    step: ReadStep,
    pending: Pending,
}

impl V6UnshapedDecoder {
    pub fn new(psk: Psk) -> Self {
        Self {
            psk,
            key: None,
            nonce: Nonce::new(),
            include_salt: true,
            step: ReadStep::Salt,
            pending: Pending::default(),
        }
    }

    /// 16-byte AEAD salt, available after the first record's salt is parsed.
    pub fn replay_identity(&self) -> Option<[u8; SALT_LEN]> {
        self.key.as_ref().map(|(_, salt)| *salt)
    }

    pub fn has_unconsumed_plaintext(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn kdf_need(&self) -> usize {
        if self.key.is_none() && matches!(self.step, ReadStep::Salt) {
            SALT_LEN
        } else {
            0
        }
    }

    pub fn kdf_salt(&self, buf: &Buffer) -> Result<[u8; SALT_LEN]> {
        buf.filled().first_chunk().copied().ok_or(Error::Truncated)
    }

    pub fn install_aead(&mut self, salt: [u8; SALT_LEN], key: [u8; AES_128_KEY_LEN]) -> Result<()> {
        self.key = Some((Aes128Gcm::new(&key)?, salt));
        Ok(())
    }

    pub fn decode(&mut self, buf: &mut Buffer) -> Result<DecodeStatus> {
        loop {
            match self.step {
                ReadStep::Salt => {
                    if let Some(need) = self.pending.need(buf, SALT_LEN)? {
                        return Ok(need);
                    }
                    if self.key.is_none() {
                        let salt = self.kdf_salt(buf)?;
                        self.key = Some((Aes128Gcm::derive(&self.psk, &salt)?, salt));
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
                    let (aead, _) = self.key.as_ref().ok_or(Error::Aead)?;
                    aead.open(&mut self.nonce, &[], &mut hdr)?;
                    let header = parse_v6_plain_header(opened_header(&hdr))?;
                    let len = header.body_len_v6_unshaped()?;
                    if len == 0 {
                        self.include_salt = false;
                        return Ok(self.pending.zero_chunk(header_end));
                    }
                    self.step = ReadStep::Body {
                        payload_len: header.payload_len,
                        len,
                    };
                }
                ReadStep::Body { payload_len, len } => {
                    let body_off = self.header_offset() + HEADER_CIPHER_LEN;
                    let body_end = body_off + len;
                    if let Some(need) = self.pending.need(buf, body_end)? {
                        return Ok(need);
                    }
                    let (aead, _) = self.key.as_ref().ok_or(Error::Aead)?;
                    aead.open(
                        &mut self.nonce,
                        &[],
                        &mut buf.filled_mut()[body_off..body_end],
                    )?;
                    self.include_salt = false;
                    self.step = ReadStep::Header;
                    return Ok(self
                        .pending
                        .data(body_end, body_off..body_off + payload_len));
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

    fn psk() -> Psk {
        Psk::new(b"0123456789abcdef").unwrap()
    }

    fn seal(encoder: &mut V6UnshapedEncoder, buf: &mut Buffer, payload: &[u8]) {
        let mut rec = encoder.reserve(buf, &[], payload.len()).unwrap();
        rec.payload_mut()[..payload.len()].copy_from_slice(payload);
        rec.seal(payload.len()).unwrap();
    }

    #[test]
    fn second_record_compacts_over_unsent_prefix_without_salt() {
        let mut enc = V6UnshapedEncoder::with_salt(&psk(), [7; SALT_LEN]).unwrap();
        let mut out = Buffer::new(100);
        seal(&mut enc, &mut out, b"hello");
        let first = out.filled().to_vec();
        assert_eq!(first.len(), SALT_LEN + HEADER_CIPHER_LEN + 5 + TAG_LEN);
        out.consume(10).unwrap();
        seal(&mut enc, &mut out, b"world");
        let pending = out.filled().to_vec();
        assert_eq!(&pending[..50], &first[10..]);
        assert_eq!(pending.len() - 50, HEADER_CIPHER_LEN + 5 + TAG_LEN);

        let mut decoder = V6UnshapedDecoder::new(psk());
        let mut buf = Buffer::new(4096);
        buf.extend_from_slice(&first).unwrap();
        buf.extend_from_slice(&pending[50..]).unwrap();
        for expected in [&b"hello"[..], b"world"] {
            let DecodeStatus::Record(record) = decoder.decode(&mut buf).unwrap() else {
                panic!("record not decoded");
            };
            assert_eq!(record.plaintext(buf.filled()), expected);
            decoder.consume(&mut buf, &record).unwrap();
        }
    }
}

//! V6 unshaped codec: AEAD-protected frames without traffic shaping.
//!
//! Same framing and KDF (HKDF → AES-128-GCM) as V4, but:
//! - **No padding** — `padding_len` is forced to zero.
//! - **No congestion window** — the encoder writes up to [`MAX_PACKET_SIZE`] per record.
//! - First record carries a 16-byte salt; subsequent records are header+body only.
//!
//! # Wire layout
//!
//! ```text
//!   first record:   SALT(16) | HEADER_CIPHER(23) | BODY?
//!   subsequent:               HEADER_CIPHER(23) | BODY?
//!
//!   HEADER_CIPHER = HEADER_PLAIN(7) || TAG(16)
//!   HEADER_PLAIN  = [4][0][0][0][0][PAYLOAD_HI][PAYLOAD_LO]
//!   BODY          = PAYLOAD_CIPHER || TAG          (payload_len > 0)
//!                 = (omitted)                      (payload_len == 0, zero chunk)
//!
//!   AEAD AAD = empty (no associated data)
//!   max payload per record = MAX_PACKET_SIZE (0x3fff)
//! ```
//!
//! # Encode / Decode flow
//!
//! Same as V4 minus padding interleave and congestion window:
//! - Encoder: `seal_plain owned payload → take_pending_wire`
//! - Decoder: `Salt → Header (decrypt) → Body (swap_padding is a no-op) → plaintext`

use std::{
    fmt,
    io::{self, IoSlice},
    sync::Arc,
};

use compio::buf::{IoBuf, IoBufMut};
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Tag};

use super::super::{
    DecodeEvent, DecodedHeader, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN, MAX_PACKET_SIZE, NONCE_LEN,
    PendingWire, PendingWireSegment, PlaintextFrame, PlaintextSegment, SALT_LEN, SnellTcpDecoder,
    SnellTcpEncoder,
    common::{
        ReadStep, decode_v6_unshaped_header, invalid_data, invalid_input, next_nonce,
        pending_plaintext_slice, seal_header, seal_payload_detached, v6_key, write_v6_plain_header,
    },
};

/// V6 unshaped encoder — AEAD frames, no shaping.
///
/// Holds the session key derived from the salt and a monotonic nonce. The first
/// record carries a random salt; subsequent records are header + body only.
pub struct V6UnshapedEncoder {
    key: LessSafeKey,
    nonce: [u8; NONCE_LEN],
    salt: [u8; SALT_LEN],
    salt_sent: bool,
    pending: PendingWire,
}

impl fmt::Debug for V6UnshapedEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6UnshapedEncoder")
            .field("salt_sent", &self.salt_sent)
            .field("pending_len", &self.pending.total_len())
            .finish()
    }
}

/// V6 unshaped decoder — AEAD frames, no shaping.
///
/// The PSK is kept (cloned) so the session key can be derived lazily once the
/// peer's salt arrives. `read_step` drives the salt → header → body state machine.
#[derive(Debug)]
pub struct V6UnshapedDecoder {
    psk: Arc<[u8]>,
    key: Option<LessSafeKey>,
    nonce: [u8; NONCE_LEN],
    read_step: ReadStep,
    plain: PlaintextFrame,
}

impl V6UnshapedEncoder {
    /// Create an encoder with a random salt.
    pub fn new(psk: &[u8]) -> io::Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        Self::with_salt(psk, salt)
    }

    fn with_salt(psk: &[u8], salt: [u8; SALT_LEN]) -> io::Result<Self> {
        Ok(Self {
            key: v6_key(psk, &salt)?,
            nonce: [0; NONCE_LEN],
            salt,
            salt_sent: false,
            pending: PendingWire::default(),
        })
    }

    fn seal_owned_payload<B>(&mut self, payload: B) -> io::Result<()>
    where
        B: IoBufMut + Into<PendingWireSegment>,
    {
        let mut payload = payload;
        if !self.pending_empty() {
            return Err(invalid_input("snell pending wire not fully written"));
        }

        let payload_len = payload.as_init().len();
        if payload_len > MAX_PACKET_SIZE {
            return Err(invalid_input("snell payload exceeds record capacity"));
        }
        let first_record = !self.salt_sent;
        let mut header = [0; HEADER_CIPHER_LEN];
        write_v6_plain_header(&mut header[..HEADER_PLAIN_LEN], 0, payload_len)?;
        seal_header(
            &self.key,
            &mut self.nonce,
            &[],
            &mut header,
            "snell v6 unshaped header encrypt failed",
        )?;

        let mut tag = None;
        if payload_len > 0 {
            tag = Some(seal_payload_detached(
                &self.key,
                &mut self.nonce,
                &[],
                payload.as_mut_slice(),
                "snell v6 unshaped payload encrypt failed",
            )?);
        }

        let mut pending = PendingWire::default();
        if first_record {
            pending.push(self.salt);
        }
        pending.push(header);
        if payload_len > 0 {
            pending.push(payload);
            pending.push(tag.expect("tag set for non-empty payload"));
        }
        self.pending = pending;
        self.salt_sent = true;
        Ok(())
    }

    /// Whether all sealed bytes have been flushed.
    pub fn pending_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn take_pending_wire(&mut self) -> PendingWire {
        std::mem::take(&mut self.pending)
    }

    pub fn restore_pending_wire(&mut self, wire: PendingWire) {
        self.pending = wire;
    }
}

impl V6UnshapedDecoder {
    /// Create a decoder holding the PSK; the session key is derived lazily.
    pub fn new(psk: impl Into<Arc<[u8]>>) -> Self {
        Self {
            psk: psk.into(),
            key: None,
            nonce: [0; NONCE_LEN],
            read_step: ReadStep::Salt { filled: 0 },
            plain: PlaintextFrame::default(),
        }
    }

    /// Seed the session key from the peer's salt: `key = HKDF(psk, salt)`.
    fn init_salt(&mut self, salt: [u8; SALT_LEN]) -> io::Result<()> {
        self.key = Some(v6_key(&self.psk, &salt)?);
        Ok(())
    }

    /// Decrypt the header currently buffered in `read_buf`.
    ///
    /// Steps: `AEAD open(HEADER_PLAIN, TAG, nonce++, AAD empty)`.
    fn decode_header_in_place(&mut self, header_cipher: &mut [u8]) -> io::Result<DecodedHeader> {
        let nonce = next_nonce(&mut self.nonce);
        let (cipher, tag) = header_cipher.split_at_mut(HEADER_PLAIN_LEN);
        let tag = Tag::try_from(&tag[..]).map_err(|_| invalid_data("snell v6 invalid tag"))?;
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| invalid_data("snell v6 unshaped reader key not initialized"))?;
        let header = key
            .open_in_place_separate_tag(nonce, Aad::empty(), tag, cipher, 0..)
            .map_err(|_| invalid_data("snell v6 unshaped header decrypt failed"))?;
        decode_v6_unshaped_header(header)
    }

    /// Decrypt the body, copying plaintext into the `self.plain` range.
    ///
    /// Steps: `AEAD open(payload_cipher, tag, nonce++)`, no padding to swap.
    fn finish_body<B>(&mut self, input: B, header: DecodedHeader) -> io::Result<bool>
    where
        B: IoBufMut + Into<PlaintextSegment>,
    {
        self.plain = PlaintextFrame::default();
        if header.payload_len == 0 {
            return Ok(false);
        }

        let key = self
            .key
            .as_ref()
            .ok_or_else(|| invalid_data("snell v6 unshaped reader key not initialized"))?;
        let mut frame = PlaintextFrame::from_segment(input, 0..0);
        let body = frame.body_mut();
        if body.len() != header.body_len {
            return Err(invalid_data("snell v6 unshaped body length mismatch"));
        }
        let (payload_cipher, tag) = body.split_at_mut(header.payload_len);
        let tag = Tag::try_from(&tag[..]).map_err(|_| invalid_data("snell v6 invalid tag"))?;
        let nonce = next_nonce(&mut self.nonce);
        key.open_in_place_separate_tag(nonce, Aad::empty(), tag, payload_cipher, 0..)
            .map_err(|_| invalid_data("snell v6 unshaped payload decrypt failed"))?;
        frame.set_plain(0..header.payload_len);
        self.plain = frame;
        Ok(true)
    }

    /// Borrow the decrypted plaintext region from the current record.
    pub fn pending_plain(&self) -> &[u8] {
        self.plain.as_init()
    }

    /// Mark `n` bytes from [`V6UnshapedDecoder::pending_plain`] as consumed.
    pub fn consume_plain(&mut self, n: usize) {
        self.plain.advance(n);
    }

    pub fn take_pending_plain(&mut self) -> Option<PlaintextFrame> {
        if self.plain.is_empty() {
            return None;
        }
        Some(std::mem::take(&mut self.plain))
    }
}

impl SnellTcpEncoder for V6UnshapedEncoder {
    fn next_plain_capacity(&self) -> usize {
        MAX_PACKET_SIZE
    }

    fn seal_plain<B>(&mut self, payload: B) -> io::Result<()>
    where
        B: IoBufMut + Into<PendingWireSegment>,
    {
        self.seal_owned_payload(payload)
    }

    fn take_pending_wire(&mut self) -> PendingWire {
        V6UnshapedEncoder::take_pending_wire(self)
    }

    fn restore_pending_wire(&mut self, wire: PendingWire) {
        V6UnshapedEncoder::restore_pending_wire(self, wire);
    }

    fn has_pending_wire(&self) -> bool {
        !self.pending_empty()
    }
}

impl SnellTcpDecoder for V6UnshapedDecoder {
    fn next_cipher_len(&self) -> usize {
        if !self.pending_plain().is_empty() {
            return 0;
        }
        match self.read_step {
            ReadStep::Salt { filled } => SALT_LEN - filled,
            ReadStep::Header { filled } => HEADER_CIPHER_LEN - filled,
            ReadStep::Body { header, filled } => header.body_len - filled,
        }
    }

    fn decode_ciphertext<B>(&mut self, input: B) -> io::Result<DecodeEvent<'_>>
    where
        B: IoBufMut + Into<PlaintextSegment>,
    {
        if !self.pending_plain().is_empty() {
            return Ok(DecodeEvent::PlainData);
        }

        match self.read_step {
            ReadStep::Salt { filled } => {
                if filled != 0 || input.as_init().len() != SALT_LEN {
                    return Err(invalid_data("snell v6 unshaped salt length mismatch"));
                }
                let salt: [u8; SALT_LEN] = input.as_init().try_into().expect("salt buffer filled");
                self.init_salt(salt)?;
                self.read_step = ReadStep::Header { filled: 0 };
                Ok(DecodeEvent::NeedMore)
            }
            ReadStep::Header { filled } => {
                if filled != 0 || input.as_init().len() != HEADER_CIPHER_LEN {
                    return Err(invalid_data("snell v6 unshaped header length mismatch"));
                }
                let mut input = input;
                let header = self.decode_header_in_place(input.as_mut_slice())?;
                if header.body_len == 0 {
                    self.read_step = ReadStep::Header { filled: 0 };
                    return if self.finish_body(input, header)? {
                        Ok(DecodeEvent::PlainData)
                    } else {
                        Ok(DecodeEvent::ZeroChunk)
                    };
                }
                self.read_step = ReadStep::Body { header, filled: 0 };
                Ok(DecodeEvent::NeedMore)
            }
            ReadStep::Body { header, filled } => {
                if filled != 0 || input.as_init().len() != header.body_len {
                    return Err(invalid_data("snell v6 unshaped body length mismatch"));
                }
                self.read_step = ReadStep::Header { filled: 0 };
                if self.finish_body(input, header)? {
                    Ok(DecodeEvent::PlainData)
                } else {
                    Ok(DecodeEvent::ZeroChunk)
                }
            }
        }
    }

    fn pending_plaintext<'a>(&'a self, out: &mut [IoSlice<'a>]) -> usize {
        pending_plaintext_slice(self.pending_plain(), out)
    }

    fn advance_plaintext(&mut self, n: usize) {
        V6UnshapedDecoder::consume_plain(self, n);
    }

    fn take_pending_plaintext(&mut self) -> Option<PlaintextFrame> {
        V6UnshapedDecoder::take_pending_plain(self)
    }
}

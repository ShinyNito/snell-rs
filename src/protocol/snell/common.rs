//! Shared helpers for the Snell V4 / V6 codecs.
//!
//! Everything here is `pub(super)` and used by [`super::v4`] and the
//! [`super::v6`] variants. The helpers fall into three groups:
//! - IO plumbing: plaintext slice projection, exact-read state, error shims.
//! - Frame headers: plaintext header encode/decode for V4 and V6.
//! - AEAD + obfuscation: nonce management, header/payload sealing, padding.

use std::io::{self, IoSlice};

use argon2::{Algorithm, Argon2, Params, Version};
use rand::{Rng, RngCore};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};

use crate::protocol::ParseState;

use super::crypto::kdf::aead_key;

use super::{
    DecodedHeader, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN, MAX_PACKET_SIZE, NONCE_LEN, PlainPrefix,
    SALT_LEN, TAG_LEN, WriteReservation,
};

/// Streaming read state machine shared by V4 and V6-unshaped decoders.
///
/// Each record is consumed in three phases: salt (V4/unshaped) or salt block
/// (shaped, see shaped.rs), AEAD header, then body. `filled` tracks how many
/// bytes of the current phase are already in the read buffer.
#[derive(Clone, Copy, Debug)]
pub(super) enum ReadStep {
    /// Reading the 16-byte salt that seeds the session key.
    Salt {
        /// Bytes of the salt already received.
        filled: usize,
    },
    /// Reading the AEAD-protected frame header.
    Header {
        /// Bytes of the header already received.
        filled: usize,
    },
    /// Reading the frame body (padding + ciphertext payload + tag).
    Body {
        /// Decoded header describing the body that follows.
        header: DecodedHeader,
        /// Bytes of the body already received.
        filled: usize,
    },
}

pub(super) fn fill_from_input(src: &mut &[u8], dst: &mut [u8], filled: usize) -> usize {
    let take = (dst.len() - filled).min(src.len());
    dst[filled..filled + take].copy_from_slice(&src[..take]);
    *src = &src[take..];
    filled + take
}

/// Push a single plaintext slice as the sole vectored entry.
///
/// Returns the number of slices written (0 or 1).
pub(super) fn pending_plaintext_slice<'a>(plain: &'a [u8], out: &mut [IoSlice<'a>]) -> usize {
    if plain.is_empty() || out.is_empty() {
        return 0;
    }
    out[0] = IoSlice::new(plain);
    1
}

/// Map a fill level to the shared exact-read [`ParseState`].
pub(super) fn need_filled(filled: usize, total: usize) -> ParseState<()> {
    if filled < total {
        ParseState::Need(total)
    } else {
        ParseState::Done(())
    }
}

/// Convert a [`ParseState`] into an `io::Result`, failing on `Need`.
pub(super) fn parse_done<T>(state: ParseState<T>, message: &'static str) -> io::Result<T> {
    match state {
        ParseState::Done(value) => Ok(value),
        ParseState::Need(_) => Err(invalid_data(message)),
    }
}

/// Copy a plaintext prefix into a reserved payload region.
///
/// Validates the prefix fits within the reservation and records its length so
/// [`plain_slot_with_prefix`] can expose the remaining slot to the caller.
pub(super) fn apply_plain_prefix(
    wire: &mut [u8],
    reservation: &mut WriteReservation,
    prefix: PlainPrefix<'_>,
) -> io::Result<()> {
    if prefix.len() > reservation.max_payload_len {
        return Err(invalid_input("snell plain prefix exceeds record capacity"));
    }
    prefix.copy_to(&mut wire[reservation.payload_start..]);
    reservation.plain_prefix_len = prefix.len();
    Ok(())
}

/// Borrow the caller-writable slot after any prefix has been laid down.
pub(super) fn plain_slot_with_prefix<'a>(
    wire: &'a mut [u8],
    reservation: &WriteReservation,
) -> &'a mut [u8] {
    let start = reservation.payload_start + reservation.plain_prefix_len;
    let end = reservation.payload_start + reservation.max_payload_len;
    &mut wire[start..end]
}

/// Resolve the final payload length including any prefix, with bounds checks.
pub(super) fn finish_len_with_prefix(
    reservation: &WriteReservation,
    payload_len: usize,
) -> io::Result<usize> {
    let total = reservation
        .plain_prefix_len
        .checked_add(payload_len)
        .ok_or_else(|| invalid_input("snell payload length overflow"))?;
    if total > reservation.max_payload_len {
        return Err(invalid_input("snell payload exceeds reservation"));
    }
    Ok(total)
}

/// Write a plaintext V4 frame header.
///
/// Layout: `4 PADDING(2) PAYLOAD(2)` (bytes 1–2 stay zero).
pub(super) fn write_plain_header(
    header: &mut [u8],
    padding_len: usize,
    payload_len: usize,
) -> io::Result<()> {
    if padding_len > MAX_PACKET_SIZE || payload_len > MAX_PACKET_SIZE {
        return Err(invalid_input("snell v4 frame too large"));
    }
    if header.len() != HEADER_PLAIN_LEN {
        return Err(invalid_input("snell v4 header buffer too small"));
    }

    header[0] = 4;
    header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
    header[5..7].copy_from_slice(&(payload_len as u16).to_be_bytes());
    Ok(())
}

/// Parse a V4 plaintext header, exact-read friendly.
///
/// Returns [`ParseState::Need`] until [`HEADER_PLAIN_LEN`] bytes are present.
pub(super) fn parse_v4_plain_header_need(header: &[u8]) -> io::Result<ParseState<DecodedHeader>> {
    if header.len() < HEADER_PLAIN_LEN {
        return Ok(ParseState::Need(HEADER_PLAIN_LEN));
    }
    let header = &header[..HEADER_PLAIN_LEN];
    if header[0] != 4 {
        return Err(invalid_data("snell v4 invalid frame header"));
    }

    let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
    if padding_len > MAX_PACKET_SIZE || payload_len > MAX_PACKET_SIZE {
        return Err(invalid_data("snell v4 frame too large"));
    }
    if payload_len == 0 && padding_len != 0 {
        return Err(invalid_data("snell v4 zero chunk with padding"));
    }

    Ok(ParseState::Done(DecodedHeader {
        padding_len,
        payload_len,
        body_len: padding_len
            + if payload_len == 0 {
                0
            } else {
                payload_len + TAG_LEN
            },
    }))
}

/// Fully parse a V4 plaintext header, failing on truncation.
pub(super) fn decode_plain_header(header: &[u8]) -> io::Result<DecodedHeader> {
    parse_done(
        parse_v4_plain_header_need(header)?,
        "snell v4 truncated frame header",
    )
}

/// Write a plaintext V6 frame header.
///
/// Layout: `4 0 0 PADDING(2) PAYLOAD(2)` (bytes 1–2 are reserved and zero).
pub(super) fn write_v6_plain_header(
    header: &mut [u8],
    padding_len: usize,
    payload_len: usize,
) -> io::Result<()> {
    if padding_len > u16::MAX as usize || payload_len > u16::MAX as usize {
        return Err(invalid_input("snell v6 frame too large"));
    }
    if header.len() != HEADER_PLAIN_LEN {
        return Err(invalid_input("snell v6 header buffer too small"));
    }

    header[0] = 4;
    header[1] = 0;
    header[2] = 0;
    header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
    header[5..7].copy_from_slice(&(payload_len as u16).to_be_bytes());
    Ok(())
}

/// Parse a V6 header's raw `(padding_len, payload_len)` pair, exact-read friendly.
///
/// Shared by the V6 raw, unshaped, and shaped header parsers.
pub(super) fn parse_v6_header_parts_need(header: &[u8]) -> io::Result<ParseState<(usize, usize)>> {
    if header.len() < HEADER_PLAIN_LEN {
        return Ok(ParseState::Need(HEADER_PLAIN_LEN));
    }
    let header = &header[..HEADER_PLAIN_LEN];
    if header[0] != 4 {
        return Err(invalid_data("snell v6 invalid frame header"));
    }
    if header[1] != 0 || header[2] != 0 {
        return Err(invalid_data("snell v6 invalid reserved header bytes"));
    }
    Ok(ParseState::Done((
        u16::from_be_bytes([header[3], header[4]]) as usize,
        u16::from_be_bytes([header[5], header[6]]) as usize,
    )))
}

/// Parse a V6 unsafe-raw header: padding must be zero, body is plaintext.
pub(super) fn parse_v6_raw_header_need(header: &[u8]) -> io::Result<ParseState<DecodedHeader>> {
    let (padding_len, payload_len) = match parse_v6_header_parts_need(header)? {
        ParseState::Need(total) => return Ok(ParseState::Need(total)),
        ParseState::Done(parts) => parts,
    };
    if padding_len != 0 {
        return Err(invalid_data("snell v6 unsafe-raw padding must be zero"));
    }
    Ok(ParseState::Done(DecodedHeader {
        padding_len,
        payload_len,
        body_len: payload_len,
    }))
}

/// Parse a V6 unshaped header: padding must be zero, payload is AEAD-sealed.
pub(super) fn parse_v6_unshaped_header_need(
    header: &[u8],
) -> io::Result<ParseState<DecodedHeader>> {
    let (padding_len, payload_len) = match parse_v6_header_parts_need(header)? {
        ParseState::Need(total) => return Ok(ParseState::Need(total)),
        ParseState::Done(parts) => parts,
    };
    if padding_len != 0 {
        return Err(invalid_data("snell v6 unshaped padding must be zero"));
    }
    if payload_len > MAX_PACKET_SIZE {
        return Err(invalid_data("snell v6 unshaped frame too large"));
    }
    Ok(ParseState::Done(DecodedHeader {
        padding_len,
        payload_len,
        body_len: if payload_len == 0 {
            0
        } else {
            payload_len + TAG_LEN
        },
    }))
}

/// Fully parse a V6 unshaped header, failing on truncation.
pub(super) fn decode_v6_unshaped_header(header: &[u8]) -> io::Result<DecodedHeader> {
    parse_done(
        parse_v6_unshaped_header_need(header)?,
        "snell v6 unshaped truncated frame header",
    )
}

/// Parse a V6 shaped header: padding may be non-zero, payload is AEAD-sealed.
pub(super) fn parse_v6_shaped_header_need(header: &[u8]) -> io::Result<ParseState<DecodedHeader>> {
    let (padding_len, payload_len) = match parse_v6_header_parts_need(header)? {
        ParseState::Need(total) => return Ok(ParseState::Need(total)),
        ParseState::Done(parts) => parts,
    };
    Ok(ParseState::Done(DecodedHeader {
        padding_len,
        payload_len,
        body_len: padding_len
            + if payload_len == 0 {
                0
            } else {
                payload_len + TAG_LEN
            },
    }))
}

/// Fully parse a V6 shaped header, failing on truncation.
pub(super) fn decode_v6_shaped_header(header: &[u8]) -> io::Result<DecodedHeader> {
    parse_done(
        parse_v6_shaped_header_need(header)?,
        "snell v6 shaped truncated frame header",
    )
}

/// AEAD-seal a frame header in place, appending the tag after the plaintext.
///
/// `aad` is the associated data (e.g. the obfuscation prefix) bound to the tag.
pub(super) fn seal_header(
    key: &LessSafeKey,
    nonce: &mut [u8; NONCE_LEN],
    aad: &[u8],
    header: &mut [u8],
    error: &'static str,
) -> io::Result<()> {
    if header.len() != HEADER_CIPHER_LEN {
        return Err(invalid_input("snell header buffer too small"));
    }
    let (cipher, tag_dst) = header.split_at_mut(HEADER_PLAIN_LEN);
    let tag = key
        .seal_in_place_separate_tag(next_nonce(nonce), Aad::from(aad), cipher)
        .map_err(|_| invalid_data(error))?;
    tag_dst.copy_from_slice(tag.as_ref());
    Ok(())
}

/// AEAD-seal `payload_len` bytes of `body` in place, appending the tag.
///
/// `body` must hold at least `payload_len + TAG_LEN` bytes. `aad` is bound to
/// the resulting tag (e.g. the padding region for shaped records).
pub(super) fn seal_payload(
    key: &LessSafeKey,
    nonce: &mut [u8; NONCE_LEN],
    aad: &[u8],
    body: &mut [u8],
    payload_len: usize,
    error: &'static str,
) -> io::Result<()> {
    if body.len() < payload_len + TAG_LEN {
        return Err(invalid_input("snell payload buffer too small"));
    }
    let (payload, tag_dst) = body[..payload_len + TAG_LEN].split_at_mut(payload_len);
    let tag = key
        .seal_in_place_separate_tag(next_nonce(nonce), Aad::from(aad), payload)
        .map_err(|_| invalid_data(error))?;
    tag_dst.copy_from_slice(tag.as_ref());
    Ok(())
}

/// Derive a V4 session key: Argon2id(psk, salt) → AES-128-GCM.
pub(super) fn v4_key(psk: &[u8], salt: &[u8; SALT_LEN]) -> io::Result<LessSafeKey> {
    let params =
        Params::new(8, 3, 1, Some(32)).map_err(|_| invalid_data("invalid argon2 params"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(psk, salt, &mut out)
        .map_err(|_| invalid_data("snell v4 kdf failed"))?;
    let unbound = UnboundKey::new(&aead::AES_128_GCM, &out[..16])
        .map_err(|_| invalid_data("snell v4 aead key failed"))?;
    Ok(LessSafeKey::new(unbound))
}

/// Derive a V6 session key: HKDF-style `aead_key(psk, salt)` → AES-128-GCM.
pub(super) fn v6_key(psk: &[u8], salt: &[u8; SALT_LEN]) -> io::Result<LessSafeKey> {
    let key = aead_key(psk, salt).map_err(|_| invalid_data("snell v6 kdf failed"))?;
    let unbound = UnboundKey::new(&aead::AES_128_GCM, &key)
        .map_err(|_| invalid_data("snell v6 aead key failed"))?;
    Ok(LessSafeKey::new(unbound))
}

/// Wrap the current nonce without advancing it (used for header decrypt).
pub(super) fn current_nonce(nonce: &[u8; NONCE_LEN]) -> Nonce {
    Nonce::assume_unique_for_key(*nonce)
}

/// Return the current nonce and advance the counter by one.
pub(super) fn next_nonce(nonce: &mut [u8; NONCE_LEN]) -> Nonce {
    let current = *nonce;
    increment_nonce(nonce);
    Nonce::assume_unique_for_key(current)
}

/// Increment the 96-bit nonce as a little-endian counter.
pub(super) fn increment_nonce(nonce: &mut [u8; NONCE_LEN]) {
    for byte in nonce.iter_mut() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
}

/// De-interleave padding and payload bytes that [`make_padding`] interleaved.
///
/// V4 writes padding then ciphertext payload contiguously, then swaps pairs of
/// bytes across the boundary to obscure the split; this reverses that swap.
pub(super) fn swap_padding(padding: &mut [u8], payload_cipher: &mut [u8]) {
    let limit = padding.len().min(payload_cipher.len());
    for i in (0..limit).step_by(2) {
        std::mem::swap(&mut padding[i], &mut payload_cipher[i]);
    }
}

/// Generate V4 padding whose bit density counters the payload's.
///
/// The goal is to keep the on-wire 0/1 ratio near a target so the stream does
/// not leak the payload's entropy profile. Falls back to uniform random bytes
/// when the payload is already balanced or the target is unreachable.
pub(super) fn make_padding(padding: &mut [u8], payload_cipher: &[u8]) {
    let ones = payload_cipher[..payload_cipher.len() & !3]
        .iter()
        .map(|byte| byte.count_ones() as usize)
        .sum::<usize>();
    let zeros = payload_cipher.len() * u8::BITS as usize - ones;
    if zeros == 0 {
        rand::thread_rng().fill_bytes(padding);
        return;
    }

    let ratio = ones as f64 / zeros as f64;
    if !(0.5..=1.6).contains(&ratio) {
        rand::thread_rng().fill_bytes(padding);
        return;
    }

    let target_ratio =
        if zeros < ones { 0.4 } else { 1.6 } + rand::thread_rng().gen_range(0.0..0.1);
    let total_bits = (padding.len() + payload_cipher.len()) * u8::BITS as usize;
    let target = total_bits as f64 * (target_ratio / (target_ratio + 1.0)) - ones as f64;
    if !target.is_finite() || target < 0.0 || target > (padding.len() * u8::BITS as usize) as f64 {
        rand::thread_rng().fill_bytes(padding);
        return;
    }

    fill_padding_bits(padding, target.floor() as usize);
}

/// Set exactly `target_ones` bits in `padding` using rejection-sampled indices.
///
/// Picks the smaller of "set ones" vs "clear zeros" to minimise work.
pub(super) fn fill_padding_bits(padding: &mut [u8], target_ones: usize) {
    let bits = padding.len() * u8::BITS as usize;
    let mut random = [0u8; 4096];
    let mut offset = random.len();
    let mut pick = |max: usize| -> usize {
        let span = max as u64 + 1;
        let zone = u64::MAX - (u64::MAX % span);
        loop {
            if offset + 8 > random.len() {
                rand::thread_rng().fill_bytes(&mut random);
                offset = 0;
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&random[offset..offset + 8]);
            offset += 8;
            let value = u64::from_le_bytes(bytes);
            if value < zone {
                return (value % span) as usize;
            }
        }
    };
    if target_ones <= bits - target_ones {
        padding.fill(0);
        for j in bits - target_ones..bits {
            let candidate = pick(j);
            let index = if padding[candidate >> 3] & (1u8 << (candidate & 7)) != 0 {
                j
            } else {
                candidate
            };
            padding[index >> 3] |= 1u8 << (index & 7);
        }
    } else {
        padding.fill(0xff);
        for j in target_ones..bits {
            let candidate = pick(j);
            let index = if padding[candidate >> 3] & (1u8 << (candidate & 7)) == 0 {
                j
            } else {
                candidate
            };
            padding[index >> 3] &= !(1u8 << (index & 7));
        }
    }
}

/// Build an [`io::Error`] tagged `InvalidData` for malformed peer input.
pub(super) fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Build an [`io::Error`] tagged `InvalidInput` for caller contract violations.
pub(super) fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

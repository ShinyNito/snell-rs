//! Key derivation functions: BLAKE2b profile secret and Argon2id AEAD key.
//!
//! Both functions run once per connection (not per record), so they are not on
//! the hot path. They must nonetheless match the protocol byte-for-byte.
//!
//! - Profile secret: `BLAKE2b-256(seed_24 ‖ psk)`.
//! - AEAD key:        libsodium `crypto_pwhash` (Argon2id) on the PSK with the
//!   16-byte record salt, producing a 32-byte output of which the first 16 bytes
//!   are the AES-128-GCM key.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use tracing::trace;

/// The 24-byte binary seed prepended to the PSK before BLAKE2b.
///
/// Copied byte-for-byte; do not edit — any change desyncs the profile secret
/// from the server.
pub const SEED_24: [u8; 24] = [
    0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94, 0x33, 0x18, 0xc0, 0x6e,
    0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
];

/// Argon2id parameters (libsodium `crypto_pwhash`).
///
/// - `m_cost = 8 KiB`  (memlimit `0x2000` bytes; Argon2 `m_cost` is in KiB,
///   so `0x2000` bytes = `8 KiB` → `m_cost = 8`.)
/// - `t_cost = 3`      (opslimit low bits)
/// - `p_cost = 1`
/// - algorithm = Argon2id (libsodium alg `2`, version `0x13`).
pub const ARGON2_M_COST_KIB: u32 = 8; // 0x2000 bytes
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 1;
pub const PSK_MIN_LEN: usize = 16;
pub const PSK_MAX_LEN: usize = 255;

/// Compute the 32-byte profile secret: `BLAKE2b-256(seed_24 ‖ psk)`.
///
/// The server copies the 24-byte seed into a stack buffer, `memcpy`s the PSK
/// right after it, then calls BLAKE2b with output length 32 and no key.
///
/// `psk` is the raw PSK bytes (length 16..=255).
///
/// # Errors
/// Returns [`KdfError::Blake2`] only if BLAKE2b rejects the 32-byte output
/// size (cannot happen for a fixed valid size; kept for API hygiene).
pub fn profile_secret(psk: &[u8]) -> Result<[u8; 32], KdfError> {
    if !(PSK_MIN_LEN..=PSK_MAX_LEN).contains(&psk.len()) {
        return Err(KdfError::InvalidPskLen(psk.len()));
    }
    let mut hasher = Blake2bVar::new(32).map_err(|_| KdfError::Blake2("invalid output size"))?;
    Update::update(&mut hasher, &SEED_24);
    Update::update(&mut hasher, psk);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .map_err(|_| KdfError::Blake2("finalize failed"))?;
    trace!(psk_len = psk.len(), "derived profile secret");
    Ok(out)
}

/// Derive the 16-byte AES-128-GCM key from the PSK and the 16-byte record salt
/// via Argon2id, using the official libsodium parameters.
///
/// libsodium's `crypto_pwhash` emits 32 bytes; the server uses the first 16 as
/// the AES-128-GCM key. We return the full 32-byte raw output (`aead_key_raw`)
/// so callers that need the second half (e.g. for future SIV modes) can access
/// it; the active record codec uses [`AeadKey::aes128`] for the first 16 bytes.
///
/// # Errors
/// Returns [`KdfError::Argon2`] if the underlying Argon2id computation fails
/// (e.g. invalid parameters or allocation failure).
pub fn aead_key_raw(psk: &[u8], salt_16: &[u8; 16]) -> Result<[u8; 32], KdfError> {
    if !(PSK_MIN_LEN..=PSK_MAX_LEN).contains(&psk.len()) {
        return Err(KdfError::InvalidPskLen(psk.len()));
    }
    let params = argon2::Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| KdfError::Argon2(e.to_string()))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    // libsodium uses the PSK as both the password and (implicitly) no associated
    // data; salt is the raw 16-byte record salt. No secret key / ad.
    argon
        .hash_password_into(psk, salt_16, &mut out)
        .map_err(|e| KdfError::Argon2(e.to_string()))?;
    trace!(psk_len = psk.len(), "derived argon2id aead key");
    Ok(out)
}

/// Convenience: the 16-byte AES-128-GCM key derived from `aead_key_raw`.
///
/// This is the AES-128-GCM key passed to `aws_lc_rs::aead`.
pub fn aead_key(psk: &[u8], salt_16: &[u8; 16]) -> Result<[u8; 16], KdfError> {
    let raw = aead_key_raw(psk, salt_16)?;
    let mut key = [0u8; 16];
    key.copy_from_slice(&raw[..16]);
    Ok(key)
}

/// KDF errors.
#[derive(Debug, thiserror::Error)]
pub enum KdfError {
    /// PSK length was outside the official 16..=255 byte range.
    #[error("invalid psk length: {0} (expected 16..=255)")]
    InvalidPskLen(usize),
    /// BLAKE2b profile-secret computation failed.
    #[error("blake2b profile secret: {0}")]
    Blake2(&'static str),
    /// Argon2id AEAD key derivation failed.
    #[error("argon2id aead key: {0}")]
    Argon2(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed24_matches_canonical_bytes() {
        // Sanity: the seed must be exactly the canonical bytes. If anyone
        // edits SEED_24, this hex string breaks.
        assert_eq!(
            hex::encode(SEED_24),
            "8d41a7135ce209bb702fd6943318c06e4a9125fdb80377ac",
        );
    }

    #[test]
    fn profile_secret_is_32_bytes_and_deterministic() {
        let psk = b"16-byte-psk-test";
        let a = profile_secret(psk).unwrap();
        let b = profile_secret(psk).unwrap();
        assert_eq!(a.len(), 32);
        assert_eq!(a, b, "deterministic");
    }

    #[test]
    fn profile_secret_depends_on_psk() {
        let a = profile_secret(b"psk-one-16bytes!").unwrap();
        let b = profile_secret(b"psk-two-16bytes!").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn profile_secret_depends_on_seed24() {
        // If someone zeroed SEED_24, the output would change — pin the seed.
        let with_seed = profile_secret(b"some-psk-here!!!").unwrap();
        let mut no_seed = Blake2bVar::new(32).expect("32-byte output");
        Update::update(&mut no_seed, b"some-psk-here!!!");
        let mut against_zero = [0u8; 32];
        no_seed.finalize_variable(&mut against_zero).unwrap();
        assert_ne!(with_seed, against_zero);
    }

    #[test]
    fn rejects_invalid_psk_len() {
        let salt = [0u8; 16];
        assert!(matches!(
            profile_secret(b"too short"),
            Err(KdfError::InvalidPskLen(9))
        ));
        assert!(matches!(
            aead_key(b"too short", &salt),
            Err(KdfError::InvalidPskLen(9))
        ));
        assert!(matches!(
            profile_secret(&vec![0u8; 256]),
            Err(KdfError::InvalidPskLen(256))
        ));
    }

    #[test]
    fn aead_key_is_first_16_of_32_byte_argon2_output() {
        let psk = b"16-byte-psk-test";
        let salt = [0xAA; 16];
        let raw = aead_key_raw(psk, &salt).unwrap();
        let key16 = aead_key(psk, &salt).unwrap();
        assert_eq!(raw[..16], key16[..]);
    }

    #[test]
    fn aead_key_depends_on_salt_and_psk() {
        let psk = b"16-byte-psk-test";
        let salt1 = [0x01u8; 16];
        let salt2 = [0x02u8; 16];
        assert_ne!(
            aead_key(psk, &salt1).unwrap(),
            aead_key(psk, &salt2).unwrap()
        );
        assert_ne!(
            aead_key(psk, &salt1).unwrap(),
            aead_key(b"different-psk-16", &salt1).unwrap()
        );
    }
}

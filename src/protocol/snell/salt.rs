//! Salt block obfuscation.
//!
//! The first frame of the shaped codec begins with a *salt block*: a
//! `salt_prefix_len + 16` byte buffer in which the 16-byte AEAD salt is hidden
//! via a position permutation (Fisher-Yates driven by a salt-specific PRF) and
//! a per-position XOR mask. The receiver extracts the salt, derives the AEAD
//! key, and proceeds with record decryption.
//!
//! ## Functions
//!
//! | Function | Role |
//! |---|---|
//! | `salt_shuffle_prf` | salt-specific PRF for the shuffle |
//! | `shuffle`          | build the position permutation |
//! | `mask`             | per-position XOR mask |
//! | `extract`          | read 16 salt bytes out of a block |
//! | `write`            | hide 16 salt bytes into a block |
//!
//! ## Key detail
//!
//! The salt shuffle PRF is NOT the generic PRF32. It uses a salt-specific
//! constant XOR'd into the namespace, omits the label term, and swaps which
//! parameter plays the `a`/`b` roles.

use super::MIX_HANDSHAKE_DOMAIN;
use super::crypto::{
    prf::{ADD_A, ADD_B, COEF_A, COEF_B, prf32_fold},
    splitmix::splitmix64,
};

/// Salt-specific namespace XOR constant.
///
/// This is the single most fragile constant in the salt path: it is NOT present
/// in the generic PRF and is not documented elsewhere. It is XOR'd into the
/// namespace before the fold.
const SALT_NS_XOR: u64 = 0xDAA66D2C7DDF743F;

/// The salt-specific PRF used by the shuffle.
///
/// Translated line-by-line:
///
/// ```text
/// rdx = i * COEF_B + ADD_B               // i plays the "b" role
/// rdi = ns_salt ^ SALT_NS_XOR            // salt-specific namespace tweak
/// rdx = rdx ^ rdi
/// rsi = domain * COEF_A + ADD_A          // domain plays the "a" role
/// return fold(splitmix64(rdx ^ rsi))     // NO label term (unlike the generic PRF)
/// ```
///
/// Note: unlike the generic [`super::crypto::prf::prf32_fold`], there is no
/// `label * GOLDEN_GAMMA` term, and the namespace is XOR'd with [`SALT_NS_XOR`].
#[inline]
#[must_use]
fn salt_shuffle_prf(ns_salt: u64, domain: u32, i: u32) -> u32 {
    let rdx = u64::from(i).wrapping_mul(COEF_B).wrapping_add(ADD_B);
    let rdi = ns_salt ^ SALT_NS_XOR;
    let rdx = rdx ^ rdi;
    let rsi = u64::from(domain).wrapping_mul(COEF_A).wrapping_add(ADD_A);
    let x = rdx ^ rsi;
    let y = splitmix64(x);
    (y ^ (y >> 32)) as u32
}

/// Build the position permutation for a salt block of length `len`.
///
/// Produces a Fisher-Yates-style permutation of `0..len` in `out` (caller must
/// size `out.len() == len`).
///
/// - `ns_salt`: the salt namespace (resolved from the profile secret).
/// - `rounds`: number of full shuffle passes (mix_rounds_handshake); clamped to
///   `>= 1`.
/// - `len`: salt block length (`salt_prefix_len + 16`).
///
/// For each round `r` and position `i`:
/// ```text
/// domain = MIX_HANDSHAKE_DOMAIN + r
/// raw    = salt_shuffle_prf(ns_salt, domain, i)
/// j      = i + (raw % (len - i))
/// swap(out[i], out[j])
/// ```
pub fn shuffle_perm(ns_salt: u64, rounds: u8, len: usize, out: &mut [u8]) {
    debug_assert_eq!(out.len(), len, "out must be sized to len");
    if len == 0 {
        return;
    }
    // Identity init: out[i] = i. The binary writes bytes, so len <= 256.
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = i as u8;
    }
    let rounds = if rounds == 0 { 1 } else { rounds };
    for round in 0..u32::from(rounds) {
        let domain = MIX_HANDSHAKE_DOMAIN + round;
        for i in 0..len {
            // len - i is always >= 1 here since i < len.
            let span = (len - i) as u64;
            let raw = u64::from(salt_shuffle_prf(ns_salt, domain, i as u32));
            let j = i + (raw % span) as usize;
            out.swap(i, j);
        }
    }
}

/// Maximum salt block length supported by the stack-based permutation buffer.
///
/// Salt-block positions are stored as bytes (`out[i]` is a `u8`), so the block
/// length never exceeds 256. In practice it is `salt_prefix_len + 16`, well
/// under `0xa0`. We size the stack scratch buffer to the theoretical max and
/// slice into it, avoiding any heap allocation in the salt path.
pub const MAX_SALT_BLOCK_LEN: usize = 256;

/// Per-position XOR mask for salt byte `i`.
///
/// ```text
/// prf = prf32_fold(ns_salt, label=2, a=MIX_HANDSHAKE_DOMAIN, b=i)
/// mask = ((i * mix_stride) as u8) ^ (prf as u8)
/// ```
///
/// `mix_stride` is `mix_stride_handshake` from the profile (a `u8`). The
/// computation uses an 8-bit `mulb`, so only the low byte of
/// `i * mix_stride` is kept.
#[inline]
#[must_use]
fn mask(ns_salt: u64, mix_stride: u8, i: u32) -> u8 {
    let prf = prf32_fold(ns_salt, 2, u64::from(MIX_HANDSHAKE_DOMAIN), u64::from(i));
    let stride_term = (i as u8).wrapping_mul(mix_stride);
    stride_term ^ (prf as u8)
}

/// Extract the 16-byte salt from a salt block.
///
/// For each `i` in `0..16`: `out[i] = mask(i) XOR block[perm[i]]`.
///
/// - `block`: the full salt block (`salt_prefix_len + 16` bytes, `≤ 256`).
/// - `out`: 16-byte destination.
///
/// Uses a fixed-size stack scratch buffer for the permutation — no heap
/// allocation. Returns [`SaltError::BlockTooLarge`] if `block.len() > 256`.
///
/// # Errors
/// See [`SaltError`].
pub fn extract(
    ns_salt: u64,
    mix_stride: u8,
    rounds: u8,
    block: &[u8],
    out: &mut [u8; 16],
) -> Result<(), SaltError> {
    let len = block.len();
    if len > MAX_SALT_BLOCK_LEN {
        return Err(SaltError::BlockTooLarge(len));
    }
    // Permutation on the stack. `len ≤ 256`, so [u8; 256] always suffices.
    let mut perm = [0u8; MAX_SALT_BLOCK_LEN];
    shuffle_perm(ns_salt, rounds, len, &mut perm[..len]);
    for i in 0..16 {
        let p = perm[i] as usize;
        out[i] = mask(ns_salt, mix_stride, i as u32) ^ block[p];
    }
    Ok(())
}

/// Hide the 16-byte salt into a freshly-built salt block.
///
/// For each `i` in `0..16`: `block[perm[i]] = mask(i) XOR salt[i]`. Positions
/// not targeted by the permutation are left as-is (the caller fills the prefix
/// region with random/fill bytes before calling this).
///
/// - `block`: the full salt block buffer (`prefix_len + 16` bytes, `≤ 256`),
///   prefix region already populated.
/// - `salt`: the 16-byte AEAD salt to hide.
///
/// Uses a fixed-size stack scratch buffer for the permutation — no heap
/// allocation.
///
/// # Errors
/// See [`SaltError`].
pub fn write(
    ns_salt: u64,
    mix_stride: u8,
    rounds: u8,
    block: &mut [u8],
    salt: &[u8; 16],
) -> Result<(), SaltError> {
    let len = block.len();
    if len > MAX_SALT_BLOCK_LEN {
        return Err(SaltError::BlockTooLarge(len));
    }
    let mut perm = [0u8; MAX_SALT_BLOCK_LEN];
    shuffle_perm(ns_salt, rounds, len, &mut perm[..len]);
    for i in 0..16 {
        let p = perm[i] as usize;
        block[p] = mask(ns_salt, mix_stride, i as u32) ^ salt[i];
    }
    Ok(())
}

/// Salt-block errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SaltError {
    /// Salt block exceeded the 256-byte position-encoding limit.
    #[error("salt block too large: {0} > {MAX_SALT_BLOCK_LEN}")]
    BlockTooLarge(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns_salt() -> u64 {
        // A fixed, non-trivial namespace for deterministic tests.
        0x3E8A91B52740F6CD
    }

    #[test]
    fn shuffle_perm_is_valid_permutation() {
        let ns = ns_salt();
        for &len in &[16usize, 20, 32, 48, 64] {
            let mut perm = [0u8; MAX_SALT_BLOCK_LEN];
            shuffle_perm(ns, 3, len, &mut perm[..len]);
            // Must be a permutation of 0..len.
            let mut seen = vec![false; len];
            for &v in &perm[..len] {
                let v = v as usize;
                assert!(v < len, "perm value {v} out of range for len {len}");
                assert!(!seen[v], "perm value {v} duplicated");
                seen[v] = true;
            }
            assert!(seen.iter().all(|&s| s), "not all positions covered");
        }
    }

    #[test]
    fn shuffle_perm_deterministic() {
        let ns = ns_salt();
        let (mut a, mut b) = ([0u8; MAX_SALT_BLOCK_LEN], [0u8; MAX_SALT_BLOCK_LEN]);
        shuffle_perm(ns, 3, 32, &mut a[..32]);
        shuffle_perm(ns, 3, 32, &mut b[..32]);
        assert_eq!(&a[..32], &b[..32]);
    }

    #[test]
    fn shuffle_perm_changes_with_rounds() {
        let ns = ns_salt();
        let (mut a, mut b) = ([0u8; MAX_SALT_BLOCK_LEN], [0u8; MAX_SALT_BLOCK_LEN]);
        shuffle_perm(ns, 1, 32, &mut a[..32]);
        shuffle_perm(ns, 4, 32, &mut b[..32]);
        assert_ne!(
            &a[..32],
            &b[..32],
            "more rounds should (almost surely) change the perm"
        );
    }

    #[test]
    fn shuffle_perm_empty_is_noop() {
        let mut perm: [u8; 0] = [];
        shuffle_perm(ns_salt(), 3, 0, &mut perm);
        // No panic, no writes.
    }

    #[test]
    fn write_then_extract_round_trips() {
        // The core invariant: hide a salt, then recover it exactly.
        let ns = ns_salt();
        let mix_stride = 0x37u8;
        let rounds = 3u8;
        let prefix_len = 20usize;
        let salt = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];

        // Build a block with a prefix (filler) + 16 hidden salt bytes.
        let mut block = vec![0xAAu8; prefix_len + 16];
        write(ns, mix_stride, rounds, &mut block, &salt).unwrap();

        let mut extracted = [0u8; 16];
        extract(ns, mix_stride, rounds, &block, &mut extracted).unwrap();
        assert_eq!(extracted, salt, "extract must invert write");
    }

    #[test]
    fn write_then_extract_round_trips_minimal_block() {
        // Smallest possible block: no prefix, just the 16 salt bytes.
        let ns = ns_salt();
        let salt = [0x42u8; 16];
        let mut block = [0u8; 16];
        write(ns, 0x55, 2, &mut block, &salt).unwrap();
        let mut extracted = [0u8; 16];
        extract(ns, 0x55, 2, &block, &mut extracted).unwrap();
        assert_eq!(extracted, salt);
    }

    #[test]
    fn extract_fails_to_invert_with_wrong_ns() {
        // Wrong namespace → wrong permutation/mask → garbage salt.
        let ns = ns_salt();
        let salt = [0x77u8; 16];
        let mut block = [0u8; 16];
        write(ns, 0x55, 2, &mut block, &salt).unwrap();

        let mut extracted = [0u8; 16];
        extract(0xDEADBEEFCAFEBABE, 0x55, 2, &block, &mut extracted).unwrap();
        assert_ne!(extracted, salt);
    }

    #[test]
    fn oversize_block_rejected() {
        let mut block = vec![0u8; MAX_SALT_BLOCK_LEN + 1];
        let salt = [0u8; 16];
        assert_eq!(
            write(ns_salt(), 0x55, 2, &mut block, &salt),
            Err(SaltError::BlockTooLarge(MAX_SALT_BLOCK_LEN + 1))
        );
        let mut out = [0u8; 16];
        assert_eq!(
            extract(ns_salt(), 0x55, 2, &block, &mut out),
            Err(SaltError::BlockTooLarge(MAX_SALT_BLOCK_LEN + 1))
        );
    }

    #[test]
    fn mask_deterministic_and_depends_on_stride() {
        let ns = ns_salt();
        let a = mask(ns, 0x10, 5);
        let b = mask(ns, 0x10, 5);
        assert_eq!(a, b, "deterministic");
        let c = mask(ns, 0x20, 5);
        assert_ne!(a, c, "different stride → different mask");
    }

    #[test]
    fn salt_shuffle_prf_is_u32() {
        let v = salt_shuffle_prf(ns_salt(), MIX_HANDSHAKE_DOMAIN, 7);
        let _ = v; // just a u32; guards the signature.
    }
}

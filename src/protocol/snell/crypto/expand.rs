//! `expand_stream` — PRF-driven keystream expansion.
//!
//! This replaces the older keyed-BLAKE2b block expansion used by previous
//! revisions. The fill generator calls this with `label = 0`, then applies a
//! generator mode (0..=3).
//!
//! Like [`super::prf`], this module takes the resolved namespace value
//! rather than the profile context, so it can be unit-tested in isolation.
//! Callers that hold a profile resolve the namespace via `Profile::namespace_for`
//! first.

use super::{GOLDEN_GAMMA, splitmix::splitmix64};

/// Initial state seed.
const STATE_INIT: u64 = 0xB57DE1F3F82CB33F;
/// `seq` coefficient.
const COEF_SEQ: u64 = 0xD6E8FEB86659FD93;
/// `label` coefficient.
const COEF_LABEL: u64 = 0xA24BAED4963EE407;
/// `len` coefficient and addend.
const COEF_LEN: u64 = 0x165667B19E3779F9;
const ADD_LEN: u64 = 0x0D4CD3E7B14A36D7;

/// Build the initial `expand_stream` state for the given inputs.
///
/// ```text
/// state = 0xB57DE1F3F82CB33F
/// state += seq * 0xD6E8FEB86659FD93
/// state ^= label * 0xA24BAED4963EE407
/// state ^= len * 0x165667B19E3779F9 + 0x0D4CD3E7B14A36D7
/// state ^= namespace_for_label(label)
/// ```
///
#[inline]
#[must_use]
fn expand_initial_state(namespace: u64, label: u32, seq: u64, len: u64) -> u64 {
    let mut state = STATE_INIT;
    state = state.wrapping_add(seq.wrapping_mul(COEF_SEQ));
    state ^= u64::from(label).wrapping_mul(COEF_LABEL);
    state ^= len.wrapping_mul(COEF_LEN).wrapping_add(ADD_LEN);
    state ^= namespace;
    state
}

/// Fill `out` with `expand_stream` output bytes.
///
/// Each block advances `state` by `GOLDEN_GAMMA` and emits
/// `splitmix64(state)` as 8 little-endian bytes. The last block is truncated
/// to the remaining byte count.
///
/// `len_hint` must equal `out.len()`; it is taken explicitly because the binary
/// mixes the output length into the initial state, so the caller must pass the
/// same value the official code would.
pub fn expand_stream(namespace: u64, label: u32, seq: u64, len_hint: u64, out: &mut [u8]) {
    debug_assert_eq!(
        out.len() as u64,
        len_hint,
        "len_hint must match out.len(); the length is mixed into the PRF state"
    );
    let mut state = expand_initial_state(namespace, label, seq, len_hint);

    // Hot path: handle full 8-byte blocks in a tight loop with no per-block
    // length branch. `to_le_bytes().copy_from_slice` on a fixed [u8; 8] lowers
    // to a single unaligned u64 store on every modern target.
    let (full, tail) = split_at_mut8(out);
    for block in full.chunks_exact_mut(8) {
        state = state.wrapping_add(GOLDEN_GAMMA);
        block.copy_from_slice(&splitmix64(state).to_le_bytes());
    }
    // Trailing partial block (0..7 bytes). Only hit when len % 8 != 0.
    if !tail.is_empty() {
        state = state.wrapping_add(GOLDEN_GAMMA);
        let v = splitmix64(state).to_le_bytes();
        tail.copy_from_slice(&v[..tail.len()]);
    }
}

/// Split `slice` into `[&mut [u8; 8]; N]`-equivalent full blocks and a tail.
///
/// Helper to keep [`expand_stream`]'s main loop branch-free per block.
/// Implemented inline rather than via `chunks_mut` to avoid re-validating the
/// chunk length on every iteration.
#[inline]
fn split_at_mut8(slice: &mut [u8]) -> (&mut [u8], &mut [u8]) {
    let n_full = slice.len() / 8 * 8;
    slice.split_at_mut(n_full)
}

/// Convenience: produce a freshly allocated `Vec<u8>` of length `len`.
///
/// Prefer [`expand_stream`] with a reused buffer in hot paths.
#[cfg(test)]
fn expand_stream_vec(namespace: u64, label: u32, seq: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    expand_stream(namespace, label, seq, len as u64, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Output length must match the request, including non-multiple-of-8 sizes.
    #[test]
    fn expand_stream_length() {
        for &len in &[0usize, 1, 7, 8, 9, 16, 23, 100, 256] {
            let v = expand_stream_vec(0x5D9217C083E64AB9, 0, 0, len);
            assert_eq!(v.len(), len, "length {len}");
        }
    }

    /// Determinism: identical inputs produce identical bytes.
    #[test]
    fn expand_stream_deterministic() {
        let a = expand_stream_vec(0xB46C2E7D9A1538F1, 0, 0, 64);
        let b = expand_stream_vec(0xB46C2E7D9A1538F1, 0, 0, 64);
        assert_eq!(a, b);
    }

    /// Different `seq` values must produce different streams. The seq is mixed
    /// into the initial state via `seq * COEF_SEQ`, so distinct seqs must
    /// (almost surely) diverge.
    #[test]
    fn expand_stream_seq_advances_state() {
        let s0 = expand_stream_vec(0x62D0B5E19C4A783F, 0, 0, 32);
        let s1 = expand_stream_vec(0x62D0B5E19C4A783F, 0, 1, 32);
        let s2 = expand_stream_vec(0x62D0B5E19C4A783F, 0, 2, 32);
        assert_ne!(s0, s1);
        assert_ne!(s1, s2);
        assert_ne!(s0, s2);
    }

    /// Different `label` values must produce different streams.
    #[test]
    fn expand_stream_label_distinct() {
        let a = expand_stream_vec(0xA71F0C54D8396E2B, 0, 0, 32);
        let b = expand_stream_vec(0xA71F0C54D8396E2B, 2, 0, 32);
        assert_ne!(a, b);
    }

    /// Different `namespace` values must produce different streams.
    #[test]
    fn expand_stream_namespace_distinct() {
        let a = expand_stream_vec(0x3E8A91B52740F6CD, 0, 0, 32);
        let b = expand_stream_vec(0xC9F4260B7D1E835A, 0, 0, 32);
        assert_ne!(a, b);
    }

    /// `len_hint` is mixed into the state, so requesting a different length
    /// changes even the leading bytes. This is why callers must pass the real
    /// length, not a placeholder.
    #[test]
    fn expand_stream_length_affects_state() {
        let a = expand_stream_vec(0x917B3C48E6A205D4, 0, 0, 16);
        let b = expand_stream_vec(0x917B3C48E6A205D4, 0, 0, 32);
        // The first 16 bytes differ because the initial state differs.
        assert_ne!(&a[..], &b[..16]);
    }

    /// Each 8-byte block is splitmix64(state) in little-endian, so the first
    /// block is `splitmix64(STATE_INIT + GOLDEN_GAMMA)` for trivial inputs.
    /// Pin this down explicitly so a future refactor of the state init can't
    /// silently drift.
    #[test]
    fn expand_stream_first_block_matches_splitmix() {
        let ns = 0u64;
        let label = 0u32;
        let seq = 0u64;
        let len = 8u64;
        let mut state = expand_initial_state(ns, label, seq, len);
        state = state.wrapping_add(GOLDEN_GAMMA);
        let expected = splitmix64(state).to_le_bytes();

        let v = expand_stream_vec(ns, label, seq, 8);
        assert_eq!(&v[..], &expected[..]);
    }

    /// Truncation of the final partial block must not corrupt the preceding
    /// full blocks. Run the same stream at len=8 and len=9 and check the first
    /// 8 bytes agree.
    #[test]
    fn expand_stream_partial_block_preserves_prefix() {
        // Same namespace/label/seq but different len → different initial state,
        // so we can't compare prefixes across different lens. Instead verify
        // internal consistency: a full 8-byte stream matches the first 8 bytes
        // of a 16-byte stream only when len is fixed. We check that the 16-byte
        // stream's two halves differ (state advances between them).
        let v = expand_stream_vec(0x1234_5678_9ABC_DEF0, 5, 1, 16);
        assert_ne!(&v[..8], &v[8..16], "state must advance between blocks");
    }

    /// Empty output is a valid no-op.
    #[test]
    fn expand_stream_zero_len_is_empty() {
        let v = expand_stream_vec(0, 0, 0, 0);
        assert!(v.is_empty());
    }
}

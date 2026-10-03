//! SplitMix64, PRF32, and expand_stream. These are the v6 profile generators.

/// Canonical SplitMix64 stream increment; also a PRF coefficient.
pub(crate) const GOLDEN_GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;

const SPLITMIX_MUL1: u64 = 0xbf58_476d_1ce4_e5b9;
const SPLITMIX_MUL2: u64 = 0x94d0_49bb_1331_11eb;

pub(crate) const PRF_COEF_B: u64 = 0x5899_65cc_7537_4cc3;
pub(crate) const PRF_ADD_B: u64 = 0x33a2_13ec_50ff_e2e9;
pub(crate) const PRF_COEF_A: u64 = 0xe703_7ed1_a0b4_28db;
pub(crate) const PRF_ADD_A: u64 = 0x8f39_07f7_b2b8_0c35;

const EXPAND_STATE_INIT: u64 = 0xb57d_e1f3_f82c_b33f;
const EXPAND_COEF_SEQ: u64 = 0xd6e8_feb8_6659_fd93;
const EXPAND_COEF_LABEL: u64 = 0xa24b_aed4_963e_e407;
const EXPAND_COEF_LEN: u64 = 0x1656_67b1_9e37_79f9;
const EXPAND_ADD_LEN: u64 = 0x0d4c_d3e7_b14a_36d7;

pub(crate) fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(SPLITMIX_MUL1);
    x ^= x >> 27;
    x = x.wrapping_mul(SPLITMIX_MUL2);
    x ^= x >> 31;
    x
}

pub(crate) fn prf32(namespace: u64, label: u32, a: u64, b: u64) -> u32 {
    let x = namespace
        ^ b.wrapping_mul(PRF_COEF_B).wrapping_add(PRF_ADD_B)
        ^ u64::from(label).wrapping_mul(GOLDEN_GAMMA)
        ^ a.wrapping_mul(PRF_COEF_A).wrapping_add(PRF_ADD_A);
    let y = splitmix64(x);
    (y ^ (y >> 32)) as u32
}

/// Keystream for `out`; its length is mixed into the state.
pub(crate) fn expand_stream(namespace: u64, label: u32, seq: u64, out: &mut [u8]) {
    let len_hint = out.len() as u64;
    let mut state = EXPAND_STATE_INIT;
    state = state.wrapping_add(seq.wrapping_mul(EXPAND_COEF_SEQ));
    state ^= u64::from(label).wrapping_mul(EXPAND_COEF_LABEL);
    state ^= len_hint
        .wrapping_mul(EXPAND_COEF_LEN)
        .wrapping_add(EXPAND_ADD_LEN);
    state ^= namespace;

    let (blocks, tail) = out.as_chunks_mut::<8>();
    for block in blocks {
        state = state.wrapping_add(GOLDEN_GAMMA);
        *block = splitmix64(state).to_le_bytes();
    }
    if !tail.is_empty() {
        state = state.wrapping_add(GOLDEN_GAMMA);
        let v = splitmix64(state).to_le_bytes();
        tail.copy_from_slice(&v[..tail.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix64_stafford_stream() {
        assert_eq!(splitmix64(0), 0);
        assert_eq!(
            splitmix64(GOLDEN_GAMMA.wrapping_mul(1)),
            0xe220_a839_7b1d_cdaf
        );
        assert_eq!(
            splitmix64(GOLDEN_GAMMA.wrapping_mul(2)),
            0x6e78_9e6a_a1b9_65f4
        );
        assert_eq!(
            splitmix64(GOLDEN_GAMMA.wrapping_mul(3)),
            0x06c4_5d18_8009_454f
        );
    }

    #[test]
    fn expand_first_block_is_splitmix_of_state() {
        let ns = 0u64;
        let mut state = EXPAND_STATE_INIT;
        state ^= 8u64
            .wrapping_mul(EXPAND_COEF_LEN)
            .wrapping_add(EXPAND_ADD_LEN);
        state ^= ns;
        state = state.wrapping_add(GOLDEN_GAMMA);
        let expected = splitmix64(state).to_le_bytes();
        let mut out = [0u8; 8];
        expand_stream(ns, 0, 0, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn expand_length_changes_prefix() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 32];
        expand_stream(0x917b_3c48_e6a2_05d4, 0, 0, &mut a);
        expand_stream(0x917b_3c48_e6a2_05d4, 0, 0, &mut b);
        assert_ne!(&a[..], &b[..16]);
    }
}

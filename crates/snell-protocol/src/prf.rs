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

pub(crate) fn prf32_fold(namespace: u64, label: u32, a: u64, b: u64) -> u32 {
    let x = namespace
        ^ b.wrapping_mul(PRF_COEF_B).wrapping_add(PRF_ADD_B)
        ^ u64::from(label).wrapping_mul(GOLDEN_GAMMA)
        ^ a.wrapping_mul(PRF_COEF_A).wrapping_add(PRF_ADD_A);
    let y = splitmix64(x);
    (y ^ (y >> 32)) as u32
}

pub(crate) fn prf32_seq(namespace: u64, label: u32, seq: u64, domain: u32) -> u32 {
    prf32_fold(namespace, label, seq, u64::from(domain))
}

pub(crate) fn prf32(namespace: u64, label: u32, domain: u32) -> u32 {
    prf32_seq(namespace, label, 0, domain)
}

pub(crate) fn expand_stream(namespace: u64, label: u32, seq: u64, len_hint: u64, out: &mut [u8]) {
    debug_assert_eq!(out.len() as u64, len_hint);
    let mut state = EXPAND_STATE_INIT;
    state = state.wrapping_add(seq.wrapping_mul(EXPAND_COEF_SEQ));
    state ^= u64::from(label).wrapping_mul(EXPAND_COEF_LABEL);
    state ^= len_hint
        .wrapping_mul(EXPAND_COEF_LEN)
        .wrapping_add(EXPAND_ADD_LEN);
    state ^= namespace;

    const G1: u64 = GOLDEN_GAMMA;
    const G2: u64 = G1.wrapping_mul(2);
    const G3: u64 = G1.wrapping_mul(3);
    const G4: u64 = G1.wrapping_mul(4);

    let (quads, remainder) = out.as_chunks_mut::<32>();
    for quad in quads {
        let mut x0 = state.wrapping_add(G1);
        let mut x1 = state.wrapping_add(G2);
        let mut x2 = state.wrapping_add(G3);
        let mut x3 = state.wrapping_add(G4);
        state = state.wrapping_add(G4);

        x0 ^= x0 >> 30;
        x1 ^= x1 >> 30;
        x2 ^= x2 >> 30;
        x3 ^= x3 >> 30;

        x0 = x0.wrapping_mul(SPLITMIX_MUL1);
        x1 = x1.wrapping_mul(SPLITMIX_MUL1);
        x2 = x2.wrapping_mul(SPLITMIX_MUL1);
        x3 = x3.wrapping_mul(SPLITMIX_MUL1);

        x0 ^= x0 >> 27;
        x1 ^= x1 >> 27;
        x2 ^= x2 >> 27;
        x3 ^= x3 >> 27;

        x0 = x0.wrapping_mul(SPLITMIX_MUL2);
        x1 = x1.wrapping_mul(SPLITMIX_MUL2);
        x2 = x2.wrapping_mul(SPLITMIX_MUL2);
        x3 = x3.wrapping_mul(SPLITMIX_MUL2);

        x0 ^= x0 >> 31;
        x1 ^= x1 >> 31;
        x2 ^= x2 >> 31;
        x3 ^= x3 >> 31;

        quad[0..8].copy_from_slice(&x0.to_le_bytes());
        quad[8..16].copy_from_slice(&x1.to_le_bytes());
        quad[16..24].copy_from_slice(&x2.to_le_bytes());
        quad[24..32].copy_from_slice(&x3.to_le_bytes());
    }

    let (blocks, tail) = remainder.as_chunks_mut::<8>();
    for block in blocks {
        state = state.wrapping_add(G1);
        block.copy_from_slice(&splitmix64(state).to_le_bytes());
    }
    if !tail.is_empty() {
        state = state.wrapping_add(G1);
        let last = splitmix64(state).to_le_bytes();
        tail.copy_from_slice(&last[..tail.len()]);
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
    fn prf32_is_seq_zero() {
        let ns = 0xa71f_0c54_d839_6e2b;
        assert_eq!(prf32(ns, 2, 0x51a7), prf32_seq(ns, 2, 0, 0x51a7));
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
        expand_stream(ns, 0, 0, 8, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn expand_length_changes_prefix() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 32];
        expand_stream(0x917b_3c48_e6a2_05d4, 0, 0, 16, &mut a);
        expand_stream(0x917b_3c48_e6a2_05d4, 0, 0, 32, &mut b);
        assert_ne!(&a[..], &b[..16]);
    }

    fn expand_stream_scalar(namespace: u64, label: u32, seq: u64, len_hint: u64, out: &mut [u8]) {
        debug_assert_eq!(out.len() as u64, len_hint);
        let mut state = EXPAND_STATE_INIT;
        state = state.wrapping_add(seq.wrapping_mul(EXPAND_COEF_SEQ));
        state ^= u64::from(label).wrapping_mul(EXPAND_COEF_LABEL);
        state ^= len_hint
            .wrapping_mul(EXPAND_COEF_LEN)
            .wrapping_add(EXPAND_ADD_LEN);
        state ^= namespace;

        let n_full = out.len() / 8 * 8;
        let (full, tail) = out.split_at_mut(n_full);
        let (blocks, _) = full.as_chunks_mut::<8>();
        for block in blocks {
            state = state.wrapping_add(GOLDEN_GAMMA);
            block.copy_from_slice(&splitmix64(state).to_le_bytes());
        }
        if !tail.is_empty() {
            state = state.wrapping_add(GOLDEN_GAMMA);
            let v = splitmix64(state).to_le_bytes();
            tail.copy_from_slice(&v[..tail.len()]);
        }
    }

    #[test]
    fn expand_stream_matches_sequential() {
        const LENGTHS: &[usize] = &[
            0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 257, 1023,
            1024, 1025, 4095, 4096, 4097, 16379, 16380, 16381, 16382, 16383,
        ];
        let cases: &[(u64, u32, u64)] = &[
            (0, 0, 0),
            (0x917b_3c48_e6a2_05d4, 0, 0),
            (0xa71f_0c54_d839_6e2b, 2, 7),
            (u64::MAX, u32::MAX, 1),
        ];
        for &(namespace, label, seq) in cases {
            for &len in LENGTHS {
                let mut sequential = vec![0u8; len];
                let mut got = vec![0u8; len];
                expand_stream_scalar(namespace, label, seq, len as u64, &mut sequential);
                expand_stream(namespace, label, seq, len as u64, &mut got);
                assert_eq!(
                    got, sequential,
                    "ns={namespace:#x} label={label} seq={seq} len={len}"
                );
            }
        }
    }
}

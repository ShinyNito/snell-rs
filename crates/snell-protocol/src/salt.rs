//! Hide the 16-byte AEAD salt inside a v6 shaped salt block.

use crate::MAX_SALT_BLOCK_LEN;
use crate::prf::{PRF_ADD_A, PRF_ADD_B, PRF_COEF_A, PRF_COEF_B, prf32_fold, splitmix64};

/// Domain mixed into the handshake salt shuffle and mask.
pub(crate) const MIX_HANDSHAKE_DOMAIN: u32 = 0x51a7;

const SALT_NS_XOR: u64 = 0xdaa6_6d2c_7ddf_743f;

fn salt_shuffle_prf(ns_salt: u64, domain: u32, i: u32) -> u32 {
    let rdx = u64::from(i)
        .wrapping_mul(PRF_COEF_B)
        .wrapping_add(PRF_ADD_B);
    let rdi = ns_salt ^ SALT_NS_XOR;
    let rdx = rdx ^ rdi;
    let rsi = u64::from(domain)
        .wrapping_mul(PRF_COEF_A)
        .wrapping_add(PRF_ADD_A);
    let y = splitmix64(rdx ^ rsi);
    (y ^ (y >> 32)) as u32
}

pub(crate) fn shuffle_perm(ns_salt: u64, rounds: u8, len: usize, out: &mut [u8]) {
    debug_assert_eq!(out.len(), len);
    if len == 0 {
        return;
    }
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = i as u8;
    }
    let rounds = rounds.max(1);
    for round in 0..u32::from(rounds) {
        let domain = MIX_HANDSHAKE_DOMAIN.wrapping_add(round);
        for i in 0..len {
            let span = (len - i) as u64;
            let raw = u64::from(salt_shuffle_prf(ns_salt, domain, i as u32));
            let j = i + (raw % span) as usize;
            out.swap(i, j);
        }
    }
}

fn mask(ns_salt: u64, mix_stride: u8, i: u32) -> u8 {
    let prf = prf32_fold(ns_salt, 2, u64::from(MIX_HANDSHAKE_DOMAIN), u64::from(i));
    (i as u8).wrapping_mul(mix_stride) ^ (prf as u8)
}

pub(crate) fn extract(
    ns_salt: u64,
    mix_stride: u8,
    rounds: u8,
    block: &[u8],
    out: &mut [u8; 16],
) -> Result<(), ()> {
    let len = block.len();
    if len > MAX_SALT_BLOCK_LEN {
        return Err(());
    }
    let mut perm = [0u8; MAX_SALT_BLOCK_LEN];
    shuffle_perm(ns_salt, rounds, len, &mut perm[..len]);
    for i in 0..16 {
        let p = usize::from(perm[i]);
        if p >= len {
            return Err(());
        }
        out[i] = mask(ns_salt, mix_stride, i as u32) ^ block[p];
    }
    Ok(())
}

pub(crate) fn write(
    ns_salt: u64,
    mix_stride: u8,
    rounds: u8,
    block: &mut [u8],
    salt: &[u8; 16],
) -> Result<(), ()> {
    let len = block.len();
    if len > MAX_SALT_BLOCK_LEN {
        return Err(());
    }
    let mut perm = [0u8; MAX_SALT_BLOCK_LEN];
    shuffle_perm(ns_salt, rounds, len, &mut perm[..len]);
    for i in 0..16 {
        let p = usize::from(perm[i]);
        if p >= len {
            return Err(());
        }
        block[p] = mask(ns_salt, mix_stride, i as u32) ^ salt[i];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns() -> u64 {
        0x3e8a_91b5_2740_f6cd
    }

    #[test]
    fn write_then_extract_round_trips() {
        let salt = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let mut block = vec![0xaa; 36];
        write(ns(), 0x37, 3, &mut block, &salt).unwrap();
        let mut extracted = [0u8; 16];
        extract(ns(), 0x37, 3, &block, &mut extracted).unwrap();
        assert_eq!(extracted, salt);
    }

    #[test]
    fn shuffle_is_a_permutation() {
        let len = 32;
        let mut perm = [0u8; MAX_SALT_BLOCK_LEN];
        shuffle_perm(ns(), 3, len, &mut perm[..len]);
        let mut seen = [false; 32];
        for &v in &perm[..len] {
            assert!(!seen[usize::from(v)]);
            seen[usize::from(v)] = true;
        }
        assert!(seen.iter().all(|&s| s));
    }

    #[test]
    fn oversize_block_rejected() {
        let mut block = vec![0u8; MAX_SALT_BLOCK_LEN + 1];
        assert!(write(ns(), 0x55, 2, &mut block, &[0; 16]).is_err());
    }
}

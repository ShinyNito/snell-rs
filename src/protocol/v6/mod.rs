use std::collections::HashSet;
use std::ops::Range;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use bytes::{BufMut, BytesMut};

use crate::MAX_V6_RECORD_PAYLOAD_LEN;
use crate::error::{Error, Result};
use crate::protocol::crypto::{AEAD_TAG_SIZE, Aes128GcmCrypto, SALT_SIZE};
use crate::protocol::nonce::Nonce12;
use crate::protocol::random::fill_random;

type Blake2b256 = Blake2b<U32>;

pub const V6_HEADER_PLAIN_SIZE: usize = 7;
pub const V6_HEADER_CIPHER_SIZE: usize = V6_HEADER_PLAIN_SIZE + AEAD_TAG_SIZE;
pub const V6_PAYLOAD_TAG_SIZE: usize = AEAD_TAG_SIZE;
pub const V6_SALT_REPLAY_CACHE_CAPACITY: usize = 65_536;
const PROFILE_SEED: &[u8; 24] = b"\x8d\x41\xa7\x13\x5c\xe2\x09\xbb\x70\x2f\xd6\x94\x33\x18\xc0\x6e\x4a\x91\x25\xfd\xb8\x03\x77\xac";
const HANDSHAKE_DOMAIN: u32 = 0x7053;
const MIX_HANDSHAKE_DOMAIN: u32 = 0x51a7;
const MAX_EXTRA_TARGET_PADDING: usize = 0x02da;
const V6_CHUNK_MAX_RAW_BOUND: usize = 0x3fff;
const V6_TRAFFIC_SHAPING_MTU_CAP: usize = 0x05b4;
const V6_TARGET_DIRECT_LIMIT: usize = 0x05b3;
const V6_TARGET_U16_LIMIT: usize = 0xfffe;
const LABEL_PADDING: u32 = 0;
const LABEL_BIT_PERCENT: u32 = 1;
const LABEL_MOTIF: u32 = 2;
const LABEL_MIX_OFFSET: u32 = 3;
const LABEL_PROFILE_ID: u32 = 5;
const LABEL_GENERATOR: u32 = 6;
const LABEL_PAD_MIN: u32 = 7;
const LABEL_PAD_MAX: u32 = 8;
const LABEL_PAD_COUNT: u32 = 9;
const LABEL_PAD_INTERVAL: u32 = 10;
const LABEL_SMALL_LIMIT: u32 = 11;
const LABEL_BIT_MIN: u32 = 12;
const LABEL_BIT_MAX: u32 = 13;
const LABEL_PREFIX_MIN: u32 = 14;
const LABEL_PREFIX_MAX: u32 = 15;
const LABEL_MIX_MODE: u32 = 16;
const LABEL_MIX_ROUNDS: u32 = 17;
const LABEL_MIX_STRIDE: u32 = 18;
const LABEL_MIX_OFFSET_BASE: u32 = 19;
const LABEL_MIX_BLOCK: u32 = 20;
const LABEL_CHUNK_POLICY: u32 = 21;
const LABEL_CHUNK_INITIAL: u32 = 22;
const LABEL_CHUNK_MAX: u32 = 23;
const LABEL_CHUNK_STEP: u32 = 24;
const LABEL_CHUNK_JITTER: u32 = 25;
const LABEL_CHUNK_BUCKET: u32 = 26;
const LABEL_IDLE_RESET: u32 = 27;
const LABEL_WRITE_POLICY: u32 = 28;
const LABEL_WRITE_FIRST: u32 = 29;
const LABEL_WRITE_BUCKET: u32 = 30;
const LABEL_WRITE_SEQ: u32 = 31;
const LABEL_WRITE_JITTER: u32 = 32;
const LABEL_RECORD_PREFIX: u32 = 33;
const LABEL_PAYLOAD_PADDING: u32 = 34;
const LABEL_WRITE_TARGET: u32 = 35;
const LABEL_WRITE_JITTER_VALUE: u32 = 36;
const LABEL_WRITE_NEXT: u32 = 37;
const LABEL_CHUNK_SIZE: u32 = 38;
const LABEL_CHUNK_JITTER_VALUE: u32 = 39;

// Fixed namespace seeds used to derive independent PRF domains from the
// profile secret. These are protocol constants, not secrets.
const NS_SEED_PROFILE: u64 = 0xb46c_2e7d_9a15_38f1;
const NS_SEED_PREFIX: u64 = 0x5d92_17c0_83e6_4ab9;
const NS_SEED_MOTIF: u64 = 0xa71f_0c54_d839_6e2b;
const NS_SEED_SALT: u64 = 0x3e8a_91b5_2740_f6cd;
const NS_SEED_MIX: u64 = 0xc9f4_260b_7d1e_835a;
const NS_SEED_CHUNK: u64 = 0x62d0_b5e1_9c4a_783f;
const NS_SEED_WRITE: u64 = 0x917b_3c48_e6a2_05d4;

const GOLDEN_RATIO_64: u64 = 0x9e37_79b9_7f4a_7c15;
const MIX_ROUND_MOD3_RECIPROCAL: u32 = 171;
const MIX_ROUND_MOD3_SHIFT: u32 = 9;
const MIX_ROUND_BYTE_MASK: u32 = 0xff;

// PRF/stream mixer constants; keep exact for protocol compatibility.
const DOMAIN_MUL: u64 = 0xd6e8_feb8_6659_fd93;
const NAMESPACE_SEED_ADD: u64 = 0xa076_1d64_78bd_642f;
const NAMESPACE_SECRET_WORD2_ROTATE: u32 = 17;
const NAMESPACE_SECRET_WORD3_ROTATE: u32 = 11;
const PRF_B_MUL: u64 = 0x5899_65cc_7537_4cc3;
const PRF_B_ADD: u64 = 0x33a2_13ec_50ff_e2e9;
const PRF_A_MUL: u64 = 0xe703_7ed1_a0b4_28db;
const PRF_A_ADD: u64 = 0x8f39_07f7_b2b8_0c35;
const STREAM_INITIAL_STATE: u64 = 0xb57d_e1f3_f82c_b33f;
const STREAM_LABEL_MUL: u64 = 0xa24b_aed4_963e_e407;
const STREAM_LEN_MUL: u64 = 0x1656_67b1_9e37_79f9;
const STREAM_LEN_ADD: u64 = 0x0d4c_d3e7_b14a_36d7;
const SALT_NAMESPACE_XOR: u64 = 0xdaa6_6d2c_7ddf_743f;

// Standard SplitMix64 finalizer constants; keep exact for protocol compatibility.
const SPLITMIX64_FINALIZER_MUL1: u64 = 0xbf58_476d_1ce4_e5b9;
const SPLITMIX64_FINALIZER_MUL2: u64 = 0x94d0_49bb_1331_11eb;

mod chunk;
mod frame;
mod profile;
mod replay;
mod salt;
#[cfg(test)]
mod tests;

pub use chunk::V6ChunkSizer;
pub use frame::{V6DecodedHeader, V6FrameDecoder, V6FrameEncoder};
pub use profile::V6Profile;
pub use replay::V6SaltReplayCache;
pub(in crate::protocol::v6) use salt::salt_positions;
#[cfg(test)]
pub(crate) use salt::split_salt_block;

#[inline]
fn mix_padding_payload(
    profile: &V6Profile,
    seq: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
) {
    let n = padding.len().min(payload_cipher.len());
    if n == 0 {
        return;
    }

    for r in 0..profile.mix_rounds {
        match profile.mix_mode {
            0 => mix_fixed_stride(profile, r, padding, payload_cipher, n),
            1 => mix_alternating_block(profile, r, padding, payload_cipher, n),
            2 => mix_prf_stride(profile, seq, r, padding, payload_cipher, n),
            _ => unreachable!("mix mode is derived modulo 3"),
        }
    }
}

const fn mix_round_delta(round: u32) -> u32 {
    let quotient = (MIX_ROUND_MOD3_RECIPROCAL * round) >> MIX_ROUND_MOD3_SHIFT;
    (round - 3 * quotient) & MIX_ROUND_BYTE_MASK
}

fn mix_fixed_stride(
    profile: &V6Profile,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
) {
    let rr = mix_round_delta(round);
    let stride = (profile.mix_stride + rr as usize).max(1);
    if stride == 1 {
        padding[..n].swap_with_slice(&mut payload_cipher[..n]);
        return;
    }

    let mut off = profile.mix_offset_base % stride;
    while off < n {
        std::mem::swap(&mut padding[off], &mut payload_cipher[off]);
        off += stride;
    }
}

fn mix_alternating_block(
    profile: &V6Profile,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
) {
    let block = profile.mix_block;
    let mut off = (round as usize & 1) * block;
    while off + block <= n {
        let end = off + block;
        padding[off..end].swap_with_slice(&mut payload_cipher[off..end]);
        off += block * 2;
    }
}

fn mix_prf_stride(
    profile: &V6Profile,
    seq: u32,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
) {
    let rr = mix_round_delta(round);
    let stride = (profile.mix_stride + rr as usize).max(1);
    let mut off =
        (profile.prf32(LABEL_MIX_OFFSET, seq, round) as usize + profile.mix_offset_base) % stride;
    if stride == 1 {
        padding[..n].swap_with_slice(&mut payload_cipher[..n]);
        return;
    }

    while off < n {
        std::mem::swap(&mut padding[off], &mut payload_cipher[off]);
        off += stride;
    }
}

fn blake2b_256_from_slices(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    for part in parts {
        Digest::update(&mut hasher, *part);
    }
    let digest = hasher.finalize();
    let mut out = [0; 32];
    out.copy_from_slice(&digest);
    out
}

fn read_le_u64(input: &[u8; 32], offset: usize) -> u64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&input[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

const fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(SPLITMIX64_FINALIZER_MUL1);
    x ^= x >> 27;
    x = x.wrapping_mul(SPLITMIX64_FINALIZER_MUL2);
    x ^ (x >> 31)
}

const fn fold_u64_to_u32(x: u64) -> u32 {
    let bytes = (x ^ (x >> 32)).to_le_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn derive_namespace(profile_secret: &[u8; 32], label: u32, seed_const: u64) -> u64 {
    let s0 = read_le_u64(profile_secret, 0);
    let s1 = read_le_u64(profile_secret, 8);
    let s2 = read_le_u64(profile_secret, 16);
    let s3 = read_le_u64(profile_secret, 24);
    let mixed = u64::from(label).wrapping_mul(DOMAIN_MUL)
        ^ seed_const.wrapping_add(NAMESPACE_SEED_ADD)
        ^ s0
        ^ s1.wrapping_add(GOLDEN_RATIO_64)
        ^ s2.rotate_left(NAMESPACE_SECRET_WORD2_ROTATE)
        ^ s3.rotate_right(NAMESPACE_SECRET_WORD3_ROTATE);
    splitmix64(mixed)
}

const fn prf32_mix(namespace: u64, label: u32, a: u32, b: u32) -> u32 {
    let mixed = namespace
        ^ (b as u64).wrapping_mul(PRF_B_MUL).wrapping_add(PRF_B_ADD)
        ^ (label as u64).wrapping_mul(GOLDEN_RATIO_64)
        ^ (a as u64).wrapping_mul(PRF_A_MUL).wrapping_add(PRF_A_ADD);
    fold_u64_to_u32(splitmix64(mixed))
}

fn expand_stream(namespace: u64, label: u32, seq: u32, len: usize, out: &mut BytesMut) {
    if len == 0 {
        return;
    }

    out.reserve(len);
    let mut state = stream_initial_state(namespace, label, seq, len);
    let mut written = 0;

    {
        let spare = out.chunk_mut();
        debug_assert!(spare.len() >= len);
        let spare = &mut spare[..len];

        while written + 8 <= len {
            state = state.wrapping_add(GOLDEN_RATIO_64);
            spare[written..written + 8].copy_from_slice(&splitmix64(state).to_le_bytes());
            written += 8;
        }

        if written < len {
            state = state.wrapping_add(GOLDEN_RATIO_64);
            spare[written..len].copy_from_slice(&splitmix64(state).to_le_bytes()[..len - written]);
        }
    }

    // SAFETY: every byte in the spare region is initialized by copy_from_slice
    // before the initialized length is advanced.
    unsafe {
        out.advance_mut(len);
    }
}

fn expand_stream_array<const N: usize>(namespace: u64, label: u32, seq: u32) -> [u8; N] {
    let mut out = [0; N];
    let mut state = stream_initial_state(namespace, label, seq, N);
    let mut chunks = out.chunks_exact_mut(8);
    for chunk in &mut chunks {
        state = state.wrapping_add(GOLDEN_RATIO_64);
        chunk.copy_from_slice(&splitmix64(state).to_le_bytes());
    }

    let tail = chunks.into_remainder();
    if !tail.is_empty() {
        state = state.wrapping_add(GOLDEN_RATIO_64);
        tail.copy_from_slice(&splitmix64(state).to_le_bytes()[..tail.len()]);
    }
    out
}

#[inline]
const fn stream_initial_state(namespace: u64, label: u32, seq: u32, len: usize) -> u64 {
    STREAM_INITIAL_STATE.wrapping_add((seq as u64).wrapping_mul(DOMAIN_MUL))
        ^ (label as u64).wrapping_mul(STREAM_LABEL_MUL)
        ^ (len as u64)
            .wrapping_mul(STREAM_LEN_MUL)
            .wrapping_add(STREAM_LEN_ADD)
        ^ namespace
}

const fn salt_shuffle_prf(ns_salt: u64, domain_round: u32, index: u32) -> u32 {
    let index_part = (index as u64)
        .wrapping_mul(PRF_B_MUL)
        .wrapping_add(PRF_B_ADD)
        ^ (ns_salt ^ SALT_NAMESPACE_XOR);
    let mixed = (domain_round as u64)
        .wrapping_mul(PRF_A_MUL)
        .wrapping_add(PRF_A_ADD)
        ^ index_part;
    fold_u64_to_u32(splitmix64(mixed))
}

const fn pick_u32(raw: u32, lo: u32, hi: u32) -> u32 {
    if hi <= lo {
        lo
    } else {
        lo + raw % (hi - lo + 1)
    }
}

const fn pick_usize(raw: u32, lo: usize, hi: usize) -> usize {
    if hi <= lo {
        lo
    } else {
        lo + raw as usize % (hi - lo + 1)
    }
}

use std::collections::{HashSet, VecDeque};
use std::ops::Range;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use blake2::digest::{KeyInit, Mac, consts::U32};
use blake2::{Blake2b, Blake2bMac, Digest};
use bytes::BytesMut;

use crate::MAX_V6_RECORD_PAYLOAD_LEN;
use crate::error::{Error, Result};
use crate::protocol::crypto::{AEAD_TAG_SIZE, Aes128GcmCrypto, SALT_SIZE};
use crate::protocol::nonce::Nonce12;
use crate::protocol::random::fill_random;

type Blake2b256 = Blake2b<U32>;
type Blake2bMac256 = Blake2bMac<U32>;

pub const V6_HEADER_PLAIN_SIZE: usize = 7;
pub const V6_HEADER_CIPHER_SIZE: usize = V6_HEADER_PLAIN_SIZE + AEAD_TAG_SIZE;
pub const V6_PAYLOAD_TAG_SIZE: usize = AEAD_TAG_SIZE;
pub const V6_SALT_REPLAY_CACHE_CAPACITY: usize = 65_536;
const V6_SHAPE_LABEL: &[u8] = b"snell-shape-v1";
const HANDSHAKE_DOMAIN: u32 = 0x7053;
const MIX_HANDSHAKE_DOMAIN: u32 = 0x51a7;
const MAX_EXTRA_TARGET_PADDING: usize = 0x02da;
const V6_CHUNK_MAX_RAW_BOUND: usize = 0x3fff;
const V6_TRAFFIC_SHAPING_MTU_CAP: usize = 0x05b4;
const V6_MTU_OVERHEAD_LIMIT: usize = 0x0553;
const V6_STEADY_OVERHEAD: usize = V6_HEADER_CIPHER_SIZE + V6_PAYLOAD_TAG_SIZE;

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
pub use salt::split_salt_block;

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

fn mix_fixed_stride(
    profile: &V6Profile,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
) {
    let rr = (round - 3 * ((171 * round) >> 9)) & 0xff;
    let stride = (profile.mix_stride + rr as usize).max(1);
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
        for index in off..off + block {
            std::mem::swap(&mut padding[index], &mut payload_cipher[index]);
        }
        off += 2 * block;
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
    let rr = (round - 3 * ((171 * round) >> 9)) & 0xff;
    let stride = (profile.mix_stride + rr as usize).max(1);
    let mut off =
        (profile.prf32("mix-offset", seq, round) as usize + profile.mix_offset_base) % stride;
    while off < n {
        std::mem::swap(&mut padding[off], &mut payload_cipher[off]);
        off += stride;
    }
}

fn prf32_with_secret(profile_secret: &[u8; 32], label: &str, a: u32, b: u32) -> u32 {
    let a = a.to_be_bytes();
    let b = b.to_be_bytes();
    let parts: [&[u8]; 3] = [label.as_bytes(), &a, &b];
    let digest = blake2b_256_keyed_parts(profile_secret, &parts);
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

fn blake2b_256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    Digest::update(&mut hasher, input);
    let digest = hasher.finalize();
    let mut out = [0; 32];
    out.copy_from_slice(&digest);
    out
}

fn blake2b_256_keyed_parts(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Blake2bMac256 as KeyInit>::new_from_slice(key)
        .expect("BLAKE2b accepts the fixed-size Snell v6 profile key");
    for part in parts {
        Mac::update(&mut mac, part);
    }
    let digest = mac.finalize().into_bytes();
    let mut out = [0; 32];
    out.copy_from_slice(&digest);
    out
}

fn pick_u32(raw: u32, lo: u32, hi: u32) -> u32 {
    if hi <= lo {
        lo
    } else {
        lo + raw % (hi - lo + 1)
    }
}

fn pick_usize(raw: u32, lo: usize, hi: usize) -> usize {
    if hi <= lo {
        lo
    } else {
        lo + raw as usize % (hi - lo + 1)
    }
}

fn clamp_usize(x: usize, lo: usize, hi: usize) -> usize {
    x.max(lo).min(hi)
}

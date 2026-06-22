//! Shaped profile derivation and traffic-shaping helpers.
//!
//! This module keeps the protocol layer synchronous and buffer-oriented so a
//! transport layer can decide how to own and submit buffers.

use std::time::Duration;

use super::crypto::GOLDEN_GAMMA;
use super::crypto::expand::expand_stream;
use super::crypto::kdf::profile_secret;
use super::crypto::prf::{prf32, prf32_seq};
use super::crypto::splitmix::splitmix64;
use super::{MIX_HANDSHAKE_DOMAIN, salt};

mod fill;
mod mix;
mod sizing;

pub(crate) use mix::mix_padding_payload;

pub const SALT_LEN: usize = 16;
const HANDSHAKE_DOMAIN: u32 = 0x7053;
const CHUNK_INITIAL_DOMAIN: u32 = 0xf17c;
const MAX_EXTRA_TARGET_PADDING: usize = 0x02da;
const PROFILE_CHUNK_MAX_RAW_BOUND: usize = 0x3fff;
const PROFILE_TRAFFIC_SHAPING_MTU_CAP: usize = 0x05b4;
const PROFILE_TARGET_DIRECT_LIMIT: usize = 0x05b3;
const PROFILE_TARGET_U16_LIMIT: usize = 0xfffe;

mod labels {
    pub(super) const PADDING: u32 = 0;
    pub(super) const BIT_PERCENT: u32 = 1;
    pub(super) const MOTIF: u32 = 2;
    pub(super) const MIX_OFFSET: u32 = 3;
    pub(super) const PROFILE_ID: u32 = 5;
    pub(super) const GENERATOR: u32 = 6;
    pub(super) const PAD_MIN: u32 = 7;
    pub(super) const PAD_MAX: u32 = 8;
    pub(super) const PAD_COUNT: u32 = 9;
    pub(super) const PAD_INTERVAL: u32 = 10;
    pub(super) const SMALL_LIMIT: u32 = 11;
    pub(super) const BIT_MIN: u32 = 12;
    pub(super) const BIT_MAX: u32 = 13;
    pub(super) const PREFIX_MIN: u32 = 14;
    pub(super) const PREFIX_MAX: u32 = 15;
    pub(super) const MIX_MODE: u32 = 16;
    pub(super) const MIX_ROUNDS: u32 = 17;
    pub(super) const MIX_STRIDE: u32 = 18;
    pub(super) const MIX_OFFSET_BASE: u32 = 19;
    pub(super) const MIX_BLOCK: u32 = 20;
    pub(super) const CHUNK_POLICY: u32 = 21;
    pub(super) const CHUNK_INITIAL: u32 = 22;
    pub(super) const CHUNK_FIRST_CAP: u32 = 22;
    pub(super) const CHUNK_MAX: u32 = 23;
    pub(super) const CHUNK_STEP: u32 = 24;
    pub(super) const CHUNK_JITTER: u32 = 25;
    pub(super) const CHUNK_BUCKET: u32 = 26;
    pub(super) const IDLE_RESET: u32 = 27;
    pub(super) const WRITE_POLICY: u32 = 28;
    pub(super) const WRITE_FIRST: u32 = 29;
    pub(super) const WRITE_BUCKET: u32 = 30;
    pub(super) const WRITE_SEQ: u32 = 31;
    pub(super) const WRITE_JITTER: u32 = 32;
    pub(super) const RECORD_PREFIX: u32 = 33;
    pub(super) const PAYLOAD_PADDING: u32 = 34;
    pub(super) const WRITE_TARGET: u32 = 35;
    pub(super) const WRITE_JITTER_VALUE: u32 = 36;
    pub(super) const WRITE_NEXT: u32 = 37;
    pub(super) const CHUNK_SIZE: u32 = 38;
    pub(super) const CHUNK_JITTER_VALUE: u32 = 39;
}

use labels::*;

const NS_SEED_PROFILE: u64 = 0xb46c_2e7d_9a15_38f1;
const NS_SEED_PREFIX: u64 = 0x5d92_17c0_83e6_4ab9;
const NS_SEED_MOTIF: u64 = 0xa71f_0c54_d839_6e2b;
const NS_SEED_SALT: u64 = 0x3e8a_91b5_2740_f6cd;
const NS_SEED_MIX: u64 = 0xc9f4_260b_7d1e_835a;
const NS_SEED_CHUNK: u64 = 0x62d0_b5e1_9c4a_783f;
const NS_SEED_WRITE: u64 = 0x917b_3c48_e6a2_05d4;

const DOMAIN_MUL: u64 = 0xd6e8_feb8_6659_fd93;
const NAMESPACE_SEED_ADD: u64 = 0xa076_1d64_78bd_642f;
const NAMESPACE_SECRET_WORD2_ROTATE: u32 = 17;
const NAMESPACE_SECRET_WORD3_ROTATE: u32 = 11;

#[derive(Clone, Copy, Debug)]
struct Namespaces {
    profile: u64,
    prefix: u64,
    motif: u64,
    salt: u64,
    mix: u64,
    chunk: u64,
    write: u64,
}

impl Namespaces {
    #[must_use]
    fn derive(secret: &[u8; 32]) -> Self {
        Self {
            profile: derive_namespace(secret, PROFILE_ID, NS_SEED_PROFILE),
            prefix: derive_namespace(secret, PADDING, NS_SEED_PREFIX),
            motif: derive_namespace(secret, MOTIF, NS_SEED_MOTIF),
            // Derivation label 3 seeds the salt namespace; lookup label 3 still maps to mix.
            salt: derive_namespace(secret, 3, NS_SEED_SALT),
            mix: derive_namespace(secret, MIX_MODE, NS_SEED_MIX),
            chunk: derive_namespace(secret, CHUNK_POLICY, NS_SEED_CHUNK),
            write: derive_namespace(secret, WRITE_POLICY, NS_SEED_WRITE),
        }
    }

    #[must_use]
    const fn for_label(self, label: u32) -> u64 {
        match label {
            0 | 1 | 14 | 15 | 33 | 34 => self.prefix,
            2 => self.motif,
            3 | 16..=20 => self.mix,
            21..=26 | 38 | 39 => self.chunk,
            28..=32 | 35..=37 => self.write,
            _ => self.profile,
        }
    }

    #[must_use]
    fn prf32(self, label: u32, a: u32, b: u32) -> u32 {
        prf32_seq(self.for_label(label), label, u64::from(a), b)
    }

    #[must_use]
    fn prf_static(self, label: u32, domain: u32) -> u32 {
        prf32(self.for_label(label), label, domain)
    }

    fn expand_slice(self, label: u32, seq: u32, out: &mut [u8]) {
        expand_stream(
            self.for_label(label),
            label,
            u64::from(seq),
            out.len() as u64,
            out,
        );
    }

    fn expand_array<const N: usize>(self, label: u32, seq: u32) -> [u8; N] {
        let mut out = [0; N];
        expand_stream(
            self.for_label(label),
            label,
            u64::from(seq),
            N as u64,
            &mut out,
        );
        out
    }
}

#[derive(Clone, Debug)]
pub struct ShapedProfile {
    namespaces: Namespaces,
    generator: u32,
    pad_min: usize,
    pad_max: usize,
    pad_count: u32,
    pad_interval: u32,
    small_limit: usize,
    bit_min: u32,
    bit_max: u32,
    prefix_min_record: usize,
    prefix_max_record: usize,
    mix_mode: u32,
    mix_rounds: u32,
    mix_stride: usize,
    mix_offset_base: usize,
    mix_block: usize,
    chunk_policy: u32,
    chunk_initial: usize,
    first_record_cap: usize,
    chunk_max: usize,
    chunk_step: usize,
    chunk_jitter: usize,
    idle_reset: Duration,
    write_policy: u32,
    write_first: u32,
    chunk_buckets: [usize; 8],
    write_buckets: [usize; 8],
    write_seq: [usize; 8],
    write_jitter: usize,
    write_jitter_percent: usize,
    g1: usize,
    g2: usize,
    g3: usize,
    g4: usize,
    g5: usize,
    g6: usize,
    salt_block_len: usize,
    #[cfg(test)]
    salt_positions: [usize; SALT_LEN],
    mix_stride_handshake: usize,
    mix_rounds_handshake: u32,
}

pub type Profile = ShapedProfile;

impl ShapedProfile {
    #[must_use]
    pub fn derive(psk: &[u8]) -> Self {
        let secret = profile_secret(psk)
            .expect("psk length is 16..=255 and fixed BLAKE2b-256 output size is valid");
        let namespaces = Namespaces::derive(&secret);

        let generator = namespaces.prf_static(GENERATOR, 0) & 3;
        let pad_min = pick_usize(namespaces.prf_static(PAD_MIN, 0), 0x18, 0xa0);
        let pad_max = (pad_min + pick_usize(namespaces.prf_static(PAD_MAX, 0), 0xa0, 0x3c0))
            .min(MAX_EXTRA_TARGET_PADDING);
        let pad_count = pick_u32(namespaces.prf_static(PAD_COUNT, 0), 2, 8);
        let pad_interval = pick_u32(namespaces.prf_static(PAD_INTERVAL, 0), 2, 0x0b);
        let small_limit = pick_usize(namespaces.prf_static(SMALL_LIMIT, 0), 0x60, 0x300);
        let bit_min = pick_u32(namespaces.prf_static(BIT_MIN, 0), 0x18, 0x29);
        let bit_max = pick_u32(namespaces.prf_static(BIT_MAX, 0), 0x3a, 0x4c);

        let prefix_min_handshake = pick_usize(
            namespaces.prf_static(PREFIX_MIN, HANDSHAKE_DOMAIN),
            0x10,
            0x60,
        );
        let mut prefix_max_handshake = prefix_min_handshake
            + pick_usize(
                namespaces.prf_static(PREFIX_MAX, HANDSHAKE_DOMAIN),
                0x10,
                0xa0,
            );
        prefix_max_handshake = prefix_max_handshake.min(0x80);
        let prefix_min_handshake = prefix_min_handshake.min(prefix_max_handshake);
        let salt_prefix_len = pick_usize(
            namespaces.prf_static(RECORD_PREFIX, HANDSHAKE_DOMAIN),
            prefix_min_handshake,
            prefix_max_handshake,
        );
        let salt_block_len = SALT_LEN + salt_prefix_len;
        let mix_rounds_handshake = pick_u32(
            namespaces.prf_static(MIX_ROUNDS, MIX_HANDSHAKE_DOMAIN),
            1,
            4,
        );
        let mix_stride_handshake = pick_usize(
            namespaces.prf_static(MIX_STRIDE, MIX_HANDSHAKE_DOMAIN),
            0x11,
            0xfb,
        );
        #[cfg(test)]
        let salt_positions = salt_positions(namespaces.salt, salt_block_len, mix_rounds_handshake);

        let prefix_min_record = pick_usize(namespaces.prf_static(PREFIX_MIN, 0), 0x08, 0x50);
        let mut prefix_max_record =
            prefix_min_record + pick_usize(namespaces.prf_static(PREFIX_MAX, 0), 0x10, 0xa0);
        prefix_max_record = prefix_max_record.min(0x80);
        let prefix_min_record = prefix_min_record.min(prefix_max_record);

        let mix_mode = namespaces.prf_static(MIX_MODE, 0) % 3;
        let mix_rounds = pick_u32(namespaces.prf_static(MIX_ROUNDS, 0), 1, 3);
        let mix_stride = pick_usize(namespaces.prf_static(MIX_STRIDE, 0), 2, 13);
        let mix_offset_base = pick_usize(namespaces.prf_static(MIX_OFFSET_BASE, 0), 0, 15);
        let mix_block = pick_usize(namespaces.prf_static(MIX_BLOCK, 0), 8, 0x40);

        let chunk_policy = namespaces.prf_static(CHUNK_POLICY, 0) % 3;
        let chunk_initial = pick_usize(
            namespaces.prf_static(CHUNK_INITIAL, 0),
            0x200,
            PROFILE_TRAFFIC_SHAPING_MTU_CAP,
        )
        .clamp(0x60, PROFILE_TRAFFIC_SHAPING_MTU_CAP);
        let first_record_cap = pick_usize(
            namespaces.prf_static(CHUNK_FIRST_CAP, CHUNK_INITIAL_DOMAIN),
            0x100,
            0x300,
        )
        .clamp(0x100, chunk_initial.min(0x300));
        let chunk_max = pick_usize(
            namespaces.prf_static(CHUNK_MAX, 0),
            0x2000,
            PROFILE_CHUNK_MAX_RAW_BOUND,
        )
        .max(chunk_initial);
        let chunk_step =
            pick_usize(namespaces.prf_static(CHUNK_STEP, 0), 0x400, 0x1000).min(0x0b68);
        let chunk_jitter =
            pick_usize(namespaces.prf_static(CHUNK_JITTER, 0), 0x10, 0xc0).min(0x0b6);
        let idle_reset = Duration::from_secs(pick_usize(
            namespaces.prf_static(IDLE_RESET, 0),
            0x0c,
            0x5a,
        ) as u64);
        let write_policy = namespaces.prf_static(WRITE_POLICY, 0) % 3;
        let write_first = pick_u32(namespaces.prf_static(WRITE_FIRST, 0), 4, 8);

        let mut chunk_buckets = [0; 8];
        let mut write_buckets = [0; 8];
        let mut write_seq = [0; 8];
        for i in 0..8 {
            let chunk_bucket = pick_usize(
                namespaces.prf_static(CHUNK_BUCKET, i as u32),
                0x1000,
                chunk_max,
            );
            chunk_buckets[i] = if chunk_bucket > chunk_max {
                chunk_max
            } else if chunk_bucket <= 0x0fff {
                0x1000
            } else {
                chunk_bucket
            };
            write_buckets[i] = pick_usize(
                namespaces.prf_static(WRITE_BUCKET, i as u32),
                0x140,
                PROFILE_TRAFFIC_SHAPING_MTU_CAP,
            )
            .clamp(0x100, PROFILE_TRAFFIC_SHAPING_MTU_CAP);
            write_seq[i] = pick_usize(
                namespaces.prf_static(WRITE_SEQ, i as u32),
                0x168,
                PROFILE_TRAFFIC_SHAPING_MTU_CAP,
            )
            .clamp(0x100, PROFILE_TRAFFIC_SHAPING_MTU_CAP);
        }

        let write_jitter = pick_usize(namespaces.prf_static(WRITE_JITTER, 0), 0x08, 0x60);
        let write_jitter_percent = pick_usize(namespaces.prf_static(WRITE_POLICY, 0x504c), 8, 0x30);

        let g1 = pick_usize(namespaces.prf_static(GENERATOR, 1), 0x18, 0x80);
        let g2 = pick_usize(namespaces.prf_static(GENERATOR, 2), 0x10, 0x60);
        let g3 = pick_usize(namespaces.prf_static(GENERATOR, 3), 0x10, 0x60);
        let g4 = pick_usize(namespaces.prf_static(GENERATOR, 4), 0x00, 0x09);
        let g5 = pick_usize(namespaces.prf_static(GENERATOR, 5), 0x01, 0x08);
        let g6 = pick_usize(namespaces.prf_static(GENERATOR, 6), 0x07, 0x17);

        Self {
            namespaces,
            generator,
            pad_min,
            pad_max,
            pad_count,
            pad_interval,
            small_limit,
            bit_min,
            bit_max,
            prefix_min_record,
            prefix_max_record,
            mix_mode,
            mix_rounds,
            mix_stride,
            mix_offset_base,
            mix_block,
            chunk_policy,
            chunk_initial,
            first_record_cap,
            chunk_max,
            chunk_step,
            chunk_jitter,
            idle_reset,
            write_policy,
            write_first,
            chunk_buckets,
            write_buckets,
            write_seq,
            write_jitter,
            write_jitter_percent,
            g1,
            g2,
            g3,
            g4,
            g5,
            g6,
            salt_block_len,
            #[cfg(test)]
            salt_positions,
            mix_stride_handshake,
            mix_rounds_handshake,
        }
    }

    #[must_use]
    pub(crate) const fn salt_block_len(&self) -> usize {
        self.salt_block_len
    }

    #[must_use]
    pub(crate) const fn max_padding_len(&self) -> usize {
        self.pad_max + MAX_EXTRA_TARGET_PADDING
    }

    #[must_use]
    pub const fn idle_reset(&self) -> Duration {
        self.idle_reset
    }

    #[must_use]
    pub(crate) const fn first_record_cap(&self) -> usize {
        self.first_record_cap
    }

    #[must_use]
    pub(crate) const fn chunk_initial(&self) -> usize {
        self.chunk_initial
    }

    #[must_use]
    pub(crate) fn record_prefix_len(&self, seq: u32) -> usize {
        self.pick(
            RECORD_PREFIX,
            seq,
            0,
            self.prefix_min_record,
            self.prefix_max_record,
        )
    }

    pub(crate) fn write_salt_block(
        &self,
        salt_bytes: &[u8; SALT_LEN],
        block: &mut [u8],
    ) -> Result<(), ProfileError> {
        if block.len() != self.salt_block_len {
            return Err(ProfileError::FrameLengthMismatch);
        }
        self.fill_official(u32::MAX, block);
        salt::write(
            self.namespaces.salt,
            low_u8(self.mix_stride_handshake),
            low_u8_u32(self.mix_rounds_handshake),
            block,
            salt_bytes,
        )?;
        Ok(())
    }

    pub(crate) fn extract_salt(&self, block: &[u8]) -> Result<[u8; SALT_LEN], ProfileError> {
        if block.len() != self.salt_block_len {
            return Err(ProfileError::FrameLengthMismatch);
        }
        let mut salt_bytes = [0; SALT_LEN];
        salt::extract(
            self.namespaces.salt,
            low_u8(self.mix_stride_handshake),
            low_u8_u32(self.mix_rounds_handshake),
            block,
            &mut salt_bytes,
        )?;
        Ok(salt_bytes)
    }

    #[must_use]
    pub(crate) fn prf32(&self, label: u32, a: u32, b: u32) -> u32 {
        self.namespaces.prf32(label, a, b)
    }

    fn pick(&self, label: u32, a: u32, b: u32, lo: usize, hi: usize) -> usize {
        pick_usize(self.prf32(label, a, b), lo, hi)
    }

    #[must_use]
    #[cfg(test)]
    fn salt_mask(&self, i: usize) -> u8 {
        let raw = prf32_seq(
            self.namespaces.salt,
            MOTIF,
            u64::from(MIX_HANDSHAKE_DOMAIN),
            u32_from_usize(i),
        );
        low_u8(i).wrapping_mul(low_u8(self.mix_stride_handshake)) ^ low_u8_u32(raw)
    }
}

fn derive_namespace(secret: &[u8; 32], label: u32, seed_const: u64) -> u64 {
    let s0 = read_le_u64(secret, 0);
    let s1 = read_le_u64(secret, 8);
    let s2 = read_le_u64(secret, 16);
    let s3 = read_le_u64(secret, 24);
    let mixed = u64::from(label).wrapping_mul(DOMAIN_MUL)
        ^ seed_const.wrapping_add(NAMESPACE_SEED_ADD)
        ^ s0
        ^ s1.wrapping_add(GOLDEN_GAMMA)
        ^ s2.rotate_left(NAMESPACE_SECRET_WORD2_ROTATE)
        ^ s3.rotate_right(NAMESPACE_SECRET_WORD3_ROTATE);
    splitmix64(mixed)
}

fn read_le_u64(input: &[u8; 32], offset: usize) -> u64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&input[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
fn salt_positions(ns_salt: u64, salt_block_len: usize, rounds: u32) -> [usize; SALT_LEN] {
    debug_assert!(salt_block_len <= salt::MAX_SALT_BLOCK_LEN);
    let mut perm = [0u8; salt::MAX_SALT_BLOCK_LEN];
    salt::shuffle_perm(
        ns_salt,
        low_u8_u32(rounds),
        salt_block_len,
        &mut perm[..salt_block_len],
    );
    let mut positions = [0; SALT_LEN];
    for (dst, src) in positions.iter_mut().zip(perm.iter()) {
        *dst = usize::from(*src);
    }
    positions
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

fn u8_from_usize(value: usize) -> u8 {
    u8::try_from(value).expect("profile value fits u8")
}

fn u32_from_usize(value: usize) -> u32 {
    u32::try_from(value).expect("profile value fits u32")
}

fn usize_from_u32(value: u32) -> usize {
    usize::try_from(value).expect("u32 fits usize on supported targets")
}

fn isize_from_usize(value: usize) -> isize {
    isize::try_from(value).expect("profile value fits isize")
}

fn usize_from_isize(value: isize) -> usize {
    usize::try_from(value).expect("profile value is non-negative")
}

fn low_u8(value: usize) -> u8 {
    value.to_le_bytes()[0]
}

fn low_u8_u32(value: u32) -> u8 {
    value.to_le_bytes()[0]
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum ProfileError {
    #[error("salt block length mismatch")]
    FrameLengthMismatch,
    #[error("salt block failed: {0}")]
    Salt(#[from] salt::SaltError),
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PSK: &[u8] = b"test psk 16 byte";

    #[test]
    fn profile_derivation_matches_canonical_constants() {
        let profile = ShapedProfile::derive(TEST_PSK);
        assert_eq!(profile.namespaces.profile, 0xb69d_2dab_f942_0ee1);
        assert_eq!(profile.namespaces.prefix, 0x33bd_41e0_6ce7_0796);
        assert_eq!(profile.namespaces.motif, 0xddf9_dcc5_ba13_ef14);
        assert_eq!(profile.namespaces.salt, 0xd6fd_9bed_1f73_b346);
        assert_eq!(profile.namespaces.mix, 0x7dcb_b472_e7aa_fe76);
        assert_eq!(profile.namespaces.chunk, 0xa73f_99fe_f4cd_8034);
        assert_eq!(profile.namespaces.write, 0xfd25_4fd3_0efd_d16c);
        assert_eq!(profile.generator, 1);
        assert_eq!(profile.pad_min, 26);
        assert_eq!(profile.pad_max, 397);
        assert_eq!(profile.salt_block_len, 58);
        assert_eq!(profile.mix_stride_handshake, 163);
        assert_eq!(profile.prefix_min_record, 35);
        assert_eq!(profile.prefix_max_record, 128);
        assert_eq!(profile.mix_mode, 1);
        assert_eq!(profile.chunk_initial, 1270);
        assert_eq!(profile.first_record_cap, 402);
        assert_eq!(profile.chunk_max, 11_159);
        assert_eq!(profile.idle_reset(), Duration::from_secs(87));
        assert_eq!(
            profile.salt_positions,
            [15, 49, 39, 51, 36, 2, 17, 25, 9, 52, 54, 24, 6, 22, 19, 21]
        );
        assert_eq!(
            (0..SALT_LEN)
                .map(|i| profile.salt_mask(i))
                .collect::<Vec<_>>(),
            [
                190, 19, 36, 231, 76, 193, 214, 233, 63, 250, 166, 232, 7, 203, 0, 164
            ]
        );
    }

    #[test]
    fn official_v6b3_probe_chunk_profile_matches_binary_dump() {
        let profile = ShapedProfile::derive(b"0123456789abcdef");

        assert_eq!(profile.chunk_policy, 1);
        assert_eq!(profile.chunk_initial, 876);
        assert_eq!(profile.first_record_cap, 299);
        assert_eq!(profile.chunk_max, 14_987);
        assert_eq!(profile.chunk_step, 1_717);
        assert_eq!(profile.chunk_jitter, 138);
        assert_eq!(profile.idle_reset(), Duration::from_secs(38));
        assert_eq!(
            profile.chunk_buckets,
            [10_128, 12_375, 7_861, 12_739, 7_403, 7_901, 9_952, 11_290]
        );
    }

    #[test]
    fn runtime_prf_and_fill_match_canonical_constants() {
        let profile = ShapedProfile::derive(TEST_PSK);
        let mut fill = vec![0; 32];
        let mut salt_fill = vec![0; 32];

        profile.fill_official(7, &mut fill);
        profile.fill_official(u32::MAX, &mut salt_fill);

        assert_eq!(
            &fill[..],
            &[
                0x35, 0xf7, 0xa1, 0xb6, 0xcf, 0x60, 0xf3, 0xc4, 0xdf, 0x5a, 0xa0, 0x49, 0xe3, 0xd4,
                0xba, 0xd8, 0xb4, 0x4f, 0xc6, 0xe1, 0x4f, 0x25, 0x5f, 0xc0, 0xe3, 0x27, 0xef, 0x2d,
                0x89, 0xcf, 0x89, 0x71,
            ]
        );
        assert_eq!(
            &salt_fill[..],
            &[
                0xf8, 0x5a, 0x4c, 0xcd, 0x4e, 0x27, 0xdc, 0xd4, 0xf5, 0xca, 0x5c, 0xe6, 0x31, 0xc6,
                0xbf, 0xac, 0xf5, 0xc8, 0xc3, 0xf9, 0x62, 0xe4, 0x4d, 0x44, 0xbc, 0xd6, 0x54, 0xed,
                0x66, 0x40, 0x31, 0xdb,
            ]
        );
        assert_eq!(
            (0..8)
                .map(|seq| profile.record_prefix_len(seq))
                .collect::<Vec<_>>(),
            [97, 36, 54, 72, 121, 112, 77, 69]
        );
        assert_eq!(
            [
                profile.final_padding_len(0, profile.record_prefix_len(0), 0, true),
                profile.final_padding_len(0, profile.record_prefix_len(0), 18, true),
                profile.final_padding_len(1, profile.record_prefix_len(1), 120, false),
                profile.final_padding_len(7, profile.record_prefix_len(7), 1024, false),
            ],
            [503, 146, 1124, 126]
        );
        assert_eq!(
            [
                profile.chunk_limit(0, 0, None),
                profile.chunk_limit(1, profile.chunk_initial, None),
                profile.chunk_limit(2, 512, None),
            ],
            [1270, 1270, 512]
        );
        assert_eq!(
            profile.chunk_limit(2, 512, Some(profile.idle_reset() + Duration::from_secs(1))),
            profile.chunk_limit(2, profile.chunk_initial, None)
        );
        assert_eq!(profile.advance_chunk_size(0, None), profile.chunk_initial);
        assert_eq!(
            profile.advance_chunk_size(512, Some(profile.idle_reset() + Duration::from_secs(1))),
            profile.advance_chunk_size(profile.chunk_initial, None)
        );
    }

    #[test]
    fn salt_block_round_trips_salt() {
        let profile = ShapedProfile::derive(TEST_PSK);
        let salt = [0x5a; SALT_LEN];
        let mut block = vec![0; profile.salt_block_len()];

        profile.write_salt_block(&salt, &mut block).unwrap();
        let extracted = profile.extract_salt(&block).unwrap();

        assert_eq!(extracted, salt);
    }

    #[test]
    fn mixing_is_self_inverse() {
        let profile = ShapedProfile::derive(TEST_PSK);
        let mut padding = (0..128u8).collect::<Vec<_>>();
        let mut payload = (128..=255u8).collect::<Vec<_>>();
        let original_padding = padding.clone();
        let original_payload = payload.clone();

        mix_padding_payload(&profile, 3, &mut padding, &mut payload);
        mix_padding_payload(&profile, 3, &mut padding, &mut payload);

        assert_eq!(padding, original_padding);
        assert_eq!(payload, original_payload);
    }
}

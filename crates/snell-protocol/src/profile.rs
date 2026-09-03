//! v6 shaped profile: namespace PRF, salt block, prefix, padding, mix, chunk.

use crate::kdf::profile_secret;
use crate::prf::{GOLDEN_GAMMA, expand_stream, prf32, prf32_seq, splitmix64};
use crate::salt::{MIX_HANDSHAKE_DOMAIN, extract as salt_extract, write as salt_write};
use crate::{Error, HEADER_CIPHER_LEN, MAX_SALT_BLOCK_LEN, Result, SALT_LEN, TAG_LEN};

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
    fn derive(secret: &[u8; 32]) -> Self {
        Self {
            profile: derive_namespace(secret, PROFILE_ID, NS_SEED_PROFILE),
            prefix: derive_namespace(secret, PADDING, NS_SEED_PREFIX),
            motif: derive_namespace(secret, MOTIF, NS_SEED_MOTIF),
            salt: derive_namespace(secret, 3, NS_SEED_SALT),
            mix: derive_namespace(secret, MIX_MODE, NS_SEED_MIX),
            chunk: derive_namespace(secret, CHUNK_POLICY, NS_SEED_CHUNK),
            write: derive_namespace(secret, WRITE_POLICY, NS_SEED_WRITE),
        }
    }

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

    fn prf32(self, label: u32, a: u32, b: u32) -> u32 {
        prf32_seq(self.for_label(label), label, u64::from(a), b)
    }

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

/// Deterministic v6 shaped traffic profile derived from the PSK.
#[derive(Clone, Debug)]
pub struct Profile {
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
    idle_reset_secs: u64,
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
    mix_stride_handshake: usize,
    mix_rounds_handshake: u32,
}

impl Profile {
    pub fn derive(psk: &[u8]) -> Result<Self> {
        let secret = profile_secret(psk)?;
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
        let idle_reset_secs = pick_usize(namespaces.prf_static(IDLE_RESET, 0), 0x0c, 0x5a) as u64;
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

        Ok(Self {
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
            idle_reset_secs,
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
            mix_stride_handshake,
            mix_rounds_handshake,
        })
    }

    pub(crate) const fn salt_block_len(&self) -> usize {
        self.salt_block_len
    }

    pub(crate) const fn max_padding_len(&self) -> usize {
        self.pad_max + MAX_EXTRA_TARGET_PADDING
    }

    pub(crate) const fn idle_reset_secs(&self) -> u64 {
        self.idle_reset_secs
    }

    pub(crate) const fn first_record_cap(&self) -> usize {
        self.first_record_cap
    }

    pub(crate) const fn chunk_initial(&self) -> usize {
        self.chunk_initial
    }

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
    ) -> Result<()> {
        if block.len() != self.salt_block_len || block.len() > MAX_SALT_BLOCK_LEN {
            return Err(Error::Malformed("salt block length"));
        }
        self.fill_official(u32::MAX, block);
        salt_write(
            self.namespaces.salt,
            self.mix_stride_handshake as u8,
            self.mix_rounds_handshake as u8,
            block,
            salt_bytes,
        )
        .map_err(|()| Error::Malformed("salt block"))
    }

    pub(crate) fn extract_salt(&self, block: &[u8]) -> Result<[u8; SALT_LEN]> {
        if block.len() != self.salt_block_len {
            return Err(Error::Malformed("salt block length"));
        }
        let mut salt_bytes = [0; SALT_LEN];
        salt_extract(
            self.namespaces.salt,
            self.mix_stride_handshake as u8,
            self.mix_rounds_handshake as u8,
            block,
            &mut salt_bytes,
        )
        .map_err(|()| Error::Malformed("salt block"))?;
        Ok(salt_bytes)
    }

    pub(crate) fn fill_official(&self, seq: u32, out: &mut [u8]) {
        self.namespaces.expand_slice(PADDING, seq, out);
        match self.generator {
            1 => self.apply_generator_1(out),
            2 => self.apply_generator_2(out),
            3 => self.apply_generator_3(seq, out),
            _ => self.apply_generator_0(seq, out),
        }
    }

    pub(crate) fn final_padding_len(
        &self,
        seq: u32,
        prefix_len: usize,
        payload_len: usize,
        first_frame: bool,
    ) -> usize {
        let mut base_pad = 0;
        if seq < self.pad_count
            || (payload_len != 0 && payload_len <= self.small_limit)
            || (self.pad_interval != 0 && seq.is_multiple_of(self.pad_interval))
        {
            base_pad = self.pick(
                PAYLOAD_PADDING,
                seq,
                payload_len as u32,
                self.pad_min,
                self.pad_max,
            );
        }

        let mut current_len = prefix_len
            + HEADER_CIPHER_LEN
            + base_pad
            + if payload_len > 0 {
                payload_len + TAG_LEN
            } else {
                0
            };
        if first_frame {
            current_len += self.salt_block_len;
        }

        let target = self.write_target_len(seq, current_len);
        if current_len < target {
            base_pad += MAX_EXTRA_TARGET_PADDING.min(target - current_len);
        }
        base_pad
    }

    pub(crate) fn chunk_limit(&self, seq: u32, current_chunk_size: usize) -> usize {
        let mut cur = if current_chunk_size == 0 {
            self.chunk_initial
        } else {
            current_chunk_size
        };
        match self.chunk_policy {
            1 => {
                let idx =
                    self.prf32(CHUNK_SIZE, seq, cur as u32) as usize % self.chunk_buckets.len();
                cur = self.chunk_buckets[idx];
            }
            2 => {
                let span = 2 * self.chunk_jitter + 1;
                let raw = self.prf32(CHUNK_JITTER_VALUE, seq, cur as u32) as usize % span;
                let j = raw as i64 - self.chunk_jitter as i64;
                cur = (cur as i64 + j).max(0x40) as usize;
            }
            _ => {}
        }
        cur.clamp(0x40, self.chunk_max)
    }

    pub(crate) fn advance_chunk_size(&self, current_chunk_size: usize) -> usize {
        if current_chunk_size == 0 {
            return self.chunk_initial;
        }
        current_chunk_size
            .saturating_add(self.chunk_step)
            .min(self.chunk_max)
    }

    fn write_target_len(&self, seq: u32, current_len: usize) -> usize {
        if current_len > PROFILE_TARGET_DIRECT_LIMIT {
            return if current_len <= PROFILE_TARGET_U16_LIMIT {
                current_len
            } else {
                u32::MAX as usize
            };
        }

        let mut target = if seq < self.write_first {
            self.write_seq[seq as usize]
        } else {
            let idx = self.prf32(WRITE_TARGET, seq, current_len as u32) as usize
                % self.write_buckets.len();
            self.write_buckets[idx]
        };

        if self.write_policy == 2 {
            let span = 2 * self.write_jitter + 1;
            let raw = self.prf32(WRITE_JITTER_VALUE, seq, 0) as usize % span;
            let j = raw as i64 - self.write_jitter as i64;
            target = (target as i64 + j).max(1) as usize;
        }

        let jitter_bound =
            MAX_EXTRA_TARGET_PADDING.min(self.write_jitter_percent * current_len / 100);
        if self.prf32(WRITE_TARGET, seq, jitter_bound as u32) & 1 == 0 {
            target = target.saturating_add(jitter_bound);
        } else if target > jitter_bound / 2 {
            target -= jitter_bound / 2;
        }

        while current_len > target {
            let idx =
                self.prf32(WRITE_NEXT, seq, target as u32) as usize % self.write_buckets.len();
            let cand = self.write_buckets[idx];
            if target < cand {
                target = cand;
            } else {
                target = target.saturating_add(self.pad_max);
                if target > u16::MAX as usize {
                    return u32::MAX as usize;
                }
            }
        }

        target
    }

    fn prf32(&self, label: u32, a: u32, b: u32) -> u32 {
        self.namespaces.prf32(label, a, b)
    }

    fn pick(&self, label: u32, a: u32, b: u32, lo: usize, hi: usize) -> usize {
        pick_usize(self.prf32(label, a, b), lo, hi)
    }

    fn apply_generator_0(&self, seq: u32, out: &mut [u8]) {
        let percent = self.pick(
            BIT_PERCENT,
            seq,
            0,
            self.bit_min as usize,
            self.bit_max as usize,
        );
        let scaled = percent * 8;
        let target_bits = if scaled <= 49 {
            1u32
        } else if scaled > 749 {
            7
        } else {
            ((scaled + 50) / 100) as u32
        };
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = generator0_byte(*byte, i & 7, target_bits);
        }
    }

    fn apply_generator_1(&self, out: &mut [u8]) {
        let total = self.g1 + self.g2 + self.g3;
        if total == 0 {
            return;
        }
        for (i, byte) in out.iter_mut().enumerate() {
            let b = *byte;
            let r = usize::from(b) % total;
            *byte = if r < self.g1 {
                0x20 + b.wrapping_add(i as u8) % 0x5f
            } else if r < self.g1 + self.g2 {
                0x80 + ((b ^ (i as u8)) % 0x40)
            } else {
                0xc0 + b.wrapping_add((7 * i) as u8) % 0x40
            };
        }
    }

    fn apply_generator_2(&self, out: &mut [u8]) {
        for (i, byte) in out.iter_mut().enumerate() {
            let b = *byte;
            let hi = (((b >> 4).wrapping_add((i & 3) as u8).wrapping_add(3)) << 4) & 0xf0;
            let lo = ((usize::from(b & 0x0f) + self.g4 + (i & 1)) % 10) as u8;
            *byte = hi | lo;
        }
    }

    fn apply_generator_3(&self, seq: u32, out: &mut [u8]) {
        let motif = self.namespaces.expand_array::<32>(MOTIF, seq);
        let motif_len = (self.g5 * 4).min(motif.len()).max(1);
        let interval = self.g6.max(1);
        for (i, byte) in out.iter_mut().enumerate() {
            let b = *byte;
            let r = i % interval;
            *byte = if r + 3 < interval {
                (((self.g5 + 3) * i) as u8) ^ motif[i % motif_len]
            } else if r + 1 < interval {
                0x30 + b % 10
            } else {
                b
            };
        }
    }
}

pub(crate) fn mix_padding_payload(
    profile: &Profile,
    seq: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
) {
    let n = padding.len().min(payload_cipher.len());
    if n == 0 {
        return;
    }
    for round in 0..profile.mix_rounds {
        match profile.mix_mode {
            1 => mix_alternating_block(profile, round, padding, payload_cipher, n),
            2 => mix_prf_stride(profile, seq, round, padding, payload_cipher, n),
            _ => mix_fixed_stride(profile, round, padding, payload_cipher, n),
        }
    }
}

fn mix_fixed_stride(
    profile: &Profile,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
) {
    let stride = (profile.mix_stride + (round % 3) as usize).max(1);
    if stride == 1 {
        padding[..n].swap_with_slice(&mut payload_cipher[..n]);
        return;
    }
    let mut off = profile.mix_offset_base % stride;
    while off < n {
        core::mem::swap(&mut padding[off], &mut payload_cipher[off]);
        off += stride;
    }
}

fn mix_alternating_block(
    profile: &Profile,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
) {
    let block = profile.mix_block.max(1);
    let mut off = (round as usize & 1) * block;
    while off + block <= n {
        let end = off + block;
        padding[off..end].swap_with_slice(&mut payload_cipher[off..end]);
        off += block * 2;
    }
}

fn mix_prf_stride(
    profile: &Profile,
    seq: u32,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
) {
    let stride = (profile.mix_stride + (round % 3) as usize).max(1);
    let mut off =
        (profile.prf32(MIX_OFFSET, seq, round) as usize + profile.mix_offset_base) % stride;
    if stride == 1 {
        padding[..n].swap_with_slice(&mut payload_cipher[..n]);
        return;
    }
    while off < n {
        core::mem::swap(&mut padding[off], &mut payload_cipher[off]);
        off += stride;
    }
}

fn generator0_byte(orig: u8, index_mod: usize, target_bits: u32) -> u8 {
    let mut b = orig;
    let mut ones = b.count_ones();
    for k in 0..8 {
        if ones == target_bits {
            break;
        }
        let bit = (usize::from(orig) + index_mod + 3 * k) & 7;
        let mask = 1u8 << bit;
        if ones < target_bits {
            if b & mask == 0 {
                b |= mask;
                ones += 1;
            }
        } else if b & mask != 0 {
            b &= !mask;
            ones -= 1;
        }
    }
    b
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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PSK: &[u8] = b"test psk 16 byte";

    #[test]
    fn profile_derivation_matches_canonical_constants() {
        let profile = Profile::derive(TEST_PSK).unwrap();
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
        assert_eq!(profile.idle_reset_secs(), 87);
    }

    #[test]
    fn official_psk_chunk_profile() {
        let profile = Profile::derive(b"0123456789abcdef").unwrap();
        assert_eq!(profile.chunk_policy, 1);
        assert_eq!(profile.chunk_initial, 876);
        assert_eq!(profile.first_record_cap, 299);
        assert_eq!(profile.chunk_max, 14_987);
        assert_eq!(profile.chunk_step, 1_717);
        assert_eq!(profile.chunk_jitter, 138);
        assert_eq!(profile.idle_reset_secs(), 38);
        assert_eq!(
            profile.chunk_buckets,
            [10_128, 12_375, 7_861, 12_739, 7_403, 7_901, 9_952, 11_290]
        );
    }

    #[test]
    fn fill_and_prefix_match_canonical() {
        let profile = Profile::derive(TEST_PSK).unwrap();
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
                profile.chunk_limit(0, 0),
                profile.chunk_limit(1, profile.chunk_initial),
                profile.chunk_limit(2, 512),
            ],
            [1270, 1270, 512]
        );
        assert_eq!(profile.advance_chunk_size(0), profile.chunk_initial);
        assert_eq!(
            profile.advance_chunk_size(512),
            (512 + profile.chunk_step).min(profile.chunk_max)
        );
    }

    #[test]
    fn salt_block_round_trips_salt() {
        let profile = Profile::derive(TEST_PSK).unwrap();
        let salt = [0x5a; SALT_LEN];
        let mut block = vec![0; profile.salt_block_len()];
        profile.write_salt_block(&salt, &mut block).unwrap();
        assert_eq!(profile.extract_salt(&block).unwrap(), salt);
    }

    #[test]
    fn mixing_is_self_inverse() {
        let profile = Profile::derive(TEST_PSK).unwrap();
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

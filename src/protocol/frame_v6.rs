use std::collections::{HashSet, VecDeque};
use std::ops::Range;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use blake2::digest::{KeyInit, Mac, consts::U32};
use blake2::{Blake2b, Blake2bMac, Digest};
use bytes::BytesMut;

use crate::MAX_PACKET_SIZE;
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
const V6_MTU_CAP: usize = 0x05b4;
const V6_MTU_OVERHEAD_LIMIT: usize = 0x0553;
const V6_STEADY_OVERHEAD: usize = V6_HEADER_CIPHER_SIZE + V6_PAYLOAD_TAG_SIZE;

#[derive(Clone, Debug)]
pub struct V6SaltReplayCache {
    inner: Arc<Mutex<V6SaltReplayCacheInner>>,
}

#[derive(Debug)]
struct V6SaltReplayCacheInner {
    capacity: usize,
    salts: HashSet<[u8; SALT_SIZE]>,
    order: VecDeque<[u8; SALT_SIZE]>,
}

impl V6SaltReplayCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(V6SaltReplayCacheInner {
                capacity: capacity.max(1),
                salts: HashSet::new(),
                order: VecDeque::new(),
            })),
        }
    }

    pub fn remember(&self, salt: [u8; SALT_SIZE]) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if inner.salts.contains(&salt) {
            return Err(Error::SaltReplay);
        }

        if inner.salts.len() == inner.capacity
            && let Some(oldest) = inner.order.pop_front()
        {
            inner.salts.remove(&oldest);
        }
        inner.salts.insert(salt);
        inner.order.push_back(salt);
        Ok(())
    }
}

impl Default for V6SaltReplayCache {
    fn default() -> Self {
        Self::new(V6_SALT_REPLAY_CACHE_CAPACITY)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct V6DecodedHeader {
    pub padding_len: usize,
    pub payload_len: usize,
}

impl V6DecodedHeader {
    pub fn body_len(self) -> Result<usize> {
        if self.padding_len > MAX_PACKET_SIZE || self.payload_len > MAX_PACKET_SIZE {
            return Err(Error::PayloadTooLarge);
        }
        Ok(self.padding_len
            + if self.payload_len > 0 {
                self.payload_len + AEAD_TAG_SIZE
            } else {
                0
            })
    }
}

#[derive(Clone, Debug)]
pub struct V6Profile {
    profile_secret: [u8; 32],
    pub profile_id: u32,
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
    salt_positions: [usize; SALT_SIZE],
    mix_stride_handshake: usize,
}

impl V6Profile {
    pub fn derive(psk: &[u8]) -> Self {
        let mut input = Vec::with_capacity(V6_SHAPE_LABEL.len() + psk.len());
        input.extend_from_slice(V6_SHAPE_LABEL);
        input.extend_from_slice(psk);
        let profile_secret = blake2b_256(&input);

        let profile_id = prf32_with_secret(&profile_secret, "profile-id", 0, 0);
        let generator = prf32_with_secret(&profile_secret, "generator", 0, 0) & 3;
        let pad_min = pick_usize(
            prf32_with_secret(&profile_secret, "pad-min", 0, 0),
            0x18,
            0xa0,
        );
        let pad_max = (pad_min
            + pick_usize(
                prf32_with_secret(&profile_secret, "pad-max", 0, 0),
                0xa0,
                0x3c0,
            ))
        .min(MAX_EXTRA_TARGET_PADDING);
        let pad_count = pick_u32(prf32_with_secret(&profile_secret, "pad-count", 0, 0), 2, 8);
        let pad_interval = pick_u32(
            prf32_with_secret(&profile_secret, "pad-interval", 0, 0),
            2,
            0x0b,
        );
        let small_limit = pick_usize(
            prf32_with_secret(&profile_secret, "small-limit", 0, 0),
            0x60,
            0x300,
        );
        let bit_min = pick_u32(
            prf32_with_secret(&profile_secret, "bit-min", 0, 0),
            0x18,
            0x29,
        );
        let bit_max = pick_u32(
            prf32_with_secret(&profile_secret, "bit-max", 0, 0),
            0x3a,
            0x4c,
        );

        let prefix_min_handshake = pick_usize(
            prf32_with_secret(&profile_secret, "prefix-min", 0, HANDSHAKE_DOMAIN),
            0x10,
            0x60,
        );
        let mut prefix_max_handshake = prefix_min_handshake
            + pick_usize(
                prf32_with_secret(&profile_secret, "prefix-max", 0, HANDSHAKE_DOMAIN),
                0x10,
                0xa0,
            );
        prefix_max_handshake = prefix_max_handshake.min(0x80);
        let prefix_min_handshake = prefix_min_handshake.min(prefix_max_handshake);
        let salt_prefix_len = pick_usize(
            prf32_with_secret(&profile_secret, "header-prefix", 0, HANDSHAKE_DOMAIN),
            prefix_min_handshake,
            prefix_max_handshake,
        );
        let salt_block_len = SALT_SIZE + salt_prefix_len;
        let mix_rounds_handshake = pick_u32(
            prf32_with_secret(&profile_secret, "mix-rounds", 0, MIX_HANDSHAKE_DOMAIN),
            1,
            4,
        );
        let mix_stride_handshake = pick_usize(
            prf32_with_secret(&profile_secret, "mix-stride", 0, MIX_HANDSHAKE_DOMAIN),
            0x11,
            0xfb,
        );
        let salt_positions = salt_positions(&profile_secret, salt_block_len, mix_rounds_handshake);

        let prefix_min_record = pick_usize(
            prf32_with_secret(&profile_secret, "prefix-min", 0, 0),
            0x08,
            0x50,
        );
        let mut prefix_max_record = prefix_min_record
            + pick_usize(
                prf32_with_secret(&profile_secret, "prefix-max", 0, 0),
                0x10,
                0xa0,
            );
        prefix_max_record = prefix_max_record.min(0x80);
        let prefix_min_record = prefix_min_record.min(prefix_max_record);

        let mix_mode = prf32_with_secret(&profile_secret, "mix-mode", 0, 0) % 3;
        let mix_rounds = pick_u32(prf32_with_secret(&profile_secret, "mix-rounds", 0, 0), 1, 3);
        let mix_stride = pick_usize(
            prf32_with_secret(&profile_secret, "mix-stride", 0, 0),
            2,
            13,
        );
        let mix_offset_base = pick_usize(
            prf32_with_secret(&profile_secret, "mix-offset-base", 0, 0),
            0,
            15,
        );
        let mix_block = pick_usize(
            prf32_with_secret(&profile_secret, "mix-block", 0, 0),
            8,
            0x40,
        );

        let chunk_policy = prf32_with_secret(&profile_secret, "chunk-policy", 0, 0) % 3;
        let chunk_initial = clamp_usize(
            pick_usize(
                prf32_with_secret(&profile_secret, "chunk-initial", 0, 0),
                0xa0,
                0x3c0,
            ),
            0x60,
            0x5b4,
        );
        let chunk_max = clamp_usize(
            pick_usize(
                prf32_with_secret(&profile_secret, "chunk-max", 0, 0),
                0x0800,
                0x3fff,
            ),
            0x60,
            0x5b4,
        );
        let chunk_step = clamp_usize(
            pick_usize(
                prf32_with_secret(&profile_secret, "chunk-step", 0, 0),
                0x60,
                0x500,
            ),
            0x60,
            0x5b4,
        );
        let chunk_jitter = pick_usize(
            prf32_with_secret(&profile_secret, "chunk-jitter", 0, 0),
            0x10,
            0xc0,
        );
        let idle_reset = Duration::from_secs(pick_usize(
            prf32_with_secret(&profile_secret, "idle-reset", 0, 0),
            0x0c,
            0x5a,
        ) as u64);
        let write_policy = prf32_with_secret(&profile_secret, "write-policy", 0, 0) % 3;
        let write_first = pick_u32(
            prf32_with_secret(&profile_secret, "write-first", 0, 0),
            4,
            8,
        );

        let mut chunk_buckets = [0; 8];
        let mut write_buckets = [0; 8];
        let mut write_seq = [0; 8];
        for i in 0..8 {
            chunk_buckets[i] = clamp_usize(
                pick_usize(
                    prf32_with_secret(&profile_secret, "chunk-bucket", 0, i as u32),
                    0x140,
                    0x5b4,
                ),
                0x60,
                0x5b4,
            );
            write_buckets[i] = clamp_usize(
                pick_usize(
                    prf32_with_secret(&profile_secret, "write-bucket", 0, i as u32),
                    0x140,
                    0x5b4,
                ),
                0x60,
                0x5b4,
            );
            write_seq[i] = clamp_usize(
                pick_usize(
                    prf32_with_secret(&profile_secret, "write-seq", 0, i as u32),
                    0x168,
                    0x5b4,
                ),
                0x60,
                0x5b4,
            );
        }

        let write_jitter = pick_usize(
            prf32_with_secret(&profile_secret, "write-jitter", 0, 0),
            0x08,
            0x60,
        );
        let write_jitter_percent = pick_usize(
            prf32_with_secret(&profile_secret, "write-policy", 0, 0x504c),
            8,
            0x30,
        );

        let g1 = pick_usize(
            prf32_with_secret(&profile_secret, "generator", 0, 1),
            0x18,
            0x80,
        );
        let g2 = pick_usize(
            prf32_with_secret(&profile_secret, "generator", 0, 2),
            0x10,
            0x60,
        );
        let g3 = pick_usize(
            prf32_with_secret(&profile_secret, "generator", 0, 3),
            0x10,
            0x60,
        );
        let g4 = pick_usize(
            prf32_with_secret(&profile_secret, "generator", 0, 4),
            0x00,
            0x09,
        );
        let g5 = pick_usize(
            prf32_with_secret(&profile_secret, "generator", 0, 5),
            0x01,
            0x08,
        );
        let g6 = pick_usize(
            prf32_with_secret(&profile_secret, "generator", 0, 6),
            0x07,
            0x17,
        );

        Self {
            profile_secret,
            profile_id,
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
            salt_positions,
            mix_stride_handshake,
        }
    }

    pub const fn salt_block_len(&self) -> usize {
        self.salt_block_len
    }

    pub fn record_prefix_len(&self, seq: u32) -> usize {
        self.pick(
            "header-prefix",
            seq,
            0,
            self.prefix_min_record,
            self.prefix_max_record,
        )
    }

    fn append_salt_block(&self, salt: &[u8; SALT_SIZE], out: &mut BytesMut) -> Range<usize> {
        let block = self.append_official_fill(u32::MAX, self.salt_block_len, out);
        for (i, salt_byte) in salt.iter().enumerate() {
            out[block.start + self.salt_positions[i]] = *salt_byte ^ self.salt_mask(i);
        }
        block
    }

    pub fn extract_salt(&self, block: &[u8]) -> Result<[u8; SALT_SIZE]> {
        if block.len() != self.salt_block_len {
            return Err(Error::FrameLengthMismatch);
        }
        let mut salt = [0; SALT_SIZE];
        for (i, salt_byte) in salt.iter_mut().enumerate() {
            *salt_byte = block[self.salt_positions[i]] ^ self.salt_mask(i);
        }
        Ok(salt)
    }

    fn append_official_fill(&self, seq: u32, len: usize, out: &mut BytesMut) -> Range<usize> {
        let start = out.len();
        self.expand_into("padding", seq, len, out);
        let end = out.len();
        let fill = &mut out[start..end];
        match self.generator {
            0 => self.apply_generator_0(seq, fill),
            1 => self.apply_generator_1(fill),
            2 => self.apply_generator_2(fill),
            3 => self.apply_generator_3(seq, fill),
            _ => unreachable!("generator is masked to 0..=3"),
        }
        start..end
    }

    pub fn final_padding_len(&self, seq: u32, payload_len: usize, first_frame: bool) -> usize {
        let prefix_len = self.record_prefix_len(seq);
        let mut base_pad = 0;
        if seq < self.pad_count
            || (payload_len != 0 && payload_len <= self.small_limit)
            || seq.is_multiple_of(self.pad_interval)
        {
            base_pad = self.pick(
                "payload-padding",
                seq,
                payload_len as u32,
                self.pad_min,
                self.pad_max,
            );
        }

        let mut current_len = prefix_len
            + V6_HEADER_CIPHER_SIZE
            + base_pad
            + if payload_len > 0 {
                payload_len + AEAD_TAG_SIZE
            } else {
                0
            };
        if first_frame {
            current_len += self.salt_block_len;
        }

        let mut target = if seq < self.write_first {
            self.write_seq[seq as usize]
        } else {
            self.write_buckets[(self.prf32("write-target", seq, current_len as u32) as usize) % 8]
        };

        if self.write_policy == 2 {
            let span = 2 * self.write_jitter + 1;
            let j = (self.prf32("write-jitter-value", seq, 0) as usize % span) as isize
                - self.write_jitter as isize;
            target = (target as isize + j).max(1) as usize;
        }

        let jitter_bound =
            MAX_EXTRA_TARGET_PADDING.min(self.write_jitter_percent * current_len / 100);
        if self.prf32("write-target", seq, jitter_bound as u32) & 1 == 0 {
            target = target.saturating_add(jitter_bound);
        } else if target > jitter_bound / 2 {
            target -= jitter_bound / 2;
        }

        while current_len > target {
            let cand =
                self.write_buckets[(self.prf32("write-next", seq, target as u32) as usize) % 8];
            if target < cand {
                target = cand;
            } else {
                target = target.saturating_add(self.pad_max);
            }
        }

        let extra_pad = MAX_EXTRA_TARGET_PADDING.min(target.saturating_sub(current_len));
        base_pad + extra_pad
    }

    pub fn chunk_limit(&self, seq: u32, current_chunk_size: usize) -> usize {
        let mut cur = if current_chunk_size != 0 {
            current_chunk_size
        } else {
            self.chunk_initial
        };
        match self.chunk_policy {
            1 => {
                cur = self.chunk_buckets[(self.prf32("chunk-size", seq, cur as u32) as usize) % 8];
            }
            2 => {
                let span = 2 * self.chunk_jitter + 1;
                let j = (self.prf32("chunk-jitter-value", seq, cur as u32) as usize % span)
                    as isize
                    - self.chunk_jitter as isize;
                cur = (cur as isize + j).max(0x40) as usize;
            }
            _ => {}
        }

        let worst_overhead = self.pad_max + self.prefix_max_record + V6_STEADY_OVERHEAD;
        if cur + worst_overhead > V6_MTU_CAP && worst_overhead <= V6_MTU_OVERHEAD_LIMIT {
            cur = V6_MTU_CAP - worst_overhead;
        }
        cur.clamp(0x40, self.chunk_max)
    }

    fn next_chunk_size(&self, current_chunk_size: usize) -> usize {
        if current_chunk_size == 0 {
            self.chunk_initial
        } else if self.chunk_policy == 0 {
            (current_chunk_size + self.chunk_step).min(self.chunk_max)
        } else {
            current_chunk_size
        }
    }

    fn prf32(&self, label: &str, a: u32, b: u32) -> u32 {
        prf32_with_secret(&self.profile_secret, label, a, b)
    }

    fn pick(&self, label: &str, a: u32, b: u32, lo: usize, hi: usize) -> usize {
        pick_usize(self.prf32(label, a, b), lo, hi)
    }

    fn expand_into(&self, label: &str, seq: u32, len: usize, out: &mut BytesMut) {
        out.reserve(len);
        let target_len = out.len() + len;
        let mut counter = 0u32;
        while out.len() < target_len {
            let digest = self.expand_block(label, seq, counter, len);
            let remaining = target_len - out.len();
            out.extend_from_slice(&digest[..remaining.min(digest.len())]);
            counter = counter.wrapping_add(1);
        }
    }

    fn expand_block(&self, label: &str, seq: u32, counter: u32, len: usize) -> [u8; 32] {
        let seq = seq.to_be_bytes();
        let counter = counter.to_be_bytes();
        let len = (len as u32).to_be_bytes();
        let parts: [&[u8]; 4] = [label.as_bytes(), &seq, &counter, &len];
        blake2b_256_keyed_parts(&self.profile_secret, &parts)
    }

    fn apply_generator_0(&self, seq: u32, out: &mut [u8]) {
        let percent = self.pick(
            "bit-percent",
            seq,
            0,
            self.bit_min as usize,
            self.bit_max as usize,
        );
        let scaled = percent * 8;
        let target_bits = if scaled <= 49 {
            1
        } else if scaled > 749 {
            7
        } else {
            (scaled + 50) / 100
        } as u32;

        for (i, byte) in out.iter_mut().enumerate() {
            let orig = *byte;
            let mut b = *byte;
            for k in 0..8 {
                if b.count_ones() == target_bits {
                    break;
                }
                let bit = (usize::from(orig) + i + 3 * k) & 7;
                if b.count_ones() < target_bits {
                    b |= 1 << bit;
                } else {
                    b &= !(1 << bit);
                }
            }
            *byte = b;
        }
    }

    fn apply_generator_1(&self, out: &mut [u8]) {
        let total = self.g1 + self.g2 + self.g3;
        for (i, byte) in out.iter_mut().enumerate() {
            let b = *byte;
            let r = usize::from(b) % total;
            *byte = if r < self.g1 {
                0x20 + b.wrapping_add(i as u8) % 0x5f
            } else if r < self.g1 + self.g2 {
                0x80 + ((b ^ i as u8) % 0x40)
            } else {
                0xc0 + b.wrapping_add((7 * i) as u8) % 0x40
            };
        }
    }

    fn apply_generator_2(&self, out: &mut [u8]) {
        for (i, byte) in out.iter_mut().enumerate() {
            let b = *byte;
            let hi = (((b >> 4).wrapping_add((i & 3) as u8).wrapping_add(3)) << 4) & 0xf0;
            let lo = ((b & 0x0f) as usize + self.g4 + (i & 1)) % 10;
            *byte = hi | lo as u8;
        }
    }

    fn apply_generator_3(&self, seq: u32, out: &mut [u8]) {
        let motif = self.expand_block("padding-motif", seq, 0, 32);
        let motif_len = self.g5 * 4;
        let interval = self.g6;
        for (i, byte) in out.iter_mut().enumerate() {
            let b = *byte;
            let r = i % interval;
            *byte = if r < interval - 3 {
                ((self.g5 + 3) * i) as u8 ^ motif[i % motif_len]
            } else if r < interval - 1 {
                0x30 + b % 10
            } else {
                b
            };
        }
    }

    fn salt_mask(&self, i: usize) -> u8 {
        ((i * self.mix_stride_handshake) as u32
            ^ self.prf32("padding-motif", MIX_HANDSHAKE_DOMAIN, i as u32)) as u8
    }
}

pub struct V6FrameEncoder {
    profile: V6Profile,
    crypto: Aes128GcmCrypto,
    nonce: Nonce12,
    salt: [u8; SALT_SIZE],
    salt_sent: bool,
    seq: u32,
}

impl V6FrameEncoder {
    pub fn new(psk: &[u8]) -> Result<Self> {
        let mut salt = [0; SALT_SIZE];
        fill_random(&mut salt)?;
        Self::with_salt(psk, salt)
    }

    #[doc(hidden)]
    pub fn with_salt(psk: &[u8], salt: [u8; SALT_SIZE]) -> Result<Self> {
        let profile = V6Profile::derive(psk);
        let crypto = Aes128GcmCrypto::from_psk_and_salt(psk, &salt)?;
        Ok(Self {
            profile,
            crypto,
            nonce: Nonce12::new(),
            salt,
            salt_sent: false,
            seq: 0,
        })
    }

    pub const fn salt(&self) -> &[u8; SALT_SIZE] {
        &self.salt
    }

    pub const fn profile(&self) -> &V6Profile {
        &self.profile
    }

    pub const fn seq(&self) -> u32 {
        self.seq
    }

    pub fn encode_empty_frame(&mut self, head: &mut BytesMut) -> Result<usize> {
        self.encode_payload_in_place(&mut BytesMut::new(), 0, head)
    }

    pub fn encode_payload_in_place(
        &mut self,
        payload: &mut BytesMut,
        payload_len: usize,
        head: &mut BytesMut,
    ) -> Result<usize> {
        if payload_len > MAX_PACKET_SIZE {
            return Err(Error::PayloadTooLarge);
        }
        if payload.len() != payload_len {
            return Err(Error::FrameLengthMismatch);
        }

        let start_len = head.len();
        let first_frame = !self.salt_sent;
        let prefix_len = self.profile.record_prefix_len(self.seq);
        let padding_len = self
            .profile
            .final_padding_len(self.seq, payload_len, first_frame);
        if padding_len > u16::MAX as usize || payload_len > u16::MAX as usize {
            return Err(Error::PayloadTooLarge);
        }

        head.reserve(
            usize::from(first_frame) * self.profile.salt_block_len()
                + prefix_len
                + V6_HEADER_CIPHER_SIZE
                + padding_len,
        );
        if first_frame {
            self.profile.append_salt_block(&self.salt, head);
            self.salt_sent = true;
        }

        let prefix = self
            .profile
            .append_official_fill(self.seq, prefix_len, head);

        let mut header = [0u8; V6_HEADER_PLAIN_SIZE];
        header[0] = 4;
        header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
        header[5..7].copy_from_slice(&(payload_len as u16).to_be_bytes());
        let header_tag = self.crypto.encrypt_detached_with_aad(
            self.nonce.as_bytes(),
            &mut header,
            &head[prefix],
        )?;
        self.nonce.increment();
        head.extend_from_slice(&header);
        head.extend_from_slice(&header_tag);

        let padding = self
            .profile
            .append_official_fill(self.seq, padding_len, head);
        let padding = &mut head[padding];

        if payload_len > 0 {
            let payload_tag = self.crypto.encrypt_detached_with_aad(
                self.nonce.as_bytes(),
                &mut payload[..payload_len],
                padding,
            )?;
            self.nonce.increment();
            payload.extend_from_slice(&payload_tag);
            mix_padding_payload(&self.profile, self.seq, padding, payload);
        }

        self.seq = self.seq.wrapping_add(1);
        Ok(head.len() - start_len + payload.len())
    }
}

pub struct V6FrameDecoder {
    profile: V6Profile,
    crypto: Aes128GcmCrypto,
    nonce: Nonce12,
    seq: u32,
}

impl V6FrameDecoder {
    pub fn new(psk: &[u8], salt: [u8; SALT_SIZE]) -> Result<Self> {
        let profile = V6Profile::derive(psk);
        Ok(Self {
            profile,
            crypto: Aes128GcmCrypto::from_psk_and_salt(psk, &salt)?,
            nonce: Nonce12::new(),
            seq: 0,
        })
    }

    pub const fn profile(&self) -> &V6Profile {
        &self.profile
    }

    pub const fn seq(&self) -> u32 {
        self.seq
    }

    pub fn next_prefix_len(&self) -> usize {
        self.profile.record_prefix_len(self.seq)
    }

    pub fn decode_header(
        &mut self,
        prefix: &[u8],
        header_cipher: &mut [u8; V6_HEADER_CIPHER_SIZE],
    ) -> Result<V6DecodedHeader> {
        let decrypt_result =
            self.crypto
                .decrypt_within_with_aad(self.nonce.as_bytes(), header_cipher, 0.., prefix);
        self.nonce.increment();
        let header = decrypt_result?;

        if header[0] != 4 || header[1] != 0 || header[2] != 0 {
            return Err(Error::InvalidV4Header);
        }

        let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
        if padding_len > MAX_PACKET_SIZE || payload_len > MAX_PACKET_SIZE {
            return Err(Error::PayloadTooLarge);
        }
        Ok(V6DecodedHeader {
            padding_len,
            payload_len,
        })
    }

    pub fn decode_payload_in_place<'a>(
        &mut self,
        header: V6DecodedHeader,
        body: &'a mut [u8],
    ) -> Result<&'a mut [u8]> {
        let expected_body_len = header.body_len()?;
        if body.len() != expected_body_len {
            return Err(Error::FrameLengthMismatch);
        }

        if header.payload_len == 0 {
            self.seq = self.seq.wrapping_add(1);
            return Err(Error::ZeroChunk);
        }

        let (padding, payload_cipher_and_tag) = body.split_at_mut(header.padding_len);
        mix_padding_payload(&self.profile, self.seq, padding, payload_cipher_and_tag);
        let decrypt_result = self.crypto.decrypt_within_with_aad(
            self.nonce.as_bytes(),
            payload_cipher_and_tag,
            0..,
            padding,
        );
        self.nonce.increment();
        let payload = decrypt_result?;
        self.seq = self.seq.wrapping_add(1);

        Ok(payload)
    }
}

#[derive(Clone, Debug)]
pub struct V6ChunkSizer {
    profile: V6Profile,
    current_chunk_size: usize,
    last_record_at: Option<Instant>,
}

impl V6ChunkSizer {
    pub fn new(profile: V6Profile) -> Self {
        Self {
            profile,
            current_chunk_size: 0,
            last_record_at: None,
        }
    }

    pub fn peek_limit(&self, seq: u32, now: Instant) -> usize {
        let current = if self
            .last_record_at
            .is_some_and(|last| now.duration_since(last) > self.profile.idle_reset)
        {
            self.profile.chunk_initial
        } else {
            self.current_chunk_size
        };
        self.profile.chunk_limit(seq, current)
    }

    pub fn commit_record(&mut self, now: Instant) {
        if self
            .last_record_at
            .is_some_and(|last| now.duration_since(last) > self.profile.idle_reset)
        {
            self.current_chunk_size = self.profile.chunk_initial;
        }
        self.current_chunk_size = self.profile.next_chunk_size(self.current_chunk_size);
        self.last_record_at = Some(now);
    }
}

#[doc(hidden)]
pub fn split_salt_block<'a>(
    profile: &V6Profile,
    frame: &'a [u8],
) -> Result<([u8; SALT_SIZE], &'a [u8])> {
    let salt_block_len = profile.salt_block_len();
    if frame.len() < salt_block_len {
        return Err(Error::FrameTooShort);
    }
    let salt = profile.extract_salt(&frame[..salt_block_len])?;
    Ok((salt, &frame[salt_block_len..]))
}

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

fn salt_positions(
    profile_secret: &[u8; 32],
    salt_block_len: usize,
    mix_rounds_handshake: u32,
) -> [usize; SALT_SIZE] {
    let mut arr = (0..salt_block_len).collect::<Vec<_>>();
    for round in 0..mix_rounds_handshake {
        for i in 0..salt_block_len {
            let raw = prf32_with_secret(
                profile_secret,
                "mix-offset",
                MIX_HANDSHAKE_DOMAIN + round,
                i as u32,
            );
            let j = i + raw as usize % (salt_block_len - i);
            arr.swap(i, j);
        }
    }
    let mut positions = [0; SALT_SIZE];
    positions.copy_from_slice(&arr[..SALT_SIZE]);
    positions
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

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::{
        V6_HEADER_CIPHER_SIZE, V6FrameDecoder, V6FrameEncoder, V6Profile, V6SaltReplayCache,
        mix_padding_payload, split_salt_block,
    };
    use crate::error::Error;

    fn encode_test_frame(
        encoder: &mut V6FrameEncoder,
        payload: &[u8],
        wire: &mut BytesMut,
    ) -> usize {
        let start_len = wire.len();
        let mut head = BytesMut::new();
        let mut body = BytesMut::from(payload);
        encoder
            .encode_payload_in_place(&mut body, payload.len(), &mut head)
            .unwrap();
        wire.extend_from_slice(&head);
        wire.extend_from_slice(&body);
        wire.len() - start_len
    }

    #[test]
    fn derives_stable_profile_from_psk() {
        let first = V6Profile::derive(b"test psk");
        let second = V6Profile::derive(b"test psk");
        let other = V6Profile::derive(b"other psk");

        assert_eq!(first.profile_id, second.profile_id);
        assert_ne!(first.profile_id, other.profile_id);
        assert!(first.salt_block_len() >= 32);
        assert!(first.record_prefix_len(0) >= 8);
    }

    #[test]
    fn salt_block_round_trips_salt() {
        let profile = V6Profile::derive(b"test psk");
        let salt = [0x5a; 16];
        let mut block = BytesMut::new();

        let block_range = profile.append_salt_block(&salt, &mut block);
        let extracted = profile.extract_salt(&block).unwrap();

        assert_eq!(block_range, 0..profile.salt_block_len());
        assert_eq!(extracted, salt);
    }

    #[test]
    fn official_fill_is_stable_and_profile_specific() {
        let first_profile = V6Profile::derive(b"test psk");
        let second_profile = V6Profile::derive(b"test psk");
        let other_profile = V6Profile::derive(b"other psk");
        let mut first = BytesMut::new();
        let mut second = BytesMut::new();
        let mut other = BytesMut::new();

        first_profile.append_official_fill(7, 96, &mut first);
        second_profile.append_official_fill(7, 96, &mut second);
        other_profile.append_official_fill(7, 96, &mut other);

        assert_eq!(first, second);
        assert_ne!(first, other);
    }

    #[test]
    fn mixing_is_self_inverse() {
        for psk in [
            b"mix-mode-a" as &[u8],
            b"mix-mode-b",
            b"mix-mode-c",
            b"mix-mode-d",
        ] {
            let profile = V6Profile::derive(psk);
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

    #[test]
    fn encodes_and_decodes_payload_frame() {
        let psk = b"test psk";
        let salt = [3u8; 16];
        let payload = b"GET / HTTP/1.1\r\n\r\n";
        let mut encoder = V6FrameEncoder::with_salt(psk, salt).unwrap();
        let mut wire = BytesMut::with_capacity(512);

        let written = encode_test_frame(&mut encoder, payload, &mut wire);
        assert_eq!(written, wire.len());

        let profile = V6Profile::derive(psk);
        let (decoded_salt, frame) = split_salt_block(&profile, &wire).unwrap();
        assert_eq!(decoded_salt, salt);

        let mut frame = BytesMut::from(frame);
        let mut decoder = V6FrameDecoder::new(psk, decoded_salt).unwrap();
        let prefix_len = decoder.next_prefix_len();
        let prefix = frame.split_to(prefix_len);
        let mut header_cipher = [0; V6_HEADER_CIPHER_SIZE];
        header_cipher.copy_from_slice(&frame[..V6_HEADER_CIPHER_SIZE]);
        let header = decoder.decode_header(&prefix, &mut header_cipher).unwrap();
        let mut body = frame.split_off(V6_HEADER_CIPHER_SIZE);
        let decoded = decoder.decode_payload_in_place(header, &mut body).unwrap();

        assert_eq!(decoded, payload);
        assert_eq!(encoder.seq(), 1);
        assert_eq!(decoder.seq(), 1);
    }

    #[test]
    fn rejects_header_when_prefix_aad_changes() {
        let psk = b"test psk";
        let salt = [9u8; 16];
        let mut encoder = V6FrameEncoder::with_salt(psk, salt).unwrap();
        let mut wire = BytesMut::new();

        encode_test_frame(&mut encoder, b"hello", &mut wire);
        let profile = V6Profile::derive(psk);
        let (decoded_salt, frame) = split_salt_block(&profile, &wire).unwrap();
        let mut frame = BytesMut::from(frame);
        let mut decoder = V6FrameDecoder::new(psk, decoded_salt).unwrap();
        let prefix_len = decoder.next_prefix_len();
        let mut prefix = frame.split_to(prefix_len);
        prefix[0] ^= 0xff;
        let mut header_cipher = [0; V6_HEADER_CIPHER_SIZE];
        header_cipher.copy_from_slice(&frame[..V6_HEADER_CIPHER_SIZE]);

        assert!(matches!(
            decoder.decode_header(&prefix, &mut header_cipher),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn decodes_zero_payload_as_zero_chunk_even_with_padding() {
        let psk = b"test psk";
        let salt = [2u8; 16];
        let mut encoder = V6FrameEncoder::with_salt(psk, salt).unwrap();
        let mut wire = BytesMut::new();

        encode_test_frame(&mut encoder, b"", &mut wire);
        let profile = V6Profile::derive(psk);
        let (decoded_salt, frame) = split_salt_block(&profile, &wire).unwrap();
        let mut frame = BytesMut::from(frame);
        let mut decoder = V6FrameDecoder::new(psk, decoded_salt).unwrap();
        let prefix_len = decoder.next_prefix_len();
        let prefix = frame.split_to(prefix_len);
        let mut header_cipher = [0; V6_HEADER_CIPHER_SIZE];
        header_cipher.copy_from_slice(&frame[..V6_HEADER_CIPHER_SIZE]);
        let header = decoder.decode_header(&prefix, &mut header_cipher).unwrap();
        let mut body = frame.split_off(V6_HEADER_CIPHER_SIZE);

        assert!(header.padding_len > 0);
        assert!(matches!(
            decoder.decode_payload_in_place(header, &mut body),
            Err(Error::ZeroChunk)
        ));
    }

    #[test]
    fn salt_replay_cache_rejects_recent_reuse_and_evicts_oldest() {
        let cache = V6SaltReplayCache::new(2);
        let first = [1u8; 16];
        let second = [2u8; 16];
        let third = [3u8; 16];

        cache.remember(first).unwrap();
        assert!(matches!(cache.remember(first), Err(Error::SaltReplay)));

        cache.remember(second).unwrap();
        cache.remember(third).unwrap();
        cache.remember(first).unwrap();
    }
}

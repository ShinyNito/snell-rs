use std::sync::LazyLock;

use super::*;

static GENERATOR0_BYTE_TABLE: LazyLock<[[[u8; 256]; 8]; 8]> =
    LazyLock::new(build_generator0_byte_table);

#[derive(Clone, Copy, Debug)]
struct V6Namespaces {
    profile: u64,
    prefix: u64,
    motif: u64,
    salt: u64,
    mix: u64,
    chunk: u64,
    write: u64,
}

impl V6Namespaces {
    fn derive(profile_secret: &[u8; 32]) -> Self {
        Self {
            profile: derive_namespace(profile_secret, LABEL_PROFILE_ID, NS_SEED_PROFILE),
            prefix: derive_namespace(profile_secret, 0, NS_SEED_PREFIX),
            motif: derive_namespace(profile_secret, LABEL_MOTIF, NS_SEED_MOTIF),
            salt: derive_namespace(profile_secret, 3, NS_SEED_SALT),
            mix: derive_namespace(profile_secret, 0x10, NS_SEED_MIX),
            chunk: derive_namespace(profile_secret, 0x15, NS_SEED_CHUNK),
            write: derive_namespace(profile_secret, 0x1c, NS_SEED_WRITE),
        }
    }

    const fn for_label(self, label: u32) -> u64 {
        match label {
            0 | 1 | 14 | 15 | 33 | 34 => self.prefix,
            2 => self.motif,
            3 | 16..=20 => self.mix,
            4..=13 | 27 => self.profile,
            21..=26 | 38 | 39 => self.chunk,
            28..=32 | 35..=37 => self.write,
            _ => self.profile,
        }
    }

    const fn prf32(self, label: u32, a: u32, b: u32) -> u32 {
        prf32_mix(self.for_label(label), label, a, b)
    }

    const fn prf_static(self, label: u32, domain: u32) -> u32 {
        self.prf32(label, 0, domain)
    }

    fn expand_into(self, label: u32, seq: u32, len: usize, out: &mut BytesMut) {
        expand_stream(self.for_label(label), label, seq, len, out);
    }

    fn expand_array<const N: usize>(self, label: u32, seq: u32) -> [u8; N] {
        expand_stream_array(self.for_label(label), label, seq)
    }
}

#[derive(Clone, Debug)]
pub struct V6Profile {
    namespaces: V6Namespaces,
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
    pub(in crate::protocol::v6) mix_mode: u32,
    pub(in crate::protocol::v6) mix_rounds: u32,
    pub(in crate::protocol::v6) mix_stride: usize,
    pub(in crate::protocol::v6) mix_offset_base: usize,
    pub(in crate::protocol::v6) mix_block: usize,
    chunk_policy: u32,
    pub(in crate::protocol::v6) chunk_initial: usize,
    chunk_max: usize,
    chunk_step: usize,
    chunk_jitter: usize,
    pub(in crate::protocol::v6) idle_reset: Duration,
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
        let profile_secret = blake2b_256_from_slices(&[PROFILE_SEED, psk]);
        let namespaces = V6Namespaces::derive(&profile_secret);

        let profile_id = namespaces.prf_static(LABEL_PROFILE_ID, 0);
        let generator = namespaces.prf_static(LABEL_GENERATOR, 0) & 3;
        let pad_min = pick_usize(namespaces.prf_static(LABEL_PAD_MIN, 0), 0x18, 0xa0);
        let pad_max = (pad_min + pick_usize(namespaces.prf_static(LABEL_PAD_MAX, 0), 0xa0, 0x3c0))
            .min(MAX_EXTRA_TARGET_PADDING);
        let pad_count = pick_u32(namespaces.prf_static(LABEL_PAD_COUNT, 0), 2, 8);
        let pad_interval = pick_u32(namespaces.prf_static(LABEL_PAD_INTERVAL, 0), 2, 0x0b);
        let small_limit = pick_usize(namespaces.prf_static(LABEL_SMALL_LIMIT, 0), 0x60, 0x300);
        let bit_min = pick_u32(namespaces.prf_static(LABEL_BIT_MIN, 0), 0x18, 0x29);
        let bit_max = pick_u32(namespaces.prf_static(LABEL_BIT_MAX, 0), 0x3a, 0x4c);

        let prefix_min_handshake = pick_usize(
            namespaces.prf_static(LABEL_PREFIX_MIN, HANDSHAKE_DOMAIN),
            0x10,
            0x60,
        );
        let mut prefix_max_handshake = prefix_min_handshake
            + pick_usize(
                namespaces.prf_static(LABEL_PREFIX_MAX, HANDSHAKE_DOMAIN),
                0x10,
                0xa0,
            );
        prefix_max_handshake = prefix_max_handshake.min(0x80);
        let prefix_min_handshake = prefix_min_handshake.min(prefix_max_handshake);
        let salt_prefix_len = pick_usize(
            namespaces.prf_static(LABEL_RECORD_PREFIX, HANDSHAKE_DOMAIN),
            prefix_min_handshake,
            prefix_max_handshake,
        );
        let salt_block_len = SALT_SIZE + salt_prefix_len;
        let mix_rounds_handshake = pick_u32(
            namespaces.prf_static(LABEL_MIX_ROUNDS, MIX_HANDSHAKE_DOMAIN),
            1,
            4,
        );
        let mix_stride_handshake = pick_usize(
            namespaces.prf_static(LABEL_MIX_STRIDE, MIX_HANDSHAKE_DOMAIN),
            0x11,
            0xfb,
        );
        let salt_positions = salt_positions(namespaces.salt, salt_block_len, mix_rounds_handshake);

        let prefix_min_record = pick_usize(namespaces.prf_static(LABEL_PREFIX_MIN, 0), 0x08, 0x50);
        let mut prefix_max_record =
            prefix_min_record + pick_usize(namespaces.prf_static(LABEL_PREFIX_MAX, 0), 0x10, 0xa0);
        prefix_max_record = prefix_max_record.min(0x80);
        let prefix_min_record = prefix_min_record.min(prefix_max_record);

        let mix_mode = namespaces.prf_static(LABEL_MIX_MODE, 0) % 3;
        let mix_rounds = pick_u32(namespaces.prf_static(LABEL_MIX_ROUNDS, 0), 1, 3);
        let mix_stride = pick_usize(namespaces.prf_static(LABEL_MIX_STRIDE, 0), 2, 13);
        let mix_offset_base = pick_usize(namespaces.prf_static(LABEL_MIX_OFFSET_BASE, 0), 0, 15);
        let mix_block = pick_usize(namespaces.prf_static(LABEL_MIX_BLOCK, 0), 8, 0x40);

        let chunk_policy = namespaces.prf_static(LABEL_CHUNK_POLICY, 0) % 3;
        let chunk_initial = clamp_usize(
            pick_usize(
                namespaces.prf_static(LABEL_CHUNK_INITIAL, 0),
                0x200,
                V6_TRAFFIC_SHAPING_MTU_CAP,
            ),
            0x60,
            V6_TRAFFIC_SHAPING_MTU_CAP,
        );
        let chunk_max = pick_usize(
            namespaces.prf_static(LABEL_CHUNK_MAX, 0),
            0x2000,
            V6_CHUNK_MAX_RAW_BOUND,
        )
        .max(chunk_initial);
        let chunk_step =
            pick_usize(namespaces.prf_static(LABEL_CHUNK_STEP, 0), 0x400, 0x1000).min(0x0b68);
        let chunk_jitter =
            pick_usize(namespaces.prf_static(LABEL_CHUNK_JITTER, 0), 0x10, 0xc0).min(0x0b6);
        let idle_reset =
            Duration::from_secs(
                pick_usize(namespaces.prf_static(LABEL_IDLE_RESET, 0), 0x0c, 0x5a) as u64,
            );
        let write_policy = namespaces.prf_static(LABEL_WRITE_POLICY, 0) % 3;
        let write_first = pick_u32(namespaces.prf_static(LABEL_WRITE_FIRST, 0), 4, 8);

        let mut chunk_buckets = [0; 8];
        let mut write_buckets = [0; 8];
        let mut write_seq = [0; 8];
        for i in 0..8 {
            let chunk_bucket = pick_usize(
                namespaces.prf_static(LABEL_CHUNK_BUCKET, i as u32),
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
            write_buckets[i] = clamp_usize(
                pick_usize(
                    namespaces.prf_static(LABEL_WRITE_BUCKET, i as u32),
                    0x140,
                    V6_TRAFFIC_SHAPING_MTU_CAP,
                ),
                0x100,
                V6_TRAFFIC_SHAPING_MTU_CAP,
            );
            write_seq[i] = clamp_usize(
                pick_usize(
                    namespaces.prf_static(LABEL_WRITE_SEQ, i as u32),
                    0x168,
                    V6_TRAFFIC_SHAPING_MTU_CAP,
                ),
                0x100,
                V6_TRAFFIC_SHAPING_MTU_CAP,
            );
        }

        let write_jitter = pick_usize(namespaces.prf_static(LABEL_WRITE_JITTER, 0), 0x08, 0x60);
        let write_jitter_percent =
            pick_usize(namespaces.prf_static(LABEL_WRITE_POLICY, 0x504c), 8, 0x30);

        let g1 = pick_usize(namespaces.prf_static(LABEL_GENERATOR, 1), 0x18, 0x80);
        let g2 = pick_usize(namespaces.prf_static(LABEL_GENERATOR, 2), 0x10, 0x60);
        let g3 = pick_usize(namespaces.prf_static(LABEL_GENERATOR, 3), 0x10, 0x60);
        let g4 = pick_usize(namespaces.prf_static(LABEL_GENERATOR, 4), 0x00, 0x09);
        let g5 = pick_usize(namespaces.prf_static(LABEL_GENERATOR, 5), 0x01, 0x08);
        let g6 = pick_usize(namespaces.prf_static(LABEL_GENERATOR, 6), 0x07, 0x17);

        Self {
            namespaces,
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

    pub const fn record_prefix_len(&self, seq: u32) -> usize {
        self.pick(
            LABEL_RECORD_PREFIX,
            seq,
            0,
            self.prefix_min_record,
            self.prefix_max_record,
        )
    }

    pub(in crate::protocol::v6) fn append_salt_block(
        &self,
        salt: &[u8; SALT_SIZE],
        out: &mut BytesMut,
    ) -> Range<usize> {
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

    pub(in crate::protocol::v6) fn append_official_fill(
        &self,
        seq: u32,
        len: usize,
        out: &mut BytesMut,
    ) -> Range<usize> {
        let start = out.len();
        self.namespaces.expand_into(LABEL_PADDING, seq, len, out);
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
                LABEL_PAYLOAD_PADDING,
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

        let target = self.write_target_len(seq, current_len);
        if current_len < target {
            let delta = target - current_len;
            base_pad += MAX_EXTRA_TARGET_PADDING.min(delta);
        }
        base_pad
    }

    pub fn chunk_limit(&self, seq: u32, current_chunk_size: usize) -> usize {
        let mut cur = if current_chunk_size != 0 {
            current_chunk_size
        } else {
            self.chunk_initial
        };
        match self.chunk_policy {
            1 => {
                cur = self.chunk_buckets[(self.prf32(LABEL_CHUNK_SIZE, seq, cur as u32) as usize)
                    % self.chunk_buckets.len()];
            }
            2 => {
                let span = 2 * self.chunk_jitter + 1;
                let j = (self.prf32(LABEL_CHUNK_JITTER_VALUE, seq, cur as u32) as usize % span)
                    as isize
                    - self.chunk_jitter as isize;
                cur = (cur as isize + j).max(0x40) as usize;
            }
            _ => {}
        }

        cur.clamp(0x40, self.chunk_max)
    }

    pub(in crate::protocol::v6) fn next_chunk_size(&self, current_chunk_size: usize) -> usize {
        if current_chunk_size == 0 {
            self.chunk_initial
        } else {
            current_chunk_size
                .saturating_add(self.chunk_step)
                .min(self.chunk_max)
        }
    }

    pub(in crate::protocol::v6) const fn prf32(&self, label: u32, a: u32, b: u32) -> u32 {
        self.namespaces.prf32(label, a, b)
    }

    const fn pick(&self, label: u32, a: u32, b: u32, lo: usize, hi: usize) -> usize {
        pick_usize(self.prf32(label, a, b), lo, hi)
    }

    fn write_target_len(&self, seq: u32, current_len: usize) -> usize {
        if current_len > V6_TARGET_DIRECT_LIMIT {
            return if current_len <= V6_TARGET_U16_LIMIT {
                current_len
            } else {
                u32::MAX as usize
            };
        }

        let mut target = if seq < self.write_first {
            self.write_seq[seq as usize]
        } else {
            self.write_buckets[(self.prf32(LABEL_WRITE_TARGET, seq, current_len as u32) as usize)
                % self.write_buckets.len()]
        };

        if self.write_policy == 2 {
            let span = 2 * self.write_jitter + 1;
            let j = (self.prf32(LABEL_WRITE_JITTER_VALUE, seq, 0) as usize % span) as isize
                - self.write_jitter as isize;
            target = (target as isize + j).max(1) as usize;
        }

        let jitter_bound =
            MAX_EXTRA_TARGET_PADDING.min(self.write_jitter_percent * current_len / 100);
        if self.prf32(LABEL_WRITE_TARGET, seq, jitter_bound as u32) & 1 == 0 {
            target = target.saturating_add(jitter_bound);
        } else if target > jitter_bound / 2 {
            target -= jitter_bound / 2;
        }

        while current_len > target {
            let cand = self.write_buckets[(self.prf32(LABEL_WRITE_NEXT, seq, target as u32)
                as usize)
                % self.write_buckets.len()];
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

    fn apply_generator_0(&self, seq: u32, out: &mut [u8]) {
        let percent = self.pick(
            LABEL_BIT_PERCENT,
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

        let table = &GENERATOR0_BYTE_TABLE[target_bits as usize];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = table[i & 7][usize::from(*byte)];
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
        let motif = self.namespaces.expand_array::<32>(LABEL_MOTIF, seq);
        let motif_len = (self.g5 * 4).min(motif.len());
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

    const fn salt_mask(&self, i: usize) -> u8 {
        let raw = prf32_mix(
            self.namespaces.salt,
            LABEL_MOTIF,
            MIX_HANDSHAKE_DOMAIN,
            i as u32,
        );
        (i as u8).wrapping_mul(self.mix_stride_handshake as u8) ^ raw as u8
    }
}

fn build_generator0_byte_table() -> [[[u8; 256]; 8]; 8] {
    let mut table = [[[0; 256]; 8]; 8];
    for (target_bits, target_table) in table.iter_mut().enumerate() {
        for (index_mod, index_table) in target_table.iter_mut().enumerate() {
            for (byte, slot) in index_table.iter_mut().enumerate() {
                *slot = generator0_byte(byte as u8, index_mod, target_bits as u32);
            }
        }
    }
    table
}

fn generator0_byte(orig: u8, index_mod: usize, target_bits: u32) -> u8 {
    let mut b = orig;
    let mut ones = b.count_ones();
    for k in 0..8 {
        if ones == target_bits {
            break;
        }
        let bit = (usize::from(orig) + index_mod + 3 * k) & 7;
        let mask = 1 << bit;
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

#[cfg(test)]
mod tests;

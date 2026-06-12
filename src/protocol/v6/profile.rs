use super::*;

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
            V6_TRAFFIC_SHAPING_MTU_CAP,
        );
        let chunk_max = clamp_usize(
            pick_usize(
                prf32_with_secret(&profile_secret, "chunk-max", 0, 0),
                0x0800,
                V6_CHUNK_MAX_RAW_BOUND,
            ),
            0x60,
            V6_TRAFFIC_SHAPING_MTU_CAP,
        );
        let chunk_step = clamp_usize(
            pick_usize(
                prf32_with_secret(&profile_secret, "chunk-step", 0, 0),
                0x60,
                0x500,
            ),
            0x60,
            V6_TRAFFIC_SHAPING_MTU_CAP,
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
                    V6_TRAFFIC_SHAPING_MTU_CAP,
                ),
                0x60,
                V6_TRAFFIC_SHAPING_MTU_CAP,
            );
            write_buckets[i] = clamp_usize(
                pick_usize(
                    prf32_with_secret(&profile_secret, "write-bucket", 0, i as u32),
                    0x140,
                    V6_TRAFFIC_SHAPING_MTU_CAP,
                ),
                0x60,
                V6_TRAFFIC_SHAPING_MTU_CAP,
            );
            write_seq[i] = clamp_usize(
                pick_usize(
                    prf32_with_secret(&profile_secret, "write-seq", 0, i as u32),
                    0x168,
                    V6_TRAFFIC_SHAPING_MTU_CAP,
                ),
                0x60,
                V6_TRAFFIC_SHAPING_MTU_CAP,
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
        if cur + worst_overhead > V6_TRAFFIC_SHAPING_MTU_CAP
            && worst_overhead <= V6_MTU_OVERHEAD_LIMIT
        {
            cur = V6_TRAFFIC_SHAPING_MTU_CAP - worst_overhead;
        }
        cur.clamp(0x40, self.chunk_max)
    }

    pub(in crate::protocol::v6) fn next_chunk_size(&self, current_chunk_size: usize) -> usize {
        if current_chunk_size == 0 {
            self.chunk_initial
        } else if self.chunk_policy == 0 {
            (current_chunk_size + self.chunk_step).min(self.chunk_max)
        } else {
            current_chunk_size
        }
    }

    pub(in crate::protocol::v6) fn prf32(&self, label: &str, a: u32, b: u32) -> u32 {
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

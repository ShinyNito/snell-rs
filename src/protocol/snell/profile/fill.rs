use std::sync::LazyLock;

#[cfg(test)]
use super::super::crypto::expand::expand_stream;
use super::super::crypto::{GOLDEN_GAMMA, expand::expand_initial_state, splitmix::splitmix64};
use super::labels::{BIT_PERCENT, MOTIF, PADDING};
use super::{ShapedProfile, low_u8, u8_from_usize, u32_from_usize, usize_from_u32};

static GENERATOR0_BYTE_TABLE: LazyLock<[[[u8; 256]; 8]; 8]> =
    LazyLock::new(build_generator0_byte_table);
static GENERATOR2_BYTE_TABLE: LazyLock<[[[u8; 256]; 4]; 10]> =
    LazyLock::new(build_generator2_byte_table);

impl ShapedProfile {
    pub(crate) fn fill_official(&self, seq: u32, out: &mut [u8]) {
        match self.generator {
            0 => self.fill_generator_0(seq, out),
            1 => self.fill_generator_1(seq, out),
            2 => self.fill_generator_2(seq, out),
            3 => self.fill_generator_3(seq, out),
            _ => unreachable!("generator is masked to 0..=3"),
        }
    }

    fn fill_generator_0(&self, seq: u32, out: &mut [u8]) {
        let percent = self.pick(
            BIT_PERCENT,
            seq,
            0,
            self.bit_min as usize,
            self.bit_max as usize,
        );
        let scaled = percent * 8;
        let target_bits = u32_from_usize(if scaled <= 49 {
            1
        } else if scaled > 749 {
            7
        } else {
            (scaled + 50) / 100
        });

        let table = &GENERATOR0_BYTE_TABLE[usize_from_u32(target_bits)];
        self.fill_padding_mapped_raw(seq, out, |i, byte| table[i & 7][usize::from(byte)]);
    }

    fn fill_generator_1(&self, seq: u32, out: &mut [u8]) {
        let total = self.g1 + self.g2 + self.g3;
        let g1 = self.g1;
        let g12 = self.g1 + self.g2;
        self.fill_padding_mapped_raw(seq, out, |i, b| {
            generator1_byte(b, low_u8(i), total, g1, g12)
        });
    }

    fn fill_generator_2(&self, seq: u32, out: &mut [u8]) {
        let table = &GENERATOR2_BYTE_TABLE[self.g4];
        self.fill_padding_mapped_raw(seq, out, |i, b| table[i & 3][usize::from(b)]);
    }

    fn fill_generator_3(&self, seq: u32, out: &mut [u8]) {
        let motif = self.namespaces.expand_array::<32>(MOTIF, seq);
        let motif_len = (self.g5 * 4).min(motif.len());
        let interval = self.g6;
        self.fill_padding_mapped_raw(seq, out, |i, b| {
            let r = i % interval;
            if r < interval - 3 {
                low_u8((self.g5 + 3) * i) ^ motif[i % motif_len]
            } else if r < interval - 1 {
                0x30 + b % 10
            } else {
                b
            }
        });
    }

    #[inline(always)]
    fn fill_padding_mapped_raw<F>(&self, seq: u32, out: &mut [u8], mut map: F)
    where
        F: FnMut(usize, u8) -> u8,
    {
        let mut state = expand_initial_state(
            self.namespaces.for_label(PADDING),
            PADDING,
            u64::from(seq),
            out.len() as u64,
        );
        let ptr = out.as_mut_ptr();
        let len = out.len();
        let mut offset = 0usize;

        // SAFETY: `offset + 8 <= len` in the word loop and `offset + i < len`
        // in the tail loop. `ptr` comes from the unique `&mut [u8]`, and
        // unaligned u64 stores are intentional because the output slice has no
        // alignment contract.
        unsafe {
            while offset + 8 <= len {
                state = state.wrapping_add(GOLDEN_GAMMA);
                let bytes = splitmix64(state).to_le_bytes();
                let mapped = [
                    map(offset, bytes[0]),
                    map(offset + 1, bytes[1]),
                    map(offset + 2, bytes[2]),
                    map(offset + 3, bytes[3]),
                    map(offset + 4, bytes[4]),
                    map(offset + 5, bytes[5]),
                    map(offset + 6, bytes[6]),
                    map(offset + 7, bytes[7]),
                ];
                std::ptr::write_unaligned(
                    ptr.add(offset).cast::<u64>(),
                    u64::from_le_bytes(mapped).to_le(),
                );
                offset += 8;
            }

            if offset < len {
                state = state.wrapping_add(GOLDEN_GAMMA);
                let bytes = splitmix64(state).to_le_bytes();
                for (i, byte) in bytes.iter().take(len - offset).enumerate() {
                    ptr.add(offset + i).write(map(offset + i, *byte));
                }
            }
        }
    }
}

fn build_generator0_byte_table() -> [[[u8; 256]; 8]; 8] {
    let mut table = [[[0; 256]; 8]; 8];
    for (target_bits, target_table) in table.iter_mut().enumerate() {
        for (index_mod, index_table) in target_table.iter_mut().enumerate() {
            for (byte, slot) in index_table.iter_mut().enumerate() {
                *slot =
                    generator0_byte(u8_from_usize(byte), index_mod, u32_from_usize(target_bits));
            }
        }
    }
    table
}

fn build_generator2_byte_table() -> [[[u8; 256]; 4]; 10] {
    let mut table = [[[0; 256]; 4]; 10];
    for (g4, g4_table) in table.iter_mut().enumerate() {
        for (index_mod, index_table) in g4_table.iter_mut().enumerate() {
            for (byte, slot) in index_table.iter_mut().enumerate() {
                *slot = generator2_byte(u8_from_usize(byte), index_mod, g4);
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

#[inline(always)]
fn generator1_byte(byte: u8, index_low: u8, total: usize, g1: usize, g12: usize) -> u8 {
    let r = byte_mod_total(byte, total);
    if r < g1 {
        0x20 + byte.wrapping_add(index_low) % 0x5f
    } else if r < g12 {
        0x80 + ((byte ^ index_low) % 0x40)
    } else {
        0xc0 + byte.wrapping_add(index_low.wrapping_mul(7)) % 0x40
    }
}

#[inline(always)]
fn byte_mod_total(byte: u8, total: usize) -> usize {
    let mut r = usize::from(byte);
    if r >= total {
        r -= total;
        if r >= total {
            r -= total;
            if r >= total {
                r -= total;
                if r >= total {
                    r -= total;
                }
            }
        }
    }
    r
}

fn generator2_byte(byte: u8, index_mod: usize, g4: usize) -> u8 {
    let hi = (((byte >> 4).wrapping_add(low_u8(index_mod)).wrapping_add(3)) << 4) & 0xf0;
    let lo = ((byte & 0x0f) as usize + g4 + (index_mod & 1)) % 10;
    hi | u8_from_usize(lo)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PSK: &[u8] = b"test psk 16 byte";

    #[test]
    fn fill_generators_match_slow_reference() {
        for generator in 0..=3 {
            for seq in [0, 1, 7, u32::MAX] {
                for len in [0usize, 1, 7, 8, 31, 128, 1024] {
                    let mut profile = ShapedProfile::derive(TEST_PSK);
                    profile.generator = generator;
                    let mut fast = vec![0; len];
                    let mut slow = vec![0; len];

                    profile.fill_official(seq, &mut fast);
                    fill_slow(&profile, generator, seq, &mut slow);

                    assert_eq!(fast, slow, "generator={generator}, seq={seq}, len={len}");
                }
            }
        }
    }

    fn fill_slow(profile: &ShapedProfile, generator: u32, seq: u32, out: &mut [u8]) {
        match generator {
            0 => fill_generator_0_slow(profile, seq, out),
            1 => fill_generator_1_slow(profile, seq, out),
            2 => fill_generator_2_slow(profile, seq, out),
            3 => fill_generator_3_slow(profile, seq, out),
            _ => unreachable!("test generator range is fixed"),
        }
    }

    fn fill_generator_0_slow(profile: &ShapedProfile, seq: u32, out: &mut [u8]) {
        let stream = padding_stream(profile, seq, out.len());
        let percent = profile.pick(
            BIT_PERCENT,
            seq,
            0,
            profile.bit_min as usize,
            profile.bit_max as usize,
        );
        let scaled = percent * 8;
        let target_bits = u32_from_usize(if scaled <= 49 {
            1
        } else if scaled > 749 {
            7
        } else {
            (scaled + 50) / 100
        });

        for (i, (dst, byte)) in out.iter_mut().zip(stream).enumerate() {
            *dst = generator0_byte(byte, i & 7, target_bits);
        }
    }

    fn fill_generator_1_slow(profile: &ShapedProfile, seq: u32, out: &mut [u8]) {
        let stream = padding_stream(profile, seq, out.len());
        let total = profile.g1 + profile.g2 + profile.g3;
        for (i, (dst, b)) in out.iter_mut().zip(stream).enumerate() {
            let r = usize::from(b) % total;
            *dst = if r < profile.g1 {
                0x20 + b.wrapping_add(low_u8(i)) % 0x5f
            } else if r < profile.g1 + profile.g2 {
                0x80 + ((b ^ low_u8(i)) % 0x40)
            } else {
                0xc0 + b.wrapping_add(low_u8(7 * i)) % 0x40
            };
        }
    }

    fn fill_generator_2_slow(profile: &ShapedProfile, seq: u32, out: &mut [u8]) {
        let stream = padding_stream(profile, seq, out.len());
        for (i, (dst, b)) in out.iter_mut().zip(stream).enumerate() {
            let hi = (((b >> 4).wrapping_add(low_u8(i & 3)).wrapping_add(3)) << 4) & 0xf0;
            let lo = ((b & 0x0f) as usize + profile.g4 + (i & 1)) % 10;
            *dst = hi | u8_from_usize(lo);
        }
    }

    fn fill_generator_3_slow(profile: &ShapedProfile, seq: u32, out: &mut [u8]) {
        let stream = padding_stream(profile, seq, out.len());
        let motif = profile.namespaces.expand_array::<32>(MOTIF, seq);
        let motif_len = (profile.g5 * 4).min(motif.len());
        let interval = profile.g6;
        for (i, (dst, b)) in out.iter_mut().zip(stream).enumerate() {
            let r = i % interval;
            *dst = if r < interval - 3 {
                low_u8((profile.g5 + 3) * i) ^ motif[i % motif_len]
            } else if r < interval - 1 {
                0x30 + b % 10
            } else {
                b
            };
        }
    }

    fn padding_stream(profile: &ShapedProfile, seq: u32, len: usize) -> Vec<u8> {
        let mut stream = vec![0; len];
        expand_stream(
            profile.namespaces.for_label(PADDING),
            PADDING,
            u64::from(seq),
            len as u64,
            &mut stream,
        );
        stream
    }
}

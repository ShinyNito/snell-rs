use std::sync::LazyLock;

use super::labels::{BIT_PERCENT, MOTIF, PADDING};
use super::{ShapedProfile, low_u8, u8_from_usize, u32_from_usize, usize_from_u32};

static GENERATOR0_BYTE_TABLE: LazyLock<[[[u8; 256]; 8]; 8]> =
    LazyLock::new(build_generator0_byte_table);

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
        self.namespaces
            .expand_slice_mapped(PADDING, seq, out, |i, byte| table[i & 7][usize::from(byte)]);
    }

    fn fill_generator_1(&self, seq: u32, out: &mut [u8]) {
        let total = self.g1 + self.g2 + self.g3;
        self.namespaces
            .expand_slice_mapped(PADDING, seq, out, |i, b| {
                let r = usize::from(b) % total;
                if r < self.g1 {
                    0x20 + b.wrapping_add(low_u8(i)) % 0x5f
                } else if r < self.g1 + self.g2 {
                    0x80 + ((b ^ low_u8(i)) % 0x40)
                } else {
                    0xc0 + b.wrapping_add(low_u8(7 * i)) % 0x40
                }
            });
    }

    fn fill_generator_2(&self, seq: u32, out: &mut [u8]) {
        self.namespaces
            .expand_slice_mapped(PADDING, seq, out, |i, b| {
                let hi = (((b >> 4).wrapping_add(low_u8(i & 3)).wrapping_add(3)) << 4) & 0xf0;
                let lo = ((b & 0x0f) as usize + self.g4 + (i & 1)) % 10;
                hi | u8_from_usize(lo)
            });
    }

    fn fill_generator_3(&self, seq: u32, out: &mut [u8]) {
        let motif = self.namespaces.expand_array::<32>(MOTIF, seq);
        let motif_len = (self.g5 * 4).min(motif.len());
        let interval = self.g6;
        self.namespaces
            .expand_slice_mapped(PADDING, seq, out, |i, b| {
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

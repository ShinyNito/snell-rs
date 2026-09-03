use crate::{Entropy, Result};

#[inline]
fn count_ones(bytes: &[u8]) -> usize {
    let slice = &bytes[..bytes.len() & !3];
    let (chunks, remainder) = slice.as_chunks::<8>();
    let mut total = chunks
        .iter()
        .map(|chunk| u64::from_ne_bytes(*chunk).count_ones() as usize)
        .sum::<usize>();
    for &byte in remainder {
        total += byte.count_ones() as usize;
    }
    total
}

/// Swap even-indexed bytes across the padding / payload-cipher boundary.
///
/// Applied after sealing so the on-wire split is not a clean padding|cipher cut.
/// The same function undoes the swap before opening.
pub fn swap_even_indices(padding: &mut [u8], payload_cipher: &mut [u8]) {
    const MASK: u64 = u64::from_ne_bytes([0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0]);
    let limit = padding.len().min(payload_cipher.len());
    let padding = &mut padding[..limit];
    let payload_cipher = &mut payload_cipher[..limit];
    let (p_chunks, p_tail) = padding.as_chunks_mut::<8>();
    let (c_chunks, c_tail) = payload_cipher.as_chunks_mut::<8>();
    for (p, c) in p_chunks.iter_mut().zip(c_chunks) {
        let a = u64::from_ne_bytes(*p);
        let b = u64::from_ne_bytes(*c);
        let diff = (a ^ b) & MASK;
        *p = (a ^ diff).to_ne_bytes();
        *c = (b ^ diff).to_ne_bytes();
    }
    for i in (0..p_tail.len()).step_by(2) {
        core::mem::swap(&mut p_tail[i], &mut c_tail[i]);
    }
}

/// Fill v4 padding so the body's 0/1 ratio stays near a target, else uniform random.
///
/// Ones are counted on `payload_cipher` truncated to a multiple of 4; zeros use the
/// full slice length. That mismatch is part of the wire algorithm.
pub fn fill_v4_padding<E: Entropy>(
    padding: &mut [u8],
    payload_cipher: &[u8],
    entropy: &mut E,
) -> Result<()> {
    if padding.is_empty() {
        return Ok(());
    }

    let ones = count_ones(payload_cipher);
    let zeros = payload_cipher.len() * u8::BITS as usize - ones;
    if zeros == 0 {
        return entropy.fill(padding);
    }

    let ratio = ones as f64 / zeros as f64;
    if !(0.5..=1.6).contains(&ratio) {
        return entropy.fill(padding);
    }

    let mut rnd = [0u8; 8];
    entropy.fill(&mut rnd)?;
    let jitter = u64::from_le_bytes(rnd) as f64 / (u64::MAX as f64) * 0.1;
    let target_ratio = if zeros < ones { 0.4 } else { 1.6 } + jitter;
    let total_bits = (padding.len() + payload_cipher.len()) * u8::BITS as usize;
    let target = total_bits as f64 * (target_ratio / (target_ratio + 1.0)) - ones as f64;
    if !target.is_finite() || target < 0.0 || target > (padding.len() * u8::BITS as usize) as f64 {
        return entropy.fill(padding);
    }

    fill_padding_bits(padding, target.floor() as usize, entropy)
}

fn fill_padding_bits<E: Entropy>(
    padding: &mut [u8],
    target_ones: usize,
    entropy: &mut E,
) -> Result<()> {
    let bits = padding.len() * u8::BITS as usize;
    let mut rng = BitRng {
        entropy,
        random: [0u8; 4096],
        offset: 4096,
    };
    if target_ones <= bits - target_ones {
        padding.fill(0);
        for j in bits - target_ones..bits {
            let candidate = rng.pick(j)?;
            let index = if padding[candidate >> 3] & (1u8 << (candidate & 7)) != 0 {
                j
            } else {
                candidate
            };
            padding[index >> 3] |= 1u8 << (index & 7);
        }
    } else {
        padding.fill(0xff);
        for j in target_ones..bits {
            let candidate = rng.pick(j)?;
            let index = if padding[candidate >> 3] & (1u8 << (candidate & 7)) == 0 {
                j
            } else {
                candidate
            };
            padding[index >> 3] &= !(1u8 << (index & 7));
        }
    }
    Ok(())
}

struct BitRng<'a, E> {
    entropy: &'a mut E,
    random: [u8; 4096],
    offset: usize,
}

impl<E: Entropy> BitRng<'_, E> {
    fn pick(&mut self, max: usize) -> Result<usize> {
        let span = max as u64 + 1;
        let zone = u64::MAX - (u64::MAX % span);
        loop {
            if self.offset + 8 > self.random.len() {
                self.entropy.fill(&mut self.random)?;
                self.offset = 0;
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&self.random[self.offset..self.offset + 8]);
            self.offset += 8;
            let value = u64::from_le_bytes(bytes);
            if value < zone {
                return Ok((value % span) as usize);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RepeatEntropy;

    const LENGTHS: &[usize] = &[
        0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 257, 1023, 1024,
        1025, 4095, 4096, 4097, 16379, 16380, 16381, 16382, 16383,
    ];

    fn count_ones_scalar(bytes: &[u8]) -> usize {
        bytes[..bytes.len() & !3]
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum()
    }

    fn swap_even_indices_scalar(padding: &mut [u8], payload_cipher: &mut [u8]) {
        let limit = padding.len().min(payload_cipher.len());
        for i in (0..limit).step_by(2) {
            core::mem::swap(&mut padding[i], &mut payload_cipher[i]);
        }
    }

    #[test]
    fn count_ones_matches_scalar_truncated() {
        let known = [0xFFu8, 0x00, 0x0F, 0xF0, 0x01];
        assert_eq!(count_ones_scalar(&known), 16);
        assert_eq!(count_ones(&known), 16);
        assert_eq!(
            known
                .iter()
                .map(|byte| byte.count_ones() as usize)
                .sum::<usize>(),
            17
        );
        for &len in LENGTHS {
            let bytes: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                .collect();
            assert_eq!(count_ones(&bytes), count_ones_scalar(&bytes), "len={len}");
        }
    }

    #[test]
    fn swap_is_an_involution() {
        let mut padding = [1, 2, 3, 4, 5];
        let mut payload = [10, 20, 30, 40, 50, 60];
        let before_p = padding;
        let before_c = payload;
        swap_even_indices(&mut padding, &mut payload);
        assert_ne!(padding, before_p);
        swap_even_indices(&mut padding, &mut payload);
        assert_eq!(padding, before_p);
        assert_eq!(payload, before_c);
    }

    #[test]
    fn swap_even_indices_matches_scalar_loop() {
        for &plen in LENGTHS {
            for clen in [plen.saturating_sub(1), plen, plen.saturating_add(1)] {
                let mut p_scalar: Vec<u8> = (0..plen).map(|i| (i as u8).wrapping_add(1)).collect();
                let mut c_scalar: Vec<u8> =
                    (0..clen).map(|i| (i as u8).wrapping_add(100)).collect();
                let mut p_got = p_scalar.clone();
                let mut c_got = c_scalar.clone();
                swap_even_indices_scalar(&mut p_scalar, &mut c_scalar);
                swap_even_indices(&mut p_got, &mut c_got);
                assert_eq!(p_got, p_scalar, "padding plen={plen} clen={clen}");
                assert_eq!(c_got, c_scalar, "cipher plen={plen} clen={clen}");
            }
        }
    }

    #[test]
    fn fill_does_not_panic_on_peer_sized_buffers() {
        let mut padding = [0u8; 64];
        let payload = [0x55u8; 80];
        fill_v4_padding(&mut padding, &payload, &mut RepeatEntropy { byte: 0x3c }).unwrap();
    }
}

use crate::{Entropy, Result};

/// Swap even-indexed bytes across the padding / payload-cipher boundary.
///
/// Applied after sealing so the on-wire split is not a clean padding|cipher cut.
/// The same function undoes the swap before opening.
pub fn swap_even_indices(padding: &mut [u8], payload_cipher: &mut [u8]) {
    let limit = padding.len().min(payload_cipher.len());
    for i in (0..limit).step_by(2) {
        core::mem::swap(&mut padding[i], &mut payload_cipher[i]);
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

    let ones = payload_cipher[..payload_cipher.len() & !3]
        .iter()
        .map(|byte| byte.count_ones() as usize)
        .sum::<usize>();
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
    fn fill_does_not_panic_on_peer_sized_buffers() {
        let mut padding = [0u8; 64];
        let payload = [0x55u8; 80];
        fill_v4_padding(&mut padding, &payload, &mut RepeatEntropy { byte: 0x3c }).unwrap();
    }
}

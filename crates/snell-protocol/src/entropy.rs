use ring::rand::{SecureRandom, SystemRandom};

use crate::{Error, Result};

pub trait Entropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()>;
}

/// Operating-system CSPRNG via ring's `SystemRandom`.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        SystemRandom::new().fill(buf).map_err(|_| Error::Entropy)
    }
}

/// Repeats a single byte. Deterministic and unbounded; for tests and benches.
#[derive(Clone, Copy, Debug)]
pub struct RepeatEntropy {
    pub byte: u8,
}

impl Entropy for RepeatEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        buf.fill(self.byte);
        Ok(())
    }
}

/// Deterministic entropy for tests. Exhausts after the supplied bytes.
pub struct SequenceEntropy<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SequenceEntropy<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl Entropy for SequenceEntropy<'_> {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        if self.offset + buf.len() > self.bytes.len() {
            return Err(Error::EntropyExhausted);
        }
        buf.copy_from_slice(&self.bytes[self.offset..self.offset + buf.len()]);
        self.offset += buf.len();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_fills_then_exhausts() {
        let mut entropy = SequenceEntropy::new(&[1, 2, 3]);
        let mut buf = [0; 2];
        entropy.fill(&mut buf).unwrap();
        assert_eq!(buf, [1, 2]);
        assert!(entropy.fill(&mut buf).is_err());
    }
}

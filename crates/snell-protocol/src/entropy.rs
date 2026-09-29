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
}

impl<'a> SequenceEntropy<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl Entropy for SequenceEntropy<'_> {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        let (head, rest) = self
            .bytes
            .split_at_checked(buf.len())
            .ok_or(Error::EntropyExhausted)?;
        buf.copy_from_slice(head);
        self.bytes = rest;
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

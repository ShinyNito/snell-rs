#[derive(Debug, Default, Eq, PartialEq)]
pub struct Nonce12([u8; 12]);

impl Nonce12 {
    pub const fn new() -> Self {
        Self([0; 12])
    }

    pub const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    #[inline]
    pub fn increment(&mut self) {
        for byte in &mut self.0 {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Nonce12;

    #[test]
    fn increments_little_endian() {
        let mut nonce = Nonce12::new();
        nonce.increment();
        assert_eq!(nonce.as_bytes()[0], 1);

        let mut nonce = Nonce12([0xff; 12]);
        nonce.increment();
        assert_eq!(nonce.as_bytes(), &[0; 12]);
    }
}

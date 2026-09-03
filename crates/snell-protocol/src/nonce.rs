use crate::NONCE_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    pub const fn new() -> Self {
        Self([0; NONCE_LEN])
    }

    pub const fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }

    pub fn increment(&mut self) {
        for byte in &mut self.0 {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            if !overflow {
                return;
            }
        }
    }
}

impl Default for Nonce {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increments_little_endian_and_wraps() {
        let mut nonce = Nonce::new();
        nonce.increment();
        assert_eq!(nonce.as_bytes()[0], 1);

        let mut nonce = Nonce([0xff; NONCE_LEN]);
        nonce.increment();
        assert_eq!(nonce.as_bytes(), &[0; NONCE_LEN]);
    }
}

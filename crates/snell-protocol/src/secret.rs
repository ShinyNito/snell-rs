use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, PSK_MAX_LEN, PSK_MIN_LEN, Result};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Psk(Vec<u8>);

impl Psk {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        if !(PSK_MIN_LEN..=PSK_MAX_LEN).contains(&bytes.len()) {
            return Err(Error::InvalidPskLen(bytes.len()));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Psk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Psk(redacted)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_psk() {
        assert!(matches!(Psk::new(b"short"), Err(Error::InvalidPskLen(5))));
    }

    #[test]
    fn debug_does_not_contain_secret() {
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        assert_eq!(format!("{psk:?}"), "Psk(redacted)");
    }
}

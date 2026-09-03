use core::fmt;

use ring::aead::{self, Aad, LessSafeKey, UnboundKey};

use crate::{AES_128_KEY_LEN, Error, Nonce, Result, TAG_LEN};

/// AES-128-GCM with empty or caller-supplied AAD.
///
/// Debug does not print the key.
pub struct Aes128Gcm {
    key: LessSafeKey,
}

impl Aes128Gcm {
    pub fn new(key: &[u8; AES_128_KEY_LEN]) -> Result<Self> {
        let unbound = UnboundKey::new(&aead::AES_128_GCM, key).map_err(|_| Error::Aead)?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
        })
    }

    pub fn seal(&self, nonce: &Nonce, aad: &[u8], buf: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        let tag = self
            .key
            .seal_in_place_separate_tag(ring_nonce(nonce), Aad::from(aad), buf)
            .map_err(|_| Error::Aead)?;
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }

    pub fn open(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<()> {
        let tag = aead::Tag::try_from(tag.as_slice()).map_err(|_| Error::Aead)?;
        self.key
            .open_in_place_separate_tag(ring_nonce(nonce), Aad::from(aad), tag, buf, 0..)
            .map_err(|_| Error::Aead)?;
        Ok(())
    }
}

impl fmt::Debug for Aes128Gcm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Aes128Gcm")
    }
}

fn ring_nonce(nonce: &Nonce) -> aead::Nonce {
    aead::Nonce::assume_unique_for_key(*nonce.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_empty_plaintext() {
        let key = [0u8; AES_128_KEY_LEN];
        let aead = Aes128Gcm::new(&key).unwrap();
        let nonce = Nonce::new();
        let tag = aead.seal(&nonce, &[], &mut []).unwrap();
        assert_eq!(
            tag,
            [
                0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
                0x45, 0x5a
            ]
        );
    }

    #[test]
    fn round_trip_and_tamper() {
        let key = [0x11u8; AES_128_KEY_LEN];
        let aead = Aes128Gcm::new(&key).unwrap();
        let nonce = Nonce::new();
        let mut buf = *b"hello";
        let tag = aead.seal(&nonce, &[], &mut buf).unwrap();
        aead.open(&nonce, &[], &mut buf, &tag).unwrap();
        assert_eq!(&buf, b"hello");
        let mut bad = tag;
        bad[0] ^= 1;
        let mut buf = *b"hello";
        let _ = aead.seal(&nonce, &[], &mut buf).unwrap();
        assert_eq!(aead.open(&nonce, &[], &mut buf, &bad), Err(Error::Aead));
    }

    #[test]
    fn debug_hides_key() {
        let aead = Aes128Gcm::new(&[0x42; AES_128_KEY_LEN]).unwrap();
        assert_eq!(format!("{aead:?}"), "Aes128Gcm");
    }
}

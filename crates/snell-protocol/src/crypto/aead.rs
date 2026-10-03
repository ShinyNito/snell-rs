use core::fmt;

use ring::aead::{self, Aad, LessSafeKey, UnboundKey};
use zeroize::Zeroize;

use crate::crypto::kdf::aead_key;
use crate::{AES_128_KEY_LEN, Error, Nonce, Psk, Result, SALT_LEN, TAG_LEN};

/// AES-128-GCM with empty or caller-supplied AAD.
///
/// Every successful seal or open advances the caller's nonce.
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

    /// Argon2id session cipher for `salt`. The intermediate key is wiped.
    pub fn derive(psk: &Psk, salt: &[u8; SALT_LEN]) -> Result<Self> {
        let mut key = aead_key(psk, salt)?;
        let aead = Self::new(&key);
        key.zeroize();
        aead
    }

    /// Seal `in_out[..len - TAG_LEN]` in place and write the tag into the
    /// trailing `TAG_LEN` bytes.
    pub fn seal(&self, nonce: &mut Nonce, aad: &[u8], in_out: &mut [u8]) -> Result<()> {
        let (plain, tag_dst) = in_out
            .split_last_chunk_mut::<TAG_LEN>()
            .ok_or(Error::Truncated)?;
        let tag = self
            .key
            .seal_in_place_separate_tag(ring_nonce(nonce), Aad::from(aad), plain)
            .map_err(|_| Error::Aead)?;
        tag_dst.copy_from_slice(tag.as_ref());
        nonce.increment();
        Ok(())
    }

    /// Open `in_out[..len - TAG_LEN]` in place against the trailing tag.
    pub fn open(&self, nonce: &mut Nonce, aad: &[u8], in_out: &mut [u8]) -> Result<()> {
        let (cipher, tag) = in_out
            .split_last_chunk_mut::<TAG_LEN>()
            .ok_or(Error::Truncated)?;
        self.key
            .open_in_place_separate_tag(
                ring_nonce(nonce),
                Aad::from(aad),
                aead::Tag::from(*tag),
                cipher,
                0..,
            )
            .map_err(|_| Error::Aead)?;
        nonce.increment();
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
        let aead = Aes128Gcm::new(&[0u8; AES_128_KEY_LEN]).unwrap();
        let mut nonce = Nonce::new();
        let mut tag = [0u8; TAG_LEN];
        aead.seal(&mut nonce, &[], &mut tag).unwrap();
        assert_eq!(
            tag,
            [
                0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
                0x45, 0x5a
            ]
        );
        assert_eq!(nonce.as_bytes()[0], 1, "seal advances the nonce");
    }

    #[test]
    fn round_trip_and_tamper() {
        let aead = Aes128Gcm::new(&[0x11u8; AES_128_KEY_LEN]).unwrap();
        let mut sealed = [0u8; 5 + TAG_LEN];
        sealed[..5].copy_from_slice(b"hello");
        aead.seal(&mut Nonce::new(), &[], &mut sealed).unwrap();

        let mut buf = sealed;
        let mut nonce = Nonce::new();
        aead.open(&mut nonce, &[], &mut buf).unwrap();
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(nonce.as_bytes()[0], 1, "open advances the nonce");

        let mut bad = sealed;
        bad[5] ^= 1;
        let mut nonce = Nonce::new();
        assert_eq!(aead.open(&mut nonce, &[], &mut bad), Err(Error::Aead));
        assert_eq!(nonce, Nonce::new(), "failed open keeps the nonce");
    }

    #[test]
    fn debug_hides_key() {
        let aead = Aes128Gcm::new(&[0x42; AES_128_KEY_LEN]).unwrap();
        assert_eq!(format!("{aead:?}"), "Aes128Gcm");
    }
}

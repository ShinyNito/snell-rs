use argon2::{Algorithm, Argon2, Params, Version};
use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use std::ops::RangeFrom;
use zeroize::Zeroize;

use crate::error::{Argon2Error, Error, Result};

pub const SALT_SIZE: usize = 16;
pub const AEAD_TAG_SIZE: usize = 16;
pub const AES_128_KEY_SIZE: usize = 16;
pub const ARGON2_OUTPUT_SIZE: usize = 32;

const SNELL_ARGON2_MEMORY_KIB: u32 = 8;
const SNELL_ARGON2_ITERATIONS: u32 = 3;
const SNELL_ARGON2_PARALLELISM: u32 = 1;

pub struct Aes128GcmCrypto {
    key: LessSafeKey,
}

impl Aes128GcmCrypto {
    #[must_use]
    pub fn new(key: [u8; AES_128_KEY_SIZE]) -> Self {
        let key = UnboundKey::new(&AES_128_GCM, &key)
            .expect("Aes128GcmCrypto::new received a fixed-size AES-128 key");
        Self {
            key: LessSafeKey::new(key),
        }
    }

    pub fn from_psk_and_salt(psk: &[u8], salt: &[u8; SALT_SIZE]) -> Result<Self> {
        Ok(Self::new(derive_aes128_key(psk, salt)?))
    }

    pub fn encrypt_detached(&self, nonce: &[u8; 12], data: &mut [u8]) -> Result<[u8; 16]> {
        self.encrypt_detached_with_aad(nonce, data, &[])
    }

    pub fn encrypt_detached_with_aad(
        &self,
        nonce: &[u8; 12],
        data: &mut [u8],
        aad: &[u8],
    ) -> Result<[u8; 16]> {
        let tag = self
            .key
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(*nonce), Aad::from(aad), data)
            .map_err(|_| Error::AuthenticationFailed)?;
        let mut out = [0; AEAD_TAG_SIZE];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }

    pub fn decrypt_within<'a>(
        &self,
        nonce: &[u8; 12],
        data_and_tag: &'a mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<&'a mut [u8]> {
        self.decrypt_within_with_aad(nonce, data_and_tag, ciphertext_and_tag, &[])
    }

    pub fn decrypt_within_with_aad<'a>(
        &self,
        nonce: &[u8; 12],
        data_and_tag: &'a mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
        aad: &[u8],
    ) -> Result<&'a mut [u8]> {
        self.key
            .open_within(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                data_and_tag,
                ciphertext_and_tag,
            )
            .map_err(|_| Error::AuthenticationFailed)
    }
}

pub fn derive_aes128_key(psk: &[u8], salt: &[u8; SALT_SIZE]) -> Result<[u8; AES_128_KEY_SIZE]> {
    let params = Params::new(
        SNELL_ARGON2_MEMORY_KIB,
        SNELL_ARGON2_ITERATIONS,
        SNELL_ARGON2_PARALLELISM,
        Some(ARGON2_OUTPUT_SIZE),
    )
    .map_err(Argon2Error)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0; ARGON2_OUTPUT_SIZE];
    argon2
        .hash_password_into(psk, salt, &mut output)
        .map_err(Argon2Error)?;

    let mut key = [0; AES_128_KEY_SIZE];
    key.copy_from_slice(&output[..AES_128_KEY_SIZE]);
    output.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::{Aes128GcmCrypto, SALT_SIZE, derive_aes128_key};

    #[test]
    fn derives_stable_key() {
        let salt = [7u8; SALT_SIZE];
        let first = derive_aes128_key(b"password", &salt).unwrap();
        let second = derive_aes128_key(b"password", &salt).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn encrypts_and_decrypts_in_place() {
        let salt = [9u8; SALT_SIZE];
        let crypto = Aes128GcmCrypto::from_psk_and_salt(b"password", &salt).unwrap();
        let nonce = [0u8; 12];
        let mut data = *b"hello snell";

        let tag = crypto.encrypt_detached(&nonce, &mut data).unwrap();
        assert_ne!(&data, b"hello snell");

        let mut data_and_tag = data.to_vec();
        data_and_tag.extend_from_slice(&tag);

        let plaintext = crypto
            .decrypt_within(&nonce, &mut data_and_tag, 0..)
            .unwrap();
        assert_eq!(plaintext, b"hello snell");
    }

    #[test]
    fn decrypts_within_shifted_payload_in_place() {
        let salt = [9u8; SALT_SIZE];
        let crypto = Aes128GcmCrypto::from_psk_and_salt(b"password", &salt).unwrap();
        let nonce = [0u8; 12];
        let mut data = b"hello snell".to_vec();

        let tag = crypto.encrypt_detached(&nonce, &mut data).unwrap();
        let mut shifted = vec![0xaa; 7];
        shifted.extend_from_slice(&data);
        shifted.extend_from_slice(&tag);

        let plaintext = crypto.decrypt_within(&nonce, &mut shifted, 7..).unwrap();
        assert_eq!(plaintext, b"hello snell");
        assert_eq!(&shifted[..b"hello snell".len()], b"hello snell");
    }
}

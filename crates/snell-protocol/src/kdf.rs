use argon2::{Algorithm, Argon2, Params, Version};
use blake2::Blake2b;
use blake2::digest::Digest;
use blake2::digest::consts::U32;
use zeroize::Zeroize;

use crate::{
    AES_128_KEY_LEN, ARGON2_M_COST_KIB, ARGON2_OUTPUT_LEN, ARGON2_P_COST, ARGON2_T_COST, Error,
    PROFILE_SEED_24, Psk, Result, SALT_LEN,
};

/// BLAKE2b-256 over the profile seed and PSK. [`Psk`] already enforces the length.
pub(crate) fn profile_secret(psk: &Psk) -> [u8; 32] {
    Blake2b::<U32>::new()
        .chain_update(PROFILE_SEED_24)
        .chain_update(psk.as_bytes())
        .finalize()
        .into()
}

fn aead_key_raw(psk: &Psk, salt: &[u8; SALT_LEN]) -> Result<[u8; ARGON2_OUTPUT_LEN]> {
    let params = Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|_| Error::Kdf)?;
    let mut out = [0u8; ARGON2_OUTPUT_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(psk.as_bytes(), salt, &mut out)
        .map_err(|_| Error::Kdf)?;
    Ok(out)
}

/// Argon2id key for one session salt; AES-128-GCM uses the first 16 bytes.
pub fn aead_key(psk: &Psk, salt: &[u8; SALT_LEN]) -> Result<[u8; AES_128_KEY_LEN]> {
    let mut raw = aead_key_raw(psk, salt)?;
    let key = *raw
        .first_chunk::<AES_128_KEY_LEN>()
        .expect("Argon2 output covers the AES key");
    raw.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_key_is_first_16_of_raw() {
        let psk = Psk::new(b"16-byte-psk-test").unwrap();
        let salt = [0xAA; SALT_LEN];
        let raw = aead_key_raw(&psk, &salt).unwrap();
        let key = aead_key(&psk, &salt).unwrap();
        assert_eq!(raw[..16], key);
    }
}

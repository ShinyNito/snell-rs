use argon2::{Algorithm, Argon2, Params, Version};
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use zeroize::Zeroize;

use crate::{
    AES_128_KEY_LEN, ARGON2_M_COST_KIB, ARGON2_OUTPUT_LEN, ARGON2_P_COST, ARGON2_T_COST, Error,
    PROFILE_SEED_24, PSK_MAX_LEN, PSK_MIN_LEN, Result, SALT_LEN,
};

pub fn profile_secret(psk: &[u8]) -> Result<[u8; 32]> {
    check_psk(psk)?;
    let mut hasher = Blake2bVar::new(32).map_err(|_| Error::Kdf)?;
    Update::update(&mut hasher, &PROFILE_SEED_24);
    Update::update(&mut hasher, psk);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).map_err(|_| Error::Kdf)?;
    Ok(out)
}

pub fn aead_key_raw(psk: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; ARGON2_OUTPUT_LEN]> {
    check_psk(psk)?;
    let params = Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|_| Error::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; ARGON2_OUTPUT_LEN];
    argon
        .hash_password_into(psk, salt, &mut out)
        .map_err(|_| Error::Kdf)?;
    Ok(out)
}

pub fn aead_key(psk: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; AES_128_KEY_LEN]> {
    let mut raw = aead_key_raw(psk, salt)?;
    let mut key = [0u8; AES_128_KEY_LEN];
    key.copy_from_slice(&raw[..AES_128_KEY_LEN]);
    raw.zeroize();
    Ok(key)
}

fn check_psk(psk: &[u8]) -> Result<()> {
    if (PSK_MIN_LEN..=PSK_MAX_LEN).contains(&psk.len()) {
        Ok(())
    } else {
        Err(Error::InvalidPskLen(psk.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_secret_is_deterministic() {
        let psk = b"16-byte-psk-test";
        assert_eq!(profile_secret(psk).unwrap(), profile_secret(psk).unwrap());
    }

    #[test]
    fn aead_key_is_first_16_of_raw() {
        let psk = b"16-byte-psk-test";
        let salt = [0xAA; SALT_LEN];
        let raw = aead_key_raw(psk, &salt).unwrap();
        let key = aead_key(psk, &salt).unwrap();
        assert_eq!(raw[..16], key);
    }

    #[test]
    fn seed24_matches_documented_bytes() {
        assert_eq!(PROFILE_SEED_24[0..4], [0x8d, 0x41, 0xa7, 0x13]);
    }
}

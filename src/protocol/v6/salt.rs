use super::*;

#[doc(hidden)]
pub fn split_salt_block<'a>(
    profile: &V6Profile,
    frame: &'a [u8],
) -> Result<([u8; SALT_SIZE], &'a [u8])> {
    let salt_block_len = profile.salt_block_len();
    if frame.len() < salt_block_len {
        return Err(Error::FrameTooShort);
    }
    let salt = profile.extract_salt(&frame[..salt_block_len])?;
    Ok((salt, &frame[salt_block_len..]))
}

pub(in crate::protocol::v6) fn salt_positions(
    ns_salt: u64,
    salt_block_len: usize,
    mix_rounds_handshake: u32,
) -> [usize; SALT_SIZE] {
    let mut arr = (0..salt_block_len).collect::<Vec<_>>();
    for round in 0..mix_rounds_handshake {
        for i in 0..salt_block_len {
            let raw = salt_shuffle_prf(ns_salt, MIX_HANDSHAKE_DOMAIN + round, i as u32);
            let j = i + raw as usize % (salt_block_len - i);
            arr.swap(i, j);
        }
    }
    let mut positions = [0; SALT_SIZE];
    positions.copy_from_slice(&arr[..SALT_SIZE]);
    positions
}

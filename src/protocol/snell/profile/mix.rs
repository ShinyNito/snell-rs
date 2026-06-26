use super::labels::MIX_OFFSET;
use super::{ShapedProfile, usize_from_u32};

const MIX_ROUND_MOD3_RECIPROCAL: u32 = 171;
const MIX_ROUND_MOD3_SHIFT: u32 = 9;
const MIX_ROUND_BYTE_MASK: u32 = 0xff;

pub(crate) fn mix_padding_payload(
    profile: &ShapedProfile,
    seq: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
) {
    let n = padding.len().min(payload_cipher.len());
    if n == 0 {
        return;
    }
    for round in 0..profile.mix_rounds {
        match profile.mix_mode {
            0 => mix_fixed_stride(profile, round, padding, payload_cipher, n),
            1 => mix_alternating_block(profile, round, padding, payload_cipher, n),
            2 => mix_prf_stride(profile, seq, round, padding, payload_cipher, n),
            _ => unreachable!("mix mode is derived modulo 3"),
        }
    }
}

pub(crate) fn mix_padding_payload_split(
    profile: &ShapedProfile,
    seq: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    payload_tag: &mut [u8],
) {
    let n = padding.len().min(payload_cipher.len() + payload_tag.len());
    if n == 0 {
        return;
    }
    for round in 0..profile.mix_rounds {
        match profile.mix_mode {
            0 => mix_fixed_stride_split(profile, round, padding, payload_cipher, payload_tag, n),
            1 => {
                mix_alternating_block_split(profile, round, padding, payload_cipher, payload_tag, n)
            }
            2 => mix_prf_stride_split(profile, seq, round, padding, payload_cipher, payload_tag, n),
            _ => unreachable!("mix mode is derived modulo 3"),
        }
    }
}

fn mix_fixed_stride(
    profile: &ShapedProfile,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
) {
    let stride = (profile.mix_stride + usize_from_u32(mix_round_delta(round))).max(1);
    if stride == 1 {
        padding[..n].swap_with_slice(&mut payload_cipher[..n]);
        return;
    }

    let mut off = profile.mix_offset_base % stride;
    while off < n {
        std::mem::swap(&mut padding[off], &mut payload_cipher[off]);
        off += stride;
    }
}

fn mix_fixed_stride_split(
    profile: &ShapedProfile,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    payload_tag: &mut [u8],
    n: usize,
) {
    let stride = (profile.mix_stride + usize_from_u32(mix_round_delta(round))).max(1);
    if stride == 1 {
        swap_payload_range_split(padding, payload_cipher, payload_tag, 0, n);
        return;
    }

    let mut off = profile.mix_offset_base % stride;
    while off < n {
        swap_payload_byte_split(padding, payload_cipher, payload_tag, off);
        off += stride;
    }
}

fn mix_alternating_block(
    profile: &ShapedProfile,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
) {
    let block = profile.mix_block;
    let mut off = (round as usize & 1) * block;
    while off + block <= n {
        let end = off + block;
        padding[off..end].swap_with_slice(&mut payload_cipher[off..end]);
        off += block * 2;
    }
}

fn mix_alternating_block_split(
    profile: &ShapedProfile,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    payload_tag: &mut [u8],
    n: usize,
) {
    let block = profile.mix_block;
    let mut off = (round as usize & 1) * block;
    while off + block <= n {
        let end = off + block;
        swap_payload_range_split(padding, payload_cipher, payload_tag, off, end);
        off += block * 2;
    }
}

fn mix_prf_stride(
    profile: &ShapedProfile,
    seq: u32,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
) {
    let stride = (profile.mix_stride + usize_from_u32(mix_round_delta(round))).max(1);
    let mut off =
        (profile.prf32(MIX_OFFSET, seq, round) as usize + profile.mix_offset_base) % stride;
    if stride == 1 {
        padding[..n].swap_with_slice(&mut payload_cipher[..n]);
        return;
    }

    while off < n {
        std::mem::swap(&mut padding[off], &mut payload_cipher[off]);
        off += stride;
    }
}

fn mix_prf_stride_split(
    profile: &ShapedProfile,
    seq: u32,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    payload_tag: &mut [u8],
    n: usize,
) {
    let stride = (profile.mix_stride + usize_from_u32(mix_round_delta(round))).max(1);
    let mut off =
        (profile.prf32(MIX_OFFSET, seq, round) as usize + profile.mix_offset_base) % stride;
    if stride == 1 {
        swap_payload_range_split(padding, payload_cipher, payload_tag, 0, n);
        return;
    }

    while off < n {
        swap_payload_byte_split(padding, payload_cipher, payload_tag, off);
        off += stride;
    }
}

fn swap_payload_range_split(
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    payload_tag: &mut [u8],
    start: usize,
    end: usize,
) {
    let mut off = start;
    if off < payload_cipher.len() {
        let cipher_end = end.min(payload_cipher.len());
        padding[off..cipher_end].swap_with_slice(&mut payload_cipher[off..cipher_end]);
        off = cipher_end;
    }
    if off < end {
        let tag_start = off - payload_cipher.len();
        let tag_end = end - payload_cipher.len();
        padding[off..end].swap_with_slice(&mut payload_tag[tag_start..tag_end]);
    }
}

fn swap_payload_byte_split(
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    payload_tag: &mut [u8],
    off: usize,
) {
    if off < payload_cipher.len() {
        std::mem::swap(&mut padding[off], &mut payload_cipher[off]);
    } else {
        std::mem::swap(
            &mut padding[off],
            &mut payload_tag[off - payload_cipher.len()],
        );
    }
}

const fn mix_round_delta(round: u32) -> u32 {
    let quotient = (MIX_ROUND_MOD3_RECIPROCAL * round) >> MIX_ROUND_MOD3_SHIFT;
    (round - 3 * quotient) & MIX_ROUND_BYTE_MASK
}

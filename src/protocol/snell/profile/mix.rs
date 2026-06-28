use super::labels::MIX_OFFSET;
use super::{ShapedProfile, usize_from_u32};

const MIX_ROUND_MOD3_RECIPROCAL: u32 = 171;
const MIX_ROUND_MOD3_SHIFT: u32 = 9;
const MIX_ROUND_BYTE_MASK: u32 = 0xff;

macro_rules! swap_payload_stride_split {
    ($padding:ident, $payload_cipher:ident, $payload_tag:ident, $n:expr, $off:expr, $stride:expr) => {{
        let n = $n;
        let mut off = $off;
        let stride = $stride;
        let cipher_len = $payload_cipher.len();
        let cipher_limit = n.min(cipher_len);

        while off < cipher_limit {
            std::mem::swap(&mut $padding[off], &mut $payload_cipher[off]);
            off += stride;
        }

        while off < n {
            let tag_off = off - cipher_len;
            std::mem::swap(&mut $padding[off], &mut $payload_tag[tag_off]);
            off += stride;
        }
    }};
}

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
    match profile.mix_mode {
        0 => {
            for round in 0..profile.mix_rounds {
                mix_fixed_stride(profile, round, padding, payload_cipher, n);
            }
        }
        1 => {
            for round in 0..profile.mix_rounds {
                mix_alternating_block(profile, round, padding, payload_cipher, n);
            }
        }
        2 => {
            for round in 0..profile.mix_rounds {
                mix_prf_stride(profile, seq, round, padding, payload_cipher, n);
            }
        }
        _ => unreachable!("mix mode is derived modulo 3"),
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
    match profile.mix_mode {
        0 => {
            for round in 0..profile.mix_rounds {
                mix_fixed_stride_split(profile, round, padding, payload_cipher, payload_tag, n);
            }
        }
        1 => {
            for round in 0..profile.mix_rounds {
                mix_alternating_block_split(profile, round, padding, payload_cipher, payload_tag, n)
            }
        }
        2 => {
            for round in 0..profile.mix_rounds {
                mix_prf_stride_split(profile, seq, round, padding, payload_cipher, payload_tag, n);
            }
        }
        _ => unreachable!("mix mode is derived modulo 3"),
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

    let off = profile.mix_offset_base % stride;
    swap_payload_stride_split!(padding, payload_cipher, payload_tag, n, off, stride);
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
    let step = block * 2;
    let cipher_len = payload_cipher.len();
    let cipher_limit = n.min(cipher_len);
    let mut off = (round as usize & 1) * block;

    while off + block <= cipher_limit {
        let end = off + block;
        padding[off..end].swap_with_slice(&mut payload_cipher[off..end]);
        off += step;
    }

    if off + block <= n && off < cipher_len {
        let end = off + block;
        swap_payload_range_split(padding, payload_cipher, payload_tag, off, end);
        off += step;
    }

    while off + block <= n {
        let end = off + block;
        let tag_start = off - cipher_len;
        let tag_end = tag_start + block;
        padding[off..end].swap_with_slice(&mut payload_tag[tag_start..tag_end]);
        off += step;
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
    let off = (profile.prf32(MIX_OFFSET, seq, round) as usize + profile.mix_offset_base) % stride;
    if stride == 1 {
        swap_payload_range_split(padding, payload_cipher, payload_tag, 0, n);
        return;
    }

    swap_payload_stride_split!(padding, payload_cipher, payload_tag, n, off, stride);
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

const fn mix_round_delta(round: u32) -> u32 {
    let quotient = (MIX_ROUND_MOD3_RECIPROCAL * round) >> MIX_ROUND_MOD3_SHIFT;
    (round - 3 * quotient) & MIX_ROUND_BYTE_MASK
}

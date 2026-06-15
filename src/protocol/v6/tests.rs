#[cfg(test)]
use bytes::BytesMut;

use super::{
    V6_HEADER_CIPHER_SIZE, V6FrameDecoder, V6FrameEncoder, V6Profile, V6SaltReplayCache,
    mix_padding_payload, split_salt_block,
};
use crate::error::Error;
use crate::test_support::TEST_PSK;

fn encode_test_frame(
    profile: &V6Profile,
    encoder: &mut V6FrameEncoder,
    payload: &[u8],
    wire: &mut BytesMut,
) -> usize {
    let start_len = wire.len();
    let mut head = BytesMut::new();
    let mut body = BytesMut::from(payload);
    encoder
        .encode_payload_in_place(profile, &mut body, payload.len(), &mut head)
        .unwrap();
    wire.extend_from_slice(&head);
    wire.extend_from_slice(&body);
    wire.len() - start_len
}

#[test]
fn derives_stable_profile_from_psk() {
    let first = V6Profile::derive(TEST_PSK);
    let second = V6Profile::derive(TEST_PSK);
    let other = V6Profile::derive(b"other psk");

    assert_eq!(first.profile_id, second.profile_id);
    assert_ne!(first.profile_id, other.profile_id);
    assert!(first.salt_block_len() >= 32);
    assert!(first.record_prefix_len(0) >= 8);
}

#[test]
fn salt_block_round_trips_salt() {
    let profile = V6Profile::derive(TEST_PSK);
    let salt = [0x5a; 16];
    let mut block = BytesMut::new();

    let block_range = profile.append_salt_block(&salt, &mut block);
    let extracted = profile.extract_salt(&block).unwrap();

    assert_eq!(block_range, 0..profile.salt_block_len());
    assert_eq!(extracted, salt);
}

#[test]
fn official_fill_is_stable_and_profile_specific() {
    let first_profile = V6Profile::derive(TEST_PSK);
    let second_profile = V6Profile::derive(TEST_PSK);
    let other_profile = V6Profile::derive(b"other psk");
    let mut first = BytesMut::new();
    let mut second = BytesMut::new();
    let mut other = BytesMut::new();

    first_profile.append_official_fill(7, 96, &mut first);
    second_profile.append_official_fill(7, 96, &mut second);
    other_profile.append_official_fill(7, 96, &mut other);

    assert_eq!(first, second);
    assert_ne!(first, other);
}

#[test]
fn mixing_is_self_inverse() {
    for psk in [
        b"mix-mode-a" as &[u8],
        b"mix-mode-b",
        b"mix-mode-c",
        b"mix-mode-d",
    ] {
        let profile = V6Profile::derive(psk);
        let mut padding = (0..128u8).collect::<Vec<_>>();
        let mut payload = (128..=255u8).collect::<Vec<_>>();
        let original_padding = padding.clone();
        let original_payload = payload.clone();

        mix_padding_payload(&profile, 3, &mut padding, &mut payload);
        mix_padding_payload(&profile, 3, &mut padding, &mut payload);

        assert_eq!(padding, original_padding);
        assert_eq!(payload, original_payload);
    }
}

#[test]
fn optimized_mixing_matches_reference() {
    let mut profiles = Vec::new();
    let mut seen = [false; 3];

    for index in 0..512 {
        let psk = format!("mix-profile-{index}");
        let profile = V6Profile::derive(psk.as_bytes());
        let mode = profile.mix_mode as usize;
        if !seen[mode] {
            seen[mode] = true;
            profiles.push(profile);
        }
        if seen.iter().all(|seen| *seen) {
            break;
        }
    }
    assert!(seen.iter().all(|seen| *seen));

    for profile in profiles {
        for seq in [0, 1, 3, 17, 255] {
            for len in [0, 1, 7, 8, 31, 64, 127, 512, 1500] {
                let mut actual_padding = patterned_bytes(len, 0x31);
                let mut actual_payload = patterned_bytes(len + 17, 0xa7);
                let mut expected_padding = actual_padding.clone();
                let mut expected_payload = actual_payload.clone();

                mix_padding_payload(&profile, seq, &mut actual_padding, &mut actual_payload);
                reference_mix_padding_payload(
                    &profile,
                    seq,
                    &mut expected_padding,
                    &mut expected_payload,
                );

                assert_eq!(actual_padding, expected_padding);
                assert_eq!(actual_payload, expected_payload);
            }
        }
    }
}

fn patterned_bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_add((i as u8).wrapping_mul(37)) ^ ((i >> 3) as u8))
        .collect()
}

fn reference_mix_padding_payload(
    profile: &V6Profile,
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
            0 => reference_mix_fixed_stride(profile, round, padding, payload_cipher, n),
            1 => reference_mix_alternating_block(profile, round, padding, payload_cipher, n),
            2 => reference_mix_prf_stride(profile, seq, round, padding, payload_cipher, n),
            _ => unreachable!("mix mode is derived modulo 3"),
        }
    }
}

fn reference_mix_fixed_stride(
    profile: &V6Profile,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
) {
    let rr = reference_mix_round_delta(round);
    let stride = (profile.mix_stride + rr as usize).max(1);
    let mut off = profile.mix_offset_base % stride;
    while off < n {
        std::mem::swap(&mut padding[off], &mut payload_cipher[off]);
        off += stride;
    }
}

fn reference_mix_alternating_block(
    profile: &V6Profile,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
) {
    let block = profile.mix_block;
    let mut off = (round as usize & 1) * block;
    while off + block <= n {
        for index in off..off + block {
            std::mem::swap(&mut padding[index], &mut payload_cipher[index]);
        }
        off += 2 * block;
    }
}

fn reference_mix_prf_stride(
    profile: &V6Profile,
    seq: u32,
    round: u32,
    padding: &mut [u8],
    payload_cipher: &mut [u8],
    n: usize,
) {
    let rr = reference_mix_round_delta(round);
    let stride = (profile.mix_stride + rr as usize).max(1);
    let mut off = (profile.prf32(super::LABEL_MIX_OFFSET, seq, round) as usize
        + profile.mix_offset_base)
        % stride;
    while off < n {
        std::mem::swap(&mut padding[off], &mut payload_cipher[off]);
        off += stride;
    }
}

fn reference_mix_round_delta(round: u32) -> u32 {
    let quotient = (super::MIX_ROUND_MOD3_RECIPROCAL * round) >> super::MIX_ROUND_MOD3_SHIFT;
    (round - 3 * quotient) & super::MIX_ROUND_BYTE_MASK
}

#[test]
fn encodes_and_decodes_payload_frame() {
    let psk = TEST_PSK;
    let salt = [3u8; 16];
    let payload = b"GET / HTTP/1.1\r\n\r\n";
    let profile = V6Profile::derive(psk);
    let mut encoder = V6FrameEncoder::with_salt(psk, salt).unwrap();
    let mut wire = BytesMut::with_capacity(512);

    let written = encode_test_frame(&profile, &mut encoder, payload, &mut wire);
    assert_eq!(written, wire.len());

    let (decoded_salt, frame) = split_salt_block(&profile, &wire).unwrap();
    assert_eq!(decoded_salt, salt);

    let mut frame = BytesMut::from(frame);
    let mut decoder = V6FrameDecoder::new(psk, decoded_salt).unwrap();
    let prefix_len = decoder.next_prefix_len(&profile);
    let prefix = frame.split_to(prefix_len);
    let mut header_cipher = [0; V6_HEADER_CIPHER_SIZE];
    header_cipher.copy_from_slice(&frame[..V6_HEADER_CIPHER_SIZE]);
    let header = decoder.decode_header(&prefix, &mut header_cipher).unwrap();
    let mut body = frame.split_off(V6_HEADER_CIPHER_SIZE);
    let decoded = decoder
        .decode_payload_in_place(&profile, header, &mut body)
        .unwrap();

    assert_eq!(decoded, payload);
    assert_eq!(encoder.seq(), 1);
    assert_eq!(decoder.seq(), 1);
}

#[test]
fn rejects_header_when_prefix_aad_changes() {
    let psk = TEST_PSK;
    let salt = [9u8; 16];
    let profile = V6Profile::derive(psk);
    let mut encoder = V6FrameEncoder::with_salt(psk, salt).unwrap();
    let mut wire = BytesMut::new();

    encode_test_frame(&profile, &mut encoder, b"hello", &mut wire);
    let (decoded_salt, frame) = split_salt_block(&profile, &wire).unwrap();
    let mut frame = BytesMut::from(frame);
    let mut decoder = V6FrameDecoder::new(psk, decoded_salt).unwrap();
    let prefix_len = decoder.next_prefix_len(&profile);
    let mut prefix = frame.split_to(prefix_len);
    prefix[0] ^= 0xff;
    let mut header_cipher = [0; V6_HEADER_CIPHER_SIZE];
    header_cipher.copy_from_slice(&frame[..V6_HEADER_CIPHER_SIZE]);

    assert!(matches!(
        decoder.decode_header(&prefix, &mut header_cipher),
        Err(Error::AuthenticationFailed)
    ));
}

#[test]
fn decodes_zero_payload_as_zero_chunk_even_with_padding() {
    let psk = TEST_PSK;
    let salt = [2u8; 16];
    let profile = V6Profile::derive(psk);
    let mut encoder = V6FrameEncoder::with_salt(psk, salt).unwrap();
    let mut wire = BytesMut::new();

    encode_test_frame(&profile, &mut encoder, b"", &mut wire);
    let (decoded_salt, frame) = split_salt_block(&profile, &wire).unwrap();
    let mut frame = BytesMut::from(frame);
    let mut decoder = V6FrameDecoder::new(psk, decoded_salt).unwrap();
    let prefix_len = decoder.next_prefix_len(&profile);
    let prefix = frame.split_to(prefix_len);
    let mut header_cipher = [0; V6_HEADER_CIPHER_SIZE];
    header_cipher.copy_from_slice(&frame[..V6_HEADER_CIPHER_SIZE]);
    let header = decoder.decode_header(&prefix, &mut header_cipher).unwrap();
    let mut body = frame.split_off(V6_HEADER_CIPHER_SIZE);

    assert!(header.padding_len > 0);
    assert!(matches!(
        decoder.decode_payload_in_place(&profile, header, &mut body),
        Err(Error::ZeroChunk)
    ));
}

#[test]
fn salt_replay_cache_rejects_recent_reuse_and_evicts_oldest() {
    let cache = V6SaltReplayCache::new(2);
    let first = [1u8; 16];
    let second = [2u8; 16];
    let third = [3u8; 16];

    cache.remember(first).unwrap();
    assert!(matches!(cache.remember(first), Err(Error::SaltReplay)));

    cache.remember(second).unwrap();
    cache.remember(third).unwrap();
    cache.remember(first).unwrap();
}

#[test]
fn salt_replay_cache_capacity_one_replaces_previous_salt() {
    let cache = V6SaltReplayCache::new(1);
    let first = [1u8; 16];
    let second = [2u8; 16];

    cache.remember(first).unwrap();
    assert!(matches!(cache.remember(first), Err(Error::SaltReplay)));

    cache.remember(second).unwrap();
    cache.remember(first).unwrap();
    assert!(matches!(cache.remember(first), Err(Error::SaltReplay)));
}

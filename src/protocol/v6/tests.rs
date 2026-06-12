#[cfg(test)]
use bytes::BytesMut;

use super::{
    V6_HEADER_CIPHER_SIZE, V6FrameDecoder, V6FrameEncoder, V6Profile, V6SaltReplayCache,
    mix_padding_payload, split_salt_block,
};
use crate::error::Error;

fn encode_test_frame(encoder: &mut V6FrameEncoder, payload: &[u8], wire: &mut BytesMut) -> usize {
    let start_len = wire.len();
    let mut head = BytesMut::new();
    let mut body = BytesMut::from(payload);
    encoder
        .encode_payload_in_place(&mut body, payload.len(), &mut head)
        .unwrap();
    wire.extend_from_slice(&head);
    wire.extend_from_slice(&body);
    wire.len() - start_len
}

#[test]
fn derives_stable_profile_from_psk() {
    let first = V6Profile::derive(b"test psk");
    let second = V6Profile::derive(b"test psk");
    let other = V6Profile::derive(b"other psk");

    assert_eq!(first.profile_id, second.profile_id);
    assert_ne!(first.profile_id, other.profile_id);
    assert!(first.salt_block_len() >= 32);
    assert!(first.record_prefix_len(0) >= 8);
}

#[test]
fn salt_block_round_trips_salt() {
    let profile = V6Profile::derive(b"test psk");
    let salt = [0x5a; 16];
    let mut block = BytesMut::new();

    let block_range = profile.append_salt_block(&salt, &mut block);
    let extracted = profile.extract_salt(&block).unwrap();

    assert_eq!(block_range, 0..profile.salt_block_len());
    assert_eq!(extracted, salt);
}

#[test]
fn official_fill_is_stable_and_profile_specific() {
    let first_profile = V6Profile::derive(b"test psk");
    let second_profile = V6Profile::derive(b"test psk");
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
fn encodes_and_decodes_payload_frame() {
    let psk = b"test psk";
    let salt = [3u8; 16];
    let payload = b"GET / HTTP/1.1\r\n\r\n";
    let mut encoder = V6FrameEncoder::with_salt(psk, salt).unwrap();
    let mut wire = BytesMut::with_capacity(512);

    let written = encode_test_frame(&mut encoder, payload, &mut wire);
    assert_eq!(written, wire.len());

    let profile = V6Profile::derive(psk);
    let (decoded_salt, frame) = split_salt_block(&profile, &wire).unwrap();
    assert_eq!(decoded_salt, salt);

    let mut frame = BytesMut::from(frame);
    let mut decoder = V6FrameDecoder::new(psk, decoded_salt).unwrap();
    let prefix_len = decoder.next_prefix_len();
    let prefix = frame.split_to(prefix_len);
    let mut header_cipher = [0; V6_HEADER_CIPHER_SIZE];
    header_cipher.copy_from_slice(&frame[..V6_HEADER_CIPHER_SIZE]);
    let header = decoder.decode_header(&prefix, &mut header_cipher).unwrap();
    let mut body = frame.split_off(V6_HEADER_CIPHER_SIZE);
    let decoded = decoder.decode_payload_in_place(header, &mut body).unwrap();

    assert_eq!(decoded, payload);
    assert_eq!(encoder.seq(), 1);
    assert_eq!(decoder.seq(), 1);
}

#[test]
fn rejects_header_when_prefix_aad_changes() {
    let psk = b"test psk";
    let salt = [9u8; 16];
    let mut encoder = V6FrameEncoder::with_salt(psk, salt).unwrap();
    let mut wire = BytesMut::new();

    encode_test_frame(&mut encoder, b"hello", &mut wire);
    let profile = V6Profile::derive(psk);
    let (decoded_salt, frame) = split_salt_block(&profile, &wire).unwrap();
    let mut frame = BytesMut::from(frame);
    let mut decoder = V6FrameDecoder::new(psk, decoded_salt).unwrap();
    let prefix_len = decoder.next_prefix_len();
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
    let psk = b"test psk";
    let salt = [2u8; 16];
    let mut encoder = V6FrameEncoder::with_salt(psk, salt).unwrap();
    let mut wire = BytesMut::new();

    encode_test_frame(&mut encoder, b"", &mut wire);
    let profile = V6Profile::derive(psk);
    let (decoded_salt, frame) = split_salt_block(&profile, &wire).unwrap();
    let mut frame = BytesMut::from(frame);
    let mut decoder = V6FrameDecoder::new(psk, decoded_salt).unwrap();
    let prefix_len = decoder.next_prefix_len();
    let prefix = frame.split_to(prefix_len);
    let mut header_cipher = [0; V6_HEADER_CIPHER_SIZE];
    header_cipher.copy_from_slice(&frame[..V6_HEADER_CIPHER_SIZE]);
    let header = decoder.decode_header(&prefix, &mut header_cipher).unwrap();
    let mut body = frame.split_off(V6_HEADER_CIPHER_SIZE);

    assert!(header.padding_len > 0);
    assert!(matches!(
        decoder.decode_payload_in_place(header, &mut body),
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

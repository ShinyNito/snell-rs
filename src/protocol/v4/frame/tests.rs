use bytes::BytesMut;

use super::{
    V4_HEADER_CIPHER_SIZE, V4FrameDecoder, V4FrameEncoder, V4PaddingMode, count_one_bits,
    count_v4_payload_ones, fill_padding_with_sampled_bits, make_v4_padding, split_salt,
    swap_padding, v4_padding_target_ones_for_ratio,
};
use crate::error::Error;
use crate::test_support::TEST_PSK;

fn encode_test_frame(encoder: &mut V4FrameEncoder, payload: &[u8], wire: &mut BytesMut) -> usize {
    let start_len = wire.len();
    let mut head = BytesMut::new();
    if payload.is_empty() {
        encoder.encode_empty_frame(&mut head).unwrap();
        wire.extend_from_slice(&head);
    } else {
        let mut body = BytesMut::from(payload);
        encoder
            .encode_payload_in_place(&mut body, payload.len(), &mut head)
            .unwrap();
        wire.extend_from_slice(&head);
        wire.extend_from_slice(&body);
    }
    wire.len() - start_len
}

#[test]
fn swaps_every_other_byte_until_shorter_side() {
    let mut padding = [1, 2, 3, 4, 5];
    let mut payload = [10, 20, 30];
    swap_padding(&mut padding, &mut payload);
    assert_eq!(padding, [10, 2, 30, 4, 5]);
    assert_eq!(payload, [1, 20, 3]);
}

#[test]
fn counts_payload_ones_on_four_byte_aligned_prefix() {
    let payload_cipher = [0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff];

    assert_eq!(count_v4_payload_ones(&payload_cipher), 8);
}

#[test]
fn counts_one_bits_with_word_chunks_and_tail() {
    let bytes = [
        0xff, 0x0f, 0x00, 0x80, 0x55, 0xaa, 0x33, 0xcc, 0x01, 0x03, 0x07,
    ];

    assert_eq!(count_one_bits(&bytes), 35);
}

#[test]
fn target_ones_uses_target_ratio_over_padding_and_payload_bits() {
    let target = v4_padding_target_ones_for_ratio(8, 16, 48, 0.4);

    assert_eq!(target, Some(6));
}

#[test]
fn target_ones_rejects_impossible_padding_bit_count() {
    let target = v4_padding_target_ones_for_ratio(1, 16, 120, 0.4);

    assert_eq!(target, None);
}

#[test]
fn sampled_padding_has_exact_target_ones() {
    let mut padding = [0; 32];

    fill_padding_with_sampled_bits(&mut padding, 101);

    assert_eq!(count_one_bits(&padding), 101);
}

#[test]
fn make_padding_uses_bit_ratio_inside_payload_ratio_window() {
    let mut padding = [0; 8];
    let payload_cipher = [0xff, 0x00, 0xff, 0x00];

    let mode = make_v4_padding(&mut padding, &payload_cipher).unwrap();
    let padding_ones = count_one_bits(&padding);
    let min_target =
        v4_padding_target_ones_for_ratio(padding.len(), payload_cipher.len(), 16, 1.6).unwrap();
    let max_target =
        v4_padding_target_ones_for_ratio(padding.len(), payload_cipher.len(), 16, 1.7).unwrap();

    assert_eq!(mode, V4PaddingMode::BitRatio);
    assert!(padding_ones >= min_target);
    assert!(padding_ones <= max_target);
}

#[test]
fn make_padding_falls_back_to_random_outside_payload_ratio_window() {
    let mut padding = [0; 8];
    let payload_cipher = [0; 4];

    let mode = make_v4_padding(&mut padding, &payload_cipher).unwrap();

    assert_eq!(mode, V4PaddingMode::Random);
}

#[test]
fn encodes_and_decodes_payload_frame() {
    let psk = TEST_PSK;
    let salt = [3u8; 16];
    let payload = b"GET / HTTP/1.1\r\n\r\n";
    let mut encoder = V4FrameEncoder::with_salt_and_initial_padding(psk, salt, 8).unwrap();
    let mut wire = BytesMut::with_capacity(128);

    let written = encode_test_frame(&mut encoder, payload, &mut wire);
    assert_eq!(written, wire.len());
    assert_eq!(&wire[..16], &salt);
    assert!(wire.len() > 16 + V4_HEADER_CIPHER_SIZE + payload.len());

    let (decoded_salt, frame) = split_salt(&wire).unwrap();
    let mut frame = BytesMut::from(frame);
    let mut decoder = V4FrameDecoder::new(psk, decoded_salt).unwrap();
    let mut header_cipher = [0; V4_HEADER_CIPHER_SIZE];
    header_cipher.copy_from_slice(&frame[..V4_HEADER_CIPHER_SIZE]);
    let header = decoder.decode_header(&mut header_cipher).unwrap();
    let mut body = frame.split_off(V4_HEADER_CIPHER_SIZE);

    let out = decoder.decode_payload_in_place(header, &mut body).unwrap();
    assert_eq!(out.len(), payload.len());
    assert_eq!(out, payload);
}

#[test]
fn encoded_padding_biases_unmixed_body_bit_ratio() {
    let psk = TEST_PSK;
    let salt = [7u8; 16];
    let payload = [0x51; 128];
    let initial_padding_len = 256;
    let mut encoder =
        V4FrameEncoder::with_salt_and_initial_padding(psk, salt, initial_padding_len).unwrap();
    let mut wire = BytesMut::with_capacity(512);

    encode_test_frame(&mut encoder, &payload, &mut wire);

    let (decoded_salt, frame) = split_salt(&wire).unwrap();
    let mut header_cipher = [0; V4_HEADER_CIPHER_SIZE];
    header_cipher.copy_from_slice(&frame[..V4_HEADER_CIPHER_SIZE]);
    let mut decoder = V4FrameDecoder::new(psk, decoded_salt).unwrap();
    let header = decoder.decode_header(&mut header_cipher).unwrap();
    assert_eq!(header.padding_len, initial_padding_len);

    let mut body = BytesMut::from(&frame[V4_HEADER_CIPHER_SIZE..]);
    let (padding, payload_cipher) = body.split_at_mut(header.padding_len);
    swap_padding(padding, payload_cipher);

    let payload_ones = count_v4_payload_ones(payload_cipher);
    let payload_zeros = payload_cipher.len() * 8 - payload_ones;
    let payload_ratio = payload_ones as f64 / payload_zeros as f64;
    assert!(payload_ratio > 0.5);
    assert!(payload_ratio < 1.6);

    let total_bits = (padding.len() + payload_cipher.len()) * 8;
    let mixed_ones = count_one_bits(padding) + payload_ones;
    let mixed_zeros = total_bits - mixed_ones;
    let mixed_ratio = mixed_ones as f64 / mixed_zeros as f64;
    if payload_zeros < payload_ones {
        assert!(mixed_ratio >= 0.39);
        assert!(mixed_ratio < 0.50);
    } else {
        assert!(mixed_ratio >= 1.59);
        assert!(mixed_ratio < 1.70);
    }
}

#[test]
fn payload_in_place_path_appends_to_non_empty_output() {
    let psk = TEST_PSK;
    let salt = [9u8; 16];
    let payload = b"streamed payload";
    let mut encoder = V4FrameEncoder::with_salt_and_initial_padding(psk, salt, 8).unwrap();
    let mut wire = BytesMut::from(&b"prefix"[..]);

    let start_len = wire.len();
    let mut head = BytesMut::new();
    let mut body = BytesMut::from(&payload[..]);
    let written = encoder
        .encode_payload_in_place(&mut body, payload.len(), &mut head)
        .unwrap();
    wire.extend_from_slice(&head);
    wire.extend_from_slice(&body);

    assert_eq!(written, wire.len() - start_len);
    assert_eq!(&wire[..start_len], b"prefix");

    let (decoded_salt, frame) = split_salt(&wire[start_len..]).unwrap();
    let mut frame = BytesMut::from(frame);
    let mut decoder = V4FrameDecoder::new(psk, decoded_salt).unwrap();
    let mut header_cipher = [0; V4_HEADER_CIPHER_SIZE];
    header_cipher.copy_from_slice(&frame[..V4_HEADER_CIPHER_SIZE]);
    let header = decoder.decode_header(&mut header_cipher).unwrap();
    let decoded = decoder
        .decode_payload_in_place(header, &mut frame[V4_HEADER_CIPHER_SIZE..])
        .unwrap();

    assert_eq!(decoded, payload);
}

#[test]
fn encodes_zero_chunk() {
    let psk = TEST_PSK;
    let salt = [4u8; 16];
    let mut encoder = V4FrameEncoder::with_salt_and_initial_padding(psk, salt, 8).unwrap();
    let mut wire = BytesMut::new();

    encode_test_frame(&mut encoder, &[], &mut wire);
    let (decoded_salt, frame) = split_salt(&wire).unwrap();
    let mut frame = BytesMut::from(frame);
    let mut decoder = V4FrameDecoder::new(psk, decoded_salt).unwrap();
    let mut header_cipher = [0; V4_HEADER_CIPHER_SIZE];
    header_cipher.copy_from_slice(&frame[..V4_HEADER_CIPHER_SIZE]);
    let header = decoder.decode_header(&mut header_cipher).unwrap();

    assert!(matches!(
        decoder.decode_payload_in_place(header, &mut frame[V4_HEADER_CIPHER_SIZE..]),
        Err(Error::ZeroChunk)
    ));
}

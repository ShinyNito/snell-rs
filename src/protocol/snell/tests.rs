use super::v4::{V4_FIRST_RECORD_OVERHEAD, V4_MSS_BASE, next_v4_chunk_limit};
use super::*;
use crate::protocol::{ParseState, address::Address};
use bytes::BytesMut;
use std::{net::SocketAddr, sync::Arc};

#[test]
fn connect_v2_header_matches_wire_shape() {
    let address = Address::domain("example.com", 443).unwrap();
    let mut out = [0; 17];

    let n = encode_connect_request_into(&mut out, address.as_view(), true).unwrap();

    assert_eq!(
        &out[..n],
        [
            PROTOCOL_VERSION,
            COMMAND_CONNECT_V2,
            0,
            11,
            b'e',
            b'x',
            b'a',
            b'm',
            b'p',
            b'l',
            b'e',
            b'.',
            b'c',
            b'o',
            b'm',
            0x01,
            0xbb,
        ]
    );
}

#[test]
fn connect_request_with_client_id_decodes() {
    let wire = b"\x01\x01\x03abc\x03dns\x00\x35";

    let request = decode_connect_request(wire).unwrap();

    assert_eq!(request.destination, Address::domain("dns", 53).unwrap());
    assert!(!request.reuse);
}

#[test]
fn connect_request_prefix_allows_coalesced_payload() {
    let wire = b"\x01\x05\x03abc\x03dns\x01\xbbhello";

    let (request, consumed) = decode_connect_request_prefix(wire).unwrap();

    assert_eq!(request.destination, Address::domain("dns", 443).unwrap());
    assert!(request.reuse);
    assert_eq!(consumed, wire.len() - b"hello".len());
    assert!(decode_connect_request(wire).is_err());
}

#[test]
fn connect_request_prefix_reports_needed_total() {
    let partial = b"\x01\x01\x03abc";

    assert_eq!(
        parse_connect_request_prefix(partial).unwrap(),
        ParseState::Need(7)
    );
}

#[test]
fn udp_setup_header_matches_wire_shape() {
    let mut out = [0; 3];

    let n = encode_udp_setup_request_into(&mut out).unwrap();

    assert_eq!(&out[..n], &[PROTOCOL_VERSION, COMMAND_UDP, 0]);
    assert_eq!(decode_udp_setup_request_prefix(&out[..n]).unwrap(), n);
}

#[test]
fn udp_setup_prefix_reports_needed_total() {
    let partial = b"\x01\x06\x03ab";

    assert_eq!(
        parse_udp_setup_request_prefix(partial).unwrap(),
        ParseState::Need(6)
    );
}

#[test]
fn udp_request_packet_round_trips_domain_and_ip() {
    let domain = Address::domain("example.com", 443).unwrap();
    let ip = Address::from(SocketAddr::from(([1, 1, 1, 1], 53)));

    assert_udp_request_round_trip(&domain, b"hello");
    assert_udp_request_round_trip(&ip, b"dns");
}

#[test]
fn udp_request_ipv4_matches_official_forward_shape() {
    let wire = b"\x01\x00\x04\x7f\x00\x00\x01\x1f\x90payload";

    let packet = decode_udp_request_packet(wire).unwrap();

    assert_eq!(
        packet.address,
        Address::from(SocketAddr::from(([127, 0, 0, 1], 8080))).as_view()
    );
    assert_eq!(packet.header_len, 9);
    assert_eq!(packet.payload, b"payload");
}

#[test]
fn udp_response_packet_round_trips_domain_and_ip() {
    let domain = Address::domain("example.com", 443).unwrap();
    let ip = Address::from(SocketAddr::from(([8, 8, 8, 8], 53)));

    assert_udp_response_round_trip(&domain, b"hello");
    assert_udp_response_round_trip(&ip, b"dns");
}

#[test]
fn v4_codec_round_trips_in_place() {
    let psk = b"0123456789abcdef";
    let mut encoder = V4Encoder::new(psk).unwrap();
    let wire = encoder.seal_plain(b"hello").unwrap();

    let mut decoder = V4Decoder::new(&psk[..]);
    let mut src = wire.as_ref();
    loop {
        match decode_next(&mut decoder, &mut src) {
            DecodeEvent::NeedMore => assert!(
                !src.is_empty(),
                "decoder needs more bytes than encoder emitted"
            ),
            DecodeEvent::PlainData => break,
            event => panic!("unexpected decode event: {event:?}"),
        }
    }
    assert_eq!(decoder.pending_plain(), b"hello");
}

#[test]
fn v4_encoder_applies_padding_and_chunk_size() {
    let psk = b"0123456789abcdef";
    let mut encoder = V4Encoder::with_salt_and_initial_padding(psk, [7; SALT_LEN], 8).unwrap();

    let first_limit = V4_MSS_BASE - V4_FIRST_RECORD_OVERHEAD - 8;
    assert_eq!(encoder.next_plain_capacity(), first_limit);
    let payload = vec![0x42; first_limit];
    let wire = encoder.seal_plain(&payload).unwrap();
    assert_eq!(
        wire.len(),
        SALT_LEN + HEADER_CIPHER_LEN + 8 + first_limit + TAG_LEN
    );

    assert_eq!(
        encoder.next_plain_capacity(),
        next_v4_chunk_limit(first_limit)
    );
}

#[test]
fn v6_unsafe_raw_round_trips_through_trait() {
    assert_eq!(
        round_trip_mode::<V6UnsafeRawMode>(b"0123456789abcdef", b"raw payload"),
        b"raw payload"
    );
}

#[test]
fn v6_unshaped_round_trips_through_trait() {
    assert_eq!(
        round_trip_mode::<V6UnshapedMode>(b"0123456789abcdef", b"unshaped payload"),
        b"unshaped payload"
    );
}

#[test]
fn v6_shaped_round_trips_through_trait() {
    assert_eq!(
        round_trip_mode::<V6ShapedMode>(b"0123456789abcdef", b"shaped payload"),
        b"shaped payload"
    );
}

#[test]
fn v6_shaped_reads_payload_after_zero_chunk() {
    assert_eq!(
        round_trip_mode_frames::<V6ShapedMode>(
            b"0123456789abcdef",
            &[b"first".as_slice(), b"".as_slice(), b"second".as_slice()],
        ),
        vec![Some(b"first".to_vec()), None, Some(b"second".to_vec()),]
    );
}

fn round_trip_mode<M>(psk: &[u8], payload: &[u8]) -> Vec<u8>
where
    M: SnellMode,
{
    let mut encoder = M::new_encoder(psk).unwrap();
    let wire = encoder.seal_plain(payload).unwrap();

    let mut decoder = M::new_decoder(Arc::from(psk));
    let mut src = wire.as_ref();
    loop {
        let event = decode_next(&mut decoder, &mut src);
        match event {
            DecodeEvent::NeedMore => {
                assert!(
                    !src.is_empty(),
                    "decoder needs more bytes than encoder emitted"
                );
            }
            DecodeEvent::PlainData => return collect_plaintext(&mut decoder),
            DecodeEvent::ZeroChunk => panic!("unexpected zero chunk"),
            _ => continue,
        }
    }
}

fn round_trip_mode_frames<M>(psk: &[u8], payloads: &[&[u8]]) -> Vec<Option<Vec<u8>>>
where
    M: SnellMode,
{
    let mut encoder = M::new_encoder(psk).unwrap();
    let mut wire = Vec::new();
    for payload in payloads {
        let frame = encoder.seal_plain(payload).unwrap();
        wire.extend_from_slice(&frame);
    }

    let mut decoder = M::new_decoder(Arc::from(psk));
    let mut src = wire.as_slice();
    let mut frames = Vec::new();
    while !src.is_empty() {
        let event = decode_next(&mut decoder, &mut src);
        match event {
            DecodeEvent::NeedMore => {
                assert!(
                    !src.is_empty(),
                    "decoder needs more bytes than encoder emitted"
                );
            }
            DecodeEvent::PlainData => frames.push(Some(collect_plaintext(&mut decoder))),
            DecodeEvent::ZeroChunk => frames.push(None),
            _ => {}
        }
    }
    frames
}

fn decode_next<'a, D>(decoder: &'a mut D, src: &mut &[u8]) -> DecodeEvent<'a>
where
    D: SnellTcpDecoder,
{
    if src.is_empty() {
        return decoder.feed_owned(BytesMut::new()).unwrap();
    }
    let n = src.len().min(1);
    let chunk = BytesMut::from(&src[..n]);
    *src = &src[n..];
    decoder.feed_owned(chunk).unwrap()
}

fn collect_plaintext<D>(decoder: &mut D) -> Vec<u8>
where
    D: SnellTcpDecoder,
{
    let mut out = Vec::new();
    while decoder.has_pending_plain() {
        let plain = decoder.pending_plain();
        let copied = plain.len();
        out.extend_from_slice(plain);
        decoder.consume_plain(copied);
    }
    out
}

fn assert_udp_request_round_trip(address: &Address, payload: &[u8]) {
    let header_len = udp_request_addr_len(address.as_view()).unwrap();
    let mut buf = vec![0; header_len + payload.len()];
    encode_udp_request_addr(&mut buf, address.as_view()).unwrap();
    buf[header_len..].copy_from_slice(payload);

    let packet = decode_udp_request_packet(&buf).unwrap();

    assert_eq!(packet.address, address.as_view());
    assert_eq!(packet.payload, payload);
    assert_eq!(packet.header_len, header_len);
}

fn assert_udp_response_round_trip(address: &Address, payload: &[u8]) {
    let header_len = udp_response_addr_len(address.as_view()).unwrap();
    let mut buf = vec![0; header_len + payload.len()];
    encode_udp_response_addr(&mut buf, address.as_view()).unwrap();
    buf[header_len..].copy_from_slice(payload);

    let packet = decode_udp_response_packet(&buf).unwrap();

    assert_eq!(packet.address, address.as_view());
    assert_eq!(packet.payload, payload);
    assert_eq!(packet.header_len, header_len);
}

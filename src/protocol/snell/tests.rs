use super::v4::{V4_FIRST_RECORD_OVERHEAD, V4_MSS_BASE, next_v4_chunk_limit};
use super::*;
use crate::protocol::address::Address;
use std::{io::IoSlice, net::SocketAddr, sync::Arc};

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
fn udp_setup_header_matches_wire_shape() {
    let mut out = [0; 3];

    let n = encode_udp_setup_request_into(&mut out).unwrap();

    assert_eq!(&out[..n], &[PROTOCOL_VERSION, COMMAND_UDP, 0]);
    assert_eq!(decode_udp_setup_request_prefix(&out[..n]).unwrap(), n);
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
    let reservation = encoder.begin_write(32).unwrap();
    encoder.plain_slot(reservation)[..5].copy_from_slice(b"hello");
    encoder.finish_write(reservation, 5).unwrap();

    let wire = collect_pending(&encoder);
    let mut decoder = V4Decoder::new(&psk[..]);
    let salt: [u8; SALT_LEN] = wire[..SALT_LEN].try_into().unwrap();
    decoder.init_salt(salt).unwrap();
    let mut header: [u8; HEADER_CIPHER_LEN] = wire[SALT_LEN..SALT_LEN + HEADER_CIPHER_LEN]
        .try_into()
        .unwrap();
    let decoded = decoder.decode_header(&mut header).unwrap();
    decoder
        .body_slot(decoded)
        .copy_from_slice(&wire[SALT_LEN + HEADER_CIPHER_LEN..]);

    assert!(decoder.finish_body(decoded).unwrap());
    assert_eq!(decoder.pending_plain(), b"hello");
}

#[test]
fn v4_encoder_applies_padding_and_chunk_size() {
    let psk = b"0123456789abcdef";
    let mut encoder = V4Encoder::with_salt_and_initial_padding(psk, [7; SALT_LEN], 8).unwrap();

    let first = encoder.begin_write(MAX_PACKET_SIZE).unwrap();
    let first_limit = V4_MSS_BASE - V4_FIRST_RECORD_OVERHEAD - 8;
    assert_eq!(first.max_payload_len, first_limit);
    assert_eq!(first.padding_len, 8);
    encoder.plain_slot(first).fill(0x42);
    encoder.finish_write(first, first_limit).unwrap();
    let pending = collect_pending(&encoder).len();
    encoder.advance_wire(pending);

    let second = encoder.begin_write(MAX_PACKET_SIZE).unwrap();
    assert_eq!(second.padding_len, 0);
    assert_eq!(second.max_payload_len, next_v4_chunk_limit(first_limit));
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

fn round_trip_mode<M>(psk: &[u8], payload: &[u8]) -> Vec<u8>
where
    M: SnellMode,
{
    let mut encoder = M::new_encoder(psk).unwrap();
    let reservation = encoder
        .begin_plain_reservation(PlainPrefix::none(), payload.len())
        .unwrap();
    encoder.plain_slot(&reservation)[..payload.len()].copy_from_slice(payload);
    encoder
        .finish_plain_reservation(reservation, payload.len())
        .unwrap();

    let wire = collect_pending_trait(&encoder);
    let mut decoder = M::new_decoder(Arc::from(psk));
    let mut offset = 0;
    loop {
        let event = match decoder.next_ciphertext_slot() {
            DecodeSlot::Read(slot) => {
                assert!(
                    offset < wire.len(),
                    "decoder needs more bytes than encoder emitted"
                );
                let n = slot.len().min(wire.len() - offset);
                slot[..n].copy_from_slice(&wire[offset..offset + n]);
                offset += n;
                decoder.commit_ciphertext(n).unwrap()
            }
            DecodeSlot::BlockedByPlaintext => DecodeEvent::PlainData,
        };

        match event {
            DecodeEvent::NeedMore => continue,
            DecodeEvent::PlainData => return collect_plaintext(&mut decoder),
            DecodeEvent::ZeroChunk => panic!("unexpected zero chunk"),
            _ => continue,
        }
    }
}

fn collect_pending_trait<E>(encoder: &E) -> Vec<u8>
where
    E: SnellTcpEncoder,
{
    let mut out = Vec::new();
    let mut pending = [IoSlice::new(&[]); 5];
    let n = encoder.pending_wire(&mut pending);
    for slice in &pending[..n] {
        out.extend_from_slice(slice);
    }
    out
}

fn collect_plaintext<D>(decoder: &mut D) -> Vec<u8>
where
    D: SnellTcpDecoder,
{
    let mut out = Vec::new();
    while decoder.has_pending_plaintext() {
        let mut pending = [IoSlice::new(&[]); 4];
        let n = decoder.pending_plaintext(&mut pending);
        let copied = pending[..n].iter().map(|slice| slice.len()).sum();
        for slice in &pending[..n] {
            out.extend_from_slice(slice);
        }
        decoder.advance_plaintext(copied);
    }
    out
}

fn collect_pending(encoder: &V4Encoder) -> Vec<u8> {
    let mut pending = [IoSlice::new(&[]); 5];
    let n = encoder.pending_wire(&mut pending);
    pending[..n]
        .iter()
        .flat_map(|slice| slice.as_ref().iter().copied())
        .collect()
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

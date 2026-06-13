use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BytesMut};

use super as udp_io;
use super::{
    SnellUdpPacketKind, UdpRecvBatch, UdpSendPacket, parse_socks_udp_header,
    reframe_socks_udp_packet, send_udp_batch,
};
use crate::error::Error;
use crate::protocol::socks5::write_udp_packet as write_socks_udp_packet;
use crate::protocol::udp::{
    AddressRef, parse_udp_request, parse_udp_response, write_udp_request_prefix,
    write_udp_response_prefix,
};
use crate::test_support::test_udp_socket;

fn v4_socks_udp_datagram_limit() -> usize {
    udp_io::max_socks_udp_datagram_len(crate::MAX_PACKET_SIZE)
}

fn reframe(mut datagram: BytesMut, kind: SnellUdpPacketKind) -> (BytesMut, usize) {
    let header = parse_socks_udp_header(&datagram).unwrap();
    let payload_len = header.payload_len();
    // SAFETY: `payload_start` was parsed from this datagram and is in-bounds.
    let payload_ptr = unsafe { datagram.as_ptr().add(header.payload_start) };

    let prefix_start =
        reframe_socks_udp_packet(&mut datagram, &header, kind, crate::MAX_PACKET_SIZE).unwrap();
    datagram.advance(prefix_start);

    let new_payload_start = datagram.len() - payload_len;
    // SAFETY: `new_payload_start` is derived from the current datagram
    // length and the preserved payload length, so it is in-bounds.
    let new_payload_ptr = unsafe { datagram.as_ptr().add(new_payload_start) };
    assert_eq!(new_payload_ptr, payload_ptr);

    (datagram, payload_len)
}

#[test]
fn reframes_ipv4_socks_udp_as_snell_request_without_payload_copy() {
    let payload = b"hello";
    let mut datagram = BytesMut::new();
    let address = AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    write_socks_udp_packet(&mut datagram, address, 53, payload).unwrap();

    let (reframed, payload_len) = reframe(datagram, SnellUdpPacketKind::Request);
    let parsed = parse_udp_request(&reframed).unwrap();

    assert_eq!(payload_len, payload.len());
    assert_eq!(parsed.address, address);
    assert_eq!(parsed.port, 53);
    assert_eq!(parsed.payload, payload);
}

#[test]
fn reframes_domain_socks_udp_as_snell_response_without_payload_copy() {
    let payload = b"dns-response";
    let mut datagram = BytesMut::new();
    let address = AddressRef::Domain("example.com");
    write_socks_udp_packet(&mut datagram, address, 5353, payload).unwrap();

    let (reframed, payload_len) = reframe(datagram, SnellUdpPacketKind::Response);
    let parsed = parse_udp_response(&reframed).unwrap();

    assert_eq!(payload_len, payload.len());
    assert_eq!(parsed.address, address);
    assert_eq!(parsed.port, 5353);
    assert_eq!(parsed.payload, payload);
}

#[test]
fn reframe_matches_existing_snell_prefix_encoders() {
    let payload = b"payload";
    let mut datagram = BytesMut::new();
    let address = AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
    write_socks_udp_packet(&mut datagram, address, 443, payload).unwrap();

    let (request, _) = reframe(datagram.clone(), SnellUdpPacketKind::Request);
    let mut expected_request = BytesMut::new();
    write_udp_request_prefix(&mut expected_request, address, 443).unwrap();
    expected_request.extend_from_slice(payload);
    assert_eq!(request, expected_request);

    let (response, _) = reframe(datagram, SnellUdpPacketKind::Response);
    let mut expected_response = BytesMut::new();
    write_udp_response_prefix(&mut expected_response, address, 443).unwrap();
    expected_response.extend_from_slice(payload);
    assert_eq!(response, expected_response);
}

#[test]
fn rejects_reframed_payload_larger_than_snell_packet() {
    let mut datagram = BytesMut::new();
    let address = AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let payload = vec![0x42; crate::MAX_PACKET_SIZE];
    write_socks_udp_packet(&mut datagram, address, 53, &payload).unwrap();
    let header = parse_socks_udp_header(&datagram).unwrap();

    assert!(matches!(
        reframe_socks_udp_packet(
            &mut datagram,
            &header,
            SnellUdpPacketKind::Request,
            crate::MAX_PACKET_SIZE,
        ),
        Err(Error::PayloadTooLarge)
    ));
}

#[test]
fn reframe_allows_large_packet_when_snell_record_limit_allows_it() {
    let mut datagram = BytesMut::new();
    let address = AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let payload = vec![0x42; 60_000];
    write_socks_udp_packet(&mut datagram, address, 53, &payload).unwrap();
    let header = parse_socks_udp_header(&datagram).unwrap();

    let prefix_start = reframe_socks_udp_packet(
        &mut datagram,
        &header,
        SnellUdpPacketKind::Request,
        crate::MAX_V6_RECORD_PAYLOAD_LEN,
    )
    .unwrap();
    datagram.advance(prefix_start);
    let parsed = parse_udp_request(&datagram).unwrap();

    assert_eq!(parsed.address, address);
    assert_eq!(parsed.port, 53);
    assert_eq!(parsed.payload, payload);
}

#[test]
fn rejects_stale_socks_udp_header_without_panicking() {
    let mut datagram = BytesMut::new();
    write_socks_udp_packet(
        &mut datagram,
        AddressRef::Domain("example.com"),
        53,
        b"payload",
    )
    .unwrap();
    let header = parse_socks_udp_header(&datagram).unwrap();
    datagram.truncate(header.payload_start);

    assert!(matches!(
        reframe_socks_udp_packet(
            &mut datagram,
            &header,
            SnellUdpPacketKind::Request,
            crate::MAX_PACKET_SIZE,
        ),
        Err(Error::InvalidSocksRequest)
    ));
}

#[test]
fn max_socks_udp_header_includes_domain_length_byte() {
    let host = "x".repeat(u8::MAX as usize);
    let mut datagram = BytesMut::new();
    write_socks_udp_packet(&mut datagram, AddressRef::Domain(&host), 53, &[]).unwrap();

    assert_eq!(datagram.len(), udp_io::MAX_SOCKS_UDP_HEADER);
}

#[tokio::test]
async fn recv_socks_udp_datagram_reports_peer_and_preserves_bytes() {
    let receiver = test_udp_socket().await;
    let sender = test_udp_socket().await;
    let sender_addr = sender.local_addr().unwrap();
    let mut sent = BytesMut::new();
    write_socks_udp_packet(
        &mut sent,
        AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        53,
        b"query",
    )
    .unwrap();

    sender
        .send_to(&sent, receiver.local_addr().unwrap())
        .await
        .unwrap();

    let mut received = UdpRecvBatch::new(v4_socks_udp_datagram_limit());
    let n = received.recv_from(&receiver).await.unwrap();
    let entry = received.get(0).unwrap();

    assert_eq!(n, 1);
    assert_eq!(entry.peer(), sender_addr);
    assert_eq!(entry.payload_len(), sent.len());
    assert_eq!(entry.payload(), &sent[..]);
}

#[test]
fn recv_oversized_sentinel_marks_datagram_too_large() {
    let v4_limit = v4_socks_udp_datagram_limit();
    assert!(!udp_io::udp_datagram_too_large(v4_limit, v4_limit,));
    assert!(udp_io::udp_datagram_too_large(v4_limit + 1, v4_limit,));
}

#[test]
fn send_full_datagram_check_rejects_short_write() {
    assert!(udp_io::ensure_full_datagram_sent(4, 5).is_err());
    udp_io::ensure_full_datagram_sent(5, 5).unwrap();
}

#[test]
fn socks_udp_datagram_limit_allows_socks_rsv_overhead() {
    assert_eq!(
        udp_io::max_socks_udp_datagram_len(crate::MAX_V6_RECORD_PAYLOAD_LEN),
        crate::MAX_V6_RECORD_PAYLOAD_LEN + 3
    );
}

#[tokio::test]
async fn send_udp_batch_combines_prefix_and_payload() {
    let sender = test_udp_socket().await;
    let receiver = test_udp_socket().await;

    send_udp_batch(
        &sender,
        &[UdpSendPacket::parts(
            b"header",
            b"payload",
            receiver.local_addr().unwrap(),
        )],
        v4_socks_udp_datagram_limit(),
    )
    .await
    .unwrap();

    let mut received = [0; 64];
    let (n, peer) = receiver.recv_from(&mut received).await.unwrap();

    assert_eq!(peer, sender.local_addr().unwrap());
    assert_eq!(&received[..n], b"headerpayload");
}

#[tokio::test]
async fn send_udp_batch_rejects_packets_above_call_site_limit() {
    let sender = test_udp_socket().await;
    let receiver = test_udp_socket().await;

    assert!(matches!(
        send_udp_batch(
            &sender,
            &[UdpSendPacket::parts(
                b"header",
                b"payload",
                receiver.local_addr().unwrap(),
            )],
            b"header".len() + b"payload".len() - 1,
        )
        .await,
        Err(Error::PayloadTooLarge)
    ));
}

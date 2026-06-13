use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::Error;
use crate::protocol::udp::{AddressRef, parse_udp_response};
use crate::test_support::{test_snell_reader, test_snell_writer};

const UDP_IPV4_RESPONSE_OVERHEAD: usize = 1 + 4 + 2;
const UDP_IPV6_RESPONSE_OVERHEAD: usize = 1 + 16 + 2;
const UDP_MAX_IPV4_RESPONSE_PAYLOAD: usize = crate::MAX_PACKET_SIZE - UDP_IPV4_RESPONSE_OVERHEAD;
const UDP_MAX_IPV6_RESPONSE_PAYLOAD: usize = crate::MAX_PACKET_SIZE - UDP_IPV6_RESPONSE_OVERHEAD;

#[tokio::test]
async fn udp_response_accepts_largest_payloads_that_fit_frame() {
    let v4_payload = vec![0x42; UDP_MAX_IPV4_RESPONSE_PAYLOAD];
    let v6_payload = vec![0x43; UDP_MAX_IPV6_RESPONSE_PAYLOAD];

    let read_v4 = async {
        let (writer_io, reader_io) = tokio::io::duplex(crate::MAX_PACKET_SIZE + 2048);
        let mut reader = test_snell_reader(reader_io);
        let mut writer = test_snell_writer(writer_io);
        let write = writer.write_test_udp_response(
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            53,
            &v4_payload,
        );
        let read = async {
            let frame = reader.read_frame_payload().await.unwrap();
            let response = parse_udp_response(frame).unwrap();
            assert_eq!(response.payload.len(), UDP_MAX_IPV4_RESPONSE_PAYLOAD);
            frame.len()
        };

        let (write_result, read_result) = tokio::join!(write, read);
        assert_eq!(write_result.unwrap(), UDP_MAX_IPV4_RESPONSE_PAYLOAD);
        assert_eq!(read_result, crate::MAX_PACKET_SIZE);
    };

    let read_v6 = async {
        let (writer_io, reader_io) = tokio::io::duplex(crate::MAX_PACKET_SIZE + 2048);
        let mut reader = test_snell_reader(reader_io);
        let mut writer = test_snell_writer(writer_io);
        let write = writer.write_test_udp_response(
            AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            53,
            &v6_payload,
        );
        let read = async {
            let frame = reader.read_frame_payload().await.unwrap();
            let response = parse_udp_response(frame).unwrap();
            assert_eq!(response.payload.len(), UDP_MAX_IPV6_RESPONSE_PAYLOAD);
            frame.len()
        };

        let (write_result, read_result) = tokio::join!(write, read);
        assert_eq!(write_result.unwrap(), UDP_MAX_IPV6_RESPONSE_PAYLOAD);
        assert_eq!(read_result, crate::MAX_PACKET_SIZE);
    };

    tokio::join!(read_v4, read_v6);
}

#[tokio::test]
async fn udp_response_rejects_payload_too_large_for_frame() {
    let v4_payload = vec![0x42; UDP_MAX_IPV4_RESPONSE_PAYLOAD + 1];
    let v6_payload = vec![0x43; UDP_MAX_IPV6_RESPONSE_PAYLOAD + 1];
    let mut v4_writer = test_snell_writer(tokio::io::sink());
    let mut v6_writer = test_snell_writer(tokio::io::sink());

    assert!(matches!(
        v4_writer
            .write_test_udp_response(
                AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                53,
                &v4_payload,
            )
            .await,
        Err(Error::PayloadTooLarge)
    ));
    assert!(matches!(
        v6_writer
            .write_test_udp_response(
                AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                53,
                &v6_payload,
            )
            .await,
        Err(Error::PayloadTooLarge)
    ));
}

#[test]
fn udp_response_payload_limits_leave_room_for_address_headers() {
    assert_eq!(
        UDP_MAX_IPV4_RESPONSE_PAYLOAD + 1 + 4 + 2,
        crate::MAX_PACKET_SIZE
    );
    assert_eq!(
        UDP_MAX_IPV6_RESPONSE_PAYLOAD + 1 + 16 + 2,
        crate::MAX_PACKET_SIZE
    );
}

#[test]
fn udp_send_short_write_is_rejected() {
    assert!(crate::proxy::outbound::udp::ensure_full_datagram_sent(4, 5).is_err());
    crate::proxy::outbound::udp::ensure_full_datagram_sent(5, 5).unwrap();
}

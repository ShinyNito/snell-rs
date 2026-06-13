use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::relay_udp_server_stream;
use crate::error::Error;
use crate::net::dns::DnsResolver;
use crate::protocol::socks5::{
    SocksReply, SocksRequest, SocksTarget, parse_udp_packet as parse_socks_udp_packet,
    write_udp_packet as write_socks_udp_packet,
};
use crate::protocol::udp::AddressRef;
use crate::proxy::outbound::RelayOptions;
use crate::proxy::snell::server::serve_server_connection;
use crate::proxy::socks5::inbound::{
    read_client_request as read_socks_client_request, write_reply_with_bind,
};
use crate::session::udp::stream::UdpClientStream;
use crate::test_support::{
    TEST_PSK, accept_udp_server_stream, read_udp_response_frame, test_duplex_pair,
    test_tcp_listener, test_udp_socket,
};

fn direct_options(ipv6: bool) -> RelayOptions {
    RelayOptions::direct(ipv6, DnsResolver::system())
}

fn socks5_options(ipv6: bool, proxy_addr: std::net::SocketAddr) -> RelayOptions {
    RelayOptions::socks5(ipv6, proxy_addr, DnsResolver::system())
}

#[tokio::test]
async fn udp_server_stream_relays_one_datagram_response() {
    let psk = TEST_PSK;
    let udp_target = test_udp_socket().await;
    let target_addr = udp_target.local_addr().unwrap();
    let (client_upload, server_upload) = test_duplex_pair();
    let (server_download, client_download) = test_duplex_pair();

    let target = async {
        let mut input = [0u8; 64];
        let (n, peer) = udp_target.recv_from(&mut input).await.unwrap();
        assert_eq!(&input[..n], b"query");
        udp_target.send_to(b"answer", peer).await.unwrap();
    };

    let server = async {
        let stream = accept_udp_server_stream(
            server_upload,
            server_download,
            psk,
            crate::ProtocolVersion::V4,
        )
        .await
        .unwrap();
        relay_udp_server_stream(stream, direct_options(false), Duration::from_secs(1))
            .await
            .unwrap()
    };

    let client = async {
        let (mut reader, mut writer) = UdpClientStream::open_io(
            client_download,
            client_upload,
            psk,
            crate::ProtocolVersion::V4,
        )
        .await
        .unwrap()
        .into_parts();
        writer
            .write_test_udp_packet(
                AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                target_addr.port(),
                b"query",
            )
            .await
            .unwrap();

        let response = read_udp_response_frame(&mut reader).await.unwrap().unwrap();
        assert_eq!(response.payload, b"answer");
        assert_eq!(response.port, target_addr.port());
        writer.write_zero_chunk().await.unwrap();
    };

    let (stats, (), ()) = tokio::join!(server, client, target);
    assert_eq!(stats.packets_sent, 1);
    assert_eq!(stats.packets_received, 1);
    assert_eq!(stats.bytes_sent, 5);
    assert_eq!(stats.bytes_received, 6);
}

#[tokio::test]
async fn udp_stream_does_not_head_of_line_block_on_missing_response() {
    let psk = TEST_PSK;
    let no_reply_target = test_udp_socket().await;
    let no_reply_addr = no_reply_target.local_addr().unwrap();
    let reply_target = test_udp_socket().await;
    let reply_addr = reply_target.local_addr().unwrap();
    let (client_upload, server_upload) = test_duplex_pair();
    let (server_download, client_download) = test_duplex_pair();

    let no_reply = async {
        let mut input = [0u8; 64];
        let (n, _) = no_reply_target.recv_from(&mut input).await.unwrap();
        assert_eq!(&input[..n], b"lost");
    };

    let reply = async {
        let mut input = [0u8; 64];
        let (n, peer) = reply_target.recv_from(&mut input).await.unwrap();
        assert_eq!(&input[..n], b"query");
        reply_target.send_to(b"answer", peer).await.unwrap();
    };

    let server = async {
        let stream = accept_udp_server_stream(
            server_upload,
            server_download,
            psk,
            crate::ProtocolVersion::V4,
        )
        .await
        .unwrap();
        relay_udp_server_stream(stream, direct_options(false), Duration::from_secs(2))
            .await
            .unwrap()
    };

    let client = async {
        let (mut reader, mut writer) = UdpClientStream::open_io(
            client_download,
            client_upload,
            psk,
            crate::ProtocolVersion::V4,
        )
        .await
        .unwrap()
        .into_parts();
        writer
            .write_test_udp_packet(
                AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                no_reply_addr.port(),
                b"lost",
            )
            .await
            .unwrap();
        writer
            .write_test_udp_packet(
                AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                reply_addr.port(),
                b"query",
            )
            .await
            .unwrap();

        let response = tokio::time::timeout(
            Duration::from_millis(500),
            read_udp_response_frame(&mut reader),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(response.payload, b"answer");
        assert_eq!(response.port, reply_addr.port());
        writer.write_zero_chunk().await.unwrap();
    };

    let (stats, (), (), ()) = tokio::join!(server, client, no_reply, reply);
    assert_eq!(stats.packets_sent, 2);
    assert_eq!(stats.packets_received, 1);
    assert_eq!(stats.bytes_sent, 9);
    assert_eq!(stats.bytes_received, 6);
}

#[tokio::test]
async fn udp_server_relays_datagram_via_upstream_socks5() {
    let psk = TEST_PSK;
    let udp_target = test_udp_socket().await;
    let target_addr = udp_target.local_addr().unwrap();
    let socks_listener = test_tcp_listener().await;
    let socks_addr = socks_listener.local_addr().unwrap();
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();

    let target = async {
        let mut input = [0u8; 64];
        let (n, peer) = udp_target.recv_from(&mut input).await.unwrap();
        assert_eq!(&input[..n], b"query");
        udp_target.send_to(b"answer", peer).await.unwrap();
    };

    let socks = async {
        let (mut control, _) = socks_listener.accept().await.unwrap();
        let request = read_socks_client_request(&mut control).await.unwrap();
        assert_eq!(
            request,
            SocksRequest::UdpAssociate(SocksTarget {
                host: "0.0.0.0".to_owned(),
                port: 0,
            })
        );
        let relay = test_udp_socket().await;
        let relay_addr = relay.local_addr().unwrap();
        write_reply_with_bind(&mut control, SocksReply::Succeeded, relay_addr)
            .await
            .unwrap();

        let mut request = bytes::BytesMut::with_capacity(crate::MAX_PACKET_SIZE + 512);
        let (n, snell_peer) = relay.recv_buf_from(&mut request).await.unwrap();
        let packet = parse_socks_udp_packet(&request[..n]).unwrap();
        assert_eq!(
            packet.address,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(packet.port, target_addr.port());
        assert_eq!(packet.payload, b"query");
        relay.send_to(packet.payload, target_addr).await.unwrap();

        let mut response = [0u8; 64];
        let (n, peer) = relay.recv_from(&mut response).await.unwrap();
        assert_eq!(peer, target_addr);
        let mut socks_response = bytes::BytesMut::new();
        write_socks_udp_packet(
            &mut socks_response,
            AddressRef::Ip(peer.ip()),
            peer.port(),
            &response[..n],
        )
        .unwrap();
        relay.send_to(&socks_response, snell_peer).await.unwrap();

        let mut control_buf = [0; 1];
        let _ = control.read(&mut control_buf).await;
    };

    let server = async {
        let (client, _) = snell_listener.accept().await.unwrap();
        serve_server_connection(client, psk, socks5_options(false, socks_addr))
            .await
            .unwrap()
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        let (mut reader, mut writer) =
            UdpClientStream::open_io(reader, writer, psk, crate::ProtocolVersion::V4)
                .await
                .unwrap()
                .into_parts();
        writer
            .write_test_udp_packet(
                AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                target_addr.port(),
                b"query",
            )
            .await
            .unwrap();

        let response = read_udp_response_frame(&mut reader).await.unwrap().unwrap();
        assert_eq!(response.payload, b"answer");
        assert_eq!(response.port, target_addr.port());
        writer.write_zero_chunk().await.unwrap();
    };

    let ((), (), (), ()) = tokio::join!(target, socks, server, client);
}

#[tokio::test]
async fn udp_upstream_socks5_failure_returns_server_error_before_tunnel_success() {
    let psk = TEST_PSK;
    let socks_listener = test_tcp_listener().await;
    let socks_addr = socks_listener.local_addr().unwrap();
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();

    let socks = async {
        let (control, _) = socks_listener.accept().await.unwrap();
        drop(control);
    };

    let server = async {
        let (client, _) = snell_listener.accept().await.unwrap();
        serve_server_connection(client, psk, socks5_options(false, socks_addr)).await
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        assert!(matches!(
            UdpClientStream::open_io(reader, writer, psk, crate::ProtocolVersion::V4).await,
            Err(Error::Server { code: 1, message }) if message == "connect failed"
        ));
    };

    let ((), server_result, ()) = tokio::join!(socks, server, client);
    assert!(server_result.is_err());
}

#[tokio::test]
async fn udp_upstream_socks5_control_close_ends_association() {
    let psk = TEST_PSK;
    let socks_listener = test_tcp_listener().await;
    let socks_addr = socks_listener.local_addr().unwrap();
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();

    let socks = async {
        let (mut control, _) = socks_listener.accept().await.unwrap();
        let request = read_socks_client_request(&mut control).await.unwrap();
        assert!(matches!(request, SocksRequest::UdpAssociate(_)));
        let relay = test_udp_socket().await;
        write_reply_with_bind(
            &mut control,
            SocksReply::Succeeded,
            relay.local_addr().unwrap(),
        )
        .await
        .unwrap();
    };

    let server = async {
        let (client, _) = snell_listener.accept().await.unwrap();
        serve_server_connection(client, psk, socks5_options(false, socks_addr))
            .await
            .unwrap()
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        let (mut reader, _) =
            UdpClientStream::open_io(reader, writer, psk, crate::ProtocolVersion::V4)
                .await
                .unwrap()
                .into_parts();
        assert!(
            timeout(
                Duration::from_millis(200),
                read_udp_response_frame(&mut reader)
            )
            .await
            .unwrap()
            .unwrap()
            .is_none()
        );
    };

    let ((), (), ()) = tokio::join!(socks, server, client);
}

#[tokio::test]
async fn udp_association_idle_timeout_sends_zero_chunk_to_client() {
    let psk = TEST_PSK;
    let (client_upload, server_upload) = test_duplex_pair();
    let (server_download, client_download) = test_duplex_pair();

    let server = async {
        let stream = accept_udp_server_stream(
            server_upload,
            server_download,
            psk,
            crate::ProtocolVersion::V4,
        )
        .await
        .unwrap();
        relay_udp_server_stream(stream, direct_options(false), Duration::from_millis(20))
            .await
            .unwrap()
    };

    let client = async {
        let (mut reader, _writer) = UdpClientStream::open_io(
            client_download,
            client_upload,
            psk,
            crate::ProtocolVersion::V4,
        )
        .await
        .unwrap()
        .into_parts();
        assert!(
            timeout(
                Duration::from_millis(200),
                read_udp_response_frame(&mut reader)
            )
            .await
            .unwrap()
            .unwrap()
            .is_none()
        );
    };

    let (stats, ()) = tokio::join!(server, client);
    assert_eq!(stats.packets_sent, 0);
    assert_eq!(stats.packets_received, 0);
}

#[tokio::test]
async fn client_zero_chunk_ends_udp_association_without_waiting_for_idle() {
    let psk = TEST_PSK;
    let (client_upload, server_upload) = test_duplex_pair();
    let (server_download, client_download) = test_duplex_pair();

    let server = async {
        let stream = accept_udp_server_stream(
            server_upload,
            server_download,
            psk,
            crate::ProtocolVersion::V4,
        )
        .await
        .unwrap();
        timeout(
            Duration::from_millis(200),
            relay_udp_server_stream(stream, direct_options(false), Duration::from_secs(60)),
        )
        .await
        .unwrap()
        .unwrap()
    };

    let client = async {
        let (_, mut writer) = UdpClientStream::open_io(
            client_download,
            client_upload,
            psk,
            crate::ProtocolVersion::V4,
        )
        .await
        .unwrap()
        .into_parts();
        writer.write_zero_chunk().await.unwrap();
    };

    let (stats, ()) = tokio::join!(server, client);
    assert_eq!(stats.packets_sent, 0);
    assert_eq!(stats.packets_received, 0);
}

#[tokio::test]
async fn udp_to_snell_stops_when_snell_writer_is_closed() {
    let psk = TEST_PSK;
    let udp_target = test_udp_socket().await;
    let target_addr = udp_target.local_addr().unwrap();
    let (client_upload, server_upload) = test_duplex_pair();
    let (server_download, client_download) = test_duplex_pair();

    let target = async {
        let mut input = [0u8; 64];
        let (n, peer) = udp_target.recv_from(&mut input).await.unwrap();
        assert_eq!(&input[..n], b"query");
        udp_target.send_to(b"answer", peer).await.unwrap();
    };

    let server = async {
        let stream = accept_udp_server_stream(
            server_upload,
            server_download,
            psk,
            crate::ProtocolVersion::V4,
        )
        .await
        .unwrap();
        timeout(
            Duration::from_millis(500),
            relay_udp_server_stream(stream, direct_options(false), Duration::from_secs(60)),
        )
        .await
        .unwrap()
        .unwrap()
    };

    let client = async {
        let (reader, mut writer) = UdpClientStream::open_io(
            client_download,
            client_upload,
            psk,
            crate::ProtocolVersion::V4,
        )
        .await
        .unwrap()
        .into_parts();
        writer
            .write_test_udp_packet(
                AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                target_addr.port(),
                b"query",
            )
            .await
            .unwrap();
        drop(reader);
        writer
    };

    let (stats, writer, ()) = tokio::join!(server, client, target);
    drop(writer);
    assert_eq!(stats.packets_sent, 1);
    assert_eq!(stats.packets_received, 0);
    assert_eq!(stats.bytes_sent, 5);
    assert_eq!(stats.bytes_received, 0);
}

#[tokio::test]
async fn udp_tcp_connection_rejects_ipv6_when_disabled() {
    let psk = TEST_PSK;
    let listener = test_tcp_listener().await;
    let server_addr = listener.local_addr().unwrap();

    let server = async {
        let (client, _) = listener.accept().await.unwrap();
        serve_server_connection(client, psk, direct_options(false)).await
    };

    let client = async {
        let stream = TcpStream::connect(server_addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        let (_, mut writer) =
            UdpClientStream::open_io(reader, writer, psk, crate::ProtocolVersion::V4)
                .await
                .unwrap()
                .into_parts();
        writer
            .write_test_udp_packet(
                AddressRef::Ip(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
                53,
                b"query",
            )
            .await
            .unwrap();
    };

    let (server_result, ()) = tokio::join!(server, client);
    assert!(matches!(server_result, Err(Error::Ipv6Disabled)));
}

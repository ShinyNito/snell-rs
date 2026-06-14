use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

use super::relay_udp_server_stream;
use crate::error::Error;
use crate::framed::SnellStreamWriter;
use crate::net::dns::DnsResolver;
use crate::protocol::socks5::{
    SocksReply, SocksRequest, SocksTarget, parse_udp_packet as parse_socks_udp_packet,
    write_udp_packet as write_socks_udp_packet,
};
use crate::protocol::udp::{AddressRef, parse_udp_response};
use crate::protocol::v6::V6SaltReplayCache;
use crate::proxy::outbound::RelayOptions;
use crate::proxy::snell::server::{
    SERVER_TCP_ACTIVITY_TIMEOUTS, open_tcp_target, serve_server_connection,
};
use crate::proxy::socks5::inbound::{
    read_client_request as read_socks_client_request, write_reply_with_bind,
};
use crate::session::udp::stream::UdpClientStream;
use crate::test_support::{
    TEST_PSK, TestUdpPacket, accept_udp_server_stream, shared_secret, test_duplex_pair,
    test_tcp_listener, test_udp_socket, write_snell_udp_packet,
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
        relay_udp_server_stream(stream, direct_options(false))
            .await
            .unwrap()
    };

    let client = async {
        let secret = shared_secret(psk);
        let (mut reader, mut writer) = UdpClientStream::open_io(
            client_download,
            client_upload,
            &secret,
            crate::ProtocolVersion::V4,
        )
        .await
        .unwrap()
        .into_parts();
        write_snell_udp_packet(
            &mut writer,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            target_addr.port(),
            b"query",
        )
        .await
        .unwrap();

        let message = reader.read_udp_response_message().await.unwrap().unwrap();
        let response = TestUdpPacket::from_ref(parse_udp_response(&message).unwrap());
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
        relay_udp_server_stream(stream, direct_options(false))
            .await
            .unwrap()
    };

    let client = async {
        let secret = shared_secret(psk);
        let (mut reader, mut writer) = UdpClientStream::open_io(
            client_download,
            client_upload,
            &secret,
            crate::ProtocolVersion::V4,
        )
        .await
        .unwrap()
        .into_parts();
        write_snell_udp_packet(
            &mut writer,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            no_reply_addr.port(),
            b"lost",
        )
        .await
        .unwrap();
        write_snell_udp_packet(
            &mut writer,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            reply_addr.port(),
            b"query",
        )
        .await
        .unwrap();

        let message = tokio::time::timeout(
            Duration::from_millis(500),
            reader.read_udp_response_message(),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let response = TestUdpPacket::from_ref(parse_udp_response(&message).unwrap());
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
        let (mut control, _) = timeout(Duration::from_millis(500), socks_listener.accept())
            .await
            .unwrap()
            .unwrap();
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
        serve_server_connection(
            client,
            shared_secret(psk),
            socks5_options(false, socks_addr),
            V6SaltReplayCache::default(),
            open_tcp_target,
            SERVER_TCP_ACTIVITY_TIMEOUTS,
        )
        .await
        .unwrap()
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        let secret = shared_secret(psk);
        let (mut reader, mut writer) =
            UdpClientStream::open_io(reader, writer, &secret, crate::ProtocolVersion::V4)
                .await
                .unwrap()
                .into_parts();
        write_snell_udp_packet(
            &mut writer,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            target_addr.port(),
            b"query",
        )
        .await
        .unwrap();

        let message = reader.read_udp_response_message().await.unwrap().unwrap();
        let response = TestUdpPacket::from_ref(parse_udp_response(&message).unwrap());
        assert_eq!(response.payload, b"answer");
        assert_eq!(response.port, target_addr.port());
        writer.write_zero_chunk().await.unwrap();
    };

    let ((), (), (), ()) = tokio::join!(target, socks, server, client);
}

#[tokio::test]
async fn udp_upstream_socks5_failure_after_tunnel_open_closes_server() {
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
        serve_server_connection(
            client,
            shared_secret(psk),
            socks5_options(false, socks_addr),
            V6SaltReplayCache::default(),
            open_tcp_target,
            SERVER_TCP_ACTIVITY_TIMEOUTS,
        )
        .await
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        let secret = shared_secret(psk);
        let (mut reader, mut writer) =
            UdpClientStream::open_io(reader, writer, &secret, crate::ProtocolVersion::V4)
                .await
                .unwrap()
                .into_parts();
        write_snell_udp_packet(
            &mut writer,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            53,
            b"query",
        )
        .await
        .unwrap();

        let result = timeout(
            Duration::from_millis(500),
            reader.read_udp_response_message(),
        )
        .await
        .unwrap();
        match result {
            Ok(None) => {}
            Err(err) if err.is_closed_io() => {}
            other => panic!("unexpected udp response read result: {other:?}"),
        }
    };

    let ((), server_result, ()) = tokio::join!(socks, server, client);
    assert!(server_result.is_err());
}

#[tokio::test]
async fn udp_upstream_socks5_control_close_reopens_without_ending_association() {
    let psk = TEST_PSK;
    let socks_listener = test_tcp_listener().await;
    let socks_addr = socks_listener.local_addr().unwrap();
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();

    let socks = async {
        let (mut control, _) = timeout(Duration::from_millis(500), socks_listener.accept())
            .await
            .unwrap()
            .unwrap();
        let request = read_socks_client_request(&mut control).await.unwrap();
        assert!(matches!(request, SocksRequest::UdpAssociate(_)));
        let relay = test_udp_socket().await;
        let relay_addr = relay.local_addr().unwrap();
        write_reply_with_bind(&mut control, SocksReply::Succeeded, relay_addr)
            .await
            .unwrap();

        let mut packet_buf = bytes::BytesMut::with_capacity(crate::MAX_PACKET_SIZE + 512);
        let (n, _) = timeout(
            Duration::from_millis(500),
            relay.recv_buf_from(&mut packet_buf),
        )
        .await
        .unwrap()
        .unwrap();
        let packet = parse_socks_udp_packet(&packet_buf[..n]).unwrap();
        assert_eq!(packet.payload, b"first");
        drop(control);

        let (mut control, _) = timeout(Duration::from_millis(500), socks_listener.accept())
            .await
            .unwrap()
            .unwrap();
        let request = read_socks_client_request(&mut control).await.unwrap();
        assert!(matches!(request, SocksRequest::UdpAssociate(_)));
        let relay = test_udp_socket().await;
        let relay_addr = relay.local_addr().unwrap();
        write_reply_with_bind(&mut control, SocksReply::Succeeded, relay_addr)
            .await
            .unwrap();

        packet_buf.clear();
        let (n, snell_peer) = timeout(
            Duration::from_millis(500),
            relay.recv_buf_from(&mut packet_buf),
        )
        .await
        .unwrap()
        .unwrap();
        let packet = parse_socks_udp_packet(&packet_buf[..n]).unwrap();
        assert_eq!(packet.payload, b"second");
        let mut response = bytes::BytesMut::new();
        write_socks_udp_packet(
            &mut response,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            5353,
            b"answer",
        )
        .unwrap();
        relay.send_to(&response, snell_peer).await.unwrap();

        let mut control_buf = [0; 1];
        let _ = timeout(Duration::from_millis(500), control.read(&mut control_buf)).await;
    };

    let server = async {
        let (client, _) = snell_listener.accept().await.unwrap();
        serve_server_connection(
            client,
            shared_secret(psk),
            socks5_options(false, socks_addr),
            V6SaltReplayCache::default(),
            open_tcp_target,
            SERVER_TCP_ACTIVITY_TIMEOUTS,
        )
        .await
        .unwrap()
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        let secret = shared_secret(psk);
        let (mut reader, mut writer) =
            UdpClientStream::open_io(reader, writer, &secret, crate::ProtocolVersion::V4)
                .await
                .unwrap()
                .into_parts();
        write_snell_udp_packet(
            &mut writer,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            53,
            b"first",
        )
        .await
        .unwrap();
        sleep(Duration::from_millis(100)).await;
        write_snell_udp_packet(
            &mut writer,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            53,
            b"second",
        )
        .await
        .unwrap();

        let message = timeout(
            Duration::from_millis(500),
            reader.read_udp_response_message(),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let response = TestUdpPacket::from_ref(parse_udp_response(&message).unwrap());
        assert_eq!(response.payload, b"answer");
        assert_eq!(response.port, 5353);
        writer.write_zero_chunk().await.unwrap();
    };

    let ((), (), ()) = tokio::join!(socks, server, client);
}

#[tokio::test]
async fn udp_upstream_socks5_idle_reopens_without_ending_association() {
    let psk = TEST_PSK;
    let socks_listener = test_tcp_listener().await;
    let socks_addr = socks_listener.local_addr().unwrap();
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();

    let socks = async {
        let (mut control, _) = timeout(Duration::from_millis(500), socks_listener.accept())
            .await
            .unwrap()
            .unwrap();
        let request = read_socks_client_request(&mut control).await.unwrap();
        assert!(matches!(request, SocksRequest::UdpAssociate(_)));
        let relay = test_udp_socket().await;
        let relay_addr = relay.local_addr().unwrap();
        write_reply_with_bind(&mut control, SocksReply::Succeeded, relay_addr)
            .await
            .unwrap();

        let mut packet_buf = bytes::BytesMut::with_capacity(crate::MAX_PACKET_SIZE + 512);
        let (n, _) = timeout(
            Duration::from_millis(500),
            relay.recv_buf_from(&mut packet_buf),
        )
        .await
        .unwrap()
        .unwrap();
        let packet = parse_socks_udp_packet(&packet_buf[..n]).unwrap();
        assert_eq!(packet.payload, b"first");

        let mut control_buf = [0; 1];
        let n = timeout(Duration::from_millis(500), control.read(&mut control_buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0);

        let (mut control, _) = timeout(Duration::from_millis(500), socks_listener.accept())
            .await
            .unwrap()
            .unwrap();
        let request = read_socks_client_request(&mut control).await.unwrap();
        assert!(matches!(request, SocksRequest::UdpAssociate(_)));
        let relay = test_udp_socket().await;
        let relay_addr = relay.local_addr().unwrap();
        write_reply_with_bind(&mut control, SocksReply::Succeeded, relay_addr)
            .await
            .unwrap();

        packet_buf.clear();
        let (n, snell_peer) = timeout(
            Duration::from_millis(500),
            relay.recv_buf_from(&mut packet_buf),
        )
        .await
        .unwrap()
        .unwrap();
        let packet = parse_socks_udp_packet(&packet_buf[..n]).unwrap();
        assert_eq!(packet.payload, b"second");
        let mut response = bytes::BytesMut::new();
        write_socks_udp_packet(
            &mut response,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            5353,
            b"answer",
        )
        .unwrap();
        relay.send_to(&response, snell_peer).await.unwrap();

        let _ = timeout(Duration::from_millis(500), control.read(&mut control_buf)).await;
    };

    let server = async {
        let (client, _) = snell_listener.accept().await.unwrap();
        serve_server_connection(
            client,
            shared_secret(psk),
            socks5_options(false, socks_addr),
            V6SaltReplayCache::default(),
            open_tcp_target,
            SERVER_TCP_ACTIVITY_TIMEOUTS,
        )
        .await
        .unwrap()
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        let secret = shared_secret(psk);
        let (mut reader, mut writer) =
            UdpClientStream::open_io(reader, writer, &secret, crate::ProtocolVersion::V4)
                .await
                .unwrap()
                .into_parts();
        write_snell_udp_packet(
            &mut writer,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            53,
            b"first",
        )
        .await
        .unwrap();
        sleep(Duration::from_millis(150)).await;
        write_snell_udp_packet(
            &mut writer,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            53,
            b"second",
        )
        .await
        .unwrap();

        let message = timeout(
            Duration::from_millis(500),
            reader.read_udp_response_message(),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let response = TestUdpPacket::from_ref(parse_udp_response(&message).unwrap());
        assert_eq!(response.payload, b"answer");
        assert_eq!(response.port, 5353);
        writer.write_zero_chunk().await.unwrap();
    };

    let ((), (), ()) = tokio::join!(socks, server, client);
}

#[tokio::test]
async fn udp_association_transport_eof_closes_without_zero_chunk() {
    let psk = TEST_PSK;
    let (client_upload, server_upload) = test_duplex_pair();
    let server_download = RecordingWrite::default();
    let recorded_download = server_download.clone();

    let server = async {
        let stream = accept_udp_server_stream(
            server_upload,
            server_download,
            psk,
            crate::ProtocolVersion::V4,
        )
        .await
        .unwrap();
        let bytes_after_accept = recorded_download.len();
        let stats = relay_udp_server_stream(stream, direct_options(false))
            .await
            .unwrap();
        assert_eq!(recorded_download.len(), bytes_after_accept);
        stats
    };

    let client = async {
        let secret = shared_secret(psk);
        let mut writer =
            SnellStreamWriter::new(client_upload, &secret, crate::ProtocolVersion::V4).unwrap();
        writer.write_udp_request().await.unwrap();
        sleep(Duration::from_millis(100)).await;
    };

    let (stats, ()) = tokio::join!(server, client);
    assert_eq!(stats.packets_sent, 0);
    assert_eq!(stats.packets_received, 0);
}

#[derive(Clone, Default)]
struct RecordingWrite {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl RecordingWrite {
    fn len(&self) -> usize {
        self.bytes.lock().expect("recording writer poisoned").len()
    }
}

impl AsyncWrite for RecordingWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.bytes
            .lock()
            .expect("recording writer poisoned")
            .extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
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
            relay_udp_server_stream(stream, direct_options(false)),
        )
        .await
        .unwrap()
        .unwrap()
    };

    let client = async {
        let secret = shared_secret(psk);
        let (_, mut writer) = UdpClientStream::open_io(
            client_download,
            client_upload,
            &secret,
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
            relay_udp_server_stream(stream, direct_options(false)),
        )
        .await
        .unwrap()
        .unwrap()
    };

    let client = async {
        let secret = shared_secret(psk);
        let (reader, mut writer) = UdpClientStream::open_io(
            client_download,
            client_upload,
            &secret,
            crate::ProtocolVersion::V4,
        )
        .await
        .unwrap()
        .into_parts();
        write_snell_udp_packet(
            &mut writer,
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
        serve_server_connection(
            client,
            shared_secret(psk),
            direct_options(false),
            V6SaltReplayCache::default(),
            open_tcp_target,
            SERVER_TCP_ACTIVITY_TIMEOUTS,
        )
        .await
    };

    let client = async {
        let stream = TcpStream::connect(server_addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        let secret = shared_secret(psk);
        let (_, mut writer) =
            UdpClientStream::open_io(reader, writer, &secret, crate::ProtocolVersion::V4)
                .await
                .unwrap()
                .into_parts();
        write_snell_udp_packet(
            &mut writer,
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

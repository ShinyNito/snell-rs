use core::range::Range;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::ProtocolVersion;
use crate::error::{Error, Result};
use crate::net::dns::DnsResolver;
use crate::protocol::quic_proxy::decode_init_datagram;
use crate::protocol::request::{ClientRequest, parse_client_request};
use crate::protocol::socks5::{parse_udp_packet, write_udp_packet};
use crate::protocol::udp::AddressRef;
use crate::protocol::version::DEFAULT_CLIENT_VERSION;
use crate::proxy::outbound::RelayOptions;
use crate::proxy::outbound::snell::SnellClientOutbound;
use crate::proxy::snell::server::serve_server_connection;
use crate::proxy::socks5::udp::is_allowed_socks_udp_peer;
use crate::test_support::{
    TEST_PSK, accept_udp_server_stream, read_udp_request_frame, test_snell_reader,
    test_snell_writer, test_tcp_listener, test_udp_socket,
};

fn direct_options(ipv6: bool) -> RelayOptions {
    RelayOptions::direct(ipv6, DnsResolver::system())
}

async fn relay_socks5_connection(
    local: TcpStream,
    server_addr: SocketAddr,
    psk: &[u8],
    reuse: bool,
) -> Result<crate::proxy::outbound::RelayStats> {
    relay_socks5_connection_with_options(
        local,
        server_addr,
        psk,
        reuse,
        DEFAULT_CLIENT_VERSION,
        false,
    )
    .await
}

async fn relay_socks5_connection_with_options(
    local: TcpStream,
    server_addr: SocketAddr,
    psk: &[u8],
    reuse: bool,
    version: ProtocolVersion,
    quic_proxy: bool,
) -> Result<crate::proxy::outbound::RelayStats> {
    let outbound = Arc::new(SnellClientOutbound::new(
        server_addr,
        psk.to_vec(),
        reuse,
        version,
    )?);
    super::relay_socks5_connection(local, outbound, quic_proxy).await
}

#[tokio::test]
async fn socks5_connection_relays_tcp_over_snell() {
    let psk = TEST_PSK;
    let echo_listener = test_tcp_listener().await;
    let echo_addr = echo_listener.local_addr().unwrap();
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();
    let socks_listener = test_tcp_listener().await;
    let socks_addr = socks_listener.local_addr().unwrap();

    let echo = async {
        let (mut stream, _) = echo_listener.accept().await.unwrap();
        let mut input = Vec::new();
        stream.read_to_end(&mut input).await.unwrap();
        assert_eq!(input, b"ping");
        stream.write_all(b"pong").await.unwrap();
        stream.shutdown().await.unwrap();
    };

    let snell_server = async {
        let (stream, _) = snell_listener.accept().await.unwrap();
        serve_server_connection(stream, psk, direct_options(false))
            .await
            .unwrap()
    };

    let socks_server = async {
        let (stream, _) = socks_listener.accept().await.unwrap();
        relay_socks5_connection(stream, snell_addr, psk, false)
            .await
            .unwrap()
    };

    let client = async {
        let mut stream = TcpStream::connect(socks_addr).await.unwrap();
        let mut request = vec![5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_addr.port().to_be_bytes());
        stream.write_all(&request).await.unwrap();

        let mut method = [0; 2];
        stream.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);

        let mut reply = [0; 10];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);

        stream.write_all(b"ping").await.unwrap();
        stream.shutdown().await.unwrap();

        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"pong");
    };

    let ((), (), socks_stats, ()) = tokio::join!(echo, snell_server, socks_server, client);
    assert_eq!(socks_stats.uploaded, 4);
    assert_eq!(socks_stats.downloaded, 4);
}

#[tokio::test]
async fn socks5_connect_sends_success_before_snell_tunnel_reply() {
    let psk = TEST_PSK;
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();
    let socks_listener = test_tcp_listener().await;
    let socks_addr = socks_listener.local_addr().unwrap();
    let request_payload = b"GET / HTTP/1.1\r\n\r\n";
    let response_payload = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

    let snell_server = async {
        let (stream, _) = snell_listener.accept().await.unwrap();
        let (server_read, server_write) = stream.into_split();
        let mut reader = test_snell_reader(server_read);
        let payload = reader.read_frame_payload().await.unwrap();
        let request = parse_client_request(payload).unwrap();
        assert_eq!(
            request,
            ClientRequest::Connect {
                reuse: false,
                host: "1.1.1.1",
                port: 80,
                rest_span: Range { start: 13, end: 13 },
                rest: b"",
            }
        );

        let payload = reader.read_frame_payload().await.unwrap();
        assert_eq!(payload, request_payload);

        let mut server_writer = test_snell_writer(server_write);
        server_writer
            .write_test_tunnel_reply(response_payload)
            .await
            .unwrap();
        server_writer.write_zero_chunk().await.unwrap();
    };

    let socks_server = async {
        let (stream, _) = socks_listener.accept().await.unwrap();
        relay_socks5_connection(stream, snell_addr, psk, false)
            .await
            .unwrap()
    };

    let client = async {
        let mut stream = TcpStream::connect(socks_addr).await.unwrap();
        stream
            .write_all(&[5, 1, 0, 5, 1, 0, 1, 1, 1, 1, 1, 0, 80])
            .await
            .unwrap();

        let mut method = [0; 2];
        stream.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);

        let mut reply = [0; 10];
        timeout(Duration::from_millis(200), stream.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);

        stream.write_all(request_payload).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, response_payload);
    };

    let ((), stats, ()) = tokio::join!(snell_server, socks_server, client);
    assert_eq!(stats.uploaded, request_payload.len() as u64);
    assert_eq!(stats.downloaded, response_payload.len() as u64);
}

#[tokio::test]
async fn socks5_failure_reply_closes_tcp_connection() {
    let psk = TEST_PSK;
    let dead_snell_listener = test_tcp_listener().await;
    let dead_snell_addr = dead_snell_listener.local_addr().unwrap();
    drop(dead_snell_listener);
    let socks_listener = test_tcp_listener().await;
    let socks_addr = socks_listener.local_addr().unwrap();

    let socks_server = async {
        let (stream, _) = socks_listener.accept().await.unwrap();
        assert!(
            relay_socks5_connection(stream, dead_snell_addr, psk, false)
                .await
                .is_err()
        );
    };

    let client = async {
        let mut stream = TcpStream::connect(socks_addr).await.unwrap();
        stream
            .write_all(&[
                5, 1, 0, 5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
                b'o', b'm', 0x01, 0xbb,
            ])
            .await
            .unwrap();

        let mut method = [0; 2];
        stream.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);

        let mut reply = [0; 10];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);

        let mut tail = Vec::new();
        timeout(Duration::from_secs(1), stream.read_to_end(&mut tail))
            .await
            .unwrap()
            .unwrap();
        assert!(tail.is_empty());
    };

    let ((), ()) = tokio::join!(socks_server, client);
}

#[tokio::test]
async fn socks5_udp_associate_relays_datagram_over_snell() {
    let psk = TEST_PSK;
    let udp_target = test_udp_socket().await;
    let target_addr = udp_target.local_addr().unwrap();
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();
    let socks_listener = test_tcp_listener().await;
    let socks_addr = socks_listener.local_addr().unwrap();

    let target = async {
        let mut input = [0; 64];
        let (n, peer) = udp_target.recv_from(&mut input).await.unwrap();
        assert_eq!(&input[..n], b"query");
        udp_target.send_to(b"answer", peer).await.unwrap();
    };

    let snell_server = async {
        let (stream, _) = snell_listener.accept().await.unwrap();
        serve_server_connection(stream, psk, direct_options(false))
            .await
            .unwrap();
    };

    let socks_server = async {
        let (stream, _) = socks_listener.accept().await.unwrap();
        relay_socks5_connection(stream, snell_addr, psk, false)
            .await
            .unwrap()
    };

    let client = async {
        let mut control = TcpStream::connect(socks_addr).await.unwrap();
        control
            .write_all(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();

        let mut method = [0; 2];
        control.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);

        let mut reply = [0; 10];
        control.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let relay_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7])),
            u16::from_be_bytes([reply[8], reply[9]]),
        );

        let udp = test_udp_socket().await;
        let mut request = BytesMut::new();
        write_udp_packet(
            &mut request,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            target_addr.port(),
            b"query",
        )
        .unwrap();
        udp.send_to(&request, relay_addr).await.unwrap();

        let mut response = [0; 128];
        let (n, _) = timeout(Duration::from_secs(1), udp.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        let packet = parse_udp_packet(&response[..n]).unwrap();
        assert_eq!(packet.payload, b"answer");
        assert_eq!(packet.port, target_addr.port());

        control.shutdown().await.unwrap();
    };

    let ((), (), socks_stats, ()) = tokio::join!(target, snell_server, socks_server, client);
    assert_eq!(socks_stats.uploaded, 5);
    assert_eq!(socks_stats.downloaded, 6);
}

#[tokio::test]
async fn socks5_v5_quic_first_packet_uses_quic_proxy_udp() {
    let psk = TEST_PSK;
    let snell_udp = test_udp_socket().await;
    let snell_addr = snell_udp.local_addr().unwrap();
    let socks_listener = test_tcp_listener().await;
    let socks_addr = socks_listener.local_addr().unwrap();

    let snell_server = async {
        let mut datagram = [0; 256];
        let (n, peer) = snell_udp.recv_from(&mut datagram).await.unwrap();
        let mut wire = datagram[..n].to_vec();
        let init = decode_init_datagram(psk, &mut wire).unwrap();
        assert_eq!(init.host, "127.0.0.1");
        assert_eq!(init.port, 443);
        assert_eq!(init.payload, b"\xc0first");
        snell_udp.send_to(b"\x40reply", peer).await.unwrap();
    };

    let socks_server = async {
        let (stream, _) = socks_listener.accept().await.unwrap();
        relay_socks5_connection_with_options(
            stream,
            snell_addr,
            psk,
            false,
            ProtocolVersion::V5,
            true,
        )
        .await
        .unwrap()
    };

    let client = async {
        let mut control = TcpStream::connect(socks_addr).await.unwrap();
        control
            .write_all(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();

        let mut method = [0; 2];
        control.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);

        let mut reply = [0; 10];
        control.read_exact(&mut reply).await.unwrap();
        let relay_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7])),
            u16::from_be_bytes([reply[8], reply[9]]),
        );

        let udp = test_udp_socket().await;
        let mut request = BytesMut::new();
        write_udp_packet(
            &mut request,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            443,
            b"\xc0first",
        )
        .unwrap();
        udp.send_to(&request, relay_addr).await.unwrap();

        let mut response = [0; 128];
        let (n, _) = timeout(Duration::from_secs(1), udp.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        let packet = parse_udp_packet(&response[..n]).unwrap();
        assert_eq!(packet.payload, b"\x40reply");
        control.shutdown().await.unwrap();
    };

    let ((), socks_stats, ()) = tokio::join!(snell_server, socks_server, client);
    assert_eq!(socks_stats.uploaded, 6);
    assert_eq!(socks_stats.downloaded, 6);
}

#[tokio::test]
async fn socks5_v5_quic_initial_after_short_header_is_rewrapped() {
    let psk = TEST_PSK;
    let snell_udp = test_udp_socket().await;
    let snell_addr = snell_udp.local_addr().unwrap();
    let socks_listener = test_tcp_listener().await;
    let socks_addr = socks_listener.local_addr().unwrap();
    let (done_tx, done_rx) = oneshot::channel();

    let snell_server = async move {
        let mut datagram = [0; 512];

        let (n, peer) = snell_udp.recv_from(&mut datagram).await.unwrap();
        let mut wire = datagram[..n].to_vec();
        let init = decode_init_datagram(psk, &mut wire).unwrap();
        assert_eq!(init.payload, b"\xc0first");

        let (n, next_peer) = snell_udp.recv_from(&mut datagram).await.unwrap();
        assert_eq!(next_peer, peer);
        assert_eq!(&datagram[..n], b"\x40one-rtt");

        let (n, next_peer) = snell_udp.recv_from(&mut datagram).await.unwrap();
        assert_eq!(next_peer, peer);
        assert!(!crate::protocol::quic_proxy::is_quic_looking(datagram[0]));
        let mut wire = datagram[..n].to_vec();
        let init = decode_init_datagram(psk, &mut wire).unwrap();
        assert_eq!(init.payload, b"\xc0new");

        done_tx.send(()).unwrap();
    };

    let socks_server = async {
        let (stream, _) = socks_listener.accept().await.unwrap();
        relay_socks5_connection_with_options(
            stream,
            snell_addr,
            psk,
            false,
            ProtocolVersion::V5,
            true,
        )
        .await
        .unwrap()
    };

    let client = async {
        let mut control = TcpStream::connect(socks_addr).await.unwrap();
        control
            .write_all(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut method = [0; 2];
        control.read_exact(&mut method).await.unwrap();
        let mut reply = [0; 10];
        control.read_exact(&mut reply).await.unwrap();
        let relay_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7])),
            u16::from_be_bytes([reply[8], reply[9]]),
        );

        let udp = test_udp_socket().await;
        for payload in [b"\xc0first".as_slice(), b"\x40one-rtt", b"\xc0new"] {
            let mut request = BytesMut::new();
            write_udp_packet(
                &mut request,
                AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                443,
                payload,
            )
            .unwrap();
            udp.send_to(&request, relay_addr).await.unwrap();
        }

        timeout(Duration::from_secs(1), done_rx)
            .await
            .unwrap()
            .unwrap();
        control.shutdown().await.unwrap();
    };

    let ((), _, ()) = tokio::join!(snell_server, socks_server, client);
}

#[tokio::test]
async fn socks5_v5_non_quic_udp_falls_back_to_udp_over_tcp() {
    let psk = TEST_PSK;
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();
    let socks_listener = test_tcp_listener().await;
    let socks_addr = socks_listener.local_addr().unwrap();

    let snell_server = async {
        let (stream, _) = snell_listener.accept().await.unwrap();
        let (reader, writer) = stream.into_split();
        let (mut reader, mut writer) =
            accept_udp_server_stream(reader, writer, psk, ProtocolVersion::V5)
                .await
                .unwrap()
                .into_parts();
        let request = read_udp_request_frame(&mut reader).await.unwrap().unwrap();
        assert_eq!(request.payload, b"query");
        assert_eq!(request.port, 53);
        writer
            .write_test_udp_response(
                AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                53,
                b"answer",
            )
            .await
            .unwrap();
        std::assert_matches!(reader.read_frame_payload().await, Err(Error::ZeroChunk));
    };

    let socks_server = async {
        let (stream, _) = socks_listener.accept().await.unwrap();
        relay_socks5_connection_with_options(
            stream,
            snell_addr,
            psk,
            false,
            ProtocolVersion::V5,
            true,
        )
        .await
        .unwrap()
    };

    let client = async {
        let mut control = TcpStream::connect(socks_addr).await.unwrap();
        control
            .write_all(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut method = [0; 2];
        control.read_exact(&mut method).await.unwrap();
        let mut reply = [0; 10];
        control.read_exact(&mut reply).await.unwrap();
        let relay_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7])),
            u16::from_be_bytes([reply[8], reply[9]]),
        );

        let udp = test_udp_socket().await;
        let mut request = BytesMut::new();
        write_udp_packet(
            &mut request,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            53,
            b"query",
        )
        .unwrap();
        udp.send_to(&request, relay_addr).await.unwrap();

        let mut response = [0; 128];
        let (n, _) = timeout(Duration::from_secs(1), udp.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        let packet = parse_udp_packet(&response[..n]).unwrap();
        assert_eq!(packet.payload, b"answer");
        control.shutdown().await.unwrap();
    };

    let ((), socks_stats, ()) = tokio::join!(snell_server, socks_server, client);
    assert_eq!(socks_stats.uploaded, 5);
    assert_eq!(socks_stats.downloaded, 6);
}

#[tokio::test]
async fn socks5_v4_udp_ignores_quic_proxy_flag() {
    let psk = TEST_PSK;
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();
    let socks_listener = test_tcp_listener().await;
    let socks_addr = socks_listener.local_addr().unwrap();

    let snell_server = async {
        let (stream, _) = snell_listener.accept().await.unwrap();
        let (reader, writer) = stream.into_split();
        let (mut reader, mut writer) =
            accept_udp_server_stream(reader, writer, psk, ProtocolVersion::V4)
                .await
                .unwrap()
                .into_parts();
        let request = read_udp_request_frame(&mut reader).await.unwrap().unwrap();
        assert_eq!(request.payload, b"\xc0still-over-tcp");
        assert_eq!(request.port, 443);
        writer
            .write_test_udp_response(AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 443, b"ok")
            .await
            .unwrap();
        std::assert_matches!(reader.read_frame_payload().await, Err(Error::ZeroChunk));
    };

    let socks_server = async {
        let (stream, _) = socks_listener.accept().await.unwrap();
        relay_socks5_connection_with_options(
            stream,
            snell_addr,
            psk,
            false,
            ProtocolVersion::V4,
            true,
        )
        .await
        .unwrap()
    };

    let client = async {
        let mut control = TcpStream::connect(socks_addr).await.unwrap();
        control
            .write_all(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut method = [0; 2];
        control.read_exact(&mut method).await.unwrap();
        let mut reply = [0; 10];
        control.read_exact(&mut reply).await.unwrap();
        let relay_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7])),
            u16::from_be_bytes([reply[8], reply[9]]),
        );

        let udp = test_udp_socket().await;
        let mut request = BytesMut::new();
        write_udp_packet(
            &mut request,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            443,
            b"\xc0still-over-tcp",
        )
        .unwrap();
        udp.send_to(&request, relay_addr).await.unwrap();
        let mut response = [0; 128];
        let (n, _) = timeout(Duration::from_secs(1), udp.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        let packet = parse_udp_packet(&response[..n]).unwrap();
        assert_eq!(packet.payload, b"ok");
        control.shutdown().await.unwrap();
    };

    let ((), socks_stats, ()) = tokio::join!(snell_server, socks_server, client);
    assert_eq!(socks_stats.uploaded, b"\xc0still-over-tcp".len() as u64);
    assert_eq!(socks_stats.downloaded, 2);
}

#[tokio::test]
async fn socks5_udp_associate_allows_same_ip_different_udp_port() {
    let psk = TEST_PSK;
    let udp_target = test_udp_socket().await;
    let target_addr = udp_target.local_addr().unwrap();
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();
    let socks_listener = test_tcp_listener().await;
    let socks_addr = socks_listener.local_addr().unwrap();

    let target = async {
        let mut input = [0; 64];
        let (n, peer) = udp_target.recv_from(&mut input).await.unwrap();
        assert_eq!(&input[..n], b"first");
        udp_target.send_to(b"ok", peer).await.unwrap();

        let (n, peer) = udp_target.recv_from(&mut input).await.unwrap();
        assert_eq!(&input[..n], b"hijack");
        udp_target.send_to(b"ok2", peer).await.unwrap();
    };

    let snell_server = async {
        let (stream, _) = snell_listener.accept().await.unwrap();
        serve_server_connection(stream, psk, direct_options(false))
            .await
            .unwrap();
    };

    let socks_server = async {
        let (stream, _) = socks_listener.accept().await.unwrap();
        relay_socks5_connection(stream, snell_addr, psk, false)
            .await
            .unwrap()
    };

    let client = async {
        let mut control = TcpStream::connect(socks_addr).await.unwrap();
        control
            .write_all(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();

        let mut method = [0; 2];
        control.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);

        let mut reply = [0; 10];
        control.read_exact(&mut reply).await.unwrap();
        let relay_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7])),
            u16::from_be_bytes([reply[8], reply[9]]),
        );

        let first_peer = test_udp_socket().await;
        let second_peer = test_udp_socket().await;

        let mut first = BytesMut::new();
        write_udp_packet(
            &mut first,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            target_addr.port(),
            b"first",
        )
        .unwrap();
        first_peer.send_to(&first, relay_addr).await.unwrap();

        let mut response = [0; 128];
        let (n, _) = timeout(Duration::from_secs(1), first_peer.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        let packet = parse_udp_packet(&response[..n]).unwrap();
        assert_eq!(packet.payload, b"ok");

        let mut hijack = BytesMut::new();
        write_udp_packet(
            &mut hijack,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            target_addr.port(),
            b"hijack",
        )
        .unwrap();
        second_peer.send_to(&hijack, relay_addr).await.unwrap();

        let (n, _) = timeout(Duration::from_secs(1), second_peer.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        let packet = parse_udp_packet(&response[..n]).unwrap();
        assert_eq!(packet.payload, b"ok2");

        control.shutdown().await.unwrap();
    };

    let ((), (), socks_stats, ()) = tokio::join!(target, snell_server, socks_server, client);
    assert_eq!(socks_stats.uploaded, 11);
    assert_eq!(socks_stats.downloaded, 5);
}

#[test]
fn socks5_udp_peer_filter_uses_source_ip_not_port() {
    let control_peer_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    assert!(is_allowed_socks_udp_peer(
        control_peer_ip,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 11111)
    ));
    assert!(is_allowed_socks_udp_peer(
        control_peer_ip,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 22222)
    ));
    assert!(!is_allowed_socks_udp_peer(
        control_peer_ip,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 11111)
    ));
}

#[tokio::test]
async fn socks5_udp_associate_drops_invalid_datagrams_without_closing() {
    let psk = TEST_PSK;
    let udp_target = test_udp_socket().await;
    let target_addr = udp_target.local_addr().unwrap();
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();
    let socks_listener = test_tcp_listener().await;
    let socks_addr = socks_listener.local_addr().unwrap();

    let target = async {
        let mut input = [0; 64];
        let (n, peer) = udp_target.recv_from(&mut input).await.unwrap();
        assert_eq!(&input[..n], b"valid");
        udp_target.send_to(b"reply", peer).await.unwrap();
    };

    let snell_server = async {
        let (stream, _) = snell_listener.accept().await.unwrap();
        serve_server_connection(stream, psk, direct_options(false))
            .await
            .unwrap();
    };

    let socks_server = async {
        let (stream, _) = socks_listener.accept().await.unwrap();
        relay_socks5_connection(stream, snell_addr, psk, false)
            .await
            .unwrap()
    };

    let client = async {
        let mut control = TcpStream::connect(socks_addr).await.unwrap();
        control
            .write_all(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();

        let mut method = [0; 2];
        control.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);

        let mut reply = [0; 10];
        control.read_exact(&mut reply).await.unwrap();
        let relay_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7])),
            u16::from_be_bytes([reply[8], reply[9]]),
        );

        let udp = test_udp_socket().await;
        udp.send_to(&[0, 0, 1, 1, 127, 0, 0, 1, 0, 53, b'x'], relay_addr)
            .await
            .unwrap();

        let mut request = BytesMut::new();
        write_udp_packet(
            &mut request,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            target_addr.port(),
            b"valid",
        )
        .unwrap();
        udp.send_to(&request, relay_addr).await.unwrap();

        let mut response = [0; 128];
        let (n, _) = timeout(Duration::from_secs(1), udp.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        let packet = parse_udp_packet(&response[..n]).unwrap();
        assert_eq!(packet.payload, b"reply");

        control.shutdown().await.unwrap();
    };

    let ((), (), socks_stats, ()) = tokio::join!(target, snell_server, socks_server, client);
    assert_eq!(socks_stats.uploaded, 5);
    assert_eq!(socks_stats.downloaded, 5);
}

#[tokio::test]
async fn socks5_udp_associate_drops_invalid_snell_responses_without_closing() {
    let psk = TEST_PSK;
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();
    let socks_listener = test_tcp_listener().await;
    let socks_addr = socks_listener.local_addr().unwrap();

    let snell_server = async {
        let (stream, _) = snell_listener.accept().await.unwrap();
        let (reader, writer) = stream.into_split();
        let (mut reader, mut writer) =
            accept_udp_server_stream(reader, writer, psk, ProtocolVersion::V4)
                .await
                .unwrap()
                .into_parts();
        let request = read_udp_request_frame(&mut reader).await.unwrap().unwrap();
        assert_eq!(request.payload, b"query");
        assert_eq!(request.port, 53);

        writer.write_test_frame(&[0xff]).await.unwrap();
        writer
            .write_test_udp_response(
                AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                53,
                b"answer",
            )
            .await
            .unwrap();

        std::assert_matches!(reader.read_frame_payload().await, Err(Error::ZeroChunk));
    };

    let socks_server = async {
        let (stream, _) = socks_listener.accept().await.unwrap();
        relay_socks5_connection(stream, snell_addr, psk, false)
            .await
            .unwrap()
    };

    let client = async {
        let mut control = TcpStream::connect(socks_addr).await.unwrap();
        control
            .write_all(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();

        let mut method = [0; 2];
        control.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);

        let mut reply = [0; 10];
        control.read_exact(&mut reply).await.unwrap();
        let relay_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7])),
            u16::from_be_bytes([reply[8], reply[9]]),
        );

        let udp = test_udp_socket().await;
        let mut request = BytesMut::new();
        write_udp_packet(
            &mut request,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            53,
            b"query",
        )
        .unwrap();
        udp.send_to(&request, relay_addr).await.unwrap();

        let mut response = [0; 128];
        let (n, _) = timeout(Duration::from_secs(1), udp.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        let packet = parse_udp_packet(&response[..n]).unwrap();
        assert_eq!(packet.payload, b"answer");
        assert_eq!(packet.port, 53);

        control.shutdown().await.unwrap();
    };

    let ((), socks_stats, ()) = tokio::join!(snell_server, socks_server, client);
    assert_eq!(socks_stats.uploaded, 5);
    assert_eq!(socks_stats.downloaded, 6);
}

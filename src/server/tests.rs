use core::range::Range;
use std::time::Duration;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use super::{
    TcpServerRuntime, serve_tcp_listener_with_shutdown_and_timeout,
    serve_tcp_listeners_with_shutdown_and_timeout,
};
use crate::ProtocolVersion;
use crate::error::Error;
use crate::framed::{SnellStreamReader, SnellStreamWriter};
use crate::net::dns::DnsResolver;
use crate::protocol::header::{COMMAND_PING, PROTOCOL_VERSION};
use crate::protocol::request::{ServerReply, parse_server_reply};
use crate::protocol::socks5::{SocksReply, SocksRequest, SocksTarget};
use crate::protocol::v4::frame::V4FrameEncoder;
use crate::protocol::v6::V6SaltReplayCache;
use crate::proxy::outbound::RelayOptions;
use crate::proxy::snell::server::{
    V6_ERROR_CONNECTION_REFUSED, serve_server_connection,
    serve_server_connection_with_salt_replay_cache, serve_server_connection_with_target_opener,
};
use crate::proxy::socks5::inbound::{read_client_request, write_reply_with_bind};
use crate::server::shutdown::bind_tcp_listener;
use crate::session::tcp::{TcpClientStream, TcpClientWriter};
use crate::test_support::{TEST_PSK, test_tcp_listener};

fn direct_options(ipv6: bool) -> RelayOptions {
    RelayOptions::direct(ipv6, DnsResolver::system())
}

fn socks5_options(ipv6: bool, proxy_addr: std::net::SocketAddr) -> RelayOptions {
    RelayOptions::socks5(ipv6, proxy_addr, DnsResolver::system())
}

fn tcp_server_runtime(
    psk: &[u8],
    options: RelayOptions,
    shutdown: CancellationToken,
    drain_timeout: Duration,
) -> TcpServerRuntime {
    TcpServerRuntime {
        psk: psk.to_vec(),
        options,
        tcp_brutal: None,
        v6_salt_replay_cache: V6SaltReplayCache::default(),
        shutdown,
        drain_timeout,
    }
}

async fn write_client_payload<W>(
    writer: &mut TcpClientWriter<W>,
    payload: &[u8],
) -> crate::error::Result<usize>
where
    W: AsyncWrite + Unpin,
{
    let mut plain = payload;
    Ok(writer
        .write_next_payload_record_from_reader(&mut plain)
        .await?
        .unwrap_or(0))
}

async fn write_v4_test_frame_with_salt<W>(
    writer: &mut W,
    psk: &[u8],
    salt: [u8; 16],
    payload: &[u8],
) -> crate::error::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut encoder = V4FrameEncoder::with_salt_and_initial_padding(psk, salt, 0)?;
    let mut head = BytesMut::new();
    let mut body = BytesMut::from(payload);
    encoder.encode_payload_in_place(&mut body, payload.len(), &mut head)?;
    writer.write_all(&head).await?;
    writer.write_all(&body).await?;
    Ok(())
}

async fn assert_snell_ping(addr: std::net::SocketAddr, psk: &[u8], version: ProtocolVersion) {
    let stream = TcpStream::connect(addr).await.unwrap();
    let (snell_reader_io, snell_writer_io) = stream.into_split();
    let mut writer = SnellStreamWriter::new(snell_writer_io, psk, version).unwrap();
    writer
        .write_test_frame(&[PROTOCOL_VERSION, COMMAND_PING])
        .await
        .unwrap();
    let mut reader = SnellStreamReader::new(snell_reader_io, psk, version);
    let payload = reader.read_frame_payload().await.unwrap();
    assert_eq!(parse_server_reply(payload).unwrap(), ServerReply::Pong);
}

#[tokio::test]
async fn serve_server_connection_relays_to_connected_target() {
    let psk = TEST_PSK;
    let echo_listener = test_tcp_listener().await;
    let echo_addr = echo_listener.local_addr().unwrap();
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();

    let echo = async {
        let (mut stream, _) = echo_listener.accept().await.unwrap();
        let mut input = Vec::new();
        stream.read_to_end(&mut input).await.unwrap();
        assert_eq!(input, b"ping");
        stream.write_all(b"pong").await.unwrap();
        stream.shutdown().await.unwrap();
    };

    let server = async {
        let (client, _) = snell_listener.accept().await.unwrap();
        serve_server_connection_with_target_opener(
            client,
            psk,
            direct_options(true),
            move |target, _options| async move {
                assert_eq!(target.host, "example.com");
                assert_eq!(target.port, 443);
                Ok(TcpStream::connect(echo_addr).await?)
            },
        )
        .await
        .unwrap()
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        let snell = TcpClientStream::open_io(
            reader,
            writer,
            psk,
            "example.com",
            443,
            ProtocolVersion::V4,
            false,
        )
        .await
        .unwrap();
        let (mut snell_reader, mut snell_writer) = snell.into_split();

        write_client_payload(&mut snell_writer, b"ping")
            .await
            .unwrap();
        snell_writer.close_write().await.unwrap();

        let payload = snell_reader.take_payload_chunk().await.unwrap().unwrap();
        assert_eq!(&payload[..], b"pong");
        assert!(snell_reader.take_payload_chunk().await.unwrap().is_none());
    };

    let ((), (), ()) = tokio::join!(server, client, echo);
}

#[tokio::test]
async fn serve_server_connection_relays_v5_family_to_connected_target() {
    let psk = TEST_PSK;
    let echo_listener = test_tcp_listener().await;
    let echo_addr = echo_listener.local_addr().unwrap();
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();

    let echo = async {
        let (mut stream, _) = echo_listener.accept().await.unwrap();
        let mut input = Vec::new();
        stream.read_to_end(&mut input).await.unwrap();
        assert_eq!(input, b"v5 ping");
        stream.write_all(b"v5 pong").await.unwrap();
        stream.shutdown().await.unwrap();
    };

    let server = async {
        let (client, _) = snell_listener.accept().await.unwrap();
        serve_server_connection_with_target_opener(
            client,
            psk,
            direct_options(true),
            move |target, _options| async move {
                assert_eq!(target.host, "v5.example.com");
                assert_eq!(target.port, 443);
                Ok(TcpStream::connect(echo_addr).await?)
            },
        )
        .await
        .unwrap()
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        let snell = TcpClientStream::open_io(
            reader,
            writer,
            psk,
            "v5.example.com",
            443,
            ProtocolVersion::V5,
            false,
        )
        .await
        .unwrap();
        let (mut snell_reader, mut snell_writer) = snell.into_split();

        write_client_payload(&mut snell_writer, b"v5 ping")
            .await
            .unwrap();
        snell_writer.close_write().await.unwrap();

        let payload = snell_reader.take_payload_chunk().await.unwrap().unwrap();
        assert_eq!(&payload[..], b"v5 pong");
        assert!(snell_reader.take_payload_chunk().await.unwrap().is_none());
    };

    let ((), (), ()) = tokio::join!(server, client, echo);
}

#[tokio::test]
async fn serve_server_connection_relays_v6_to_connected_target() {
    let psk = TEST_PSK;
    let echo_listener = test_tcp_listener().await;
    let echo_addr = echo_listener.local_addr().unwrap();
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();

    let echo = async {
        let (mut stream, _) = echo_listener.accept().await.unwrap();
        let mut input = Vec::new();
        stream.read_to_end(&mut input).await.unwrap();
        assert_eq!(input, b"v6 ping");
        stream.write_all(b"v6 pong").await.unwrap();
        stream.shutdown().await.unwrap();
    };

    let server = async {
        let (client, _) = snell_listener.accept().await.unwrap();
        serve_server_connection_with_target_opener(
            client,
            psk,
            direct_options(true),
            move |target, _options| async move {
                assert_eq!(target.host, "v6.example.com");
                assert_eq!(target.port, 443);
                Ok(TcpStream::connect(echo_addr).await?)
            },
        )
        .await
        .unwrap()
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        let snell = TcpClientStream::open_io(
            reader,
            writer,
            psk,
            "v6.example.com",
            443,
            ProtocolVersion::V6,
            false,
        )
        .await
        .unwrap();
        let (mut snell_reader, mut snell_writer) = snell.into_split();

        write_client_payload(&mut snell_writer, b"v6 ping")
            .await
            .unwrap();
        snell_writer.close_write().await.unwrap();

        let payload = snell_reader.take_payload_chunk().await.unwrap().unwrap();
        assert_eq!(&payload[..], b"v6 pong");
        assert!(snell_reader.take_payload_chunk().await.unwrap().is_none());
    };

    let ((), (), ()) = tokio::join!(server, client, echo);
}

#[tokio::test]
async fn v4_family_detection_does_not_pollute_v6_replay_cache() {
    let psk = TEST_PSK;
    let salt = [0x44; 16];
    let cache = V6SaltReplayCache::new(16);
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();

    let server = async {
        let (first, _) = snell_listener.accept().await.unwrap();
        serve_server_connection_with_salt_replay_cache(
            first,
            psk,
            direct_options(false),
            cache.clone(),
        )
        .await
        .unwrap();

        let (second, _) = snell_listener.accept().await.unwrap();
        serve_server_connection_with_salt_replay_cache(second, psk, direct_options(false), cache)
            .await
            .unwrap();
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (snell_reader_io, mut snell_writer_io) = stream.into_split();
        write_v4_test_frame_with_salt(
            &mut snell_writer_io,
            psk,
            salt,
            &[PROTOCOL_VERSION, COMMAND_PING],
        )
        .await
        .unwrap();
        let mut reader = SnellStreamReader::new(snell_reader_io, psk, ProtocolVersion::V4);
        let payload = reader.read_frame_payload().await.unwrap();
        assert_eq!(parse_server_reply(payload).unwrap(), ServerReply::Pong);

        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (snell_reader_io, snell_writer_io) = stream.into_split();
        let mut writer = SnellStreamWriter::new_with_v6_salt(snell_writer_io, psk, salt).unwrap();
        writer
            .write_test_frame(&[PROTOCOL_VERSION, COMMAND_PING])
            .await
            .unwrap();
        let mut reader = SnellStreamReader::new(snell_reader_io, psk, ProtocolVersion::V6);
        let payload = reader.read_frame_payload().await.unwrap();
        assert_eq!(parse_server_reply(payload).unwrap(), ServerReply::Pong);
    };

    let ((), ()) = tokio::join!(server, client);
}

#[tokio::test]
async fn serve_server_connection_handles_v6_ping() {
    let psk = TEST_PSK;
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();

    let server = async {
        let (client, _) = snell_listener.accept().await.unwrap();
        serve_server_connection(client, psk, direct_options(false))
            .await
            .unwrap()
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (snell_reader_io, snell_writer_io) = stream.into_split();
        let mut snell_writer =
            SnellStreamWriter::new(snell_writer_io, psk, ProtocolVersion::V6).unwrap();
        snell_writer
            .write_test_frame(&[PROTOCOL_VERSION, COMMAND_PING])
            .await
            .unwrap();

        let mut snell_reader = SnellStreamReader::new(snell_reader_io, psk, ProtocolVersion::V6);
        let payload = snell_reader.read_frame_payload().await.unwrap();
        assert_eq!(parse_server_reply(payload).unwrap(), ServerReply::Pong);
    };

    let ((), ()) = tokio::join!(server, client);
}

#[tokio::test]
async fn serve_server_connection_v6_rejects_replayed_client_salt() {
    let psk = TEST_PSK;
    let salt = [0x44; 16];
    let cache = V6SaltReplayCache::new(16);
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();

    let server = async {
        let (first, _) = snell_listener.accept().await.unwrap();
        serve_server_connection_with_salt_replay_cache(
            first,
            psk,
            direct_options(false),
            cache.clone(),
        )
        .await
        .unwrap();

        let (second, _) = snell_listener.accept().await.unwrap();
        assert!(matches!(
            serve_server_connection_with_salt_replay_cache(
                second,
                psk,
                direct_options(false),
                cache,
            )
            .await,
            Err(Error::SaltReplay)
        ));
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (snell_reader_io, snell_writer_io) = stream.into_split();
        let mut writer = SnellStreamWriter::new_with_v6_salt(snell_writer_io, psk, salt).unwrap();
        writer
            .write_test_frame(&[PROTOCOL_VERSION, COMMAND_PING])
            .await
            .unwrap();
        let mut reader = SnellStreamReader::new(snell_reader_io, psk, ProtocolVersion::V6);
        let payload = reader.read_frame_payload().await.unwrap();
        assert_eq!(parse_server_reply(payload).unwrap(), ServerReply::Pong);

        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (snell_reader_io, snell_writer_io) = stream.into_split();
        let mut writer = SnellStreamWriter::new_with_v6_salt(snell_writer_io, psk, salt).unwrap();
        writer
            .write_test_frame(&[PROTOCOL_VERSION, COMMAND_PING])
            .await
            .unwrap();
        let mut reader = SnellStreamReader::new(snell_reader_io, psk, ProtocolVersion::V6);
        let err = reader.read_frame_payload().await.unwrap_err();
        assert!(err.is_closed_io(), "{err:?}");
    };

    let ((), ()) = tokio::join!(server, client);
}

#[tokio::test]
async fn serve_server_connection_relays_via_upstream_socks5() {
    let psk = TEST_PSK;
    let echo_listener = test_tcp_listener().await;
    let echo_addr = echo_listener.local_addr().unwrap();
    let socks_listener = test_tcp_listener().await;
    let socks_addr = socks_listener.local_addr().unwrap();
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();

    let echo = async {
        let (mut stream, _) = echo_listener.accept().await.unwrap();
        let mut input = Vec::new();
        stream.read_to_end(&mut input).await.unwrap();
        assert_eq!(input, b"ping");
        stream.write_all(b"pong").await.unwrap();
        stream.shutdown().await.unwrap();
    };

    let socks = async {
        let (mut client, _) = socks_listener.accept().await.unwrap();
        let request = read_client_request(&mut client).await.unwrap();
        assert_eq!(
            request,
            SocksRequest::Connect(SocksTarget {
                host: "example.com".to_owned(),
                port: 443,
            })
        );
        let mut upstream = TcpStream::connect(echo_addr).await.unwrap();
        write_reply_with_bind(
            &mut client,
            SocksReply::Succeeded,
            "0.0.0.0:0".parse().unwrap(),
        )
        .await
        .unwrap();
        tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .unwrap();
    };

    let server = async {
        let (client, _) = snell_listener.accept().await.unwrap();
        serve_server_connection(client, psk, socks5_options(true, socks_addr))
            .await
            .unwrap()
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        let snell = TcpClientStream::open_io(
            reader,
            writer,
            psk,
            "example.com",
            443,
            ProtocolVersion::V4,
            false,
        )
        .await
        .unwrap();
        let (mut snell_reader, mut snell_writer) = snell.into_split();

        write_client_payload(&mut snell_writer, b"ping")
            .await
            .unwrap();
        snell_writer.close_write().await.unwrap();

        let payload = snell_reader.take_payload_chunk().await.unwrap().unwrap();
        assert_eq!(&payload[..], b"pong");
        assert!(snell_reader.take_payload_chunk().await.unwrap().is_none());
    };

    let ((), (), (), ()) = tokio::join!(echo, socks, server, client);
}

#[tokio::test]
async fn serve_server_connection_closes_when_upstream_socks5_rejects_after_fast_open() {
    let psk = TEST_PSK;
    let socks_listener = test_tcp_listener().await;
    let socks_addr = socks_listener.local_addr().unwrap();
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();

    let socks = async {
        let (mut client, _) = socks_listener.accept().await.unwrap();
        let request = read_client_request(&mut client).await.unwrap();
        assert!(matches!(request, SocksRequest::Connect(_)));
        write_reply_with_bind(
            &mut client,
            SocksReply::GeneralFailure,
            "0.0.0.0:0".parse().unwrap(),
        )
        .await
        .unwrap();
    };

    let server = async {
        let (client, _) = snell_listener.accept().await.unwrap();
        serve_server_connection(client, psk, socks5_options(true, socks_addr)).await
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        let snell = TcpClientStream::open_io(
            reader,
            writer,
            psk,
            "example.com",
            443,
            ProtocolVersion::V4,
            false,
        )
        .await
        .unwrap();
        let (mut snell_reader, _) = snell.into_split();
        assert!(
            timeout(Duration::from_secs(1), snell_reader.take_payload_chunk())
                .await
                .unwrap()
                .unwrap()
                .is_none()
        );
    };

    let ((), server_result, ()) = tokio::join!(socks, server, client);
    assert!(matches!(server_result, Err(Error::Socks5Reply(1))));
}

#[tokio::test]
async fn serve_server_connection_fast_open_accepts_before_target_connects() {
    let psk = TEST_PSK;
    let echo_listener = test_tcp_listener().await;
    let echo_addr = echo_listener.local_addr().unwrap();
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();
    let (connect_tx, connect_rx) = oneshot::channel();

    let echo = async {
        let (mut stream, _) = echo_listener.accept().await.unwrap();
        let mut input = Vec::new();
        stream.read_to_end(&mut input).await.unwrap();
        assert_eq!(input, b"early");
        stream.write_all(b"pong").await.unwrap();
        stream.shutdown().await.unwrap();
    };

    let server = async {
        let (client, _) = snell_listener.accept().await.unwrap();
        let mut connect_rx = Some(connect_rx);
        serve_server_connection_with_target_opener(
            client,
            psk,
            direct_options(true),
            move |target, _options| {
                let connect_rx = connect_rx.take().unwrap();
                async move {
                    assert_eq!(target.host, "example.com");
                    assert_eq!(target.port, 443);
                    connect_rx.await.unwrap();
                    Ok(TcpStream::connect(echo_addr).await?)
                }
            },
        )
        .await
        .unwrap()
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (snell_reader_io, snell_writer_io) = stream.into_split();
        let mut snell_reader = SnellStreamReader::new(snell_reader_io, psk, ProtocolVersion::V4);
        let mut snell_writer =
            SnellStreamWriter::new(snell_writer_io, psk, ProtocolVersion::V4).unwrap();
        snell_writer
            .write_tcp_request("example.com", 443, false)
            .await
            .unwrap();

        let payload = timeout(
            Duration::from_millis(200),
            snell_reader.read_frame_payload(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            parse_server_reply(payload).unwrap(),
            ServerReply::Tunnel {
                payload_span: Range { start: 1, end: 1 },
                payload: b"",
            }
        );

        snell_writer.write_test_frame(b"early").await.unwrap();
        snell_writer.write_zero_chunk().await.unwrap();
        connect_tx.send(()).unwrap();

        let payload = snell_reader.read_frame_payload().await.unwrap();
        assert_eq!(payload, b"pong");
        assert!(matches!(
            snell_reader.read_frame_payload().await,
            Err(Error::ZeroChunk)
        ));
    };

    let ((), (), ()) = tokio::join!(echo, server, client);
}

#[tokio::test]
async fn serve_tcp_listener_with_shutdown_stops_accepting_connections() {
    let psk = TEST_PSK;
    let listener = test_tcp_listener().await;
    let addr = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let server = tokio::spawn(serve_tcp_listener_with_shutdown_and_timeout(
        listener,
        tcp_server_runtime(
            psk,
            direct_options(true),
            shutdown.clone(),
            Duration::from_millis(100),
        ),
    ));

    shutdown.cancel();
    timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert!(TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
async fn serve_tcp_listeners_accepts_connections_on_each_listener() {
    let psk = TEST_PSK;
    let first = test_tcp_listener().await;
    let first_addr = first.local_addr().unwrap();
    let second = test_tcp_listener().await;
    let second_addr = second.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let server = tokio::spawn(serve_tcp_listeners_with_shutdown_and_timeout(
        vec![first, second],
        TcpServerRuntime {
            v6_salt_replay_cache: V6SaltReplayCache::new(16),
            ..tcp_server_runtime(
                psk,
                direct_options(false),
                shutdown.clone(),
                Duration::from_millis(100),
            )
        },
    ));

    assert_snell_ping(first_addr, psk, ProtocolVersion::V6).await;
    assert_snell_ping(second_addr, psk, ProtocolVersion::V6).await;
    shutdown.cancel();
    timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn serve_tcp_listener_auto_detects_v5_family_and_v6_on_same_listener() {
    let psk = TEST_PSK;
    let listener = test_tcp_listener().await;
    let addr = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let server = tokio::spawn(serve_tcp_listener_with_shutdown_and_timeout(
        listener,
        tcp_server_runtime(
            psk,
            direct_options(false),
            shutdown.clone(),
            Duration::from_millis(100),
        ),
    ));

    assert_snell_ping(addr, psk, ProtocolVersion::V5).await;
    assert_snell_ping(addr, psk, ProtocolVersion::V6).await;
    shutdown.cancel();
    timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn serve_tcp_listener_with_shutdown_drains_active_connection() {
    let psk = TEST_PSK;
    let echo_listener = test_tcp_listener().await;
    let echo_addr = echo_listener.local_addr().unwrap();
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let (echo_ready_tx, echo_ready_rx) = oneshot::channel();
    let (echo_continue_tx, echo_continue_rx) = oneshot::channel();
    let server = tokio::spawn(serve_tcp_listener_with_shutdown_and_timeout(
        snell_listener,
        tcp_server_runtime(
            psk,
            direct_options(true),
            shutdown.clone(),
            Duration::from_secs(1),
        ),
    ));

    let echo = async {
        let (mut stream, _) = echo_listener.accept().await.unwrap();
        let mut input = Vec::new();
        stream.read_to_end(&mut input).await.unwrap();
        assert_eq!(input, b"ping");
        echo_ready_tx.send(()).unwrap();
        echo_continue_rx.await.unwrap();
        stream.write_all(b"pong").await.unwrap();
        stream.shutdown().await.unwrap();
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        let snell = TcpClientStream::open_io(
            reader,
            writer,
            psk,
            "127.0.0.1",
            echo_addr.port(),
            ProtocolVersion::V4,
            false,
        )
        .await
        .unwrap();
        let (mut snell_reader, mut snell_writer) = snell.into_split();

        write_client_payload(&mut snell_writer, b"ping")
            .await
            .unwrap();
        snell_writer.close_write().await.unwrap();
        echo_ready_rx.await.unwrap();

        shutdown.cancel();
        echo_continue_tx.send(()).unwrap();

        let payload = snell_reader.take_payload_chunk().await.unwrap().unwrap();
        assert_eq!(&payload[..], b"pong");
        assert!(snell_reader.take_payload_chunk().await.unwrap().is_none());
    };

    let ((), ()) = tokio::join!(client, echo);
    timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn bind_tcp_listener_accepts_tcp_fast_open_flag() {
    let listener = bind_tcp_listener("127.0.0.1:0".parse().unwrap(), true).unwrap();
    let addr = listener.local_addr().unwrap();

    let server = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut input = [0; 4];
        stream.read_exact(&mut input).await.unwrap();
        assert_eq!(&input, b"ping");
        stream.write_all(b"pong").await.unwrap();
    };

    let client = async {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"ping").await.unwrap();

        let mut output = [0; 4];
        stream.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"pong");
    };

    let ((), ()) = tokio::join!(server, client);
}

#[tokio::test]
async fn connect_target_rejects_ipv6_literal_when_disabled() {
    let resolver = crate::net::dns::DnsResolver::system();
    let result = crate::proxy::outbound::direct::open_direct_tcp(
        "::1",
        443,
        false,
        crate::net::dns::DnsIpPreference::Default,
        &resolver,
    )
    .await;

    assert!(matches!(
        result,
        Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::InvalidInput
    ));
}

#[tokio::test]
async fn serve_server_connection_closes_after_fast_open_connect_failure() {
    let psk = TEST_PSK;
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();

    let server = async {
        let (client, _) = snell_listener.accept().await.unwrap();
        serve_server_connection_with_target_opener(
            client,
            psk,
            direct_options(true),
            |_target, _options| async move {
                Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "test refusal",
                )))
            },
        )
        .await
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (snell_reader_io, snell_writer_io) = stream.into_split();
        let mut snell_writer =
            SnellStreamWriter::new(snell_writer_io, psk, ProtocolVersion::V4).unwrap();
        snell_writer
            .write_tcp_request("blocked.example", 443, false)
            .await
            .unwrap();

        let mut snell_reader = SnellStreamReader::new(snell_reader_io, psk, ProtocolVersion::V4);
        let payload = snell_reader.read_frame_payload().await.unwrap();
        assert_eq!(
            parse_server_reply(payload).unwrap(),
            ServerReply::Tunnel {
                payload_span: Range { start: 1, end: 1 },
                payload: b"",
            }
        );
        let err = snell_reader.read_frame_payload().await.unwrap_err();
        assert!(err.is_closed_io(), "{err:?}");
    };

    let (server_result, ()) = tokio::join!(server, client);
    assert!(matches!(server_result, Err(Error::Io(_))));
}

#[tokio::test]
async fn serve_server_connection_v6_returns_error_reply_on_connect_failure() {
    let psk = TEST_PSK;
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();

    let server = async {
        let (client, _) = snell_listener.accept().await.unwrap();
        serve_server_connection_with_target_opener(
            client,
            psk,
            direct_options(true),
            |_target, _options| async move {
                Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "test refusal",
                )))
            },
        )
        .await
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (snell_reader_io, snell_writer_io) = stream.into_split();
        let mut snell_writer =
            SnellStreamWriter::new(snell_writer_io, psk, ProtocolVersion::V6).unwrap();
        snell_writer
            .write_tcp_request("blocked.example", 443, false)
            .await
            .unwrap();

        let mut snell_reader = SnellStreamReader::new(snell_reader_io, psk, ProtocolVersion::V6);
        let payload = snell_reader.read_frame_payload().await.unwrap();
        assert_eq!(
            parse_server_reply(payload).unwrap(),
            ServerReply::Error {
                code: V6_ERROR_CONNECTION_REFUSED,
                message: "test refusal",
            }
        );
    };

    let (server_result, ()) = tokio::join!(server, client);
    assert!(matches!(server_result, Err(Error::Io(_))));
}

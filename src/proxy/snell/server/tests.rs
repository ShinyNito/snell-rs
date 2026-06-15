use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::{Duration, sleep, timeout};

use super::{
    SERVER_EARLY_UPLOAD_BUFFER_LIMIT, V6_ERROR_DNS_FAILED, V6_ERROR_DNS_FAILED_MESSAGE,
    V6_ERROR_FALLBACK, buffer_upload_until_connected, serve_server_connection,
    v6_server_error_reply,
};
use crate::MAX_PACKET_SIZE;
use crate::ProtocolVersion;
use crate::error::Error;
use crate::net::dns::DnsResolver;
use crate::protocol::request::{
    ClientRequest, ServerReply, parse_client_request, parse_server_reply,
};
use crate::protocol::udp::AddressRef;
use crate::protocol::v6::V6SaltReplayCache;
use crate::proxy::outbound::RelayOptions;
use crate::relay::activity::{RelayActivity, RelayActivityTimeouts};
use crate::relay::tcp::{PrefixedReadStream, ReadPrefixBuffer, TcpClosePolicy, TcpRelayDriver};
use crate::test_support::{
    read_snell_frame_payload, test_duplex_pair, test_secret, test_snell_reader, test_snell_writer,
    test_tcp_listener, test_udp_socket, write_snell_payload_message, write_snell_udp_packet,
};
use crate::transport::tcp::TcpServerStream;
use crate::transport::udp::stream::UdpClientStream;

#[test]
fn v6_server_error_reply_maps_dns_errors_structurally() {
    let (code, message) = v6_server_error_reply(&Error::DnsUnavailable);
    assert_eq!(code, V6_ERROR_DNS_FAILED);
    assert_eq!(message, V6_ERROR_DNS_FAILED_MESSAGE);

    let (code, message) = v6_server_error_reply(&Error::DnsTimeout);
    assert_eq!(code, V6_ERROR_DNS_FAILED);
    assert_eq!(message, V6_ERROR_DNS_FAILED_MESSAGE);
}

#[test]
fn v6_server_error_reply_does_not_parse_io_error_text() {
    let (code, message) =
        v6_server_error_reply(&Error::Io(std::io::Error::other("dns resolution failed")));

    assert_eq!(code, V6_ERROR_FALLBACK);
    assert_eq!(message, "dns resolution failed");
}

#[tokio::test]
async fn early_upload_buffer_stops_before_next_frame_could_exceed_limit() {
    let (client_upload, server_upload) = test_duplex_pair();

    let mut writer = test_snell_writer(client_upload);
    write_snell_payload_message(&mut writer, b"held")
        .await
        .unwrap();

    let reader = test_snell_reader(server_upload);
    let writer = test_snell_writer(tokio::io::sink());
    let mut snell = TcpServerStream::from_parts_with_pending(reader, writer, Bytes::new());
    let mut read_prefix = ReadPrefixBuffer::new();
    let initial_len = SERVER_EARLY_UPLOAD_BUFFER_LIMIT - MAX_PACKET_SIZE + 1;
    read_prefix.push(Bytes::from(vec![0; initial_len]));

    let (connect_tx, connect_rx) = oneshot::channel();
    let connect = async {
        connect_rx.await.unwrap();
        Ok::<_, Error>(())
    };
    let (activity, _last_activity) = RelayActivity::new();
    {
        let early_upload =
            buffer_upload_until_connected(&mut snell, connect, &mut read_prefix, &activity);
        tokio::pin!(early_upload);

        assert!(
            timeout(Duration::from_millis(50), &mut early_upload)
                .await
                .is_err()
        );
        connect_tx.send(()).unwrap();
        early_upload.await.unwrap();
    }
    assert_eq!(read_prefix.len(), initial_len);
}

#[tokio::test]
async fn reusable_relay_releases_upstream_when_upstream_closes_first() {
    let (client_upload, server_upload) = test_duplex_pair();
    let (server_download, client_download) = test_duplex_pair();
    let upstream_listener = test_tcp_listener().await;
    let upstream = TcpStream::connect(upstream_listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut target, _) = upstream_listener.accept().await.unwrap();
    let (released_tx, released_rx) = oneshot::channel();

    let target = async {
        target.shutdown().await.unwrap();

        let mut buf = [0; 1];
        let n = timeout(Duration::from_secs(1), target.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0);
        released_tx.send(()).unwrap();
    };

    let client = async {
        let mut reader = test_snell_reader(client_download);
        let mut writer = test_snell_writer(client_upload);

        let payload = read_snell_frame_payload(&mut reader).await.unwrap();
        assert!(matches!(
            parse_server_reply(&payload),
            Ok(ServerReply::Tunnel {
                payload_start: 1,
                payload: []
            })
        ));
        assert!(matches!(
            read_snell_frame_payload(&mut reader).await,
            Err(Error::ZeroChunk)
        ));

        timeout(Duration::from_secs(1), released_rx)
            .await
            .unwrap()
            .unwrap();
        poll_fn(|cx| writer.poll_write_zero_chunk(cx))
            .await
            .unwrap();
        writer
            .write_tcp_request("next.example", 443, true)
            .await
            .unwrap();
    };

    let server = async {
        let reader = test_snell_reader(server_upload);
        let writer = test_snell_writer(server_download);
        let snell = TcpServerStream::from_parts_with_pending(reader, writer, Bytes::new());
        let (activity, _last_activity) = RelayActivity::new();

        let upstream = upstream;
        let mut snell = snell;
        let stats = {
            tokio::pin!(upstream);
            let prefixed_snell =
                PrefixedReadStream::new(std::pin::Pin::new(&mut snell), ReadPrefixBuffer::new());
            tokio::pin!(prefixed_snell);
            let relay = TcpRelayDriver::new(
                upstream.as_mut(),
                prefixed_snell.as_mut(),
                TcpClosePolicy::EndWhenPlainToSnellClosed,
                activity.clone(),
            );
            tokio::pin!(relay);
            relay.as_mut().await.unwrap()
        };
        super::drain_tcp_stream(&mut snell, &activity)
            .await
            .unwrap();
        let (mut reader, _) = snell.into_frame_parts();

        assert_eq!(stats.uploaded, 0);
        assert_eq!(stats.downloaded, 0);
        let payload = read_snell_frame_payload(&mut reader).await.unwrap();
        assert_eq!(
            parse_client_request(&payload).unwrap(),
            ClientRequest::Connect {
                reuse: true,
                host: "next.example",
                port: 443,
                rest_start: 18,
                rest: b"",
            }
        );
    };

    let ((), (), ()) = tokio::join!(client, target, server);
}

#[tokio::test]
async fn server_tcp_relay_reports_uploaded_and_downloaded_for_reusable_policy() {
    let upload = b"client-upload";
    let download = b"target-download";
    let (client_upload, server_upload) = test_duplex_pair();
    let (server_download, client_download) = test_duplex_pair();
    let upstream_listener = test_tcp_listener().await;
    let upstream = TcpStream::connect(upstream_listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut target, _) = upstream_listener.accept().await.unwrap();

    let target = async {
        let mut received = vec![0; upload.len()];
        target.read_exact(&mut received).await.unwrap();
        assert_eq!(received, upload);
        target.write_all(download).await.unwrap();
        target.shutdown().await.unwrap();
    };

    let client = async {
        let mut reader = test_snell_reader(client_download);
        let mut writer = test_snell_writer(client_upload);
        write_snell_payload_message(&mut writer, upload)
            .await
            .unwrap();
        poll_fn(|cx| writer.poll_write_zero_chunk(cx))
            .await
            .unwrap();

        let payload = read_snell_frame_payload(&mut reader).await.unwrap();
        assert!(matches!(
            parse_server_reply(&payload),
            Ok(ServerReply::Tunnel {
                payload_start: 1,
                payload
            }) if payload == download
        ));
        assert!(matches!(
            read_snell_frame_payload(&mut reader).await,
            Err(Error::ZeroChunk)
        ));
    };

    let server = async {
        let reader = test_snell_reader(server_upload);
        let writer = test_snell_writer(server_download);
        let snell = TcpServerStream::from_parts_with_pending(reader, writer, Bytes::new());
        let (activity, _last_activity) = RelayActivity::new();

        let upstream = upstream;
        let mut snell = snell;
        let stats = {
            tokio::pin!(upstream);
            let prefixed_snell =
                PrefixedReadStream::new(std::pin::Pin::new(&mut snell), ReadPrefixBuffer::new());
            tokio::pin!(prefixed_snell);
            let relay = TcpRelayDriver::new(
                upstream.as_mut(),
                prefixed_snell.as_mut(),
                TcpClosePolicy::EndWhenPlainToSnellClosed,
                activity,
            );
            tokio::pin!(relay);
            relay.as_mut().await.unwrap()
        };

        assert_eq!(stats.uploaded, upload.len() as u64);
        assert_eq!(stats.downloaded, download.len() as u64);
    };

    let ((), (), ()) = tokio::join!(client, target, server);
}

#[tokio::test]
async fn serve_server_connection_times_out_before_handshake_activity() {
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();
    let timeouts = short_activity_timeouts();

    let server = tokio::spawn(async move {
        let (client, _) = snell_listener.accept().await.unwrap();
        serve_server_connection(
            client,
            test_secret(),
            direct_options(),
            V6SaltReplayCache::default(),
            |_target, _options| async move { panic!("target opener should not run") },
            timeouts,
        )
        .await
    });

    let mut client = TcpStream::connect(snell_addr).await.unwrap();
    let server_result = timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        server_result,
        Err(Error::SnellServerTcpIdleTimeout)
    ));

    let mut buf = [0; 1];
    let n = timeout(Duration::from_secs(1), client.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn serve_server_connection_switches_to_idle_timeout_after_first_activity() {
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();
    let timeouts =
        RelayActivityTimeouts::new(Duration::from_millis(40), Duration::from_millis(160));

    let server = tokio::spawn(async move {
        let (client, _) = snell_listener.accept().await.unwrap();
        serve_server_connection(
            client,
            test_secret(),
            direct_options(),
            V6SaltReplayCache::default(),
            |_target, _options| async move { panic!("target opener should not run") },
            timeouts,
        )
        .await
    });

    let mut client = TcpStream::connect(snell_addr).await.unwrap();
    client.write_all(&[0]).await.unwrap();

    let mut buf = [0; 1];
    assert!(
        timeout(Duration::from_millis(80), client.read(&mut buf))
            .await
            .is_err()
    );

    let n = timeout(Duration::from_secs(1), client.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);
    let server_result = server.await.unwrap();
    assert!(matches!(
        server_result,
        Err(Error::SnellServerTcpIdleTimeout)
    ));
}

#[tokio::test]
async fn serve_server_connection_times_out_idle_tcp_tunnel() {
    let upstream_listener = test_tcp_listener().await;
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();
    let timeouts = short_activity_timeouts();

    let upstream = async {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        let mut buf = [0; 1];
        let n = timeout(Duration::from_secs(1), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0);
    };

    let server = async {
        let (client, _) = snell_listener.accept().await.unwrap();
        serve_server_connection(
            client,
            test_secret(),
            direct_options(),
            V6SaltReplayCache::default(),
            move |_target, _options| async move { Ok(TcpStream::connect(upstream_addr).await?) },
            timeouts,
        )
        .await
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (snell_reader_io, snell_writer_io) = stream.into_split();
        let mut snell_reader = crate::test_support::test_snell_reader(snell_reader_io);
        let mut snell_writer = crate::test_support::test_snell_writer(snell_writer_io);

        snell_writer
            .write_tcp_request("example.com", 443, false)
            .await
            .unwrap();
        let payload = read_snell_frame_payload(&mut snell_reader).await.unwrap();
        assert_eq!(
            parse_server_reply(&payload).unwrap(),
            ServerReply::Tunnel {
                payload_start: 1,
                payload: b"",
            }
        );

        let err = timeout(
            Duration::from_secs(1),
            read_snell_frame_payload(&mut snell_reader),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(err.is_closed_io(), "{err:?}");
    };

    let ((), server_result, ()) = tokio::join!(upstream, server, client);
    assert!(matches!(
        server_result,
        Err(Error::SnellServerTcpIdleTimeout)
    ));
}

#[tokio::test]
async fn serve_server_connection_udp_activity_resets_tcp_idle_timeout() {
    let udp_target = test_udp_socket().await;
    let target_addr = udp_target.local_addr().unwrap();
    let snell_listener = test_tcp_listener().await;
    let snell_addr = snell_listener.local_addr().unwrap();
    let timeouts = short_activity_timeouts();

    let target = async {
        let mut input = [0; 64];
        for _ in 0..3 {
            let (n, _) = timeout(Duration::from_secs(1), udp_target.recv_from(&mut input))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&input[..n], b"query");
        }
    };

    let server = async {
        let (client, _) = snell_listener.accept().await.unwrap();
        serve_server_connection(
            client,
            test_secret(),
            direct_options(),
            V6SaltReplayCache::default(),
            |_target, _options| async move { panic!("target opener should not run") },
            timeouts,
        )
        .await
    };

    let client = async {
        let stream = TcpStream::connect(snell_addr).await.unwrap();
        let (reader_io, writer_io) = stream.into_split();
        let secret = test_secret();
        let (mut reader, mut writer) =
            UdpClientStream::open_io(reader_io, writer_io, &secret, ProtocolVersion::V4)
                .await
                .unwrap()
                .into_parts();

        for index in 0..3 {
            write_snell_udp_packet(
                &mut writer,
                AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                target_addr.port(),
                b"query",
            )
            .await
            .unwrap();
            if index < 2 {
                sleep(Duration::from_millis(50)).await;
            }
        }

        assert!(
            timeout(
                Duration::from_millis(40),
                poll_fn(|cx| reader.poll_read_udp_response_message(cx))
            )
            .await
            .is_err()
        );
        poll_fn(|cx| writer.poll_write_zero_chunk(cx))
            .await
            .unwrap();
    };

    let ((), server_result, ()) = tokio::join!(target, server, client);
    assert!(server_result.is_ok(), "{server_result:?}");
}

fn short_activity_timeouts() -> RelayActivityTimeouts {
    RelayActivityTimeouts::new(Duration::from_millis(40), Duration::from_millis(80))
}

fn direct_options() -> RelayOptions {
    RelayOptions::direct(true, DnsResolver::system())
}

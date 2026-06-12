use core::range::Range;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::{Duration, timeout};

use super::{
    SERVER_FAST_OPEN_BUFFER_LIMIT, V6_ERROR_DNS_FAILED, V6_ERROR_DNS_FAILED_MESSAGE,
    V6_ERROR_FALLBACK, buffer_fast_open_payload_until_connected, relay_tcp_server_stream_reusable,
    v6_server_error_reply,
};
use crate::error::Error;
use crate::framed::{
    STREAM_BUFFER_INITIAL_CAPACITY, STREAM_BUFFER_RETAIN_CAPACITY, SnellStreamReader,
    SnellStreamWriter,
};
use crate::protocol::request::{ClientRequest, ServerReply};
use crate::session::tcp::{TcpPayloadReader, TcpServerStream};
use crate::{MAX_PACKET_SIZE, ProtocolVersion};

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
async fn reusable_relay_compacts_stream_buffers_after_request() {
    let psk = b"test psk";
    let upload = vec![0x51; STREAM_BUFFER_INITIAL_CAPACITY * 4];
    let download = vec![0x52; STREAM_BUFFER_INITIAL_CAPACITY * 4];
    let upload_len = upload.len();
    let download_len = download.len();

    let (client_upload, server_upload) = duplex(32 * 1024);
    let (server_download, client_download) = duplex(32 * 1024);
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = TcpStream::connect(upstream_listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut target, _) = upstream_listener.accept().await.unwrap();

    let client = async {
        let mut writer = SnellStreamWriter::new(client_upload, psk, ProtocolVersion::V4).unwrap();
        writer.write_test_frame(&upload).await.unwrap();
        writer.write_zero_chunk().await.unwrap();

        let mut reader = TcpPayloadReader::client(
            SnellStreamReader::new(client_download, psk, ProtocolVersion::V4).unwrap(),
        );
        reader.read_tunnel_reply().await.unwrap();

        let mut received = Vec::new();
        while let Some(payload) = reader.read_payload_chunk_strict().await.unwrap() {
            received.extend_from_slice(payload);
            let len = payload.len();
            reader.consume_payload_chunk(len);
        }
        assert_eq!(received, download);
    };

    let target = async {
        let mut received = Vec::new();
        target.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, upload);
        target.write_all(&download).await.unwrap();
        target.shutdown().await.unwrap();
    };

    let server = async {
        let reader = SnellStreamReader::new(server_upload, psk, ProtocolVersion::V4).unwrap();
        let writer = SnellStreamWriter::new(server_download, psk, ProtocolVersion::V4).unwrap();
        let snell = TcpServerStream::from_parts_with_pending(reader, writer, Bytes::new());

        let (stats, reader, writer) = relay_tcp_server_stream_reusable(snell, upstream, true)
            .await
            .unwrap();

        assert_eq!(stats.uploaded, upload_len as u64);
        assert_eq!(stats.downloaded, download_len as u64);
        assert!(reader.body_capacity() > STREAM_BUFFER_INITIAL_CAPACITY);
        assert!(reader.body_capacity() <= STREAM_BUFFER_RETAIN_CAPACITY);
        assert!(writer.frame_capacity() > STREAM_BUFFER_INITIAL_CAPACITY);
        assert!(writer.frame_capacity() <= STREAM_BUFFER_RETAIN_CAPACITY);
    };

    let ((), (), ()) = tokio::join!(client, target, server);
}

#[tokio::test]
async fn fast_open_buffer_stops_before_next_frame_could_exceed_limit() {
    let psk = b"test psk";
    let (client_upload, server_upload) = duplex(4096);

    let mut writer = SnellStreamWriter::new(client_upload, psk, ProtocolVersion::V4).unwrap();
    writer.write_test_frame(b"held").await.unwrap();

    let reader = SnellStreamReader::new(server_upload, psk, ProtocolVersion::V4).unwrap();
    let writer = SnellStreamWriter::new(tokio::io::sink(), psk, ProtocolVersion::V4).unwrap();
    let snell = TcpServerStream::from_parts_with_pending(reader, writer, Bytes::new());
    let (mut snell_reader, _) = snell.into_split();
    let mut early_payload = BytesMut::new();
    let initial_len = SERVER_FAST_OPEN_BUFFER_LIMIT - MAX_PACKET_SIZE + 1;
    early_payload.resize(initial_len, 0);

    let (connect_tx, connect_rx) = oneshot::channel();
    let connect = async {
        connect_rx.await.unwrap();
        Ok::<_, Error>(())
    };
    {
        let fast_open = buffer_fast_open_payload_until_connected(
            &mut snell_reader,
            connect,
            &mut early_payload,
        );
        tokio::pin!(fast_open);

        assert!(
            timeout(Duration::from_millis(50), &mut fast_open)
                .await
                .is_err()
        );
        connect_tx.send(()).unwrap();
        fast_open.await.unwrap();
    }
    assert_eq!(early_payload.len(), initial_len);
}

#[tokio::test]
async fn reusable_relay_releases_upstream_when_upstream_closes_first() {
    let psk = b"test psk";
    let (client_upload, server_upload) = duplex(4096);
    let (server_download, client_download) = duplex(4096);
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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
        let mut reader = SnellStreamReader::new(client_download, psk, ProtocolVersion::V4).unwrap();
        let mut writer = SnellStreamWriter::new(client_upload, psk, ProtocolVersion::V4).unwrap();

        assert!(matches!(
            reader.read_server_reply().await,
            Ok(ServerReply::Tunnel {
                payload_span: Range { start: 1, end: 1 },
                payload: []
            })
        ));
        assert!(matches!(
            reader.read_frame_payload().await,
            Err(Error::ZeroChunk)
        ));

        timeout(Duration::from_secs(1), released_rx)
            .await
            .unwrap()
            .unwrap();
        writer.write_zero_chunk().await.unwrap();
        writer
            .write_tcp_request("next.example", 443, true)
            .await
            .unwrap();
    };

    let server = async {
        let reader = SnellStreamReader::new(server_upload, psk, ProtocolVersion::V4).unwrap();
        let writer = SnellStreamWriter::new(server_download, psk, ProtocolVersion::V4).unwrap();
        let snell = TcpServerStream::from_parts_with_pending(reader, writer, Bytes::new());

        let (stats, mut reader, _) = relay_tcp_server_stream_reusable(snell, upstream, true)
            .await
            .unwrap();

        assert_eq!(stats.uploaded, 0);
        assert_eq!(stats.downloaded, 0);
        assert_eq!(
            reader.read_client_request().await.unwrap(),
            ClientRequest::Connect {
                reuse: true,
                host: "next.example",
                port: 443,
                rest_span: Range { start: 18, end: 18 },
                rest: b"",
            }
        );
    };

    let ((), (), ()) = tokio::join!(client, target, server);
}

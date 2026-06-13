use core::range::Range;
use std::io;
use std::io::IoSlice;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, duplex};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::{Duration, timeout};

use super::{
    SERVER_FAST_OPEN_BUFFER_LIMIT, V6_ERROR_DNS_FAILED, V6_ERROR_DNS_FAILED_MESSAGE,
    V6_ERROR_FALLBACK, buffer_fast_open_payload_until_connected,
    relay_tcp_reader_to_plain_vectored_counted_with_initial, relay_tcp_server_stream_reusable,
    v6_server_error_reply,
};
use crate::MAX_PACKET_SIZE;
use crate::error::Error;
use crate::framed::{STREAM_BUFFER_INITIAL_CAPACITY, STREAM_BUFFER_RETAIN_CAPACITY};
use crate::protocol::request::{ClientRequest, ServerReply};
use crate::session::tcp::{TcpPayloadReader, TcpServerStream};
use crate::test_support::{
    test_duplex_pair, test_snell_reader, test_snell_writer, test_tcp_listener,
};

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
    let upload = vec![0x51; STREAM_BUFFER_INITIAL_CAPACITY * 4];
    let download = vec![0x52; STREAM_BUFFER_INITIAL_CAPACITY * 4];
    let upload_len = upload.len();
    let download_len = download.len();

    let (client_upload, server_upload) = duplex(32 * 1024);
    let (server_download, client_download) = duplex(32 * 1024);
    let upstream_listener = test_tcp_listener().await;
    let upstream = TcpStream::connect(upstream_listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut target, _) = upstream_listener.accept().await.unwrap();

    let client = async {
        let mut writer = test_snell_writer(client_upload);
        writer.write_test_frame(&upload).await.unwrap();
        writer.write_zero_chunk().await.unwrap();

        let mut reader = TcpPayloadReader::client(test_snell_reader(client_download));
        reader.read_tunnel_reply().await.unwrap();

        let mut received = Vec::new();
        while let Some(payload) = reader.take_payload_chunk_strict().await.unwrap() {
            received.extend_from_slice(&payload);
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
        let reader = test_snell_reader(server_upload);
        let writer = test_snell_writer(server_download);
        let snell = TcpServerStream::from_parts_with_pending(reader, writer, Bytes::new());

        let (stats, reader, writer) = relay_tcp_server_stream_reusable(snell, upstream, true)
            .await
            .unwrap();

        assert_eq!(stats.uploaded, upload_len as u64);
        assert_eq!(stats.downloaded, download_len as u64);
        assert!(reader.body_capacity() <= STREAM_BUFFER_RETAIN_CAPACITY);
        assert!(writer.frame_capacity() <= STREAM_BUFFER_RETAIN_CAPACITY);
    };

    let ((), (), ()) = tokio::join!(client, target, server);
}

#[tokio::test]
async fn fast_open_buffer_stops_before_next_frame_could_exceed_limit() {
    let (client_upload, server_upload) = test_duplex_pair();

    let mut writer = test_snell_writer(client_upload);
    writer.write_test_frame(b"held").await.unwrap();

    let reader = test_snell_reader(server_upload);
    let writer = test_snell_writer(tokio::io::sink());
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
async fn server_plain_upload_coalesces_ready_records() {
    let payloads = [b"one".as_slice(), b"two".as_slice()];

    let mut coalesced_reader = tcp_reader_with_payloads(&payloads).await;
    let mut coalesced_plain = RecordingWriter::default();
    let mut coalesced_total = 0;
    relay_tcp_reader_to_plain_vectored_counted_with_initial(
        &mut coalesced_reader,
        &mut coalesced_plain,
        &mut coalesced_total,
        BytesMut::from(&b"early"[..]),
    )
    .await
    .unwrap();

    assert_eq!(coalesced_total, 11);
    assert_eq!(coalesced_plain.writes, vec![b"earlyonetwo".to_vec()]);
    assert_eq!(coalesced_plain.shutdowns, 1);
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
        let reader = test_snell_reader(server_upload);
        let writer = test_snell_writer(server_download);
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

async fn tcp_reader_with_payloads(
    payloads: &[&[u8]],
) -> crate::session::tcp::TcpReader<DuplexStream> {
    let (client_upload, server_upload) = test_duplex_pair();
    let mut client_writer = test_snell_writer(client_upload);
    for payload in payloads {
        client_writer.write_test_frame(payload).await.unwrap();
    }
    client_writer.write_zero_chunk().await.unwrap();
    drop(client_writer);

    let reader = test_snell_reader(server_upload);
    let writer = test_snell_writer(tokio::io::sink());
    let snell = TcpServerStream::from_parts_with_pending(reader, writer, Bytes::new());
    let (reader, _) = snell.into_split();
    reader
}

#[derive(Default)]
struct RecordingWriter {
    writes: Vec<Vec<u8>>,
    shutdowns: usize,
}

impl AsyncWrite for RecordingWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes.push(buf.to_vec());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdowns += 1;
        Poll::Ready(Ok(()))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let len = bufs.iter().map(|buf| buf.len()).sum();
        let mut write = Vec::with_capacity(len);
        for buf in bufs {
            write.extend_from_slice(buf);
        }
        self.writes.push(write);
        Poll::Ready(Ok(len))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }
}

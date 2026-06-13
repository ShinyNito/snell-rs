use core::range::Range;
use std::io;
use std::io::IoSlice;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::{Duration, timeout};

use super::{
    PlainUploadBatch, SERVER_FAST_OPEN_BUFFER_LIMIT, V6_ERROR_DNS_FAILED,
    V6_ERROR_DNS_FAILED_MESSAGE, V6_ERROR_FALLBACK, buffer_fast_open_payload_until_connected,
    relay_tcp_reader_to_plain_vectored_counted_with_initial, relay_tcp_server_stream_reusable,
    v6_server_error_reply,
};
use crate::MAX_PACKET_SIZE;
use crate::error::Error;
use crate::protocol::request::{
    ClientRequest, ServerReply, parse_client_request, parse_server_reply,
};
use crate::session::tcp::TcpServerStream;
use crate::test_support::{
    test_duplex_pair, test_snell_reader, test_snell_writer, test_tcp_listener,
    write_snell_payload_message,
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
async fn fast_open_buffer_stops_before_next_frame_could_exceed_limit() {
    let (client_upload, server_upload) = test_duplex_pair();

    let mut writer = test_snell_writer(client_upload);
    write_snell_payload_message(&mut writer, b"held")
        .await
        .unwrap();

    let reader = test_snell_reader(server_upload);
    let writer = test_snell_writer(tokio::io::sink());
    let snell = TcpServerStream::from_parts_with_pending(reader, writer, Bytes::new());
    let (mut snell_reader, _) = snell.into_split();
    let mut early_payload = PlainUploadBatch::new();
    let initial_len = SERVER_FAST_OPEN_BUFFER_LIMIT - MAX_PACKET_SIZE + 1;
    early_payload.push(Bytes::from(vec![0; initial_len]));

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
    let mut early_payload = PlainUploadBatch::new();
    early_payload.push(Bytes::from_static(b"early"));
    relay_tcp_reader_to_plain_vectored_counted_with_initial(
        &mut coalesced_reader,
        &mut coalesced_plain,
        &mut coalesced_total,
        early_payload,
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

        let payload = reader.read_frame_payload().await.unwrap();
        assert!(matches!(
            parse_server_reply(payload),
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
        let payload = reader.read_frame_payload().await.unwrap();
        assert_eq!(
            parse_client_request(payload).unwrap(),
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
        write_snell_payload_message(&mut client_writer, payload)
            .await
            .unwrap();
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

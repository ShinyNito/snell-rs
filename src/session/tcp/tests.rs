use core::range::Range;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{SERVER_PLAIN_READ_AHEAD_CAPACITY, TcpClientStream, TcpServerStream, TcpTarget};
use crate::ProtocolVersion;
use crate::error::Error;
use crate::protocol::header::write_tcp_request_header;
use crate::protocol::request::{
    ClientRequest, ServerReply, parse_client_request, parse_server_reply,
};
use crate::test_support::{
    TEST_PSK, test_duplex_pair, test_snell_reader, test_snell_writer, write_snell_payload_message,
    write_snell_tunnel_reply_message,
};

struct RecordingPlainReadWindow {
    payload: Vec<u8>,
    observed: Arc<Mutex<Vec<usize>>>,
}

impl RecordingPlainReadWindow {
    fn new(payload: &'static [u8], observed: Arc<Mutex<Vec<usize>>>) -> Self {
        Self {
            payload: payload.to_vec(),
            observed,
        }
    }
}

impl AsyncRead for RecordingPlainReadWindow {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.observed.lock().unwrap().push(buf.remaining());
        let n = self.payload.len().min(buf.remaining());
        if n != 0 {
            buf.put_slice(&self.payload[..n]);
            self.payload.drain(..n);
        }
        Poll::Ready(Ok(()))
    }
}

async fn write_client_payload<W>(
    writer: &mut super::TcpClientWriter<W>,
    payload: &[u8],
) -> crate::error::Result<usize>
where
    W: AsyncWrite + Unpin,
{
    let mut plain = payload;
    Ok(writer
        .write_payload_message_from_reader(&mut plain)
        .await?
        .unwrap_or(0))
}

async fn write_server_payload<W>(
    writer: &mut super::TcpServerWriter<W>,
    payload: &[u8],
) -> crate::error::Result<usize>
where
    W: AsyncWrite + Unpin,
{
    let mut plain = payload;
    Ok(writer
        .write_payload_message_from_reader(&mut plain)
        .await?
        .unwrap_or(0))
}

async fn accept_client_connect<R, W>(
    reader_io: R,
    writer_io: W,
    psk: &[u8],
) -> crate::error::Result<(TcpTarget, TcpServerStream<R, W>)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = crate::framed::SnellStreamReader::new(reader_io, psk, ProtocolVersion::V4);
    let payload = reader.read_frame_payload().await?;
    let (target, rest_start) = match parse_client_request(payload)? {
        ClientRequest::Connect {
            reuse,
            host,
            port,
            rest_span,
            ..
        } => (
            TcpTarget {
                host: host.to_owned(),
                port,
                reuse,
            },
            rest_span.start,
        ),
        ClientRequest::Ping | ClientRequest::Udp { .. } => {
            return Err(Error::InvalidClientRequest);
        }
    };
    let pending = reader.take_payload_from(rest_start);
    let writer = crate::framed::SnellStreamWriter::new(writer_io, psk, ProtocolVersion::V4)?;
    Ok((
        target,
        TcpServerStream::from_parts_with_pending(reader, writer, pending),
    ))
}

#[test]
fn client_payload_reader_starts_without_pending_allocation() {
    let reader = test_snell_reader(tokio::io::empty());
    let payload = super::TcpPayloadReader::client(reader);

    assert!(payload.pending.is_empty());
}

#[test]
fn compact_for_reuse_clears_pending_slice() {
    let reader = test_snell_reader(tokio::io::empty());
    let pending = Bytes::from_static(b"early");
    let mut payload = super::TcpPayloadReader::new(reader, pending);

    payload.compact_buffers_for_reuse();

    assert!(payload.pending.is_empty());
}

#[tokio::test]
async fn client_open_writes_connect_request() {
    let (client_upload, server_upload) = test_duplex_pair();

    let client = async {
        let stream = TcpClientStream::open_io(
            tokio::io::empty(),
            client_upload,
            TEST_PSK,
            "example.com",
            443,
            ProtocolVersion::V4,
            false,
        )
        .await
        .unwrap();
        let _ = stream.into_split();
    };

    let server = async {
        let mut reader = test_snell_reader(server_upload);
        let payload = reader.read_frame_payload().await.unwrap();
        let request = parse_client_request(payload).unwrap();
        assert_eq!(
            request,
            ClientRequest::Connect {
                reuse: false,
                host: "example.com",
                port: 443,
                rest_span: Range { start: 17, end: 17 },
                rest: b"",
            }
        );
    };

    let ((), ()) = tokio::join!(client, server);
}

#[tokio::test]
async fn client_reader_maps_transport_eof_after_tunnel_to_eof() {
    let (server_download, client_download) = test_duplex_pair();

    let client = async {
        let frame_reader = test_snell_reader(client_download);
        let mut reader = super::TcpReader::client(frame_reader);

        let reply = reader.take_payload_chunk().await.unwrap().unwrap();
        assert_eq!(&reply[..], b"accepted");

        assert!(reader.take_payload_chunk().await.unwrap().is_none());
    };

    let server = async {
        let mut server_writer = test_snell_writer(server_download);
        write_snell_tunnel_reply_message(&mut server_writer, b"accepted")
            .await
            .unwrap();
        server_writer.shutdown().await.unwrap();
    };

    let ((), ()) = tokio::join!(client, server);
}

#[tokio::test]
async fn server_reader_maps_transport_eof_to_eof() {
    let (client_upload, server_upload) = test_duplex_pair();
    drop(client_upload);

    let frame_reader = test_snell_reader(server_upload);
    let mut reader = super::TcpReader::server(frame_reader, Bytes::new());
    assert!(reader.take_payload_chunk().await.unwrap().is_none());
}

#[tokio::test]
async fn server_stream_preserves_early_data_and_coalesces_first_reply() {
    let (client_upload, server_upload) = test_duplex_pair();
    let (server_download, client_download) = test_duplex_pair();

    let client = async {
        let mut plain = BytesMut::new();
        write_tcp_request_header(&mut plain, "example.com", 443, ProtocolVersion::V4, true)
            .unwrap();
        plain.extend_from_slice(b"early");

        let mut writer = test_snell_writer(client_upload);
        write_snell_payload_message(&mut writer, &plain)
            .await
            .unwrap();

        let mut reader = test_snell_reader(client_download);
        let payload = reader.read_frame_payload().await.unwrap();
        let reply = parse_server_reply(payload).unwrap();
        assert_eq!(
            reply,
            ServerReply::Tunnel {
                payload_span: Range { start: 1, end: 6 },
                payload: b"first"
            }
        );
    };

    let server = async {
        let (target, stream) = accept_client_connect(server_upload, server_download, TEST_PSK)
            .await
            .unwrap();
        assert_eq!(
            target,
            TcpTarget {
                host: "example.com".to_owned(),
                port: 443,
                reuse: true,
            }
        );

        let (mut reader, mut writer) = stream.into_split();
        let early = reader.take_payload_chunk().await.unwrap().unwrap();
        assert_eq!(&early[..], b"early");

        assert_eq!(
            write_server_payload(&mut writer, b"first").await.unwrap(),
            5
        );
    };

    let ((), ()) = tokio::join!(client, server);
}

#[tokio::test]
async fn server_writer_coalesces_tunnel_with_first_reader_payload() {
    let (server_download, client_download) = test_duplex_pair();

    let server = async {
        let writer = test_snell_writer(server_download);
        let mut writer = super::TcpServerWriter::new(writer);
        assert_eq!(
            write_server_payload(&mut writer, b"first").await.unwrap(),
            5
        );
    };

    let client = async {
        let mut reader = test_snell_reader(client_download);
        let payload = reader.read_frame_payload().await.unwrap();
        let reply = parse_server_reply(payload).unwrap();

        assert_eq!(
            reply,
            ServerReply::Tunnel {
                payload_span: Range { start: 1, end: 6 },
                payload: b"first"
            }
        );
    };

    let ((), ()) = tokio::join!(client, server);
}

#[tokio::test]
async fn server_writer_batch_drains_plain_buffer_across_records() {
    let (server_download, client_download) = tokio::io::duplex(256 * 1024);
    let payload = vec![0x42; SERVER_PLAIN_READ_AHEAD_CAPACITY / 2];

    let server = async {
        let writer = test_snell_writer(server_download);
        let mut writer = super::TcpServerWriter::new(writer);
        let mut plain = payload.as_slice();

        assert_eq!(
            writer
                .write_payload_message_from_reader(&mut plain)
                .await
                .unwrap(),
            Some(payload.len())
        );
        writer.close_write().await.unwrap();
    };

    let client = async {
        let frame_reader = test_snell_reader(client_download);
        let mut reader = super::TcpReader::client(frame_reader);
        let mut received = Vec::with_capacity(payload.len());

        while received.len() < payload.len() {
            let chunk = reader.take_payload_chunk().await.unwrap().unwrap();
            received.extend_from_slice(&chunk);
        }

        assert_eq!(received, payload);
        assert!(reader.take_payload_chunk().await.unwrap().is_none());
    };

    let ((), ()) = tokio::join!(client, server);
}

#[tokio::test]
async fn server_writer_plain_batch_uses_large_read_ahead_window() {
    let (server_download, _client_download) = test_duplex_pair();
    let writer = test_snell_writer(server_download);
    let mut writer = super::TcpServerWriter::new(writer);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let mut plain = RecordingPlainReadWindow::new(b"tiny", observed.clone());

    assert_eq!(
        writer
            .write_payload_message_from_reader(&mut plain)
            .await
            .unwrap(),
        Some(4)
    );
    assert!(
        observed
            .lock()
            .unwrap()
            .iter()
            .any(|remaining| *remaining >= SERVER_PLAIN_READ_AHEAD_CAPACITY)
    );
}

#[tokio::test]
async fn split_halves_can_read_and_write_concurrently() {
    let (client_upload, server_upload) = test_duplex_pair();
    let (server_download, client_download) = test_duplex_pair();

    let client = async {
        let stream = TcpClientStream::open_io(
            client_download,
            client_upload,
            TEST_PSK,
            "example.com",
            443,
            ProtocolVersion::V4,
            false,
        )
        .await
        .unwrap();
        let (mut reader, mut writer) = stream.into_split();

        let write = async {
            write_client_payload(&mut writer, b"ping").await.unwrap();
            writer.close_write().await.unwrap();
        };
        let read = async {
            let payload = reader.take_payload_chunk().await.unwrap().unwrap();
            assert_eq!(&payload[..], b"pong");
        };

        tokio::join!(read, write);
    };

    let server = async {
        let (target, stream) = accept_client_connect(server_upload, server_download, TEST_PSK)
            .await
            .unwrap();
        assert_eq!(target.host, "example.com");
        let (mut reader, mut writer) = stream.into_split();

        let read = async {
            let payload = reader.take_payload_chunk().await.unwrap().unwrap();
            assert_eq!(&payload[..], b"ping");
        };
        let write = async {
            write_server_payload(&mut writer, b"pong").await.unwrap();
            writer.close_write().await.unwrap();
        };

        tokio::join!(read, write);
    };

    let ((), ()) = tokio::join!(client, server);
}

#[tokio::test]
async fn client_writer_rejects_write_after_close() {
    let frame_writer = test_snell_writer(tokio::io::sink());
    let mut writer = super::TcpClientWriter::new(frame_writer);

    writer.close_write().await.unwrap();
    assert!(matches!(
        write_client_payload(&mut writer, b"after close").await,
        Err(Error::WriteClosed)
    ));
}

#[tokio::test]
async fn server_writer_rejects_write_after_close() {
    let frame_writer = test_snell_writer(tokio::io::sink());
    let mut writer = super::TcpServerWriter::new(frame_writer);

    writer.close_write().await.unwrap();
    assert!(matches!(
        write_server_payload(&mut writer, b"after close").await,
        Err(Error::WriteClosed)
    ));
}

#[tokio::test]
async fn server_stream_can_reject_before_opening_tunnel() {
    let (server_download, client_download) = test_duplex_pair();

    let read = async {
        let mut reader = test_snell_reader(client_download);
        let payload = reader.read_frame_payload().await.unwrap();
        assert!(matches!(
            parse_server_reply(payload),
            Ok(ServerReply::Error {
                code: 9,
                message: "blocked"
            })
        ));
    };

    let reject = async {
        let reader = test_snell_reader(tokio::io::empty());
        let writer = test_snell_writer(server_download);
        let stream = TcpServerStream::from_parts_with_pending(reader, writer, Bytes::new());
        stream.reject(9, "blocked").await.unwrap();
    };

    let ((), ()) = tokio::join!(read, reject);
}

use core::range::Range;
use std::io;
use std::io::ErrorKind;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{
    SERVER_PLAIN_READ_AHEAD_CAPACITY, TcpClientOpenOptions, TcpClientStream, TcpServerStream,
    TcpTarget,
};
use crate::ProtocolVersion;
use crate::error::Error;
use crate::protocol::header::write_tcp_request_header;
use crate::protocol::request::{
    ClientRequest, ServerReply, parse_client_request, parse_server_reply,
};
use crate::test_support::{
    TEST_PSK, read_snell_frame_payload, shared_secret, test_duplex_pair, test_snell_reader,
    test_snell_writer, write_snell_payload_message, write_snell_tunnel_reply_message,
};

async fn write_client_payload<W>(writer: &mut W, payload: &[u8]) -> io::Result<usize>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(payload.len())
}

async fn write_server_payload<W>(writer: &mut W, payload: &[u8]) -> io::Result<usize>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(payload.len())
}

async fn close_client_writer<W>(writer: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.shutdown().await
}

async fn close_server_writer<W>(writer: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.shutdown().await
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
    let secret = shared_secret(psk);
    let mut reader = crate::framed::SnellStreamReader::new(reader_io, &secret, ProtocolVersion::V4);
    let payload = read_snell_frame_payload(&mut reader).await?;
    let (target, rest_start) = match parse_client_request(&payload)? {
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
    let writer = crate::framed::SnellStreamWriter::new(writer_io, &secret, ProtocolVersion::V4)?;
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
        let secret = shared_secret(TEST_PSK);
        let stream = TcpClientStream::open_io(
            tokio::io::empty(),
            client_upload,
            TcpClientOpenOptions {
                secret: &secret,
                host: "example.com",
                port: 443,
                version: ProtocolVersion::V4,
                reuse: false,
            },
        )
        .await
        .unwrap();
        drop(stream);
    };

    let server = async {
        let mut reader = test_snell_reader(server_upload);
        let payload = read_snell_frame_payload(&mut reader).await.unwrap();
        let request = parse_client_request(&payload).unwrap();
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

        let mut reply = Vec::new();
        reader.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"accepted");
    };

    let server = async {
        let mut server_writer = test_snell_writer(server_download);
        write_snell_tunnel_reply_message(&mut server_writer, b"accepted")
            .await
            .unwrap();
        drop(server_writer);
    };

    let ((), ()) = tokio::join!(client, server);
}

#[tokio::test]
async fn server_reader_maps_transport_eof_to_eof() {
    let (client_upload, server_upload) = test_duplex_pair();
    drop(client_upload);

    let frame_reader = test_snell_reader(server_upload);
    let mut reader = super::TcpReader::server(frame_reader, Bytes::new());
    let mut out = [0; 1];
    assert_eq!(reader.read(&mut out).await.unwrap(), 0);
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
        let payload = read_snell_frame_payload(&mut reader).await.unwrap();
        let reply = parse_server_reply(&payload).unwrap();
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

        let mut stream = stream;
        let mut early = [0; 5];
        stream.read_exact(&mut early).await.unwrap();
        assert_eq!(&early, b"early");

        assert_eq!(
            write_server_payload(&mut stream, b"first").await.unwrap(),
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
        let payload = read_snell_frame_payload(&mut reader).await.unwrap();
        let reply = parse_server_reply(&payload).unwrap();

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

        assert_eq!(
            write_server_payload(&mut writer, &payload).await.unwrap(),
            payload.len()
        );
        close_server_writer(&mut writer).await.unwrap();
    };

    let client = async {
        let frame_reader = test_snell_reader(client_download);
        let mut reader = super::TcpReader::client(frame_reader);
        let mut received = Vec::with_capacity(payload.len());

        reader.read_to_end(&mut received).await.unwrap();

        assert_eq!(received, payload);
    };

    let ((), ()) = tokio::join!(client, server);
}

#[tokio::test]
async fn split_halves_can_read_and_write_concurrently() {
    let (client_upload, server_upload) = test_duplex_pair();
    let (server_download, client_download) = test_duplex_pair();

    let client = async {
        let secret = shared_secret(TEST_PSK);
        let stream = TcpClientStream::open_io(
            client_download,
            client_upload,
            TcpClientOpenOptions {
                secret: &secret,
                host: "example.com",
                port: 443,
                version: ProtocolVersion::V4,
                reuse: false,
            },
        )
        .await
        .unwrap();
        let (mut reader, mut writer) = tokio::io::split(stream);

        let write = async {
            write_client_payload(&mut writer, b"ping").await.unwrap();
            close_client_writer(&mut writer).await.unwrap();
        };
        let read = async {
            let mut payload = [0; 4];
            reader.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"pong");
        };

        tokio::join!(read, write);
    };

    let server = async {
        let (target, stream) = accept_client_connect(server_upload, server_download, TEST_PSK)
            .await
            .unwrap();
        assert_eq!(target.host, "example.com");
        let (mut reader, mut writer) = tokio::io::split(stream);

        let read = async {
            let mut payload = [0; 4];
            reader.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
        };
        let write = async {
            write_server_payload(&mut writer, b"pong").await.unwrap();
            close_server_writer(&mut writer).await.unwrap();
        };

        tokio::join!(read, write);
    };

    let ((), ()) = tokio::join!(client, server);
}

#[tokio::test]
async fn client_writer_rejects_write_after_close() {
    let frame_writer = test_snell_writer(tokio::io::sink());
    let mut writer = super::TcpClientWriter::new(frame_writer);

    close_client_writer(&mut writer).await.unwrap();
    assert!(matches!(
        write_client_payload(&mut writer, b"after close").await,
        Err(err) if err.kind() == ErrorKind::BrokenPipe
    ));
}

#[tokio::test]
async fn server_writer_rejects_write_after_close() {
    let frame_writer = test_snell_writer(tokio::io::sink());
    let mut writer = super::TcpServerWriter::new(frame_writer);

    close_server_writer(&mut writer).await.unwrap();
    assert!(matches!(
        write_server_payload(&mut writer, b"after close").await,
        Err(err) if err.kind() == ErrorKind::BrokenPipe
    ));
}

#[tokio::test]
async fn server_stream_can_reject_before_opening_tunnel() {
    let (server_download, client_download) = test_duplex_pair();

    let read = async {
        let mut reader = test_snell_reader(client_download);
        let payload = read_snell_frame_payload(&mut reader).await.unwrap();
        assert!(matches!(
            parse_server_reply(&payload),
            Ok(ServerReply::Error {
                code: 9,
                message: "blocked"
            })
        ));
    };

    let reject = async {
        let reader = test_snell_reader(tokio::io::empty());
        let writer = test_snell_writer(server_download);
        let mut stream = TcpServerStream::from_parts_with_pending(reader, writer, Bytes::new());
        stream.reject(9, "blocked").await.unwrap();
    };

    let ((), ()) = tokio::join!(read, reject);
}

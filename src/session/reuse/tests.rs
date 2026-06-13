use core::range::Range;
use std::future::poll_fn;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use super::{ReuseClientConn, ReuseClientReader, ReuseClientWriter};
use crate::error::Error;
use crate::protocol::request::{ClientRequest, parse_client_request};
use crate::test_support::{
    test_duplex_pair, test_snell_reader, test_snell_writer, write_snell_tunnel_reply_message,
};

macro_rules! assert_next_payload {
    ($conn:expr, $expected:expr) => {{
        let payload = take_payload_chunk(&mut $conn.reader)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&payload[..], $expected);
    }};
}

async fn take_payload_chunk<R>(
    reader: &mut ReuseClientReader<R>,
) -> crate::error::Result<Option<bytes::Bytes>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    poll_fn(|cx| reader.poll_take_payload_chunk(cx)).await
}

async fn write_reuse_payload<W>(
    writer: &mut ReuseClientWriter<W>,
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

#[tokio::test]
async fn reuse_conn_requires_both_sides_done_before_reuse() {
    let (client_upload, server_upload) = test_duplex_pair();
    let (server_download, client_download) = test_duplex_pair();

    let client = async {
        let mut writer = test_snell_writer(client_upload);
        writer
            .write_tcp_request("example.com", 443, true)
            .await
            .unwrap();

        let reader = test_snell_reader(client_download);
        let mut conn = ReuseClientConn::from_parts(reader, writer);

        assert_next_payload!(conn, b"pong");
        assert!(!conn.can_reuse());

        assert!(
            take_payload_chunk(&mut conn.reader)
                .await
                .unwrap()
                .is_none()
        );
        assert!(!conn.can_reuse());

        conn.writer.close_write().await.unwrap();
        assert!(conn.can_reuse());
    };

    let server = async {
        let mut reader = test_snell_reader(server_upload);
        let payload = reader.read_frame_payload().await.unwrap();
        let request = parse_client_request(payload).unwrap();
        assert_eq!(
            request,
            ClientRequest::Connect {
                reuse: true,
                host: "example.com",
                port: 443,
                rest_span: Range { start: 17, end: 17 },
                rest: b"",
            }
        );

        let mut server_writer = test_snell_writer(server_download);
        write_snell_tunnel_reply_message(&mut server_writer, b"pong")
            .await
            .unwrap();
        server_writer.write_zero_chunk().await.unwrap();

        assert!(matches!(
            reader.read_frame_payload().await,
            Err(Error::ZeroChunk)
        ));
    };

    let ((), ()) = tokio::join!(client, server);
}

#[tokio::test]
async fn reuse_conn_with_pending_payload_is_not_reusable() {
    let (client_upload, _server_upload) = test_duplex_pair();
    let (server_download, client_download) = test_duplex_pair();

    let client = async {
        let writer = test_snell_writer(client_upload);
        let reader = test_snell_reader(client_download);
        let mut conn = ReuseClientConn::from_parts(reader, writer);
        let payload = take_payload_chunk(&mut conn.reader).await.unwrap().unwrap();
        assert_eq!(&payload[..2], b"po");
        conn.writer.close_write().await.unwrap();
        assert!(!conn.can_reuse());
    };

    let server = async {
        let mut server_writer = test_snell_writer(server_download);
        write_snell_tunnel_reply_message(&mut server_writer, b"pong")
            .await
            .unwrap();
        server_writer.write_zero_chunk().await.unwrap();
    };

    let ((), ()) = tokio::join!(client, server);
}

#[tokio::test]
async fn reuse_conn_surfaces_server_error_reply() {
    let (client_upload, _server_upload) = test_duplex_pair();
    let (server_download, client_download) = test_duplex_pair();

    let client = async {
        let writer = test_snell_writer(client_upload);
        let reader = test_snell_reader(client_download);
        let mut conn = ReuseClientConn::from_parts(reader, writer);
        assert!(matches!(
            take_payload_chunk(&mut conn.reader).await,
            Err(Error::Server { code: 9, message }) if message == "denied"
        ));
    };

    let server = async {
        let mut server_writer = test_snell_writer(server_download);
        server_writer.write_error_reply(9, "denied").await.unwrap();
    };

    let ((), ()) = tokio::join!(client, server);
}

#[tokio::test]
async fn reuse_conn_error_is_not_reusable() {
    let (client_upload, _server_upload) = test_duplex_pair();
    let (server_download, client_download) = test_duplex_pair();

    let client = async {
        let writer = test_snell_writer(client_upload);
        let reader = test_snell_reader(client_download);
        let mut conn = ReuseClientConn::from_parts(reader, writer);
        assert!(take_payload_chunk(&mut conn.reader).await.is_err());
        assert!(!conn.can_reuse());
    };

    let server = async {
        let mut server_writer = test_snell_writer(server_download);
        server_writer.write_error_reply(9, "denied").await.unwrap();
    };

    let ((), ()) = tokio::join!(client, server);
}

#[tokio::test]
async fn reuse_conn_rejects_write_after_close() {
    let (client_upload, _server_upload) = test_duplex_pair();
    let (_server_download, client_download) = test_duplex_pair();

    let writer = test_snell_writer(client_upload);
    let reader = test_snell_reader(client_download);
    let mut conn = ReuseClientConn::from_parts(reader, writer);

    conn.writer.close_write().await.unwrap();
    assert!(matches!(
        write_reuse_payload(&mut conn.writer, b"after close").await,
        Err(Error::WriteClosed)
    ));
}

#[tokio::test]
async fn close_whole_connection_drops_reader_and_writer_halves() {
    let (client_upload, mut server_upload) = test_duplex_pair();
    let (_server_download, client_download) = test_duplex_pair();

    let writer = test_snell_writer(client_upload);
    let reader = test_snell_reader(client_download);
    let conn = ReuseClientConn::from_parts(reader, writer);

    conn.close_whole_connection().await;

    let mut buf = [0; 1];
    assert_eq!(server_upload.read(&mut buf).await.unwrap(), 0);
}

#[tokio::test]
async fn reuse_conn_writer_filling_from_failed_plain_reader_marks_broken() {
    let (client_upload, _server_upload) = test_duplex_pair();
    let (_server_download, client_download) = test_duplex_pair();

    let writer = test_snell_writer(client_upload);
    let reader = test_snell_reader(client_download);
    let mut conn = ReuseClientConn::from_parts(reader, writer);

    let mut plain = FailingPlainReader;
    assert!(matches!(
        conn.writer
            .write_payload_message_from_reader(&mut plain)
            .await,
        Err(Error::Io(err)) if err.kind() == ErrorKind::UnexpectedEof
    ));
    assert!(conn.writer.broken);
}

// A plain reader whose reads always fail, simulating a broken upstream so the
// fill stage of `write_payload_message_from_reader` surfaces an error.
struct FailingPlainReader;

impl AsyncRead for FailingPlainReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::from(ErrorKind::UnexpectedEof)))
    }
}

use core::range::Range;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::ReuseClientConn;
use crate::error::Error;
use crate::protocol::request::{ClientRequest, parse_client_request};
use crate::test_support::{
    read_snell_frame_payload, test_duplex_pair, test_snell_reader, test_snell_writer,
    write_snell_tunnel_reply_message,
};

macro_rules! assert_next_payload {
    ($conn:expr, $expected:expr) => {{
        let mut payload = vec![0; $expected.len()];
        $conn.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, $expected);
    }};
}

async fn write_reuse_payload<W>(writer: &mut W, payload: &[u8]) -> io::Result<usize>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(payload.len())
}

async fn close_reuse_writer<W>(writer: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.shutdown().await
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

        let mut rest = Vec::new();
        conn.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        assert!(!conn.can_reuse());

        close_reuse_writer(&mut conn).await.unwrap();
        assert!(conn.can_reuse());
    };

    let server = async {
        let mut reader = test_snell_reader(server_upload);
        let payload = read_snell_frame_payload(&mut reader).await.unwrap();
        let request = parse_client_request(&payload).unwrap();
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
            read_snell_frame_payload(&mut reader).await,
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
        let mut payload = [0; 2];
        conn.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"po");
        close_reuse_writer(&mut conn).await.unwrap();
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
        let mut out = [0; 1];
        let err = conn.read(&mut out).await.unwrap_err();
        assert!(matches!(
            err.get_ref().and_then(|err| err.downcast_ref::<Error>()),
            Some(Error::Server { code, message }) if *code == 9 && message == "denied"
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
        let mut out = [0; 1];
        assert!(conn.read(&mut out).await.is_err());
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

    close_reuse_writer(&mut conn).await.unwrap();
    assert!(matches!(
        write_reuse_payload(&mut conn, b"after close").await,
        Err(err) if err.kind() == ErrorKind::BrokenPipe
    ));
}

#[tokio::test]
async fn reuse_conn_writer_failed_transport_write_marks_broken() {
    let (_server_download, client_download) = test_duplex_pair();

    let writer = test_snell_writer(FailingPlainWriter);
    let reader = test_snell_reader(client_download);
    let mut conn = ReuseClientConn::from_parts(reader, writer);

    assert!(matches!(
        conn.write_all(b"payload").await,
        Err(err) if err.kind() == ErrorKind::UnexpectedEof
    ));
    assert!(conn.writer.broken);
}

struct FailingPlainWriter;

impl AsyncWrite for FailingPlainWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::from(ErrorKind::UnexpectedEof)))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

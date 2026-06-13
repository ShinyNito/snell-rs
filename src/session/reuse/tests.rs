use core::range::Range;

use tokio::io::{AsyncReadExt, AsyncWrite};

use super::{ReuseClientConn, ReuseClientWriter};
use crate::error::Error;
use crate::protocol::request::{ClientRequest, parse_client_request};
use crate::test_support::{test_duplex_pair, test_snell_reader, test_snell_writer};

macro_rules! assert_next_payload {
    ($conn:expr, $expected:expr) => {{
        let payload = $conn.reader.take_payload_chunk().await.unwrap().unwrap();
        assert_eq!(&payload[..], $expected);
    }};
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
        .write_next_payload_record_from_reader(&mut plain)
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

        assert!(conn.reader.take_payload_chunk().await.unwrap().is_none());
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
        server_writer
            .write_test_tunnel_reply(b"pong")
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
        let payload = conn.reader.take_payload_chunk().await.unwrap().unwrap();
        assert_eq!(&payload[..2], b"po");
        conn.writer.close_write().await.unwrap();
        assert!(!conn.can_reuse());
    };

    let server = async {
        let mut server_writer = test_snell_writer(server_download);
        server_writer
            .write_test_tunnel_reply(b"pong")
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
            conn.reader.take_payload_chunk().await,
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
        assert!(conn.reader.take_payload_chunk().await.is_err());
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

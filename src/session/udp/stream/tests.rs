use core::range::Range;

use super::{UdpClientStream, UdpServerStream};
use crate::ProtocolVersion;
use crate::error::Error;
use crate::protocol::request::{
    ClientRequest, ServerReply, parse_client_request, parse_server_reply,
};
use crate::test_support::{
    TEST_PSK, test_duplex_pair, test_snell_reader, test_snell_reader_with_version,
    test_snell_writer, test_snell_writer_with_version,
};

#[tokio::test]
async fn udp_client_open_writes_udp_request_and_accepts_empty_tunnel() {
    let (client_upload, server_upload) = test_duplex_pair();
    let (server_download, client_download) = test_duplex_pair();

    let client = async {
        UdpClientStream::open_io(
            client_download,
            client_upload,
            TEST_PSK,
            ProtocolVersion::V4,
        )
        .await
        .unwrap()
    };

    let server = async {
        let mut reader = test_snell_reader(server_upload);
        let payload = reader.read_frame_payload().await.unwrap();
        let request = parse_client_request(payload).unwrap();
        assert_eq!(
            request,
            ClientRequest::Udp {
                rest_span: Range { start: 3, end: 3 },
                rest: b"",
            }
        );

        let writer = test_snell_writer(server_download);
        UdpServerStream::accept(reader, writer).await.unwrap()
    };

    let (client, server) = tokio::join!(client, server);
    let _ = client.into_parts();
    let _ = server.into_parts();
}

#[tokio::test]
async fn udp_client_open_supports_v6_stream() {
    let (client_upload, server_upload) = test_duplex_pair();
    let (server_download, client_download) = test_duplex_pair();

    let client = async {
        UdpClientStream::open_io(
            client_download,
            client_upload,
            TEST_PSK,
            ProtocolVersion::V6,
        )
        .await
        .unwrap()
    };

    let server = async {
        let mut reader = test_snell_reader_with_version(server_upload, ProtocolVersion::V6);
        let payload = reader.read_frame_payload().await.unwrap();
        let request = parse_client_request(payload).unwrap();
        assert_eq!(
            request,
            ClientRequest::Udp {
                rest_span: Range { start: 3, end: 3 },
                rest: b"",
            }
        );

        let writer = test_snell_writer_with_version(server_download, ProtocolVersion::V6);
        UdpServerStream::accept(reader, writer).await.unwrap()
    };

    let (client, server) = tokio::join!(client, server);
    let _ = client.into_parts();
    let _ = server.into_parts();
}

#[tokio::test]
async fn udp_client_open_rejects_non_empty_tunnel_reply() {
    let (client_upload, server_upload) = test_duplex_pair();
    let (server_download, client_download) = test_duplex_pair();

    let client = async {
        UdpClientStream::open_io(
            client_download,
            client_upload,
            TEST_PSK,
            ProtocolVersion::V4,
        )
        .await
    };

    let server = async {
        let mut reader = test_snell_reader(server_upload);
        let payload = reader.read_frame_payload().await.unwrap();
        assert!(matches!(
            parse_client_request(payload).unwrap(),
            ClientRequest::Udp { .. }
        ));

        let mut server_writer = test_snell_writer(server_download);
        server_writer
            .write_test_tunnel_reply(b"unexpected")
            .await
            .unwrap();
    };

    let (result, ()) = tokio::join!(client, server);
    assert!(matches!(result, Err(Error::InvalidServerReply)));
}

#[tokio::test]
async fn udp_server_accept_sends_empty_tunnel_reply() {
    let (server_download, client_download) = test_duplex_pair();

    let server = async {
        let reader = test_snell_reader(tokio::io::empty());
        let writer = test_snell_writer(server_download);
        UdpServerStream::accept(reader, writer).await.unwrap()
    };

    let client = async {
        let mut reader = test_snell_reader(client_download);
        let payload = reader.read_frame_payload().await.unwrap();
        assert_eq!(
            parse_server_reply(payload).unwrap(),
            ServerReply::Tunnel {
                payload_span: Range { start: 1, end: 1 },
                payload: b"",
            }
        );
    };

    let (server, ()) = tokio::join!(server, client);
    let _ = server.into_parts();
}

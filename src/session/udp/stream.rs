use tokio::io::{AsyncRead, AsyncWrite};

use crate::ProtocolVersion;
use crate::error::{Error, Result};
use crate::framed::{SnellStreamReader, SnellStreamWriter};
use crate::protocol::request::ServerReply;

pub(crate) struct UdpClientStream<R, W> {
    reader: SnellStreamReader<R>,
    writer: SnellStreamWriter<W>,
}

impl<R, W> UdpClientStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub(crate) async fn open_io(
        reader_io: R,
        writer_io: W,
        psk: &[u8],
        snell_version: ProtocolVersion,
    ) -> Result<Self> {
        let mut writer = SnellStreamWriter::new(writer_io, psk, snell_version)?;
        writer.write_udp_request().await?;
        let reader = SnellStreamReader::new(reader_io, psk, snell_version)?;
        Self::finish_open(reader, writer).await
    }

    async fn finish_open(
        mut reader: SnellStreamReader<R>,
        writer: SnellStreamWriter<W>,
    ) -> Result<Self> {
        match reader.read_server_reply().await? {
            ServerReply::Tunnel { payload: [], .. } => Ok(Self::from_parts(reader, writer)),
            ServerReply::Tunnel { .. } => Err(Error::InvalidServerReply),
            ServerReply::Pong => Err(Error::InvalidServerReply),
            ServerReply::Error { code, message } => Err(Error::Server {
                code,
                message: message.to_owned(),
            }),
        }
    }

    fn from_parts(reader: SnellStreamReader<R>, writer: SnellStreamWriter<W>) -> Self {
        Self { reader, writer }
    }

    pub(crate) fn into_parts(self) -> (SnellStreamReader<R>, SnellStreamWriter<W>) {
        (self.reader, self.writer)
    }
}

pub(crate) struct UdpServerStream<R, W> {
    reader: SnellStreamReader<R>,
    writer: SnellStreamWriter<W>,
}

impl<R, W> UdpServerStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub(crate) async fn accept(
        reader: SnellStreamReader<R>,
        mut frame_writer: SnellStreamWriter<W>,
    ) -> Result<Self> {
        frame_writer.write_empty_tunnel_reply().await?;
        Ok(Self::from_parts(reader, frame_writer))
    }

    fn from_parts(reader: SnellStreamReader<R>, writer: SnellStreamWriter<W>) -> Self {
        Self { reader, writer }
    }

    pub(crate) fn into_parts(self) -> (SnellStreamReader<R>, SnellStreamWriter<W>) {
        (self.reader, self.writer)
    }
}

#[cfg(test)]
mod tests {
    use core::range::Range;

    use tokio::io::duplex;

    use super::{UdpClientStream, UdpServerStream};
    use crate::ProtocolVersion;
    use crate::error::Error;
    use crate::framed::{SnellStreamReader, SnellStreamWriter};
    use crate::protocol::request::{ClientRequest, ServerReply};

    #[tokio::test]
    async fn udp_client_open_writes_udp_request_and_accepts_empty_tunnel() {
        let (client_upload, server_upload) = duplex(4096);
        let (server_download, client_download) = duplex(4096);
        let psk = b"test psk";

        let client = async {
            UdpClientStream::open_io(client_download, client_upload, psk, ProtocolVersion::V4)
                .await
                .unwrap()
        };

        let server = async {
            let mut reader =
                SnellStreamReader::new(server_upload, psk, ProtocolVersion::V4).unwrap();
            let request = reader.read_client_request().await.unwrap();
            assert_eq!(
                request,
                ClientRequest::Udp {
                    rest_span: Range { start: 3, end: 3 },
                    rest: b"",
                }
            );

            let writer = SnellStreamWriter::new(server_download, psk, ProtocolVersion::V4).unwrap();
            UdpServerStream::accept(reader, writer).await.unwrap()
        };

        let (client, server) = tokio::join!(client, server);
        let _ = client.into_parts();
        let _ = server.into_parts();
    }

    #[tokio::test]
    async fn udp_client_open_supports_v6_stream() {
        let (client_upload, server_upload) = duplex(4096);
        let (server_download, client_download) = duplex(4096);
        let psk = b"test psk";

        let client = async {
            UdpClientStream::open_io(client_download, client_upload, psk, ProtocolVersion::V6)
                .await
                .unwrap()
        };

        let server = async {
            let mut reader =
                SnellStreamReader::new(server_upload, psk, ProtocolVersion::V6).unwrap();
            let request = reader.read_client_request().await.unwrap();
            assert_eq!(
                request,
                ClientRequest::Udp {
                    rest_span: Range { start: 3, end: 3 },
                    rest: b"",
                }
            );

            let writer = SnellStreamWriter::new(server_download, psk, ProtocolVersion::V6).unwrap();
            UdpServerStream::accept(reader, writer).await.unwrap()
        };

        let (client, server) = tokio::join!(client, server);
        let _ = client.into_parts();
        let _ = server.into_parts();
    }

    #[tokio::test]
    async fn udp_client_open_rejects_non_empty_tunnel_reply() {
        let (client_upload, server_upload) = duplex(4096);
        let (server_download, client_download) = duplex(4096);
        let psk = b"test psk";

        let client = async {
            UdpClientStream::open_io(client_download, client_upload, psk, ProtocolVersion::V4).await
        };

        let server = async {
            let mut reader =
                SnellStreamReader::new(server_upload, psk, ProtocolVersion::V4).unwrap();
            assert!(matches!(
                reader.read_client_request().await.unwrap(),
                ClientRequest::Udp { .. }
            ));

            let mut server_writer =
                SnellStreamWriter::new(server_download, psk, ProtocolVersion::V4).unwrap();
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
        let (server_download, client_download) = duplex(4096);
        let psk = b"test psk";

        let server = async {
            let reader =
                SnellStreamReader::new(tokio::io::empty(), psk, ProtocolVersion::V4).unwrap();
            let writer = SnellStreamWriter::new(server_download, psk, ProtocolVersion::V4).unwrap();
            UdpServerStream::accept(reader, writer).await.unwrap()
        };

        let client = async {
            let mut reader =
                SnellStreamReader::new(client_download, psk, ProtocolVersion::V4).unwrap();
            assert_eq!(
                reader.read_server_reply().await.unwrap(),
                ServerReply::Tunnel {
                    payload_span: Range { start: 1, end: 1 },
                    payload: b"",
                }
            );
        };

        let (server, ()) = tokio::join!(server, client);
        let _ = server.into_parts();
    }
}

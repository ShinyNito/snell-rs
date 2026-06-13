use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};
use crate::framed::{SnellStreamReader, SnellStreamWriter};
use crate::session::tcp::TcpPayloadReader;

pub(crate) struct ReuseClientConn<R, W> {
    reader: ReuseClientReader<R>,
    writer: ReuseClientWriter<W>,
}

impl<R, W> ReuseClientConn<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub(crate) fn from_parts(reader: SnellStreamReader<R>, writer: SnellStreamWriter<W>) -> Self {
        Self {
            reader: ReuseClientReader::new(reader),
            writer: ReuseClientWriter::new(writer),
        }
    }

    pub(crate) async fn start_request(&mut self, host: &str, port: u16) -> Result<()> {
        self.reset_request_state();
        self.writer.write_reuse_request(host, port).await
    }

    pub(crate) fn can_reuse(&self) -> bool {
        self.writer.write_closed
            && self.reader.payload.is_done()
            && !self.reader.payload.has_pending()
            && !self.reader.broken
            && !self.writer.broken
    }

    pub(crate) fn reset_request_state(&mut self) {
        self.reader.payload.reset();
        self.reader.reply_read = false;
        self.reader.broken = false;
        self.writer.write_closed = false;
        self.writer.broken = false;
    }

    pub(crate) fn compact_buffers_for_reuse(&mut self) {
        self.reader.compact_buffers_for_reuse();
        self.writer.compact_buffers_for_reuse();
    }

    pub(crate) async fn close_whole_connection(mut self) {
        self.writer.shutdown().await;
    }

    #[cfg(test)]
    pub(crate) fn reader_mut(&mut self) -> &mut ReuseClientReader<R> {
        &mut self.reader
    }

    #[cfg(test)]
    pub(crate) fn writer_mut(&mut self) -> &mut ReuseClientWriter<W> {
        &mut self.writer
    }

    pub(crate) fn into_split(self) -> (ReuseClientReader<R>, ReuseClientWriter<W>) {
        (self.reader, self.writer)
    }

    pub(crate) fn from_split(reader: ReuseClientReader<R>, writer: ReuseClientWriter<W>) -> Self {
        Self { reader, writer }
    }
}

pub(crate) struct ReuseClientReader<R> {
    payload: TcpPayloadReader<R>,
    reply_read: bool,
    broken: bool,
}

impl<R> ReuseClientReader<R>
where
    R: AsyncRead + Unpin,
{
    fn new(reader: SnellStreamReader<R>) -> Self {
        Self {
            payload: TcpPayloadReader::client(reader),
            reply_read: false,
            broken: false,
        }
    }

    async fn read_tunnel_reply(&mut self) -> Result<()> {
        if self.reply_read {
            return Ok(());
        }
        match self.payload.read_tunnel_reply().await {
            Ok(()) => self.reply_read = true,
            Err(err) => {
                self.broken = true;
                return Err(err);
            }
        }
        Ok(())
    }

    pub(crate) async fn take_payload_chunk(&mut self) -> Result<Option<Bytes>> {
        if self.payload.is_done() {
            return Ok(None);
        }
        if !self.reply_read {
            self.read_tunnel_reply().await?;
        }

        match self.payload.take_payload_chunk_strict().await {
            Ok(payload) => Ok(payload),
            Err(err) => {
                self.broken = true;
                Err(err)
            }
        }
    }

    fn compact_buffers_for_reuse(&mut self) {
        self.payload.compact_buffers_for_reuse();
    }
}

pub(crate) struct ReuseClientWriter<W> {
    frame_writer: SnellStreamWriter<W>,
    write_closed: bool,
    broken: bool,
}

impl<W> ReuseClientWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn new(writer: SnellStreamWriter<W>) -> Self {
        Self {
            frame_writer: writer,
            write_closed: false,
            broken: false,
        }
    }

    async fn write_reuse_request(&mut self, host: &str, port: u16) -> Result<()> {
        match self.frame_writer.write_tcp_request(host, port, true).await {
            Ok(()) => Ok(()),
            Err(err) => {
                self.broken = true;
                Err(err)
            }
        }
    }

    pub(crate) async fn write_next_payload_record_from_reader<P>(
        &mut self,
        plain: &mut P,
    ) -> Result<Option<usize>>
    where
        P: AsyncRead + Unpin,
    {
        if self.write_closed {
            return Err(Error::WriteClosed);
        }
        match self
            .frame_writer
            .write_next_payload_record_from_reader(plain)
            .await
        {
            Ok(n) => Ok(n),
            Err(err) => {
                self.broken = true;
                Err(err)
            }
        }
    }

    pub(crate) async fn close_write(&mut self) -> Result<()> {
        if !self.write_closed {
            match self.frame_writer.write_zero_chunk().await {
                Ok(()) => self.write_closed = true,
                Err(err) => {
                    self.broken = true;
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    async fn shutdown(&mut self) {
        let _ = self.frame_writer.shutdown().await;
    }

    fn compact_buffers_for_reuse(&mut self) {
        self.frame_writer.compact_buffers_for_reuse();
    }
}

#[cfg(test)]
mod tests {
    use core::range::Range;

    use tokio::io::{AsyncReadExt, AsyncWrite};

    use super::{ReuseClientConn, ReuseClientWriter};
    use crate::error::Error;
    use crate::protocol::request::ClientRequest;
    use crate::test_support::{test_duplex_pair, test_snell_reader, test_snell_writer};

    macro_rules! assert_next_payload {
        ($conn:expr, $expected:expr) => {{
            let payload = $conn
                .reader_mut()
                .take_payload_chunk()
                .await
                .unwrap()
                .unwrap();
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

            assert!(
                conn.reader_mut()
                    .take_payload_chunk()
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(!conn.can_reuse());

            conn.writer_mut().close_write().await.unwrap();
            assert!(conn.can_reuse());
        };

        let server = async {
            let mut reader = test_snell_reader(server_upload);
            let request = reader.read_client_request().await.unwrap();
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
            let payload = conn
                .reader_mut()
                .take_payload_chunk()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&payload[..2], b"po");
            conn.writer_mut().close_write().await.unwrap();
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
                conn.reader_mut().take_payload_chunk().await,
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
            assert!(conn.reader_mut().take_payload_chunk().await.is_err());
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

        conn.writer_mut().close_write().await.unwrap();
        assert!(matches!(
            write_reuse_payload(conn.writer_mut(), b"after close").await,
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
}

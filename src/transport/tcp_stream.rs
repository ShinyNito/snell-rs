use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};
use crate::protocol::request::ServerReply;
use crate::transport::tokio_io::{STREAM_BUFFER_RETAIN_CAPACITY, V4StreamReader, V4StreamWriter};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TcpTarget {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) reuse: bool,
}

pub(crate) struct TcpClientStream<R, W> {
    reader: TcpReader<R>,
    writer: TcpClientWriter<W>,
}

impl<R, W> TcpClientStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub(crate) async fn open_io(
        reader_io: R,
        writer_io: W,
        psk: &[u8],
        host: &str,
        port: u16,
        snell_version: u8,
        reuse: bool,
    ) -> Result<Self> {
        let mut writer = V4StreamWriter::new(writer_io, psk)?;
        writer
            .write_tcp_request(host, port, snell_version, reuse)
            .await?;
        let reader = V4StreamReader::new(reader_io, psk)?;
        Ok(Self::from_parts(reader, writer))
    }

    fn from_parts(reader: V4StreamReader<R>, writer: V4StreamWriter<W>) -> Self {
        Self {
            reader: TcpReader::client(reader),
            writer: TcpClientWriter::new(writer),
        }
    }

    pub(crate) fn into_split(self) -> (TcpReader<R>, TcpClientWriter<W>) {
        (self.reader, self.writer)
    }
}

pub(crate) struct TcpPayloadReader<R> {
    reader: V4StreamReader<R>,
    pending: BytesMut,
    done: bool,
}

impl<R> TcpPayloadReader<R>
where
    R: AsyncRead + Unpin,
{
    pub(crate) fn client(reader: V4StreamReader<R>) -> Self {
        Self::new(reader, BytesMut::new())
    }

    fn new(reader: V4StreamReader<R>, pending: BytesMut) -> Self {
        Self {
            reader,
            pending,
            done: false,
        }
    }

    pub(crate) async fn read_tunnel_reply(&mut self) -> Result<()> {
        let payload_start = match self.reader.read_server_reply().await? {
            ServerReply::Tunnel { payload_span, .. } => Ok(payload_span.start),
            ServerReply::Pong => Err(Error::InvalidServerReply),
            ServerReply::Error { code, message } => Err(Error::Server {
                code,
                message: message.to_owned(),
            }),
        }?;
        self.pending = self.reader.take_payload_from(payload_start);
        Ok(())
    }

    async fn read_payload_chunk_with_transport_eof(
        &mut self,
        transport_eof_is_done: bool,
    ) -> Result<Option<&[u8]>> {
        if self.done {
            return Ok(None);
        }

        if !self.pending.is_empty() {
            return Ok(Some(&self.pending));
        }

        match self.reader.read_frame_payload().await {
            Ok(payload) => Ok(Some(payload)),
            Err(Error::ZeroChunk) => {
                self.done = true;
                Ok(None)
            }
            Err(Error::Io(err))
                if transport_eof_is_done && Error::is_closed_io_kind(err.kind()) =>
            {
                self.done = true;
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    async fn read_payload_chunk(&mut self) -> Result<Option<&[u8]>> {
        self.read_payload_chunk_with_transport_eof(true).await
    }

    pub(crate) async fn read_payload_chunk_strict(&mut self) -> Result<Option<&[u8]>> {
        self.read_payload_chunk_with_transport_eof(false).await
    }

    pub(crate) fn consume_payload_chunk(&mut self, len: usize) {
        if !self.pending.is_empty() {
            self.pending.advance(len.min(self.pending.len()));
        }
    }

    pub(crate) fn reset(&mut self) {
        self.pending.clear();
        self.done = false;
    }

    pub(crate) fn compact_buffers_for_reuse(&mut self) {
        self.reader.compact_buffers_for_reuse();
        self.pending.clear();
        if self.pending.capacity() > STREAM_BUFFER_RETAIN_CAPACITY {
            self.pending = BytesMut::new();
        }
    }

    pub(crate) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    pub(crate) fn is_done(&self) -> bool {
        self.done
    }

    fn into_frame_reader(self) -> V4StreamReader<R> {
        self.reader
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TcpReaderPhase {
    ServerReply,
    Payload,
}

pub(crate) struct TcpReader<R> {
    payload: TcpPayloadReader<R>,
    phase: TcpReaderPhase,
}

impl<R> TcpReader<R>
where
    R: AsyncRead + Unpin,
{
    fn client(reader: V4StreamReader<R>) -> Self {
        Self {
            payload: TcpPayloadReader::client(reader),
            phase: TcpReaderPhase::ServerReply,
        }
    }

    fn server(reader: V4StreamReader<R>, pending: BytesMut) -> Self {
        Self {
            payload: TcpPayloadReader::new(reader, pending),
            phase: TcpReaderPhase::Payload,
        }
    }

    async fn read_tunnel_reply(&mut self) -> Result<()> {
        if self.phase == TcpReaderPhase::Payload {
            return Ok(());
        }

        self.payload.read_tunnel_reply().await?;
        self.phase = TcpReaderPhase::Payload;
        Ok(())
    }

    pub(crate) async fn read_payload_chunk(&mut self) -> Result<Option<&[u8]>> {
        if self.phase == TcpReaderPhase::ServerReply {
            self.read_tunnel_reply().await?;
        }
        self.payload.read_payload_chunk().await
    }

    pub(crate) fn consume_payload_chunk(&mut self, len: usize) {
        self.payload.consume_payload_chunk(len);
    }

    pub(crate) fn into_frame_reader(self) -> V4StreamReader<R> {
        self.payload.into_frame_reader()
    }
}

pub(crate) struct TcpClientWriter<W> {
    frame_writer: V4StreamWriter<W>,
    write_closed: bool,
}

impl<W> TcpClientWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn new(writer: V4StreamWriter<W>) -> Self {
        Self {
            frame_writer: writer,
            write_closed: false,
        }
    }

    pub(crate) async fn write_payload_from_reader<P>(
        &mut self,
        plain: &mut P,
    ) -> Result<Option<usize>>
    where
        P: AsyncRead + Unpin,
    {
        if self.write_closed {
            return Err(Error::WriteClosed);
        }
        self.frame_writer.write_payload_from_reader(plain).await
    }

    pub(crate) async fn close_write(&mut self) -> Result<()> {
        if !self.write_closed {
            self.frame_writer.write_zero_chunk().await?;
            self.write_closed = true;
        }
        Ok(())
    }
}

pub(crate) struct TcpServerStream<R, W> {
    reader: TcpReader<R>,
    writer: TcpServerWriter<W>,
}

impl<R, W> TcpServerStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub(crate) fn from_parts_with_pending(
        reader: V4StreamReader<R>,
        writer: V4StreamWriter<W>,
        pending: BytesMut,
    ) -> Self {
        Self {
            reader: TcpReader::server(reader, pending),
            writer: TcpServerWriter::new(writer),
        }
    }

    pub(crate) async fn accept(&mut self) -> Result<()> {
        self.writer.open_tunnel().await
    }

    #[cfg(test)]
    pub(crate) async fn reject(self, code: u8, message: &str) -> Result<()> {
        self.writer.reject(code, message).await
    }

    pub(crate) fn into_split(self) -> (TcpReader<R>, TcpServerWriter<W>) {
        (self.reader, self.writer)
    }
}

pub(crate) struct TcpServerWriter<W> {
    frame_writer: V4StreamWriter<W>,
    tunnel_open: bool,
    write_closed: bool,
}

impl<W> TcpServerWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn new(writer: V4StreamWriter<W>) -> Self {
        Self {
            frame_writer: writer,
            tunnel_open: false,
            write_closed: false,
        }
    }

    async fn open_tunnel(&mut self) -> Result<()> {
        if !self.tunnel_open {
            self.frame_writer.write_tunnel_reply(&[]).await?;
            self.tunnel_open = true;
        }
        Ok(())
    }

    #[cfg(test)]
    async fn reject(mut self, code: u8, message: &str) -> Result<()> {
        if !self.tunnel_open && !self.write_closed {
            self.frame_writer.write_error_reply(code, message).await?;
            self.write_closed = true;
        }
        Ok(())
    }

    pub(crate) async fn write_payload_from_reader<P>(
        &mut self,
        plain: &mut P,
    ) -> Result<Option<usize>>
    where
        P: AsyncRead + Unpin,
    {
        if self.write_closed {
            return Err(Error::WriteClosed);
        }
        if !self.tunnel_open {
            let n = self
                .frame_writer
                .write_tunnel_reply_from_reader(plain)
                .await?;
            if n.is_some() {
                self.tunnel_open = true;
            }
            return Ok(n);
        }
        self.frame_writer.write_payload_from_reader(plain).await
    }

    pub(crate) async fn close_write(&mut self) -> Result<()> {
        if !self.write_closed {
            self.open_tunnel().await?;
            self.frame_writer.write_zero_chunk().await?;
            self.write_closed = true;
        }
        Ok(())
    }

    pub(crate) fn into_frame_writer(self) -> V4StreamWriter<W> {
        self.frame_writer
    }
}

#[cfg(test)]
mod tests {
    use core::range::Range;

    use bytes::BytesMut;
    use tokio::io::{AsyncRead, AsyncWrite, duplex};

    use super::{TcpClientStream, TcpServerStream, TcpTarget};
    use crate::VERSION_4;
    use crate::error::Error;
    use crate::protocol::header::write_tcp_request_header;
    use crate::protocol::request::{ClientRequest, ServerReply};
    use crate::transport::tokio_io::{
        STREAM_BUFFER_RETAIN_CAPACITY, V4StreamReader, V4StreamWriter,
    };

    async fn write_client_payload<W>(
        writer: &mut super::TcpClientWriter<W>,
        payload: &[u8],
    ) -> crate::error::Result<usize>
    where
        W: AsyncWrite + Unpin,
    {
        let mut plain = payload;
        Ok(writer
            .write_payload_from_reader(&mut plain)
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
            .write_payload_from_reader(&mut plain)
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
        let mut reader = V4StreamReader::new(reader_io, psk)?;
        let (target, rest_start) = match reader.read_client_request().await? {
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
        let writer = V4StreamWriter::new(writer_io, psk)?;
        Ok((
            target,
            TcpServerStream::from_parts_with_pending(reader, writer, pending),
        ))
    }

    #[test]
    fn client_payload_reader_starts_without_pending_allocation() {
        let psk = b"test psk";
        let reader = V4StreamReader::new(tokio::io::empty(), psk).unwrap();
        let payload = super::TcpPayloadReader::client(reader);

        assert_eq!(payload.pending.capacity(), 0);
    }

    #[test]
    fn compact_for_reuse_retains_bounded_pending_buffer() {
        let psk = b"test psk";
        let reader = V4StreamReader::new(tokio::io::empty(), psk).unwrap();
        let mut pending = BytesMut::with_capacity(128);
        pending.extend_from_slice(b"early");
        let mut payload = super::TcpPayloadReader::new(reader, pending);

        payload.compact_buffers_for_reuse();

        assert!(payload.pending.is_empty());
        assert!(payload.pending.capacity() >= 128);
        assert!(payload.pending.capacity() <= STREAM_BUFFER_RETAIN_CAPACITY);
    }

    #[test]
    fn compact_for_reuse_drops_oversized_pending_buffer() {
        let psk = b"test psk";
        let reader = V4StreamReader::new(tokio::io::empty(), psk).unwrap();
        let mut pending = BytesMut::with_capacity(STREAM_BUFFER_RETAIN_CAPACITY + 1);
        pending.extend_from_slice(b"early");
        assert!(pending.capacity() > STREAM_BUFFER_RETAIN_CAPACITY);
        let mut payload = super::TcpPayloadReader::new(reader, pending);

        payload.compact_buffers_for_reuse();

        assert!(payload.pending.is_empty());
        assert_eq!(payload.pending.capacity(), 0);
    }

    #[tokio::test]
    async fn client_open_writes_connect_request() {
        let (client_upload, server_upload) = duplex(4096);
        let psk = b"test psk";

        let client = async {
            let stream = TcpClientStream::open_io(
                tokio::io::empty(),
                client_upload,
                psk,
                "example.com",
                443,
                VERSION_4,
                false,
            )
            .await
            .unwrap();
            let _ = stream.into_split();
        };

        let server = async {
            let mut reader = V4StreamReader::new(server_upload, psk).unwrap();
            let request = reader.read_client_request().await.unwrap();
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
        let (server_download, client_download) = duplex(4096);
        let psk = b"test psk";

        let client = async {
            let frame_reader = V4StreamReader::new(client_download, psk).unwrap();
            let mut reader = super::TcpReader::client(frame_reader);

            let reply = reader.read_payload_chunk().await.unwrap().unwrap();
            assert_eq!(reply, b"accepted");
            let reply_len = reply.len();
            reader.consume_payload_chunk(reply_len);

            assert!(reader.read_payload_chunk().await.unwrap().is_none());
        };

        let server = async {
            let mut server_writer = V4StreamWriter::new(server_download, psk).unwrap();
            server_writer.write_tunnel_reply(b"accepted").await.unwrap();
            server_writer.shutdown().await.unwrap();
        };

        let ((), ()) = tokio::join!(client, server);
    }

    #[tokio::test]
    async fn server_reader_maps_transport_eof_to_eof() {
        let (client_upload, server_upload) = duplex(4096);
        let psk = b"test psk";
        drop(client_upload);

        let frame_reader = V4StreamReader::new(server_upload, psk).unwrap();
        let mut reader = super::TcpReader::server(frame_reader, BytesMut::new());
        assert!(reader.read_payload_chunk().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn server_stream_preserves_early_data_and_coalesces_first_reply() {
        let (client_upload, server_upload) = duplex(4096);
        let (server_download, client_download) = duplex(4096);
        let psk = b"test psk";

        let client = async {
            let mut plain = BytesMut::new();
            write_tcp_request_header(&mut plain, "example.com", 443, VERSION_4, true).unwrap();
            plain.extend_from_slice(b"early");

            let mut writer = V4StreamWriter::new(client_upload, psk).unwrap();
            writer.write_frame(&plain).await.unwrap();

            let mut reader = V4StreamReader::new(client_download, psk).unwrap();
            let reply = reader.read_server_reply().await.unwrap();
            assert_eq!(
                reply,
                ServerReply::Tunnel {
                    payload_span: Range { start: 1, end: 6 },
                    payload: b"first"
                }
            );
        };

        let server = async {
            let (target, stream) = accept_client_connect(server_upload, server_download, psk)
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
            let early = reader.read_payload_chunk().await.unwrap().unwrap();
            assert_eq!(early, b"early");
            let early_len = early.len();
            reader.consume_payload_chunk(early_len);

            assert_eq!(
                write_server_payload(&mut writer, b"first").await.unwrap(),
                5
            );
        };

        let ((), ()) = tokio::join!(client, server);
    }

    #[tokio::test]
    async fn server_writer_coalesces_tunnel_with_first_reader_payload() {
        let (server_download, client_download) = duplex(4096);
        let psk = b"test psk";

        let server = async {
            let writer = V4StreamWriter::new(server_download, psk).unwrap();
            let mut writer = super::TcpServerWriter::new(writer);
            assert_eq!(
                write_server_payload(&mut writer, b"first").await.unwrap(),
                5
            );
        };

        let client = async {
            let mut reader = V4StreamReader::new(client_download, psk).unwrap();
            let reply = reader.read_server_reply().await.unwrap();

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
    async fn split_halves_can_read_and_write_concurrently() {
        let (client_upload, server_upload) = duplex(4096);
        let (server_download, client_download) = duplex(4096);
        let psk = b"test psk";

        let client = async {
            let stream = TcpClientStream::open_io(
                client_download,
                client_upload,
                psk,
                "example.com",
                443,
                VERSION_4,
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
                let payload = reader.read_payload_chunk().await.unwrap().unwrap();
                assert_eq!(payload, b"pong");
                let len = payload.len();
                reader.consume_payload_chunk(len);
            };

            tokio::join!(read, write);
        };

        let server = async {
            let (target, stream) = accept_client_connect(server_upload, server_download, psk)
                .await
                .unwrap();
            assert_eq!(target.host, "example.com");
            let (mut reader, mut writer) = stream.into_split();

            let read = async {
                let payload = reader.read_payload_chunk().await.unwrap().unwrap();
                assert_eq!(payload, b"ping");
                let len = payload.len();
                reader.consume_payload_chunk(len);
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
        let psk = b"test psk";
        let frame_writer = V4StreamWriter::new(tokio::io::sink(), psk).unwrap();
        let mut writer = super::TcpClientWriter::new(frame_writer);

        writer.close_write().await.unwrap();
        assert!(matches!(
            write_client_payload(&mut writer, b"after close").await,
            Err(Error::WriteClosed)
        ));
    }

    #[tokio::test]
    async fn server_writer_rejects_write_after_close() {
        let psk = b"test psk";
        let frame_writer = V4StreamWriter::new(tokio::io::sink(), psk).unwrap();
        let mut writer = super::TcpServerWriter::new(frame_writer);

        writer.close_write().await.unwrap();
        assert!(matches!(
            write_server_payload(&mut writer, b"after close").await,
            Err(Error::WriteClosed)
        ));
    }

    #[tokio::test]
    async fn server_stream_can_reject_before_opening_tunnel() {
        let (server_download, client_download) = duplex(4096);
        let psk = b"test psk";

        let read = async {
            let mut reader = V4StreamReader::new(client_download, psk).unwrap();
            assert!(matches!(
                reader.read_server_reply().await,
                Ok(ServerReply::Error {
                    code: 9,
                    message: "blocked"
                })
            ));
        };

        let reject = async {
            let reader = V4StreamReader::new(tokio::io::empty(), psk).unwrap();
            let writer = V4StreamWriter::new(server_download, psk).unwrap();
            let stream = TcpServerStream::from_parts_with_pending(reader, writer, BytesMut::new());
            stream.reject(9, "blocked").await.unwrap();
        };

        let ((), ()) = tokio::join!(read, reject);
    }
}

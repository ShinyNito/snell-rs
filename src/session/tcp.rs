use std::future::poll_fn;
use std::task::{Context, Poll, ready};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::ProtocolVersion;
use crate::error::{Error, Result};
use crate::framed::{
    SnellStreamReader, SnellStreamWriter, poll_read_ahead_into_spare_with_capacity,
};
use crate::protocol::request::ServerReply;

pub(crate) mod relay;

const SERVER_PLAIN_BATCH_INITIAL_CAPACITY: usize = 64 * 1024;
pub(crate) const SERVER_PLAIN_READ_AHEAD_CAPACITY: usize = 256 * 1024;

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
        snell_version: ProtocolVersion,
        reuse: bool,
    ) -> Result<Self> {
        let mut writer = SnellStreamWriter::new(writer_io, psk, snell_version)?;
        writer.write_tcp_request(host, port, reuse).await?;
        let reader = SnellStreamReader::new(reader_io, psk, snell_version)?;
        Ok(Self::from_parts(reader, writer))
    }

    fn from_parts(reader: SnellStreamReader<R>, writer: SnellStreamWriter<W>) -> Self {
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
    reader: SnellStreamReader<R>,
    pending: Bytes,
    done: bool,
}

impl<R> TcpPayloadReader<R>
where
    R: AsyncRead + Unpin,
{
    pub(crate) fn client(reader: SnellStreamReader<R>) -> Self {
        Self::new(reader, Bytes::new())
    }

    fn new(reader: SnellStreamReader<R>, pending: Bytes) -> Self {
        Self {
            reader,
            pending,
            done: false,
        }
    }

    pub(crate) async fn read_tunnel_reply(&mut self) -> Result<()> {
        poll_fn(|cx| self.poll_read_tunnel_reply(cx)).await
    }

    fn poll_read_tunnel_reply(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let payload_start = match ready!(self.reader.poll_read_server_reply(cx))? {
            ServerReply::Tunnel { payload_span, .. } => Ok(payload_span.start),
            ServerReply::Pong => Err(Error::InvalidServerReply),
            ServerReply::Error { code, message } => Err(Error::Server {
                code,
                message: message.to_owned(),
            }),
        }?;
        self.pending = self.reader.take_payload_from(payload_start);
        Poll::Ready(Ok(()))
    }

    fn poll_take_payload_chunk_with_transport_eof(
        &mut self,
        cx: &mut Context<'_>,
        transport_eof_is_done: bool,
    ) -> Poll<Result<Option<Bytes>>> {
        if self.done {
            return Poll::Ready(Ok(None));
        }

        if !self.pending.is_empty() {
            return Poll::Ready(Ok(Some(std::mem::take(&mut self.pending))));
        }

        match ready!(self.reader.poll_read_frame_payload(cx)) {
            Ok(_) => Poll::Ready(Ok(Some(self.reader.take_payload_from(0)))),
            Err(Error::ZeroChunk) => {
                self.done = true;
                Poll::Ready(Ok(None))
            }
            Err(Error::Io(err))
                if transport_eof_is_done && Error::is_closed_io_kind(err.kind()) =>
            {
                self.done = true;
                Poll::Ready(Ok(None))
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    pub(crate) async fn take_payload_chunk_strict(&mut self) -> Result<Option<Bytes>> {
        poll_fn(|cx| self.poll_take_payload_chunk_with_transport_eof(cx, false)).await
    }

    pub(crate) fn reset(&mut self) {
        self.pending = Bytes::new();
        self.done = false;
    }

    pub(crate) fn compact_buffers_for_reuse(&mut self) {
        self.reader.compact_buffers_for_reuse();
        self.pending = Bytes::new();
    }

    pub(crate) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    pub(crate) fn is_done(&self) -> bool {
        self.done
    }

    fn into_frame_reader(self) -> SnellStreamReader<R> {
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
    fn client(reader: SnellStreamReader<R>) -> Self {
        Self {
            payload: TcpPayloadReader::client(reader),
            phase: TcpReaderPhase::ServerReply,
        }
    }

    fn server(reader: SnellStreamReader<R>, pending: Bytes) -> Self {
        Self {
            payload: TcpPayloadReader::new(reader, pending),
            phase: TcpReaderPhase::Payload,
        }
    }

    fn poll_read_tunnel_reply(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if self.phase == TcpReaderPhase::Payload {
            return Poll::Ready(Ok(()));
        }

        ready!(self.payload.poll_read_tunnel_reply(cx))?;
        self.phase = TcpReaderPhase::Payload;
        Poll::Ready(Ok(()))
    }

    pub(crate) fn poll_take_payload_chunk(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>>> {
        if self.phase == TcpReaderPhase::ServerReply {
            ready!(self.poll_read_tunnel_reply(cx))?;
        }
        self.payload
            .poll_take_payload_chunk_with_transport_eof(cx, true)
    }

    pub(crate) async fn take_payload_chunk(&mut self) -> Result<Option<Bytes>> {
        poll_fn(|cx| self.poll_take_payload_chunk(cx)).await
    }

    pub(crate) fn into_frame_reader(self) -> SnellStreamReader<R> {
        self.payload.into_frame_reader()
    }
}

pub(crate) struct TcpClientWriter<W> {
    frame_writer: SnellStreamWriter<W>,
    write_closed: bool,
}

impl<W> TcpClientWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn new(writer: SnellStreamWriter<W>) -> Self {
        Self {
            frame_writer: writer,
            write_closed: false,
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
        self.frame_writer
            .write_next_payload_record_from_reader(plain)
            .await
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
        reader: SnellStreamReader<R>,
        writer: SnellStreamWriter<W>,
        pending: Bytes,
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
    pub(crate) async fn reject(mut self, code: u8, message: &str) -> Result<()> {
        self.writer.reject(code, message).await
    }

    pub(crate) fn into_split(self) -> (TcpReader<R>, TcpServerWriter<W>) {
        (self.reader, self.writer)
    }
}

pub(crate) struct TcpServerWriter<W> {
    frame_writer: SnellStreamWriter<W>,
    plain_batch: PlainReadBatch,
    tunnel_open: bool,
    write_closed: bool,
}

impl<W> TcpServerWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn new(writer: SnellStreamWriter<W>) -> Self {
        Self {
            frame_writer: writer,
            plain_batch: PlainReadBatch::new(),
            tunnel_open: false,
            write_closed: false,
        }
    }

    pub(crate) async fn open_tunnel(&mut self) -> Result<()> {
        if !self.tunnel_open {
            self.frame_writer.write_empty_tunnel_reply().await?;
            self.tunnel_open = true;
        }
        Ok(())
    }

    pub(crate) async fn reject(&mut self, code: u8, message: &str) -> Result<()> {
        if !self.tunnel_open && !self.write_closed {
            self.frame_writer.write_error_reply(code, message).await?;
            self.write_closed = true;
        }
        Ok(())
    }

    pub(crate) async fn write_payload_batch_from_reader<P>(
        &mut self,
        plain: &mut P,
    ) -> Result<Option<usize>>
    where
        P: AsyncRead + Unpin,
    {
        if self.write_closed {
            return Err(Error::WriteClosed);
        }

        poll_fn(|cx| self.plain_batch.poll_fill_from(plain, cx)).await?;

        let mut written = 0;
        while !self.plain_batch.buffer.is_empty() {
            let n = if !self.tunnel_open {
                let Some(n) = self
                    .frame_writer
                    .write_tunnel_reply_from_buffer(&mut self.plain_batch.buffer)
                    .await?
                else {
                    break;
                };
                self.tunnel_open = true;
                n
            } else {
                let Some(n) = self
                    .frame_writer
                    .write_payload_from_buffer(&mut self.plain_batch.buffer)
                    .await?
                else {
                    break;
                };
                n
            };
            written += n;
        }

        if written != 0 {
            Ok(Some(written))
        } else if self.plain_batch.is_done() {
            Ok(None)
        } else {
            debug_assert!(false, "plain batch should contain data or be done");
            Ok(None)
        }
    }

    pub(crate) async fn close_write(&mut self) -> Result<()> {
        if !self.write_closed {
            self.open_tunnel().await?;
            self.frame_writer.write_zero_chunk().await?;
            self.write_closed = true;
        }
        Ok(())
    }

    pub(crate) fn into_frame_writer(self) -> SnellStreamWriter<W> {
        self.frame_writer
    }
}

struct PlainReadBatch {
    buffer: BytesMut,
    eof: bool,
}

impl PlainReadBatch {
    fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(SERVER_PLAIN_BATCH_INITIAL_CAPACITY),
            eof: false,
        }
    }

    fn is_done(&self) -> bool {
        self.eof && self.buffer.is_empty()
    }

    fn poll_fill_from<P>(&mut self, plain: &mut P, cx: &mut Context<'_>) -> Poll<Result<()>>
    where
        P: AsyncRead + Unpin,
    {
        if self.eof || self.buffer.len() >= SERVER_PLAIN_READ_AHEAD_CAPACITY {
            return Poll::Ready(Ok(()));
        }

        loop {
            let min_spare = SERVER_PLAIN_READ_AHEAD_CAPACITY.saturating_sub(self.buffer.len());
            match poll_read_ahead_into_spare_with_capacity(
                plain,
                cx,
                &mut self.buffer,
                min_spare,
                SERVER_PLAIN_READ_AHEAD_CAPACITY,
            ) {
                Poll::Pending if self.buffer.is_empty() => return Poll::Pending,
                Poll::Pending => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(0)) => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(_)) if self.buffer.len() >= SERVER_PLAIN_READ_AHEAD_CAPACITY => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
    use crate::protocol::request::{ClientRequest, ServerReply};
    use crate::test_support::{TEST_PSK, test_duplex_pair, test_snell_reader, test_snell_writer};

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
            .write_next_payload_record_from_reader(&mut plain)
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
            .write_payload_batch_from_reader(&mut plain)
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
        let mut reader =
            crate::framed::SnellStreamReader::new(reader_io, psk, ProtocolVersion::V4)?;
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
            server_writer
                .write_test_tunnel_reply(b"accepted")
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
            writer.write_test_frame(&plain).await.unwrap();

            let mut reader = test_snell_reader(client_download);
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
    async fn server_writer_batch_drains_plain_buffer_across_records() {
        let (server_download, client_download) = tokio::io::duplex(256 * 1024);
        let payload = vec![0x42; SERVER_PLAIN_READ_AHEAD_CAPACITY / 2];

        let server = async {
            let writer = test_snell_writer(server_download);
            let mut writer = super::TcpServerWriter::new(writer);
            let mut plain = payload.as_slice();

            assert_eq!(
                writer
                    .write_payload_batch_from_reader(&mut plain)
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
                .write_payload_batch_from_reader(&mut plain)
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
            assert!(matches!(
                reader.read_server_reply().await,
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
}

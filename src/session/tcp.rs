use std::future::poll_fn;
use std::task::{Context, Poll, ready};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::ProtocolVersion;
use crate::error::{Error, Result};
use crate::framed::{
    SnellStreamReader, SnellStreamWriter, poll_read_ahead_into_spare_with_capacity,
};
use crate::protocol::request::{ServerReply, parse_server_reply};

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
        let reader = SnellStreamReader::new(reader_io, psk, snell_version);
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

    pub(crate) fn poll_read_tunnel_reply(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let payload_start = {
            let payload = ready!(self.reader.poll_read_frame_payload(cx))?;
            match parse_server_reply(payload)? {
                ServerReply::Tunnel { payload_span, .. } => Ok(payload_span.start),
                ServerReply::Pong => Err(Error::InvalidServerReply),
                ServerReply::Error { code, message } => Err(Error::Server {
                    code,
                    message: message.to_owned(),
                }),
            }
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

    pub(crate) fn poll_take_payload_chunk_strict(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>>> {
        self.poll_take_payload_chunk_with_transport_eof(cx, false)
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
    plain_batch: PlainReadBatch,
    write_closed: bool,
}

impl<W> TcpClientWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn new(writer: SnellStreamWriter<W>) -> Self {
        Self {
            frame_writer: writer,
            plain_batch: PlainReadBatch::new(),
            write_closed: false,
        }
    }

    pub(crate) async fn write_payload_message_from_reader<P>(
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
        match self
            .frame_writer
            .write_payload_message_from_buffer(&mut self.plain_batch.buffer)
            .await?
        {
            Some(n) => Ok(Some(n)),
            None if self.plain_batch.is_done() => Ok(None),
            None => {
                debug_assert!(false, "plain batch should contain data or be done");
                Ok(None)
            }
        }
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

    pub(crate) async fn write_payload_message_from_reader<P>(
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

        let written = if !self.tunnel_open {
            match self
                .frame_writer
                .write_tunnel_reply_message_from_buffer(&mut self.plain_batch.buffer)
                .await?
            {
                Some(n) => {
                    self.tunnel_open = true;
                    n
                }
                None => 0,
            }
        } else {
            self.frame_writer
                .write_payload_message_from_buffer(&mut self.plain_batch.buffer)
                .await?
                .unwrap_or(0)
        };

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

pub(crate) struct PlainReadBatch {
    pub(crate) buffer: BytesMut,
    eof: bool,
}

impl PlainReadBatch {
    pub(crate) fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(SERVER_PLAIN_BATCH_INITIAL_CAPACITY),
            eof: false,
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.eof && self.buffer.is_empty()
    }

    pub(crate) fn compact_for_reuse(&mut self) {
        self.buffer.clear();
        if self.buffer.capacity() > SERVER_PLAIN_READ_AHEAD_CAPACITY {
            self.buffer = BytesMut::with_capacity(SERVER_PLAIN_BATCH_INITIAL_CAPACITY);
        }
        self.eof = false;
    }

    pub(crate) fn poll_fill_from<P>(
        &mut self,
        plain: &mut P,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>>
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
mod tests;

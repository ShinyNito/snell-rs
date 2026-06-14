use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ProtocolVersion;
use crate::error::{Error, Result};
use crate::framed::{SnellStreamReader, SnellStreamWriter};
use crate::protocol::psk::SnellPsk;
use crate::protocol::request::{ServerReply, parse_server_reply};

pub(crate) mod relay;

const SERVER_PLAIN_BATCH_INITIAL_CAPACITY: usize = 64 * 1024;
pub(crate) const SERVER_PLAIN_READ_AHEAD_CAPACITY: usize = 256 * 1024;

pub(crate) fn error_into_io(err: Error) -> io::Error {
    match err {
        Error::Io(err) => err,
        Error::WriteClosed => io::Error::new(io::ErrorKind::BrokenPipe, err),
        err => io::Error::other(err),
    }
}

pub(crate) fn poll_result_into_io<T>(poll: Poll<Result<T>>) -> Poll<io::Result<T>> {
    match poll {
        Poll::Ready(Ok(value)) => Poll::Ready(Ok(value)),
        Poll::Ready(Err(err)) => Poll::Ready(Err(error_into_io(err))),
        Poll::Pending => Poll::Pending,
    }
}

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

pub(crate) struct TcpClientOpenOptions<'a> {
    pub(crate) secret: &'a SnellPsk,
    pub(crate) host: &'a str,
    pub(crate) port: u16,
    pub(crate) version: ProtocolVersion,
    pub(crate) reuse: bool,
}

impl<R, W> TcpClientStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub(crate) async fn open_io(
        reader_io: R,
        writer_io: W,
        options: TcpClientOpenOptions<'_>,
    ) -> Result<Self> {
        let TcpClientOpenOptions {
            secret,
            host,
            port,
            version,
            reuse,
        } = options;
        let mut writer = SnellStreamWriter::new(writer_io, secret, version)?;
        writer.write_tcp_request(host, port, reuse).await?;
        let reader = SnellStreamReader::new(reader_io, secret, version);
        Ok(Self::from_parts(reader, writer))
    }

    fn from_parts(reader: SnellStreamReader<R>, writer: SnellStreamWriter<W>) -> Self {
        Self {
            reader: TcpReader::client(reader),
            writer: TcpClientWriter::new(writer),
        }
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
    pub(crate) const fn client(reader: SnellStreamReader<R>) -> Self {
        Self::new(reader, Bytes::new())
    }

    const fn new(reader: SnellStreamReader<R>, pending: Bytes) -> Self {
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

    pub(crate) fn poll_read_payload(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
        transport_eof_is_done: bool,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 || self.done {
            return Poll::Ready(Ok(()));
        }

        loop {
            if !self.pending.is_empty() {
                let n = self.pending.len().min(out.remaining());
                out.put_slice(&self.pending[..n]);
                self.pending.advance(n);
                return Poll::Ready(Ok(()));
            }

            match ready!(self.reader.poll_read_frame_payload(cx)) {
                Ok(_) => {
                    self.pending = self.reader.take_payload_from(0);
                }
                Err(Error::ZeroChunk) => {
                    self.done = true;
                    return Poll::Ready(Ok(()));
                }
                Err(Error::Io(err))
                    if transport_eof_is_done && Error::is_closed_io_kind(err.kind()) =>
                {
                    self.done = true;
                    return Poll::Ready(Ok(()));
                }
                Err(err) => return Poll::Ready(Err(error_into_io(err))),
            }
        }
    }

    pub(crate) fn reset(&mut self) {
        self.pending = Bytes::new();
        self.done = false;
    }

    pub(crate) fn compact_buffers_for_reuse(&mut self) {
        self.reader.compact_buffers_for_reuse();
        self.pending = Bytes::new();
    }

    pub(crate) const fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    pub(crate) const fn is_done(&self) -> bool {
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

struct TcpReader<R> {
    payload: TcpPayloadReader<R>,
    phase: TcpReaderPhase,
}

impl<R> TcpReader<R>
where
    R: AsyncRead + Unpin,
{
    const fn client(reader: SnellStreamReader<R>) -> Self {
        Self {
            payload: TcpPayloadReader::client(reader),
            phase: TcpReaderPhase::ServerReply,
        }
    }

    const fn server(reader: SnellStreamReader<R>, pending: Bytes) -> Self {
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

    fn into_frame_reader(self) -> SnellStreamReader<R> {
        self.payload.into_frame_reader()
    }
}

impl<R> AsyncRead for TcpReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.phase == TcpReaderPhase::ServerReply
            && let Err(err) = ready!(this.poll_read_tunnel_reply(cx))
        {
            return Poll::Ready(Err(error_into_io(err)));
        }
        this.payload.poll_read_payload(cx, out, true)
    }
}

impl<R, W> AsyncRead for TcpClientStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, out)
    }
}

struct PlainWriteBuffer {
    batch: PlainReadBatch,
    pending_write_len: Option<usize>,
}

impl PlainWriteBuffer {
    fn new() -> Self {
        Self {
            batch: PlainReadBatch::new(),
            pending_write_len: None,
        }
    }

    fn poll_write_payload<W>(
        &mut self,
        frame_writer: &mut SnellStreamWriter<W>,
        buf: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        self.poll_write_with(buf, cx, |batch, cx| {
            batch.poll_flush_payload(frame_writer, cx)
        })
    }

    fn poll_write_tunnel_payload<W>(
        &mut self,
        frame_writer: &mut SnellStreamWriter<W>,
        buf: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        self.poll_write_with(buf, cx, |batch, cx| {
            batch.poll_flush_tunnel_payload(frame_writer, cx)
        })
    }

    fn poll_write_with<F>(
        &mut self,
        buf: &[u8],
        cx: &mut Context<'_>,
        mut poll_flush: F,
    ) -> Poll<Result<usize>>
    where
        F: FnMut(&mut PlainReadBatch, &mut Context<'_>) -> Poll<Result<()>>,
    {
        if let Some(n) = self.pending_write_len {
            ready!(poll_flush(&mut self.batch, cx))?;
            self.pending_write_len = None;
            return Poll::Ready(Ok(n));
        }

        ready!(poll_flush(&mut self.batch, cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let n = buf.len().min(SERVER_PLAIN_READ_AHEAD_CAPACITY);
        self.batch.buffer.extend_from_slice(&buf[..n]);
        self.pending_write_len = Some(n);
        ready!(poll_flush(&mut self.batch, cx))?;
        self.pending_write_len = None;
        Poll::Ready(Ok(n))
    }

    fn poll_flush_payload<W>(
        &mut self,
        frame_writer: &mut SnellStreamWriter<W>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>>
    where
        W: AsyncWrite + Unpin,
    {
        ready!(self.batch.poll_flush_payload(frame_writer, cx))?;
        self.pending_write_len = None;
        Poll::Ready(Ok(()))
    }

    fn poll_flush_tunnel_payload<W>(
        &mut self,
        frame_writer: &mut SnellStreamWriter<W>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>>
    where
        W: AsyncWrite + Unpin,
    {
        ready!(self.batch.poll_flush_tunnel_payload(frame_writer, cx))?;
        self.pending_write_len = None;
        Poll::Ready(Ok(()))
    }
}

struct TcpClientWriter<W> {
    frame_writer: SnellStreamWriter<W>,
    plain: PlainWriteBuffer,
    write_closed: bool,
}

impl<W> TcpClientWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn new(writer: SnellStreamWriter<W>) -> Self {
        Self {
            frame_writer: writer,
            plain: PlainWriteBuffer::new(),
            write_closed: false,
        }
    }

    fn poll_close_write(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if !self.write_closed {
            ready!(self.plain.poll_flush_payload(&mut self.frame_writer, cx))?;
            ready!(self.frame_writer.poll_write_zero_chunk(cx))?;
            self.write_closed = true;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        ready!(self.plain.poll_flush_payload(&mut self.frame_writer, cx))?;
        self.frame_writer.poll_flush(cx)
    }
}

impl<W> AsyncWrite for TcpClientWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Err(error_into_io(Error::WriteClosed)));
        }
        poll_result_into_io(
            this.plain
                .poll_write_payload(&mut this.frame_writer, buf, cx),
        )
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        poll_result_into_io(self.get_mut().poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        poll_result_into_io(self.get_mut().poll_close_write(cx))
    }
}

impl<R, W> AsyncWrite for TcpClientStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
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

    pub(crate) async fn reject(&mut self, code: u8, message: &str) -> Result<()> {
        self.writer.reject(code, message).await
    }

    pub(crate) fn into_frame_parts(self) -> (SnellStreamReader<R>, SnellStreamWriter<W>) {
        (
            self.reader.into_frame_reader(),
            self.writer.into_frame_writer(),
        )
    }
}

impl<R, W> AsyncRead for TcpServerStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, out)
    }
}

struct TcpServerWriter<W> {
    frame_writer: SnellStreamWriter<W>,
    plain: PlainWriteBuffer,
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
            plain: PlainWriteBuffer::new(),
            tunnel_open: false,
            write_closed: false,
        }
    }

    async fn open_tunnel(&mut self) -> Result<()> {
        if !self.tunnel_open {
            self.frame_writer.write_empty_tunnel_reply().await?;
            self.tunnel_open = true;
        }
        Ok(())
    }

    async fn reject(&mut self, code: u8, message: &str) -> Result<()> {
        if !self.tunnel_open && !self.write_closed {
            self.frame_writer.write_error_reply(code, message).await?;
            self.write_closed = true;
        }
        Ok(())
    }

    fn poll_close_write(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if !self.write_closed {
            if !self.tunnel_open && self.plain.pending_write_len.is_some() {
                ready!(
                    self.plain
                        .poll_flush_tunnel_payload(&mut self.frame_writer, cx)
                )?;
                self.tunnel_open = true;
            } else {
                ready!(self.plain.poll_flush_payload(&mut self.frame_writer, cx))?;
                ready!(self.poll_open_tunnel(cx))?;
            }
            ready!(self.frame_writer.poll_write_zero_chunk(cx))?;
            self.write_closed = true;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_open_tunnel(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if !self.tunnel_open {
            ready!(self.frame_writer.poll_write_empty_tunnel_reply(cx))?;
            self.tunnel_open = true;
        }
        Poll::Ready(Ok(()))
    }

    fn into_frame_writer(self) -> SnellStreamWriter<W> {
        self.frame_writer
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if !self.tunnel_open && self.plain.pending_write_len.is_some() {
            ready!(
                self.plain
                    .poll_flush_tunnel_payload(&mut self.frame_writer, cx)
            )?;
            self.tunnel_open = true;
        } else if self.tunnel_open {
            ready!(self.plain.poll_flush_payload(&mut self.frame_writer, cx))?;
        }
        self.frame_writer.poll_flush(cx)
    }
}

impl<W> AsyncWrite for TcpServerWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Err(error_into_io(Error::WriteClosed)));
        }

        let result = if this.tunnel_open {
            this.plain
                .poll_write_payload(&mut this.frame_writer, buf, cx)
        } else {
            this.plain
                .poll_write_tunnel_payload(&mut this.frame_writer, buf, cx)
        };

        match result {
            Poll::Ready(Ok(n)) => {
                if n != 0 {
                    this.tunnel_open = true;
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(error_into_io(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        poll_result_into_io(self.get_mut().poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        poll_result_into_io(self.get_mut().poll_close_write(cx))
    }
}

impl<R, W> AsyncWrite for TcpServerStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

pub(crate) struct PlainReadBatch {
    pub(crate) buffer: BytesMut,
}

impl PlainReadBatch {
    pub(crate) fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(SERVER_PLAIN_BATCH_INITIAL_CAPACITY),
        }
    }

    pub(crate) fn compact_for_reuse(&mut self) {
        self.buffer.clear();
        if self.buffer.capacity() > SERVER_PLAIN_READ_AHEAD_CAPACITY {
            self.buffer = BytesMut::with_capacity(SERVER_PLAIN_BATCH_INITIAL_CAPACITY);
        }
    }

    pub(crate) fn poll_flush_payload<W>(
        &mut self,
        frame_writer: &mut SnellStreamWriter<W>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>>
    where
        W: AsyncWrite + Unpin,
    {
        self.poll_flush_message_with(frame_writer, cx, |frame_writer, buffer, cx| {
            frame_writer.poll_write_payload_message_from_buffer(buffer, cx)
        })
    }

    fn poll_flush_tunnel_payload<W>(
        &mut self,
        frame_writer: &mut SnellStreamWriter<W>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>>
    where
        W: AsyncWrite + Unpin,
    {
        self.poll_flush_message_with(frame_writer, cx, |frame_writer, buffer, cx| {
            frame_writer.poll_write_tunnel_reply_message_from_buffer(buffer, cx)
        })
    }

    fn poll_flush_message_with<W, F>(
        &mut self,
        frame_writer: &mut SnellStreamWriter<W>,
        cx: &mut Context<'_>,
        mut poll_write: F,
    ) -> Poll<Result<()>>
    where
        W: AsyncWrite + Unpin,
        F: FnMut(
            &mut SnellStreamWriter<W>,
            &mut BytesMut,
            &mut Context<'_>,
        ) -> Poll<Result<Option<usize>>>,
    {
        loop {
            if self.buffer.is_empty() && !frame_writer.has_pending_message_write() {
                return Poll::Ready(Ok(()));
            }

            match ready!(poll_write(frame_writer, &mut self.buffer, cx))? {
                Some(_) => {}
                None if self.buffer.is_empty() => return Poll::Ready(Ok(())),
                None => {
                    return Poll::Ready(Err(io::Error::other(
                        "plain batch had no payload to write before EOF",
                    )
                    .into()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;

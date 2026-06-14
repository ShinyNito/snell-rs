use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{Error, Result};
use crate::framed::{SnellStreamReader, SnellStreamWriter};
use crate::session::tcp::{PlainReadBatch, TcpPayloadReader, error_into_io, poll_result_into_io};

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

    pub(crate) async fn accept_tunnel_reply(&mut self) -> Result<()> {
        poll_fn(|cx| self.reader.poll_read_tunnel_reply(cx)).await
    }

    pub(crate) const fn can_reuse(&self) -> bool {
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
}

impl<R, W> AsyncRead for ReuseClientConn<R, W>
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

impl<R, W> AsyncWrite for ReuseClientConn<R, W>
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

struct ReuseClientReader<R> {
    payload: TcpPayloadReader<R>,
    reply_read: bool,
    broken: bool,
}

impl<R> ReuseClientReader<R>
where
    R: AsyncRead + Unpin,
{
    const fn new(reader: SnellStreamReader<R>) -> Self {
        Self {
            payload: TcpPayloadReader::client(reader),
            reply_read: false,
            broken: false,
        }
    }

    fn compact_buffers_for_reuse(&mut self) {
        self.payload.compact_buffers_for_reuse();
    }

    fn poll_read_tunnel_reply(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if self.reply_read {
            return Poll::Ready(Ok(()));
        }

        match ready!(self.payload.poll_read_tunnel_reply(cx)) {
            Ok(()) => {
                self.reply_read = true;
                Poll::Ready(Ok(()))
            }
            Err(err) => {
                self.broken = true;
                Poll::Ready(Err(err))
            }
        }
    }
}

impl<R> AsyncRead for ReuseClientReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.payload.is_done() {
            return Poll::Ready(Ok(()));
        }

        if !this.reply_read
            && let Err(err) = ready!(this.poll_read_tunnel_reply(cx))
        {
            return Poll::Ready(Err(error_into_io(err)));
        }

        match this.payload.poll_read_payload(cx, out, false) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => {
                this.broken = true;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

struct ReuseClientWriter<W> {
    frame_writer: SnellStreamWriter<W>,
    plain_batch: PlainReadBatch,
    pending_write_len: Option<usize>,
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
            plain_batch: PlainReadBatch::new(),
            pending_write_len: None,
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

    fn poll_close_write(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if !self.write_closed {
            ready!(self.poll_flush_payload(cx))?;
            match self.frame_writer.poll_write_zero_chunk(cx) {
                Poll::Ready(Ok(())) => self.write_closed = true,
                Poll::Ready(Err(err)) => {
                    self.broken = true;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_write_payload(&mut self, buf: &[u8], cx: &mut Context<'_>) -> Poll<Result<usize>> {
        if let Some(n) = self.pending_write_len {
            ready!(self.poll_flush_payload(cx))?;
            self.pending_write_len = None;
            return Poll::Ready(Ok(n));
        }

        ready!(self.poll_flush_payload(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let n = buf
            .len()
            .min(crate::session::tcp::SERVER_PLAIN_READ_AHEAD_CAPACITY);
        self.plain_batch.buffer.extend_from_slice(&buf[..n]);
        self.pending_write_len = Some(n);
        ready!(self.poll_flush_payload(cx))?;
        self.pending_write_len = None;
        Poll::Ready(Ok(n))
    }

    fn poll_flush_payload(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match self
            .plain_batch
            .poll_flush_payload(&mut self.frame_writer, cx)
        {
            Poll::Ready(Ok(())) => {
                self.pending_write_len = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                self.broken = true;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        ready!(self.poll_flush_payload(cx))?;
        self.frame_writer.poll_flush(cx)
    }

    fn compact_buffers_for_reuse(&mut self) {
        self.frame_writer.compact_buffers_for_reuse();
        self.plain_batch.compact_for_reuse();
        self.pending_write_len = None;
    }
}

impl<W> AsyncWrite for ReuseClientWriter<W>
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

        match this.poll_write_payload(buf, cx) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(err)) => {
                this.broken = true;
                Poll::Ready(Err(error_into_io(err)))
            }
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

#[cfg(test)]
mod tests;

use pin_project_lite::pin_project;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{Error, Result};
use crate::framed::{PayloadSource, PayloadWriteStatus, SnellStreamReader, SnellStreamWriter};
use crate::relay::tcp::SnellPayloadSink;
use crate::transport::tcp::{PlainReadBatch, TcpPayloadReader, error_into_io, poll_result_into_io};

pin_project! {
    pub(crate) struct ReuseClientConn<R, W> {
        #[pin]
        reader: ReuseClientReader<R>,
        #[pin]
        writer: ReuseClientWriter<W>,
    }
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
        self.project().reader.poll_read(cx, out)
    }
}

impl<R, W> SnellPayloadSink for ReuseClientConn<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn poll_write_payload_from_source<T>(
        self: Pin<&mut Self>,
        source: Pin<&mut T>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<PayloadWriteStatus>>
    where
        T: PayloadSource + ?Sized,
    {
        poll_result_into_io(
            self.project()
                .writer
                .poll_write_payload_from_source(source, cx),
        )
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
        self.project().writer.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().writer.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().writer.poll_shutdown(cx)
    }
}

pin_project! {
    struct ReuseClientReader<R> {
        payload: TcpPayloadReader<R>,
        reply_read: bool,
        broken: bool,
    }
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
        poll_reuse_read_tunnel_reply(
            &mut self.payload,
            &mut self.reply_read,
            &mut self.broken,
            cx,
        )
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
        let this = self.project();
        if this.payload.is_done() {
            return Poll::Ready(Ok(()));
        }

        if !*this.reply_read
            && let Err(err) = ready!(poll_reuse_read_tunnel_reply(
                this.payload,
                this.reply_read,
                this.broken,
                cx
            ))
        {
            return Poll::Ready(Err(error_into_io(err)));
        }

        match this.payload.poll_read_payload(cx, out, false) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => {
                *this.broken = true;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pin_project! {
    struct ReuseClientWriter<W> {
        frame_writer: SnellStreamWriter<W>,
        plain_batch: PlainReadBatch,
        pending_write_len: Option<usize>,
        write_closed: bool,
        broken: bool,
    }
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

    fn poll_write_payload_from_source<R>(
        self: Pin<&mut Self>,
        source: Pin<&mut R>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<PayloadWriteStatus>>
    where
        R: PayloadSource + ?Sized,
    {
        let this = self.project();
        if *this.write_closed {
            return Poll::Ready(Err(Error::WriteClosed));
        }

        match this.frame_writer.poll_write_payload_from_source(source, cx) {
            Poll::Ready(Err(err)) => {
                *this.broken = true;
                Poll::Ready(Err(err))
            }
            other => other,
        }
    }

    fn compact_buffers_for_reuse(&mut self) {
        self.frame_writer.compact_buffers_for_reuse();
        self.plain_batch.compact_for_reuse();
        self.pending_write_len = None;
    }
}

fn poll_reuse_read_tunnel_reply<R>(
    payload: &mut TcpPayloadReader<R>,
    reply_read: &mut bool,
    broken: &mut bool,
    cx: &mut Context<'_>,
) -> Poll<Result<()>>
where
    R: AsyncRead + Unpin,
{
    if *reply_read {
        return Poll::Ready(Ok(()));
    }

    match ready!(payload.poll_read_tunnel_reply(cx)) {
        Ok(()) => {
            *reply_read = true;
            Poll::Ready(Ok(()))
        }
        Err(err) => {
            *broken = true;
            Poll::Ready(Err(err))
        }
    }
}

fn poll_reuse_flush_payload<W>(
    frame_writer: &mut SnellStreamWriter<W>,
    plain_batch: &mut PlainReadBatch,
    pending_write_len: &mut Option<usize>,
    broken: &mut bool,
    cx: &mut Context<'_>,
) -> Poll<Result<()>>
where
    W: AsyncWrite + Unpin,
{
    match plain_batch.poll_flush_payload(frame_writer, cx) {
        Poll::Ready(Ok(())) => {
            *pending_write_len = None;
            Poll::Ready(Ok(()))
        }
        Poll::Ready(Err(err)) => {
            *broken = true;
            Poll::Ready(Err(err))
        }
        Poll::Pending => Poll::Pending,
    }
}

fn poll_reuse_write_payload<W>(
    frame_writer: &mut SnellStreamWriter<W>,
    plain_batch: &mut PlainReadBatch,
    pending_write_len: &mut Option<usize>,
    buf: &[u8],
    cx: &mut Context<'_>,
) -> Poll<Result<usize>>
where
    W: AsyncWrite + Unpin,
{
    if let Some(n) = *pending_write_len {
        ready!(plain_batch.poll_flush_payload(frame_writer, cx))?;
        *pending_write_len = None;
        return Poll::Ready(Ok(n));
    }

    ready!(plain_batch.poll_flush_payload(frame_writer, cx))?;
    if buf.is_empty() {
        return Poll::Ready(Ok(0));
    }

    let n = buf
        .len()
        .min(crate::transport::tcp::SERVER_PLAIN_READ_AHEAD_CAPACITY);
    plain_batch.buffer.extend_from_slice(&buf[..n]);
    *pending_write_len = Some(n);
    ready!(plain_batch.poll_flush_payload(frame_writer, cx))?;
    *pending_write_len = None;
    Poll::Ready(Ok(n))
}

fn poll_reuse_flush<W>(
    frame_writer: &mut SnellStreamWriter<W>,
    plain_batch: &mut PlainReadBatch,
    pending_write_len: &mut Option<usize>,
    broken: &mut bool,
    cx: &mut Context<'_>,
) -> Poll<Result<()>>
where
    W: AsyncWrite + Unpin,
{
    ready!(poll_reuse_flush_payload(
        frame_writer,
        plain_batch,
        pending_write_len,
        broken,
        cx
    ))?;
    frame_writer.poll_flush(cx)
}

fn poll_reuse_close_write<W>(
    frame_writer: &mut SnellStreamWriter<W>,
    plain_batch: &mut PlainReadBatch,
    pending_write_len: &mut Option<usize>,
    write_closed: &mut bool,
    broken: &mut bool,
    cx: &mut Context<'_>,
) -> Poll<Result<()>>
where
    W: AsyncWrite + Unpin,
{
    if !*write_closed {
        ready!(poll_reuse_flush_payload(
            frame_writer,
            plain_batch,
            pending_write_len,
            broken,
            cx
        ))?;
        match frame_writer.poll_write_zero_chunk(cx) {
            Poll::Ready(Ok(())) => *write_closed = true,
            Poll::Ready(Err(err)) => {
                *broken = true;
                return Poll::Ready(Err(err));
            }
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
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
        let this = self.project();
        if *this.write_closed {
            return Poll::Ready(Err(error_into_io(Error::WriteClosed)));
        }

        match poll_reuse_write_payload(
            this.frame_writer,
            this.plain_batch,
            this.pending_write_len,
            buf,
            cx,
        ) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(err)) => {
                *this.broken = true;
                Poll::Ready(Err(error_into_io(err)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        poll_result_into_io(poll_reuse_flush(
            this.frame_writer,
            this.plain_batch,
            this.pending_write_len,
            this.broken,
            cx,
        ))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        poll_result_into_io(poll_reuse_close_write(
            this.frame_writer,
            this.plain_batch,
            this.pending_write_len,
            this.write_closed,
            this.broken,
            cx,
        ))
    }
}

#[cfg(test)]
mod tests;

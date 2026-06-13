use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};
use crate::framed::{SnellStreamReader, SnellStreamWriter};
use crate::session::tcp::{PlainReadBatch, TcpPayloadReader};

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
    plain_batch: PlainReadBatch,
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
        std::future::poll_fn(|cx| self.plain_batch.poll_fill_from(plain, cx)).await?;
        match self
            .frame_writer
            .write_payload_message_from_buffer(&mut self.plain_batch.buffer)
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
        self.plain_batch.compact_for_reuse();
    }
}

#[cfg(test)]
mod tests;

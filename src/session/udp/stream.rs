use std::future::poll_fn;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::ProtocolVersion;
use crate::error::{Error, Result};
use crate::framed::{SnellStreamReader, SnellStreamWriter};
use crate::protocol::request::{ServerReply, parse_server_reply};

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
        let reader = SnellStreamReader::new(reader_io, psk, snell_version);
        Self::finish_open(reader, writer).await
    }

    async fn finish_open(
        mut reader: SnellStreamReader<R>,
        writer: SnellStreamWriter<W>,
    ) -> Result<Self> {
        poll_fn(|cx| poll_read_empty_tunnel_reply(&mut reader, cx)).await?;
        Ok(Self::from_parts(reader, writer))
    }

    fn from_parts(reader: SnellStreamReader<R>, writer: SnellStreamWriter<W>) -> Self {
        Self { reader, writer }
    }

    pub(crate) fn into_parts(self) -> (SnellStreamReader<R>, SnellStreamWriter<W>) {
        (self.reader, self.writer)
    }
}

fn poll_read_empty_tunnel_reply<R>(
    reader: &mut SnellStreamReader<R>,
    cx: &mut Context<'_>,
) -> Poll<Result<()>>
where
    R: AsyncRead + Unpin,
{
    let payload = ready!(reader.poll_read_frame_payload(cx))?;
    match parse_server_reply(payload)? {
        ServerReply::Tunnel { payload: [], .. } => Poll::Ready(Ok(())),
        ServerReply::Tunnel { .. } | ServerReply::Pong => {
            Poll::Ready(Err(Error::InvalidServerReply))
        }
        ServerReply::Error { code, message } => Poll::Ready(Err(Error::Server {
            code,
            message: message.to_owned(),
        })),
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
mod tests;

use std::{future::Future, io};

use compio::{
    buf::BufResult,
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use crate::protocol::{address::Address, snell::SnellMode};

use super::{
    client::SnellTransport,
    driver::{SnellStreamReader, SnellStreamWriter},
};

pub(crate) struct InboundRequest {
    pub destination: Address,
    pub reuse: bool,
}

pub(crate) trait Inbound {
    type Transport;

    async fn receive(&mut self) -> io::Result<InboundRequest>;
    async fn accept(&mut self) -> io::Result<()>;
    async fn reject(&mut self, error: &io::Error) -> io::Result<()>;
    fn into_transport(self) -> Self::Transport;
}

pub(crate) trait Outbound {
    type Transport;

    async fn connect(&self, destination: &Address) -> io::Result<Self::Transport>;
}

pub(crate) trait CopyBidirectional {
    type Peer;
    type Output;

    fn copy_bidirectional(self, peer: Self::Peer)
    -> impl Future<Output = io::Result<Self::Output>>;
}

pub(crate) fn copy_bidirectional<T>(
    transport: T,
    peer: T::Peer,
) -> impl Future<Output = io::Result<T::Output>>
where
    T: CopyBidirectional,
{
    transport.copy_bidirectional(peer)
}

impl<M> CopyBidirectional for SnellTransport<M>
where
    M: SnellMode + Unpin,
    M::Encoder: Unpin,
    M::Decoder: Unpin,
{
    type Peer = TcpStream;
    type Output = Self;

    async fn copy_bidirectional(self, peer: TcpStream) -> io::Result<Self> {
        let (peer_read, peer_write) = peer.into_split();
        let SnellTransport {
            mut reader,
            mut writer,
        } = self;

        futures::future::try_join(
            copy_plain_to_snell(&mut writer, peer_read),
            copy_snell_to_plain(&mut reader, peer_write),
        )
        .await?;

        Ok(SnellTransport { reader, writer })
    }
}

async fn copy_plain_to_snell<W, E, R>(
    writer: &mut SnellStreamWriter<W, E>,
    reader: R,
) -> io::Result<()>
where
    W: AsyncWrite + 'static,
    E: crate::protocol::snell::SnellTcpEncoder,
    R: AsyncRead + 'static,
{
    writer.write_from(reader).await
}

async fn copy_snell_to_plain<R, D, W>(
    reader: &mut SnellStreamReader<R, D>,
    mut writer: W,
) -> io::Result<()>
where
    R: AsyncRead + 'static,
    D: crate::protocol::snell::SnellTcpDecoder,
    W: AsyncWrite + 'static,
{
    while let Some(payload) = reader.read_frame_batch().await? {
        let ends_stream = payload.ends_stream();
        let BufResult(result, _payload) = writer.write_vectored_all(payload).await;
        result?;
        if ends_stream {
            writer.shutdown().await?;
            return Ok(());
        }
    }
    writer.shutdown().await
}

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use crate::protocol::{address::Address, snell::SnellMode};

use super::{
    client::SnellTransport,
    driver::{TcpTunnelReader, TcpTunnelWriter, WriteFromState},
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

pub(crate) trait Transport {
    type Peer;
    type Output;

    fn relay(self, peer: Self::Peer) -> impl Future<Output = io::Result<Self::Output>>;
}

#[derive(Debug)]
enum PlainState<R> {
    Copying(WriteFromState<R>),
    Done,
}

impl<R> Default for PlainState<R> {
    fn default() -> Self {
        Self::Copying(WriteFromState::default())
    }
}

#[derive(Debug, Default)]
enum TunnelState {
    #[default]
    Reading,
    Writing,
    ShuttingDown,
    Done,
}

impl<M> Transport for SnellTransport<M>
where
    M: SnellMode + Unpin,
    M::Encoder: Send + Unpin,
    M::Decoder: Send + Unpin,
    <M::Encoder as crate::protocol::snell::SnellTcpEncoder>::Reservation: Send + Unpin,
{
    type Peer = TcpStream;
    type Output = Self;

    fn relay(self, peer: TcpStream) -> impl Future<Output = io::Result<Self>> {
        let (peer_read, peer_write) = peer.into_split();
        SnellRelay {
            transport: Some(self),
            peer_read,
            peer_write,
            plain_state: PlainState::default(),
            tunnel_state: TunnelState::default(),
        }
    }
}

struct SnellRelay<M>
where
    M: SnellMode,
{
    transport: Option<SnellTransport<M>>,
    peer_read: tokio::net::tcp::OwnedReadHalf,
    peer_write: tokio::net::tcp::OwnedWriteHalf,
    plain_state: PlainState<<M::Encoder as crate::protocol::snell::SnellTcpEncoder>::Reservation>,
    tunnel_state: TunnelState,
}

impl<M> Future for SnellRelay<M>
where
    M: SnellMode + Unpin,
    M::Encoder: Send + Unpin,
    M::Decoder: Send + Unpin,
    <M::Encoder as crate::protocol::snell::SnellTcpEncoder>::Reservation: Send + Unpin,
{
    type Output = io::Result<SnellTransport<M>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let transport = this
            .transport
            .as_mut()
            .expect("snell relay polled after done");
        let mut pending = false;

        match poll_plain_to_snell(
            cx,
            &mut transport.writer,
            &mut this.peer_read,
            &mut this.plain_state,
        ) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => pending = true,
        }

        match poll_snell_to_plain(
            cx,
            &mut transport.reader,
            &mut this.peer_write,
            &mut this.tunnel_state,
        ) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => pending = true,
        }

        if pending {
            Poll::Pending
        } else {
            Poll::Ready(Ok(this.transport.take().expect("transport present")))
        }
    }
}

fn poll_plain_to_snell<W, E, R>(
    cx: &mut Context<'_>,
    writer: &mut TcpTunnelWriter<W, E>,
    plain_read: &mut R,
    state: &mut PlainState<E::Reservation>,
) -> Poll<io::Result<()>>
where
    W: AsyncWrite + Unpin,
    E: crate::protocol::snell::SnellTcpEncoder,
    R: AsyncRead + Unpin,
{
    loop {
        match state {
            PlainState::Copying(copy_state) => {
                match writer.poll_write_from(cx, plain_read, copy_state) {
                    Poll::Ready(Ok(true)) => continue,
                    Poll::Ready(Ok(false)) => {
                        *state = PlainState::Done;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            PlainState::Done => return Poll::Ready(Ok(())),
        }
    }
}

fn poll_snell_to_plain<R, D, W>(
    cx: &mut Context<'_>,
    reader: &mut TcpTunnelReader<R, D>,
    plain_write: &mut W,
    state: &mut TunnelState,
) -> Poll<io::Result<()>>
where
    R: AsyncRead + Unpin,
    D: crate::protocol::snell::SnellTcpDecoder,
    W: AsyncWrite + Unpin,
{
    loop {
        match state {
            TunnelState::Reading => match reader.poll_read_next_plain(cx) {
                Poll::Ready(Ok(true)) => *state = TunnelState::Writing,
                Poll::Ready(Ok(false)) => *state = TunnelState::ShuttingDown,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            },
            TunnelState::Writing => match reader.poll_write_pending_plaintext_to(cx, plain_write) {
                Poll::Ready(Ok(0)) => *state = TunnelState::Reading,
                Poll::Ready(Ok(_)) => continue,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            },
            TunnelState::ShuttingDown => match Pin::new(&mut *plain_write).poll_shutdown(cx) {
                Poll::Ready(Ok(())) => {
                    *state = TunnelState::Done;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            },
            TunnelState::Done => return Poll::Ready(Ok(())),
        }
    }
}

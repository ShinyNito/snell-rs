use std::{
    future::{Future, poll_fn},
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
    driver::{SnellStreamReader, SnellStreamWriter, WriteFromState},
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

impl<M> CopyBidirectional for SnellTransport<M>
where
    M: SnellMode + Unpin,
    M::Encoder: Send + Unpin,
    M::Decoder: Send + Unpin,
    <M::Encoder as crate::protocol::snell::SnellTcpEncoder>::Reservation: Send,
{
    type Peer = TcpStream;
    type Output = Self;

    fn copy_bidirectional(self, peer: TcpStream) -> impl Future<Output = io::Result<Self>> {
        let (mut peer_read, mut peer_write) = peer.into_split();
        let mut transport = Some(self);
        let mut plain_state = PlainState::default();
        let mut tunnel_state = TunnelState::default();

        poll_fn(move |cx| {
            let transport_ref = transport
                .as_mut()
                .expect("snell transport polled after done");
            let mut pending = false;

            match poll_plain_to_snell(
                cx,
                &mut transport_ref.writer,
                &mut peer_read,
                &mut plain_state,
            ) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => pending = true,
            }

            match poll_snell_to_plain(
                cx,
                &mut transport_ref.reader,
                &mut peer_write,
                &mut tunnel_state,
            ) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => pending = true,
            }

            if pending {
                Poll::Pending
            } else {
                Poll::Ready(Ok(transport.take().expect("transport present")))
            }
        })
    }
}

fn poll_plain_to_snell<W, E, R>(
    cx: &mut Context<'_>,
    writer: &mut SnellStreamWriter<W, E>,
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
    reader: &mut SnellStreamReader<R, D>,
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

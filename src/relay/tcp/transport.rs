use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use compio::{
    buf::BufResult,
    io::{AsyncReadManaged, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use crate::protocol::{address::Address, snell::SnellMode};

use super::{
    client::SnellTransport,
    driver::{SnellStreamReader, SnellStreamWriter, WriteFromState},
};

type PlainWriteFuture<W> = Pin<Box<dyn Future<Output = (W, BufResult<(), Vec<u8>>)>>>;
type ShutdownFuture<W> = Pin<Box<dyn Future<Output = (W, io::Result<()>)>>>;

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

enum PlainState<R: AsyncReadManaged, Reservation> {
    Copying(WriteFromState<R, Reservation>),
    Done,
}

impl<R, Reservation> PlainState<R, Reservation>
where
    R: AsyncReadManaged,
{
    fn new(reader: R) -> Self {
        Self::Copying(WriteFromState::new(reader))
    }
}

enum TunnelState<W> {
    Reading(Option<W>),
    Writing(PlainWriteFuture<W>),
    ShuttingDown(ShutdownFuture<W>),
    Done,
}

impl<W> TunnelState<W> {
    fn new(writer: W) -> Self {
        Self::Reading(Some(writer))
    }

    fn take_writer(&mut self) -> W {
        match self {
            Self::Reading(writer) => writer.take().expect("plain writer missing"),
            Self::Writing(_) | Self::ShuttingDown(_) | Self::Done => {
                unreachable!("plain writer is busy")
            }
        }
    }
}

impl<W> TunnelState<W>
where
    W: AsyncWrite + 'static,
{
    fn start_write(&mut self, payload: Vec<u8>) {
        let mut writer = self.take_writer();
        let future = Box::pin(async move {
            let result = writer.write_all(payload).await;
            (writer, result)
        });
        *self = Self::Writing(future);
    }

    fn start_shutdown(&mut self) {
        let mut writer = self.take_writer();
        let future = Box::pin(async move {
            let result = writer.shutdown().await;
            (writer, result)
        });
        *self = Self::ShuttingDown(future);
    }
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
        let (peer_read, peer_write) = peer.into_split();
        let mut transport = Some(self);
        let mut plain_state = PlainState::new(peer_read);
        let mut tunnel_state = TunnelState::new(peer_write);
        let mut tunnel_buf = Vec::new();

        poll_fn(move |cx| {
            let transport_ref = transport
                .as_mut()
                .expect("snell transport polled after done");
            let mut pending = false;

            match poll_plain_to_snell(cx, &mut transport_ref.writer, &mut plain_state) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => pending = true,
            }

            match poll_snell_to_plain(
                cx,
                &mut transport_ref.reader,
                &mut tunnel_state,
                &mut tunnel_buf,
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
    state: &mut PlainState<R, E::Reservation>,
) -> Poll<io::Result<()>>
where
    W: AsyncWrite + 'static,
    E: crate::protocol::snell::SnellTcpEncoder,
    R: AsyncReadManaged + 'static,
    R::Buffer: 'static,
{
    loop {
        match state {
            PlainState::Copying(copy_state) => match writer.poll_write_from(cx, copy_state) {
                Poll::Ready(Ok(true)) => continue,
                Poll::Ready(Ok(false)) => {
                    *state = PlainState::Done;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            },
            PlainState::Done => return Poll::Ready(Ok(())),
        }
    }
}

fn poll_snell_to_plain<R, D, W>(
    cx: &mut Context<'_>,
    reader: &mut SnellStreamReader<R, D>,
    state: &mut TunnelState<W>,
    buf: &mut Vec<u8>,
) -> Poll<io::Result<()>>
where
    R: AsyncReadManaged + 'static,
    R::Buffer: 'static,
    D: crate::protocol::snell::SnellTcpDecoder,
    W: AsyncWrite + 'static,
{
    loop {
        match state {
            TunnelState::Reading(_) => match reader.poll_read_frame_vec(cx, buf) {
                Poll::Ready(Ok(true)) => {
                    let payload = std::mem::take(buf);
                    state.start_write(payload);
                }
                Poll::Ready(Ok(false)) => state.start_shutdown(),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            },
            TunnelState::Writing(future) => {
                let (writer, BufResult(result, _payload)) = ready!(future.as_mut().poll(cx));
                *state = TunnelState::Reading(Some(writer));
                result?;
            }
            TunnelState::ShuttingDown(future) => {
                let (_writer, result) = ready!(future.as_mut().poll(cx));
                result?;
                *state = TunnelState::Done;
                return Poll::Ready(Ok(()));
            }
            TunnelState::Done => return Poll::Ready(Ok(())),
        }
    }
}

use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use compio::{
    buf::BufResult,
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use crate::protocol::{address::Address, snell::SnellMode};

use super::{
    client::SnellTransport,
    driver::{PlaintextBatch, SnellStreamReader, SnellStreamWriter, WriteFromState},
};

type PlainWriteFuture<W> = Pin<Box<dyn Future<Output = (W, BufResult<(), PlaintextBatch>)>>>;
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

enum PlainState<R: AsyncRead> {
    Copying(WriteFromState<R>),
    Done,
}

impl<R> PlainState<R>
where
    R: AsyncRead,
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
    fn start_write(&mut self, payload: PlaintextBatch) {
        let mut writer = self.take_writer();
        let future = Box::pin(async move {
            let result = writer.write_vectored_all(payload).await;
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
    M::Encoder: Unpin,
    M::Decoder: Unpin,
{
    type Peer = TcpStream;
    type Output = Self;

    fn copy_bidirectional(self, peer: TcpStream) -> impl Future<Output = io::Result<Self>> {
        let (peer_read, peer_write) = peer.into_split();
        let mut transport = Some(self);
        let mut plain_state = PlainState::new(peer_read);
        let mut tunnel_state = TunnelState::new(peer_write);

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

            match poll_snell_to_plain(cx, &mut transport_ref.reader, &mut tunnel_state) {
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
    state: &mut PlainState<R>,
) -> Poll<io::Result<()>>
where
    W: AsyncWrite + 'static,
    E: crate::protocol::snell::SnellTcpEncoder,
    R: AsyncRead + 'static,
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
) -> Poll<io::Result<()>>
where
    R: AsyncRead + 'static,
    D: crate::protocol::snell::SnellTcpDecoder,
    W: AsyncWrite + 'static,
{
    loop {
        match state {
            TunnelState::Reading(_) => match reader.poll_read_frame_batch(cx) {
                Poll::Ready(Ok(Some(payload))) => state.start_write(payload),
                Poll::Ready(Ok(None)) => state.start_shutdown(),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            },
            TunnelState::Writing(future) => {
                let (writer, BufResult(result, payload)) = ready!(future.as_mut().poll(cx));
                *state = TunnelState::Reading(Some(writer));
                result?;
                if payload.ends_stream() {
                    state.start_shutdown();
                }
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

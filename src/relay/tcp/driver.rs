use std::{
    future::{Future, poll_fn},
    io,
    io::IoSlice,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use compio::{
    buf::BufResult,
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
};

use crate::protocol::snell::{
    DecodeEvent, DecodeSlot, PlainPrefix, SnellMode, SnellTcpDecoder, SnellTcpEncoder,
};

type ReadFuture<R> = Pin<Box<dyn Future<Output = (R, BufResult<usize, Vec<u8>>)>>>;
type WriteVectoredFuture<W> = Pin<Box<dyn Future<Output = (W, BufResult<(), Vec<Vec<u8>>>)>>>;
type FlushFuture<W> = Pin<Box<dyn Future<Output = (W, io::Result<()>)>>>;

pub struct SnellStreamReader<R, D> {
    inner: ReaderIo<R>,
    decoder: D,
}

pub struct SnellStreamWriter<W, E> {
    inner: WriterIo<W>,
    encoder: E,
}

enum ReaderIo<R> {
    Idle(Option<R>),
    Reading(ReadFuture<R>),
}

enum WriterIo<W> {
    Idle(Option<W>),
    Writing {
        advance: usize,
        future: WriteVectoredFuture<W>,
    },
    Flushing(FlushFuture<W>),
}

pub(crate) enum WriteFromState<R, Reservation> {
    Reading {
        reader: Option<R>,
        reservation: Option<Reservation>,
    },
    ReadPending {
        reservation: Reservation,
        future: ReadFuture<R>,
    },
    Flushing {
        reader: Option<R>,
        eof: bool,
    },
    Done,
}

#[derive(Debug, Default)]
pub(crate) enum WriteFrameState {
    #[default]
    Encoding,
    Flushing,
}

impl<R, Reservation> WriteFromState<R, Reservation> {
    pub(crate) fn new(reader: R) -> Self {
        Self::Reading {
            reader: Some(reader),
            reservation: None,
        }
    }
}

impl<R> ReaderIo<R> {
    fn new(inner: R) -> Self {
        Self::Idle(Some(inner))
    }

    fn take_idle(&mut self) -> R {
        match self {
            Self::Idle(inner) => inner.take().expect("reader io missing"),
            Self::Reading(_) => unreachable!("reader io is busy"),
        }
    }
}

impl<R> ReaderIo<R>
where
    R: AsyncRead + 'static,
{
    fn start_read(&mut self, len: usize) {
        let mut inner = self.take_idle();
        let future = Box::pin(async move {
            let result = inner.read(Vec::with_capacity(len)).await;
            (inner, result)
        });
        *self = Self::Reading(future);
    }
}

impl<W> WriterIo<W> {
    fn new(inner: W) -> Self {
        Self::Idle(Some(inner))
    }

    fn take_idle(&mut self) -> W {
        match self {
            Self::Idle(inner) => inner.take().expect("writer io missing"),
            Self::Writing { .. } | Self::Flushing(_) => unreachable!("writer io is busy"),
        }
    }
}

impl<W> WriterIo<W>
where
    W: AsyncWrite + 'static,
{
    fn start_write_vectored_all(&mut self, buf: Vec<Vec<u8>>, advance: usize) {
        let mut inner = self.take_idle();
        let future = Box::pin(async move {
            let result = inner.write_vectored_all(buf).await;
            (inner, result)
        });
        *self = Self::Writing { advance, future };
    }

    fn start_flush(&mut self) {
        let mut inner = self.take_idle();
        let future = Box::pin(async move {
            let result = inner.flush().await;
            (inner, result)
        });
        *self = Self::Flushing(future);
    }
}

impl<R, D> SnellStreamReader<R, D>
where
    R: AsyncRead + 'static,
    D: SnellTcpDecoder,
{
    pub fn new<M>(inner: R, psk: Arc<[u8]>) -> Self
    where
        M: SnellMode<Decoder = D>,
    {
        Self {
            inner: ReaderIo::new(inner),
            decoder: M::new_decoder(psk),
        }
    }

    pub(crate) fn from_decoder(inner: R, decoder: D) -> Self {
        Self {
            inner: ReaderIo::new(inner),
            decoder,
        }
    }

    pub(crate) fn poll_read_frame_vec(
        &mut self,
        cx: &mut Context<'_>,
        dst: &mut Vec<u8>,
    ) -> Poll<io::Result<bool>> {
        dst.clear();
        if !self.decoder.has_pending_plaintext() && !ready!(self.poll_read_frame(cx))? {
            return Poll::Ready(Ok(false));
        }

        while self.decoder.has_pending_plaintext() {
            let copied = self.copy_pending_plaintext_to_vec(dst);
            if copied == 0 {
                break;
            }
        }
        Poll::Ready(Ok(true))
    }

    pub(crate) fn poll_drain_frame_plaintext_with<F>(
        &mut self,
        cx: &mut Context<'_>,
        f: F,
    ) -> Poll<io::Result<bool>>
    where
        F: FnOnce(&mut Context<'_>, &[u8]) -> Poll<io::Result<()>>,
    {
        if !self.decoder.has_pending_plaintext() && !ready!(self.poll_read_frame(cx))? {
            return Poll::Ready(Ok(false));
        }

        let (plain_len, result) = {
            let mut bufs = [IoSlice::new(&[]); 4];
            let nbufs = self.decoder.pending_plaintext(&mut bufs);
            if nbufs == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snell decoder produced no plaintext",
                )));
            }
            if nbufs != 1 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "snell decoder produced fragmented plaintext",
                )));
            }
            let plain = &bufs[0];
            (plain.len(), f(cx, plain))
        };

        match result {
            Poll::Ready(Ok(())) => {
                self.decoder.advance_plaintext(plain_len);
                Poll::Ready(Ok(true))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    pub async fn read_exact_plain(&mut self, dst: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < dst.len() {
            let copied = self.copy_pending_plaintext(&mut dst[filled..]);
            if copied != 0 {
                filled += copied;
                continue;
            }

            if !poll_fn(|cx| self.poll_read_frame(cx)).await? {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell zero chunk while reading control data",
                ));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn read_frame_vec(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut out = Vec::new();
        if poll_fn(|cx| self.poll_read_frame_vec(cx, &mut out)).await? {
            Ok(Some(out))
        } else {
            Ok(None)
        }
    }

    fn poll_read_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            match self.decoder.next_ciphertext_slot() {
                DecodeSlot::Read(slot) => {
                    if matches!(self.inner, ReaderIo::Idle(_)) {
                        self.inner.start_read(slot.len());
                    }
                }
                DecodeSlot::BlockedByPlaintext => return Poll::Ready(Ok(true)),
            }

            let (inner, BufResult(result, buf)) = match &mut self.inner {
                ReaderIo::Idle(_) => continue,
                ReaderIo::Reading(future) => ready!(future.as_mut().poll(cx)),
            };
            self.inner = ReaderIo::Idle(Some(inner));

            let n = result?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "early eof",
                )));
            }

            match self.decoder.next_ciphertext_slot() {
                DecodeSlot::Read(slot) => slot[..n].copy_from_slice(&buf[..n]),
                DecodeSlot::BlockedByPlaintext => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "snell decoder blocked after socket read",
                    )));
                }
            }

            match self.decoder.commit_ciphertext(n)? {
                DecodeEvent::PlainData => return Poll::Ready(Ok(true)),
                DecodeEvent::ZeroChunk => return Poll::Ready(Ok(false)),
                _ => continue,
            }
        }
    }

    fn copy_pending_plaintext(&mut self, dst: &mut [u8]) -> usize {
        let mut bufs = [IoSlice::new(&[]); 4];
        let nbufs = self.decoder.pending_plaintext(&mut bufs);
        let mut copied = 0;
        for buf in &bufs[..nbufs] {
            if copied == dst.len() {
                break;
            }
            let take = (dst.len() - copied).min(buf.len());
            dst[copied..copied + take].copy_from_slice(&buf[..take]);
            copied += take;
        }
        self.decoder.advance_plaintext(copied);
        copied
    }

    fn copy_pending_plaintext_to_vec(&mut self, dst: &mut Vec<u8>) -> usize {
        let mut bufs = [IoSlice::new(&[]); 4];
        let nbufs = self.decoder.pending_plaintext(&mut bufs);
        let copied = bufs[..nbufs].iter().map(|buf| buf.len()).sum();
        for buf in &bufs[..nbufs] {
            dst.extend_from_slice(buf);
        }
        self.decoder.advance_plaintext(copied);
        copied
    }
}

impl<W, E> SnellStreamWriter<W, E>
where
    W: AsyncWrite + 'static,
    E: SnellTcpEncoder,
{
    pub fn new<M>(inner: W, psk: Arc<[u8]>) -> io::Result<Self>
    where
        M: SnellMode<Encoder = E>,
    {
        Ok(Self {
            inner: WriterIo::new(inner),
            encoder: M::new_encoder(&psk)?,
        })
    }

    pub async fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.is_empty() {
            self.write_one_frame(payload).await?;
            return Ok(());
        }

        let mut offset = 0;
        while offset < payload.len() {
            let written = self.write_one_frame(&payload[offset..]).await?;
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell encoder accepted no payload",
                ));
            }
            offset += written;
        }
        Ok(())
    }

    pub(crate) fn poll_write_from<R>(
        &mut self,
        cx: &mut Context<'_>,
        state: &mut WriteFromState<R, E::Reservation>,
    ) -> Poll<io::Result<bool>>
    where
        R: AsyncRead + 'static,
    {
        loop {
            match state {
                WriteFromState::Reading {
                    reader,
                    reservation,
                } => {
                    if reservation.is_none() {
                        *reservation = Some(
                            self.encoder
                                .begin_plain_reservation(PlainPrefix::none(), usize::MAX)?,
                        );
                    }

                    let reservation_ref = reservation.as_ref().expect("reservation just created");
                    let slot_len = self.encoder.plain_slot(reservation_ref).len();
                    let mut plain_read = reader.take().expect("plain reader missing");
                    let reservation = reservation.take().expect("reservation just created");
                    let future = Box::pin(async move {
                        let result = plain_read.read(Vec::with_capacity(slot_len)).await;
                        (plain_read, result)
                    });
                    *state = WriteFromState::ReadPending {
                        reservation,
                        future,
                    };
                }
                WriteFromState::ReadPending { future, .. } => {
                    let (reader, BufResult(result, buf)) = ready!(future.as_mut().poll(cx));
                    let old_state = std::mem::replace(state, WriteFromState::Done);
                    let reservation = match old_state {
                        WriteFromState::ReadPending { reservation, .. } => reservation,
                        _ => unreachable!("write-from state changed while polling"),
                    };

                    let n = match result {
                        Ok(n) => n,
                        Err(error) => {
                            self.encoder.cancel_plain_reservation(reservation);
                            *state = WriteFromState::Reading {
                                reader: Some(reader),
                                reservation: None,
                            };
                            return Poll::Ready(Err(error));
                        }
                    };
                    self.encoder.plain_slot(&reservation)[..n].copy_from_slice(&buf[..n]);
                    self.encoder.finish_plain_reservation(reservation, n)?;
                    *state = WriteFromState::Flushing {
                        reader: Some(reader),
                        eof: n == 0,
                    };
                }
                WriteFromState::Flushing { reader, eof } => {
                    ready!(self.poll_drain_pending(cx))?;
                    let reader = reader.take().expect("plain reader missing");
                    if *eof {
                        *state = WriteFromState::Done;
                        return Poll::Ready(Ok(false));
                    }
                    *state = WriteFromState::Reading {
                        reader: Some(reader),
                        reservation: None,
                    };
                    return Poll::Ready(Ok(true));
                }
                WriteFromState::Done => return Poll::Ready(Ok(false)),
            }
        }
    }

    pub(crate) fn poll_write_frame(
        &mut self,
        cx: &mut Context<'_>,
        payload: &[u8],
        state: &mut WriteFrameState,
    ) -> Poll<io::Result<()>> {
        loop {
            match state {
                WriteFrameState::Encoding => {
                    let reservation = self
                        .encoder
                        .begin_plain_reservation(PlainPrefix::none(), payload.len())?;
                    let slot = self.encoder.plain_slot(&reservation);
                    if payload.len() > slot.len() {
                        self.encoder.cancel_plain_reservation(reservation);
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "snell udp packet is larger than one frame",
                        )));
                    }
                    slot[..payload.len()].copy_from_slice(payload);
                    self.encoder
                        .finish_plain_reservation(reservation, payload.len())?;
                    *state = WriteFrameState::Flushing;
                }
                WriteFrameState::Flushing => {
                    ready!(self.poll_drain_pending(cx))?;
                    *state = WriteFrameState::Encoding;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }

    pub async fn write_with<F>(&mut self, hint: usize, fill: F) -> io::Result<()>
    where
        F: FnOnce(&mut [u8]) -> io::Result<usize>,
    {
        let reservation = self
            .encoder
            .begin_plain_reservation(PlainPrefix::none(), hint)?;
        let n = fill(self.encoder.plain_slot(&reservation))?;
        self.encoder.finish_plain_reservation(reservation, n)?;
        self.drain_pending().await
    }

    async fn write_one_frame(&mut self, payload: &[u8]) -> io::Result<usize> {
        let reservation = self
            .encoder
            .begin_plain_reservation(PlainPrefix::none(), payload.len())?;
        let n = {
            let slot = self.encoder.plain_slot(&reservation);
            let n = payload.len().min(slot.len());
            slot[..n].copy_from_slice(&payload[..n]);
            n
        };
        self.encoder.finish_plain_reservation(reservation, n)?;
        self.drain_pending().await?;
        Ok(n)
    }

    async fn drain_pending(&mut self) -> io::Result<()> {
        poll_fn(|cx| self.poll_drain_pending(cx)).await
    }

    fn poll_drain_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match &mut self.inner {
                WriterIo::Idle(_) => {
                    if self.encoder.has_pending_wire() {
                        let mut pending = [IoSlice::new(&[]); 5];
                        let nbufs = self.encoder.pending_wire(&mut pending);
                        let mut wire = Vec::with_capacity(nbufs);
                        for slice in &pending[..nbufs] {
                            if !slice.is_empty() {
                                wire.push(slice.to_vec());
                            }
                        }
                        let len = wire.iter().map(Vec::len).sum();
                        self.inner.start_write_vectored_all(wire, len);
                        continue;
                    }
                    self.inner.start_flush();
                }
                WriterIo::Writing { advance, future } => {
                    let advance = *advance;
                    let (inner, BufResult(result, _buf)) = ready!(future.as_mut().poll(cx));
                    self.inner = WriterIo::Idle(Some(inner));
                    result?;
                    self.encoder.advance_wire(advance);
                }
                WriterIo::Flushing(future) => {
                    let (inner, result) = ready!(future.as_mut().poll(cx));
                    self.inner = WriterIo::Idle(Some(inner));
                    return Poll::Ready(result);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::snell::{V4Decoder, V4Encoder, V4Mode};
    use compio::net::{TcpListener, TcpStream};

    #[compio::test]
    async fn round_trips_payload_and_zero_chunk() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let (client, server) = tcp_pair().await;
        let (server_read, _) = server.into_split();
        let (_, client_write) = client.into_split();
        let mut writer: SnellStreamWriter<_, V4Encoder> =
            SnellStreamWriter::new::<V4Mode>(client_write, psk.clone()).unwrap();
        let mut reader: SnellStreamReader<_, V4Decoder> =
            SnellStreamReader::new::<V4Mode>(server_read, psk);

        writer.write_frame(b"hello").await.unwrap();
        writer.write_frame(&[]).await.unwrap();

        let payload = reader.read_frame_vec().await.unwrap().unwrap();
        assert_eq!(payload, b"hello");
        assert!(reader.read_frame_vec().await.unwrap().is_none());
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) =
            futures::future::try_join(TcpStream::connect(addr), listener.accept())
                .await
                .unwrap();
        let (server, _) = accepted;
        (client, server)
    }
}

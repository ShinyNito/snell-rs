use std::{
    future::{Future, poll_fn},
    io,
    io::IoSlice,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use compio::{
    buf::{BufResult, IoBuf, IoVectoredBuf},
    io::{AsyncReadManaged, AsyncWrite, AsyncWriteExt},
};

use crate::protocol::snell::{
    DecodeEvent, PendingWire, PlainPrefix, SnellMode, SnellTcpDecoder, SnellTcpEncoder,
};

type ReadOne<R> = Option<ReadBuffer<<R as AsyncReadManaged>::Buffer>>;
type ReadFuture<R> = Pin<Box<dyn Future<Output = (R, io::Result<ReadOne<R>>)>>>;
type WriteVectoredFuture<W> = Pin<Box<dyn Future<Output = (W, BufResult<(), PendingWire>)>>>;
type FlushFuture<W> = Pin<Box<dyn Future<Output = (W, io::Result<()>)>>>;

pub struct SnellStreamReader<R: AsyncReadManaged, D> {
    inner: ReaderIo<R>,
    pending_probe_ciphertext: Option<ReadBuffer<Vec<u8>>>,
    pending_ciphertext: ReadOne<R>,
    decoder: D,
}

pub struct SnellStreamWriter<W, E> {
    inner: WriterIo<W>,
    encoder: E,
}

enum ReaderIo<R: AsyncReadManaged> {
    Idle(Option<R>),
    Reading(ReadFuture<R>),
}

enum WriterIo<W> {
    Idle(Option<W>),
    Writing(WriteVectoredFuture<W>),
    Flushing(FlushFuture<W>),
}

pub(crate) enum WriteFromState<R: AsyncReadManaged, Reservation> {
    Reading {
        reader: Option<R>,
        reservation: Option<Reservation>,
        pending: ReadOne<R>,
    },
    ReadPending {
        reservation: Reservation,
        future: ReadFuture<R>,
    },
    Flushing {
        reader: Option<R>,
        eof: bool,
        pending: ReadOne<R>,
    },
    Done,
}

#[derive(Debug, Default)]
pub(crate) enum WriteFrameState {
    #[default]
    Encoding,
    Flushing,
}

impl<R, Reservation> WriteFromState<R, Reservation>
where
    R: AsyncReadManaged,
{
    pub(crate) fn new(reader: R) -> Self {
        Self::Reading {
            reader: Some(reader),
            reservation: None,
            pending: None,
        }
    }
}

impl<R> ReaderIo<R>
where
    R: AsyncReadManaged,
{
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
    R: AsyncReadManaged + 'static,
    R::Buffer: 'static,
{
    fn start_read(&mut self) {
        let inner = self.take_idle();
        let future = Box::pin(read_one(inner));
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
            Self::Writing(_) | Self::Flushing(_) => unreachable!("writer io is busy"),
        }
    }
}

impl<W> WriterIo<W>
where
    W: AsyncWrite + 'static,
{
    fn start_write_vectored_all(&mut self, wire: PendingWire) {
        let mut inner = self.take_idle();
        let future = Box::pin(async move {
            let result = inner.write_vectored_all(wire).await;
            (inner, result)
        });
        *self = Self::Writing(future);
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

impl IoVectoredBuf for PendingWire {
    fn iter_slice(&self) -> impl Iterator<Item = &[u8]> {
        self.iter_slices()
    }
}

impl<R, D> SnellStreamReader<R, D>
where
    R: AsyncReadManaged + 'static,
    R::Buffer: 'static,
    D: SnellTcpDecoder,
{
    pub fn new<M>(inner: R, psk: Arc<[u8]>) -> Self
    where
        M: SnellMode<Decoder = D>,
    {
        Self {
            inner: ReaderIo::new(inner),
            pending_probe_ciphertext: None,
            pending_ciphertext: None,
            decoder: M::new_decoder(psk),
        }
    }

    pub(crate) fn from_decoder_with_pending_ciphertext(
        inner: R,
        decoder: D,
        pending_ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            inner: ReaderIo::new(inner),
            pending_probe_ciphertext: (!pending_ciphertext.is_empty())
                .then(|| ReadBuffer::new(pending_ciphertext)),
            pending_ciphertext: None,
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
            if self.decoder.has_pending_plaintext() {
                return Poll::Ready(Ok(true));
            }

            if self.pending_probe_ciphertext.is_some() {
                let event = {
                    let read = self
                        .pending_probe_ciphertext
                        .as_mut()
                        .expect("pending checked");
                    decode_from_buffer(&mut self.decoder, read)?
                };
                if self
                    .pending_probe_ciphertext
                    .as_ref()
                    .is_some_and(ReadBuffer::is_empty)
                {
                    self.pending_probe_ciphertext = None;
                }

                match event {
                    DecodeEvent::PlainData => return Poll::Ready(Ok(true)),
                    DecodeEvent::ZeroChunk => return Poll::Ready(Ok(false)),
                    _ => continue,
                }
            }

            if self.pending_ciphertext.is_some() {
                let event = decode_from_buffer(
                    &mut self.decoder,
                    self.pending_ciphertext.as_mut().expect("pending checked"),
                )?;
                if self
                    .pending_ciphertext
                    .as_ref()
                    .is_some_and(ReadBuffer::is_empty)
                {
                    self.pending_ciphertext = None;
                }

                match event {
                    DecodeEvent::PlainData => return Poll::Ready(Ok(true)),
                    DecodeEvent::ZeroChunk => return Poll::Ready(Ok(false)),
                    _ => continue,
                }
            }

            if matches!(self.inner, ReaderIo::Idle(_)) {
                self.inner.start_read();
            }

            let (inner, result) = match &mut self.inner {
                ReaderIo::Idle(_) => continue,
                ReaderIo::Reading(future) => ready!(future.as_mut().poll(cx)),
            };
            self.inner = ReaderIo::Idle(Some(inner));

            self.pending_ciphertext = result?;
            if self.pending_ciphertext.is_none() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "early eof",
                )));
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

fn decode_from_buffer<'a, D, B>(
    decoder: &'a mut D,
    read: &mut ReadBuffer<B>,
) -> io::Result<DecodeEvent<'a>>
where
    D: SnellTcpDecoder,
    B: IoBuf,
{
    let before = read.remaining().len();
    let mut src = read.remaining();
    let event = decoder.decode_ciphertext(&mut src)?;
    read.advance(before - src.len());
    Ok(event)
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
        R: AsyncReadManaged + 'static,
        R::Buffer: 'static,
    {
        loop {
            match state {
                WriteFromState::Reading {
                    reader,
                    reservation,
                    pending,
                } => {
                    if reservation.is_none() {
                        *reservation = Some(
                            self.encoder
                                .begin_plain_reservation(PlainPrefix::none(), usize::MAX)?,
                        );
                    }

                    let reservation_ref = reservation.as_ref().expect("reservation just created");
                    let slot_len = self.encoder.plain_slot(reservation_ref).len();

                    if let Some(read) = pending.as_mut() {
                        let n = {
                            let src = read.remaining();
                            let n = slot_len.min(src.len());
                            self.encoder.plain_slot(reservation_ref)[..n]
                                .copy_from_slice(&src[..n]);
                            n
                        };
                        read.advance(n);
                        if read.is_empty() {
                            *pending = None;
                        }
                        let reservation = reservation.take().expect("reservation just created");
                        self.encoder.finish_plain_reservation(reservation, n)?;
                        *state = WriteFromState::Flushing {
                            reader: reader.take(),
                            eof: false,
                            pending: pending.take(),
                        };
                        continue;
                    }

                    let plain_read = reader.take().expect("plain reader missing");
                    let reservation = reservation.take().expect("reservation just created");
                    let future = Box::pin(read_one(plain_read));
                    *state = WriteFromState::ReadPending {
                        reservation,
                        future,
                    };
                }
                WriteFromState::ReadPending { future, .. } => {
                    let (reader, result) = ready!(future.as_mut().poll(cx));
                    let old_state = std::mem::replace(state, WriteFromState::Done);
                    let reservation = match old_state {
                        WriteFromState::ReadPending { reservation, .. } => reservation,
                        _ => unreachable!("write-from state changed while polling"),
                    };

                    let mut pending = match result {
                        Ok(pending) => pending,
                        Err(error) => {
                            self.encoder.cancel_plain_reservation(reservation);
                            *state = WriteFromState::Reading {
                                reader: Some(reader),
                                reservation: None,
                                pending: None,
                            };
                            return Poll::Ready(Err(error));
                        }
                    };

                    let n = if let Some(read) = pending.as_mut() {
                        let slot_len = self.encoder.plain_slot(&reservation).len();
                        let src = read.remaining();
                        let n = slot_len.min(src.len());
                        self.encoder.plain_slot(&reservation)[..n].copy_from_slice(&src[..n]);
                        read.advance(n);
                        if read.is_empty() {
                            pending = None;
                        }
                        n
                    } else {
                        0
                    };
                    self.encoder.finish_plain_reservation(reservation, n)?;
                    *state = WriteFromState::Flushing {
                        reader: Some(reader),
                        eof: n == 0,
                        pending,
                    };
                }
                WriteFromState::Flushing {
                    reader,
                    eof,
                    pending,
                } => {
                    ready!(self.poll_drain_pending(cx))?;
                    let reader = reader.take().expect("plain reader missing");
                    if *eof {
                        *state = WriteFromState::Done;
                        return Poll::Ready(Ok(false));
                    }
                    *state = WriteFromState::Reading {
                        reader: Some(reader),
                        reservation: None,
                        pending: std::mem::take(pending),
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
                        let wire = self.encoder.take_pending_wire();
                        if !wire.is_empty() {
                            self.inner.start_write_vectored_all(wire);
                        }
                        continue;
                    }
                    self.inner.start_flush();
                }
                WriterIo::Writing(future) => {
                    let (inner, BufResult(result, wire)) = ready!(future.as_mut().poll(cx));
                    self.inner = WriterIo::Idle(Some(inner));
                    if let Err(error) = result {
                        self.encoder.restore_pending_wire(wire);
                        return Poll::Ready(Err(error));
                    }
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

pub(crate) struct ReadBuffer<B> {
    buf: B,
    offset: usize,
}

impl<B> ReadBuffer<B>
where
    B: IoBuf,
{
    fn new(buf: B) -> Self {
        Self { buf, offset: 0 }
    }

    fn remaining(&self) -> &[u8] {
        &self.buf.as_init()[self.offset..]
    }

    fn advance(&mut self, n: usize) {
        self.offset += n;
    }

    fn is_empty(&self) -> bool {
        self.offset == self.buf.as_init().len()
    }
}

async fn read_one<R>(mut reader: R) -> (R, io::Result<ReadOne<R>>)
where
    R: AsyncReadManaged + 'static,
    R::Buffer: 'static,
{
    let result = reader
        .read_managed(0)
        .await
        .map(|buf| buf.map(ReadBuffer::new));
    (reader, result)
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

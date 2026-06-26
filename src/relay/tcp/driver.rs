use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    io,
    io::IoSlice,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::BytesMut;
use compio::{
    buf::{BufResult, IoBuf, IoBufMut, IoVectoredBuf},
    io::{AsyncRead, AsyncReadManaged, AsyncWrite, AsyncWriteExt},
};

use crate::protocol::snell::{
    DecodeEvent, PendingWire, PendingWireSegment, PlaintextFrame, PlaintextSegment, SnellMode,
    SnellTcpDecoder, SnellTcpEncoder,
};

type ReadOne<R> = Option<<R as AsyncReadManaged>::Buffer>;
type ManagedReadFuture<R> = Pin<Box<dyn Future<Output = (R, io::Result<ReadOne<R>>)>>>;
type ReadAheadFuture<R> =
    Pin<Box<dyn Future<Output = (R, io::Result<Option<<R as AsyncReadManaged>::Buffer>>)>>>;
type WriteVectoredFuture<W> = Pin<Box<dyn Future<Output = (W, BufResult<(), PendingWire>)>>>;
type FlushFuture<W> = Pin<Box<dyn Future<Output = (W, io::Result<()>)>>>;

const READ_AHEAD_LEN: usize = 64 * 1024;
const PLAINTEXT_BATCH_LEN: usize = 64 * 1024;

pub struct SnellStreamReader<R: AsyncReadManaged, D> {
    inner: ReaderIo<R>,
    prefetched_plaintext: VecDeque<PlaintextFrame>,
    prefetched_ciphertext: CiphertextQueue<R::Buffer>,
    pending_zero_chunk: bool,
    decoder: D,
}

pub struct SnellStreamWriter<W, E> {
    inner: WriterIo<W>,
    encoder: E,
}

pub(crate) struct PlaintextBatch {
    frames: Vec<PlaintextFrame>,
    len: usize,
}

struct CiphertextQueue<B> {
    segments: VecDeque<CiphertextSegment<B>>,
    len: usize,
}

enum CiphertextSegment<B> {
    Managed { buffer: B, offset: usize },
    Bytes { buffer: BytesMut, offset: usize },
}

enum CiphertextChunk<B> {
    Managed(B),
    Bytes(BytesMut),
}

enum ReaderIo<R: AsyncReadManaged> {
    Idle(Option<R>),
    Reading(ReadAheadFuture<R>),
}

enum WriterIo<W> {
    Idle(Option<W>),
    Writing(WriteVectoredFuture<W>),
    Flushing(FlushFuture<W>),
}

pub(crate) enum WriteFromState<R: AsyncReadManaged> {
    Reading { reader: Option<R> },
    ReadPending { future: ManagedReadFuture<R> },
    Flushing { reader: Option<R>, eof: bool },
    Done,
}

#[derive(Debug, Default)]
pub(crate) enum WriteFrameState {
    #[default]
    Encoding,
    Flushing,
}

impl<R> WriteFromState<R>
where
    R: AsyncReadManaged,
{
    pub(crate) fn new(reader: R) -> Self {
        Self::Reading {
            reader: Some(reader),
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
{
    fn start_read_ahead(&mut self) {
        let mut inner = self.take_idle();
        let future = Box::pin(async move {
            let result = inner.read_managed(READ_AHEAD_LEN).await;
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

impl PlaintextBatch {
    fn new() -> Self {
        Self {
            frames: Vec::new(),
            len: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    fn is_full(&self) -> bool {
        self.len >= PLAINTEXT_BATCH_LEN
    }

    fn push(&mut self, frame: PlaintextFrame) {
        if !frame.is_empty() {
            self.len += frame.as_init().len();
            self.frames.push(frame);
        }
    }

    pub(crate) fn into_frames(self) -> impl Iterator<Item = PlaintextFrame> {
        self.frames.into_iter()
    }
}

impl<B> CiphertextQueue<B>
where
    B: IoBuf,
{
    fn new() -> Self {
        Self {
            segments: VecDeque::new(),
            len: 0,
        }
    }

    fn from_bytes(buffer: BytesMut) -> Self {
        let mut queue = Self::new();
        queue.push_bytes(buffer);
        queue
    }

    fn push_managed(&mut self, buffer: B) {
        if !buffer.as_init().is_empty() {
            self.len += buffer.as_init().len();
            self.segments
                .push_back(CiphertextSegment::Managed { buffer, offset: 0 });
        }
    }

    fn push_bytes(&mut self, buffer: BytesMut) {
        if !buffer.is_empty() {
            self.len += buffer.len();
            self.segments
                .push_back(CiphertextSegment::Bytes { buffer, offset: 0 });
        }
    }

    fn has(&self, len: usize) -> bool {
        self.len >= len
    }

    fn take_exact(&mut self, len: usize) -> CiphertextChunk<B> {
        assert!(self.len >= len);

        if let Some(segment) = self.segments.front_mut() {
            let remaining = segment.remaining();
            if remaining == len {
                self.len -= len;
                return match self.segments.pop_front().expect("ciphertext segment") {
                    CiphertextSegment::Managed { buffer, offset: 0 } => {
                        CiphertextChunk::Managed(buffer)
                    }
                    CiphertextSegment::Managed { buffer, offset } => {
                        CiphertextChunk::Bytes(bytes_from_slice(&buffer.as_init()[offset..]))
                    }
                    CiphertextSegment::Bytes { buffer, offset: 0 } => {
                        CiphertextChunk::Bytes(buffer)
                    }
                    CiphertextSegment::Bytes { buffer, offset } => {
                        CiphertextChunk::Bytes(bytes_from_slice(&buffer.as_ref()[offset..]))
                    }
                };
            }

            if let CiphertextSegment::Bytes { buffer, offset: 0 } = segment
                && remaining > len
            {
                self.len -= len;
                return CiphertextChunk::Bytes(buffer.split_to(len));
            }
        }

        // ponytail: keep segmented crypto out of the protocol layer; copy only
        // exact chunks that span buffers or split a managed buffer.
        let mut out = BytesMut::with_capacity(len);
        while out.len() < len {
            let take = {
                let segment = self.segments.front_mut().expect("ciphertext segment");
                let remaining = segment.remaining();
                let take = (len - out.len()).min(remaining);
                segment.copy_to(&mut out, take);
                take
            };
            self.len -= take;
            if self
                .segments
                .front()
                .is_some_and(CiphertextSegment::is_empty)
            {
                self.segments.pop_front();
            }
        }
        CiphertextChunk::Bytes(out)
    }
}

impl<B> CiphertextSegment<B>
where
    B: IoBuf,
{
    fn remaining(&self) -> usize {
        match self {
            Self::Managed { buffer, offset } => buffer.as_init().len() - offset,
            Self::Bytes { buffer, offset } => buffer.len() - offset,
        }
    }

    fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn copy_to(&mut self, out: &mut BytesMut, len: usize) {
        match self {
            Self::Managed { buffer, offset } => {
                let start = *offset;
                *offset += len;
                out.extend_from_slice(&<B as IoBuf>::as_init(buffer)[start..start + len]);
            }
            Self::Bytes { buffer, offset } => {
                let start = *offset;
                *offset += len;
                out.extend_from_slice(&buffer.as_ref()[start..start + len]);
            }
        }
    }
}

impl IoVectoredBuf for PlaintextBatch {
    fn iter_slice(&self) -> impl Iterator<Item = &[u8]> {
        self.frames.iter().map(IoBuf::as_init)
    }

    fn total_len(&self) -> usize {
        self.len
    }
}

impl<R, D> SnellStreamReader<R, D>
where
    R: AsyncRead + AsyncReadManaged + 'static,
    R::Buffer: IoBufMut + Into<PlaintextSegment> + 'static,
    D: SnellTcpDecoder,
{
    pub fn new<M>(inner: R, psk: Arc<[u8]>) -> Self
    where
        M: SnellMode<Decoder = D>,
    {
        Self {
            inner: ReaderIo::new(inner),
            prefetched_plaintext: VecDeque::new(),
            prefetched_ciphertext: CiphertextQueue::new(),
            pending_zero_chunk: false,
            decoder: M::new_decoder(psk),
        }
    }

    pub(crate) fn from_decoder_with_pending(
        inner: R,
        decoder: D,
        pending_plaintext: Vec<PlaintextFrame>,
        pending_ciphertext: BytesMut,
    ) -> Self {
        Self {
            inner: ReaderIo::new(inner),
            prefetched_plaintext: pending_plaintext.into(),
            prefetched_ciphertext: CiphertextQueue::from_bytes(pending_ciphertext),
            pending_zero_chunk: false,
            decoder,
        }
    }

    pub(crate) fn poll_read_frame_batch(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<PlaintextBatch>>> {
        let mut batch = PlaintextBatch::new();

        if self.pending_zero_chunk {
            self.pending_zero_chunk = false;
            return Poll::Ready(Ok(None));
        }

        while !batch.is_full()
            && let Some(frame) = self.prefetched_plaintext.pop_front()
        {
            batch.push(frame);
        }
        if !batch.is_empty() {
            return Poll::Ready(Ok(Some(batch)));
        }

        loop {
            while !batch.is_full()
                && let Some(frame) = self.decoder.take_pending_plaintext()
            {
                batch.push(frame);
            }

            if !batch.is_empty() {
                if batch.is_full() {
                    return Poll::Ready(Ok(Some(batch)));
                }

                // Do not start a new read while `batch` owns plaintext; a
                // pending read would drop the local batch before it is written.
                match self.try_decode_prefetched_frame()? {
                    Some(true) => continue,
                    Some(false) => {
                        self.pending_zero_chunk = true;
                        return Poll::Ready(Ok(Some(batch)));
                    }
                    None => return Poll::Ready(Ok(Some(batch))),
                }
            }

            if !ready!(self.poll_read_frame(cx))? {
                if batch.is_empty() {
                    return Poll::Ready(Ok(None));
                }
                self.pending_zero_chunk = true;
                return Poll::Ready(Ok(Some(batch)));
            }
        }
    }

    fn try_decode_prefetched_frame(&mut self) -> io::Result<Option<bool>> {
        loop {
            if self.decoder.has_pending_plaintext() {
                return Ok(Some(true));
            }

            let len = self.decoder.next_cipher_len();
            if len == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snell decoder requested zero ciphertext bytes",
                ));
            }

            if !self.has_prefetched_ciphertext(len) {
                return Ok(None);
            }

            match self.decode_prefetched_ciphertext(len)? {
                DecodeEvent::PlainData => return Ok(Some(true)),
                DecodeEvent::ZeroChunk => return Ok(Some(false)),
                DecodeEvent::NeedMore => continue,
                _ => continue,
            }
        }
    }

    pub(crate) fn poll_drain_frame_plaintext_with<F>(
        &mut self,
        cx: &mut Context<'_>,
        f: F,
    ) -> Poll<io::Result<bool>>
    where
        F: FnOnce(&mut Context<'_>, &[u8]) -> Poll<io::Result<()>>,
    {
        if let Some(prefetched) = self.prefetched_plaintext.front() {
            let result = f(cx, IoBuf::as_init(prefetched));
            match result {
                Poll::Ready(Ok(())) => {
                    self.prefetched_plaintext.pop_front();
                    return Poll::Ready(Ok(true));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }

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
            let copied = self.copy_prefetched_plaintext(&mut dst[filled..]);
            if copied != 0 {
                filled += copied;
                continue;
            }

            let copied = self.copy_pending_control_plaintext(&mut dst[filled..]);
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

    fn copy_prefetched_plaintext(&mut self, dst: &mut [u8]) -> usize {
        let Some((take, drained)) = self.prefetched_plaintext.front_mut().map(|prefetched| {
            let plain_len = IoBuf::as_init(&*prefetched).len();
            let take = dst.len().min(plain_len);
            dst[..take].copy_from_slice(&IoBuf::as_init(&*prefetched)[..take]);
            prefetched.advance(take);
            (take, take == plain_len)
        }) else {
            return 0;
        };
        if drained {
            self.prefetched_plaintext.pop_front();
        }
        take
    }

    fn poll_read_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            if self.pending_zero_chunk {
                self.pending_zero_chunk = false;
                return Poll::Ready(Ok(false));
            }

            if self.decoder.has_pending_plaintext() {
                return Poll::Ready(Ok(true));
            }

            let len = self.decoder.next_cipher_len();
            if len == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snell decoder requested zero ciphertext bytes",
                )));
            }

            if !self.has_prefetched_ciphertext(len) {
                if !ready!(self.poll_read_ahead(cx))? {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "failed to fill snell ciphertext chunk",
                    )));
                }
                continue;
            }

            let event = self.decode_prefetched_ciphertext(len)?;
            match event {
                DecodeEvent::PlainData => return Poll::Ready(Ok(true)),
                DecodeEvent::ZeroChunk => return Poll::Ready(Ok(false)),
                DecodeEvent::NeedMore => continue,
                _ => continue,
            }
        }
    }

    fn poll_read_ahead(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if matches!(self.inner, ReaderIo::Idle(_)) {
            self.inner.start_read_ahead();
        }

        let (inner, result) = match &mut self.inner {
            ReaderIo::Idle(_) => unreachable!("reader io did not start read-ahead"),
            ReaderIo::Reading(future) => ready!(future.as_mut().poll(cx)),
        };
        self.inner = ReaderIo::Idle(Some(inner));

        match result? {
            Some(chunk) => {
                self.prefetched_ciphertext.push_managed(chunk);
                Poll::Ready(Ok(true))
            }
            None => Poll::Ready(Ok(false)),
        }
    }

    fn decode_prefetched_ciphertext(&mut self, len: usize) -> io::Result<DecodeEvent<'_>> {
        match self.prefetched_ciphertext.take_exact(len) {
            CiphertextChunk::Managed(ciphertext) => self.decoder.decode_ciphertext(ciphertext),
            CiphertextChunk::Bytes(ciphertext) => self.decoder.decode_ciphertext(ciphertext),
        }
    }

    fn has_prefetched_ciphertext(&self, len: usize) -> bool {
        self.prefetched_ciphertext.has(len)
    }

    fn copy_pending_control_plaintext(&mut self, dst: &mut [u8]) -> usize {
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
        state: &mut WriteFromState<R>,
    ) -> Poll<io::Result<bool>>
    where
        R: AsyncReadManaged + 'static,
        R::Buffer: IoBufMut + Into<PendingWireSegment> + 'static,
    {
        loop {
            match state {
                WriteFromState::Reading { reader } => {
                    let capacity = self.encoder.next_plain_capacity();
                    if capacity == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "snell encoder returned zero plaintext capacity",
                        )));
                    }
                    let plain_read = reader.take().expect("plain reader missing");
                    let future = Box::pin(read_one_len(plain_read, capacity));
                    *state = WriteFromState::ReadPending { future };
                }
                WriteFromState::ReadPending { future } => {
                    let (reader, result) = ready!(future.as_mut().poll(cx));
                    let eof = match result? {
                        Some(read) => {
                            self.encoder.seal_plain(read)?;
                            false
                        }
                        None => {
                            self.encoder.seal_plain(BytesMut::new())?;
                            true
                        }
                    };
                    *state = WriteFromState::Flushing {
                        reader: Some(reader),
                        eof,
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
                    };
                    return Poll::Ready(Ok(true));
                }
                WriteFromState::Done => return Poll::Ready(Ok(false)),
            }
        }
    }

    pub(crate) fn poll_write_owned_frame<B>(
        &mut self,
        cx: &mut Context<'_>,
        payload: B,
        state: &mut WriteFrameState,
    ) -> Poll<io::Result<()>>
    where
        B: IoBufMut + Into<PendingWireSegment>,
    {
        match state {
            WriteFrameState::Encoding => {
                if payload.as_init().len() > self.encoder.next_plain_capacity() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "snell udp packet is larger than one frame",
                    )));
                }
                self.encoder.seal_plain(payload)?;
                *state = WriteFrameState::Flushing;
            }
            WriteFrameState::Flushing => {}
        }
        ready!(self.poll_flush_frame(cx, state))?;
        Poll::Ready(Ok(()))
    }

    pub(crate) fn poll_flush_frame(
        &mut self,
        cx: &mut Context<'_>,
        state: &mut WriteFrameState,
    ) -> Poll<io::Result<bool>> {
        match state {
            WriteFrameState::Encoding => Poll::Ready(Ok(false)),
            WriteFrameState::Flushing => {
                ready!(self.poll_drain_pending(cx))?;
                *state = WriteFrameState::Encoding;
                Poll::Ready(Ok(true))
            }
        }
    }

    pub async fn write_with<F>(&mut self, hint: usize, fill: F) -> io::Result<()>
    where
        F: FnOnce(&mut [u8]) -> io::Result<usize>,
    {
        let capacity = hint.min(self.encoder.next_plain_capacity());
        let mut payload = BytesMut::with_capacity(capacity);
        payload.resize(capacity, 0);
        let n = fill(&mut payload)?;
        if n > capacity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell payload exceeds filled buffer",
            ));
        }
        payload.truncate(n);
        self.encoder.seal_plain(payload)?;
        self.drain_pending().await
    }

    async fn write_one_frame(&mut self, payload: &[u8]) -> io::Result<usize> {
        let capacity = self.encoder.next_plain_capacity();
        if capacity == 0 && !payload.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell encoder returned zero plaintext capacity",
            ));
        }
        let n = payload.len().min(capacity);
        self.encoder.seal_plain(bytes_from_slice(&payload[..n]))?;
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

fn bytes_from_slice(payload: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(payload.len());
    buf.extend_from_slice(payload);
    buf
}

async fn read_one_len<R>(mut reader: R, len: usize) -> (R, io::Result<ReadOne<R>>)
where
    R: AsyncReadManaged + 'static,
    R::Buffer: 'static,
{
    let result = reader.read_managed(len).await;
    (reader, result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::snell::{HEADER_CIPHER_LEN, V4Decoder, V4Encoder, V4Mode};
    use compio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
        runtime, time,
    };
    use std::time::Duration;

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

        let payload = read_batch_vec(&mut reader).await.unwrap().unwrap();
        assert_eq!(payload, b"hello");
        assert!(read_batch_vec(&mut reader).await.unwrap().is_none());
    }

    #[compio::test]
    async fn batches_buffered_plaintext_frames() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let mut encoder = V4Encoder::new(&psk).unwrap();
        let mut wire = Vec::new();

        encoder.seal_plain(bytes_from_slice(b"hello")).unwrap();
        append_pending_wire(&mut encoder, &mut wire);
        encoder.seal_plain(bytes_from_slice(b"world")).unwrap();
        append_pending_wire(&mut encoder, &mut wire);
        encoder.seal_plain(BytesMut::new()).unwrap();
        append_pending_wire(&mut encoder, &mut wire);

        let (_client, server) = tcp_pair().await;
        let (server_read, _) = server.into_split();
        let mut reader = SnellStreamReader::from_decoder_with_pending(
            server_read,
            V4Decoder::new(psk),
            Vec::new(),
            BytesMut::from(&wire[..]),
        );

        let payload = read_batch_vec(&mut reader).await.unwrap().unwrap();
        assert_eq!(payload, b"helloworld");
        assert!(read_batch_vec(&mut reader).await.unwrap().is_none());
    }

    #[test]
    fn ciphertext_queue_moves_exact_managed_segment() {
        let mut queue = CiphertextQueue::new();
        queue.push_managed(BytesMut::from(&b"hello"[..]));

        match queue.take_exact(5) {
            CiphertextChunk::Managed(buffer) => assert_eq!(buffer.as_init(), b"hello"),
            CiphertextChunk::Bytes(_) => panic!("exact managed segment was copied"),
        }
        assert!(!queue.has(1));
    }

    #[test]
    fn ciphertext_queue_copies_split_managed_segment_and_preserves_tail() {
        let mut queue = CiphertextQueue::new();
        queue.push_managed(BytesMut::from(&b"helloworld"[..]));

        assert_eq!(ciphertext_chunk_bytes(queue.take_exact(5)), b"hello");
        assert_eq!(ciphertext_chunk_bytes(queue.take_exact(5)), b"world");
        assert!(!queue.has(1));
    }

    #[compio::test]
    async fn reads_frame_split_across_socket_reads() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let mut encoder = V4Encoder::new(&psk).unwrap();
        let mut wire = Vec::new();
        encoder.seal_plain(bytes_from_slice(b"hello")).unwrap();
        append_pending_wire(&mut encoder, &mut wire);

        let (client, server) = tcp_pair().await;
        let (_, mut client_write) = client.into_split();
        let (server_read, _) = server.into_split();
        let mut reader: SnellStreamReader<_, V4Decoder> =
            SnellStreamReader::new::<V4Mode>(server_read, psk);

        let read = runtime::spawn(async move { read_batch_vec(&mut reader).await.unwrap() });
        client_write
            .write_all(BytesMut::from(&wire[..8]))
            .await
            .unwrap();
        time::sleep(Duration::from_millis(10)).await;
        client_write
            .write_all(BytesMut::from(&wire[8..]))
            .await
            .unwrap();

        assert_eq!(read.await.unwrap().unwrap(), b"hello");
    }

    #[compio::test]
    async fn returns_buffered_batch_before_waiting_for_next_frame_body() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let mut encoder = V4Encoder::new(&psk).unwrap();
        let mut first = Vec::new();
        let mut second = Vec::new();
        let mut zero = Vec::new();

        encoder.seal_plain(bytes_from_slice(b"hello")).unwrap();
        append_pending_wire(&mut encoder, &mut first);
        encoder.seal_plain(bytes_from_slice(b"world")).unwrap();
        append_pending_wire(&mut encoder, &mut second);
        encoder.seal_plain(BytesMut::new()).unwrap();
        append_pending_wire(&mut encoder, &mut zero);

        let (client, server) = tcp_pair().await;
        let (_, mut client_write) = client.into_split();
        let (server_read, _) = server.into_split();
        let mut reader: SnellStreamReader<_, V4Decoder> =
            SnellStreamReader::new::<V4Mode>(server_read, psk);

        let split = HEADER_CIPHER_LEN.min(second.len());
        let mut prefix = first;
        prefix.extend_from_slice(&second[..split]);
        client_write
            .write_all(BytesMut::from(&prefix[..]))
            .await
            .unwrap();

        let payload = time::timeout(Duration::from_secs(1), read_batch_vec(&mut reader))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(payload, b"hello");

        let mut suffix = Vec::from(&second[split..]);
        suffix.extend_from_slice(&zero);
        client_write
            .write_all(BytesMut::from(&suffix[..]))
            .await
            .unwrap();

        assert_eq!(
            read_batch_vec(&mut reader).await.unwrap().unwrap(),
            b"world"
        );
        assert!(read_batch_vec(&mut reader).await.unwrap().is_none());
    }

    async fn read_batch_vec<R, D>(
        reader: &mut SnellStreamReader<R, D>,
    ) -> io::Result<Option<Vec<u8>>>
    where
        R: AsyncRead + AsyncReadManaged + 'static,
        R::Buffer: IoBufMut + Into<PlaintextSegment> + 'static,
        D: SnellTcpDecoder,
    {
        let Some(batch) = poll_fn(|cx| reader.poll_read_frame_batch(cx)).await? else {
            return Ok(None);
        };
        let mut out = Vec::new();
        for slice in batch.iter_slice() {
            out.extend_from_slice(slice);
        }
        Ok(Some(out))
    }

    fn ciphertext_chunk_bytes<B>(chunk: CiphertextChunk<B>) -> Vec<u8>
    where
        B: IoBuf,
    {
        match chunk {
            CiphertextChunk::Managed(buffer) => buffer.as_init().to_vec(),
            CiphertextChunk::Bytes(buffer) => buffer.to_vec(),
        }
    }

    fn append_pending_wire(encoder: &mut V4Encoder, wire: &mut Vec<u8>) {
        let pending = encoder.take_pending_wire();
        for slice in pending.iter_slices() {
            wire.extend_from_slice(slice);
        }
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

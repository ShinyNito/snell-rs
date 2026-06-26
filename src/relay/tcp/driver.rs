use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::{Buf, Bytes, BytesMut};
use compio::{
    buf::{BufResult, IoVectoredBuf},
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
};

use crate::protocol::snell::{
    DecodeEvent, SnellMode, SnellPlainReader, SnellTcpDecoder, SnellTcpEncoder,
};

type ReadFuture<R> = Pin<Box<dyn Future<Output = (R, BufResult<usize, BytesMut>)>>>;
type WriteFuture<W> = Pin<Box<dyn Future<Output = (W, BufResult<(), Vec<Bytes>>)>>>;
type FlushFuture<W> = Pin<Box<dyn Future<Output = (W, io::Result<()>)>>>;

const READ_AHEAD_LEN: usize = 64 * 1024;
const PLAINTEXT_BATCH_LEN: usize = 64 * 1024;

pub struct SnellStreamReader<R, D> {
    inner: ReaderIo<R>,
    decoder: D,
}

pub struct SnellStreamWriter<W, E> {
    inner: WriterIo<W>,
    encoder: E,
}

pub(crate) struct PlaintextBatch {
    frames: Vec<BytesMut>,
    len: usize,
    end: bool,
}

enum CiphertextRead {
    Progress,
    ZeroChunk,
    Eof,
}

enum ReaderIo<R> {
    Idle(Option<R>),
    Reading(ReadFuture<R>),
}

enum WriterIo<W> {
    Idle(Option<W>),
    Writing(WriteFuture<W>),
    Flushing(FlushFuture<W>),
}

pub(crate) enum WriteFromState<R> {
    Reading {
        reader: Option<R>,
    },
    ReadPending {
        future: ReadFuture<R>,
    },
    Encoding {
        reader: Option<R>,
        payload: BytesMut,
        offset: usize,
    },
    Flushing {
        reader: Option<R>,
        payload: BytesMut,
        offset: usize,
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

impl<R> WriteFromState<R>
where
    R: AsyncRead,
{
    pub(crate) fn new(reader: R) -> Self {
        Self::Reading {
            reader: Some(reader),
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
    fn start_read(&mut self) {
        let mut inner = self.take_idle();
        let future = Box::pin(async move {
            let result = inner.read(BytesMut::with_capacity(READ_AHEAD_LEN)).await;
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
    fn start_write_all(&mut self, wire: Vec<Bytes>) {
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

impl PlaintextBatch {
    fn new() -> Self {
        Self {
            frames: Vec::new(),
            len: 0,
            end: false,
        }
    }

    fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    fn is_full(&self) -> bool {
        self.len >= PLAINTEXT_BATCH_LEN
    }

    fn push(&mut self, frame: BytesMut) {
        if !frame.is_empty() {
            self.len += frame.len();
            self.frames.push(frame);
        }
    }

    fn finish(&mut self) {
        self.end = true;
    }

    pub(crate) fn ends_stream(&self) -> bool {
        self.end
    }

    pub(crate) fn into_frames(self) -> impl Iterator<Item = Bytes> {
        self.frames.into_iter().map(BytesMut::freeze)
    }
}

impl IoVectoredBuf for PlaintextBatch {
    fn iter_slice(&self) -> impl Iterator<Item = &[u8]> {
        self.frames.iter().map(BytesMut::as_ref)
    }

    fn total_len(&self) -> usize {
        self.len
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

    /// Build a reader around an already-warmed decoder.
    ///
    /// After [`probe_snell_mode`] the decoder has already absorbed some
    /// ciphertext into its internal buffer; the residual lives inside the
    /// decoder itself, so no external `pending_ciphertext` parameter is needed.
    pub(crate) fn from_decoder(inner: R, decoder: D) -> Self {
        Self {
            inner: ReaderIo::new(inner),
            decoder,
        }
    }

    pub(crate) fn poll_read_frame_batch(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<PlaintextBatch>>> {
        let mut batch = PlaintextBatch::new();
        loop {
            match self.drain_decoder(&mut batch)? {
                Some(true) => {
                    if batch.is_full() {
                        return Poll::Ready(Ok(Some(batch)));
                    }
                    continue;
                }
                Some(false) => {
                    return if batch.is_empty() {
                        Poll::Ready(Ok(None))
                    } else {
                        batch.finish();
                        Poll::Ready(Ok(Some(batch)))
                    };
                }
                None if !batch.is_empty() => return Poll::Ready(Ok(Some(batch))),
                None => {}
            }

            match ready!(self.poll_read_ciphertext(cx))? {
                CiphertextRead::Progress => {}
                CiphertextRead::ZeroChunk => {
                    return if batch.is_empty() {
                        Poll::Ready(Ok(None))
                    } else {
                        batch.finish();
                        Poll::Ready(Ok(Some(batch)))
                    };
                }
                CiphertextRead::Eof => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "snell ciphertext stream ended early",
                    )));
                }
            }
        }
    }

    pub async fn read_exact_plain(&mut self, dst: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < dst.len() {
            if self.decoder.pending_plain().is_empty()
                && !poll_fn(|cx| self.poll_read_frame(cx)).await?
            {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell zero chunk while reading control data",
                ));
            }

            let plain = self.decoder.pending_plain();
            if plain.is_empty() {
                continue;
            }
            let take = (dst.len() - filled).min(plain.len());
            dst[filled..filled + take].copy_from_slice(&plain[..take]);
            self.decoder.consume_plain(take);
            filled += take;
        }
        Ok(())
    }

    fn poll_read_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            if self.decoder.has_pending_plain() {
                return Poll::Ready(Ok(true));
            }

            match self.decoder.feed_owned(BytesMut::new())? {
                DecodeEvent::PlainData => return Poll::Ready(Ok(true)),
                DecodeEvent::ZeroChunk => return Poll::Ready(Ok(false)),
                DecodeEvent::NeedMore => {}
                _ => continue,
            }

            match ready!(self.poll_read_ciphertext(cx))? {
                CiphertextRead::Progress => {}
                CiphertextRead::ZeroChunk => return Poll::Ready(Ok(false)),
                CiphertextRead::Eof => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "snell ciphertext stream ended early",
                    )));
                }
            }
        }
    }

    fn drain_decoder(&mut self, batch: &mut PlaintextBatch) -> io::Result<Option<bool>> {
        loop {
            if self.decoder.has_pending_plain() {
                batch.push(self.decoder.take_plain());
                return Ok(Some(true));
            }

            match self.decoder.feed_owned(BytesMut::new())? {
                DecodeEvent::PlainData => continue,
                DecodeEvent::ZeroChunk => return Ok(Some(false)),
                DecodeEvent::NeedMore => return Ok(None),
                _ => continue,
            }
        }
    }

    fn poll_read_ciphertext(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<CiphertextRead>> {
        if matches!(self.inner, ReaderIo::Idle(_)) {
            self.inner.start_read();
        }

        let (inner, BufResult(result, mut chunk)) = match &mut self.inner {
            ReaderIo::Idle(_) => unreachable!("reader io did not start read"),
            ReaderIo::Reading(future) => ready!(future.as_mut().poll(cx)),
        };
        self.inner = ReaderIo::Idle(Some(inner));

        let n = result?;
        if n == 0 {
            return Poll::Ready(Ok(CiphertextRead::Eof));
        }
        chunk.truncate(n);
        Poll::Ready(Ok(match self.decoder.feed_owned(chunk)? {
            DecodeEvent::ZeroChunk => CiphertextRead::ZeroChunk,
            _ => CiphertextRead::Progress,
        }))
    }
}

impl<R, D> SnellPlainReader for SnellStreamReader<R, D>
where
    R: AsyncRead + 'static,
    D: SnellTcpDecoder,
{
    async fn read_exact_plain(&mut self, dst: &mut [u8]) -> io::Result<()> {
        SnellStreamReader::read_exact_plain(self, dst).await
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
        R: AsyncRead + 'static,
    {
        loop {
            match state {
                WriteFromState::Reading { reader } => {
                    let mut reader = reader.take().expect("plain reader missing");
                    let future = Box::pin(async move {
                        let result = reader.read(BytesMut::with_capacity(READ_AHEAD_LEN)).await;
                        (reader, result)
                    });
                    *state = WriteFromState::ReadPending { future };
                }
                WriteFromState::ReadPending { future } => {
                    let (reader, BufResult(result, mut payload)) = ready!(future.as_mut().poll(cx));
                    let n = result?;
                    let eof = n == 0;
                    payload.truncate(n);
                    if eof {
                        let wire = self.encoder.seal_plain(BytesMut::new())?;
                        self.inner.start_write_all(wire);
                        *state = WriteFromState::Flushing {
                            reader: Some(reader),
                            payload,
                            offset: 0,
                            eof: true,
                        };
                    } else {
                        *state = WriteFromState::Encoding {
                            reader: Some(reader),
                            payload,
                            offset: 0,
                        };
                    };
                }
                WriteFromState::Encoding {
                    reader,
                    payload,
                    offset,
                } => {
                    if *offset >= payload.len() {
                        let reader = reader.take().expect("plain reader missing");
                        *state = WriteFromState::Reading {
                            reader: Some(reader),
                        };
                        continue;
                    }
                    let capacity = self.encoder.next_plain_capacity();
                    if capacity == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "snell encoder returned zero plaintext capacity",
                        )));
                    }
                    let n = (payload.len() - *offset).min(capacity);
                    // Take ownership so we can split the frame off zero-copy.
                    let mut payload = std::mem::take(payload);
                    payload.advance(*offset);
                    let frame = payload.split_to(n);
                    let wire = self.encoder.seal_plain(frame)?;
                    self.inner.start_write_all(wire);
                    let reader = reader.take().expect("plain reader missing");
                    *state = WriteFromState::Flushing {
                        reader: Some(reader),
                        payload,
                        offset: 0,
                        eof: false,
                    };
                }
                WriteFromState::Flushing {
                    reader,
                    payload,
                    offset,
                    eof,
                } => {
                    ready!(self.poll_drain_pending(cx))?;
                    let reader = reader.take().expect("plain reader missing");
                    if *eof {
                        *state = WriteFromState::Done;
                        return Poll::Ready(Ok(false));
                    }
                    if *offset < payload.len() {
                        let payload = std::mem::take(payload);
                        *state = WriteFromState::Encoding {
                            reader: Some(reader),
                            payload,
                            offset: *offset,
                        };
                        return Poll::Ready(Ok(true));
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
        B: AsRef<[u8]>,
    {
        match state {
            WriteFrameState::Encoding => {
                let payload = payload.as_ref();
                if payload.len() > self.encoder.next_plain_capacity() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "snell udp packet is larger than one frame",
                    )));
                }
                let wire = self.encoder.seal_plain(BytesMut::from(payload))?;
                self.inner.start_write_all(wire);
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
        let wire = self.encoder.seal_plain(payload)?;
        self.inner.start_write_all(wire);
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
        let n = if payload.is_empty() {
            0
        } else {
            payload.len().min(capacity)
        };
        let wire = self.encoder.seal_plain(BytesMut::from(&payload[..n]))?;
        self.inner.start_write_all(wire);
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
                    self.inner.start_flush();
                }
                WriterIo::Writing(future) => {
                    let (inner, BufResult(result, _wire)) = ready!(future.as_mut().poll(cx));
                    self.inner = WriterIo::Idle(Some(inner));
                    result?;
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
    use compio::{
        buf::{BufResult, IoBufMut, SetLen},
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
        runtime, time,
    };
    use std::{sync::Mutex, time::Duration};

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

        let (frames, ends_stream) = read_batch_vec(&mut reader).await.unwrap().unwrap();
        assert_eq!(frames, vec![b"hello".to_vec()]);
        if !ends_stream {
            assert!(read_batch_vec(&mut reader).await.unwrap().is_none());
        }
    }

    #[compio::test]
    async fn reads_pending_ciphertext_after_probe() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let mut encoder = V4Encoder::new(&psk).unwrap();
        let mut wire = BytesMut::new();
        for s in encoder.seal_plain(BytesMut::from(&b"hello"[..])).unwrap() {
            wire.extend_from_slice(&s);
        }
        for s in encoder.seal_plain(BytesMut::from(&b"world"[..])).unwrap() {
            wire.extend_from_slice(&s);
        }
        for s in encoder.seal_plain(BytesMut::new()).unwrap() {
            wire.extend_from_slice(&s);
        }

        let (_client, server) = tcp_pair().await;
        let (server_read, _) = server.into_split();

        // Warm the decoder with the residual ciphertext the way probe_snell_mode
        // would: the bytes sit in the decoder's internal buffer, and the reader
        // drains them before touching the socket.
        let mut decoder = V4Decoder::new(psk);
        decoder.feed_owned(wire).unwrap();
        let mut reader = SnellStreamReader::from_decoder(server_read, decoder);

        let (frames, ends_stream) = read_batch_vec(&mut reader).await.unwrap().unwrap();
        assert_eq!(frames, vec![b"hello".to_vec(), b"world".to_vec()]);
        assert!(ends_stream);
    }

    #[compio::test]
    async fn reads_frame_split_across_socket_reads() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let mut encoder = V4Encoder::new(&psk).unwrap();
        let wire: Vec<u8> = {
            let mut v = Vec::new();
            for s in encoder.seal_plain(BytesMut::from(&b"hello"[..])).unwrap() {
                v.extend_from_slice(&s);
            }
            v
        };

        let (client, server) = tcp_pair().await;
        let (_, mut client_write) = client.into_split();
        let (server_read, _) = server.into_split();
        let mut reader: SnellStreamReader<_, V4Decoder> =
            SnellStreamReader::new::<V4Mode>(server_read, psk);

        let read = runtime::spawn(async move { read_frame_vec(&mut reader).await.unwrap() });
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
    async fn write_from_reads_fixed_read_ahead_before_framing() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let (client, server) = tcp_pair().await;
        let (_, client_write) = client.into_split();
        let (_server_read, _server_write) = server.into_split();
        let read_caps = Arc::new(Mutex::new(Vec::new()));
        let reader = RecordingReader {
            payload: Some(Bytes::from_static(b"x")),
            read_caps: read_caps.clone(),
        };
        let mut state = WriteFromState::new(reader);
        let mut writer: SnellStreamWriter<_, V4Encoder> =
            SnellStreamWriter::new::<V4Mode>(client_write, psk).unwrap();

        assert!(
            poll_fn(|cx| writer.poll_write_from(cx, &mut state))
                .await
                .unwrap()
        );

        assert_eq!(*read_caps.lock().unwrap(), vec![READ_AHEAD_LEN]);
    }

    struct RecordingReader {
        payload: Option<Bytes>,
        read_caps: Arc<Mutex<Vec<usize>>>,
    }

    impl AsyncRead for RecordingReader {
        async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
            let capacity = buf.as_uninit().len();
            self.read_caps.lock().unwrap().push(capacity);
            let Some(payload) = self.payload.take() else {
                return BufResult(Ok(0), buf);
            };
            let n = payload.len().min(capacity);
            buf.ensure_init()[..n].copy_from_slice(&payload[..n]);
            unsafe {
                SetLen::set_len(&mut buf, n);
            }
            BufResult(Ok(n), buf)
        }
    }

    async fn read_frame_vec<R, D>(
        reader: &mut SnellStreamReader<R, D>,
    ) -> io::Result<Option<Vec<u8>>>
    where
        R: AsyncRead + 'static,
        D: SnellTcpDecoder,
    {
        let Some(batch) = poll_fn(|cx| reader.poll_read_frame_batch(cx)).await? else {
            return Ok(None);
        };
        let mut frames = batch.into_frames();
        let frame = frames
            .next()
            .expect("plaintext batch should contain a frame")
            .to_vec();
        assert!(frames.next().is_none(), "expected one frame in batch");
        Ok(Some(frame))
    }

    async fn read_batch_vec<R, D>(
        reader: &mut SnellStreamReader<R, D>,
    ) -> io::Result<Option<(Vec<Vec<u8>>, bool)>>
    where
        R: AsyncRead + 'static,
        D: SnellTcpDecoder,
    {
        let Some(batch) = poll_fn(|cx| reader.poll_read_frame_batch(cx)).await? else {
            return Ok(None);
        };
        let ends_stream = batch.ends_stream();
        let frames = batch
            .into_frames()
            .map(|frame| frame.to_vec())
            .collect::<Vec<_>>();
        Ok(Some((frames, ends_stream)))
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

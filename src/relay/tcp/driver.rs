use std::{io, sync::Arc};

use bytes::{Bytes, BytesMut};
use compio::{
    buf::{BufResult, IoVectoredBuf},
    driver::BufferRef,
    io::{AsyncReadManaged, AsyncWrite, AsyncWriteExt},
};

use crate::protocol::snell::{
    DecodeEvent, SnellBuffer, SnellMode, SnellPlainReader, SnellTcpDecoder, SnellTcpEncoder,
    SnellWire,
};

const READ_AHEAD_LEN: usize = 64 * 1024;
const PLAINTEXT_BATCH_LEN: usize = 64 * 1024;

pub(crate) async fn read_exact_managed<R>(reader: &mut R, dst: &mut [u8]) -> io::Result<()>
where
    R: AsyncReadManaged<Buffer = BufferRef> + 'static,
{
    let mut filled = 0;
    while filled < dst.len() {
        let Some(buf) = reader.read_managed(dst.len() - filled).await? else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "tcp stream ended early",
            ));
        };
        if buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "tcp stream returned empty buffer",
            ));
        }
        let n = buf.len().min(dst.len() - filled);
        dst[filled..filled + n].copy_from_slice(&buf[..n]);
        filled += n;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) async fn read_once_managed<R>(reader: &mut R, dst: &mut [u8]) -> io::Result<usize>
where
    R: AsyncReadManaged<Buffer = BufferRef> + 'static,
{
    let Some(buf) = reader.read_managed(dst.len()).await? else {
        return Ok(0);
    };
    let n = buf.len().min(dst.len());
    dst[..n].copy_from_slice(&buf[..n]);
    Ok(n)
}

pub struct SnellStreamReader<R, D> {
    inner: R,
    decoder: D,
}

pub struct SnellStreamWriter<W, E> {
    inner: W,
    encoder: E,
}

pub(crate) struct PlaintextBatch {
    frames: Vec<SnellBuffer>,
    len: usize,
    end: bool,
}

enum CiphertextRead {
    Progress,
    ZeroChunk,
    Eof,
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

    fn push(&mut self, frame: SnellBuffer) {
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
        self.frames.into_iter().map(SnellBuffer::into_bytes)
    }
}

impl IoVectoredBuf for PlaintextBatch {
    fn iter_slice(&self) -> impl Iterator<Item = &[u8]> {
        self.frames.iter().map(SnellBuffer::as_slice)
    }

    fn total_len(&self) -> usize {
        self.len
    }
}

impl<R, D> SnellStreamReader<R, D>
where
    R: AsyncReadManaged<Buffer = BufferRef> + 'static,
    D: SnellTcpDecoder,
{
    pub fn new<M>(inner: R, psk: Arc<[u8]>) -> Self
    where
        M: SnellMode<Decoder = D>,
    {
        Self {
            inner,
            decoder: M::new_decoder(psk),
        }
    }

    /// Build a reader around an already-warmed decoder.
    ///
    /// After [`probe_snell_mode`] the decoder has already absorbed some
    /// ciphertext into its internal buffer; the residual lives inside the
    /// decoder itself, so no external `pending_ciphertext` parameter is needed.
    pub(crate) fn from_decoder(inner: R, decoder: D) -> Self {
        Self { inner, decoder }
    }

    pub(crate) async fn read_frame_batch(&mut self) -> io::Result<Option<PlaintextBatch>> {
        let mut batch = PlaintextBatch::new();
        loop {
            match self.drain_decoder(&mut batch)? {
                Some(true) => {
                    if batch.is_full() {
                        return Ok(Some(batch));
                    }
                    continue;
                }
                Some(false) => {
                    return if batch.is_empty() {
                        Ok(None)
                    } else {
                        batch.finish();
                        Ok(Some(batch))
                    };
                }
                None if !batch.is_empty() => return Ok(Some(batch)),
                None => {}
            }

            match self.read_ciphertext().await? {
                CiphertextRead::Progress => {}
                CiphertextRead::ZeroChunk => {
                    return if batch.is_empty() {
                        Ok(None)
                    } else {
                        batch.finish();
                        Ok(Some(batch))
                    };
                }
                CiphertextRead::Eof => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "snell ciphertext stream ended early",
                    ));
                }
            }
        }
    }

    pub async fn read_exact_plain(&mut self, dst: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < dst.len() {
            if self.decoder.pending_plain().is_empty() && !self.read_frame().await? {
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

    async fn read_frame(&mut self) -> io::Result<bool> {
        loop {
            if self.decoder.has_pending_plain() {
                return Ok(true);
            }

            match self.decoder.feed_owned(SnellBuffer::empty())? {
                DecodeEvent::PlainData => return Ok(true),
                DecodeEvent::ZeroChunk => return Ok(false),
                DecodeEvent::NeedMore => {}
                _ => continue,
            }

            match self.read_ciphertext().await? {
                CiphertextRead::Progress => {}
                CiphertextRead::ZeroChunk => return Ok(false),
                CiphertextRead::Eof => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "snell ciphertext stream ended early",
                    ));
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

            match self.decoder.feed_owned(SnellBuffer::empty())? {
                DecodeEvent::PlainData => continue,
                DecodeEvent::ZeroChunk => return Ok(Some(false)),
                DecodeEvent::NeedMore => return Ok(None),
                _ => continue,
            }
        }
    }

    async fn read_ciphertext(&mut self) -> io::Result<CiphertextRead> {
        let read_len = self.decoder.next_ciphertext_read_len();
        if read_len == 0 {
            return Ok(match self.decoder.feed_owned(SnellBuffer::empty())? {
                DecodeEvent::ZeroChunk => CiphertextRead::ZeroChunk,
                _ => CiphertextRead::Progress,
            });
        }

        let Some(chunk) = self.inner.read_managed(read_len).await? else {
            return Ok(CiphertextRead::Eof);
        };
        if chunk.is_empty() {
            return Ok(CiphertextRead::Eof);
        }
        Ok(
            match self.decoder.feed_owned(SnellBuffer::from_pool(chunk))? {
                DecodeEvent::ZeroChunk => CiphertextRead::ZeroChunk,
                _ => CiphertextRead::Progress,
            },
        )
    }
}

impl<R, D> SnellPlainReader for SnellStreamReader<R, D>
where
    R: AsyncReadManaged<Buffer = BufferRef> + 'static,
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
            inner,
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

    pub(crate) async fn write_from<R>(&mut self, mut reader: R) -> io::Result<()>
    where
        R: AsyncReadManaged<Buffer = BufferRef> + 'static,
    {
        loop {
            let capacity = self.encoder.next_plain_capacity();
            if capacity == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "snell encoder returned zero plaintext capacity",
                ));
            }

            let Some(payload) = reader.read_managed(capacity.min(READ_AHEAD_LEN)).await? else {
                let wire = self.encoder.seal_plain(SnellBuffer::empty())?;
                self.write_wire(wire).await?;
                return Ok(());
            };
            let payload = SnellBuffer::from_pool(payload);
            if payload.len() > capacity {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "snell managed read exceeded encoder capacity",
                ));
            }
            let wire = self.encoder.seal_plain(payload)?;
            self.write_wire(wire).await?;
        }
    }

    pub(crate) async fn write_owned_frame(&mut self, payload: BytesMut) -> io::Result<()> {
        if payload.len() > self.encoder.next_plain_capacity() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell udp packet is larger than one frame",
            ));
        }
        let wire = self.encoder.seal_plain(SnellBuffer::from(payload))?;
        self.write_wire(wire).await
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
        let wire = self.encoder.seal_plain(SnellBuffer::from(payload))?;
        self.write_wire(wire).await
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
        let wire = self
            .encoder
            .seal_plain(SnellBuffer::from(BytesMut::from(&payload[..n])))?;
        self.write_wire(wire).await?;
        Ok(n)
    }

    async fn write_wire(&mut self, wire: SnellWire) -> io::Result<()> {
        let BufResult(result, _wire) = self.inner.write_vectored_all(wire).await;
        result?;
        self.inner.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::snell::{V4Decoder, V4Encoder, V4Mode};
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
        for s in encoder
            .seal_plain(SnellBuffer::from(BytesMut::from(&b"hello"[..])))
            .unwrap()
            .into_bytes_vec()
        {
            wire.extend_from_slice(&s);
        }
        for s in encoder
            .seal_plain(SnellBuffer::from(BytesMut::from(&b"world"[..])))
            .unwrap()
            .into_bytes_vec()
        {
            wire.extend_from_slice(&s);
        }
        for s in encoder
            .seal_plain(SnellBuffer::empty())
            .unwrap()
            .into_bytes_vec()
        {
            wire.extend_from_slice(&s);
        }

        let (_client, server) = tcp_pair().await;
        let (server_read, _) = server.into_split();

        // Warm the decoder with the residual ciphertext the way probe_snell_mode
        // would: the bytes sit in the decoder's internal buffer, and the reader
        // drains them before touching the socket.
        let mut decoder = V4Decoder::new(psk);
        decoder.feed_owned(SnellBuffer::from(wire)).unwrap();
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
            for s in encoder
                .seal_plain(SnellBuffer::from(BytesMut::from(&b"hello"[..])))
                .unwrap()
                .into_bytes_vec()
            {
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
    async fn write_from_relays_tcp_payload() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let (source_write, source_read) = tcp_pair().await;
        let (snell_read, snell_write) = tcp_pair().await;
        let (_, mut source_write) = source_write.into_split();
        let (source_read, _) = source_read.into_split();
        let (snell_read, _) = snell_read.into_split();
        let (_, snell_write) = snell_write.into_split();
        let write = runtime::spawn(async move {
            let BufResult(result, _) = source_write.write_all(BytesMut::from(&b"x"[..])).await;
            result.unwrap();
            source_write.shutdown().await.unwrap();
        });
        let mut writer: SnellStreamWriter<_, V4Encoder> =
            SnellStreamWriter::new::<V4Mode>(snell_write, psk.clone()).unwrap();
        let mut reader: SnellStreamReader<_, V4Decoder> =
            SnellStreamReader::new::<V4Mode>(snell_read, psk);

        writer.write_from(source_read).await.unwrap();
        write.await.unwrap();

        let (frames, ends_stream) = read_batch_vec(&mut reader).await.unwrap().unwrap();
        assert_eq!(frames, vec![b"x".to_vec()]);
        assert!(!ends_stream);
        assert!(read_batch_vec(&mut reader).await.unwrap().is_none());
    }

    #[compio::test(with_proactor(
        buffer_pool_size = std::num::NonZero::<u16>::new(1).expect("nonzero buffer pool size"),
        buffer_pool_buffer_len = 64 * 1024
    ))]
    async fn read_exact_plain_releases_consumed_pool_buffer() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let (server, client) = tcp_pair().await;
        let (server_read, _) = server.into_split();
        let (_, mut client_write) = client.into_split();
        let write_psk = psk.clone();
        let write = runtime::spawn(async move {
            let mut encoder = V4Encoder::new(&write_psk).unwrap();
            let mut wire = BytesMut::new();
            for payload in [b"a".as_slice(), b"b".as_slice()] {
                for segment in encoder
                    .seal_plain(SnellBuffer::from(BytesMut::from(payload)))
                    .unwrap()
                    .into_bytes_vec()
                {
                    wire.extend_from_slice(&segment);
                }
            }
            let BufResult(result, _) = client_write.write_all(wire).await;
            result.unwrap();
        });
        let mut reader: SnellStreamReader<_, V4Decoder> =
            SnellStreamReader::new::<V4Mode>(server_read, psk);

        let mut first = [0u8; 1];
        reader.read_exact_plain(&mut first).await.unwrap();
        assert_eq!(&first, b"a");

        let mut second = [0u8; 1];
        reader.read_exact_plain(&mut second).await.unwrap();
        assert_eq!(&second, b"b");

        write.await.unwrap();
    }

    async fn read_frame_vec<R, D>(
        reader: &mut SnellStreamReader<R, D>,
    ) -> io::Result<Option<Vec<u8>>>
    where
        R: AsyncReadManaged<Buffer = BufferRef> + 'static,
        D: SnellTcpDecoder,
    {
        let Some(batch) = reader.read_frame_batch().await? else {
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
        R: AsyncReadManaged<Buffer = BufferRef> + 'static,
        D: SnellTcpDecoder,
    {
        let Some(batch) = reader.read_frame_batch().await? else {
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

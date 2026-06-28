use std::{io, sync::Arc};

use bytes::BytesMut;
use compio::{
    buf::{BufResult, IntoInner, IoBuf, IoBufMut},
    driver::BufferRef,
    io::{AsyncRead, AsyncReadExt, AsyncReadManaged, AsyncWrite, AsyncWriteExt},
};

use crate::protocol::snell::{
    DecodeEvent, SnellBuffer, SnellMode, SnellPlainReader, SnellTcpDecoder, SnellTcpEncoder,
    SnellWire,
};

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
    pending_ciphertext: BytesMut,
}

pub struct SnellStreamWriter<W, E> {
    inner: W,
    encoder: E,
    wire: SnellWire,
    control_payload: BytesMut,
}

enum CiphertextRead {
    Progress,
    ZeroChunk,
    Eof,
}

impl<R, D> SnellStreamReader<R, D>
where
    R: AsyncRead + AsyncReadManaged<Buffer = BufferRef> + 'static,
    D: SnellTcpDecoder,
{
    pub fn new<M>(inner: R, psk: Arc<[u8]>) -> Self
    where
        M: SnellMode<Decoder = D>,
    {
        Self {
            inner,
            decoder: M::new_decoder(psk),
            pending_ciphertext: BytesMut::new(),
        }
    }

    /// Build a reader around a probed decoder and any ciphertext read past the
    /// bytes consumed during probing.
    pub(crate) fn from_decoder_with_pending(
        inner: R,
        decoder: D,
        pending_ciphertext: BytesMut,
    ) -> Self {
        Self {
            inner,
            decoder,
            pending_ciphertext,
        }
    }

    pub(crate) async fn read_plain_frame(&mut self) -> io::Result<Option<SnellBuffer>> {
        loop {
            if self.decoder.has_pending_plain() {
                return Ok(Some(self.decoder.take_plain()));
            }

            match self.read_ciphertext().await? {
                CiphertextRead::Progress => {}
                CiphertextRead::ZeroChunk => return Ok(None),
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

    async fn read_ciphertext(&mut self) -> io::Result<CiphertextRead> {
        let read_len = self.decoder.next_ciphertext_read_len();
        if read_len == 0 {
            return Ok(match self.decoder.feed_owned(SnellBuffer::empty())? {
                DecodeEvent::ZeroChunk => CiphertextRead::ZeroChunk,
                _ => CiphertextRead::Progress,
            });
        }

        let Some(chunk) = self.read_exact_ciphertext(read_len).await? else {
            return Ok(CiphertextRead::Eof);
        };
        Ok(match self.decoder.feed_owned(chunk)? {
            DecodeEvent::ZeroChunk => CiphertextRead::ZeroChunk,
            _ => CiphertextRead::Progress,
        })
    }

    async fn read_exact_ciphertext(&mut self, read_len: usize) -> io::Result<Option<SnellBuffer>> {
        if self.pending_ciphertext.len() >= read_len {
            return Ok(Some(SnellBuffer::from(
                self.pending_ciphertext.split_to(read_len),
            )));
        }

        if !self.pending_ciphertext.is_empty() {
            let ciphertext = std::mem::take(&mut self.pending_ciphertext);
            return self.read_exact_bytes_mut(ciphertext, read_len).await;
        }

        let Some(mut buffer) = self.inner.read_managed(read_len).await? else {
            return Ok(None);
        };
        if buffer.is_empty() {
            return Ok(None);
        }

        if buffer.buf_capacity() < read_len {
            let mut ciphertext = BytesMut::with_capacity(read_len);
            ciphertext.extend_from_slice(&buffer);
            return self.read_exact_bytes_mut(ciphertext, read_len).await;
        }

        if buffer.len() == read_len {
            return Ok(Some(SnellBuffer::from_pool(buffer)));
        }

        let filled = buffer.len();
        let BufResult(result, buffer_slice) =
            self.inner.read_exact(buffer.slice(filled..read_len)).await;
        buffer = buffer_slice.into_inner();
        match result {
            Ok(()) => {
                debug_assert_eq!(buffer.len(), read_len);
                Ok(Some(SnellBuffer::from_pool(buffer)))
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn read_exact_bytes_mut(
        &mut self,
        mut ciphertext: BytesMut,
        read_len: usize,
    ) -> io::Result<Option<SnellBuffer>> {
        debug_assert!(ciphertext.len() < read_len);

        if ciphertext.capacity() < read_len {
            ciphertext.reserve(read_len - ciphertext.capacity());
        }

        let filled = ciphertext.len();
        let BufResult(result, ciphertext_slice) = self
            .inner
            .read_exact(ciphertext.slice(filled..read_len))
            .await;
        ciphertext = ciphertext_slice.into_inner();
        match result {
            Ok(()) => {
                debug_assert_eq!(ciphertext.len(), read_len);
                Ok(Some(SnellBuffer::from(ciphertext)))
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(error) => Err(error),
        }
    }
}

impl<R, D> SnellPlainReader for SnellStreamReader<R, D>
where
    R: AsyncRead + AsyncReadManaged<Buffer = BufferRef> + 'static,
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
            wire: SnellWire::new(),
            control_payload: BytesMut::new(),
        })
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

            let Some(payload) = reader.read_managed(capacity).await? else {
                self.write_sealed(SnellBuffer::empty()).await?;
                return Ok(());
            };
            let payload = SnellBuffer::from_pool(payload);
            if payload.is_empty() {
                continue;
            }
            if payload.len() > capacity {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "snell managed read exceeded encoder capacity",
                ));
            }
            self.write_sealed(payload).await?;
        }
    }

    pub async fn write_with<F>(&mut self, hint: usize, fill: F) -> io::Result<()>
    where
        F: FnOnce(&mut [u8]) -> io::Result<usize>,
    {
        let plain_capacity = self.encoder.next_plain_capacity();
        if hint > plain_capacity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell payload is larger than one frame",
            ));
        }
        let capacity = hint;
        let mut payload = std::mem::take(&mut self.control_payload);
        if payload.capacity() < capacity {
            payload.reserve(capacity - payload.capacity());
        }
        payload.resize(capacity, 0);
        let n = match fill(&mut payload) {
            Ok(n) => n,
            Err(error) => {
                payload.clear();
                self.control_payload = payload;
                return Err(error);
            }
        };
        if n > capacity {
            payload.clear();
            self.control_payload = payload;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell payload exceeds filled buffer",
            ));
        }
        payload.truncate(n);
        self.control_payload = self
            .write_sealed(SnellBuffer::from(payload))
            .await?
            .unwrap_or_default();
        self.control_payload.clear();
        Ok(())
    }

    async fn write_sealed(&mut self, payload: SnellBuffer) -> io::Result<Option<BytesMut>> {
        let mut wire = std::mem::take(&mut self.wire);
        if let Err(error) = self.encoder.seal_plain(payload, &mut wire) {
            wire.clear();
            self.wire = wire;
            return Err(error);
        }
        let BufResult(result, mut wire) = self.inner.write_vectored_all(wire).await;
        let reusable_payload = wire.take_payload_bytes_mut();
        wire.clear();
        self.wire = wire;
        result?;
        Ok(reusable_payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::snell::{HEADER_CIPHER_LEN, SALT_LEN, V4Decoder, V4Encoder, V4Mode};
    use compio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
        runtime, time,
    };
    use std::time::Duration;

    fn seal_for_test<E>(encoder: &mut E, payload: SnellBuffer) -> SnellWire
    where
        E: SnellTcpEncoder,
    {
        let mut wire = SnellWire::new();
        encoder.seal_plain(payload, &mut wire).unwrap();
        wire
    }

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

        write_plain_frame(&mut writer, b"hello").await;
        write_plain_frame(&mut writer, b"").await;

        assert_eq!(
            read_frame_vec(&mut reader).await.unwrap().unwrap(),
            b"hello"
        );
        assert!(read_frame_vec(&mut reader).await.unwrap().is_none());
    }

    #[compio::test]
    async fn reads_pending_ciphertext_after_probe() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let mut encoder = V4Encoder::new(&psk).unwrap();
        let mut wire = BytesMut::new();
        for s in seal_for_test(
            &mut encoder,
            SnellBuffer::from(BytesMut::from(&b"hello"[..])),
        )
        .into_bytes_vec()
        {
            wire.extend_from_slice(&s);
        }
        for s in seal_for_test(
            &mut encoder,
            SnellBuffer::from(BytesMut::from(&b"world"[..])),
        )
        .into_bytes_vec()
        {
            wire.extend_from_slice(&s);
        }
        for s in seal_for_test(&mut encoder, SnellBuffer::empty()).into_bytes_vec() {
            wire.extend_from_slice(&s);
        }

        let (_client, server) = tcp_pair().await;
        let (server_read, _) = server.into_split();

        // probe_snell_mode may read past the bytes it needed to identify the
        // mode. The unread ciphertext is passed to the stream reader and
        // consumed before touching the socket again.
        let decoder = V4Decoder::new(psk);
        let mut reader = SnellStreamReader::from_decoder_with_pending(server_read, decoder, wire);

        assert_eq!(
            read_frame_vec(&mut reader).await.unwrap().unwrap(),
            b"hello"
        );
        assert_eq!(
            read_frame_vec(&mut reader).await.unwrap().unwrap(),
            b"world"
        );
        assert!(read_frame_vec(&mut reader).await.unwrap().is_none());
    }

    #[compio::test]
    async fn reads_body_split_across_socket_reads() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let mut encoder = V4Encoder::new(&psk).unwrap();
        let wire: Vec<u8> = {
            let mut v = Vec::new();
            for s in seal_for_test(
                &mut encoder,
                SnellBuffer::from(BytesMut::from(&b"hello"[..])),
            )
            .into_bytes_vec()
            {
                v.extend_from_slice(&s);
            }
            v
        };
        let body_split = SALT_LEN + HEADER_CIPHER_LEN + 1;
        assert!(
            body_split < wire.len(),
            "test frame must include body bytes"
        );

        let (client, server) = tcp_pair().await;
        let (_, mut client_write) = client.into_split();
        let (server_read, _) = server.into_split();
        let mut reader: SnellStreamReader<_, V4Decoder> =
            SnellStreamReader::new::<V4Mode>(server_read, psk);

        let read = runtime::spawn(async move { read_frame_vec(&mut reader).await.unwrap() });
        client_write
            .write_all(BytesMut::from(&wire[..body_split]))
            .await
            .unwrap();
        time::sleep(Duration::from_millis(10)).await;
        client_write
            .write_all(BytesMut::from(&wire[body_split..]))
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

        assert_eq!(read_frame_vec(&mut reader).await.unwrap().unwrap(), b"x");
        assert!(read_frame_vec(&mut reader).await.unwrap().is_none());
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
                for segment in
                    seal_for_test(&mut encoder, SnellBuffer::from(BytesMut::from(payload)))
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
        R: AsyncRead + AsyncReadManaged<Buffer = BufferRef> + 'static,
        D: SnellTcpDecoder,
    {
        let Some(frame) = reader.read_plain_frame().await? else {
            return Ok(None);
        };
        Ok(Some(frame.as_slice().to_vec()))
    }

    async fn write_plain_frame<W, E>(writer: &mut SnellStreamWriter<W, E>, payload: &[u8])
    where
        W: AsyncWrite + 'static,
        E: SnellTcpEncoder,
    {
        writer
            .write_with(payload.len(), |frame| {
                frame.copy_from_slice(payload);
                Ok(payload.len())
            })
            .await
            .unwrap();
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

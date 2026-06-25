use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use std::io::IoSlice;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::protocol::snell::{
    DecodeEvent, DecodeSlot, PlainPrefix, SnellMode, SnellTcpDecoder, SnellTcpEncoder,
};

#[derive(Debug)]
pub struct SnellStreamReader<R, D> {
    inner: R,
    decoder: D,
}

#[derive(Debug)]
pub struct SnellStreamWriter<W, E> {
    inner: W,
    encoder: E,
}

#[derive(Debug)]
pub(crate) enum WriteFromState<R> {
    Reading(Option<R>),
    Flushing { eof: bool },
    Done,
}

#[derive(Debug, Default)]
pub(crate) enum WriteFrameState {
    #[default]
    Encoding,
    Flushing,
}

impl<R> Default for WriteFromState<R> {
    fn default() -> Self {
        Self::Reading(None)
    }
}

impl<R, D> SnellStreamReader<R, D>
where
    R: AsyncRead + Unpin,
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

    pub(crate) fn poll_read_next_plain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if self.decoder.has_pending_plaintext() {
            return Poll::Ready(Ok(true));
        }
        self.poll_read_frame(cx)
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

    pub(crate) fn poll_write_pending_plaintext_to<W>(
        &mut self,
        cx: &mut Context<'_>,
        writer: &mut W,
    ) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        let mut bufs = [IoSlice::new(&[]); 4];
        let nbufs = self.decoder.pending_plaintext(&mut bufs);
        if nbufs == 0 {
            return Poll::Ready(Ok(0));
        }

        let n = ready!(Pin::new(writer).poll_write_vectored(cx, &bufs[..nbufs]))?;
        if n == 0 {
            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
        }
        self.decoder.advance_plaintext(n);
        Poll::Ready(Ok(n))
    }

    pub async fn read_exact_plain(&mut self, dst: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < dst.len() {
            let copied = self.copy_pending_plaintext(&mut dst[filled..]);
            if copied != 0 {
                filled += copied;
                continue;
            }

            if !self.read_frame().await? {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell zero chunk while reading control data",
                ));
            }
        }
        Ok(())
    }

    async fn read_frame(&mut self) -> io::Result<bool> {
        loop {
            let slot = match self.decoder.next_ciphertext_slot() {
                DecodeSlot::Read(slot) => slot,
                DecodeSlot::BlockedByPlaintext => {
                    return Ok(true);
                }
            };
            let n = self.inner.read(slot).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "early eof"));
            }

            match self.decoder.commit_ciphertext(n)? {
                DecodeEvent::PlainData => return Ok(true),
                DecodeEvent::ZeroChunk => return Ok(false),
                _ => continue,
            }
        }
    }

    fn poll_read_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            let slot = match self.decoder.next_ciphertext_slot() {
                DecodeSlot::Read(slot) => slot,
                DecodeSlot::BlockedByPlaintext => {
                    return Poll::Ready(Ok(true));
                }
            };
            let mut buf = ReadBuf::new(slot);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buf))?;
            let n = buf.filled().len();
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "early eof",
                )));
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

    #[cfg(test)]
    pub(crate) async fn read_frame_vec(&mut self) -> io::Result<Option<Vec<u8>>> {
        if !self.read_frame().await? {
            return Ok(None);
        }

        let mut out = Vec::new();
        while self.decoder.has_pending_plaintext() {
            let copied = self.copy_pending_plaintext_to_vec(&mut out);
            if copied == 0 {
                break;
            }
        }
        Ok(Some(out))
    }
}

impl<W, E> SnellStreamWriter<W, E>
where
    W: AsyncWrite + Unpin,
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
                    "snell v4 encoder accepted no payload",
                ));
            }
            offset += written;
        }
        Ok(())
    }

    pub(crate) fn poll_write_from<R>(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut R,
        state: &mut WriteFromState<E::Reservation>,
    ) -> Poll<io::Result<bool>>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            match state {
                WriteFromState::Reading(reservation) => {
                    if reservation.is_none() {
                        *reservation = Some(
                            self.encoder
                                .begin_plain_reservation(PlainPrefix::none(), usize::MAX)?,
                        );
                    }

                    let n = {
                        let reservation_ref =
                            reservation.as_ref().expect("reservation just created");
                        let slot = self.encoder.plain_slot(reservation_ref);
                        let mut buf = ReadBuf::new(slot);
                        match Pin::new(&mut *reader).poll_read(cx, &mut buf) {
                            Poll::Ready(Ok(())) => buf.filled().len(),
                            Poll::Ready(Err(error)) => {
                                let reservation =
                                    reservation.take().expect("reservation just created");
                                self.encoder.cancel_plain_reservation(reservation);
                                return Poll::Ready(Err(error));
                            }
                            Poll::Pending => return Poll::Pending,
                        }
                    };

                    let reservation = reservation.take().expect("reservation just created");
                    self.encoder.finish_plain_reservation(reservation, n)?;
                    *state = WriteFromState::Flushing { eof: n == 0 };
                }
                WriteFromState::Flushing { eof } => {
                    ready!(self.poll_drain_pending(cx))?;
                    if *eof {
                        *state = WriteFromState::Done;
                        return Poll::Ready(Ok(false));
                    }
                    *state = WriteFromState::Reading(None);
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
        while self.encoder.has_pending_wire() {
            let mut pending = [IoSlice::new(&[]); 5];
            let nbufs = self.encoder.pending_wire(&mut pending);
            let n = self.inner.write_vectored(&pending[..nbufs]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell writer made no progress",
                ));
            }
            self.encoder.advance_wire(n);
        }
        self.inner.flush().await
    }

    fn poll_drain_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.encoder.has_pending_wire() {
            let mut pending = [IoSlice::new(&[]); 5];
            let nbufs = self.encoder.pending_wire(&mut pending);
            let n = ready!(Pin::new(&mut self.inner).poll_write_vectored(cx, &pending[..nbufs]))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell writer made no progress",
                )));
            }
            self.encoder.advance_wire(n);
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::snell::{V4Decoder, V4Encoder, V4Mode};

    #[tokio::test]
    async fn round_trips_payload_and_zero_chunk() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let (client, server) = tokio::io::duplex(4096);
        let (server_read, _) = tokio::io::split(server);
        let (_, client_write) = tokio::io::split(client);
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
}

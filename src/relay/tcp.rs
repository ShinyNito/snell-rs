use std::collections::VecDeque;
use std::future::Future;
use std::io;
#[cfg(unix)]
use std::io::IoSliceMut;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use pin_project_lite::pin_project;
#[cfg(unix)]
use tokio::io::Interest;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::net::TcpStream;

use crate::error::Result;
use crate::framed::{
    PayloadReadSlot, PayloadSource, PayloadWriteStatus, poll_read_payload_into_slots_fallback,
};
use crate::proxy::outbound::RelayStats;
use crate::relay::activity::RelayActivity;

const COPY_BUFFER_SIZE: usize = 64 * 1024;
#[cfg(unix)]
const TCP_PAYLOAD_READ_IOV_MAX: usize = 64;

pub(crate) struct ReadPrefixBuffer {
    chunks: VecDeque<Bytes>,
    len: usize,
}

impl ReadPrefixBuffer {
    pub(crate) const fn new() -> Self {
        Self {
            chunks: VecDeque::new(),
            len: 0,
        }
    }

    pub(crate) fn push(&mut self, payload: Bytes) {
        if payload.is_empty() {
            return;
        }
        self.len += payload.len();
        self.chunks.push_back(payload);
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn copy_to_read_buf(&mut self, out: &mut ReadBuf<'_>) {
        while out.remaining() != 0 {
            let Some(front) = self.chunks.front_mut() else {
                debug_assert_eq!(self.len, 0);
                return;
            };

            let n = front.len().min(out.remaining());
            out.put_slice(&front[..n]);
            front.advance(n);
            self.len -= n;

            if front.is_empty() {
                self.chunks.pop_front();
            }
        }
    }
}

pin_project! {
    pub(crate) struct PrefixedReadStream<T> {
        read_prefix: ReadPrefixBuffer,
        #[pin]
        inner: T,
    }
}

impl<T> PrefixedReadStream<T> {
    pub(crate) const fn new(inner: T, read_prefix: ReadPrefixBuffer) -> Self {
        Self { read_prefix, inner }
    }
}

impl<T> AsyncRead for PrefixedReadStream<T>
where
    T: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();
        if !this.read_prefix.is_empty() {
            this.read_prefix.copy_to_read_buf(out);
            return Poll::Ready(Ok(()));
        }
        this.inner.as_mut().poll_read(cx, out)
    }
}

impl<T> AsyncWrite for PrefixedReadStream<T>
where
    T: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

pub(crate) trait SnellPayloadSink: AsyncRead + AsyncWrite {
    fn poll_write_payload_from_source<R>(
        self: Pin<&mut Self>,
        source: Pin<&mut R>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<PayloadWriteStatus>>
    where
        R: PayloadSource + ?Sized;
}

impl<T> SnellPayloadSink for PrefixedReadStream<T>
where
    T: SnellPayloadSink,
{
    fn poll_write_payload_from_source<R>(
        self: Pin<&mut Self>,
        source: Pin<&mut R>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<PayloadWriteStatus>>
    where
        R: PayloadSource + ?Sized,
    {
        T::poll_write_payload_from_source(self.project().inner, source, cx)
    }
}

impl<T> SnellPayloadSink for Box<T>
where
    T: SnellPayloadSink + Unpin + ?Sized,
{
    fn poll_write_payload_from_source<R>(
        self: Pin<&mut Self>,
        source: Pin<&mut R>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<PayloadWriteStatus>>
    where
        R: PayloadSource + ?Sized,
    {
        let inner = self.get_mut().as_mut();
        // SAFETY: the boxed allocation is stable while the Box is pinned.
        let inner = unsafe { Pin::new_unchecked(inner) };
        T::poll_write_payload_from_source(inner, source, cx)
    }
}

impl<T> SnellPayloadSink for Pin<&mut T>
where
    T: SnellPayloadSink + ?Sized,
{
    fn poll_write_payload_from_source<R>(
        mut self: Pin<&mut Self>,
        source: Pin<&mut R>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<PayloadWriteStatus>>
    where
        R: PayloadSource + ?Sized,
    {
        T::poll_write_payload_from_source(self.as_mut().get_mut().as_mut(), source, cx)
    }
}

pin_project! {
    pub(crate) struct TcpRelayDriver<P, S> {
        #[pin]
        plain: P,
        #[pin]
        snell: S,
        plain_to_snell: CopyPlainIntoSnell,
        snell_to_plain: BufferedCopy,
        close_policy: TcpClosePolicy,
        activity: RelayActivity,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TcpClosePolicy {
    BothDirectionsClosed,
    EndWhenPlainToSnellClosed,
}

impl<P, S> TcpRelayDriver<P, S> {
    pub(crate) fn new(
        plain: P,
        snell: S,
        close_policy: TcpClosePolicy,
        activity: RelayActivity,
    ) -> Self {
        Self {
            plain,
            snell,
            plain_to_snell: CopyPlainIntoSnell::new(),
            snell_to_plain: BufferedCopy::new(),
            close_policy,
            activity,
        }
    }
}

impl<P, S> Future for TcpRelayDriver<P, S>
where
    P: AsyncRead + AsyncWrite + PayloadSource,
    S: SnellPayloadSink,
{
    type Output = Result<RelayStats>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let plain_to_snell = this.plain_to_snell.poll_copy(
            this.plain.as_mut(),
            this.snell.as_mut(),
            this.activity,
            cx,
        );
        let snell_to_plain = this.snell_to_plain.poll_copy(
            this.snell.as_mut(),
            this.plain.as_mut(),
            this.activity,
            cx,
        );

        match (*this.close_policy, plain_to_snell, snell_to_plain) {
            (
                TcpClosePolicy::BothDirectionsClosed,
                Poll::Ready(Ok(uploaded)),
                Poll::Ready(Ok(downloaded)),
            ) => Poll::Ready(Ok(RelayStats {
                uploaded,
                downloaded,
            })),
            (
                TcpClosePolicy::EndWhenPlainToSnellClosed,
                Poll::Ready(Ok(plain_to_snell_copied)),
                _,
            ) => Poll::Ready(Ok(RelayStats {
                uploaded: this.snell_to_plain.copied,
                downloaded: plain_to_snell_copied,
            })),
            (_, Poll::Ready(Err(err)), _) | (_, _, Poll::Ready(Err(err))) => {
                Poll::Ready(Err(err.into()))
            }
            _ => Poll::Pending,
        }
    }
}

struct BufferedCopy {
    buffer: Vec<u8>,
    consumed: usize,
    filled: usize,
    source_eof: bool,
    sink_shutdown: bool,
    copied: u64,
}

struct CopyPlainIntoSnell {
    source_eof: bool,
    sink_shutdown: bool,
    copied: u64,
}

impl CopyPlainIntoSnell {
    const fn new() -> Self {
        Self {
            source_eof: false,
            sink_shutdown: false,
            copied: 0,
        }
    }

    fn poll_copy<R, W>(
        &mut self,
        mut plain: Pin<&mut R>,
        mut snell: Pin<&mut W>,
        activity: &RelayActivity,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<u64>>
    where
        R: PayloadSource + ?Sized,
        W: SnellPayloadSink + ?Sized,
    {
        loop {
            if !self.source_eof {
                match ready!(W::poll_write_payload_from_source(
                    snell.as_mut(),
                    plain.as_mut(),
                    cx
                ))? {
                    PayloadWriteStatus::Written(n) => {
                        self.copied += n as u64;
                        activity.record();
                        continue;
                    }
                    PayloadWriteStatus::SourceEof => {
                        self.source_eof = true;
                    }
                }
            }

            if !self.sink_shutdown {
                ready!(snell.as_mut().poll_shutdown(cx))?;
                self.sink_shutdown = true;
            }
            return Poll::Ready(Ok(self.copied));
        }
    }
}

impl PayloadSource for TcpStream {
    fn poll_read_payload_into_slots(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        slots: &mut [PayloadReadSlot],
    ) -> Poll<io::Result<usize>> {
        poll_tcp_stream_read_into_slots(self, cx, slots)
    }
}

impl PayloadSource for DuplexStream {
    fn poll_read_payload_into_slots(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        slots: &mut [PayloadReadSlot],
    ) -> Poll<io::Result<usize>> {
        poll_read_payload_into_slots_fallback(self, cx, slots)
    }
}

impl<T> PayloadSource for Pin<&mut T>
where
    T: PayloadSource + ?Sized,
{
    fn poll_read_payload_into_slots(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        slots: &mut [PayloadReadSlot],
    ) -> Poll<io::Result<usize>> {
        T::poll_read_payload_into_slots(self.as_mut().get_mut().as_mut(), cx, slots)
    }
}

#[cfg(unix)]
fn poll_tcp_stream_read_into_slots(
    mut stream: Pin<&mut TcpStream>,
    cx: &mut Context<'_>,
    slots: &mut [PayloadReadSlot],
) -> Poll<io::Result<usize>> {
    if slots.iter().all(PayloadReadSlot::is_empty) {
        return Poll::Ready(Ok(0));
    }

    loop {
        ready!(stream.as_mut().poll_read_ready(cx))?;
        if slots.len() > TCP_PAYLOAD_READ_IOV_MAX {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many readv slots",
            )));
        }
        let mut read_slots: [IoSliceMut<'_>; TCP_PAYLOAD_READ_IOV_MAX] =
            std::array::from_fn(|_| IoSliceMut::new(&mut []));
        let mut read_slot_count = 0;
        for slot in slots.iter_mut().filter(|slot| !slot.is_empty()) {
            // SAFETY: the frame writer prepared each slot to point at live
            // BytesMut spare capacity for exactly `len` bytes.
            let buf = unsafe { slot.as_mut_slice() };
            read_slots[read_slot_count] = IoSliceMut::new(buf);
            read_slot_count += 1;
        }
        let stream_ref = stream.as_ref().get_ref();
        match stream.try_io(Interest::READABLE, || {
            Ok(rustix::io::retry_on_intr(|| {
                rustix::io::readv(stream_ref, &mut read_slots[..read_slot_count])
            })?)
        }) {
            Ok(n) => return Poll::Ready(Ok(n)),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) => return Poll::Ready(Err(err)),
        }
    }
}

#[cfg(not(unix))]
fn poll_tcp_stream_read_into_slots(
    stream: Pin<&mut TcpStream>,
    cx: &mut Context<'_>,
    slots: &mut [PayloadReadSlot],
) -> Poll<io::Result<usize>> {
    poll_read_payload_into_slots_fallback(stream, cx, slots)
}

impl BufferedCopy {
    fn new() -> Self {
        Self {
            buffer: vec![0; COPY_BUFFER_SIZE],
            consumed: 0,
            filled: 0,
            source_eof: false,
            sink_shutdown: false,
            copied: 0,
        }
    }

    fn poll_copy<R, W>(
        &mut self,
        mut source: Pin<&mut R>,
        mut sink: Pin<&mut W>,
        activity: &RelayActivity,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        loop {
            if self.consumed == self.filled && !self.source_eof {
                let mut out = ReadBuf::new(&mut self.buffer);
                ready!(source.as_mut().poll_read(cx, &mut out))?;
                let n = out.filled().len();
                self.consumed = 0;
                self.filled = n;
                if n == 0 {
                    self.source_eof = true;
                }
            }

            while self.consumed < self.filled {
                let n = ready!(
                    sink.as_mut()
                        .poll_write(cx, &self.buffer[self.consumed..self.filled])
                )?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write relayed tcp payload",
                    )));
                }
                self.consumed += n;
                self.copied += n as u64;
                activity.record();
            }

            if self.consumed == self.filled {
                self.consumed = 0;
                self.filled = 0;
            }

            if self.source_eof {
                if !self.sink_shutdown {
                    ready!(sink.as_mut().poll_shutdown(cx))?;
                    self.sink_shutdown = true;
                }
                return Poll::Ready(Ok(self.copied));
            }
        }
    }
}

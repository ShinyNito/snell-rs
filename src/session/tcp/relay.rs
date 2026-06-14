use std::collections::VecDeque;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::Result;
use crate::proxy::outbound::RelayStats;
use crate::session::activity::RelayActivity;

const COPY_BUFFER_SIZE: usize = 64 * 1024;

pub(crate) struct PlainUploadBatch {
    chunks: VecDeque<Bytes>,
    len: usize,
}

impl PlainUploadBatch {
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

pub(crate) struct PrefixedRead<T> {
    prefix: PlainUploadBatch,
    inner: T,
}

impl<T> PrefixedRead<T> {
    pub(crate) const fn new(inner: T, prefix: PlainUploadBatch) -> Self {
        Self { prefix, inner }
    }

    pub(crate) fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> AsyncRead for PrefixedRead<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            this.prefix.copy_to_read_buf(out);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, out)
    }
}

impl<T> AsyncWrite for PrefixedRead<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub(crate) async fn relay_bidirectional<L, R>(
    left: &mut L,
    right: &mut R,
    activity: &RelayActivity,
) -> Result<RelayStats>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let mut relay = BidirectionalRelay::new();
    let stats = poll_fn(|cx| relay.poll_until_both_closed(left, right, activity, cx)).await?;
    Ok(stats)
}

pub(crate) async fn relay_bidirectional_until_right_closed<L, R>(
    left: &mut L,
    right: &mut R,
    activity: &RelayActivity,
) -> Result<RelayStats>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let mut relay = BidirectionalRelay::new();
    let stats = poll_fn(|cx| relay.poll_until_right_closed(left, right, activity, cx)).await?;
    Ok(stats)
}

struct BidirectionalRelay {
    left_to_right: CopyDirection,
    right_to_left: CopyDirection,
}

impl BidirectionalRelay {
    fn new() -> Self {
        Self {
            left_to_right: CopyDirection::new(),
            right_to_left: CopyDirection::new(),
        }
    }

    fn poll_until_both_closed<L, R>(
        &mut self,
        left: &mut L,
        right: &mut R,
        activity: &RelayActivity,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<RelayStats>>
    where
        L: AsyncRead + AsyncWrite + Unpin,
        R: AsyncRead + AsyncWrite + Unpin,
    {
        let left_to_right = self.left_to_right.poll_copy(left, right, activity, cx);
        let right_to_left = self.right_to_left.poll_copy(right, left, activity, cx);

        match (left_to_right, right_to_left) {
            (Poll::Ready(Ok(uploaded)), Poll::Ready(Ok(downloaded))) => {
                Poll::Ready(Ok(RelayStats {
                    uploaded,
                    downloaded,
                }))
            }
            (Poll::Ready(Err(err)), _) | (_, Poll::Ready(Err(err))) => Poll::Ready(Err(err)),
            _ => Poll::Pending,
        }
    }

    fn poll_until_right_closed<L, R>(
        &mut self,
        left: &mut L,
        right: &mut R,
        activity: &RelayActivity,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<RelayStats>>
    where
        L: AsyncRead + AsyncWrite + Unpin,
        R: AsyncRead + AsyncWrite + Unpin,
    {
        let left_to_right = self.left_to_right.poll_copy(left, right, activity, cx);
        let right_to_left = self.right_to_left.poll_copy(right, left, activity, cx);

        match (left_to_right, right_to_left) {
            (_, Poll::Ready(Ok(downloaded))) => Poll::Ready(Ok(RelayStats {
                uploaded: self.left_to_right.total,
                downloaded,
            })),
            (Poll::Ready(Err(err)), _) | (_, Poll::Ready(Err(err))) => Poll::Ready(Err(err)),
            _ => Poll::Pending,
        }
    }
}

struct CopyDirection {
    buffer: Vec<u8>,
    pos: usize,
    cap: usize,
    read_done: bool,
    shutdown_done: bool,
    total: u64,
}

impl CopyDirection {
    fn new() -> Self {
        Self {
            buffer: vec![0; COPY_BUFFER_SIZE],
            pos: 0,
            cap: 0,
            read_done: false,
            shutdown_done: false,
            total: 0,
        }
    }

    fn poll_copy<R, W>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        activity: &RelayActivity,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            if self.pos == self.cap && !self.read_done {
                let mut out = ReadBuf::new(&mut self.buffer);
                ready!(Pin::new(&mut *reader).poll_read(cx, &mut out))?;
                let n = out.filled().len();
                self.pos = 0;
                self.cap = n;
                if n == 0 {
                    self.read_done = true;
                }
            }

            while self.pos < self.cap {
                let n = ready!(
                    Pin::new(&mut *writer).poll_write(cx, &self.buffer[self.pos..self.cap])
                )?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write relayed tcp payload",
                    )));
                }
                self.pos += n;
                self.total += n as u64;
                activity.record();
            }

            if self.pos == self.cap {
                self.pos = 0;
                self.cap = 0;
            }

            if self.read_done {
                if !self.shutdown_done {
                    ready!(Pin::new(&mut *writer).poll_shutdown(cx))?;
                    self.shutdown_done = true;
                }
                return Poll::Ready(Ok(self.total));
            }
        }
    }
}

use std::future::poll_fn;
use std::io::IoSlice;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::Result;

use super::{
    STREAM_BUFFER_INITIAL_CAPACITY, STREAM_BUFFER_RETAIN_CAPACITY, STREAM_READ_AHEAD_CAPACITY,
};

pub(super) async fn write_all_vectored<W>(
    writer: &mut W,
    mut first: &[u8],
    mut second: &[u8],
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    poll_fn(|cx| {
        while !first.is_empty() || !second.is_empty() {
            let n = if first.is_empty() {
                let bufs = [IoSlice::new(second)];
                match Pin::new(&mut *writer).poll_write_vectored(cx, &bufs) {
                    Poll::Ready(result) => result?,
                    Poll::Pending => return Poll::Pending,
                }
            } else if second.is_empty() {
                let bufs = [IoSlice::new(first)];
                match Pin::new(&mut *writer).poll_write_vectored(cx, &bufs) {
                    Poll::Ready(result) => result?,
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                let bufs = [IoSlice::new(first), IoSlice::new(second)];
                match Pin::new(&mut *writer).poll_write_vectored(cx, &bufs) {
                    Poll::Ready(result) => result?,
                    Poll::Pending => return Poll::Pending,
                }
            };

            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write snell frame",
                )
                .into()));
            }

            if n < first.len() {
                first = &first[n..];
            } else {
                let rest = n - first.len();
                first = &[];
                second = &second[rest.min(second.len())..];
            }
        }

        Poll::Ready(Ok(()))
    })
    .await
}

pub(super) fn poll_write_all_vectored<W>(
    writer: &mut W,
    cx: &mut Context<'_>,
    first: &mut BytesMut,
    second: &mut BytesMut,
) -> Poll<Result<()>>
where
    W: AsyncWrite + Unpin,
{
    while !first.is_empty() || !second.is_empty() {
        let n = if first.is_empty() {
            let bufs = [IoSlice::new(second)];
            ready!(Pin::new(&mut *writer).poll_write_vectored(cx, &bufs))?
        } else if second.is_empty() {
            let bufs = [IoSlice::new(first)];
            ready!(Pin::new(&mut *writer).poll_write_vectored(cx, &bufs))?
        } else {
            let bufs = [IoSlice::new(first), IoSlice::new(second)];
            ready!(Pin::new(&mut *writer).poll_write_vectored(cx, &bufs))?
        };

        if n == 0 {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "failed to write snell frame",
            )
            .into()));
        }

        if n < first.len() {
            first.advance(n);
        } else {
            let rest = n - first.len();
            first.clear();
            second.advance(rest.min(second.len()));
        }
    }

    Poll::Ready(Ok(()))
}

/// Like `poll_read_into_spare`, but offers the reader the whole spare capacity
/// up to the stream read-ahead budget instead of an exact byte count, so one
/// syscall can pull in bytes of several frames.
pub(super) fn poll_read_ahead_into_spare<R>(
    reader: &mut R,
    cx: &mut Context<'_>,
    buffer: &mut BytesMut,
    min_spare: usize,
) -> Poll<Result<usize>>
where
    R: AsyncRead + Unpin,
{
    poll_read_ahead_into_spare_with_capacity(
        reader,
        cx,
        buffer,
        min_spare,
        STREAM_READ_AHEAD_CAPACITY,
    )
}

pub(crate) fn poll_read_ahead_into_spare_with_capacity<R>(
    reader: &mut R,
    cx: &mut Context<'_>,
    buffer: &mut BytesMut,
    min_spare: usize,
    read_ahead_capacity: usize,
) -> Poll<Result<usize>>
where
    R: AsyncRead + Unpin,
{
    let desired_spare = min_spare.max(read_ahead_capacity.saturating_sub(buffer.len()));
    if desired_spare == 0 {
        return Poll::Ready(Ok(0));
    }
    if buffer.chunk_mut().len() < desired_spare {
        buffer.reserve(desired_spare);
    }

    let read_len = buffer.chunk_mut().len().min(desired_spare);
    poll_read_into_spare(reader, cx, buffer, read_len)
}

pub(super) fn poll_read_into_spare<R>(
    reader: &mut R,
    cx: &mut Context<'_>,
    buffer: &mut BytesMut,
    read_len: usize,
) -> Poll<Result<usize>>
where
    R: AsyncRead + Unpin,
{
    debug_assert!(buffer.chunk_mut().len() >= read_len);

    // SAFETY: `chunk_mut` exposes only BytesMut's spare capacity. `ReadBuf`
    // tracks exactly which bytes the AsyncRead implementation initializes.
    let spare = unsafe { buffer.chunk_mut().as_uninit_slice_mut() };
    let mut read_buf = ReadBuf::uninit(&mut spare[..read_len]);

    match Pin::new(reader).poll_read(cx, &mut read_buf) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(())) => {
            let read_len = read_buf.filled().len();
            // SAFETY: `read_len` comes from `ReadBuf::filled`, so these bytes
            // are initialized and lie within the spare slice handed to poll_read.
            unsafe {
                buffer.advance_mut(read_len);
            }
            Poll::Ready(Ok(read_len))
        }
        Poll::Ready(Err(err)) => Poll::Ready(Err(err.into())),
    }
}

pub(super) fn compact_stream_buffer_for_reuse(buffer: &mut BytesMut) {
    buffer.clear();
    if buffer.capacity() > STREAM_BUFFER_RETAIN_CAPACITY {
        *buffer = BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY);
    }
}

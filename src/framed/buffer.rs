use std::future::poll_fn;
use std::io::IoSlice;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{Error, Result};

use super::{STREAM_BUFFER_INITIAL_CAPACITY, STREAM_BUFFER_RETAIN_CAPACITY};

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

pub(super) fn poll_read_into_spare<R>(
    reader: &mut R,
    cx: &mut Context<'_>,
    buffer: &mut BytesMut,
    read_limit: usize,
) -> Poll<Result<usize>>
where
    R: AsyncRead + Unpin,
{
    let spare_len = buffer.chunk_mut().len();
    if spare_len < read_limit {
        buffer.reserve(read_limit);
    }

    let spare = buffer.chunk_mut();
    if spare.len() < read_limit {
        return Poll::Ready(Err(Error::PayloadTooLarge));
    }

    // Same boundary Tokio's read_buf uses: poll_read may initialize only the
    // unfilled tail we hand to ReadBuf.
    let spare = unsafe { spare.as_uninit_slice_mut() };
    let mut read_buf = ReadBuf::uninit(&mut spare[..read_limit]);

    match Pin::new(reader).poll_read(cx, &mut read_buf) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(())) => {
            let read_len = read_buf.filled().len();
            // ReadBuf reports exactly how many bytes poll_read initialized in
            // BytesMut's spare capacity.
            unsafe {
                buffer.advance_mut(read_len);
            }
            Poll::Ready(Ok(read_len))
        }
        Poll::Ready(Err(err)) => Poll::Ready(Err(err.into())),
    }
}

/// Like `poll_read_into_spare`, but offers the reader the whole spare capacity
/// (at least `min_spare`) instead of an exact byte count, so one syscall can
/// pull in bytes of several frames.
pub(super) fn poll_read_ahead_into_spare<R>(
    reader: &mut R,
    cx: &mut Context<'_>,
    buffer: &mut BytesMut,
    min_spare: usize,
) -> Poll<Result<usize>>
where
    R: AsyncRead + Unpin,
{
    let spare_len = buffer.chunk_mut().len();
    if spare_len < min_spare {
        buffer.reserve(min_spare);
    }

    // Same boundary Tokio's read_buf uses: poll_read may initialize only the
    // unfilled tail we hand to ReadBuf.
    let spare = unsafe { buffer.chunk_mut().as_uninit_slice_mut() };
    let mut read_buf = ReadBuf::uninit(spare);

    match Pin::new(reader).poll_read(cx, &mut read_buf) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(())) => {
            let read_len = read_buf.filled().len();
            // ReadBuf reports exactly how many bytes poll_read initialized in
            // BytesMut's spare capacity.
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

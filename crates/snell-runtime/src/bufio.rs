#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BufMut;

use snell_protocol::{EncodeBuffer, RecvBuffer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::SessionError;

pub(crate) async fn read_into_recv<R: AsyncRead + Unpin>(
    reader: &mut R,
    recv: &mut RecvBuffer,
) -> Result<usize, SessionError> {
    poll_fn(|cx| poll_recv(cx, reader, recv, recv.len() + 1)).await
}

pub(crate) fn poll_recv<R: AsyncRead + Unpin>(
    cx: &mut Context<'_>,
    reader: &mut R,
    recv: &mut RecvBuffer,
    minimum: usize,
) -> Poll<Result<usize, SessionError>> {
    if let Err(error) = recv.spare_capacity_mut(minimum.saturating_sub(recv.len()).max(1)) {
        return Poll::Ready(Err(error.into()));
    }
    poll_read_buf(cx, reader, recv).map_err(SessionError::from)
}

/// Keep initialized-length advancement next to the ReadBuf that proves it.
pub(crate) fn poll_read_buf<R: AsyncRead + Unpin, B: BufMut>(
    cx: &mut Context<'_>,
    reader: &mut R,
    dst: &mut B,
) -> Poll<io::Result<usize>> {
    let n = {
        // SAFETY: ReadBuf never de-initializes the exposed spare capacity.
        let spare = unsafe { dst.chunk_mut().as_uninit_slice_mut() };
        let mut buf = ReadBuf::uninit(spare);
        match Pin::new(reader).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(())) => buf.filled().len(),
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
    };
    // SAFETY: n was obtained from ReadBuf::filled(), on this exact chunk.
    unsafe { dst.advance_mut(n) };
    Poll::Ready(Ok(n))
}

pub(crate) async fn drain_encode<W: AsyncWrite + Unpin>(
    writer: &mut W,
    encode: &mut EncodeBuffer,
) -> Result<(), SessionError> {
    while !encode.is_empty() {
        let n = poll_fn(|cx| Pin::new(&mut *writer).poll_write(cx, encode.pending())).await?;
        if n == 0 {
            return Err(SessionError::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                "encode write returned zero",
            )));
        }
        encode.advance(n)?;
    }
    Ok(())
}

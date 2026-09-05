#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::Poll;

use snell_protocol::{EncodeBuffer, RecvBuffer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::SessionError;

/// The one runtime boundary that turns I/O initialization into BufMut progress.
/// Both the receive buffer and record slots use this exact adapter.
pub(crate) fn poll_read_buf<R: AsyncRead + Unpin, B: bytes::BufMut>(
    reader: &mut R,
    buf: &mut B,
    cx: &mut std::task::Context<'_>,
) -> Poll<Result<usize, SessionError>> {
    if !buf.has_remaining_mut() {
        return Poll::Ready(Err(snell_protocol::Error::PayloadTooLarge.into()));
    }
    let n = {
        let chunk = buf.chunk_mut();
        // SAFETY: ReadBuf never de-initializes memory, including on Pending/error.
        let mut read = ReadBuf::uninit(unsafe { chunk.as_uninit_slice_mut() });
        std::task::ready!(Pin::new(reader).poll_read(cx, &mut read))?;
        read.filled().len()
    };
    // SAFETY: ReadBuf::filled proves these exact bytes in chunk_mut were initialized.
    unsafe { buf.advance_mut(n) };
    Poll::Ready(Ok(n))
}

pub(crate) async fn read_into_recv<R: AsyncRead + Unpin>(
    reader: &mut R,
    recv: &mut RecvBuffer,
) -> Result<usize, SessionError> {
    poll_fn(|cx| poll_read_buf(reader, recv, cx)).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use snell_protocol::{FixedClock, Psk, RepeatEntropy, V4Encoder};
    use std::task::{Context, Waker};

    #[test]
    fn short_read_commits_only_initialized_bytes_and_cancel_rolls_back() {
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let mut encoder = V4Encoder::with_salt(
            &psk,
            [7; 16],
            0,
            RepeatEntropy { byte: 0x3c },
            FixedClock::new(0),
        )
        .unwrap();
        let mut out = EncodeBuffer::new(snell_protocol::V6_WIRE_CAP);
        let mut slot = encoder.reserve(&mut out, &[], 1024).unwrap();
        let mut input = &b"abc"[..];
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            poll_read_buf(&mut input, &mut slot, &mut cx),
            Poll::Ready(Ok(3))
        ));
        // A cancelled read does not commit a record or advance its nonce.
        drop(slot);
        assert!(out.is_empty());
        let mut recv = RecvBuffer::new(8192);
        let mut input = &b"xyz"[..];
        assert!(matches!(
            poll_read_buf(&mut input, &mut recv, &mut cx),
            Poll::Ready(Ok(3))
        ));
        assert_eq!(recv.filled(), b"xyz");
        assert!(matches!(
            poll_read_buf(&mut input, &mut recv, &mut cx),
            Poll::Ready(Ok(0))
        ));
        assert_eq!(recv.filled(), b"xyz");
    }
}

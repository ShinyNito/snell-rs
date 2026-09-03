use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::Poll;

use snell_protocol::{EncodeBuffer, RecvBuffer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::SessionError;

pub(crate) async fn read_into_recv<R: AsyncRead + Unpin>(
    reader: &mut R,
    recv: &mut RecvBuffer,
) -> Result<usize, SessionError> {
    let n = poll_fn(|cx| {
        let spare = match recv.spare_capacity_mut(1) {
            Ok(spare) => spare,
            Err(error) => return Poll::Ready(Err(SessionError::from(error))),
        };
        let mut buf = ReadBuf::uninit(spare);
        match Pin::new(&mut *reader).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.filled().len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(SessionError::Io(error))),
            Poll::Pending => Poll::Pending,
        }
    })
    .await?;
    recv.commit_init(n)?;
    Ok(n)
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

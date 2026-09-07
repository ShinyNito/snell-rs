#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::future::poll_fn;
use std::io;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::task::{Context, Poll};

use snell_protocol::{Result, V4Reservation, V6ShapedReservation, V6UnshapedReservation};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::buffer::{BufferPool, PooledBuffer};
use crate::error::SessionError;
use std::sync::Arc;

/// Socket readiness avoids leasing/preparing a record only to discover Pending.
/// Both owned handshake streams and borrowed relay halves use Tokio's readiness.
pub(crate) trait ReadReady: AsyncRead {
    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}
impl ReadReady for tokio::net::TcpStream {
    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_read_ready(cx)
    }
}
impl ReadReady for tokio::net::tcp::ReadHalf<'_> {
    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.as_ref().poll_read_ready(cx)
    }
}

pub(crate) const READ_WINDOW: usize = snell_protocol::V6_WIRE_CAP;

/// Filled bytes and the initialization commit stay in the same audited poll.
/// Only incomplete input retains a lease across Pending.
pub(crate) fn poll_read_into<R: ReadReady + Unpin>(
    reader: &mut R,
    recv: &mut PooledBuffer,
    minimum: usize,
    window: usize,
    cx: &mut Context<'_>,
) -> Poll<std::result::Result<usize, SessionError>> {
    recv.release_empty();
    match reader.poll_ready(cx) {
        Poll::Ready(Ok(())) => {}
        Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
        Poll::Pending => return Poll::Pending,
    }
    let needed = minimum
        .max(recv.len().saturating_add(1))
        .max(window.min(recv.max()));
    if let Err(e) = recv.ensure(needed) {
        return Poll::Ready(Err(e));
    }
    let missing = minimum.saturating_sub(recv.len()).max(1);
    let spare = match recv.spare_capacity_mut(missing) {
        Ok(spare) => spare,
        Err(e) => return Poll::Ready(Err(e.into())),
    };
    let mut buf = ReadBuf::uninit(spare);
    match Pin::new(reader).poll_read(cx, &mut buf) {
        Poll::Ready(Ok(())) => {
            let n = buf.filled().len();
            // SAFETY: ReadBuf exposes only the bytes initialized by poll_read.
            Poll::Ready(unsafe { recv.commit(n) }.map(|()| n).map_err(Into::into))
        }
        Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
        Poll::Pending => {
            recv.release_empty();
            Poll::Pending
        }
    }
}

pub(crate) async fn read_into_recv<R: ReadReady + Unpin>(
    reader: &mut R,
    recv: &mut PooledBuffer,
    minimum: usize,
) -> std::result::Result<usize, SessionError> {
    poll_fn(|cx| poll_read_into(reader, recv, minimum, 4096, cx)).await
}

pub(crate) fn poll_read_record<R: ReadReady + Unpin, T: TcpReservation>(
    reader: &mut R,
    mut reservation: T,
    cx: &mut Context<'_>,
) -> Poll<std::result::Result<usize, SessionError>> {
    let mut buf = ReadBuf::uninit(reservation.payload_uninit());
    match Pin::new(reader).poll_read(cx, &mut buf) {
        Poll::Ready(Ok(())) => {
            let n = buf.filled().len();
            if n != 0 {
                // SAFETY: this reservation supplied the slot just filled by ReadBuf.
                if let Err(e) = unsafe { reservation.seal_init(n) } {
                    return Poll::Ready(Err(e.into()));
                }
            }
            Poll::Ready(Ok(n))
        }
        Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
        Poll::Pending => Poll::Pending,
    }
}

pub(crate) async fn drain_encode<W: AsyncWrite + Unpin>(
    writer: &mut W,
    encode: &mut PooledBuffer,
) -> std::result::Result<(), SessionError> {
    while !encode.is_empty() {
        let n = poll_fn(|cx| Pin::new(&mut *writer).poll_write(cx, encode.filled())).await?;
        if n == 0 {
            return Err(
                io::Error::new(io::ErrorKind::WriteZero, "encode write returned zero").into(),
            );
        }
        encode.consume(n)?;
    }
    encode.release_empty();
    Ok(())
}
pub(crate) trait TcpReservation {
    fn payload_mut(&mut self) -> &mut [u8];
    /// Uninitialized payload slot; pair with [`Self::seal_init`] after filling
    /// a prefix through `ReadBuf::uninit`. Do not mix with `payload_mut`.
    fn payload_uninit(&mut self) -> &mut [MaybeUninit<u8>];
    fn seal(self, written: usize) -> Result<()>;
    /// Seal after initializing `written` bytes of [`Self::payload_uninit`].
    unsafe fn seal_init(self, written: usize) -> Result<()>;
}

impl TcpReservation for V4Reservation<'_> {
    fn payload_mut(&mut self) -> &mut [u8] {
        V4Reservation::payload_mut(self)
    }

    fn payload_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        V4Reservation::payload_uninit(self)
    }

    fn seal(self, written: usize) -> Result<()> {
        V4Reservation::seal(self, written)
    }

    unsafe fn seal_init(self, written: usize) -> Result<()> {
        unsafe { V4Reservation::seal_init(self, written) }
    }
}

impl TcpReservation for V6ShapedReservation<'_> {
    fn payload_mut(&mut self) -> &mut [u8] {
        V6ShapedReservation::payload_mut(self)
    }

    fn payload_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        V6ShapedReservation::payload_uninit(self)
    }

    fn seal(self, written: usize) -> Result<()> {
        V6ShapedReservation::seal(self, written)
    }

    unsafe fn seal_init(self, written: usize) -> Result<()> {
        unsafe { V6ShapedReservation::seal_init(self, written) }
    }
}

impl TcpReservation for V6UnshapedReservation<'_> {
    fn payload_mut(&mut self) -> &mut [u8] {
        V6UnshapedReservation::payload_mut(self)
    }

    fn payload_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        V6UnshapedReservation::payload_uninit(self)
    }

    fn seal(self, written: usize) -> Result<()> {
        V6UnshapedReservation::seal(self, written)
    }

    unsafe fn seal_init(self, written: usize) -> Result<()> {
        unsafe { V6UnshapedReservation::seal_init(self, written) }
    }
}

pub(crate) async fn recv_datagram(
    socket: &tokio::net::UdpSocket,
    buffers: &Arc<BufferPool>,
) -> std::result::Result<(PooledBuffer, std::net::SocketAddr), SessionError> {
    poll_fn(|cx| {
        match socket.poll_recv_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
            Poll::Pending => return Poll::Pending,
        }
        let mut buffer = buffers.get(snell_protocol::UDP_DATAGRAM_MAX);
        if let Err(error) = buffer.ensure(snell_protocol::UDP_DATAGRAM_MAX) {
            return Poll::Ready(Err(error));
        }
        poll_recv_datagram(socket, &mut buffer, cx).map(|result| result.map(|peer| (buffer, peer)))
    })
    .await
}

pub(crate) fn poll_recv_datagram(
    socket: &tokio::net::UdpSocket,
    recv: &mut PooledBuffer,
    cx: &mut Context<'_>,
) -> Poll<std::result::Result<std::net::SocketAddr, SessionError>> {
    let spare = match recv.spare_capacity_mut(1) {
        Ok(s) => s,
        Err(e) => return Poll::Ready(Err(e.into())),
    };
    let mut read = ReadBuf::uninit(spare);
    match socket.poll_recv_from(cx, &mut read) {
        Poll::Ready(Ok(peer)) => {
            let n = read.filled().len();
            // SAFETY: the datagram was written into this exact spare slice.
            Poll::Ready(unsafe { recv.commit(n) }.map(|()| peer).map_err(Into::into))
        }
        Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
        Poll::Pending => Poll::Pending,
    }
}

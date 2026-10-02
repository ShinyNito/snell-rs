#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Buf;
use snell_protocol::{RecordEncoder, Reservation};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::UdpSocket;

use crate::buffer::{BufferPool, PooledBuffer};
use crate::error::SessionError;

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
    let Poll::Ready(ready) = reader.poll_ready(cx) else {
        recv.release_empty();
        return Poll::Pending;
    };
    ready?;
    let needed = minimum
        .max(recv.len().saturating_add(1))
        .max(window.min(recv.max()));
    recv.ensure(needed)?;
    let missing = minimum.saturating_sub(recv.len()).max(1);
    let mut buf = ReadBuf::uninit(recv.spare_capacity_mut(missing)?);
    let Poll::Ready(read) = Pin::new(reader).poll_read(cx, &mut buf) else {
        recv.release_empty();
        return Poll::Pending;
    };
    read?;
    let n = buf.filled().len();
    // SAFETY: ReadBuf exposes only the bytes initialized by poll_read.
    unsafe { recv.commit(n) }?;
    Poll::Ready(Ok(n))
}

pub(crate) async fn read_into_recv<R: ReadReady + Unpin>(
    reader: &mut R,
    recv: &mut PooledBuffer,
    minimum: usize,
) -> std::result::Result<usize, SessionError> {
    poll_fn(|cx| poll_read_into(reader, recv, minimum, 4096, cx)).await
}

pub(crate) fn poll_read_record<R: ReadReady + Unpin, E: RecordEncoder>(
    reader: &mut R,
    mut reservation: Reservation<'_, E>,
    cx: &mut Context<'_>,
) -> Poll<std::result::Result<(usize, usize), SessionError>> {
    let mut buf = ReadBuf::uninit(reservation.payload_uninit());
    ready!(Pin::new(reader).poll_read(cx, &mut buf))?;
    let n = buf.filled().len();
    let split = if n == 0 {
        0
    } else {
        // SAFETY: this reservation supplied the slot just filled by ReadBuf.
        unsafe { reservation.seal_init(n) }?
    };
    Poll::Ready(Ok((n, split)))
}

/// Write the whole encode batch in wire order, `[split..]` then `[..split]`
/// (vectored where the writer supports it), then return the lease.
pub(crate) async fn drain_encode<W: AsyncWrite + Unpin>(
    writer: &mut W,
    encode: &mut PooledBuffer,
    split: usize,
) -> std::result::Result<(), SessionError> {
    let (head, tail) = encode.filled().split_at(split);
    writer.write_all_buf(&mut tail.chain(head)).await?;
    let len = encode.len();
    encode.consume(len)?;
    encode.release_empty();
    Ok(())
}

/// Lease a datagram buffer only once the socket is readable.
pub(crate) async fn recv_datagram(
    socket: &UdpSocket,
    buffers: &Arc<BufferPool>,
) -> std::result::Result<(PooledBuffer, SocketAddr), SessionError> {
    poll_fn(|cx| {
        ready!(socket.poll_recv_ready(cx))?;
        let mut buffer = buffers.get(snell_protocol::UDP_DATAGRAM_MAX);
        buffer.ensure(snell_protocol::UDP_DATAGRAM_MAX)?;
        let peer = ready!(poll_recv_datagram(socket, &mut buffer, cx))?;
        Poll::Ready(Ok((buffer, peer)))
    })
    .await
}

pub(crate) fn poll_recv_datagram(
    socket: &UdpSocket,
    recv: &mut PooledBuffer,
    cx: &mut Context<'_>,
) -> Poll<std::result::Result<SocketAddr, SessionError>> {
    let mut read = ReadBuf::uninit(recv.spare_capacity_mut(1)?);
    let peer = ready!(socket.poll_recv_from(cx, &mut read))?;
    let n = read.filled().len();
    // SAFETY: the datagram was written into this exact spare slice.
    unsafe { recv.commit(n) }?;
    Poll::Ready(Ok(peer))
}

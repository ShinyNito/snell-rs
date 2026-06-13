use std::future::poll_fn;
use std::net::{IpAddr, SocketAddr};
use std::task::Poll;
use std::time::Instant;

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::error::{Error, Result};
use crate::protocol::crypto::AEAD_TAG_SIZE;
#[cfg(test)]
use crate::protocol::crypto::SALT_SIZE;
use crate::protocol::header::{COMMAND_TUNNEL, write_tcp_request_header, write_udp_request_header};
use crate::protocol::request::{write_error_reply, write_pong_reply, write_tunnel_reply};
#[cfg(test)]
use crate::protocol::udp::write_udp_request_prefix;
use crate::protocol::udp::{AddressRef, write_udp_response_prefix};
use crate::protocol::v4::frame::V4FrameEncoder;
use crate::protocol::v6::{V6ChunkSizer, V6FrameEncoder};
use crate::{MAX_PACKET_SIZE, MAX_V6_RECORD_PAYLOAD_LEN, ProtocolVersion};

use super::buffer::{
    compact_stream_buffer_for_reuse, poll_read_into_prepared_spare, write_all_vectored,
};
use super::{
    FRAME_HEAD_INITIAL_CAPACITY, STREAM_BUFFER_INITIAL_CAPACITY, STREAM_BUFFER_RETAIN_CAPACITY,
    TCP_FIRST_RECORD_OVERHEAD, TCP_RECORD_IDLE_TIMEOUT, TCP_RECORD_MSS, TCP_STEADY_RECORD_OVERHEAD,
};

mod v4;
mod v6;

pub(super) use v4::V4StreamWriter;
pub(super) use v6::V6StreamWriter;

pub(super) struct RecordSizer {
    pub(super) initial_padding_len: usize,
    pub(super) last_limit: usize,
    pub(super) last_record_at: Option<Instant>,
}

impl RecordSizer {
    pub(super) const fn new(initial_padding_len: usize) -> Self {
        Self {
            initial_padding_len,
            last_limit: 0,
            last_record_at: None,
        }
    }

    pub(super) fn next_limit(&mut self, now: Instant) -> usize {
        let limit = self.peek_limit(now);
        self.commit_limit(now, limit);
        limit
    }

    fn peek_limit(&self, now: Instant) -> usize {
        match self.last_record_at {
            None => TCP_RECORD_MSS
                .saturating_sub(TCP_FIRST_RECORD_OVERHEAD)
                .saturating_sub(self.initial_padding_len)
                .max(1),
            Some(last) if now.duration_since(last) > TCP_RECORD_IDLE_TIMEOUT => {
                steady_record_limit()
            }
            Some(_) => self
                .last_limit
                .saturating_add(steady_record_limit())
                .min(MAX_PACKET_SIZE),
        }
    }

    pub(super) fn commit_limit(&mut self, now: Instant, limit: usize) {
        self.last_limit = limit;
        self.last_record_at = Some(now);
    }
}

const fn steady_record_limit() -> usize {
    TCP_RECORD_MSS - TCP_STEADY_RECORD_OVERHEAD
}

struct ReaderPayloadFrame {
    payload_len: usize,
    read_len: usize,
    limit: usize,
}

#[inline]
fn prepare_payload_frame_from_buffer(
    source: &mut BytesMut,
    payload: &mut BytesMut,
    prefix: &[u8],
    limit: usize,
) -> Result<Option<ReaderPayloadFrame>> {
    let prefix_len = prefix.len();
    let Some(read_limit) = limit.checked_sub(prefix_len).filter(|limit| *limit != 0) else {
        payload.clear();
        return Err(Error::PayloadTooLarge);
    };

    if source.is_empty() {
        payload.clear();
        return Ok(None);
    }

    let read_len = source.len().min(read_limit);
    let payload_len = prefix_len + read_len;

    payload.clear();
    let required_capacity = payload_len + AEAD_TAG_SIZE;
    if payload.capacity() < required_capacity {
        payload.reserve(required_capacity);
    }
    if !prefix.is_empty() {
        payload.extend_from_slice(prefix);
    }
    payload.extend_from_slice(&source[..read_len]);
    source.advance(read_len);

    Ok(Some(ReaderPayloadFrame {
        payload_len,
        read_len,
        limit,
    }))
}

#[inline]
fn poll_read_payload_frame_from_reader<R>(
    plain: &mut R,
    cx: &mut std::task::Context<'_>,
    payload: &mut BytesMut,
    prefix: &[u8],
    limit: usize,
) -> Poll<Result<Option<ReaderPayloadFrame>>>
where
    R: AsyncRead + Unpin,
{
    let prefix_len = prefix.len();
    let Some(read_limit) = limit.checked_sub(prefix_len).filter(|limit| *limit != 0) else {
        payload.clear();
        return Poll::Ready(Err(Error::PayloadTooLarge));
    };

    payload.clear();

    let required_capacity = prefix_len + read_limit + AEAD_TAG_SIZE;
    if payload.capacity() < required_capacity {
        payload.reserve(required_capacity);
    }

    if !prefix.is_empty() {
        payload.extend_from_slice(prefix);
    }

    match poll_read_into_prepared_spare(plain, cx, payload, read_limit) {
        Poll::Pending => {
            payload.clear();
            Poll::Pending
        }
        Poll::Ready(Ok(read_len)) => {
            if read_len == 0 {
                payload.clear();
                return Poll::Ready(Ok(None));
            }
            Poll::Ready(Ok(Some(ReaderPayloadFrame {
                payload_len: prefix_len + read_len,
                read_len,
                limit,
            })))
        }
        Poll::Ready(Err(err)) => {
            payload.clear();
            Poll::Ready(Err(err))
        }
    }
}

#[derive(Clone, Copy)]
enum UdpResponseIpVersion {
    V4,
    V6,
}

impl UdpResponseIpVersion {
    const fn prefix_len(self) -> usize {
        match self {
            Self::V4 => 1 + 4 + 2,
            Self::V6 => 1 + 16 + 2,
        }
    }

    const fn matches(self, ip: IpAddr) -> bool {
        matches!(
            (self, ip),
            (Self::V4, IpAddr::V4(_)) | (Self::V6, IpAddr::V6(_))
        )
    }
}

pub(crate) enum SnellStreamWriter<W> {
    V4 {
        writer: Box<V4StreamWriter<W>>,
        version: ProtocolVersion,
    },
    V6(Box<V6StreamWriter<W>>),
}

impl<W> SnellStreamWriter<W>
where
    W: AsyncWrite + Unpin,
{
    pub(crate) fn new(inner: W, psk: &[u8], version: ProtocolVersion) -> Result<Self> {
        if version.uses_v6_frames() {
            Ok(Self::V6(Box::new(V6StreamWriter::new(inner, psk)?)))
        } else {
            Ok(Self::V4 {
                writer: Box::new(V4StreamWriter::new(inner, psk)?),
                version,
            })
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_v6_salt(inner: W, psk: &[u8], salt: [u8; SALT_SIZE]) -> Result<Self> {
        Ok(Self::V6(Box::new(V6StreamWriter::new_with_salt(
            inner, psk, salt,
        )?)))
    }

    pub(crate) async fn write_next_payload_record_from_reader<R>(
        &mut self,
        plain: &mut R,
    ) -> Result<Option<usize>>
    where
        R: AsyncRead + Unpin,
    {
        match self {
            Self::V4 { writer, .. } => writer.write_next_payload_record_from_reader(plain).await,
            Self::V6(writer) => writer.write_next_payload_record_from_reader(plain).await,
        }
    }

    pub(crate) async fn write_payload_from_buffer(
        &mut self,
        plain: &mut BytesMut,
    ) -> Result<Option<usize>> {
        match self {
            Self::V4 { writer, .. } => writer.write_payload_from_buffer(plain).await,
            Self::V6(writer) => writer.write_payload_from_buffer(plain).await,
        }
    }

    pub(crate) async fn write_tunnel_reply_from_buffer(
        &mut self,
        plain: &mut BytesMut,
    ) -> Result<Option<usize>> {
        match self {
            Self::V4 { writer, .. } => writer.write_tunnel_reply_from_buffer(plain).await,
            Self::V6(writer) => writer.write_tunnel_reply_from_buffer(plain).await,
        }
    }

    pub(crate) async fn write_tcp_request(
        &mut self,
        host: &str,
        port: u16,
        reuse: bool,
    ) -> Result<()> {
        match self {
            Self::V4 { writer, version } => {
                writer.write_tcp_request(host, port, *version, reuse).await
            }
            Self::V6(writer) => writer.write_tcp_request(host, port, reuse).await,
        }
    }

    pub(crate) async fn write_udp_request(&mut self) -> Result<()> {
        match self {
            Self::V4 { writer, version } => writer.write_udp_request(*version).await,
            Self::V6(writer) => writer.write_udp_request().await,
        }
    }

    pub(crate) async fn try_write_ipv4_udp_response_from_socket(
        &mut self,
        socket: &UdpSocket,
    ) -> Result<Option<(usize, SocketAddr)>> {
        match self {
            Self::V4 { writer, .. } => writer.try_write_ipv4_udp_response_from_socket(socket).await,
            Self::V6(writer) => writer.try_write_ipv4_udp_response_from_socket(socket).await,
        }
    }

    pub(crate) async fn try_write_ipv6_udp_response_from_socket(
        &mut self,
        socket: &UdpSocket,
    ) -> Result<Option<(usize, SocketAddr)>> {
        match self {
            Self::V4 { writer, .. } => writer.try_write_ipv6_udp_response_from_socket(socket).await,
            Self::V6(writer) => writer.try_write_ipv6_udp_response_from_socket(socket).await,
        }
    }

    pub(crate) fn start_payload_frame(&mut self) -> &mut BytesMut {
        match self {
            Self::V4 { writer, .. } => writer.start_payload_frame(),
            Self::V6(writer) => writer.start_payload_frame(),
        }
    }

    // One UDP application message is address metadata followed by datagram
    // bytes. V4 writes it as one record; V6 may split it across traffic-shaped
    // records without adding UDP-layer continuation metadata.
    pub(crate) async fn finish_udp_payload_message(&mut self, payload_len: usize) -> Result<usize> {
        match self {
            Self::V4 { writer, .. } => writer.finish_udp_payload_message(payload_len).await,
            Self::V6(writer) => writer.finish_udp_payload_message(payload_len).await,
        }
    }

    pub(crate) async fn write_owned_udp_payload_message(
        &mut self,
        payload: BytesMut,
    ) -> Result<usize> {
        match self {
            Self::V4 { writer, .. } => writer.write_owned_udp_payload_message(payload).await,
            Self::V6(writer) => writer.write_owned_udp_payload_message(payload).await,
        }
    }

    pub(crate) const fn max_udp_application_payload_len(&self) -> usize {
        match self {
            Self::V4 { .. } => MAX_PACKET_SIZE,
            Self::V6(_) => MAX_V6_RECORD_PAYLOAD_LEN,
        }
    }

    #[cfg(test)]
    pub(crate) async fn write_test_frame(&mut self, payload: &[u8]) -> Result<usize> {
        match self {
            Self::V4 { writer, .. } => writer.write_test_frame(payload).await,
            Self::V6(writer) => writer.write_test_frame(payload).await,
        }
    }

    #[cfg(test)]
    pub(crate) async fn write_test_udp_packet(
        &mut self,
        address: AddressRef<'_>,
        port: u16,
        payload: &[u8],
    ) -> Result<usize> {
        match self {
            Self::V4 { writer, .. } => writer.write_test_udp_packet(address, port, payload).await,
            Self::V6(writer) => writer.write_test_udp_packet(address, port, payload).await,
        }
    }

    #[cfg(test)]
    pub(crate) async fn write_test_udp_response(
        &mut self,
        address: AddressRef<'_>,
        port: u16,
        payload: &[u8],
    ) -> Result<usize> {
        match self {
            Self::V4 { writer, .. } => writer.write_test_udp_response(address, port, payload).await,
            Self::V6(writer) => writer.write_test_udp_response(address, port, payload).await,
        }
    }

    pub(crate) async fn write_empty_tunnel_reply(&mut self) -> Result<()> {
        match self {
            Self::V4 { writer, .. } => writer.write_empty_tunnel_reply().await,
            Self::V6(writer) => writer.write_empty_tunnel_reply().await,
        }
    }

    #[cfg(test)]
    pub(crate) async fn write_test_tunnel_reply(&mut self, payload: &[u8]) -> Result<usize> {
        match self {
            Self::V4 { writer, .. } => writer.write_test_tunnel_reply(payload).await,
            Self::V6(writer) => writer.write_test_tunnel_reply(payload).await,
        }
    }

    pub(crate) async fn write_pong_reply(&mut self) -> Result<()> {
        match self {
            Self::V4 { writer, .. } => writer.write_pong_reply().await,
            Self::V6(writer) => writer.write_pong_reply().await,
        }
    }

    pub(crate) async fn write_error_reply(&mut self, code: u8, message: &str) -> Result<()> {
        match self {
            Self::V4 { writer, .. } => writer.write_error_reply(code, message).await,
            Self::V6(writer) => writer.write_error_reply(code, message).await,
        }
    }

    pub(crate) async fn write_zero_chunk(&mut self) -> Result<()> {
        match self {
            Self::V4 { writer, .. } => writer.write_zero_chunk().await,
            Self::V6(writer) => writer.write_zero_chunk().await,
        }
    }

    pub(crate) async fn shutdown(&mut self) -> Result<()> {
        match self {
            Self::V4 { writer, .. } => writer.shutdown().await,
            Self::V6(writer) => writer.shutdown().await,
        }
    }

    pub(crate) fn compact_buffers_for_reuse(&mut self) {
        match self {
            Self::V4 { writer, .. } => writer.compact_buffers_for_reuse(),
            Self::V6(writer) => writer.compact_buffers_for_reuse(),
        }
    }

    #[cfg(test)]
    pub(crate) fn frame_capacity(&self) -> usize {
        match self {
            Self::V4 { writer, .. } => writer.frame_capacity(),
            Self::V6(writer) => writer.frame_capacity(),
        }
    }
}

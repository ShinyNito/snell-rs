use std::time::Instant;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};
#[cfg(test)]
use crate::protocol::crypto::SALT_SIZE;
use crate::protocol::header::{COMMAND_TUNNEL, write_tcp_request_header, write_udp_request_header};
use crate::protocol::request::{write_error_reply, write_pong_reply, write_tunnel_reply};
use crate::protocol::v4::frame::V4FrameEncoder;
use crate::protocol::v6::{V6ChunkSizer, V6FrameEncoder};
use crate::{MAX_PACKET_SIZE, MAX_V6_RECORD_PAYLOAD_LEN, ProtocolVersion};

use super::buffer::{compact_stream_buffer_for_reuse, write_all_contiguous, write_all_vectored};
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

    pub(super) fn peek_limit(&self, now: Instant) -> usize {
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

    pub(crate) async fn write_payload_message_from_buffer(
        &mut self,
        plain: &mut BytesMut,
    ) -> Result<Option<usize>> {
        match self {
            Self::V4 { writer, .. } => writer.write_payload_message_from_buffer(plain).await,
            Self::V6(writer) => writer.write_payload_message_from_buffer(plain).await,
        }
    }

    pub(crate) async fn write_tunnel_reply_message_from_buffer(
        &mut self,
        plain: &mut BytesMut,
    ) -> Result<Option<usize>> {
        match self {
            Self::V4 { writer, .. } => writer.write_tunnel_reply_message_from_buffer(plain).await,
            Self::V6(writer) => writer.write_tunnel_reply_message_from_buffer(plain).await,
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

    pub(crate) const fn max_udp_application_payload_len(&self) -> usize {
        match self {
            Self::V4 { .. } => MAX_PACKET_SIZE,
            Self::V6(_) => MAX_V6_RECORD_PAYLOAD_LEN,
        }
    }

    pub(crate) async fn write_empty_tunnel_reply(&mut self) -> Result<()> {
        match self {
            Self::V4 { writer, .. } => writer.write_empty_tunnel_reply().await,
            Self::V6(writer) => writer.write_empty_tunnel_reply().await,
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
}

use std::future::poll_fn;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Instant;

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{Error, Result};
#[cfg(test)]
use crate::protocol::crypto::SALT_SIZE;
use crate::protocol::header::{COMMAND_TUNNEL, write_tcp_request_header, write_udp_request_header};
use crate::protocol::psk::SnellPsk;
use crate::protocol::request::{write_error_reply, write_pong_reply, write_tunnel_reply};
use crate::protocol::v4::frame::V4FrameEncoder;
use crate::protocol::v6::{V6ChunkSizer, V6FrameEncoder};
use crate::{MAX_PACKET_SIZE, MAX_V6_RECORD_PAYLOAD_LEN, ProtocolVersion};

use super::buffer::{compact_stream_buffer_for_reuse, poll_write_all_vectored, write_all_vectored};
use super::{
    FRAME_HEAD_INITIAL_CAPACITY, STREAM_BUFFER_INITIAL_CAPACITY, STREAM_BUFFER_RETAIN_CAPACITY,
    TCP_FIRST_RECORD_OVERHEAD, TCP_RECORD_IDLE_TIMEOUT, TCP_RECORD_MSS, TCP_STEADY_RECORD_OVERHEAD,
};

mod v4;
mod v6;

pub(super) use v4::V4StreamWriter;
pub(super) use v6::V6StreamWriter;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PayloadWriteStatus {
    Written(usize),
    SourceEof,
}

#[derive(Clone)]
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

    pub(super) const fn commit_limit(&mut self, now: Instant, limit: usize) {
        self.last_limit = limit;
        self.last_record_at = Some(now);
    }
}

const fn steady_record_limit() -> usize {
    TCP_RECORD_MSS - TCP_STEADY_RECORD_OVERHEAD
}

const PAYLOAD_WRITE_BATCH_TARGET_BYTES: usize = 64 * 1024;
pub(super) const PAYLOAD_WRITE_BATCH_MAX_RECORDS: usize = 64;
const PAYLOAD_WRITE_BATCH_MAX_IO_SLICES: usize = PAYLOAD_WRITE_BATCH_MAX_RECORDS * 2;

#[derive(Clone, Copy)]
pub(crate) struct PayloadReadSlot {
    base: *mut u8,
    len: usize,
}

impl PayloadReadSlot {
    pub(crate) const fn empty() -> Self {
        Self {
            base: std::ptr::null_mut(),
            len: 0,
        }
    }

    fn new(base: *mut u8, len: usize) -> Self {
        Self { base, len }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[cfg(test)]
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    pub(crate) unsafe fn as_uninit_slice(&mut self) -> &mut [std::mem::MaybeUninit<u8>] {
        unsafe { std::slice::from_raw_parts_mut(self.base.cast(), self.len) }
    }

    #[cfg(any(unix, test))]
    pub(crate) unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.base, self.len) }
    }
}

pub(crate) trait PayloadSource {
    fn poll_read_payload_into_slots(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        slots: &mut [PayloadReadSlot],
    ) -> Poll<io::Result<usize>>;
}

pub(crate) fn poll_read_payload_into_slots_fallback<R>(
    mut reader: Pin<&mut R>,
    cx: &mut Context<'_>,
    slots: &mut [PayloadReadSlot],
) -> Poll<io::Result<usize>>
where
    R: AsyncRead + ?Sized,
{
    let Some(slot) = slots.iter_mut().find(|slot| !slot.is_empty()) else {
        return Poll::Ready(Ok(0));
    };
    // The slot points at spare capacity owned by a BytesMut. ReadBuf accepts
    // MaybeUninit here and will only mark initialized bytes as filled.
    let spare = unsafe { slot.as_uninit_slice() };
    let mut read_buf = ReadBuf::uninit(spare);
    match reader.as_mut().poll_read(cx, &mut read_buf) {
        Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
        Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        Poll::Pending => Poll::Pending,
    }
}

pub(super) struct PendingPayloadBatch {
    records: Vec<PendingPayloadRecord>,
    active_len: usize,
    write_index: usize,
    plain_len: usize,
    wire_len: usize,
}

impl PendingPayloadBatch {
    pub(super) fn new() -> Self {
        Self {
            records: Vec::new(),
            active_len: 0,
            write_index: 0,
            plain_len: 0,
            wire_len: 0,
        }
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.active_len == 0
    }

    pub(super) const fn is_full(&self) -> bool {
        self.active_len >= PAYLOAD_WRITE_BATCH_MAX_RECORDS
            || self.wire_len >= PAYLOAD_WRITE_BATCH_TARGET_BYTES
    }

    pub(super) fn begin_record(&mut self) -> &mut PendingPayloadRecord {
        debug_assert_eq!(self.write_index, 0);
        debug_assert!(self.active_len < PAYLOAD_WRITE_BATCH_MAX_RECORDS);
        if self.active_len == self.records.len() {
            self.records.push(PendingPayloadRecord::new());
        }
        let record = &mut self.records[self.active_len];
        record.clear_for_fill();
        record
    }

    pub(super) fn commit_record(&mut self, plain_len: usize) {
        let record = &mut self.records[self.active_len];
        debug_assert!(!record.head.is_empty() || !record.payload.is_empty());
        record.head_pos = 0;
        record.payload_pos = 0;
        record.plain_len = plain_len;
        self.active_len += 1;
        self.plain_len += plain_len;
        self.wire_len += record.head.len() + record.payload.len();
    }

    pub(super) fn begin_source_record(&mut self) -> &mut PendingPayloadRecord {
        debug_assert_eq!(self.write_index, 0);
        debug_assert!(self.active_len < PAYLOAD_WRITE_BATCH_MAX_RECORDS);
        if self.active_len == self.records.len() {
            self.records.push(PendingPayloadRecord::new());
        }
        let record = &mut self.records[self.active_len];
        record.clear_for_fill();
        self.active_len += 1;
        record
    }

    pub(super) fn source_record(&mut self, index: usize) -> &mut PendingPayloadRecord {
        debug_assert!(index < self.active_len);
        &mut self.records[index]
    }

    pub(super) const fn active_len(&self) -> usize {
        self.active_len
    }

    pub(super) const fn target_bytes() -> usize {
        PAYLOAD_WRITE_BATCH_TARGET_BYTES
    }

    pub(super) fn finish_source_record(&mut self, index: usize, plain_len: usize) {
        let record = &mut self.records[index];
        debug_assert!(!record.head.is_empty() || !record.payload.is_empty());
        record.head_pos = 0;
        record.payload_pos = 0;
        record.plain_len = plain_len;
        self.plain_len += plain_len;
        self.wire_len += record.head.len() + record.payload.len();
    }

    pub(super) fn truncate_active(&mut self, active_len: usize) {
        debug_assert!(active_len <= self.active_len);
        for record in &mut self.records[active_len..self.active_len] {
            record.clear_for_fill();
        }
        self.active_len = active_len;
    }

    pub(super) fn discard(&mut self) {
        self.reset_active();
    }

    pub(super) fn compact_for_reuse(&mut self) {
        self.records.clear();
        self.records.shrink_to(0);
        self.active_len = 0;
        self.write_index = 0;
        self.plain_len = 0;
        self.wire_len = 0;
    }

    pub(super) fn finish_written(&mut self) -> usize {
        debug_assert_eq!(self.write_index, self.active_len);
        let plain_len = self.plain_len;
        self.reset_active();
        plain_len
    }

    pub(super) fn poll_write_all<W>(
        &mut self,
        writer: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>>
    where
        W: AsyncWrite + Unpin,
    {
        while self.write_index < self.active_len {
            let mut bufs: [IoSlice<'_>; PAYLOAD_WRITE_BATCH_MAX_IO_SLICES] =
                std::array::from_fn(|_| IoSlice::new(&[]));
            let mut len = 0;
            for record in &self.records[self.write_index..self.active_len] {
                let head = record.remaining_head();
                if !head.is_empty() {
                    bufs[len] = IoSlice::new(head);
                    len += 1;
                }

                let payload = record.remaining_payload();
                if !payload.is_empty() {
                    bufs[len] = IoSlice::new(payload);
                    len += 1;
                }
            }
            debug_assert!(len != 0);

            let n = ready!(Pin::new(&mut *writer).poll_write_vectored(cx, &bufs[..len]))?;
            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write snell payload batch",
                )
                .into()));
            }
            self.advance(n);
        }

        Poll::Ready(Ok(()))
    }

    fn advance(&mut self, mut written: usize) {
        while written != 0 && self.write_index < self.active_len {
            let record = &mut self.records[self.write_index];
            written = record.advance(written);
            if record.is_written() {
                self.write_index += 1;
            }
        }
    }

    fn reset_active(&mut self) {
        for record in &mut self.records[..self.active_len] {
            record.clear_for_fill();
        }
        self.active_len = 0;
        self.write_index = 0;
        self.plain_len = 0;
        self.wire_len = 0;
    }
}

pub(super) struct PendingPayloadRecord {
    pub(super) head: BytesMut,
    pub(super) payload: BytesMut,
    head_pos: usize,
    payload_pos: usize,
    plain_len: usize,
    prefix_len: usize,
    read_limit: usize,
}

impl PendingPayloadRecord {
    fn new() -> Self {
        Self {
            head: BytesMut::with_capacity(FRAME_HEAD_INITIAL_CAPACITY),
            payload: BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY),
            head_pos: 0,
            payload_pos: 0,
            plain_len: 0,
            prefix_len: 0,
            read_limit: 0,
        }
    }

    fn clear_for_fill(&mut self) {
        self.head.clear();
        self.payload.clear();
        self.head_pos = 0;
        self.payload_pos = 0;
        self.plain_len = 0;
        self.prefix_len = 0;
        self.read_limit = 0;
    }

    pub(super) fn prepare_spare(&mut self, prefix: &[u8], read_limit: usize) -> PayloadReadSlot {
        self.payload.extend_from_slice(prefix);
        self.payload.reserve(read_limit);
        self.prefix_len = prefix.len();
        self.read_limit = read_limit;
        let spare = self.payload.chunk_mut();
        debug_assert!(spare.len() >= read_limit);
        PayloadReadSlot::new(spare.as_mut_ptr().cast(), read_limit)
    }

    pub(super) fn finish_read(&mut self, read_len: usize) -> usize {
        debug_assert!(read_len <= self.read_limit);
        // The reader reported these bytes as initialized in the spare capacity.
        unsafe {
            self.payload.advance_mut(read_len);
        }
        self.prefix_len + read_len
    }

    fn remaining_head(&self) -> &[u8] {
        &self.head[self.head_pos..]
    }

    fn remaining_payload(&self) -> &[u8] {
        &self.payload[self.payload_pos..]
    }

    fn is_written(&self) -> bool {
        self.head_pos == self.head.len() && self.payload_pos == self.payload.len()
    }

    fn advance(&mut self, mut written: usize) -> usize {
        let head_remaining = self.head.len() - self.head_pos;
        let head_advance = head_remaining.min(written);
        self.head_pos += head_advance;
        written -= head_advance;

        let payload_remaining = self.payload.len() - self.payload_pos;
        let payload_advance = payload_remaining.min(written);
        self.payload_pos += payload_advance;
        written - payload_advance
    }
}

pub(crate) enum SnellStreamWriter<W> {
    V4 {
        writer: V4StreamWriter<W>,
        version: ProtocolVersion,
    },
    V6(V6StreamWriter<W>),
}

impl<W> SnellStreamWriter<W>
where
    W: AsyncWrite + Unpin,
{
    pub(crate) fn new(inner: W, secret: &SnellPsk, version: ProtocolVersion) -> Result<Self> {
        if version.uses_v6_frames() {
            Ok(Self::V6(V6StreamWriter::new(inner, secret)?))
        } else {
            Ok(Self::V4 {
                writer: V4StreamWriter::new(inner, secret)?,
                version,
            })
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_v6_salt(
        inner: W,
        secret: &SnellPsk,
        salt: [u8; SALT_SIZE],
    ) -> Result<Self> {
        Ok(Self::V6(V6StreamWriter::new_with_salt(
            inner, secret, salt,
        )?))
    }

    pub(crate) async fn write_payload_from_buffer(
        &mut self,
        plain: &mut BytesMut,
    ) -> Result<Option<usize>> {
        poll_fn(|cx| self.poll_write_payload_from_buffer(plain, cx)).await
    }

    pub(crate) fn poll_write_payload_from_buffer(
        &mut self,
        plain: &mut BytesMut,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<usize>>> {
        match self {
            Self::V4 { writer, .. } => writer.poll_write_payload_from_buffer(plain, cx),
            Self::V6(writer) => writer.poll_write_payload_from_buffer(plain, cx),
        }
    }

    pub(crate) fn poll_write_payload_from_source<R>(
        &mut self,
        reader: Pin<&mut R>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<PayloadWriteStatus>>
    where
        R: PayloadSource + ?Sized,
    {
        match self {
            Self::V4 { writer, .. } => writer.poll_write_payload_from_source(reader, cx),
            Self::V6(writer) => writer.poll_write_payload_from_source(reader, cx),
        }
    }

    pub(crate) fn poll_write_tunnel_reply_from_source<R>(
        &mut self,
        reader: Pin<&mut R>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<PayloadWriteStatus>>
    where
        R: PayloadSource + ?Sized,
    {
        match self {
            Self::V4 { writer, .. } => writer.poll_write_tunnel_reply_from_source(reader, cx),
            Self::V6(writer) => writer.poll_write_tunnel_reply_from_source(reader, cx),
        }
    }

    pub(crate) fn poll_write_tunnel_reply_from_buffer(
        &mut self,
        plain: &mut BytesMut,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<usize>>> {
        match self {
            Self::V4 { writer, .. } => writer.poll_write_tunnel_reply_from_buffer(plain, cx),
            Self::V6(writer) => writer.poll_write_tunnel_reply_from_buffer(plain, cx),
        }
    }

    pub(crate) const fn has_pending_message_write(&self) -> bool {
        match self {
            Self::V4 { writer, .. } => writer.has_pending_message_write(),
            Self::V6(writer) => writer.has_pending_message_write(),
        }
    }

    fn poll_write_tcp_request(
        &mut self,
        host: &str,
        port: u16,
        reuse: bool,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        match self {
            Self::V4 { writer, version } => {
                writer.poll_write_tcp_request(host, port, *version, reuse, cx)
            }
            Self::V6(writer) => writer.poll_write_tcp_request(host, port, reuse, cx),
        }
    }

    pub(crate) async fn write_tcp_request(
        &mut self,
        host: &str,
        port: u16,
        reuse: bool,
    ) -> Result<()> {
        poll_fn(|cx| self.poll_write_tcp_request(host, port, reuse, cx)).await
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

    pub(crate) fn poll_write_empty_tunnel_reply(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        match self {
            Self::V4 { writer, .. } => writer.poll_write_empty_tunnel_reply(cx),
            Self::V6(writer) => writer.poll_write_empty_tunnel_reply(cx),
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

    pub(crate) fn poll_write_zero_chunk(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match self {
            Self::V4 { writer, .. } => writer.poll_write_zero_chunk(cx),
            Self::V6(writer) => writer.poll_write_zero_chunk(cx),
        }
    }

    pub(crate) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match self {
            Self::V4 { writer, .. } => writer.poll_flush(cx),
            Self::V6(writer) => writer.poll_flush(cx),
        }
    }

    pub(crate) fn compact_buffers_for_reuse(&mut self) {
        match self {
            Self::V4 { writer, .. } => writer.compact_buffers_for_reuse(),
            Self::V6(writer) => writer.compact_buffers_for_reuse(),
        }
    }
}

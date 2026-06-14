use std::future::poll_fn;
use std::task::{Context, Poll, ready};
use std::time::Instant;

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::AsyncRead;

use crate::ProtocolVersion;
use crate::error::{Error, Result};
use crate::protocol::crypto::SALT_SIZE;
use crate::protocol::psk::SnellPsk;
use crate::protocol::udp::{parse_udp_request, parse_udp_response};
use crate::protocol::v4::frame::{DecodedHeader, V4_HEADER_CIPHER_SIZE, V4FrameDecoder};
use crate::protocol::v6::{
    SharedV6Profile, V6_HEADER_CIPHER_SIZE, V6ChunkSizer, V6DecodedHeader, V6FrameDecoder,
    V6SaltReplayCache,
};

use super::STREAM_BUFFER_INITIAL_CAPACITY;
use super::buffer::{compact_stream_buffer_for_reuse, poll_read_ahead_into_spare};
use super::writer::RecordSizer;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SnellFrameFamily {
    V4,
    V6,
}

impl SnellFrameFamily {
    pub(crate) const fn writer_version(self) -> ProtocolVersion {
        match self {
            Self::V4 => ProtocolVersion::V4,
            Self::V6 => ProtocolVersion::V6,
        }
    }

    pub(crate) const fn uses_v6_frames(self) -> bool {
        matches!(self, Self::V6)
    }
}

pub struct V4StreamReader<R> {
    inner: R,
    pub(super) secret: Option<SnellPsk>,
    decoder: Option<V4FrameDecoder>,
    /// Raw ciphertext accumulation buffer. Reads pull as much as the spare
    /// capacity allows, so several frames can be parsed per syscall.
    pub(super) body: BytesMut,
    /// Wire length of the frame currently borrowed out of `body`; discarded
    /// at the start of the next read.
    consumed: usize,
    /// Header decoded for a frame whose body has not fully arrived yet. Keeps
    /// `read_frame_payload` cancel-safe: the header nonce is only spent once.
    pending_header: Option<DecodedHeader>,
    record_sizer: Option<RecordSizer>,
    last_chunk_limit: Option<usize>,
    pending_udp_eof: bool,
    pending_udp_record: Option<PendingUdpRecord>,
    udp_message_state: UdpMessageReadState,
    udp_message: BytesMut,
    payload_start: usize,
    payload_end: usize,
}

pub struct V6StreamReader<R> {
    inner: R,
    secret: Option<SnellPsk>,
    profile: SharedV6Profile,
    chunk_sizer: V6ChunkSizer,
    salt_replay_cache: Option<V6SaltReplayCache>,
    decoder: Option<V6FrameDecoder>,
    pub(super) body: BytesMut,
    consumed: usize,
    pending_header: Option<V6DecodedHeader>,
    payload_start: usize,
    payload_end: usize,
    last_chunk_limit: Option<usize>,
    pending_udp_eof: bool,
    pending_udp_record: Option<PendingUdpRecord>,
    udp_message_state: UdpMessageReadState,
    udp_message: BytesMut,
}

struct PendingUdpRecord {
    payload: Bytes,
    chunk_limit: usize,
}

enum UdpMessageReadState {
    Start,
    NeedNext { first_payload: Bytes },
    Accumulating,
}

#[derive(Clone, Copy)]
enum UdpPayloadKind {
    Request,
    Response,
}

impl<R> V6StreamReader<R>
where
    R: AsyncRead + Unpin,
{
    pub fn new(inner: R, secret: &SnellPsk) -> Self {
        Self::with_salt_replay_cache(inner, secret, None)
    }

    pub(crate) fn with_salt_replay_cache(
        inner: R,
        secret: &SnellPsk,
        salt_replay_cache: Option<V6SaltReplayCache>,
    ) -> Self {
        Self::with_body_salt_replay_cache(
            inner,
            secret,
            BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY),
            salt_replay_cache,
        )
    }

    fn with_body_salt_replay_cache(
        inner: R,
        secret: &SnellPsk,
        body: BytesMut,
        salt_replay_cache: Option<V6SaltReplayCache>,
    ) -> Self {
        Self {
            inner,
            secret: Some(secret.clone()),
            profile: secret.clone_v6_profile(),
            chunk_sizer: V6ChunkSizer::new(),
            salt_replay_cache,
            decoder: None,
            body,
            consumed: 0,
            pending_header: None,
            payload_start: 0,
            payload_end: 0,
            last_chunk_limit: None,
            pending_udp_eof: false,
            pending_udp_record: None,
            udp_message_state: UdpMessageReadState::Start,
            udp_message: BytesMut::new(),
        }
    }

    // Cancel-safe frame read: a decoded header is cached until the full body is
    // buffered, so a later poll does not consume the frame nonce twice.
    fn poll_read_frame_payload_inner(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.discard_consumed();
        if self.decoder.is_none() {
            let salt_block_len = self.profile.salt_block_len();
            ready!(self.poll_fill_to(cx, salt_block_len))?;
            let salt = self.profile.extract_salt(&self.body[..salt_block_len])?;
            if let Some(cache) = &self.salt_replay_cache {
                cache.remember(salt)?;
            }
            self.body.advance(salt_block_len);
            let secret = self
                .secret
                .as_ref()
                .expect("v6 reader secret is kept until decoder initialization");
            self.decoder = Some(V6FrameDecoder::new(secret.as_bytes(), salt)?);
            self.secret = None;
        }

        let prefix_len = self
            .decoder
            .as_ref()
            .expect("decoder initialized before prefix length")
            .next_prefix_len(&self.profile);
        let header = if let Some(header) = self.pending_header {
            header
        } else {
            ready!(self.poll_fill_to(cx, prefix_len + V6_HEADER_CIPHER_SIZE))?;
            let prefix = &self.body[..prefix_len];
            let mut header_bytes = [0; V6_HEADER_CIPHER_SIZE];
            header_bytes
                .copy_from_slice(&self.body[prefix_len..prefix_len + V6_HEADER_CIPHER_SIZE]);
            let header = match self
                .decoder
                .as_mut()
                .expect("decoder initialized before v6 header decode")
                .decode_header(prefix, &mut header_bytes)
            {
                Ok(header) => header,
                Err(err) => {
                    log_frame_decode_error(&err, "v6", "header", None, None);
                    return Poll::Ready(Err(err));
                }
            };
            self.pending_header = Some(header);
            header
        };

        let body_start = prefix_len + V6_HEADER_CIPHER_SIZE;
        let body_len = header.body_len()?;
        let frame_len = body_start + body_len;
        ready!(self.poll_fill_to(cx, frame_len))?;
        self.pending_header = None;
        self.consumed = frame_len;

        let payload_len = header.payload_len;
        let now = Instant::now();
        let seq = self
            .decoder
            .as_ref()
            .expect("decoder initialized before v6 payload limit")
            .seq();
        let chunk_limit = self.chunk_sizer.peek_limit(&self.profile, seq, now);
        if let Err(err) = self
            .decoder
            .as_mut()
            .expect("decoder initialized before v6 payload decode")
            .decode_payload_in_place(&self.profile, header, &mut self.body[body_start..frame_len])
        {
            log_frame_decode_error(&err, "v6", "payload", Some(payload_len), Some(body_len));
            return Poll::Ready(Err(err));
        }
        self.last_chunk_limit = Some(chunk_limit);
        if payload_len != 0 {
            self.chunk_sizer.commit_record(&self.profile, now);
        }
        self.payload_start = body_start + header.padding_len;
        self.payload_end = self.payload_start + payload_len;
        tracing::trace!(payload_len, body_len, "read snell v6 frame");
        Poll::Ready(Ok(()))
    }

    pub(crate) fn poll_read_frame_payload(&mut self, cx: &mut Context<'_>) -> Poll<Result<&[u8]>> {
        ready!(self.poll_read_frame_payload_inner(cx))?;
        Poll::Ready(Ok(&self.body[self.payload_start..self.payload_end]))
    }

    pub(crate) fn take_payload_from(&mut self, offset: usize) -> Bytes {
        let payload_len = self.payload_end - self.payload_start;
        assert!(offset <= payload_len);
        if offset == payload_len {
            self.payload_start = 0;
            self.payload_end = 0;
            return Bytes::new();
        }

        let start = self.payload_start + offset;
        let end = self.payload_end;
        let consumed = self.consumed;
        debug_assert!(consumed >= end);
        let pending = self.body.split_to(consumed).freeze().slice(start..end);
        self.consumed = 0;
        self.payload_start = 0;
        self.payload_end = 0;
        pending
    }

    pub(crate) const fn last_chunk_limit(&self) -> Option<usize> {
        self.last_chunk_limit
    }

    pub(crate) const fn take_pending_udp_eof(&mut self) -> bool {
        let pending = self.pending_udp_eof;
        self.pending_udp_eof = false;
        pending
    }

    pub(crate) const fn set_pending_udp_eof(&mut self) {
        self.pending_udp_eof = true;
    }

    const fn take_pending_udp_record(&mut self) -> Option<PendingUdpRecord> {
        self.pending_udp_record.take()
    }

    fn set_pending_udp_record(&mut self, record: PendingUdpRecord) {
        self.pending_udp_record = Some(record);
    }

    pub(crate) fn compact_buffers_for_reuse(&mut self) {
        self.discard_consumed();
        if self.body.is_empty() {
            compact_stream_buffer_for_reuse(&mut self.body);
        }
        if self.udp_message.is_empty() {
            compact_stream_buffer_for_reuse(&mut self.udp_message);
        }
    }

    fn discard_consumed(&mut self) {
        if self.consumed != 0 {
            self.body.advance(self.consumed);
            self.consumed = 0;
        }
        self.payload_start = 0;
        self.payload_end = 0;
    }

    fn poll_fill_to(&mut self, cx: &mut Context<'_>, needed: usize) -> Poll<Result<()>> {
        while self.body.len() < needed {
            let min_spare = needed - self.body.len();
            let n = ready!(poll_read_ahead_into_spare(
                &mut self.inner,
                cx,
                &mut self.body,
                min_spare
            ))?;
            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "early eof reading snell v6 frame",
                )
                .into()));
            }
        }
        Poll::Ready(Ok(()))
    }
}

pub(crate) enum SnellStreamReader<R> {
    V4(V4StreamReader<R>),
    V6(V6StreamReader<R>),
}

impl<R> SnellStreamReader<R>
where
    R: AsyncRead + Unpin,
{
    pub(crate) fn new(inner: R, secret: &SnellPsk, version: ProtocolVersion) -> Self {
        if version.uses_v6_frames() {
            Self::V6(V6StreamReader::new(inner, secret))
        } else {
            Self::V4(V4StreamReader::new(inner, secret))
        }
    }

    pub(crate) async fn auto_detect_server<F>(
        inner: R,
        secret: &SnellPsk,
        v6_salt_replay_cache: V6SaltReplayCache,
        mut record_activity: F,
    ) -> Result<(Self, SnellFrameFamily)>
    where
        F: FnMut(),
    {
        let mut detector = ServerFrameFamilyDetector::new(inner, secret);
        loop {
            let v6_attempt = detector.try_detect_v6();
            let v4_attempt = detector.try_detect_v4();
            match (v6_attempt, v4_attempt) {
                (DetectionAttempt::Authenticated(salt), _) => {
                    v6_salt_replay_cache.remember(salt)?;
                    let reader = V6StreamReader::with_body_salt_replay_cache(
                        detector.inner,
                        secret,
                        detector.body,
                        None,
                    );
                    return Ok((Self::V6(reader), SnellFrameFamily::V6));
                }
                (_, DetectionAttempt::Authenticated(())) => {
                    let reader =
                        V4StreamReader::with_prefilled_body(detector.inner, secret, detector.body);
                    return Ok((Self::V4(reader), SnellFrameFamily::V4));
                }
                (DetectionAttempt::Failed(v6_error), DetectionAttempt::Failed(v4_error)) => {
                    tracing::debug!(
                        %v6_error,
                        %v4_error,
                        buffered_len = detector.body.len(),
                        "snell server frame family detection failed"
                    );
                    return Err(v6_error);
                }
                (v6_attempt, v4_attempt) => {
                    let needed = v6_attempt
                        .needed_len()
                        .into_iter()
                        .chain(v4_attempt.needed_len())
                        .min()
                        .expect("at least one detection attempt needs more bytes");
                    detector.fill_to(needed, &mut record_activity).await?;
                }
            }
        }
    }

    pub(crate) fn poll_read_frame_payload(&mut self, cx: &mut Context<'_>) -> Poll<Result<&[u8]>> {
        match self {
            Self::V4(reader) => reader.poll_read_frame_payload(cx),
            Self::V6(reader) => reader.poll_read_frame_payload(cx),
        }
    }

    pub(crate) fn poll_read_udp_request_message(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>>> {
        self.poll_read_udp_payload_message(cx, UdpPayloadKind::Request)
    }

    pub(crate) async fn read_udp_request_message(&mut self) -> Result<Option<Bytes>> {
        poll_fn(|cx| self.poll_read_udp_request_message(cx)).await
    }

    pub(crate) fn poll_read_udp_response_message(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>>> {
        self.poll_read_udp_payload_message(cx, UdpPayloadKind::Response)
    }

    pub(crate) async fn read_udp_response_message(&mut self) -> Result<Option<Bytes>> {
        poll_fn(|cx| self.poll_read_udp_response_message(cx)).await
    }

    fn poll_read_udp_payload_message(
        &mut self,
        cx: &mut Context<'_>,
        kind: UdpPayloadKind,
    ) -> Poll<Result<Option<Bytes>>> {
        match self {
            Self::V4(reader) => poll_read_udp_payload_message_from(reader, cx, kind),
            Self::V6(reader) => poll_read_udp_payload_message_from(reader, cx, kind),
        }
    }

    pub(crate) fn take_payload_from(&mut self, offset: usize) -> Bytes {
        match self {
            Self::V4(reader) => reader.take_payload_from(offset),
            Self::V6(reader) => reader.take_payload_from(offset),
        }
    }

    pub(crate) fn compact_buffers_for_reuse(&mut self) {
        match self {
            Self::V4(reader) => reader.compact_buffers_for_reuse(),
            Self::V6(reader) => reader.compact_buffers_for_reuse(),
        }
    }
}

trait UdpRecordSource {
    fn poll_read_udp_record_frame(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>>;
    fn last_udp_chunk_limit(&self) -> Option<usize>;
    fn take_udp_payload_from(&mut self, offset: usize) -> Bytes;
    fn take_pending_udp_eof(&mut self) -> bool;
    fn set_pending_udp_eof(&mut self);
    fn take_pending_udp_record(&mut self) -> Option<PendingUdpRecord>;
    fn set_pending_udp_record(&mut self, record: PendingUdpRecord);
    fn take_udp_message_state(&mut self) -> UdpMessageReadState;
    fn set_udp_message_state(&mut self, state: UdpMessageReadState);
    fn clear_udp_message(&mut self);
    fn extend_udp_message(&mut self, bytes: &[u8]);
    fn take_udp_message(&mut self) -> Bytes;

    fn poll_take_or_read_udp_record(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<PendingUdpRecord>>> {
        if let Some(record) = self.take_pending_udp_record() {
            return Poll::Ready(Ok(Some(record)));
        }

        match ready!(self.poll_read_udp_record_frame(cx)) {
            Ok(()) => {
                let chunk_limit = self.last_udp_chunk_limit().unwrap_or(usize::MAX);
                let payload = self.take_udp_payload_from(0);
                Poll::Ready(Ok(Some(PendingUdpRecord {
                    payload,
                    chunk_limit,
                })))
            }
            Err(Error::ZeroChunk) => Poll::Ready(Ok(None)),
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

fn poll_read_udp_payload_message_from<R>(
    reader: &mut R,
    cx: &mut Context<'_>,
    kind: UdpPayloadKind,
) -> Poll<Result<Option<Bytes>>>
where
    R: UdpRecordSource,
{
    loop {
        match reader.take_udp_message_state() {
            UdpMessageReadState::Start => {
                if reader.take_pending_udp_eof() {
                    reader.set_udp_message_state(UdpMessageReadState::Start);
                    return Poll::Ready(Ok(None));
                }
                reader.clear_udp_message();
                let record = match reader.poll_take_or_read_udp_record(cx) {
                    Poll::Ready(Ok(Some(record))) => record,
                    Poll::Ready(Ok(None)) => {
                        reader.set_udp_message_state(UdpMessageReadState::Start);
                        return Poll::Ready(Ok(None));
                    }
                    Poll::Ready(Err(err)) => {
                        reader.set_udp_message_state(UdpMessageReadState::Start);
                        return Poll::Ready(Err(err));
                    }
                    Poll::Pending => {
                        reader.set_udp_message_state(UdpMessageReadState::Start);
                        return Poll::Pending;
                    }
                };
                let payload_len = record.payload.len();
                if payload_len != record.chunk_limit {
                    reader.set_udp_message_state(UdpMessageReadState::Start);
                    return Poll::Ready(Ok(Some(record.payload)));
                }
                reader.set_udp_message_state(UdpMessageReadState::NeedNext {
                    first_payload: record.payload,
                });
            }
            UdpMessageReadState::NeedNext { first_payload } => {
                let record = match reader.poll_take_or_read_udp_record(cx) {
                    Poll::Ready(Ok(record)) => record,
                    Poll::Ready(Err(err)) => {
                        reader.set_udp_message_state(UdpMessageReadState::Start);
                        return Poll::Ready(Err(err));
                    }
                    Poll::Pending => {
                        reader
                            .set_udp_message_state(UdpMessageReadState::NeedNext { first_payload });
                        return Poll::Pending;
                    }
                };
                let Some(record) = record else {
                    reader.set_pending_udp_eof();
                    reader.set_udp_message_state(UdpMessageReadState::Start);
                    return Poll::Ready(Ok(Some(first_payload)));
                };
                let payload_len = record.payload.len();
                if udp_payload_starts_new_message(kind, &record.payload) {
                    reader.set_pending_udp_record(record);
                    reader.set_udp_message_state(UdpMessageReadState::Start);
                    return Poll::Ready(Ok(Some(first_payload)));
                }
                reader.clear_udp_message();
                reader.extend_udp_message(&first_payload);
                reader.extend_udp_message(&record.payload);
                if payload_len != record.chunk_limit {
                    reader.set_udp_message_state(UdpMessageReadState::Start);
                    return Poll::Ready(Ok(Some(reader.take_udp_message())));
                }
                reader.set_udp_message_state(UdpMessageReadState::Accumulating);
            }
            UdpMessageReadState::Accumulating => {
                let record = match reader.poll_take_or_read_udp_record(cx) {
                    Poll::Ready(Ok(record)) => record,
                    Poll::Ready(Err(err)) => {
                        reader.set_udp_message_state(UdpMessageReadState::Start);
                        return Poll::Ready(Err(err));
                    }
                    Poll::Pending => {
                        reader.set_udp_message_state(UdpMessageReadState::Accumulating);
                        return Poll::Pending;
                    }
                };
                let Some(record) = record else {
                    reader.set_pending_udp_eof();
                    reader.set_udp_message_state(UdpMessageReadState::Start);
                    return Poll::Ready(Ok(Some(reader.take_udp_message())));
                };
                let payload_len = record.payload.len();
                if udp_payload_starts_new_message(kind, &record.payload) {
                    reader.set_pending_udp_record(record);
                    reader.set_udp_message_state(UdpMessageReadState::Start);
                    return Poll::Ready(Ok(Some(reader.take_udp_message())));
                }
                reader.extend_udp_message(&record.payload);
                if payload_len != record.chunk_limit {
                    reader.set_udp_message_state(UdpMessageReadState::Start);
                    return Poll::Ready(Ok(Some(reader.take_udp_message())));
                }
                reader.set_udp_message_state(UdpMessageReadState::Accumulating);
            }
        }
    }
}

impl<R> UdpRecordSource for V4StreamReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read_udp_record_frame(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.poll_read_frame_payload_inner(cx)
    }

    fn last_udp_chunk_limit(&self) -> Option<usize> {
        V4StreamReader::last_chunk_limit(self)
    }

    fn take_udp_payload_from(&mut self, offset: usize) -> Bytes {
        V4StreamReader::take_payload_from(self, offset)
    }

    fn take_pending_udp_eof(&mut self) -> bool {
        V4StreamReader::take_pending_udp_eof(self)
    }

    fn set_pending_udp_eof(&mut self) {
        V4StreamReader::set_pending_udp_eof(self);
    }

    fn take_pending_udp_record(&mut self) -> Option<PendingUdpRecord> {
        V4StreamReader::take_pending_udp_record(self)
    }

    fn set_pending_udp_record(&mut self, record: PendingUdpRecord) {
        V4StreamReader::set_pending_udp_record(self, record);
    }

    fn take_udp_message_state(&mut self) -> UdpMessageReadState {
        std::mem::replace(&mut self.udp_message_state, UdpMessageReadState::Start)
    }

    fn set_udp_message_state(&mut self, state: UdpMessageReadState) {
        self.udp_message_state = state;
    }

    fn clear_udp_message(&mut self) {
        self.udp_message.clear();
    }

    fn extend_udp_message(&mut self, bytes: &[u8]) {
        self.udp_message.extend_from_slice(bytes);
    }

    fn take_udp_message(&mut self) -> Bytes {
        let message_len = self.udp_message.len();
        self.udp_message.split_to(message_len).freeze()
    }
}

impl<R> UdpRecordSource for V6StreamReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read_udp_record_frame(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.poll_read_frame_payload_inner(cx)
    }

    fn last_udp_chunk_limit(&self) -> Option<usize> {
        V6StreamReader::last_chunk_limit(self)
    }

    fn take_udp_payload_from(&mut self, offset: usize) -> Bytes {
        V6StreamReader::take_payload_from(self, offset)
    }

    fn take_pending_udp_eof(&mut self) -> bool {
        V6StreamReader::take_pending_udp_eof(self)
    }

    fn set_pending_udp_eof(&mut self) {
        V6StreamReader::set_pending_udp_eof(self);
    }

    fn take_pending_udp_record(&mut self) -> Option<PendingUdpRecord> {
        V6StreamReader::take_pending_udp_record(self)
    }

    fn set_pending_udp_record(&mut self, record: PendingUdpRecord) {
        V6StreamReader::set_pending_udp_record(self, record);
    }

    fn take_udp_message_state(&mut self) -> UdpMessageReadState {
        std::mem::replace(&mut self.udp_message_state, UdpMessageReadState::Start)
    }

    fn set_udp_message_state(&mut self, state: UdpMessageReadState) {
        self.udp_message_state = state;
    }

    fn clear_udp_message(&mut self) {
        self.udp_message.clear();
    }

    fn extend_udp_message(&mut self, bytes: &[u8]) {
        self.udp_message.extend_from_slice(bytes);
    }

    fn take_udp_message(&mut self) -> Bytes {
        let message_len = self.udp_message.len();
        self.udp_message.split_to(message_len).freeze()
    }
}

fn udp_payload_starts_new_message(kind: UdpPayloadKind, payload: &[u8]) -> bool {
    match kind {
        UdpPayloadKind::Request => parse_udp_request(payload).is_ok(),
        UdpPayloadKind::Response => parse_udp_response(payload).is_ok(),
    }
}

enum DetectionAttempt<T> {
    Authenticated(T),
    Need(usize),
    Failed(Error),
}

impl<T> DetectionAttempt<T> {
    const fn needed_len(&self) -> Option<usize> {
        match self {
            Self::Need(needed) => Some(*needed),
            Self::Authenticated(_) | Self::Failed(_) => None,
        }
    }
}

struct ServerFrameFamilyDetector<'a, R> {
    inner: R,
    psk: &'a [u8],
    profile: SharedV6Profile,
    body: BytesMut,
}

impl<'a, R> ServerFrameFamilyDetector<'a, R>
where
    R: AsyncRead + Unpin,
{
    fn new(inner: R, secret: &'a SnellPsk) -> Self {
        Self {
            inner,
            psk: secret.as_bytes(),
            profile: secret.clone_v6_profile(),
            body: BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY),
        }
    }

    fn try_detect_v6(&self) -> DetectionAttempt<[u8; SALT_SIZE]> {
        let salt_block_len = self.profile.salt_block_len();
        if self.body.len() < salt_block_len {
            return DetectionAttempt::Need(salt_block_len);
        }

        let salt = match self.profile.extract_salt(&self.body[..salt_block_len]) {
            Ok(salt) => salt,
            Err(error) => return DetectionAttempt::Failed(error),
        };
        let mut decoder = match V6FrameDecoder::new(self.psk, salt) {
            Ok(decoder) => decoder,
            Err(error) => return DetectionAttempt::Failed(error),
        };
        let prefix_len = decoder.next_prefix_len(&self.profile);
        let needed = salt_block_len + prefix_len + V6_HEADER_CIPHER_SIZE;
        if self.body.len() < needed {
            return DetectionAttempt::Need(needed);
        }

        let prefix = &self.body[salt_block_len..salt_block_len + prefix_len];
        let mut header_bytes = [0; V6_HEADER_CIPHER_SIZE];
        header_bytes.copy_from_slice(
            &self.body
                [salt_block_len + prefix_len..salt_block_len + prefix_len + V6_HEADER_CIPHER_SIZE],
        );
        match decoder.decode_header(prefix, &mut header_bytes) {
            Ok(_) => DetectionAttempt::Authenticated(salt),
            Err(error) => DetectionAttempt::Failed(error),
        }
    }

    fn try_detect_v4(&self) -> DetectionAttempt<()> {
        let needed = SALT_SIZE + V4_HEADER_CIPHER_SIZE;
        if self.body.len() < needed {
            return DetectionAttempt::Need(needed);
        }

        let mut salt = [0; SALT_SIZE];
        salt.copy_from_slice(&self.body[..SALT_SIZE]);
        let mut decoder = match V4FrameDecoder::new(self.psk, salt) {
            Ok(decoder) => decoder,
            Err(error) => return DetectionAttempt::Failed(error),
        };
        let mut header_bytes = [0; V4_HEADER_CIPHER_SIZE];
        header_bytes.copy_from_slice(&self.body[SALT_SIZE..needed]);
        match decoder.decode_header(&mut header_bytes) {
            Ok(_) => DetectionAttempt::Authenticated(()),
            Err(error) => DetectionAttempt::Failed(error),
        }
    }

    async fn fill_to<F>(&mut self, needed: usize, record_activity: &mut F) -> Result<()>
    where
        F: FnMut(),
    {
        while self.body.len() < needed {
            let min_spare = needed - self.body.len();
            let n = poll_fn(|cx| {
                poll_read_ahead_into_spare(&mut self.inner, cx, &mut self.body, min_spare)
            })
            .await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "early eof detecting snell frame family",
                )
                .into());
            }
            record_activity();
        }
        Ok(())
    }
}

fn log_frame_decode_error(
    err: &Error,
    frame_family: &'static str,
    stage: &'static str,
    payload_len: Option<usize>,
    body_len: Option<usize>,
) {
    if matches!(err, Error::ZeroChunk) {
        return;
    }

    tracing::debug!(
        %err,
        frame_family,
        stage,
        ?payload_len,
        ?body_len,
        "snell frame decode failed"
    );
}

impl<R> V4StreamReader<R>
where
    R: AsyncRead + Unpin,
{
    /// Creates a reader without waiting for the peer salt.
    ///
    /// The salt is read and the decoder is initialized lazily on the first
    /// frame read.
    pub fn new(inner: R, secret: &SnellPsk) -> Self {
        Self::with_prefilled_body(
            inner,
            secret,
            BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY),
        )
    }

    fn with_prefilled_body(inner: R, secret: &SnellPsk, body: BytesMut) -> Self {
        Self {
            inner,
            secret: Some(secret.clone()),
            decoder: None,
            body,
            consumed: 0,
            pending_header: None,
            record_sizer: None,
            last_chunk_limit: None,
            pending_udp_eof: false,
            pending_udp_record: None,
            udp_message_state: UdpMessageReadState::Start,
            udp_message: BytesMut::new(),
            payload_start: 0,
            payload_end: 0,
        }
    }

    // Cancel-safe frame read: a decoded header is cached until the full body is
    // buffered, so a later poll does not consume the frame nonce twice.
    fn poll_read_frame_payload_inner(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.discard_consumed();
        if self.decoder.is_none() {
            ready!(self.poll_fill_to(cx, SALT_SIZE))?;
            let mut salt = [0; SALT_SIZE];
            salt.copy_from_slice(&self.body[..SALT_SIZE]);
            self.body.advance(SALT_SIZE);
            let secret = self
                .secret
                .as_ref()
                .expect("v4 reader secret is kept until decoder initialization");
            self.decoder = Some(V4FrameDecoder::new(secret.as_bytes(), salt)?);
            self.secret = None;
        }

        let header = if let Some(header) = self.pending_header {
            header
        } else {
            ready!(self.poll_fill_to(cx, V4_HEADER_CIPHER_SIZE))?;
            let header_bytes: &mut [u8; V4_HEADER_CIPHER_SIZE] = (&mut self.body
                [..V4_HEADER_CIPHER_SIZE])
                .try_into()
                .expect("header slice has cipher header length");
            let header = match self
                .decoder
                .as_mut()
                .expect("decoder initialized before header decode")
                .decode_header(header_bytes)
            {
                Ok(header) => header,
                Err(err) => {
                    log_frame_decode_error(&err, "v4", "header", None, None);
                    return Poll::Ready(Err(err));
                }
            };
            self.pending_header = Some(header);
            header
        };

        let body_len = header.body_len()?;
        let frame_len = V4_HEADER_CIPHER_SIZE + body_len;
        ready!(self.poll_fill_to(cx, frame_len))?;
        self.pending_header = None;
        self.consumed = frame_len;

        let payload_len = header.payload_len;
        if let Err(err) = self
            .decoder
            .as_mut()
            .expect("decoder initialized before payload decode")
            .decode_payload_in_place(header, &mut self.body[V4_HEADER_CIPHER_SIZE..frame_len])
        {
            log_frame_decode_error(&err, "v4", "payload", Some(payload_len), Some(body_len));
            return Poll::Ready(Err(err));
        }
        self.observe_payload_record(header);
        self.payload_start = V4_HEADER_CIPHER_SIZE;
        self.payload_end = V4_HEADER_CIPHER_SIZE + payload_len;
        tracing::trace!(payload_len, body_len, "read snell v4 frame");
        Poll::Ready(Ok(()))
    }

    pub(crate) fn poll_read_frame_payload(&mut self, cx: &mut Context<'_>) -> Poll<Result<&[u8]>> {
        ready!(self.poll_read_frame_payload_inner(cx))?;
        Poll::Ready(Ok(&self.body[self.payload_start..self.payload_end]))
    }

    pub(crate) fn take_payload_from(&mut self, offset: usize) -> Bytes {
        let payload_len = self.payload_end - self.payload_start;
        assert!(offset <= payload_len);
        if offset == payload_len {
            self.payload_start = 0;
            self.payload_end = 0;
            return Bytes::new();
        }

        let start = self.payload_start + offset;
        let end = self.payload_end;
        let consumed = self.consumed;
        debug_assert!(consumed >= end);
        let pending = self.body.split_to(consumed).freeze().slice(start..end);
        self.consumed = 0;
        self.payload_start = 0;
        self.payload_end = 0;
        pending
    }

    fn observe_payload_record(&mut self, header: DecodedHeader) {
        if header.payload_len == 0 {
            self.last_chunk_limit = None;
            return;
        }

        let now = Instant::now();
        let record_sizer = self
            .record_sizer
            .get_or_insert_with(|| RecordSizer::new(header.padding_len));
        let limit = record_sizer.peek_limit(now);
        self.last_chunk_limit = Some(limit);
        record_sizer.commit_limit(now, limit);
    }

    pub(crate) const fn last_chunk_limit(&self) -> Option<usize> {
        self.last_chunk_limit
    }

    pub(crate) const fn take_pending_udp_eof(&mut self) -> bool {
        let pending = self.pending_udp_eof;
        self.pending_udp_eof = false;
        pending
    }

    pub(crate) const fn set_pending_udp_eof(&mut self) {
        self.pending_udp_eof = true;
    }

    const fn take_pending_udp_record(&mut self) -> Option<PendingUdpRecord> {
        self.pending_udp_record.take()
    }

    fn set_pending_udp_record(&mut self, record: PendingUdpRecord) {
        self.pending_udp_record = Some(record);
    }

    pub(crate) fn compact_buffers_for_reuse(&mut self) {
        self.discard_consumed();
        if self.body.is_empty() {
            compact_stream_buffer_for_reuse(&mut self.body);
        }
        if self.udp_message.is_empty() {
            compact_stream_buffer_for_reuse(&mut self.udp_message);
        }
    }

    fn discard_consumed(&mut self) {
        if self.consumed != 0 {
            self.body.advance(self.consumed);
            self.consumed = 0;
        }
        self.payload_start = 0;
        self.payload_end = 0;
    }

    fn poll_fill_to(&mut self, cx: &mut Context<'_>, needed: usize) -> Poll<Result<()>> {
        while self.body.len() < needed {
            let min_spare = needed - self.body.len();
            let n = ready!(poll_read_ahead_into_spare(
                &mut self.inner,
                cx,
                &mut self.body,
                min_spare
            ))?;
            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "early eof reading snell frame",
                )
                .into()));
            }
        }
        Poll::Ready(Ok(()))
    }
}

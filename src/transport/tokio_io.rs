use std::future::poll_fn;
use std::io::IoSlice;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::UdpSocket;
use zeroize::Zeroizing;

use crate::MAX_PACKET_SIZE;
use crate::error::{Error, Result};
use crate::protocol::crypto::SALT_SIZE;
use crate::protocol::frame_v4::{
    DecodedHeader, V4_HEADER_CIPHER_SIZE, V4FrameDecoder, V4FrameEncoder,
};
use crate::protocol::frame_v6::{
    V6_HEADER_CIPHER_SIZE, V6ChunkSizer, V6DecodedHeader, V6FrameDecoder, V6FrameEncoder,
    V6Profile, V6SaltReplayCache,
};
use crate::protocol::header::{COMMAND_TUNNEL, write_tcp_request_header, write_udp_request_header};
use crate::protocol::request::{
    ClientRequest, ServerReply, parse_client_request, parse_server_reply, write_error_reply,
    write_pong_reply, write_tunnel_reply,
};
#[cfg(test)]
use crate::protocol::udp::write_udp_request_prefix;
use crate::protocol::udp::{AddressRef, write_udp_response_prefix};
use crate::{VERSION_1, VERSION_2, VERSION_3, VERSION_4, VERSION_5, VERSION_6};

pub const TCP_RECORD_MSS: usize = 1460;
pub const TCP_FIRST_RECORD_OVERHEAD: usize = 55;
pub const TCP_STEADY_RECORD_OVERHEAD: usize = 39;
pub const TCP_RECORD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const STREAM_BUFFER_INITIAL_CAPACITY: usize = 2048;
pub(crate) const STREAM_BUFFER_RETAIN_CAPACITY: usize = MAX_PACKET_SIZE + 1024;
const FRAME_HEAD_INITIAL_CAPACITY: usize = 512;

pub struct RecordSizer {
    initial_padding_len: usize,
    last_limit: usize,
    last_record_at: Option<Instant>,
}

impl RecordSizer {
    pub const fn new(initial_padding_len: usize) -> Self {
        Self {
            initial_padding_len,
            last_limit: 0,
            last_record_at: None,
        }
    }

    pub fn next_limit(&mut self, now: Instant) -> usize {
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

    fn commit_limit(&mut self, now: Instant, limit: usize) {
        self.last_limit = limit;
        self.last_record_at = Some(now);
    }
}

const fn steady_record_limit() -> usize {
    TCP_RECORD_MSS - TCP_STEADY_RECORD_OVERHEAD
}

pub struct V4StreamReader<R> {
    inner: R,
    psk: Zeroizing<Vec<u8>>,
    decoder: Option<V4FrameDecoder>,
    /// Raw ciphertext accumulation buffer. Reads pull as much as the spare
    /// capacity allows, so several frames can be parsed per syscall.
    body: BytesMut,
    /// Wire length of the frame currently borrowed out of `body`; discarded
    /// at the start of the next read.
    consumed: usize,
    /// Header decoded for a frame whose body has not fully arrived yet. Keeps
    /// `read_frame_payload` cancel-safe: the header nonce is only spent once.
    pending_header: Option<DecodedHeader>,
    payload_start: usize,
    payload_end: usize,
}

pub struct V6StreamReader<R> {
    inner: R,
    psk: Zeroizing<Vec<u8>>,
    profile: V6Profile,
    salt_replay_cache: Option<V6SaltReplayCache>,
    decoder: Option<V6FrameDecoder>,
    body: BytesMut,
    consumed: usize,
    pending_header: Option<V6DecodedHeader>,
    payload_start: usize,
    payload_end: usize,
}

impl<R> V6StreamReader<R>
where
    R: AsyncRead + Unpin,
{
    pub fn new(inner: R, psk: &[u8]) -> Result<Self> {
        Self::with_salt_replay_cache(inner, psk, None)
    }

    pub(crate) fn with_salt_replay_cache(
        inner: R,
        psk: &[u8],
        salt_replay_cache: Option<V6SaltReplayCache>,
    ) -> Result<Self> {
        Ok(Self {
            inner,
            psk: Zeroizing::new(psk.to_vec()),
            profile: V6Profile::derive(psk),
            salt_replay_cache,
            decoder: None,
            body: BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY),
            consumed: 0,
            pending_header: None,
            payload_start: 0,
            payload_end: 0,
        })
    }

    pub async fn read_frame_payload(&mut self) -> Result<&[u8]> {
        self.discard_consumed();
        if self.decoder.is_none() {
            let salt_block_len = self.profile.salt_block_len();
            self.fill_to(salt_block_len).await?;
            let salt = self.profile.extract_salt(&self.body[..salt_block_len])?;
            if let Some(cache) = &self.salt_replay_cache {
                cache.remember(salt)?;
            }
            self.body.advance(salt_block_len);
            self.decoder = Some(V6FrameDecoder::new(&self.psk, salt)?);
            self.psk.clear();
        }

        let prefix_len = self
            .decoder
            .as_ref()
            .expect("decoder initialized before prefix length")
            .next_prefix_len();
        let header = match self.pending_header {
            Some(header) => header,
            None => {
                self.fill_to(prefix_len + V6_HEADER_CIPHER_SIZE).await?;
                let prefix = &self.body[..prefix_len];
                let mut header_bytes = [0; V6_HEADER_CIPHER_SIZE];
                header_bytes
                    .copy_from_slice(&self.body[prefix_len..prefix_len + V6_HEADER_CIPHER_SIZE]);
                let header = self
                    .decoder
                    .as_mut()
                    .expect("decoder initialized before v6 header decode")
                    .decode_header(prefix, &mut header_bytes)?;
                self.pending_header = Some(header);
                header
            }
        };

        let body_start = prefix_len + V6_HEADER_CIPHER_SIZE;
        let body_len = header.body_len()?;
        let frame_len = body_start + body_len;
        self.fill_to(frame_len).await?;
        self.pending_header = None;
        self.consumed = frame_len;

        let payload_len = header.payload_len;
        self.decoder
            .as_mut()
            .expect("decoder initialized before v6 payload decode")
            .decode_payload_in_place(header, &mut self.body[body_start..frame_len])?;
        self.payload_start = body_start + header.padding_len;
        self.payload_end = self.payload_start + payload_len;
        tracing::trace!(payload_len, body_len, "read snell v6 frame");
        Ok(&self.body[self.payload_start..self.payload_end])
    }

    pub async fn read_client_request(&mut self) -> Result<ClientRequest<'_>> {
        let payload = self.read_frame_payload().await?;
        parse_client_request(payload)
    }

    pub async fn read_server_reply(&mut self) -> Result<ServerReply<'_>> {
        let payload = self.read_frame_payload().await?;
        parse_server_reply(payload)
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

    pub(crate) fn compact_buffers_for_reuse(&mut self) {
        self.discard_consumed();
        if self.body.is_empty() {
            compact_stream_buffer_for_reuse(&mut self.body);
        } else if self.body.capacity() > STREAM_BUFFER_RETAIN_CAPACITY {
            let mut fresh =
                BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY.max(self.body.len()));
            fresh.extend_from_slice(&self.body);
            self.body = fresh;
        }
    }

    #[cfg(test)]
    pub(crate) fn body_capacity(&self) -> usize {
        self.body.capacity()
    }

    fn discard_consumed(&mut self) {
        if self.consumed != 0 {
            self.body.advance(self.consumed);
            self.consumed = 0;
        }
        self.payload_start = 0;
        self.payload_end = 0;
    }

    async fn fill_to(&mut self, needed: usize) -> Result<()> {
        while self.body.len() < needed {
            let min_spare = needed - self.body.len();
            let n = poll_fn(|cx| {
                poll_read_ahead_into_spare(&mut self.inner, cx, &mut self.body, min_spare)
            })
            .await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "early eof reading snell v6 frame",
                )
                .into());
            }
        }
        Ok(())
    }
}

pub(crate) enum SnellStreamReader<R> {
    V4(Box<V4StreamReader<R>>),
    V6(Box<V6StreamReader<R>>),
}

impl<R> SnellStreamReader<R>
where
    R: AsyncRead + Unpin,
{
    pub(crate) fn new(inner: R, psk: &[u8], version: u8) -> Result<Self> {
        match version {
            VERSION_1 | VERSION_2 | VERSION_3 | VERSION_4 | VERSION_5 => {
                Ok(Self::V4(Box::new(V4StreamReader::new(inner, psk)?)))
            }
            VERSION_6 => Ok(Self::V6(Box::new(V6StreamReader::new(inner, psk)?))),
            other => Err(Error::UnsupportedVersion(other)),
        }
    }

    pub(crate) fn new_server(
        inner: R,
        psk: &[u8],
        version: u8,
        v6_salt_replay_cache: Option<V6SaltReplayCache>,
    ) -> Result<Self> {
        match version {
            VERSION_1 | VERSION_2 | VERSION_3 | VERSION_4 | VERSION_5 => {
                Ok(Self::V4(Box::new(V4StreamReader::new(inner, psk)?)))
            }
            VERSION_6 => Ok(Self::V6(Box::new(V6StreamReader::with_salt_replay_cache(
                inner,
                psk,
                v6_salt_replay_cache,
            )?))),
            other => Err(Error::UnsupportedVersion(other)),
        }
    }

    pub(crate) async fn read_frame_payload(&mut self) -> Result<&[u8]> {
        match self {
            Self::V4(reader) => reader.read_frame_payload().await,
            Self::V6(reader) => reader.read_frame_payload().await,
        }
    }

    pub(crate) async fn read_client_request(&mut self) -> Result<ClientRequest<'_>> {
        match self {
            Self::V4(reader) => reader.read_client_request().await,
            Self::V6(reader) => reader.read_client_request().await,
        }
    }

    pub(crate) async fn read_server_reply(&mut self) -> Result<ServerReply<'_>> {
        match self {
            Self::V4(reader) => reader.read_server_reply().await,
            Self::V6(reader) => reader.read_server_reply().await,
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

    #[cfg(test)]
    pub(crate) fn body_capacity(&self) -> usize {
        match self {
            Self::V4(reader) => reader.body_capacity(),
            Self::V6(reader) => reader.body_capacity(),
        }
    }
}

impl<R> From<V4StreamReader<R>> for SnellStreamReader<R> {
    fn from(reader: V4StreamReader<R>) -> Self {
        Self::V4(Box::new(reader))
    }
}

impl<R> From<V6StreamReader<R>> for SnellStreamReader<R> {
    fn from(reader: V6StreamReader<R>) -> Self {
        Self::V6(Box::new(reader))
    }
}

impl<R> V4StreamReader<R>
where
    R: AsyncRead + Unpin,
{
    /// Creates a reader without waiting for the peer salt.
    ///
    /// The salt is read and the decoder is initialized lazily on the first
    /// frame read.
    pub fn new(inner: R, psk: &[u8]) -> Result<Self> {
        Ok(Self {
            inner,
            psk: Zeroizing::new(psk.to_vec()),
            decoder: None,
            body: BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY),
            consumed: 0,
            pending_header: None,
            payload_start: 0,
            payload_end: 0,
        })
    }

    /// Reads one Snell frame and returns a payload slice borrowed from this reader.
    ///
    /// The returned slice is valid until the next frame read or
    /// `take_payload_from` call on the same reader. A zero chunk is returned as
    /// `Error::ZeroChunk`.
    pub async fn read_frame_payload(&mut self) -> Result<&[u8]> {
        self.discard_consumed();
        if self.decoder.is_none() {
            self.fill_to(SALT_SIZE).await?;
            let mut salt = [0; SALT_SIZE];
            salt.copy_from_slice(&self.body[..SALT_SIZE]);
            self.body.advance(SALT_SIZE);
            self.decoder = Some(V4FrameDecoder::new(&self.psk, salt)?);
            self.psk.clear();
        }

        let header = match self.pending_header {
            Some(header) => header,
            None => {
                self.fill_to(V4_HEADER_CIPHER_SIZE).await?;
                let header_bytes: &mut [u8; V4_HEADER_CIPHER_SIZE] = (&mut self.body
                    [..V4_HEADER_CIPHER_SIZE])
                    .try_into()
                    .expect("header slice has cipher header length");
                let header = self
                    .decoder
                    .as_mut()
                    .expect("decoder initialized before header decode")
                    .decode_header(header_bytes)?;
                self.pending_header = Some(header);
                header
            }
        };

        let body_len = header.body_len()?;
        let frame_len = V4_HEADER_CIPHER_SIZE + body_len;
        self.fill_to(frame_len).await?;
        self.pending_header = None;
        self.consumed = frame_len;

        let payload_len = header.payload_len;
        self.decoder
            .as_mut()
            .expect("decoder initialized before payload decode")
            .decode_payload_in_place(header, &mut self.body[V4_HEADER_CIPHER_SIZE..frame_len])?;
        self.payload_start = V4_HEADER_CIPHER_SIZE;
        self.payload_end = V4_HEADER_CIPHER_SIZE + payload_len;
        tracing::trace!(payload_len, body_len, "read snell v4 frame");
        Ok(&self.body[self.payload_start..self.payload_end])
    }

    /// Reads and parses one client request as a borrowed view into the frame payload.
    pub async fn read_client_request(&mut self) -> Result<ClientRequest<'_>> {
        let payload = self.read_frame_payload().await?;
        parse_client_request(payload)
    }

    /// Reads and parses one server reply as a borrowed view into the frame payload.
    pub async fn read_server_reply(&mut self) -> Result<ServerReply<'_>> {
        let payload = self.read_frame_payload().await?;
        parse_server_reply(payload)
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

    pub(crate) fn compact_buffers_for_reuse(&mut self) {
        self.discard_consumed();
        if self.body.is_empty() {
            compact_stream_buffer_for_reuse(&mut self.body);
        } else if self.body.capacity() > STREAM_BUFFER_RETAIN_CAPACITY {
            // Keep buffered bytes (e.g. a pipelined next request); only shed
            // the oversized allocation.
            let mut fresh =
                BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY.max(self.body.len()));
            fresh.extend_from_slice(&self.body);
            self.body = fresh;
        }
    }

    #[cfg(test)]
    pub(crate) fn body_capacity(&self) -> usize {
        self.body.capacity()
    }

    fn discard_consumed(&mut self) {
        if self.consumed != 0 {
            self.body.advance(self.consumed);
            self.consumed = 0;
        }
        self.payload_start = 0;
        self.payload_end = 0;
    }

    async fn fill_to(&mut self, needed: usize) -> Result<()> {
        while self.body.len() < needed {
            let min_spare = needed - self.body.len();
            let n = poll_fn(|cx| {
                poll_read_ahead_into_spare(&mut self.inner, cx, &mut self.body, min_spare)
            })
            .await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "early eof reading snell frame",
                )
                .into());
            }
        }
        Ok(())
    }
}

pub struct V4StreamWriter<W> {
    inner: W,
    encoder: V4FrameEncoder,
    record_sizer: RecordSizer,
    head: BytesMut,
    payload: BytesMut,
}

struct ReaderPayloadFrame {
    payload_len: usize,
    read_len: usize,
    limit: usize,
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

impl<W> V4StreamWriter<W>
where
    W: AsyncWrite + Unpin,
{
    pub fn new(inner: W, psk: &[u8]) -> Result<Self> {
        let encoder = V4FrameEncoder::new(psk)?;
        Ok(Self::from_parts(inner, encoder))
    }

    fn from_parts(inner: W, encoder: V4FrameEncoder) -> Self {
        let record_sizer = RecordSizer::new(encoder.initial_padding_len());
        Self {
            inner,
            encoder,
            record_sizer,
            head: BytesMut::with_capacity(FRAME_HEAD_INITIAL_CAPACITY),
            payload: BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY),
        }
    }

    #[cfg(test)]
    pub(crate) async fn write_test_frame(&mut self, payload: &[u8]) -> Result<usize> {
        if payload.is_empty() {
            self.write_empty_frame().await?;
            return Ok(0);
        }

        self.payload.clear();
        self.payload.extend_from_slice(payload);
        self.write_payload_buffer(payload.len(), false).await?;
        tracing::trace!(
            payload_len = payload.len(),
            wire_len = self.head.len() + self.payload.len(),
            "wrote snell v4 frame"
        );
        Ok(payload.len())
    }

    async fn write_empty_frame(&mut self) -> Result<()> {
        self.head.clear();
        self.payload.clear();
        self.encoder.encode_empty_frame(&mut self.head)?;
        let Self { inner, head, .. } = self;
        write_all_vectored(inner, head, &[]).await?;
        Ok(())
    }

    async fn write_payload_buffer(
        &mut self,
        payload_len: usize,
        advance_record_sizer: bool,
    ) -> Result<usize> {
        self.head.clear();
        let wire_len =
            self.encoder
                .encode_payload_in_place(&mut self.payload, payload_len, &mut self.head)?;
        let Self {
            inner,
            head,
            payload,
            ..
        } = self;
        write_all_vectored(inner, head, payload).await?;
        if advance_record_sizer && payload_len != 0 {
            self.record_sizer.next_limit(Instant::now());
        }
        Ok(wire_len)
    }

    pub async fn write_payload_from_reader<R>(&mut self, plain: &mut R) -> Result<Option<usize>>
    where
        R: AsyncRead + Unpin,
    {
        let Some(frame) = self.read_payload_frame_from_reader(plain, &[]).await? else {
            return Ok(None);
        };

        let wire_len = self.write_payload_buffer(frame.payload_len, false).await?;
        self.record_sizer.commit_limit(Instant::now(), frame.limit);
        tracing::trace!(
            payload_len = frame.read_len,
            wire_len,
            "wrote snell v4 payload frame"
        );
        Ok(Some(frame.read_len))
    }

    pub async fn write_tunnel_reply_from_reader<R>(
        &mut self,
        plain: &mut R,
    ) -> Result<Option<usize>>
    where
        R: AsyncRead + Unpin,
    {
        let prefix = [COMMAND_TUNNEL];

        let Some(frame) = self.read_payload_frame_from_reader(plain, &prefix).await? else {
            return Ok(None);
        };

        let wire_len = self.write_payload_buffer(frame.payload_len, false).await?;
        self.record_sizer.commit_limit(Instant::now(), frame.limit);
        tracing::trace!(
            payload_len = frame.read_len,
            wire_len,
            "wrote snell v4 tunnel payload frame"
        );
        Ok(Some(frame.read_len))
    }

    async fn read_payload_frame_from_reader<R>(
        &mut self,
        plain: &mut R,
        prefix: &[u8],
    ) -> Result<Option<ReaderPayloadFrame>>
    where
        R: AsyncRead + Unpin,
    {
        poll_fn(|cx| {
            let now = Instant::now();
            let limit = self.record_sizer.peek_limit(now);
            let prefix_len = prefix.len();
            let Some(read_limit) = limit.checked_sub(prefix_len).filter(|limit| *limit != 0) else {
                self.payload.clear();
                return Poll::Ready(Err(crate::error::Error::PayloadTooLarge));
            };

            self.payload.clear();
            self.payload
                .reserve(limit + crate::protocol::crypto::AEAD_TAG_SIZE);
            if !prefix.is_empty() {
                self.payload.extend_from_slice(prefix);
            }

            match poll_read_into_spare(plain, cx, &mut self.payload, read_limit) {
                Poll::Pending => {
                    self.payload.clear();
                    Poll::Pending
                }
                Poll::Ready(Ok(read_len)) => {
                    if read_len == 0 {
                        self.payload.clear();
                        return Poll::Ready(Ok(None));
                    }
                    Poll::Ready(Ok(Some(ReaderPayloadFrame {
                        payload_len: prefix_len + read_len,
                        read_len,
                        limit,
                    })))
                }
                Poll::Ready(Err(err)) => {
                    self.payload.clear();
                    Poll::Ready(Err(err))
                }
            }
        })
        .await
    }

    pub async fn write_tcp_request(
        &mut self,
        host: &str,
        port: u16,
        snell_version: u8,
        reuse: bool,
    ) -> Result<()> {
        self.payload.clear();
        write_tcp_request_header(&mut self.payload, host, port, snell_version, reuse)?;
        self.write_control_scratch().await
    }

    pub async fn write_udp_request(&mut self, snell_version: u8) -> Result<()> {
        self.payload.clear();
        write_udp_request_header(&mut self.payload, snell_version)?;
        self.write_control_scratch().await
    }

    #[cfg(test)]
    pub(crate) async fn write_test_udp_packet(
        &mut self,
        address: AddressRef<'_>,
        port: u16,
        payload: &[u8],
    ) -> Result<usize> {
        self.payload.clear();
        write_udp_request_prefix(&mut self.payload, address, port)?;
        self.payload.extend_from_slice(payload);
        self.write_payload_buffer(self.payload.len(), false).await?;
        Ok(payload.len())
    }

    #[cfg(test)]
    pub(crate) async fn write_test_udp_response(
        &mut self,
        address: AddressRef<'_>,
        port: u16,
        payload: &[u8],
    ) -> Result<usize> {
        self.payload.clear();
        write_udp_response_prefix(&mut self.payload, address, port)?;
        self.payload.extend_from_slice(payload);
        self.write_payload_buffer(self.payload.len(), false).await?;
        Ok(payload.len())
    }

    pub(crate) async fn try_write_ipv4_udp_response_from_socket(
        &mut self,
        socket: &UdpSocket,
    ) -> Result<Option<(usize, SocketAddr)>> {
        self.try_write_udp_response_from_socket(socket, UdpResponseIpVersion::V4)
            .await
    }

    pub(crate) async fn try_write_ipv6_udp_response_from_socket(
        &mut self,
        socket: &UdpSocket,
    ) -> Result<Option<(usize, SocketAddr)>> {
        self.try_write_udp_response_from_socket(socket, UdpResponseIpVersion::V6)
            .await
    }

    pub(crate) fn start_payload_frame(&mut self) -> &mut BytesMut {
        self.payload.clear();
        &mut self.payload
    }

    pub(crate) async fn finish_payload_frame(&mut self, payload_len: usize) -> Result<usize> {
        self.write_payload_buffer(payload_len, false).await
    }

    pub(crate) async fn write_owned_payload_frame(
        &mut self,
        mut payload: BytesMut,
    ) -> Result<usize> {
        let payload_len = payload.len();
        std::mem::swap(&mut self.payload, &mut payload);
        self.write_payload_buffer(payload_len, false).await
    }

    pub async fn write_empty_tunnel_reply(&mut self) -> Result<()> {
        self.payload.clear();
        write_tunnel_reply(&mut self.payload, &[]);
        self.write_payload_buffer(self.payload.len(), true).await?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn write_test_tunnel_reply(&mut self, payload: &[u8]) -> Result<usize> {
        self.payload.clear();
        write_tunnel_reply(&mut self.payload, &[]);
        self.payload.extend_from_slice(payload);
        self.write_payload_buffer(self.payload.len(), true).await?;
        Ok(payload.len())
    }

    pub async fn write_pong_reply(&mut self) -> Result<()> {
        self.payload.clear();
        write_pong_reply(&mut self.payload);
        self.write_control_scratch().await
    }

    pub async fn write_error_reply(&mut self, code: u8, message: &str) -> Result<()> {
        self.payload.clear();
        write_error_reply(&mut self.payload, code, message);
        self.write_control_scratch().await
    }

    pub async fn write_zero_chunk(&mut self) -> Result<()> {
        self.write_empty_frame().await?;
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.inner.shutdown().await?;
        Ok(())
    }

    pub(crate) fn compact_buffers_for_reuse(&mut self) {
        compact_stream_buffer_for_reuse(&mut self.payload);
        self.head.clear();
        if self.head.capacity() > STREAM_BUFFER_RETAIN_CAPACITY {
            self.head = BytesMut::with_capacity(FRAME_HEAD_INITIAL_CAPACITY);
        }
    }

    #[cfg(test)]
    pub(crate) fn frame_capacity(&self) -> usize {
        self.payload.capacity()
    }

    async fn try_write_udp_response_from_socket(
        &mut self,
        socket: &UdpSocket,
        ip_version: UdpResponseIpVersion,
    ) -> Result<Option<(usize, SocketAddr)>> {
        self.payload.clear();
        let prefix_len = ip_version.prefix_len();
        let payload_limit = MAX_PACKET_SIZE - prefix_len;
        self.payload
            .reserve(MAX_PACKET_SIZE + crate::protocol::crypto::AEAD_TAG_SIZE);
        self.payload.resize(prefix_len, 0);

        let min_spare = payload_limit + 1;
        let spare_len = self.payload.chunk_mut().len();
        if spare_len < min_spare {
            self.payload.reserve(min_spare);
        }

        let (payload_len, peer) = match socket.try_recv_buf_from(&mut self.payload) {
            Ok(result) => result,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                self.payload.clear();
                return Ok(None);
            }
            Err(err) => {
                self.payload.clear();
                return Err(err.into());
            }
        };

        if payload_len > payload_limit {
            self.payload.clear();
            return Err(Error::PayloadTooLarge);
        }
        if !ip_version.matches(peer.ip()) {
            self.payload.clear();
            return Err(Error::InvalidAddressType);
        }

        let mut prefix = &mut self.payload[..prefix_len];
        write_udp_response_prefix(&mut prefix, AddressRef::Ip(peer.ip()), peer.port())?;
        debug_assert!(prefix.is_empty());

        let wire_len = self
            .write_payload_buffer(prefix_len + payload_len, false)
            .await?;
        tracing::trace!(payload_len, wire_len, "wrote snell v4 udp response frame");
        Ok(Some((payload_len, peer)))
    }

    async fn write_control_scratch(&mut self) -> Result<()> {
        self.write_plain_scratch(true).await
    }

    async fn write_plain_scratch(&mut self, advance_record_sizer: bool) -> Result<()> {
        let payload_len = self.payload.len();
        let wire_len = self
            .write_payload_buffer(payload_len, advance_record_sizer)
            .await?;
        tracing::trace!(payload_len, wire_len, "wrote snell v4 request frame");
        Ok(())
    }
}

pub struct V6StreamWriter<W> {
    inner: W,
    encoder: V6FrameEncoder,
    chunk_sizer: V6ChunkSizer,
    head: BytesMut,
    payload: BytesMut,
}

impl<W> V6StreamWriter<W>
where
    W: AsyncWrite + Unpin,
{
    pub fn new(inner: W, psk: &[u8]) -> Result<Self> {
        let encoder = V6FrameEncoder::new(psk)?;
        Ok(Self::from_parts(inner, encoder))
    }

    #[cfg(test)]
    pub(crate) fn new_with_salt(inner: W, psk: &[u8], salt: [u8; SALT_SIZE]) -> Result<Self> {
        let encoder = V6FrameEncoder::with_salt(psk, salt)?;
        Ok(Self::from_parts(inner, encoder))
    }

    fn from_parts(inner: W, encoder: V6FrameEncoder) -> Self {
        let chunk_sizer = V6ChunkSizer::new(encoder.profile().clone());
        Self {
            inner,
            encoder,
            chunk_sizer,
            head: BytesMut::with_capacity(FRAME_HEAD_INITIAL_CAPACITY),
            payload: BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY),
        }
    }

    #[cfg(test)]
    pub(crate) async fn write_test_frame(&mut self, payload: &[u8]) -> Result<usize> {
        if payload.is_empty() {
            self.write_empty_frame().await?;
            return Ok(0);
        }

        self.payload.clear();
        self.payload.extend_from_slice(payload);
        self.write_payload_buffer(payload.len(), false).await?;
        Ok(payload.len())
    }

    async fn write_empty_frame(&mut self) -> Result<()> {
        self.head.clear();
        self.payload.clear();
        self.encoder.encode_empty_frame(&mut self.head)?;
        let Self { inner, head, .. } = self;
        write_all_vectored(inner, head, &[]).await?;
        Ok(())
    }

    async fn write_payload_buffer(
        &mut self,
        payload_len: usize,
        advance_chunk_sizer: bool,
    ) -> Result<usize> {
        self.head.clear();
        let wire_len =
            self.encoder
                .encode_payload_in_place(&mut self.payload, payload_len, &mut self.head)?;
        let Self {
            inner,
            head,
            payload,
            chunk_sizer,
            ..
        } = self;
        write_all_vectored(inner, head, payload).await?;
        if advance_chunk_sizer && payload_len != 0 {
            chunk_sizer.commit_record(Instant::now());
        }
        Ok(wire_len)
    }

    pub async fn write_payload_from_reader<R>(&mut self, plain: &mut R) -> Result<Option<usize>>
    where
        R: AsyncRead + Unpin,
    {
        let Some(frame) = self.read_payload_frame_from_reader(plain, &[]).await? else {
            return Ok(None);
        };

        let wire_len = self.write_payload_buffer(frame.payload_len, false).await?;
        self.chunk_sizer.commit_record(Instant::now());
        tracing::trace!(
            payload_len = frame.read_len,
            wire_len,
            "wrote snell v6 payload frame"
        );
        Ok(Some(frame.read_len))
    }

    pub async fn write_tunnel_reply_from_reader<R>(
        &mut self,
        plain: &mut R,
    ) -> Result<Option<usize>>
    where
        R: AsyncRead + Unpin,
    {
        let prefix = [COMMAND_TUNNEL];

        let Some(frame) = self.read_payload_frame_from_reader(plain, &prefix).await? else {
            return Ok(None);
        };

        let wire_len = self.write_payload_buffer(frame.payload_len, false).await?;
        self.chunk_sizer.commit_record(Instant::now());
        tracing::trace!(
            payload_len = frame.read_len,
            wire_len,
            "wrote snell v6 tunnel payload frame"
        );
        Ok(Some(frame.read_len))
    }

    async fn read_payload_frame_from_reader<R>(
        &mut self,
        plain: &mut R,
        prefix: &[u8],
    ) -> Result<Option<ReaderPayloadFrame>>
    where
        R: AsyncRead + Unpin,
    {
        poll_fn(|cx| {
            let now = Instant::now();
            let limit = self.chunk_sizer.peek_limit(self.encoder.seq(), now);
            let prefix_len = prefix.len();
            let Some(read_limit) = limit.checked_sub(prefix_len).filter(|limit| *limit != 0) else {
                self.payload.clear();
                return Poll::Ready(Err(crate::error::Error::PayloadTooLarge));
            };

            self.payload.clear();
            self.payload
                .reserve(limit + crate::protocol::crypto::AEAD_TAG_SIZE);
            if !prefix.is_empty() {
                self.payload.extend_from_slice(prefix);
            }

            match poll_read_into_spare(plain, cx, &mut self.payload, read_limit) {
                Poll::Pending => {
                    self.payload.clear();
                    Poll::Pending
                }
                Poll::Ready(Ok(read_len)) => {
                    if read_len == 0 {
                        self.payload.clear();
                        return Poll::Ready(Ok(None));
                    }
                    Poll::Ready(Ok(Some(ReaderPayloadFrame {
                        payload_len: prefix_len + read_len,
                        read_len,
                        limit,
                    })))
                }
                Poll::Ready(Err(err)) => {
                    self.payload.clear();
                    Poll::Ready(Err(err))
                }
            }
        })
        .await
    }

    pub async fn write_tcp_request(&mut self, host: &str, port: u16, reuse: bool) -> Result<()> {
        self.payload.clear();
        write_tcp_request_header(&mut self.payload, host, port, crate::VERSION_6, reuse)?;
        self.write_control_scratch().await
    }

    pub async fn write_udp_request(&mut self) -> Result<()> {
        self.payload.clear();
        write_udp_request_header(&mut self.payload, crate::VERSION_6)?;
        self.write_control_scratch().await
    }

    #[cfg(test)]
    pub(crate) async fn write_test_udp_packet(
        &mut self,
        address: AddressRef<'_>,
        port: u16,
        payload: &[u8],
    ) -> Result<usize> {
        self.payload.clear();
        write_udp_request_prefix(&mut self.payload, address, port)?;
        self.payload.extend_from_slice(payload);
        self.write_payload_buffer(self.payload.len(), false).await?;
        Ok(payload.len())
    }

    #[cfg(test)]
    pub(crate) async fn write_test_udp_response(
        &mut self,
        address: AddressRef<'_>,
        port: u16,
        payload: &[u8],
    ) -> Result<usize> {
        self.payload.clear();
        write_udp_response_prefix(&mut self.payload, address, port)?;
        self.payload.extend_from_slice(payload);
        self.write_payload_buffer(self.payload.len(), false).await?;
        Ok(payload.len())
    }

    pub(crate) async fn try_write_ipv4_udp_response_from_socket(
        &mut self,
        socket: &UdpSocket,
    ) -> Result<Option<(usize, SocketAddr)>> {
        self.try_write_udp_response_from_socket(socket, UdpResponseIpVersion::V4)
            .await
    }

    pub(crate) async fn try_write_ipv6_udp_response_from_socket(
        &mut self,
        socket: &UdpSocket,
    ) -> Result<Option<(usize, SocketAddr)>> {
        self.try_write_udp_response_from_socket(socket, UdpResponseIpVersion::V6)
            .await
    }

    pub(crate) fn start_payload_frame(&mut self) -> &mut BytesMut {
        self.payload.clear();
        &mut self.payload
    }

    pub(crate) async fn finish_payload_frame(&mut self, payload_len: usize) -> Result<usize> {
        self.write_payload_buffer(payload_len, false).await
    }

    pub(crate) async fn write_owned_payload_frame(
        &mut self,
        mut payload: BytesMut,
    ) -> Result<usize> {
        let payload_len = payload.len();
        std::mem::swap(&mut self.payload, &mut payload);
        self.write_payload_buffer(payload_len, false).await
    }

    pub async fn write_empty_tunnel_reply(&mut self) -> Result<()> {
        self.payload.clear();
        write_tunnel_reply(&mut self.payload, &[]);
        self.write_payload_buffer(self.payload.len(), true).await?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn write_test_tunnel_reply(&mut self, payload: &[u8]) -> Result<usize> {
        self.payload.clear();
        write_tunnel_reply(&mut self.payload, &[]);
        self.payload.extend_from_slice(payload);
        self.write_payload_buffer(self.payload.len(), true).await?;
        Ok(payload.len())
    }

    pub async fn write_pong_reply(&mut self) -> Result<()> {
        self.payload.clear();
        write_pong_reply(&mut self.payload);
        self.write_control_scratch().await
    }

    pub async fn write_error_reply(&mut self, code: u8, message: &str) -> Result<()> {
        self.payload.clear();
        write_error_reply(&mut self.payload, code, message);
        self.write_control_scratch().await
    }

    pub async fn write_zero_chunk(&mut self) -> Result<()> {
        self.write_empty_frame().await?;
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.inner.shutdown().await?;
        Ok(())
    }

    pub(crate) fn compact_buffers_for_reuse(&mut self) {
        compact_stream_buffer_for_reuse(&mut self.payload);
        self.head.clear();
        if self.head.capacity() > STREAM_BUFFER_RETAIN_CAPACITY {
            self.head = BytesMut::with_capacity(FRAME_HEAD_INITIAL_CAPACITY);
        }
    }

    #[cfg(test)]
    pub(crate) fn frame_capacity(&self) -> usize {
        self.payload.capacity()
    }

    async fn try_write_udp_response_from_socket(
        &mut self,
        socket: &UdpSocket,
        ip_version: UdpResponseIpVersion,
    ) -> Result<Option<(usize, SocketAddr)>> {
        self.payload.clear();
        let prefix_len = ip_version.prefix_len();
        let payload_limit = MAX_PACKET_SIZE - prefix_len;
        self.payload
            .reserve(MAX_PACKET_SIZE + crate::protocol::crypto::AEAD_TAG_SIZE);
        self.payload.resize(prefix_len, 0);

        let min_spare = payload_limit + 1;
        let spare_len = self.payload.chunk_mut().len();
        if spare_len < min_spare {
            self.payload.reserve(min_spare);
        }

        let (payload_len, peer) = match socket.try_recv_buf_from(&mut self.payload) {
            Ok(result) => result,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                self.payload.clear();
                return Ok(None);
            }
            Err(err) => {
                self.payload.clear();
                return Err(err.into());
            }
        };

        if payload_len > payload_limit {
            self.payload.clear();
            return Err(Error::PayloadTooLarge);
        }
        if !ip_version.matches(peer.ip()) {
            self.payload.clear();
            return Err(Error::InvalidAddressType);
        }

        let mut prefix = &mut self.payload[..prefix_len];
        write_udp_response_prefix(&mut prefix, AddressRef::Ip(peer.ip()), peer.port())?;
        debug_assert!(prefix.is_empty());

        let wire_len = self
            .write_payload_buffer(prefix_len + payload_len, false)
            .await?;
        tracing::trace!(payload_len, wire_len, "wrote snell v6 udp response frame");
        Ok(Some((payload_len, peer)))
    }

    async fn write_control_scratch(&mut self) -> Result<()> {
        self.write_plain_scratch(true).await
    }

    async fn write_plain_scratch(&mut self, advance_chunk_sizer: bool) -> Result<()> {
        let payload_len = self.payload.len();
        let wire_len = self
            .write_payload_buffer(payload_len, advance_chunk_sizer)
            .await?;
        tracing::trace!(payload_len, wire_len, "wrote snell v6 request frame");
        Ok(())
    }
}

pub(crate) enum SnellStreamWriter<W> {
    V4 {
        writer: Box<V4StreamWriter<W>>,
        version: u8,
    },
    V6(Box<V6StreamWriter<W>>),
}

impl<W> SnellStreamWriter<W>
where
    W: AsyncWrite + Unpin,
{
    pub(crate) fn new(inner: W, psk: &[u8], version: u8) -> Result<Self> {
        match version {
            VERSION_1 | VERSION_2 | VERSION_3 | VERSION_4 | VERSION_5 => Ok(Self::V4 {
                writer: Box::new(V4StreamWriter::new(inner, psk)?),
                version,
            }),
            VERSION_6 => Ok(Self::V6(Box::new(V6StreamWriter::new(inner, psk)?))),
            other => Err(Error::UnsupportedVersion(other)),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_v6_salt(inner: W, psk: &[u8], salt: [u8; SALT_SIZE]) -> Result<Self> {
        Ok(Self::V6(Box::new(V6StreamWriter::new_with_salt(
            inner, psk, salt,
        )?)))
    }

    pub(crate) async fn write_payload_from_reader<R>(
        &mut self,
        plain: &mut R,
    ) -> Result<Option<usize>>
    where
        R: AsyncRead + Unpin,
    {
        match self {
            Self::V4 { writer, .. } => writer.write_payload_from_reader(plain).await,
            Self::V6(writer) => writer.write_payload_from_reader(plain).await,
        }
    }

    pub(crate) async fn write_tunnel_reply_from_reader<R>(
        &mut self,
        plain: &mut R,
    ) -> Result<Option<usize>>
    where
        R: AsyncRead + Unpin,
    {
        match self {
            Self::V4 { writer, .. } => writer.write_tunnel_reply_from_reader(plain).await,
            Self::V6(writer) => writer.write_tunnel_reply_from_reader(plain).await,
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

    pub(crate) async fn finish_payload_frame(&mut self, payload_len: usize) -> Result<usize> {
        match self {
            Self::V4 { writer, .. } => writer.finish_payload_frame(payload_len).await,
            Self::V6(writer) => writer.finish_payload_frame(payload_len).await,
        }
    }

    pub(crate) async fn write_owned_payload_frame(&mut self, payload: BytesMut) -> Result<usize> {
        match self {
            Self::V4 { writer, .. } => writer.write_owned_payload_frame(payload).await,
            Self::V6(writer) => writer.write_owned_payload_frame(payload).await,
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

impl<W> From<V4StreamWriter<W>> for SnellStreamWriter<W> {
    fn from(writer: V4StreamWriter<W>) -> Self {
        Self::V4 {
            writer: Box::new(writer),
            version: VERSION_4,
        }
    }
}

impl<W> From<V6StreamWriter<W>> for SnellStreamWriter<W> {
    fn from(writer: V6StreamWriter<W>) -> Self {
        Self::V6(Box::new(writer))
    }
}

async fn write_all_vectored<W>(writer: &mut W, mut first: &[u8], mut second: &[u8]) -> Result<()>
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

fn poll_read_into_spare<R>(
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
fn poll_read_ahead_into_spare<R>(
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

fn compact_stream_buffer_for_reuse(buffer: &mut BytesMut) {
    buffer.clear();
    if buffer.capacity() > STREAM_BUFFER_RETAIN_CAPACITY {
        *buffer = BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY);
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use core::range::Range;
    use std::io::{self, Cursor};
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, duplex, sink};
    use tokio::net::UdpSocket;

    use super::{
        FRAME_HEAD_INITIAL_CAPACITY, RecordSizer, STREAM_BUFFER_INITIAL_CAPACITY,
        STREAM_BUFFER_RETAIN_CAPACITY, SnellStreamReader, SnellStreamWriter,
        TCP_FIRST_RECORD_OVERHEAD, TCP_RECORD_IDLE_TIMEOUT, TCP_RECORD_MSS,
        TCP_STEADY_RECORD_OVERHEAD, V4StreamReader, V4StreamWriter, V6StreamReader,
    };
    use crate::error::{Error, Result};
    use crate::protocol::frame_v4::V4FrameEncoder;
    use crate::protocol::frame_v6::V6SaltReplayCache;
    use crate::protocol::request::{ClientRequest, ServerReply, parse_server_reply};
    use crate::protocol::udp::{AddressRef, parse_udp_request, parse_udp_response};

    #[test]
    fn record_sizer_applies_first_idle_and_continuous_limits() {
        let initial_padding_len = 256;
        let mut sizer = RecordSizer::new(initial_padding_len);
        let start = Instant::now();

        let first = TCP_RECORD_MSS - TCP_FIRST_RECORD_OVERHEAD - initial_padding_len;
        let steady = TCP_RECORD_MSS - TCP_STEADY_RECORD_OVERHEAD;

        assert_eq!(sizer.next_limit(start), first);
        assert_eq!(
            sizer.next_limit(start + Duration::from_secs(1)),
            first + steady
        );
        assert_eq!(sizer.next_limit(start + Duration::from_secs(32)), steady);
        assert_eq!(
            sizer.next_limit(start + Duration::from_secs(33)),
            steady + steady
        );
    }

    fn writer_with_initial_padding(initial_padding_len: usize) -> V4StreamWriter<tokio::io::Sink> {
        let encoder = V4FrameEncoder::with_salt_and_initial_padding(
            b"test psk",
            [0x44; 16],
            initial_padding_len,
        )
        .unwrap();
        V4StreamWriter::from_parts(sink(), encoder)
    }

    fn assert_first_record_sized<W>(writer: &V4StreamWriter<W>, expected_limit: usize) {
        assert_eq!(writer.record_sizer.last_limit, expected_limit);
        assert!(writer.record_sizer.last_record_at.is_some());
    }

    async fn write_payload<W>(writer: &mut V4StreamWriter<W>, mut payload: &[u8]) -> Result<usize>
    where
        W: AsyncWrite + Unpin,
    {
        let total = payload.len();
        while !payload.is_empty() {
            let chunk_len = payload
                .len()
                .min(writer.record_sizer.next_limit(Instant::now()));
            let slot = writer.start_payload_frame();
            slot.extend_from_slice(&payload[..chunk_len]);
            writer.finish_payload_frame(chunk_len).await?;
            payload = &payload[chunk_len..];
        }
        Ok(total)
    }

    fn encode_test_frame(encoder: &mut V4FrameEncoder, payload: &[u8], wire: &mut BytesMut) {
        let mut head = BytesMut::new();
        if payload.is_empty() {
            encoder.encode_empty_frame(&mut head).unwrap();
            wire.extend_from_slice(&head);
            return;
        }

        let mut body = BytesMut::from(payload);
        encoder
            .encode_payload_in_place(&mut body, payload.len(), &mut head)
            .unwrap();
        wire.extend_from_slice(&head);
        wire.extend_from_slice(&body);
    }

    struct PendingThenReadyReader {
        payload: Vec<u8>,
        pending_once: bool,
        wake_after: Duration,
    }

    impl PendingThenReadyReader {
        fn new(payload: Vec<u8>, wake_after: Duration) -> Self {
            Self {
                payload,
                pending_once: true,
                wake_after,
            }
        }
    }

    impl AsyncRead for PendingThenReadyReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.pending_once {
                self.pending_once = false;
                let waker = cx.waker().clone();
                let wake_after = self.wake_after;
                std::thread::spawn(move || {
                    std::thread::sleep(wake_after);
                    waker.wake();
                });
                return Poll::Pending;
            }

            let n = self.payload.len().min(buf.remaining());
            if n != 0 {
                buf.put_slice(&self.payload[..n]);
                self.payload.drain(..n);
            }
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn write_payload_rechecks_record_limit_after_pending_read() {
        const PSK: &[u8] = b"test psk";
        const SALT: [u8; 16] = [0x44; 16];

        let steady = TCP_RECORD_MSS - TCP_STEADY_RECORD_OVERHEAD;
        let continuous = steady + steady;
        let encoder = V4FrameEncoder::with_salt_and_initial_padding(PSK, SALT, 0).unwrap();
        let mut writer = V4StreamWriter::from_parts(sink(), encoder);
        writer.record_sizer.last_limit = steady;
        writer.record_sizer.last_record_at =
            Some(Instant::now() - TCP_RECORD_IDLE_TIMEOUT + Duration::from_millis(200));

        let mut reader =
            PendingThenReadyReader::new(vec![0x51; continuous], Duration::from_millis(250));
        let n = writer.write_payload_from_reader(&mut reader).await.unwrap();

        assert_eq!(n, Some(steady));
        assert_eq!(writer.record_sizer.last_limit, steady);
    }

    #[test]
    fn stream_buffers_start_with_small_capacity() {
        let psk = b"test psk";
        let reader = V4StreamReader::new(tokio::io::empty(), psk).unwrap();
        let writer = V4StreamWriter::new(sink(), psk).unwrap();

        assert_eq!(reader.body.capacity(), STREAM_BUFFER_INITIAL_CAPACITY);
        assert_eq!(writer.payload.capacity(), STREAM_BUFFER_INITIAL_CAPACITY);
        assert_eq!(writer.head.capacity(), FRAME_HEAD_INITIAL_CAPACITY);
    }

    #[tokio::test]
    async fn compact_for_reuse_retains_bounded_stream_buffers() {
        let psk = b"test psk";
        let large_payload = vec![0x51; 4096];
        let (writer_io, reader_io) = duplex(8192);
        let mut writer = V4StreamWriter::new(writer_io, psk).unwrap();
        let mut reader = V4StreamReader::new(reader_io, psk).unwrap();

        let read = async {
            let payload = reader.read_frame_payload().await.unwrap();
            assert_eq!(payload.len(), large_payload.len());
            assert!(reader.body.capacity() > STREAM_BUFFER_INITIAL_CAPACITY);
            reader.compact_buffers_for_reuse();
            assert!(reader.body.capacity() > STREAM_BUFFER_INITIAL_CAPACITY);
            assert!(reader.body.capacity() <= STREAM_BUFFER_RETAIN_CAPACITY);
        };
        let write = async {
            let slot = writer.start_payload_frame();
            slot.extend_from_slice(&large_payload);
            writer
                .finish_payload_frame(large_payload.len())
                .await
                .unwrap();
            assert!(writer.payload.capacity() > STREAM_BUFFER_INITIAL_CAPACITY);
            writer.compact_buffers_for_reuse();
            assert!(writer.payload.capacity() > STREAM_BUFFER_INITIAL_CAPACITY);
            assert!(writer.payload.capacity() <= STREAM_BUFFER_RETAIN_CAPACITY);
        };

        let ((), ()) = tokio::join!(read, write);
    }

    #[test]
    fn compact_for_reuse_resets_oversized_stream_buffers() {
        let psk = b"test psk";
        let mut reader = V4StreamReader::new(tokio::io::empty(), psk).unwrap();
        let mut writer = V4StreamWriter::new(sink(), psk).unwrap();

        reader.body.reserve(STREAM_BUFFER_RETAIN_CAPACITY + 1);
        writer.payload.reserve(STREAM_BUFFER_RETAIN_CAPACITY + 1);
        assert!(reader.body.capacity() > STREAM_BUFFER_RETAIN_CAPACITY);
        assert!(writer.payload.capacity() > STREAM_BUFFER_RETAIN_CAPACITY);

        reader.compact_buffers_for_reuse();
        writer.compact_buffers_for_reuse();

        assert_eq!(reader.body.capacity(), STREAM_BUFFER_INITIAL_CAPACITY);
        assert_eq!(writer.payload.capacity(), STREAM_BUFFER_INITIAL_CAPACITY);
    }

    #[tokio::test]
    async fn tunnel_reply_from_reader_counts_prefix_in_first_record_limit() {
        const PSK: &[u8] = b"test psk";
        const SALT: [u8; 16] = [0x44; 16];

        let initial_padding_len = 8;
        let first_limit = TCP_RECORD_MSS - TCP_FIRST_RECORD_OVERHEAD - initial_padding_len;
        let payload = vec![0x51; first_limit + 10];
        let (server, client) = duplex(4096);

        let read = async {
            let mut reader = V4StreamReader::new(client, PSK).unwrap();
            let frame = reader.read_frame_payload().await.unwrap();
            assert_eq!(frame.len(), first_limit);

            let reply = parse_server_reply(frame).unwrap();
            assert_eq!(
                reply,
                ServerReply::Tunnel {
                    payload_span: Range {
                        start: 1,
                        end: first_limit,
                    },
                    payload: &payload[..first_limit - 1],
                }
            );
        };
        let write = async {
            let encoder =
                V4FrameEncoder::with_salt_and_initial_padding(PSK, SALT, initial_padding_len)
                    .unwrap();
            let mut writer = V4StreamWriter::from_parts(server, encoder);
            let mut plain = &payload[..];
            let n = writer
                .write_tunnel_reply_from_reader(&mut plain)
                .await
                .unwrap();
            assert_eq!(n, Some(first_limit - 1));
            assert_first_record_sized(&writer, first_limit);
        };

        let ((), ()) = tokio::join!(read, write);
    }

    #[tokio::test]
    async fn control_frames_advance_record_sizer() {
        let initial_padding_len = 8;
        let first_limit = TCP_RECORD_MSS - TCP_FIRST_RECORD_OVERHEAD - initial_padding_len;

        let mut writer = writer_with_initial_padding(initial_padding_len);
        writer
            .write_tcp_request("example.com", 443, crate::VERSION_4, false)
            .await
            .unwrap();
        assert_first_record_sized(&writer, first_limit);

        let mut writer = writer_with_initial_padding(initial_padding_len);
        writer.write_udp_request(crate::VERSION_4).await.unwrap();
        assert_first_record_sized(&writer, first_limit);

        let mut writer = writer_with_initial_padding(initial_padding_len);
        writer.write_test_tunnel_reply(&[]).await.unwrap();
        assert_first_record_sized(&writer, first_limit);

        let mut writer = writer_with_initial_padding(initial_padding_len);
        writer.write_pong_reply().await.unwrap();
        assert_first_record_sized(&writer, first_limit);

        let mut writer = writer_with_initial_padding(initial_padding_len);
        writer.write_error_reply(3, "blocked").await.unwrap();
        assert_first_record_sized(&writer, first_limit);
    }

    #[tokio::test]
    async fn datagram_frames_do_not_advance_record_sizer() {
        let initial_padding_len = 8;

        let mut writer = writer_with_initial_padding(initial_padding_len);
        writer
            .write_test_udp_packet(
                AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                53,
                b"query",
            )
            .await
            .unwrap();
        assert_eq!(writer.record_sizer.last_limit, 0);
        assert!(writer.record_sizer.last_record_at.is_none());

        let mut writer = writer_with_initial_padding(initial_padding_len);
        writer
            .write_test_udp_response(
                AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
                53,
                b"answer",
            )
            .await
            .unwrap();
        assert_eq!(writer.record_sizer.last_limit, 0);
        assert!(writer.record_sizer.last_record_at.is_none());
    }

    #[tokio::test]
    async fn transfers_frames_without_spawn_or_channel() {
        let (client, server) = duplex(4096);
        let psk = b"test psk";
        let payload = b"hello over tokio";

        let read = async {
            let mut reader = V4StreamReader::new(server, psk).unwrap();
            let out = reader.read_frame_payload().await.unwrap();
            assert_eq!(out, payload);
            out.len()
        };
        let write = async {
            let mut writer = V4StreamWriter::new(client, psk).unwrap();
            writer.write_test_frame(payload).await
        };

        let (read_result, write_result) = tokio::join!(read, write);
        assert_eq!(write_result.unwrap(), payload.len());
        assert_eq!(read_result, payload.len());
    }

    #[tokio::test]
    async fn snell_stream_v6_reads_tcp_request_and_payload_frames() {
        let (client, server) = duplex(4096);
        let psk = b"test psk";
        let payload = b"hello over snell v6";

        let read = async {
            let mut reader = SnellStreamReader::new(server, psk, crate::VERSION_6).unwrap();
            let request = reader.read_client_request().await.unwrap();
            assert_eq!(
                request,
                ClientRequest::Connect {
                    reuse: false,
                    host: "example.com",
                    port: 443,
                    rest_span: Range { start: 17, end: 17 },
                    rest: b"",
                }
            );

            let out = reader.read_frame_payload().await.unwrap();
            assert_eq!(out, payload);
        };
        let write = async {
            let mut writer = SnellStreamWriter::new(client, psk, crate::VERSION_6).unwrap();
            writer
                .write_tcp_request("example.com", 443, false)
                .await
                .unwrap();
            writer.write_test_frame(payload).await.unwrap();
        };

        let ((), ()) = tokio::join!(read, write);
    }

    #[tokio::test]
    async fn snell_stream_v6_reads_tunnel_reply_tail_and_zero_chunk() {
        let (server, client) = duplex(4096);
        let psk = b"test psk";
        let payload = b"first v6 bytes";

        let read = async {
            let mut reader = SnellStreamReader::new(client, psk, crate::VERSION_6).unwrap();
            let payload_start = match reader.read_server_reply().await.unwrap() {
                ServerReply::Tunnel { payload_span, .. } => {
                    assert_eq!(
                        payload_span,
                        Range {
                            start: 1,
                            end: 1 + payload.len()
                        }
                    );
                    payload_span.start
                }
                ServerReply::Pong | ServerReply::Error { .. } => unreachable!(),
            };
            let pending = reader.take_payload_from(payload_start);
            assert_eq!(&pending[..], payload);
            assert!(matches!(
                reader.read_frame_payload().await,
                Err(Error::ZeroChunk)
            ));
        };
        let write = async {
            let mut writer = SnellStreamWriter::new(server, psk, crate::VERSION_6).unwrap();
            writer.write_test_tunnel_reply(payload).await.unwrap();
            writer.write_zero_chunk().await.unwrap();
        };

        let ((), ()) = tokio::join!(read, write);
    }

    #[tokio::test]
    async fn v6_reader_rejects_replayed_salt_from_shared_cache() {
        let psk = b"test psk";
        let salt = [0x77; 16];
        let cache = V6SaltReplayCache::new(16);

        let (first_client, first_server) = duplex(4096);
        let first_read = async {
            let mut reader =
                V6StreamReader::with_salt_replay_cache(first_server, psk, Some(cache.clone()))
                    .unwrap();
            assert_eq!(reader.read_frame_payload().await.unwrap(), b"first");
        };
        let first_write = async {
            let mut writer = SnellStreamWriter::new_with_v6_salt(first_client, psk, salt).unwrap();
            writer.write_test_frame(b"first").await.unwrap();
        };
        let ((), ()) = tokio::join!(first_read, first_write);

        let (second_client, second_server) = duplex(4096);
        let second_read = async {
            let mut reader =
                V6StreamReader::with_salt_replay_cache(second_server, psk, Some(cache)).unwrap();
            assert!(matches!(
                reader.read_frame_payload().await,
                Err(Error::SaltReplay)
            ));
        };
        let second_write = async {
            let mut writer = SnellStreamWriter::new_with_v6_salt(second_client, psk, salt).unwrap();
            writer.write_test_frame(b"second").await.unwrap();
        };
        let ((), ()) = tokio::join!(second_read, second_write);
    }

    #[tokio::test]
    async fn reader_new_does_not_wait_for_peer_salt() {
        let (client, server) = duplex(4096);
        let psk = b"test psk";
        let payload = b"hello after lazy reader";

        let mut reader = V4StreamReader::new(server, psk).unwrap();

        let read = async {
            let out = reader.read_frame_payload().await.unwrap();
            assert_eq!(out, payload);
            out.len()
        };
        let write = async {
            let mut writer = V4StreamWriter::new(client, psk).unwrap();
            writer.write_test_frame(payload).await
        };

        let (read_result, write_result) = tokio::join!(read, write);
        assert_eq!(write_result.unwrap(), payload.len());
        assert_eq!(read_result, payload.len());
    }

    #[tokio::test]
    async fn reader_drops_psk_after_decoder_initialization() {
        let (client, server) = duplex(4096);
        let psk = b"test psk";
        let payload = b"hello after psk clear";

        let read = async {
            let mut reader = V4StreamReader::new(server, psk).unwrap();
            assert_eq!(&reader.psk[..], psk);
            let out = reader.read_frame_payload().await.unwrap();
            assert_eq!(out, payload);
            assert!(reader.psk.is_empty());
        };
        let write = async {
            let mut writer = V4StreamWriter::new(client, psk).unwrap();
            writer.write_test_frame(payload).await
        };

        let ((), write_result) = tokio::join!(read, write);
        assert_eq!(write_result.unwrap(), payload.len());
    }

    #[tokio::test]
    async fn transfers_zero_chunk_as_protocol_eof_signal() {
        let (client, server) = duplex(4096);
        let psk = b"test psk";

        let read = async {
            let mut reader = V4StreamReader::new(server, psk).unwrap();
            matches!(reader.read_frame_payload().await, Err(Error::ZeroChunk))
        };
        let write = async {
            let mut writer = V4StreamWriter::new(client, psk).unwrap();
            writer.write_zero_chunk().await.unwrap();
        };

        let (read_result, _) = tokio::join!(read, write);
        assert!(read_result);
    }

    #[tokio::test]
    async fn writes_tcp_request_without_external_header_allocation() {
        let (client, server) = duplex(4096);
        let psk = b"test psk";

        let read = async {
            let mut reader = V4StreamReader::new(server, psk).unwrap();
            let out = reader.read_frame_payload().await.unwrap();
            assert_eq!(out[0], crate::protocol::header::PROTOCOL_VERSION);
            assert_eq!(out[1], crate::protocol::header::COMMAND_CONNECT);
            assert_eq!(out[3], b"example.com".len() as u8);
            out.len()
        };
        let write = async {
            let mut writer = V4StreamWriter::new(client, psk).unwrap();
            writer
                .write_tcp_request("example.com", 443, crate::VERSION_4, false)
                .await
        };

        let (read_result, write_result) = tokio::join!(read, write);
        write_result.unwrap();
        assert!(read_result > 0);
    }

    #[tokio::test]
    async fn write_payload_uses_record_sizer_for_tcp_chunks() {
        const PSK: &[u8] = b"test psk";
        const SALT: [u8; 16] = [0x44; 16];

        let initial_padding_len = 8;
        let first_limit = TCP_RECORD_MSS - TCP_FIRST_RECORD_OVERHEAD - initial_padding_len;
        let second_limit = first_limit + (TCP_RECORD_MSS - TCP_STEADY_RECORD_OVERHEAD);
        let payload = vec![0x51; first_limit + second_limit + 10];
        let (client, server) = duplex(8192);

        let read = async {
            let mut reader = V4StreamReader::new(server, PSK).unwrap();
            let out = reader.read_frame_payload().await.unwrap();
            let first = out.len();
            assert_eq!(first, first_limit);
            assert_eq!(out.len(), first_limit);

            let out = reader.read_frame_payload().await.unwrap();
            let second = out.len();
            assert_eq!(second, second_limit);
            assert_eq!(out.len(), second_limit);

            let out = reader.read_frame_payload().await.unwrap();
            let third = out.len();
            assert_eq!(third, 10);
            assert_eq!(out.len(), 10);
        };
        let write = async {
            let encoder =
                V4FrameEncoder::with_salt_and_initial_padding(PSK, SALT, initial_padding_len)
                    .unwrap();
            let mut writer = V4StreamWriter::from_parts(client, encoder);
            write_payload(&mut writer, &payload).await
        };

        let ((), write_result) = tokio::join!(read, write);
        assert_eq!(write_result.unwrap(), payload.len());
    }

    #[tokio::test]
    async fn write_payload_continues_record_sizer_after_tcp_request() {
        const PSK: &[u8] = b"test psk";
        const SALT: [u8; 16] = [0x44; 16];

        let initial_padding_len = 8;
        let first_limit = TCP_RECORD_MSS - TCP_FIRST_RECORD_OVERHEAD - initial_padding_len;
        let second_limit = first_limit + (TCP_RECORD_MSS - TCP_STEADY_RECORD_OVERHEAD);
        let payload = vec![0x51; second_limit + 10];
        let (client, server) = duplex(8192);

        let read = async {
            let mut reader = V4StreamReader::new(server, PSK).unwrap();
            reader.read_frame_payload().await.unwrap();

            let out = reader.read_frame_payload().await.unwrap();
            let first_payload_frame = out.len();
            assert_eq!(first_payload_frame, second_limit);
            assert_eq!(out.len(), second_limit);

            let out = reader.read_frame_payload().await.unwrap();
            let second_payload_frame = out.len();
            assert_eq!(second_payload_frame, 10);
            assert_eq!(out.len(), 10);
        };
        let write = async {
            let encoder =
                V4FrameEncoder::with_salt_and_initial_padding(PSK, SALT, initial_padding_len)
                    .unwrap();
            let mut writer = V4StreamWriter::from_parts(client, encoder);
            writer
                .write_tcp_request("example.com", 443, crate::VERSION_4, false)
                .await
                .unwrap();
            write_payload(&mut writer, &payload).await
        };

        let ((), write_result) = tokio::join!(read, write);
        assert_eq!(write_result.unwrap(), payload.len());
    }

    #[tokio::test]
    async fn writes_udp_packet_as_one_frame() {
        let (client, server) = duplex(4096);
        let psk = b"test psk";
        let payload = b"hello udp";

        let read = async {
            let mut reader = V4StreamReader::new(server, psk).unwrap();
            let out = reader.read_frame_payload().await.unwrap();
            let parsed = parse_udp_request(out).unwrap();
            assert_eq!(parsed.payload, payload);
            assert_eq!(parsed.port, 53);
            out.len()
        };
        let write = async {
            let mut writer = V4StreamWriter::new(client, psk).unwrap();
            writer
                .write_test_udp_packet(
                    AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                    53,
                    payload,
                )
                .await
        };

        let (read_result, write_result) = tokio::join!(read, write);
        assert_eq!(write_result.unwrap(), payload.len());
        assert!(read_result > payload.len());
    }

    #[tokio::test]
    async fn write_udp_packet_does_not_use_record_sizer() {
        let (client, server) = duplex(8192);
        let psk = b"test psk";
        let payload = vec![0x61; 3000];

        let read = async {
            let mut reader = V4StreamReader::new(server, psk).unwrap();
            let out = reader.read_frame_payload().await.unwrap();
            let parsed = parse_udp_request(out).unwrap();
            assert_eq!(parsed.payload, payload);
            assert_eq!(parsed.port, 53);
            out.len()
        };
        let write = async {
            let mut writer = V4StreamWriter::new(client, psk).unwrap();
            writer
                .write_test_udp_packet(
                    AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
                    53,
                    &payload,
                )
                .await
        };

        let (read_result, write_result) = tokio::join!(read, write);
        assert_eq!(write_result.unwrap(), payload.len());
        assert!(read_result > payload.len());
    }

    #[tokio::test]
    async fn writes_udp_response_from_ready_ipv4_socket() {
        let (client, server) = duplex(4096);
        let psk = b"test psk";
        let payload = b"udp answer";
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let sender_addr = sender.local_addr().unwrap();

        sender
            .send_to(payload, socket.local_addr().unwrap())
            .await
            .unwrap();

        let read = async {
            let mut reader = V4StreamReader::new(server, psk).unwrap();
            let frame = reader.read_frame_payload().await.unwrap();
            let response = parse_udp_response(frame).unwrap();
            assert_eq!(response.address, AddressRef::Ip(sender_addr.ip()));
            assert_eq!(response.port, sender_addr.port());
            assert_eq!(response.payload, payload);
        };
        let write = async {
            socket.readable().await.unwrap();
            let mut writer = V4StreamWriter::new(client, psk).unwrap();
            let result = writer
                .try_write_ipv4_udp_response_from_socket(&socket)
                .await
                .unwrap();
            assert_eq!(result, Some((payload.len(), sender_addr)));
            assert_eq!(writer.record_sizer.last_limit, 0);
            assert!(writer.record_sizer.last_record_at.is_none());
        };

        let ((), ()) = tokio::join!(read, write);
    }

    #[tokio::test]
    async fn rejects_oversized_udp_packet_as_one_frame() {
        let (client, _server) = duplex(4096);
        let psk = b"test psk";
        let payload = vec![0x61; crate::MAX_PACKET_SIZE];

        let mut writer = V4StreamWriter::new(client, psk).unwrap();
        assert!(matches!(
            writer
                .write_test_udp_packet(
                    AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
                    53,
                    &payload,
                )
                .await,
            Err(Error::PayloadTooLarge)
        ));
    }

    #[tokio::test]
    async fn reads_client_connect_request() {
        let (client, server) = duplex(4096);
        let psk = b"test psk";

        let read = async {
            let mut reader = V4StreamReader::new(server, psk).unwrap();
            let request = reader.read_client_request().await.unwrap();
            assert_eq!(
                request,
                ClientRequest::Connect {
                    reuse: true,
                    host: "example.com",
                    port: 443,
                    rest_span: Range { start: 17, end: 17 },
                    rest: b"",
                }
            );
        };
        let write = async {
            let mut writer = V4StreamWriter::new(client, psk).unwrap();
            writer
                .write_tcp_request("example.com", 443, crate::VERSION_4, true)
                .await
        };

        let ((), write_result) = tokio::join!(read, write);
        write_result.unwrap();
    }

    #[tokio::test]
    async fn reads_tunnel_reply_with_first_payload() {
        let (server, client) = duplex(4096);
        let psk = b"test psk";
        let payload = b"first bytes";

        let read = async {
            let mut reader = V4StreamReader::new(client, psk).unwrap();
            let reply = reader.read_server_reply().await.unwrap();
            assert_eq!(
                reply,
                ServerReply::Tunnel {
                    payload_span: Range {
                        start: 1,
                        end: 1 + payload.len(),
                    },
                    payload: &payload[..]
                }
            );
        };
        let write = async {
            let mut writer = V4StreamWriter::new(server, psk).unwrap();
            writer.write_test_tunnel_reply(payload).await
        };

        let ((), write_result) = tokio::join!(read, write);
        assert_eq!(write_result.unwrap(), payload.len());
    }

    #[tokio::test]
    async fn takes_control_payload_tail_without_padding_or_tag() {
        let (server, client) = duplex(4096);
        let psk = b"test psk";
        let payload = b"early payload";

        let read = async {
            let mut reader = V4StreamReader::new(client, psk).unwrap();
            let payload_start = {
                let reply = reader.read_server_reply().await.unwrap();
                assert_eq!(
                    reply,
                    ServerReply::Tunnel {
                        payload_span: Range {
                            start: 1,
                            end: 1 + payload.len(),
                        },
                        payload: &payload[..]
                    }
                );
                match reply {
                    ServerReply::Tunnel { payload_span, .. } => payload_span.start,
                    ServerReply::Pong | ServerReply::Error { .. } => unreachable!(),
                }
            };

            let pending = reader.take_payload_from(payload_start);
            assert_eq!(&pending[..], payload);
        };
        let write = async {
            let encoder =
                V4FrameEncoder::with_salt_and_initial_padding(psk, [0x31; 16], 128).unwrap();
            let mut writer = V4StreamWriter::from_parts(server, encoder);
            writer.write_test_tunnel_reply(payload).await
        };

        let ((), write_result) = tokio::join!(read, write);
        assert_eq!(write_result.unwrap(), payload.len());
    }

    #[tokio::test]
    async fn taking_payload_keeps_prefetched_next_frame() {
        const PSK: &[u8] = b"test psk";
        const SALT: [u8; 16] = [0x31; 16];

        let mut wire = BytesMut::new();
        let mut encoder = V4FrameEncoder::with_salt_and_initial_padding(PSK, SALT, 0).unwrap();
        let mut reply = BytesMut::new();
        crate::protocol::request::write_tunnel_reply(&mut reply, b"early");
        encode_test_frame(&mut encoder, &reply, &mut wire);
        encode_test_frame(&mut encoder, b"next frame", &mut wire);

        let mut reader = V4StreamReader::new(Cursor::new(wire), PSK).unwrap();
        let payload_start = match reader.read_server_reply().await.unwrap() {
            ServerReply::Tunnel { payload_span, .. } => payload_span.start,
            ServerReply::Pong | ServerReply::Error { .. } => unreachable!(),
        };

        let pending = reader.take_payload_from(payload_start);
        assert_eq!(&pending[..], b"early");
        assert!(!reader.body.is_empty());

        let next = reader.read_frame_payload().await.unwrap();
        assert_eq!(next, b"next frame");
    }

    #[tokio::test]
    async fn reads_server_error_reply() {
        let (server, client) = duplex(4096);
        let psk = b"test psk";

        let read = async {
            let mut reader = V4StreamReader::new(client, psk).unwrap();
            let reply = reader.read_server_reply().await.unwrap();
            assert_eq!(
                reply,
                ServerReply::Error {
                    code: 3,
                    message: "blocked"
                }
            );
        };
        let write = async {
            let mut writer = V4StreamWriter::new(server, psk).unwrap();
            writer.write_error_reply(3, "blocked").await
        };

        let ((), write_result) = tokio::join!(read, write);
        write_result.unwrap();
    }
}

use std::future::poll_fn;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::Poll;
use std::time::{Duration, Instant};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::UdpSocket;
use zeroize::Zeroizing;

use crate::MAX_PACKET_SIZE;
use crate::error::{Error, Result};
use crate::protocol::crypto::SALT_SIZE;
use crate::protocol::frame_v4::{
    DecodedHeader, V4_HEADER_CIPHER_SIZE, V4FrameDecoder, V4FrameEncoder,
};
use crate::protocol::header::{COMMAND_TUNNEL, write_tcp_request_header, write_udp_request_header};
use crate::protocol::request::{
    ClientRequest, ServerReply, parse_client_request, parse_server_reply, write_error_reply,
    write_pong_reply, write_tunnel_reply,
};
use crate::protocol::udp::{AddressRef, write_udp_request_prefix, write_udp_response_prefix};

pub const TCP_RECORD_MSS: usize = 1460;
pub const TCP_FIRST_RECORD_OVERHEAD: usize = 55;
pub const TCP_STEADY_RECORD_OVERHEAD: usize = 39;
pub const TCP_RECORD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const STREAM_BUFFER_INITIAL_CAPACITY: usize = 2048;
const PLAIN_BUFFER_INITIAL_CAPACITY: usize = 256;

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
    header: [u8; V4_HEADER_CIPHER_SIZE],
    body: BytesMut,
    payload_start: usize,
    payload_end: usize,
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
            header: [0; V4_HEADER_CIPHER_SIZE],
            body: BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY),
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
        let header = self.read_header().await?;
        let body_len = header.body_len()?;

        self.read_body(body_len).await?;
        let payload_len = header.payload_len;
        let payload_start = header.padding_len;
        let payload_end = payload_start + payload_len;
        let payload = self
            .decoder
            .as_mut()
            .expect("decoder initialized before payload decode")
            .decode_payload_in_place(header, &mut self.body)?;
        self.payload_start = payload_start;
        self.payload_end = payload_end;
        tracing::trace!(payload_len, body_len, "read snell v4 frame");
        Ok(payload)
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

    pub(crate) fn take_payload_from(&mut self, offset: usize) -> BytesMut {
        let payload_len = self.payload_end - self.payload_start;
        assert!(offset <= payload_len);
        let split_at = self.payload_start + offset;
        let pending_len = payload_len - offset;
        let mut pending = self.body.split_off(split_at);
        pending.truncate(pending_len);
        self.payload_start = 0;
        self.payload_end = 0;
        pending
    }

    pub(crate) fn compact_buffers_for_reuse(&mut self) {
        self.body.clear();
        self.payload_start = 0;
        self.payload_end = 0;
        self.body = BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY);
    }

    async fn read_body(&mut self, body_len: usize) -> Result<()> {
        self.body.clear();
        self.payload_start = 0;
        self.payload_end = 0;
        self.body.reserve(body_len);
        while self.body.len() < body_len {
            let remaining = body_len - self.body.len();
            let n = (&mut self.inner)
                .take(remaining as u64)
                .read_buf(&mut self.body)
                .await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "early eof reading snell frame body",
                )
                .into());
            }
        }
        Ok(())
    }

    async fn read_header(&mut self) -> Result<DecodedHeader> {
        if self.decoder.is_none() {
            let mut salt = [0; SALT_SIZE];
            self.inner.read_exact(&mut salt).await?;
            self.decoder = Some(V4FrameDecoder::new(&self.psk, salt)?);
            self.psk.clear();
        }
        self.inner.read_exact(&mut self.header).await?;
        self.decoder
            .as_mut()
            .expect("decoder initialized before header decode")
            .decode_header(&mut self.header)
    }
}

pub struct V4StreamWriter<W> {
    inner: W,
    encoder: V4FrameEncoder,
    record_sizer: RecordSizer,
    frame: BytesMut,
    plain: BytesMut,
}

struct ReaderPayloadFrame {
    payload_start: usize,
    padding_len: usize,
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
            frame: BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY),
            plain: BytesMut::with_capacity(PLAIN_BUFFER_INITIAL_CAPACITY),
        }
    }

    pub(crate) async fn write_frame(&mut self, payload: &[u8]) -> Result<usize> {
        self.frame.clear();
        self.encoder.encode_frame(payload, &mut self.frame)?;
        self.inner.write_all(&self.frame).await?;
        tracing::trace!(
            payload_len = payload.len(),
            wire_len = self.frame.len(),
            "wrote snell v4 frame"
        );
        Ok(payload.len())
    }

    pub async fn write_payload_from_reader<R>(&mut self, plain: &mut R) -> Result<Option<usize>>
    where
        R: AsyncRead + Unpin,
    {
        let Some(frame) = self.read_payload_frame_from_reader(plain, &[]).await? else {
            return Ok(None);
        };

        self.encoder.finish_frame_payload_buffer(
            frame.payload_start,
            frame.padding_len,
            frame.payload_len,
            &mut self.frame,
        )?;
        self.inner.write_all(&self.frame).await?;
        self.record_sizer.commit_limit(Instant::now(), frame.limit);
        tracing::trace!(
            payload_len = frame.read_len,
            wire_len = self.frame.len(),
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

        self.encoder.finish_frame_payload_buffer(
            frame.payload_start,
            frame.padding_len,
            frame.payload_len,
            &mut self.frame,
        )?;
        self.inner.write_all(&self.frame).await?;
        self.record_sizer.commit_limit(Instant::now(), frame.limit);
        tracing::trace!(
            payload_len = frame.read_len,
            wire_len = self.frame.len(),
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
                self.frame.clear();
                return Poll::Ready(Err(crate::error::Error::PayloadTooLarge));
            };

            self.frame.clear();
            let (payload_start, padding_len) = match self
                .encoder
                .start_frame_payload_buffer(limit, &mut self.frame)
            {
                Ok(parts) => parts,
                Err(err) => return Poll::Ready(Err(err)),
            };
            if !prefix.is_empty() {
                self.frame.extend_from_slice(prefix);
            }

            let spare_len = self.frame.chunk_mut().len();
            if spare_len < read_limit {
                self.frame.reserve(read_limit - spare_len);
            }
            let spare = self.frame.chunk_mut();
            // Same boundary Tokio's read_buf uses: poll_read may initialize
            // only the unfilled tail we hand to ReadBuf.
            let spare = unsafe { spare.as_uninit_slice_mut() };
            if spare.len() < read_limit {
                self.frame.clear();
                return Poll::Ready(Err(crate::error::Error::PayloadTooLarge));
            }
            let mut read_buf = ReadBuf::uninit(&mut spare[..read_limit]);

            match Pin::new(&mut *plain).poll_read(cx, &mut read_buf) {
                Poll::Pending => {
                    self.frame.clear();
                    Poll::Pending
                }
                Poll::Ready(Ok(())) => {
                    let read_len = read_buf.filled().len();
                    if read_len == 0 {
                        self.frame.clear();
                        return Poll::Ready(Ok(None));
                    }
                    // ReadBuf reports exactly how many bytes poll_read
                    // initialized in BytesMut's spare capacity.
                    unsafe {
                        self.frame.advance_mut(read_len);
                    }
                    Poll::Ready(Ok(Some(ReaderPayloadFrame {
                        payload_start,
                        padding_len,
                        payload_len: prefix_len + read_len,
                        read_len,
                        limit,
                    })))
                }
                Poll::Ready(Err(err)) => {
                    self.frame.clear();
                    Poll::Ready(Err(err.into()))
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
        self.plain.clear();
        write_tcp_request_header(&mut self.plain, host, port, snell_version, reuse)?;
        self.write_control_scratch().await
    }

    pub async fn write_udp_request(&mut self, snell_version: u8) -> Result<()> {
        self.plain.clear();
        write_udp_request_header(&mut self.plain, snell_version)?;
        self.write_control_scratch().await
    }

    pub async fn write_udp_packet(
        &mut self,
        address: AddressRef<'_>,
        port: u16,
        payload: &[u8],
    ) -> Result<usize> {
        self.plain.clear();
        write_udp_request_prefix(&mut self.plain, address, port)?;
        self.write_plain_parts_scratch(false, payload).await?;
        Ok(payload.len())
    }

    pub async fn write_udp_response(
        &mut self,
        address: AddressRef<'_>,
        port: u16,
        payload: &[u8],
    ) -> Result<usize> {
        self.plain.clear();
        write_udp_response_prefix(&mut self.plain, address, port)?;
        self.write_plain_parts_scratch(false, payload).await?;
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

    pub async fn write_tunnel_reply(&mut self, payload: &[u8]) -> Result<usize> {
        self.plain.clear();
        write_tunnel_reply(&mut self.plain, &[]);
        self.write_plain_parts_scratch(true, payload).await?;
        Ok(payload.len())
    }

    pub async fn write_pong_reply(&mut self) -> Result<()> {
        self.plain.clear();
        write_pong_reply(&mut self.plain);
        self.write_control_scratch().await
    }

    pub async fn write_error_reply(&mut self, code: u8, message: &str) -> Result<()> {
        self.plain.clear();
        write_error_reply(&mut self.plain, code, message);
        self.write_control_scratch().await
    }

    pub async fn write_zero_chunk(&mut self) -> Result<()> {
        self.write_frame(&[]).await?;
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.inner.shutdown().await?;
        Ok(())
    }

    pub(crate) fn compact_buffers_for_reuse(&mut self) {
        self.frame.clear();
        self.frame = BytesMut::with_capacity(STREAM_BUFFER_INITIAL_CAPACITY);
    }

    async fn try_write_udp_response_from_socket(
        &mut self,
        socket: &UdpSocket,
        ip_version: UdpResponseIpVersion,
    ) -> Result<Option<(usize, SocketAddr)>> {
        self.frame.clear();
        let prefix_len = ip_version.prefix_len();
        let payload_limit = MAX_PACKET_SIZE - prefix_len;
        let (payload_start, padding_len) = self
            .encoder
            .start_frame_payload_buffer(MAX_PACKET_SIZE, &mut self.frame)?;
        self.frame.resize(payload_start + prefix_len, 0);

        let min_spare = payload_limit + 1;
        let spare_len = self.frame.chunk_mut().len();
        if spare_len < min_spare {
            self.frame.reserve(min_spare - spare_len);
        }

        let (payload_len, peer) = match socket.try_recv_buf_from(&mut self.frame) {
            Ok(result) => result,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                self.frame.clear();
                return Ok(None);
            }
            Err(err) => {
                self.frame.clear();
                return Err(err.into());
            }
        };

        if payload_len > payload_limit {
            self.frame.clear();
            return Err(Error::PayloadTooLarge);
        }
        if !ip_version.matches(peer.ip()) {
            self.frame.clear();
            return Err(Error::InvalidAddressType);
        }

        let mut prefix = &mut self.frame[payload_start..payload_start + prefix_len];
        write_udp_response_prefix(&mut prefix, AddressRef::Ip(peer.ip()), peer.port())?;
        debug_assert!(prefix.is_empty());

        self.encoder.finish_frame_payload_buffer(
            payload_start,
            padding_len,
            prefix_len + payload_len,
            &mut self.frame,
        )?;
        self.inner.write_all(&self.frame).await?;
        tracing::trace!(
            payload_len,
            wire_len = self.frame.len(),
            "wrote snell v4 udp response frame"
        );
        Ok(Some((payload_len, peer)))
    }

    async fn write_control_scratch(&mut self) -> Result<()> {
        self.write_plain_scratch(true).await
    }

    async fn write_plain_scratch(&mut self, advance_record_sizer: bool) -> Result<()> {
        self.write_plain_parts_scratch(advance_record_sizer, &[])
            .await
    }

    async fn write_plain_parts_scratch(
        &mut self,
        advance_record_sizer: bool,
        payload_tail: &[u8],
    ) -> Result<()> {
        self.frame.clear();
        let payload_len = self.plain.len() + payload_tail.len();
        self.encoder
            .encode_frame_parts(&[&self.plain, payload_tail], &mut self.frame)?;
        self.inner.write_all(&self.frame).await?;
        if advance_record_sizer && payload_len != 0 {
            self.record_sizer.next_limit(Instant::now());
        }
        tracing::trace!(
            payload_len,
            wire_len = self.frame.len(),
            "wrote snell v4 request frame"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, duplex, sink};
    use tokio::net::UdpSocket;

    use super::{
        PLAIN_BUFFER_INITIAL_CAPACITY, RecordSizer, STREAM_BUFFER_INITIAL_CAPACITY,
        TCP_FIRST_RECORD_OVERHEAD, TCP_RECORD_IDLE_TIMEOUT, TCP_RECORD_MSS,
        TCP_STEADY_RECORD_OVERHEAD, V4StreamReader, V4StreamWriter,
    };
    use crate::error::{Error, Result};
    use crate::protocol::frame_v4::V4FrameEncoder;
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
            writer.write_frame(&payload[..chunk_len]).await?;
            payload = &payload[chunk_len..];
        }
        Ok(total)
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
        assert_eq!(writer.frame.capacity(), STREAM_BUFFER_INITIAL_CAPACITY);
        assert_eq!(writer.plain.capacity(), PLAIN_BUFFER_INITIAL_CAPACITY);
    }

    #[tokio::test]
    async fn compact_for_reuse_resets_stream_buffers() {
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
            assert_eq!(reader.body.capacity(), STREAM_BUFFER_INITIAL_CAPACITY);
        };
        let write = async {
            writer.write_frame(&large_payload).await.unwrap();
            assert!(writer.frame.capacity() > STREAM_BUFFER_INITIAL_CAPACITY);
            writer.compact_buffers_for_reuse();
            assert_eq!(writer.frame.capacity(), STREAM_BUFFER_INITIAL_CAPACITY);
        };

        let ((), ()) = tokio::join!(read, write);
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
                    payload_offset: 1,
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
        writer.write_tunnel_reply(&[]).await.unwrap();
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
            .write_udp_packet(
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
            .write_udp_response(
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
            writer.write_frame(payload).await
        };

        let (read_result, write_result) = tokio::join!(read, write);
        assert_eq!(write_result.unwrap(), payload.len());
        assert_eq!(read_result, payload.len());
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
            writer.write_frame(payload).await
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
            writer.write_frame(payload).await
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
                .write_udp_packet(
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
                .write_udp_packet(
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
                .write_udp_packet(
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
                    rest_offset: 17,
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
                    payload_offset: 1,
                    payload: &payload[..]
                }
            );
        };
        let write = async {
            let mut writer = V4StreamWriter::new(server, psk).unwrap();
            writer.write_tunnel_reply(payload).await
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
            let payload_offset = {
                let reply = reader.read_server_reply().await.unwrap();
                assert_eq!(
                    reply,
                    ServerReply::Tunnel {
                        payload_offset: 1,
                        payload: &payload[..]
                    }
                );
                match reply {
                    ServerReply::Tunnel { payload_offset, .. } => payload_offset,
                    ServerReply::Pong | ServerReply::Error { .. } => unreachable!(),
                }
            };

            let pending = reader.take_payload_from(payload_offset);
            assert_eq!(&pending[..], payload);
        };
        let write = async {
            let encoder =
                V4FrameEncoder::with_salt_and_initial_padding(psk, [0x31; 16], 128).unwrap();
            let mut writer = V4StreamWriter::from_parts(server, encoder);
            writer.write_tunnel_reply(payload).await
        };

        let ((), write_result) = tokio::join!(read, write);
        assert_eq!(write_result.unwrap(), payload.len());
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

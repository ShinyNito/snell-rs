use bytes::{Buf, Bytes, BytesMut};
use std::future::{Future, poll_fn};
use std::io::{self, Cursor, IoSlice};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, DuplexStream, ReadBuf, duplex, sink};

use super::reader::{V4StreamReader, V6StreamReader};
use super::writer::{PayloadSource, RecordSizer, V4StreamWriter, V6StreamWriter};
use super::{
    FRAME_HEAD_INITIAL_CAPACITY, PayloadWriteStatus, STREAM_BUFFER_INITIAL_CAPACITY,
    STREAM_BUFFER_RETAIN_CAPACITY, STREAM_READ_AHEAD_CAPACITY, SnellStreamReader,
    SnellStreamWriter, TCP_FIRST_RECORD_OVERHEAD, TCP_RECORD_IDLE_TIMEOUT, TCP_RECORD_MSS,
    TCP_STEADY_RECORD_OVERHEAD,
};
use crate::error::{Error, Result};
use crate::protocol::request::{
    ClientRequest, ServerReply, parse_client_request, parse_server_reply,
};
use crate::protocol::udp::{
    AddressRef, parse_udp_request, parse_udp_response, write_udp_request_prefix,
    write_udp_response_prefix,
};
use crate::protocol::v4::frame::V4FrameEncoder;
use crate::protocol::v6::{V6ChunkSizer, V6Profile, V6SaltReplayCache};
use crate::test_support::{TEST_PSK, shared_secret, test_duplex_pair, test_secret};

trait TestFrameReader {
    fn poll_test_frame_payload<'a>(&'a mut self, cx: &mut Context<'_>) -> Poll<Result<&'a [u8]>>;
}

impl<R> TestFrameReader for V4StreamReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_test_frame_payload<'a>(&'a mut self, cx: &mut Context<'_>) -> Poll<Result<&'a [u8]>> {
        self.poll_read_frame_payload(cx)
    }
}

impl<R> TestFrameReader for V6StreamReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_test_frame_payload<'a>(&'a mut self, cx: &mut Context<'_>) -> Poll<Result<&'a [u8]>> {
        self.poll_read_frame_payload(cx)
    }
}

impl<R> TestFrameReader for SnellStreamReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_test_frame_payload<'a>(&'a mut self, cx: &mut Context<'_>) -> Poll<Result<&'a [u8]>> {
        self.poll_read_frame_payload(cx)
    }
}

async fn read_frame_payload<R>(reader: &mut R) -> Result<Bytes>
where
    R: TestFrameReader,
{
    poll_fn(|cx| match reader.poll_test_frame_payload(cx) {
        Poll::Ready(Ok(payload)) => Poll::Ready(Ok(Bytes::copy_from_slice(payload))),
        Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        Poll::Pending => Poll::Pending,
    })
    .await
}

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
    let encoder =
        V4FrameEncoder::with_salt_and_initial_padding(TEST_PSK, [0x44; 16], initial_padding_len)
            .unwrap();
    V4StreamWriter::from_parts(sink(), encoder)
}

fn assert_first_record_sized<W>(writer: &V4StreamWriter<W>, expected_limit: usize) {
    assert_eq!(writer.record_sizer.last_limit, expected_limit);
    assert!(writer.record_sizer.last_record_at.is_some());
}

async fn write_payload<W>(writer: &mut V4StreamWriter<W>, payload: &[u8]) -> Result<usize>
where
    W: AsyncWrite + Unpin,
{
    let mut plain = BytesMut::from(payload);
    Ok(
        poll_fn(|cx| writer.poll_write_payload_from_buffer(&mut plain, cx))
            .await?
            .unwrap_or(0),
    )
}

async fn write_v4_tunnel_reply_message<W>(
    writer: &mut V4StreamWriter<W>,
    payload: &[u8],
) -> Result<usize>
where
    W: AsyncWrite + Unpin,
{
    if payload.is_empty() {
        writer.write_empty_tunnel_reply().await?;
        return Ok(0);
    }

    let mut plain = BytesMut::from(payload);
    Ok(
        poll_fn(|cx| writer.poll_write_tunnel_reply_from_buffer(&mut plain, cx))
            .await?
            .unwrap_or(0),
    )
}

async fn write_snell_payload_message<W>(
    writer: &mut SnellStreamWriter<W>,
    payload: &[u8],
) -> Result<usize>
where
    W: AsyncWrite + Unpin,
{
    let mut plain = BytesMut::from(payload);
    Ok(writer
        .write_payload_from_buffer(&mut plain)
        .await?
        .unwrap_or(0))
}

async fn write_snell_tunnel_reply_message<W>(
    writer: &mut SnellStreamWriter<W>,
    payload: &[u8],
) -> Result<usize>
where
    W: AsyncWrite + Unpin,
{
    if payload.is_empty() {
        writer.write_empty_tunnel_reply().await?;
        return Ok(0);
    }

    let mut plain = BytesMut::from(payload);
    Ok(
        poll_fn(|cx| writer.poll_write_tunnel_reply_from_buffer(&mut plain, cx))
            .await?
            .unwrap_or(0),
    )
}

async fn write_v4_udp_packet<W>(
    writer: &mut V4StreamWriter<W>,
    address: AddressRef<'_>,
    port: u16,
    payload: &[u8],
) -> Result<usize>
where
    W: AsyncWrite + Unpin,
{
    let mut plain = BytesMut::new();
    write_udp_request_prefix(&mut plain, address, port)?;
    plain.extend_from_slice(payload);
    let message_len = plain.len();
    if message_len > crate::MAX_PACKET_SIZE {
        return Err(Error::PayloadTooLarge);
    }
    assert_eq!(
        poll_fn(|cx| writer.poll_write_payload_from_buffer(&mut plain, cx)).await?,
        Some(message_len)
    );
    Ok(payload.len())
}

async fn write_v4_udp_response<W>(
    writer: &mut V4StreamWriter<W>,
    address: AddressRef<'_>,
    port: u16,
    payload: &[u8],
) -> Result<usize>
where
    W: AsyncWrite + Unpin,
{
    let mut plain = BytesMut::new();
    write_udp_response_prefix(&mut plain, address, port)?;
    plain.extend_from_slice(payload);
    let message_len = plain.len();
    if message_len > crate::MAX_PACKET_SIZE {
        return Err(Error::PayloadTooLarge);
    }
    assert_eq!(
        poll_fn(|cx| writer.poll_write_payload_from_buffer(&mut plain, cx)).await?,
        Some(message_len)
    );
    Ok(payload.len())
}

async fn write_v6_udp_packet<W>(
    writer: &mut V6StreamWriter<W>,
    address: AddressRef<'_>,
    port: u16,
    payload: &[u8],
) -> Result<usize>
where
    W: AsyncWrite + Unpin,
{
    let mut plain = BytesMut::new();
    write_udp_request_prefix(&mut plain, address, port)?;
    plain.extend_from_slice(payload);
    let message_len = plain.len();
    if message_len > crate::MAX_V6_RECORD_PAYLOAD_LEN {
        return Err(Error::PayloadTooLarge);
    }
    assert_eq!(
        poll_fn(|cx| writer.poll_write_payload_from_buffer(&mut plain, cx)).await?,
        Some(message_len)
    );
    Ok(payload.len())
}

async fn write_v6_udp_response<W>(
    writer: &mut V6StreamWriter<W>,
    address: AddressRef<'_>,
    port: u16,
    payload: &[u8],
) -> Result<usize>
where
    W: AsyncWrite + Unpin,
{
    let mut plain = BytesMut::new();
    write_udp_response_prefix(&mut plain, address, port)?;
    plain.extend_from_slice(payload);
    let message_len = plain.len();
    if message_len > crate::MAX_V6_RECORD_PAYLOAD_LEN {
        return Err(Error::PayloadTooLarge);
    }
    assert_eq!(
        poll_fn(|cx| writer.poll_write_payload_from_buffer(&mut plain, cx)).await?,
        Some(message_len)
    );
    Ok(payload.len())
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

fn collect_v4_reference_wire(payload: &[u8]) -> Vec<u8> {
    const SALT: [u8; 16] = [0x45; 16];

    let mut encoder = V4FrameEncoder::with_salt_and_initial_padding(TEST_PSK, SALT, 0).unwrap();
    let mut sizer = RecordSizer::new(0);
    let mut plain = payload;
    let mut wire = BytesMut::new();
    while !plain.is_empty() {
        let limit = sizer.next_limit(Instant::now());
        let chunk_len = plain.len().min(limit);
        encode_test_frame(&mut encoder, &plain[..chunk_len], &mut wire);
        plain = &plain[chunk_len..];
    }
    encode_test_frame(&mut encoder, &[], &mut wire);
    wire.to_vec()
}

async fn collect_v4_message_path_wire(payload: &[u8]) -> Vec<u8> {
    const SALT: [u8; 16] = [0x45; 16];

    collect_wire(|client| async move {
        let encoder = V4FrameEncoder::with_salt_and_initial_padding(TEST_PSK, SALT, 0).unwrap();
        let mut writer = V4StreamWriter::from_parts(client, encoder);
        let mut plain = BytesMut::from(payload);
        poll_fn(|cx| writer.poll_write_payload_from_buffer(&mut plain, cx))
            .await
            .unwrap();
        poll_fn(|cx| writer.poll_write_zero_chunk(cx))
            .await
            .unwrap();
    })
    .await
}

fn collect_v6_reference_wire(payload: &[u8]) -> Vec<u8> {
    const SALT: [u8; 16] = [0x46; 16];

    let profile = V6Profile::derive(TEST_PSK);
    let mut encoder = crate::protocol::v6::V6FrameEncoder::with_salt(TEST_PSK, SALT).unwrap();
    let mut chunk_sizer = V6ChunkSizer::new();
    let mut plain = payload;
    let mut wire = BytesMut::new();
    while !plain.is_empty() {
        let now = Instant::now();
        let limit = chunk_sizer.peek_limit(&profile, encoder.seq(), now);
        let chunk_len = plain.len().min(limit);
        let mut head = BytesMut::new();
        let mut body = BytesMut::from(&plain[..chunk_len]);
        encoder
            .encode_payload_in_place(&profile, &mut body, chunk_len, &mut head)
            .unwrap();
        wire.extend_from_slice(&head);
        wire.extend_from_slice(&body);
        chunk_sizer.commit_record(&profile, now);
        plain = &plain[chunk_len..];
    }
    let mut head = BytesMut::new();
    encoder.encode_empty_frame(&profile, &mut head).unwrap();
    wire.extend_from_slice(&head);
    wire.to_vec()
}

async fn collect_v6_message_path_wire(payload: &[u8]) -> Vec<u8> {
    const SALT: [u8; 16] = [0x46; 16];

    collect_wire(|client| async move {
        let secret = test_secret();
        let mut writer = SnellStreamWriter::new_with_v6_salt(client, &secret, SALT).unwrap();
        let mut plain = BytesMut::from(payload);
        writer.write_payload_from_buffer(&mut plain).await.unwrap();
        poll_fn(|cx| writer.poll_write_zero_chunk(cx))
            .await
            .unwrap();
    })
    .await
}

async fn collect_wire<F, Fut>(write: F) -> Vec<u8>
where
    F: FnOnce(DuplexStream) -> Fut,
    Fut: Future<Output = ()>,
{
    let (client, mut server) = duplex(512 * 1024);
    let write = write(client);
    let read = async {
        let mut wire = Vec::new();
        server.read_to_end(&mut wire).await.unwrap();
        wire
    };

    let ((), wire) = tokio::join!(write, read);
    wire
}

#[tokio::test]
async fn buffer_payload_writer_matches_reader_wire_bytes() {
    let payload = vec![0x34; 96 * 1024];

    assert_eq!(
        collect_v4_message_path_wire(&payload).await,
        collect_v4_reference_wire(&payload)
    );
    assert_eq!(
        collect_v6_message_path_wire(&payload).await,
        collect_v6_reference_wire(&payload)
    );
}

struct RecordingReadWindow {
    payload: BytesMut,
    observed: Arc<Mutex<Vec<usize>>>,
}

struct RecordingWriteSink {
    writes: Arc<Mutex<Vec<usize>>>,
}

impl RecordingWriteSink {
    fn new(writes: Arc<Mutex<Vec<usize>>>) -> Self {
        Self { writes }
    }
}

impl RecordingReadWindow {
    fn new(payload: BytesMut, observed: Arc<Mutex<Vec<usize>>>) -> Self {
        Self { payload, observed }
    }
}

impl AsyncRead for RecordingReadWindow {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.observed.lock().unwrap().push(buf.remaining());
        let n = self.payload.len().min(buf.remaining());
        if n != 0 {
            buf.put_slice(&self.payload[..n]);
            self.payload.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl PayloadSource for RecordingReadWindow {
    fn poll_read_payload_into_slots(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bufs: &mut [libc::iovec],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let offered = bufs.iter().map(|buf| buf.iov_len).sum();
        this.observed.lock().unwrap().push(offered);
        let mut copied = 0;
        for buf in bufs.iter_mut().filter(|buf| buf.iov_len != 0) {
            let n = this.payload.len().min(buf.iov_len);
            if n == 0 {
                break;
            }
            // The destination iovec points at BytesMut spare capacity owned by
            // the writer under test; copying n bytes initializes that range.
            unsafe {
                std::ptr::copy_nonoverlapping(this.payload.as_ptr(), buf.iov_base.cast(), n);
            }
            this.payload.advance(n);
            copied += n;
        }
        Poll::Ready(Ok(copied))
    }
}

impl AsyncWrite for RecordingWriteSink {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes.lock().unwrap().push(buf.len());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let n = bufs.iter().map(|buf| buf.len()).sum();
        self.writes.lock().unwrap().push(n);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn message_writer_uses_current_record_limit() {
    const PSK: &[u8] = TEST_PSK;
    const SALT: [u8; 16] = [0x44; 16];

    let steady = TCP_RECORD_MSS - TCP_STEADY_RECORD_OVERHEAD;
    let continuous = steady + steady;
    let encoder = V4FrameEncoder::with_salt_and_initial_padding(PSK, SALT, 0).unwrap();
    let (client, server) = duplex(16 * 1024);
    let mut writer = V4StreamWriter::from_parts(client, encoder);
    writer.record_sizer.last_limit = steady;
    writer.record_sizer.last_record_at =
        Some(Instant::now() - TCP_RECORD_IDLE_TIMEOUT - Duration::from_millis(1));
    let mut plain = BytesMut::from(vec![0x51; continuous].as_slice());
    let secret = shared_secret(PSK);

    let write = async {
        let n = poll_fn(|cx| writer.poll_write_payload_from_buffer(&mut plain, cx))
            .await
            .unwrap();
        assert_eq!(n, Some(continuous));
        assert!(plain.is_empty());
    };
    let read = async {
        let mut reader = V4StreamReader::new(server, &secret);
        assert_eq!(read_frame_payload(&mut reader).await.unwrap().len(), steady);
    };

    let ((), ()) = tokio::join!(write, read);
}

#[tokio::test]
async fn message_writer_batches_multiple_records_into_vectored_writes() {
    let payload = vec![0x62; 24 * 1024];

    let v4_writes = Arc::new(Mutex::new(Vec::new()));
    let encoder = V4FrameEncoder::with_salt_and_initial_padding(TEST_PSK, [0x44; 16], 0).unwrap();
    let mut v4_writer =
        V4StreamWriter::from_parts(RecordingWriteSink::new(v4_writes.clone()), encoder);
    let mut v4_plain = BytesMut::from(payload.as_slice());
    assert_eq!(
        poll_fn(|cx| v4_writer.poll_write_payload_from_buffer(&mut v4_plain, cx))
            .await
            .unwrap(),
        Some(payload.len())
    );
    assert!(v4_plain.is_empty());
    {
        let v4_writes = v4_writes.lock().unwrap();
        assert!(v4_writes.len() < 8);
        assert!(v4_writes.iter().all(|&len| len != 0));
        assert!(v4_writes.iter().any(|&len| len > TCP_RECORD_MSS * 2));
        assert!(v4_writes.iter().copied().sum::<usize>() > payload.len());
    }

    let v6_writes = Arc::new(Mutex::new(Vec::new()));
    let secret = test_secret();
    let mut v6_writer = V6StreamWriter::new_with_salt(
        RecordingWriteSink::new(v6_writes.clone()),
        &secret,
        [0x46; 16],
    )
    .unwrap();
    let mut v6_plain = BytesMut::from(payload.as_slice());
    assert_eq!(
        poll_fn(|cx| v6_writer.poll_write_payload_from_buffer(&mut v6_plain, cx))
            .await
            .unwrap(),
        Some(payload.len())
    );
    assert!(v6_plain.is_empty());
    {
        let v6_writes = v6_writes.lock().unwrap();
        assert!(v6_writes.len() < 8);
        assert!(v6_writes.iter().all(|&len| len != 0));
        assert!(v6_writes.iter().any(|&len| len > TCP_RECORD_MSS * 2));
        assert!(v6_writes.iter().copied().sum::<usize>() > payload.len());
    }
}

#[tokio::test]
async fn payload_from_source_batches_multiple_records_into_vectored_write() {
    let payload = vec![0x63; 24 * 1024];

    let v4_writes = Arc::new(Mutex::new(Vec::new()));
    let v4_reads = Arc::new(Mutex::new(Vec::new()));
    let encoder = V4FrameEncoder::with_salt_and_initial_padding(TEST_PSK, [0x44; 16], 0).unwrap();
    let mut v4_writer =
        V4StreamWriter::from_parts(RecordingWriteSink::new(v4_writes.clone()), encoder);
    let mut v4_source =
        RecordingReadWindow::new(BytesMut::from(payload.as_slice()), v4_reads.clone());
    assert_eq!(
        poll_fn(|cx| v4_writer.poll_write_payload_from_source(Pin::new(&mut v4_source), cx))
            .await
            .unwrap(),
        PayloadWriteStatus::Written(payload.len())
    );
    {
        let v4_writes = v4_writes.lock().unwrap();
        assert!(v4_writes.len() < 8);
        assert!(v4_writes.iter().any(|&len| len > TCP_RECORD_MSS * 2));
        assert!(v4_writes.iter().copied().sum::<usize>() > payload.len());
    }

    let v6_writes = Arc::new(Mutex::new(Vec::new()));
    let v6_reads = Arc::new(Mutex::new(Vec::new()));
    let secret = test_secret();
    let mut v6_writer = V6StreamWriter::new_with_salt(
        RecordingWriteSink::new(v6_writes.clone()),
        &secret,
        [0x46; 16],
    )
    .unwrap();
    let mut v6_source =
        RecordingReadWindow::new(BytesMut::from(payload.as_slice()), v6_reads.clone());
    assert_eq!(
        poll_fn(|cx| v6_writer.poll_write_payload_from_source(Pin::new(&mut v6_source), cx))
            .await
            .unwrap(),
        PayloadWriteStatus::Written(payload.len())
    );
    {
        let v6_writes = v6_writes.lock().unwrap();
        assert!(v6_writes.len() < 8);
        assert!(v6_writes.iter().any(|&len| len > TCP_RECORD_MSS * 2));
        assert!(v6_writes.iter().copied().sum::<usize>() > payload.len());
    }
}

#[test]
fn stream_buffers_start_with_small_capacity() {
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let reader = V4StreamReader::new(tokio::io::empty(), &secret);
    let writer = V4StreamWriter::new(sink(), &secret).unwrap();

    assert_eq!(reader.body.capacity(), STREAM_BUFFER_INITIAL_CAPACITY);
    assert_eq!(writer.payload.capacity(), STREAM_BUFFER_INITIAL_CAPACITY);
    assert_eq!(writer.head.capacity(), FRAME_HEAD_INITIAL_CAPACITY);
}

#[tokio::test]
async fn stream_reader_uses_large_read_ahead_window() {
    const PSK: &[u8] = TEST_PSK;
    const SALT: [u8; 16] = [0x44; 16];

    let mut wire = BytesMut::new();
    let mut encoder = V4FrameEncoder::with_salt_and_initial_padding(PSK, SALT, 0).unwrap();
    encode_test_frame(&mut encoder, b"tiny", &mut wire);

    let observed = Arc::new(Mutex::new(Vec::new()));
    let source = RecordingReadWindow::new(wire, observed.clone());
    let secret = shared_secret(PSK);
    let mut reader = V4StreamReader::new(source, &secret);

    assert_eq!(&read_frame_payload(&mut reader).await.unwrap()[..], b"tiny");
    assert!(
        observed
            .lock()
            .unwrap()
            .iter()
            .any(|remaining| *remaining >= STREAM_READ_AHEAD_CAPACITY)
    );
}

#[tokio::test]
async fn compact_for_reuse_retains_bounded_stream_buffers() {
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let large_payload = vec![0x51; 4096];
    let (writer_io, reader_io) = duplex(8192);
    let mut writer = V4StreamWriter::new(writer_io, &secret).unwrap();
    let mut reader = V4StreamReader::new(reader_io, &secret);

    let read = async {
        let mut received = BytesMut::new();
        while received.len() < large_payload.len() {
            let payload = read_frame_payload(&mut reader).await.unwrap();
            received.extend_from_slice(&payload);
        }
        assert_eq!(received.len(), large_payload.len());
        assert!(reader.body.capacity() > STREAM_BUFFER_INITIAL_CAPACITY);
        reader.compact_buffers_for_reuse();
        assert!(reader.body.capacity() <= STREAM_BUFFER_RETAIN_CAPACITY);
    };
    let write = async {
        let mut plain = BytesMut::from(&large_payload[..]);
        let written = poll_fn(|cx| writer.poll_write_payload_from_buffer(&mut plain, cx))
            .await
            .unwrap();
        assert_eq!(written, Some(large_payload.len()));
        assert!(plain.is_empty());
        writer.compact_buffers_for_reuse();
        assert!(writer.payload.capacity() <= STREAM_BUFFER_RETAIN_CAPACITY);
    };

    let ((), ()) = tokio::join!(read, write);
}

#[test]
fn compact_for_reuse_resets_oversized_stream_buffers() {
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let mut reader = V4StreamReader::new(tokio::io::empty(), &secret);
    let mut writer = V4StreamWriter::new(sink(), &secret).unwrap();

    reader.body.reserve(STREAM_BUFFER_RETAIN_CAPACITY + 1);
    writer.payload.reserve(STREAM_BUFFER_RETAIN_CAPACITY + 1);
    assert!(reader.body.capacity() > STREAM_BUFFER_RETAIN_CAPACITY);
    assert!(writer.payload.capacity() > STREAM_BUFFER_RETAIN_CAPACITY);

    reader.compact_buffers_for_reuse();
    writer.compact_buffers_for_reuse();

    assert_eq!(reader.body.capacity(), STREAM_BUFFER_INITIAL_CAPACITY);
    assert_eq!(writer.payload.capacity(), STREAM_BUFFER_INITIAL_CAPACITY);
}

#[test]
fn compact_for_reuse_does_not_copy_buffered_reader_bytes() {
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let mut v4_reader = V4StreamReader::new(tokio::io::empty(), &secret);
    let mut v6_reader = V6StreamReader::new(tokio::io::empty(), &secret);

    v4_reader.body.extend_from_slice(b"prefetched-v4");
    v4_reader.body.reserve(STREAM_BUFFER_RETAIN_CAPACITY + 1);
    let v4_ptr = v4_reader.body.as_ptr();
    let v4_capacity = v4_reader.body.capacity();
    v4_reader.compact_buffers_for_reuse();
    assert_eq!(&v4_reader.body[..], b"prefetched-v4");
    assert_eq!(v4_reader.body.as_ptr(), v4_ptr);
    assert_eq!(v4_reader.body.capacity(), v4_capacity);

    v6_reader.body.extend_from_slice(b"prefetched-v6");
    v6_reader.body.reserve(STREAM_BUFFER_RETAIN_CAPACITY + 1);
    let v6_ptr = v6_reader.body.as_ptr();
    let v6_capacity = v6_reader.body.capacity();
    v6_reader.compact_buffers_for_reuse();
    assert_eq!(&v6_reader.body[..], b"prefetched-v6");
    assert_eq!(v6_reader.body.as_ptr(), v6_ptr);
    assert_eq!(v6_reader.body.capacity(), v6_capacity);
}

#[tokio::test]
async fn tunnel_reply_from_buffer_counts_prefix_in_first_record_limit() {
    const PSK: &[u8] = TEST_PSK;
    const SALT: [u8; 16] = [0x44; 16];

    let initial_padding_len = 8;
    let first_limit = TCP_RECORD_MSS - TCP_FIRST_RECORD_OVERHEAD - initial_padding_len;
    let payload = vec![0x51; first_limit + 10];
    let (server, client) = test_duplex_pair();
    let secret = shared_secret(PSK);

    let read = async {
        let mut reader = V4StreamReader::new(client, &secret);
        let frame = read_frame_payload(&mut reader).await.unwrap();
        assert_eq!(frame.len(), first_limit);

        let reply = parse_server_reply(&frame).unwrap();
        assert_eq!(
            reply,
            ServerReply::Tunnel {
                payload_start: 1,
                payload: &payload[..first_limit - 1],
            }
        );
    };
    let write = async {
        let encoder =
            V4FrameEncoder::with_salt_and_initial_padding(PSK, SALT, initial_padding_len).unwrap();
        let mut writer = V4StreamWriter::from_parts(server, encoder);
        let mut plain = BytesMut::from(&payload[..]);
        let n = poll_fn(|cx| writer.poll_write_tunnel_reply_from_buffer(&mut plain, cx))
            .await
            .unwrap();
        assert_eq!(n, Some(payload.len()));
        assert!(plain.is_empty());
    };

    let ((), ()) = tokio::join!(read, write);
}

#[tokio::test]
async fn control_frames_advance_record_sizer() {
    let initial_padding_len = 8;
    let first_limit = TCP_RECORD_MSS - TCP_FIRST_RECORD_OVERHEAD - initial_padding_len;

    let mut writer = writer_with_initial_padding(initial_padding_len);
    poll_fn(|cx| {
        writer.poll_write_tcp_request("example.com", 443, crate::ProtocolVersion::V4, false, cx)
    })
    .await
    .unwrap();
    assert_first_record_sized(&writer, first_limit);

    let mut writer = writer_with_initial_padding(initial_padding_len);
    writer
        .write_udp_request(crate::ProtocolVersion::V4)
        .await
        .unwrap();
    assert_first_record_sized(&writer, first_limit);

    let mut writer = writer_with_initial_padding(initial_padding_len);
    writer.write_empty_tunnel_reply().await.unwrap();
    assert_first_record_sized(&writer, first_limit);

    let mut writer = writer_with_initial_padding(initial_padding_len);
    writer.write_pong_reply().await.unwrap();
    assert_first_record_sized(&writer, first_limit);

    let mut writer = writer_with_initial_padding(initial_padding_len);
    writer.write_error_reply(3, "blocked").await.unwrap();
    assert_first_record_sized(&writer, first_limit);
}

#[tokio::test]
async fn datagram_frames_advance_record_sizer() {
    let initial_padding_len = 8;
    let first_limit = TCP_RECORD_MSS - TCP_FIRST_RECORD_OVERHEAD - initial_padding_len;

    let mut writer = writer_with_initial_padding(initial_padding_len);
    write_v4_udp_packet(
        &mut writer,
        AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        53,
        b"query",
    )
    .await
    .unwrap();
    assert_first_record_sized(&writer, first_limit);

    let mut writer = writer_with_initial_padding(initial_padding_len);
    write_v4_udp_response(
        &mut writer,
        AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
        53,
        b"answer",
    )
    .await
    .unwrap();
    assert_first_record_sized(&writer, first_limit);
}

#[tokio::test]
async fn transfers_frames_without_spawn_or_channel() {
    let (client, server) = test_duplex_pair();
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let payload = b"hello over tokio";

    let read = async {
        let mut reader = V4StreamReader::new(server, &secret);
        let out = read_frame_payload(&mut reader).await.unwrap();
        assert_eq!(&out[..], payload);
        out.len()
    };
    let write = async {
        let mut writer = V4StreamWriter::new(client, &secret).unwrap();
        write_payload(&mut writer, payload).await
    };

    let (read_result, write_result) = tokio::join!(read, write);
    assert_eq!(write_result.unwrap(), payload.len());
    assert_eq!(read_result, payload.len());
}

#[tokio::test]
async fn snell_stream_v6_reads_tcp_request_and_payload_frames() {
    let (client, server) = test_duplex_pair();
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let payload = b"hello over snell v6";

    let read = async {
        let mut reader = SnellStreamReader::new(server, &secret, crate::ProtocolVersion::V6);
        let request_payload = read_frame_payload(&mut reader).await.unwrap();
        let request = parse_client_request(&request_payload).unwrap();
        assert_eq!(
            request,
            ClientRequest::Connect {
                reuse: false,
                host: "example.com",
                port: 443,
                rest_start: 17,
                rest: b"",
            }
        );

        let out = read_frame_payload(&mut reader).await.unwrap();
        assert_eq!(&out[..], payload);
    };
    let write = async {
        let mut writer =
            SnellStreamWriter::new(client, &secret, crate::ProtocolVersion::V6).unwrap();
        writer
            .write_tcp_request("example.com", 443, false)
            .await
            .unwrap();
        write_snell_payload_message(&mut writer, payload)
            .await
            .unwrap();
    };

    let ((), ()) = tokio::join!(read, write);
}

#[tokio::test]
async fn snell_stream_v6_reads_tunnel_reply_tail_and_zero_chunk() {
    let (server, client) = test_duplex_pair();
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let payload = b"first v6 bytes";

    let read = async {
        let mut reader = SnellStreamReader::new(client, &secret, crate::ProtocolVersion::V6);
        let frame_payload = read_frame_payload(&mut reader).await.unwrap();
        let payload_start = match parse_server_reply(&frame_payload).unwrap() {
            ServerReply::Tunnel { payload_start, .. } => {
                assert_eq!(payload_start, 1);
                payload_start
            }
            ServerReply::Pong | ServerReply::Error { .. } => unreachable!(),
        };
        let pending = reader.take_payload_from(payload_start);
        assert_eq!(&pending[..], payload);
        assert!(matches!(
            read_frame_payload(&mut reader).await,
            Err(Error::ZeroChunk)
        ));
    };
    let write = async {
        let mut writer =
            SnellStreamWriter::new(server, &secret, crate::ProtocolVersion::V6).unwrap();
        write_snell_tunnel_reply_message(&mut writer, payload)
            .await
            .unwrap();
        poll_fn(|cx| writer.poll_write_zero_chunk(cx))
            .await
            .unwrap();
    };

    let ((), ()) = tokio::join!(read, write);
}

#[tokio::test]
async fn v6_reader_rejects_replayed_salt_from_shared_cache() {
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let salt = [0x77; 16];
    let cache = V6SaltReplayCache::new(16);

    let (first_client, first_server) = test_duplex_pair();
    let first_read = async {
        let mut reader =
            V6StreamReader::with_salt_replay_cache(first_server, &secret, Some(cache.clone()));
        assert_eq!(
            &read_frame_payload(&mut reader).await.unwrap()[..],
            b"first"
        );
    };
    let first_write = async {
        let mut writer = SnellStreamWriter::new_with_v6_salt(first_client, &secret, salt).unwrap();
        write_snell_payload_message(&mut writer, b"first")
            .await
            .unwrap();
    };
    let ((), ()) = tokio::join!(first_read, first_write);

    let (second_client, second_server) = test_duplex_pair();
    let second_read = async {
        let mut reader =
            V6StreamReader::with_salt_replay_cache(second_server, &secret, Some(cache));
        assert!(matches!(
            read_frame_payload(&mut reader).await,
            Err(Error::SaltReplay)
        ));
    };
    let second_write = async {
        let mut writer = SnellStreamWriter::new_with_v6_salt(second_client, &secret, salt).unwrap();
        write_snell_payload_message(&mut writer, b"second")
            .await
            .unwrap();
    };
    let ((), ()) = tokio::join!(second_read, second_write);
}

#[tokio::test]
async fn reader_new_does_not_wait_for_peer_salt() {
    let (client, server) = test_duplex_pair();
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let payload = b"hello after lazy reader";

    let mut reader = V4StreamReader::new(server, &secret);

    let read = async {
        let out = read_frame_payload(&mut reader).await.unwrap();
        assert_eq!(&out[..], payload);
        out.len()
    };
    let write = async {
        let mut writer = V4StreamWriter::new(client, &secret).unwrap();
        write_payload(&mut writer, payload).await
    };

    let (read_result, write_result) = tokio::join!(read, write);
    assert_eq!(write_result.unwrap(), payload.len());
    assert_eq!(read_result, payload.len());
}

#[tokio::test]
async fn reader_initializes_decoder_after_first_frame() {
    let (client, server) = test_duplex_pair();
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let payload = b"hello after decoder init";

    let read = async {
        let mut reader = V4StreamReader::new(server, &secret);
        let out = read_frame_payload(&mut reader).await.unwrap();
        assert_eq!(&out[..], payload);
    };
    let write = async {
        let mut writer = V4StreamWriter::new(client, &secret).unwrap();
        write_payload(&mut writer, payload).await
    };

    let ((), write_result) = tokio::join!(read, write);
    assert_eq!(write_result.unwrap(), payload.len());
}

#[tokio::test]
async fn transfers_zero_chunk_as_protocol_eof_signal() {
    let (client, server) = test_duplex_pair();
    let psk = TEST_PSK;
    let secret = shared_secret(psk);

    let read = async {
        let mut reader = V4StreamReader::new(server, &secret);
        matches!(read_frame_payload(&mut reader).await, Err(Error::ZeroChunk))
    };
    let write = async {
        let mut writer = V4StreamWriter::new(client, &secret).unwrap();
        poll_fn(|cx| writer.poll_write_zero_chunk(cx))
            .await
            .unwrap();
    };

    let (read_result, _) = tokio::join!(read, write);
    assert!(read_result);
}

#[tokio::test]
async fn writes_tcp_request_without_external_header_allocation() {
    let (client, server) = test_duplex_pair();
    let psk = TEST_PSK;
    let secret = shared_secret(psk);

    let read = async {
        let mut reader = V4StreamReader::new(server, &secret);
        let out = read_frame_payload(&mut reader).await.unwrap();
        assert_eq!(out[0], crate::protocol::header::PROTOCOL_VERSION);
        assert_eq!(out[1], crate::protocol::header::COMMAND_CONNECT);
        assert_eq!(out[3], b"example.com".len() as u8);
        out.len()
    };
    let write = async {
        let mut writer = V4StreamWriter::new(client, &secret).unwrap();
        poll_fn(|cx| {
            writer.poll_write_tcp_request("example.com", 443, crate::ProtocolVersion::V4, false, cx)
        })
        .await
    };

    let (read_result, write_result) = tokio::join!(read, write);
    write_result.unwrap();
    assert!(read_result > 0);
}

#[tokio::test]
async fn write_payload_uses_record_sizer_for_tcp_chunks() {
    const PSK: &[u8] = TEST_PSK;
    const SALT: [u8; 16] = [0x44; 16];

    let initial_padding_len = 8;
    let first_limit = TCP_RECORD_MSS - TCP_FIRST_RECORD_OVERHEAD - initial_padding_len;
    let second_limit = first_limit + (TCP_RECORD_MSS - TCP_STEADY_RECORD_OVERHEAD);
    let payload = vec![0x51; first_limit + second_limit + 10];
    let (client, server) = duplex(8192);
    let secret = shared_secret(PSK);

    let read = async {
        let mut reader = V4StreamReader::new(server, &secret);
        let out = read_frame_payload(&mut reader).await.unwrap();
        let first = out.len();
        assert_eq!(first, first_limit);
        assert_eq!(out.len(), first_limit);

        let out = read_frame_payload(&mut reader).await.unwrap();
        let second = out.len();
        assert_eq!(second, second_limit);
        assert_eq!(out.len(), second_limit);

        let out = read_frame_payload(&mut reader).await.unwrap();
        let third = out.len();
        assert_eq!(third, 10);
        assert_eq!(out.len(), 10);
    };
    let write = async {
        let encoder =
            V4FrameEncoder::with_salt_and_initial_padding(PSK, SALT, initial_padding_len).unwrap();
        let mut writer = V4StreamWriter::from_parts(client, encoder);
        write_payload(&mut writer, &payload).await
    };

    let ((), write_result) = tokio::join!(read, write);
    assert_eq!(write_result.unwrap(), payload.len());
}

#[tokio::test]
async fn write_payload_continues_record_sizer_after_tcp_request() {
    const PSK: &[u8] = TEST_PSK;
    const SALT: [u8; 16] = [0x44; 16];

    let initial_padding_len = 8;
    let first_limit = TCP_RECORD_MSS - TCP_FIRST_RECORD_OVERHEAD - initial_padding_len;
    let second_limit = first_limit + (TCP_RECORD_MSS - TCP_STEADY_RECORD_OVERHEAD);
    let payload = vec![0x51; second_limit + 10];
    let (client, server) = duplex(8192);
    let secret = shared_secret(PSK);

    let read = async {
        let mut reader = V4StreamReader::new(server, &secret);
        read_frame_payload(&mut reader).await.unwrap();

        let out = read_frame_payload(&mut reader).await.unwrap();
        let first_payload_frame = out.len();
        assert_eq!(first_payload_frame, second_limit);
        assert_eq!(out.len(), second_limit);

        let out = read_frame_payload(&mut reader).await.unwrap();
        let second_payload_frame = out.len();
        assert_eq!(second_payload_frame, 10);
        assert_eq!(out.len(), 10);
    };
    let write = async {
        let encoder =
            V4FrameEncoder::with_salt_and_initial_padding(PSK, SALT, initial_padding_len).unwrap();
        let mut writer = V4StreamWriter::from_parts(client, encoder);
        poll_fn(|cx| {
            writer.poll_write_tcp_request("example.com", 443, crate::ProtocolVersion::V4, false, cx)
        })
        .await
        .unwrap();
        write_payload(&mut writer, &payload).await
    };

    let ((), write_result) = tokio::join!(read, write);
    assert_eq!(write_result.unwrap(), payload.len());
}

#[tokio::test]
async fn writes_udp_packet_as_one_frame() {
    let (client, server) = test_duplex_pair();
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let payload = b"hello udp";

    let read = async {
        let mut reader = V4StreamReader::new(server, &secret);
        let out = read_frame_payload(&mut reader).await.unwrap();
        let parsed = parse_udp_request(&out).unwrap();
        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.port, 53);
        out.len()
    };
    let write = async {
        let mut writer = V4StreamWriter::new(client, &secret).unwrap();
        write_v4_udp_packet(
            &mut writer,
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
async fn v4_udp_request_message_reader_reassembles_split_records_and_advances_record_sizer() {
    let (client, server) = duplex(140_000);
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let payload = vec![0x61; 3000];
    let expected_payload = payload.clone();

    let read = async {
        let mut reader = SnellStreamReader::new(server, &secret, crate::ProtocolVersion::V4);
        let message = poll_fn(|cx| reader.poll_read_udp_request_message(cx))
            .await
            .unwrap()
            .unwrap();
        let parsed = parse_udp_request(&message).unwrap();
        assert_eq!(parsed.payload, expected_payload);
        assert_eq!(parsed.port, 53);
        message.len()
    };
    let write = async {
        let mut writer = V4StreamWriter::new(client, &secret).unwrap();
        let written = write_v4_udp_packet(
            &mut writer,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
            53,
            &payload,
        )
        .await?;
        assert!(writer.record_sizer.last_record_at.is_some());
        Ok::<usize, Error>(written)
    };

    let (read_result, write_result) = tokio::join!(read, write);
    assert_eq!(write_result.unwrap(), payload.len());
    assert!(read_result > payload.len());
}

#[tokio::test]
async fn v6_udp_packet_splits_across_chunk_records_and_advances_chunk_state() {
    let (client, server) = duplex(140_000);
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let payload = vec![0x61; 60_000];
    let expected_payload = payload.clone();
    let expected_len = payload.len() + 9;

    let read = async {
        let mut reader = V6StreamReader::new(server, &secret);
        let mut records = 0;
        let mut concat = BytesMut::with_capacity(expected_len);
        while concat.len() < expected_len {
            let frame = read_frame_payload(&mut reader).await.unwrap();
            if records == 0 {
                let first = parse_udp_request(&frame).unwrap();
                assert_eq!(first.port, 53);
                assert!(first.payload.len() < expected_payload.len());
                assert_eq!(first.payload, &expected_payload[..first.payload.len()]);
            }
            concat.extend_from_slice(&frame);
            records += 1;
        }

        let parsed = parse_udp_request(&concat).unwrap();
        assert_eq!(parsed.payload, expected_payload);
        assert_eq!(parsed.port, 53);
        records
    };
    let write = async {
        let mut writer = V6StreamWriter::new(client, &secret).unwrap();
        let written = write_v6_udp_packet(
            &mut writer,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
            53,
            &payload,
        )
        .await?;
        assert!(writer.has_committed_chunk_record());
        Ok::<usize, Error>(written)
    };

    let (records, write_result) = tokio::join!(read, write);
    assert!(records > 1);
    assert_eq!(write_result.unwrap(), payload.len());
}

#[tokio::test]
async fn v6_udp_request_message_reader_reassembles_split_records() {
    let (client, server) = duplex(140_000);
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let payload = vec![0x63; 60_000];
    let expected_payload = payload.clone();

    let read = async {
        let mut reader = SnellStreamReader::new(server, &secret, crate::ProtocolVersion::V6);
        let message = poll_fn(|cx| reader.poll_read_udp_request_message(cx))
            .await
            .unwrap()
            .unwrap();
        let parsed = parse_udp_request(&message).unwrap();
        assert_eq!(parsed.payload, expected_payload);
        assert_eq!(parsed.port, 53);
    };
    let write = async {
        let mut writer = V6StreamWriter::new(client, &secret).unwrap();
        write_v6_udp_packet(
            &mut writer,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
            53,
            &payload,
        )
        .await
    };

    let ((), write_result) = tokio::join!(read, write);
    assert_eq!(write_result.unwrap(), payload.len());
}

#[tokio::test]
async fn v6_udp_exact_limit_message_reader_preserves_following_zero_chunk() {
    let (client, server) = duplex(140_000);
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let profile = V6Profile::derive(psk);
    let chunk_sizer = V6ChunkSizer::new();
    let first_limit = chunk_sizer.peek_limit(&profile, 0, Instant::now());
    let payload = vec![0x65; first_limit - 9];
    let expected_payload = payload.clone();

    let read = async {
        let mut reader = SnellStreamReader::new(server, &secret, crate::ProtocolVersion::V6);
        let message = poll_fn(|cx| reader.poll_read_udp_request_message(cx))
            .await
            .unwrap()
            .unwrap();
        let parsed = parse_udp_request(&message).unwrap();
        assert_eq!(parsed.payload, expected_payload);
        assert_eq!(parsed.port, 53);

        let eof = poll_fn(|cx| reader.poll_read_udp_request_message(cx))
            .await
            .unwrap();
        assert!(eof.is_none());
    };
    let write = async {
        let mut writer = V6StreamWriter::new(client, &secret).unwrap();
        let written = write_v6_udp_packet(
            &mut writer,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
            53,
            &payload,
        )
        .await?;
        poll_fn(|cx| writer.poll_write_zero_chunk(cx)).await?;
        Ok::<usize, Error>(written)
    };

    let ((), write_result) = tokio::join!(read, write);
    assert_eq!(write_result.unwrap(), payload.len());
}

#[tokio::test]
async fn v6_udp_exact_limit_request_reader_preserves_following_udp_message() {
    let (client, server) = duplex(140_000);
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let profile = V6Profile::derive(psk);
    let chunk_sizer = V6ChunkSizer::new();
    let first_limit = chunk_sizer.peek_limit(&profile, 0, Instant::now());
    let first_payload = vec![0x65; first_limit - 9];
    let second_payload = vec![0x66; 32];
    let expected_first = first_payload.clone();
    let expected_second = second_payload.clone();

    let read = async {
        let mut reader = SnellStreamReader::new(server, &secret, crate::ProtocolVersion::V6);

        let first = poll_fn(|cx| reader.poll_read_udp_request_message(cx))
            .await
            .unwrap()
            .unwrap();
        let first = parse_udp_request(&first).unwrap();
        assert_eq!(first.payload, expected_first);
        assert_eq!(first.port, 53);

        let second = poll_fn(|cx| reader.poll_read_udp_request_message(cx))
            .await
            .unwrap()
            .unwrap();
        let second = parse_udp_request(&second).unwrap();
        assert_eq!(second.payload, expected_second);
        assert_eq!(second.port, 54);
    };
    let write = async {
        let mut writer = V6StreamWriter::new(client, &secret).unwrap();
        write_v6_udp_packet(
            &mut writer,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
            53,
            &first_payload,
        )
        .await?;
        write_v6_udp_packet(
            &mut writer,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
            54,
            &second_payload,
        )
        .await
    };

    let ((), write_result) = tokio::join!(read, write);
    assert_eq!(write_result.unwrap(), second_payload.len());
}

#[tokio::test]
async fn v6_udp_response_message_can_split_one_datagram_across_records() {
    let (client, server) = duplex(140_000);
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let payload = vec![0x62; 60_000];
    let expected_payload = payload.clone();
    // IPv6 source header plus payload only; no UDP-layer datagram id,
    // fragment id, total length, continuation flag, or end marker is inserted.
    let expected_len = payload.len() + 19;

    let read = async {
        let mut reader = V6StreamReader::new(server, &secret);
        let mut records = 0;
        let mut concat = BytesMut::with_capacity(expected_len);
        while concat.len() < expected_len {
            let frame = read_frame_payload(&mut reader).await.unwrap();
            if records == 0 {
                let first = parse_udp_response(&frame).unwrap();
                assert_eq!(
                    first.address,
                    AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
                );
                assert_eq!(first.port, 53);
                assert!(first.payload.len() < expected_payload.len());
                assert_eq!(first.payload, &expected_payload[..first.payload.len()]);
            }
            concat.extend_from_slice(&frame);
            records += 1;
        }

        let response = parse_udp_response(&concat).unwrap();
        assert_eq!(
            response.address,
            AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(response.port, 53);
        assert_eq!(response.payload, expected_payload);
        records
    };
    let write = async {
        let mut writer = V6StreamWriter::new(client, &secret).unwrap();
        let mut plain = BytesMut::new();
        write_udp_response_prefix(
            &mut plain,
            AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            53,
        )?;
        plain.extend_from_slice(&payload);
        let written = poll_fn(|cx| writer.poll_write_payload_from_buffer(&mut plain, cx))
            .await?
            .unwrap_or(0);
        assert!(writer.has_committed_chunk_record());
        Ok::<usize, Error>(written)
    };

    let (records, write_result) = tokio::join!(read, write);
    assert!(records > 1);
    assert_eq!(write_result.unwrap(), expected_len);
}

#[tokio::test]
async fn v6_udp_response_message_reader_reassembles_split_records() {
    let (client, server) = duplex(140_000);
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let payload = vec![0x64; 60_000];
    let expected_payload = payload.clone();

    let read = async {
        let mut reader = SnellStreamReader::new(server, &secret, crate::ProtocolVersion::V6);
        let message = poll_fn(|cx| reader.poll_read_udp_response_message(cx))
            .await
            .unwrap()
            .unwrap();
        let parsed = parse_udp_response(&message).unwrap();
        assert_eq!(
            parsed.address,
            AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(parsed.port, 53);
        assert_eq!(parsed.payload, expected_payload);
    };
    let write = async {
        let mut writer = V6StreamWriter::new(client, &secret).unwrap();
        write_v6_udp_response(
            &mut writer,
            AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            53,
            &payload,
        )
        .await
    };

    let ((), write_result) = tokio::join!(read, write);
    assert_eq!(write_result.unwrap(), payload.len());
}

#[tokio::test]
async fn v6_udp_exact_limit_response_reader_preserves_following_udp_message() {
    let (client, server) = duplex(140_000);
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let profile = V6Profile::derive(psk);
    let chunk_sizer = V6ChunkSizer::new();
    let first_limit = chunk_sizer.peek_limit(&profile, 0, Instant::now());
    let first_payload = vec![0x67; first_limit - 19];
    let second_payload = vec![0x68; 32];
    let expected_first = first_payload.clone();
    let expected_second = second_payload.clone();

    let read = async {
        let mut reader = SnellStreamReader::new(server, &secret, crate::ProtocolVersion::V6);

        let first = poll_fn(|cx| reader.poll_read_udp_response_message(cx))
            .await
            .unwrap()
            .unwrap();
        let first = parse_udp_response(&first).unwrap();
        assert_eq!(
            first.address,
            AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(first.payload, expected_first);
        assert_eq!(first.port, 53);

        let second = poll_fn(|cx| reader.poll_read_udp_response_message(cx))
            .await
            .unwrap()
            .unwrap();
        let second = parse_udp_response(&second).unwrap();
        assert_eq!(
            second.address,
            AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(second.payload, expected_second);
        assert_eq!(second.port, 54);
    };
    let write = async {
        let mut writer = V6StreamWriter::new(client, &secret).unwrap();
        write_v6_udp_response(
            &mut writer,
            AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            53,
            &first_payload,
        )
        .await?;
        write_v6_udp_response(
            &mut writer,
            AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            54,
            &second_payload,
        )
        .await
    };

    let ((), write_result) = tokio::join!(read, write);
    assert_eq!(write_result.unwrap(), second_payload.len());
}

#[tokio::test]
async fn writes_udp_response_payload_message() {
    let (client, server) = test_duplex_pair();
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let payload = b"udp answer";
    let port = 5353;

    let read = async {
        let mut reader = V4StreamReader::new(server, &secret);
        let frame = read_frame_payload(&mut reader).await.unwrap();
        let response = parse_udp_response(&frame).unwrap();
        assert_eq!(
            response.address,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(response.port, port);
        assert_eq!(response.payload, payload);
    };
    let write = async {
        let mut writer = V4StreamWriter::new(client, &secret).unwrap();
        let mut plain = BytesMut::new();
        write_udp_response_prefix(
            &mut plain,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port,
        )
        .unwrap();
        plain.extend_from_slice(payload);
        let message_len = plain.len();
        let written = poll_fn(|cx| writer.poll_write_payload_from_buffer(&mut plain, cx))
            .await
            .unwrap();
        assert_eq!(written, Some(message_len));
        assert!(writer.record_sizer.last_record_at.is_some());
    };

    let ((), ()) = tokio::join!(read, write);
}

#[tokio::test]
async fn rejects_v4_udp_packet_that_exceeds_application_message_len() {
    let client = sink();
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let payload = vec![0x61; crate::MAX_PACKET_SIZE];

    let mut writer = V4StreamWriter::new(client, &secret).unwrap();
    assert!(matches!(
        write_v4_udp_packet(
            &mut writer,
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
            53,
            &payload,
        )
        .await,
        Err(Error::PayloadTooLarge)
    ));
}

#[tokio::test]
async fn rejects_v6_udp_packet_that_exceeds_application_message_len() {
    let writer = sink();
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let payload = vec![0x61; crate::MAX_V6_RECORD_PAYLOAD_LEN];

    let mut writer = V6StreamWriter::new(writer, &secret).unwrap();
    assert!(matches!(
        write_v6_udp_packet(
            &mut writer,
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
    let (client, server) = test_duplex_pair();
    let psk = TEST_PSK;
    let secret = shared_secret(psk);

    let read = async {
        let mut reader = V4StreamReader::new(server, &secret);
        let payload = read_frame_payload(&mut reader).await.unwrap();
        let request = parse_client_request(&payload).unwrap();
        assert_eq!(
            request,
            ClientRequest::Connect {
                reuse: true,
                host: "example.com",
                port: 443,
                rest_start: 17,
                rest: b"",
            }
        );
    };
    let write = async {
        let mut writer = V4StreamWriter::new(client, &secret).unwrap();
        poll_fn(|cx| {
            writer.poll_write_tcp_request("example.com", 443, crate::ProtocolVersion::V4, true, cx)
        })
        .await
    };

    let ((), write_result) = tokio::join!(read, write);
    write_result.unwrap();
}

#[tokio::test]
async fn reads_tunnel_reply_with_first_payload() {
    let (server, client) = test_duplex_pair();
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let payload = b"first bytes";

    let read = async {
        let mut reader = V4StreamReader::new(client, &secret);
        let frame_payload = read_frame_payload(&mut reader).await.unwrap();
        let reply = parse_server_reply(&frame_payload).unwrap();
        assert_eq!(
            reply,
            ServerReply::Tunnel {
                payload_start: 1,
                payload: &payload[..]
            }
        );
    };
    let write = async {
        let mut writer = V4StreamWriter::new(server, &secret).unwrap();
        write_v4_tunnel_reply_message(&mut writer, payload).await
    };

    let ((), write_result) = tokio::join!(read, write);
    assert_eq!(write_result.unwrap(), payload.len());
}

#[tokio::test]
async fn takes_control_payload_tail_without_padding_or_tag() {
    let (server, client) = test_duplex_pair();
    let psk = TEST_PSK;
    let secret = shared_secret(psk);
    let payload = b"early payload";

    let read = async {
        let mut reader = V4StreamReader::new(client, &secret);
        let payload_start = {
            let frame_payload = read_frame_payload(&mut reader).await.unwrap();
            let reply = parse_server_reply(&frame_payload).unwrap();
            assert_eq!(
                reply,
                ServerReply::Tunnel {
                    payload_start: 1,
                    payload: &payload[..]
                }
            );
            match reply {
                ServerReply::Tunnel { payload_start, .. } => payload_start,
                ServerReply::Pong | ServerReply::Error { .. } => unreachable!(),
            }
        };

        let pending = reader.take_payload_from(payload_start);
        assert_eq!(&pending[..], payload);
    };
    let write = async {
        let encoder = V4FrameEncoder::with_salt_and_initial_padding(psk, [0x31; 16], 128).unwrap();
        let mut writer = V4StreamWriter::from_parts(server, encoder);
        write_v4_tunnel_reply_message(&mut writer, payload).await
    };

    let ((), write_result) = tokio::join!(read, write);
    assert_eq!(write_result.unwrap(), payload.len());
}

#[tokio::test]
async fn taking_payload_keeps_prefetched_next_frame() {
    const PSK: &[u8] = TEST_PSK;
    const SALT: [u8; 16] = [0x31; 16];

    let mut wire = BytesMut::new();
    let mut encoder = V4FrameEncoder::with_salt_and_initial_padding(PSK, SALT, 0).unwrap();
    let mut reply = BytesMut::new();
    crate::protocol::request::write_tunnel_reply(&mut reply, b"early");
    encode_test_frame(&mut encoder, &reply, &mut wire);
    encode_test_frame(&mut encoder, b"next frame", &mut wire);

    let secret = shared_secret(PSK);
    let mut reader = V4StreamReader::new(Cursor::new(wire), &secret);
    let payload = read_frame_payload(&mut reader).await.unwrap();
    let payload_start = match parse_server_reply(&payload).unwrap() {
        ServerReply::Tunnel { payload_start, .. } => payload_start,
        ServerReply::Pong | ServerReply::Error { .. } => unreachable!(),
    };

    let pending = reader.take_payload_from(payload_start);
    assert_eq!(&pending[..], b"early");
    assert!(!reader.body.is_empty());

    let next = read_frame_payload(&mut reader).await.unwrap();
    assert_eq!(&next[..], b"next frame");
}

#[tokio::test]
async fn reads_server_error_reply() {
    let (server, client) = test_duplex_pair();
    let psk = TEST_PSK;
    let secret = shared_secret(psk);

    let read = async {
        let mut reader = V4StreamReader::new(client, &secret);
        let payload = read_frame_payload(&mut reader).await.unwrap();
        let reply = parse_server_reply(&payload).unwrap();
        assert_eq!(
            reply,
            ServerReply::Error {
                code: 3,
                message: "blocked"
            }
        );
    };
    let write = async {
        let mut writer = V4StreamWriter::new(server, &secret).unwrap();
        writer.write_error_reply(3, "blocked").await
    };

    let ((), write_result) = tokio::join!(read, write);
    write_result.unwrap();
}

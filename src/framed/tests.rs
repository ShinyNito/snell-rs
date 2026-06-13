use bytes::{Buf, BytesMut};
use core::range::Range;
use std::future::Future;
use std::io::{self, Cursor};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, DuplexStream, ReadBuf, duplex, sink};
use tokio::net::UdpSocket;

use super::reader::{V4StreamReader, V6StreamReader};
use super::writer::{RecordSizer, V4StreamWriter, V6StreamWriter};
use super::{
    FRAME_HEAD_INITIAL_CAPACITY, STREAM_BUFFER_INITIAL_CAPACITY, STREAM_BUFFER_RETAIN_CAPACITY,
    STREAM_READ_AHEAD_CAPACITY, SnellStreamReader, SnellStreamWriter, TCP_FIRST_RECORD_OVERHEAD,
    TCP_RECORD_IDLE_TIMEOUT, TCP_RECORD_MSS, TCP_STEADY_RECORD_OVERHEAD,
};
use crate::error::{Error, Result};
use crate::protocol::request::{
    ClientRequest, ServerReply, parse_client_request, parse_server_reply,
};
use crate::protocol::udp::{
    AddressRef, parse_udp_request, parse_udp_response, write_udp_response_prefix,
};
use crate::protocol::v4::frame::V4FrameEncoder;
use crate::protocol::v6::{V6ChunkSizer, V6Profile, V6SaltReplayCache};
use crate::test_support::{TEST_PSK, test_duplex_pair};

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

async fn collect_v4_reader_path_wire(payload: &[u8]) -> Vec<u8> {
    const SALT: [u8; 16] = [0x45; 16];

    collect_wire(|client| async move {
        let encoder = V4FrameEncoder::with_salt_and_initial_padding(TEST_PSK, SALT, 0).unwrap();
        let mut writer = V4StreamWriter::from_parts(client, encoder);
        let mut plain = payload;
        while writer
            .write_next_payload_record_from_reader(&mut plain)
            .await
            .unwrap()
            .is_some()
        {}
        writer.write_zero_chunk().await.unwrap();
    })
    .await
}

async fn collect_v4_buffer_path_wire(payload: &[u8]) -> Vec<u8> {
    const SALT: [u8; 16] = [0x45; 16];

    collect_wire(|client| async move {
        let encoder = V4FrameEncoder::with_salt_and_initial_padding(TEST_PSK, SALT, 0).unwrap();
        let mut writer = V4StreamWriter::from_parts(client, encoder);
        let mut plain = BytesMut::from(payload);
        while writer
            .write_payload_from_buffer(&mut plain)
            .await
            .unwrap()
            .is_some()
        {}
        writer.write_zero_chunk().await.unwrap();
    })
    .await
}

async fn collect_v6_reader_path_wire(payload: &[u8]) -> Vec<u8> {
    const SALT: [u8; 16] = [0x46; 16];

    collect_wire(|client| async move {
        let mut writer = SnellStreamWriter::new_with_v6_salt(client, TEST_PSK, SALT).unwrap();
        let mut plain = payload;
        while writer
            .write_next_payload_record_from_reader(&mut plain)
            .await
            .unwrap()
            .is_some()
        {}
        writer.write_zero_chunk().await.unwrap();
    })
    .await
}

async fn collect_v6_buffer_path_wire(payload: &[u8]) -> Vec<u8> {
    const SALT: [u8; 16] = [0x46; 16];

    collect_wire(|client| async move {
        let mut writer = SnellStreamWriter::new_with_v6_salt(client, TEST_PSK, SALT).unwrap();
        let mut plain = BytesMut::from(payload);
        while writer
            .write_payload_from_buffer(&mut plain)
            .await
            .unwrap()
            .is_some()
        {}
        writer.write_zero_chunk().await.unwrap();
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
        collect_v4_buffer_path_wire(&payload).await,
        collect_v4_reader_path_wire(&payload).await
    );
    assert_eq!(
        collect_v6_buffer_path_wire(&payload).await,
        collect_v6_reader_path_wire(&payload).await
    );
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

struct RecordingReadWindow {
    payload: BytesMut,
    observed: Arc<Mutex<Vec<usize>>>,
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
    const PSK: &[u8] = TEST_PSK;
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
    let n = writer
        .write_next_payload_record_from_reader(&mut reader)
        .await
        .unwrap();

    assert_eq!(n, Some(steady));
    assert_eq!(writer.record_sizer.last_limit, steady);
}

#[test]
fn stream_buffers_start_with_small_capacity() {
    let psk = TEST_PSK;
    let reader = V4StreamReader::new(tokio::io::empty(), psk);
    let writer = V4StreamWriter::new(sink(), psk).unwrap();

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
    let mut reader = V4StreamReader::new(source, PSK);

    assert_eq!(reader.read_frame_payload().await.unwrap(), b"tiny");
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
    let large_payload = vec![0x51; 4096];
    let (writer_io, reader_io) = duplex(8192);
    let mut writer = V4StreamWriter::new(writer_io, psk).unwrap();
    let mut reader = V4StreamReader::new(reader_io, psk);

    let read = async {
        let payload = reader.read_frame_payload().await.unwrap();
        assert_eq!(payload.len(), large_payload.len());
        assert!(reader.body.capacity() > STREAM_BUFFER_INITIAL_CAPACITY);
        reader.compact_buffers_for_reuse();
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
    let psk = TEST_PSK;
    let mut reader = V4StreamReader::new(tokio::io::empty(), psk);
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

#[test]
fn compact_for_reuse_does_not_copy_buffered_reader_bytes() {
    let psk = TEST_PSK;
    let mut v4_reader = V4StreamReader::new(tokio::io::empty(), psk);
    let mut v6_reader = V6StreamReader::new(tokio::io::empty(), psk);

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

    let read = async {
        let mut reader = V4StreamReader::new(client, PSK);
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
            V4FrameEncoder::with_salt_and_initial_padding(PSK, SALT, initial_padding_len).unwrap();
        let mut writer = V4StreamWriter::from_parts(server, encoder);
        let mut plain = BytesMut::from(&payload[..]);
        let n = writer
            .write_tunnel_reply_from_buffer(&mut plain)
            .await
            .unwrap();
        assert_eq!(n, Some(first_limit - 1));
        assert_eq!(plain.len(), 11);
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
        .write_tcp_request("example.com", 443, crate::ProtocolVersion::V4, false)
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
async fn datagram_frames_advance_record_sizer() {
    let initial_padding_len = 8;
    let first_limit = TCP_RECORD_MSS - TCP_FIRST_RECORD_OVERHEAD - initial_padding_len;

    let mut writer = writer_with_initial_padding(initial_padding_len);
    writer
        .write_test_udp_packet(
            AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            53,
            b"query",
        )
        .await
        .unwrap();
    assert_first_record_sized(&writer, first_limit);

    let mut writer = writer_with_initial_padding(initial_padding_len);
    writer
        .write_test_udp_response(
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
    let payload = b"hello over tokio";

    let read = async {
        let mut reader = V4StreamReader::new(server, psk);
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
    let (client, server) = test_duplex_pair();
    let psk = TEST_PSK;
    let payload = b"hello over snell v6";

    let read = async {
        let mut reader = SnellStreamReader::new(server, psk, crate::ProtocolVersion::V6);
        let request_payload = reader.read_frame_payload().await.unwrap();
        let request = parse_client_request(request_payload).unwrap();
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
        let mut writer = SnellStreamWriter::new(client, psk, crate::ProtocolVersion::V6).unwrap();
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
    let (server, client) = test_duplex_pair();
    let psk = TEST_PSK;
    let payload = b"first v6 bytes";

    let read = async {
        let mut reader = SnellStreamReader::new(client, psk, crate::ProtocolVersion::V6);
        let frame_payload = reader.read_frame_payload().await.unwrap();
        let payload_start = match parse_server_reply(frame_payload).unwrap() {
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
        let mut writer = SnellStreamWriter::new(server, psk, crate::ProtocolVersion::V6).unwrap();
        writer.write_test_tunnel_reply(payload).await.unwrap();
        writer.write_zero_chunk().await.unwrap();
    };

    let ((), ()) = tokio::join!(read, write);
}

#[tokio::test]
async fn v6_reader_rejects_replayed_salt_from_shared_cache() {
    let psk = TEST_PSK;
    let salt = [0x77; 16];
    let cache = V6SaltReplayCache::new(16);

    let (first_client, first_server) = test_duplex_pair();
    let first_read = async {
        let mut reader =
            V6StreamReader::with_salt_replay_cache(first_server, psk, Some(cache.clone()));
        assert_eq!(reader.read_frame_payload().await.unwrap(), b"first");
    };
    let first_write = async {
        let mut writer = SnellStreamWriter::new_with_v6_salt(first_client, psk, salt).unwrap();
        writer.write_test_frame(b"first").await.unwrap();
    };
    let ((), ()) = tokio::join!(first_read, first_write);

    let (second_client, second_server) = test_duplex_pair();
    let second_read = async {
        let mut reader = V6StreamReader::with_salt_replay_cache(second_server, psk, Some(cache));
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
    let (client, server) = test_duplex_pair();
    let psk = TEST_PSK;
    let payload = b"hello after lazy reader";

    let mut reader = V4StreamReader::new(server, psk);

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
    let (client, server) = test_duplex_pair();
    let psk = TEST_PSK;
    let payload = b"hello after psk clear";

    let read = async {
        let mut reader = V4StreamReader::new(server, psk);
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
    let (client, server) = test_duplex_pair();
    let psk = TEST_PSK;

    let read = async {
        let mut reader = V4StreamReader::new(server, psk);
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
    let (client, server) = test_duplex_pair();
    let psk = TEST_PSK;

    let read = async {
        let mut reader = V4StreamReader::new(server, psk);
        let out = reader.read_frame_payload().await.unwrap();
        assert_eq!(out[0], crate::protocol::header::PROTOCOL_VERSION);
        assert_eq!(out[1], crate::protocol::header::COMMAND_CONNECT);
        assert_eq!(out[3], b"example.com".len() as u8);
        out.len()
    };
    let write = async {
        let mut writer = V4StreamWriter::new(client, psk).unwrap();
        writer
            .write_tcp_request("example.com", 443, crate::ProtocolVersion::V4, false)
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

    let read = async {
        let mut reader = V4StreamReader::new(server, PSK);
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

    let read = async {
        let mut reader = V4StreamReader::new(server, PSK);
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
            V4FrameEncoder::with_salt_and_initial_padding(PSK, SALT, initial_padding_len).unwrap();
        let mut writer = V4StreamWriter::from_parts(client, encoder);
        writer
            .write_tcp_request("example.com", 443, crate::ProtocolVersion::V4, false)
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
    let payload = b"hello udp";

    let read = async {
        let mut reader = V4StreamReader::new(server, psk);
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
async fn write_udp_packet_is_single_frame_and_advances_record_sizer() {
    let (client, server) = duplex(8192);
    let psk = TEST_PSK;
    let payload = vec![0x61; 3000];
    let expected_payload = payload.clone();

    let read = async {
        let mut reader = V4StreamReader::new(server, psk);
        let out = reader.read_frame_payload().await.unwrap();
        let parsed = parse_udp_request(out).unwrap();
        assert_eq!(parsed.payload, expected_payload);
        assert_eq!(parsed.port, 53);
        out.len()
    };
    let write = async {
        let mut writer = V4StreamWriter::new(client, psk).unwrap();
        let written = writer
            .write_test_udp_packet(
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
    let payload = vec![0x61; 60_000];
    let expected_payload = payload.clone();
    let expected_len = payload.len() + 9;

    let read = async {
        let mut reader = V6StreamReader::new(server, psk);
        let mut records = 0;
        let mut concat = BytesMut::with_capacity(expected_len);
        while concat.len() < expected_len {
            let frame = reader.read_frame_payload().await.unwrap();
            if records == 0 {
                let first = parse_udp_request(frame).unwrap();
                assert_eq!(first.port, 53);
                assert!(first.payload.len() < expected_payload.len());
                assert_eq!(first.payload, &expected_payload[..first.payload.len()]);
            }
            concat.extend_from_slice(frame);
            records += 1;
        }

        let parsed = parse_udp_request(&concat).unwrap();
        assert_eq!(parsed.payload, expected_payload);
        assert_eq!(parsed.port, 53);
        records
    };
    let write = async {
        let mut writer = V6StreamWriter::new(client, psk).unwrap();
        let written = writer
            .write_test_udp_packet(
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
    let payload = vec![0x63; 60_000];
    let expected_payload = payload.clone();

    let read = async {
        let mut reader = SnellStreamReader::new(server, psk, crate::ProtocolVersion::V6);
        let mut scratch = BytesMut::new();
        let message = reader
            .read_udp_request_message(&mut scratch)
            .await
            .unwrap()
            .unwrap();
        let parsed = parse_udp_request(&message).unwrap();
        assert_eq!(parsed.payload, expected_payload);
        assert_eq!(parsed.port, 53);
    };
    let write = async {
        let mut writer = V6StreamWriter::new(client, psk).unwrap();
        writer
            .write_test_udp_packet(
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
    let chunk_sizer = V6ChunkSizer::new(V6Profile::derive(psk));
    let first_limit = chunk_sizer.peek_limit(0, Instant::now());
    let payload = vec![0x65; first_limit - 9];
    let expected_payload = payload.clone();

    let read = async {
        let mut reader = SnellStreamReader::new(server, psk, crate::ProtocolVersion::V6);
        let mut scratch = BytesMut::new();
        let message = reader
            .read_udp_request_message(&mut scratch)
            .await
            .unwrap()
            .unwrap();
        let parsed = parse_udp_request(&message).unwrap();
        assert_eq!(parsed.payload, expected_payload);
        assert_eq!(parsed.port, 53);

        let eof = reader.read_udp_request_message(&mut scratch).await.unwrap();
        assert!(eof.is_none());
    };
    let write = async {
        let mut writer = V6StreamWriter::new(client, psk).unwrap();
        let written = writer
            .write_test_udp_packet(
                AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
                53,
                &payload,
            )
            .await?;
        writer.write_zero_chunk().await?;
        Ok::<usize, Error>(written)
    };

    let ((), write_result) = tokio::join!(read, write);
    assert_eq!(write_result.unwrap(), payload.len());
}

#[tokio::test]
async fn v6_udp_exact_limit_request_reader_preserves_following_udp_message() {
    let (client, server) = duplex(140_000);
    let psk = TEST_PSK;
    let chunk_sizer = V6ChunkSizer::new(V6Profile::derive(psk));
    let first_limit = chunk_sizer.peek_limit(0, Instant::now());
    let first_payload = vec![0x65; first_limit - 9];
    let second_payload = vec![0x66; 32];
    let expected_first = first_payload.clone();
    let expected_second = second_payload.clone();

    let read = async {
        let mut reader = SnellStreamReader::new(server, psk, crate::ProtocolVersion::V6);
        let mut scratch = BytesMut::new();

        let first = reader
            .read_udp_request_message(&mut scratch)
            .await
            .unwrap()
            .unwrap();
        let first = parse_udp_request(&first).unwrap();
        assert_eq!(first.payload, expected_first);
        assert_eq!(first.port, 53);

        let second = reader
            .read_udp_request_message(&mut scratch)
            .await
            .unwrap()
            .unwrap();
        let second = parse_udp_request(&second).unwrap();
        assert_eq!(second.payload, expected_second);
        assert_eq!(second.port, 54);
    };
    let write = async {
        let mut writer = V6StreamWriter::new(client, psk).unwrap();
        writer
            .write_test_udp_packet(
                AddressRef::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
                53,
                &first_payload,
            )
            .await?;
        writer
            .write_test_udp_packet(
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
    let payload = vec![0x62; 60_000];
    let expected_payload = payload.clone();
    // IPv6 source header plus payload only; no UDP-layer datagram id,
    // fragment id, total length, continuation flag, or end marker is inserted.
    let expected_len = payload.len() + 19;

    let read = async {
        let mut reader = V6StreamReader::new(server, psk);
        let mut records = 0;
        let mut concat = BytesMut::with_capacity(expected_len);
        while concat.len() < expected_len {
            let frame = reader.read_frame_payload().await.unwrap();
            if records == 0 {
                let first = parse_udp_response(frame).unwrap();
                assert_eq!(
                    first.address,
                    AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
                );
                assert_eq!(first.port, 53);
                assert!(first.payload.len() < expected_payload.len());
                assert_eq!(first.payload, &expected_payload[..first.payload.len()]);
            }
            concat.extend_from_slice(frame);
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
        let mut writer = V6StreamWriter::new(client, psk).unwrap();
        let frame_len = {
            let frame = writer.start_payload_frame();
            write_udp_response_prefix(frame, AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)), 53)?;
            frame.extend_from_slice(&payload);
            frame.len()
        };
        let written = writer.finish_udp_payload_message(frame_len).await?;
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
    let payload = vec![0x64; 60_000];
    let expected_payload = payload.clone();

    let read = async {
        let mut reader = SnellStreamReader::new(server, psk, crate::ProtocolVersion::V6);
        let mut scratch = BytesMut::new();
        let message = reader
            .read_udp_response_message(&mut scratch)
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
        let mut writer = V6StreamWriter::new(client, psk).unwrap();
        writer
            .write_test_udp_response(
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
    let chunk_sizer = V6ChunkSizer::new(V6Profile::derive(psk));
    let first_limit = chunk_sizer.peek_limit(0, Instant::now());
    let first_payload = vec![0x67; first_limit - 19];
    let second_payload = vec![0x68; 32];
    let expected_first = first_payload.clone();
    let expected_second = second_payload.clone();

    let read = async {
        let mut reader = SnellStreamReader::new(server, psk, crate::ProtocolVersion::V6);
        let mut scratch = BytesMut::new();

        let first = reader
            .read_udp_response_message(&mut scratch)
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

        let second = reader
            .read_udp_response_message(&mut scratch)
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
        let mut writer = V6StreamWriter::new(client, psk).unwrap();
        writer
            .write_test_udp_response(
                AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                53,
                &first_payload,
            )
            .await?;
        writer
            .write_test_udp_response(
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
async fn writes_udp_response_from_ready_ipv4_socket() {
    let (client, server) = test_duplex_pair();
    let psk = TEST_PSK;
    let payload = b"udp answer";
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let sender_addr = sender.local_addr().unwrap();

    sender
        .send_to(payload, socket.local_addr().unwrap())
        .await
        .unwrap();

    let read = async {
        let mut reader = V4StreamReader::new(server, psk);
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
        assert!(writer.record_sizer.last_record_at.is_some());
    };

    let ((), ()) = tokio::join!(read, write);
}

#[tokio::test]
async fn rejects_oversized_udp_packet_as_one_frame() {
    let (client, _server) = test_duplex_pair();
    let psk = TEST_PSK;
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
async fn v6_rejects_udp_packet_that_exceeds_record_payload_len() {
    let writer = sink();
    let psk = TEST_PSK;
    let payload = vec![0x61; crate::MAX_V6_RECORD_PAYLOAD_LEN];

    let mut writer = V6StreamWriter::new(writer, psk).unwrap();
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
    let (client, server) = test_duplex_pair();
    let psk = TEST_PSK;

    let read = async {
        let mut reader = V4StreamReader::new(server, psk);
        let payload = reader.read_frame_payload().await.unwrap();
        let request = parse_client_request(payload).unwrap();
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
            .write_tcp_request("example.com", 443, crate::ProtocolVersion::V4, true)
            .await
    };

    let ((), write_result) = tokio::join!(read, write);
    write_result.unwrap();
}

#[tokio::test]
async fn reads_tunnel_reply_with_first_payload() {
    let (server, client) = test_duplex_pair();
    let psk = TEST_PSK;
    let payload = b"first bytes";

    let read = async {
        let mut reader = V4StreamReader::new(client, psk);
        let frame_payload = reader.read_frame_payload().await.unwrap();
        let reply = parse_server_reply(frame_payload).unwrap();
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
    let (server, client) = test_duplex_pair();
    let psk = TEST_PSK;
    let payload = b"early payload";

    let read = async {
        let mut reader = V4StreamReader::new(client, psk);
        let payload_start = {
            let frame_payload = reader.read_frame_payload().await.unwrap();
            let reply = parse_server_reply(frame_payload).unwrap();
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
        let encoder = V4FrameEncoder::with_salt_and_initial_padding(psk, [0x31; 16], 128).unwrap();
        let mut writer = V4StreamWriter::from_parts(server, encoder);
        writer.write_test_tunnel_reply(payload).await
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

    let mut reader = V4StreamReader::new(Cursor::new(wire), PSK);
    let payload = reader.read_frame_payload().await.unwrap();
    let payload_start = match parse_server_reply(payload).unwrap() {
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
    let (server, client) = test_duplex_pair();
    let psk = TEST_PSK;

    let read = async {
        let mut reader = V4StreamReader::new(client, psk);
        let payload = reader.read_frame_payload().await.unwrap();
        let reply = parse_server_reply(payload).unwrap();
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

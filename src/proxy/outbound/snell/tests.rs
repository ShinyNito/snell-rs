use core::range::Range;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::time::timeout;
use zeroize::Zeroizing;

use super::{ReusePool, ReusedSnellTcp, SharedPsk, SnellClientOutbound};
use crate::ProtocolVersion;
use crate::error::Error;
use crate::protocol::request::ClientRequest;
use crate::test_support::{
    TEST_PSK, test_snell_reader, test_snell_reader_with_version, test_snell_writer,
    test_snell_writer_with_version, test_tcp_listener,
};

macro_rules! assert_next_payload {
    ($conn:expr, $expected:expr) => {{
        let payload = $conn
            .reader_mut()
            .take_payload_chunk()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&payload[..], $expected);
    }};
}

fn idle_len(pool: &ReusePool) -> usize {
    pool.idle.lock().expect("reuse pool mutex poisoned").len()
}

fn shared_psk(psk: &[u8]) -> SharedPsk {
    Arc::new(Zeroizing::new(psk.to_vec()))
}

async fn pool_conn_after_reply(
    reply: &'static [u8],
    send_server_zero: bool,
    read_until_done: bool,
) -> (ReusePool, ReusedSnellTcp) {
    let listener = test_tcp_listener().await;
    let server_addr = listener.local_addr().unwrap();
    let pool = ReusePool::with_limits(
        server_addr,
        shared_psk(TEST_PSK),
        ProtocolVersion::V4,
        4,
        Duration::from_secs(60),
    )
    .unwrap();

    let server = async {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader_io, writer_io) = stream.into_split();
        let mut reader = test_snell_reader(reader_io);
        let mut server_writer = test_snell_writer(writer_io);
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

        server_writer.write_test_tunnel_reply(reply).await.unwrap();
        if send_server_zero {
            server_writer.write_zero_chunk().await.unwrap();
        }

        std::assert_matches!(reader.read_frame_payload().await, Err(Error::ZeroChunk));
    };

    let client = async {
        let mut conn = pool.open("example.com", 443).await.unwrap();
        let payload = conn
            .reader_mut()
            .take_payload_chunk()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(payload, reply);
        if read_until_done {
            assert!(
                conn.reader_mut()
                    .take_payload_chunk()
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        conn.writer_mut().close_write().await.unwrap();
        conn
    };

    let ((), conn) = tokio::join!(server, client);
    (pool, conn)
}

async fn completed_pool_conn() -> (ReusePool, ReusedSnellTcp) {
    pool_conn_after_reply(b"ok", true, true).await
}

async fn read_ok_and_close(conn: &mut ReusedSnellTcp) {
    assert_next_payload!(conn, b"ok");
    assert!(
        conn.reader_mut()
            .take_payload_chunk()
            .await
            .unwrap()
            .is_none()
    );
    conn.writer_mut().close_write().await.unwrap();
}

#[test]
fn snell_outbound_shares_psk_with_reuse_pool() {
    let server_addr = "127.0.0.1:1".parse().unwrap();
    let outbound =
        SnellClientOutbound::new(server_addr, TEST_PSK.to_vec(), true, ProtocolVersion::V4)
            .unwrap();
    let pool = outbound.pool.as_ref().expect("reuse pool");

    assert!(Arc::ptr_eq(&outbound.psk, &pool.psk));
}

#[tokio::test]
async fn reuse_pool_reuses_completed_stream() {
    let listener = test_tcp_listener().await;
    let server_addr = listener.local_addr().unwrap();
    let pool = ReusePool::with_limits(
        server_addr,
        shared_psk(TEST_PSK),
        ProtocolVersion::V4,
        2,
        Duration::from_secs(60),
    )
    .unwrap();

    let server = async {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader_io, writer_io) = stream.into_split();
        let mut reader = test_snell_reader(reader_io);
        let mut server_writer = test_snell_writer(writer_io);

        for (host, reply) in [("one.example", b"one" as &[u8]), ("two.example", b"two")] {
            let request = timeout(Duration::from_secs(1), reader.read_client_request())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                request,
                ClientRequest::Connect {
                    reuse: true,
                    host,
                    port: 443,
                    rest_span: Range { start: 17, end: 17 },
                    rest: b"",
                }
            );
            server_writer.write_test_tunnel_reply(reply).await.unwrap();
            server_writer.write_zero_chunk().await.unwrap();

            std::assert_matches!(reader.read_frame_payload().await, Err(Error::ZeroChunk));
        }

        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    };

    let client = async {
        let mut first = pool.open("one.example", 443).await.unwrap();
        assert_next_payload!(first, b"one");
        assert!(
            first
                .reader_mut()
                .take_payload_chunk()
                .await
                .unwrap()
                .is_none()
        );
        first.writer_mut().close_write().await.unwrap();
        pool.put(first).await;
        assert_eq!(idle_len(&pool), 1);

        let mut second = pool.open("two.example", 443).await.unwrap();
        assert_next_payload!(second, b"two");
        assert!(
            second
                .reader_mut()
                .take_payload_chunk()
                .await
                .unwrap()
                .is_none()
        );
        second.writer_mut().close_write().await.unwrap();
        pool.put(second).await;
        assert_eq!(idle_len(&pool), 1);
    };

    let ((), ()) = tokio::join!(server, client);
}

#[tokio::test]
async fn reuse_pool_reuses_completed_v6_stream() {
    let listener = test_tcp_listener().await;
    let server_addr = listener.local_addr().unwrap();
    let pool = ReusePool::with_limits(
        server_addr,
        shared_psk(TEST_PSK),
        ProtocolVersion::V6,
        2,
        Duration::from_secs(60),
    )
    .unwrap();

    let server = async {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader_io, writer_io) = stream.into_split();
        let mut reader = test_snell_reader_with_version(reader_io, ProtocolVersion::V6);
        let mut server_writer = test_snell_writer_with_version(writer_io, ProtocolVersion::V6);

        for (host, reply) in [("one.example", b"one" as &[u8]), ("two.example", b"two")] {
            let request = timeout(Duration::from_secs(1), reader.read_client_request())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                request,
                ClientRequest::Connect {
                    reuse: true,
                    host,
                    port: 443,
                    rest_span: Range { start: 17, end: 17 },
                    rest: b"",
                }
            );
            server_writer.write_test_tunnel_reply(reply).await.unwrap();
            server_writer.write_zero_chunk().await.unwrap();

            std::assert_matches!(reader.read_frame_payload().await, Err(Error::ZeroChunk));
        }

        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    };

    let client = async {
        let mut first = pool.open("one.example", 443).await.unwrap();
        assert_next_payload!(first, b"one");
        assert!(
            first
                .reader_mut()
                .take_payload_chunk()
                .await
                .unwrap()
                .is_none()
        );
        first.writer_mut().close_write().await.unwrap();
        pool.put(first).await;
        assert_eq!(idle_len(&pool), 1);

        let mut second = pool.open("two.example", 443).await.unwrap();
        assert_next_payload!(second, b"two");
        assert!(
            second
                .reader_mut()
                .take_payload_chunk()
                .await
                .unwrap()
                .is_none()
        );
        second.writer_mut().close_write().await.unwrap();
        pool.put(second).await;
        assert_eq!(idle_len(&pool), 1);
    };

    let ((), ()) = tokio::join!(server, client);
}

#[tokio::test]
async fn reuse_pool_prunes_expired_connections_before_put() {
    let listener = test_tcp_listener().await;
    let server_addr = listener.local_addr().unwrap();
    let pool = ReusePool::with_limits(
        server_addr,
        shared_psk(TEST_PSK),
        ProtocolVersion::V4,
        1,
        Duration::from_secs(60),
    )
    .unwrap();

    let server = async {
        for host in ["old.example", "new.example"] {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader_io, writer_io) = stream.into_split();
            let mut reader = test_snell_reader(reader_io);
            let mut server_writer = test_snell_writer(writer_io);
            let request = reader.read_client_request().await.unwrap();
            assert_eq!(
                request,
                ClientRequest::Connect {
                    reuse: true,
                    host,
                    port: 443,
                    rest_span: Range { start: 17, end: 17 },
                    rest: b"",
                }
            );
            server_writer.write_test_tunnel_reply(b"ok").await.unwrap();
            server_writer.write_zero_chunk().await.unwrap();
            std::assert_matches!(reader.read_frame_payload().await, Err(Error::ZeroChunk));
        }
    };

    let client = async {
        let mut old = pool.open("old.example", 443).await.unwrap();
        read_ok_and_close(&mut old).await;

        let mut new = pool.open("new.example", 443).await.unwrap();
        read_ok_and_close(&mut new).await;

        pool.put(old).await;
        {
            let mut idle = pool.idle.lock().expect("reuse pool mutex poisoned");
            idle.front_mut().unwrap().idle_since = Instant::now() - Duration::from_secs(61);
        }
        pool.put(new).await;

        let retained = pool.take().await.expect("fresh idle connection retained");
        assert_eq!(idle_len(&pool), 0);
        retained.close_whole_connection().await;
    };

    let ((), ()) = tokio::join!(server, client);
}

#[tokio::test]
async fn reuse_pool_drops_idle_expired_connection() {
    let (pool, conn) = completed_pool_conn().await;
    pool.put(conn).await;
    {
        let mut idle = pool.idle.lock().expect("reuse pool mutex poisoned");
        idle.front_mut().unwrap().idle_since = Instant::now() - Duration::from_secs(61);
    }

    assert!(pool.take().await.is_none());
    assert_eq!(idle_len(&pool), 0);
}

#[tokio::test]
async fn reuse_pool_close_idle_drains_idle_connections() {
    let (pool, conn) = completed_pool_conn().await;
    pool.put(conn).await;
    assert_eq!(idle_len(&pool), 1);

    pool.close_idle().await;

    assert_eq!(idle_len(&pool), 0);
}

#[tokio::test]
async fn reuse_conn_total_age_does_not_block_reuse() {
    let (_pool, conn) = completed_pool_conn().await;

    assert!(conn.can_reuse());
}

#[tokio::test]
async fn reuse_pool_keeps_only_max_size_connections() {
    let listener = test_tcp_listener().await;
    let server_addr = listener.local_addr().unwrap();
    let pool = ReusePool::with_limits(
        server_addr,
        shared_psk(TEST_PSK),
        ProtocolVersion::V4,
        1,
        Duration::from_secs(60),
    )
    .unwrap();

    let server = async {
        for host in ["one.example", "two.example"] {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader_io, writer_io) = stream.into_split();
            let mut reader = test_snell_reader(reader_io);
            let mut server_writer = test_snell_writer(writer_io);
            let request = reader.read_client_request().await.unwrap();
            assert_eq!(
                request,
                ClientRequest::Connect {
                    reuse: true,
                    host,
                    port: 443,
                    rest_span: Range { start: 17, end: 17 },
                    rest: b"",
                }
            );
            server_writer.write_test_tunnel_reply(b"ok").await.unwrap();
            server_writer.write_zero_chunk().await.unwrap();
            std::assert_matches!(reader.read_frame_payload().await, Err(Error::ZeroChunk));
        }
    };

    let client = async {
        let mut first = pool.open("one.example", 443).await.unwrap();
        read_ok_and_close(&mut first).await;

        let mut second = pool.open("two.example", 443).await.unwrap();
        read_ok_and_close(&mut second).await;

        pool.put(first).await;
        pool.put(second).await;
        assert_eq!(idle_len(&pool), 1);
    };

    let ((), ()) = tokio::join!(server, client);
}

#[tokio::test]
async fn reuse_pool_only_recycles_complete_successful_streams() {
    #[derive(Clone, Copy, Debug)]
    enum Case {
        Complete,
        PendingPayload,
        ServerStillOpen,
    }

    for case in [Case::Complete, Case::PendingPayload, Case::ServerStillOpen] {
        let (pool, conn) = match case {
            Case::PendingPayload => pool_conn_after_reply(b"pending", true, false).await,
            Case::ServerStillOpen => pool_conn_after_reply(b"ok", false, false).await,
            Case::Complete => completed_pool_conn().await,
        };

        let expected_idle = match case {
            Case::Complete => 1,
            Case::PendingPayload | Case::ServerStillOpen => 0,
        };

        pool.put(conn).await;
        assert_eq!(idle_len(&pool), expected_idle, "{case:?}");
    }
}

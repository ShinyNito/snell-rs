use core::range::Range;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use super::{ReusePool, ReusedSnellTcp, SnellClientOutbound};
use crate::ProtocolVersion;
use crate::error::{Error, Result};
use crate::protocol::request::{ClientRequest, parse_client_request};
use crate::test_support::{
    TEST_PSK, read_snell_frame_payload, shared_secret, test_snell_reader,
    test_snell_reader_with_version, test_snell_writer, test_snell_writer_with_version,
    test_tcp_listener, write_snell_tunnel_reply_message,
};

macro_rules! assert_next_payload {
    ($conn:expr, $expected:expr) => {{
        let payload = read_exact_payload($conn, $expected.len()).await.unwrap();
        assert_eq!(&payload, $expected);
    }};
}

async fn read_exact_payload(conn: &mut ReusedSnellTcp, len: usize) -> Result<Vec<u8>> {
    let mut payload = vec![0; len];
    conn.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn close_reuse_writer(conn: &mut ReusedSnellTcp) -> Result<()> {
    conn.shutdown().await?;
    Ok(())
}

async fn read_reuse_to_end(conn: &mut ReusedSnellTcp) -> Result<Vec<u8>> {
    let mut rest = Vec::new();
    conn.read_to_end(&mut rest).await?;
    Ok(rest)
}

fn idle_len(pool: &ReusePool) -> usize {
    pool.idle.lock().expect("reuse pool mutex poisoned").len()
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
        shared_secret(TEST_PSK),
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
        let payload = read_snell_frame_payload(&mut reader).await.unwrap();
        let request = parse_client_request(&payload).unwrap();
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

        write_snell_tunnel_reply_message(&mut server_writer, reply)
            .await
            .unwrap();
        if send_server_zero {
            server_writer.write_zero_chunk().await.unwrap();
        }

        std::assert_matches!(
            read_snell_frame_payload(&mut reader).await,
            Err(Error::ZeroChunk)
        );
    };

    let client = async {
        let mut conn = pool.open("example.com", 443).await.unwrap();
        let payload = read_exact_payload(&mut conn, reply.len()).await.unwrap();
        assert_eq!(payload, reply);
        if read_until_done {
            assert!(read_reuse_to_end(&mut conn).await.unwrap().is_empty());
        }
        close_reuse_writer(&mut conn).await.unwrap();
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
    assert!(read_reuse_to_end(conn).await.unwrap().is_empty());
    close_reuse_writer(conn).await.unwrap();
}

#[test]
fn snell_outbound_initializes_reuse_pool_from_secret() {
    let server_addr = "127.0.0.1:1".parse().unwrap();
    let outbound = SnellClientOutbound::new(
        server_addr,
        shared_secret(TEST_PSK),
        true,
        ProtocolVersion::V4,
    )
    .unwrap();
    let pool = outbound.pool.as_ref().expect("reuse pool");

    assert_eq!(pool.server_addr, server_addr);
    assert_eq!(pool.version, ProtocolVersion::V4);
}

#[tokio::test]
async fn reuse_pool_reuses_completed_stream() {
    let listener = test_tcp_listener().await;
    let server_addr = listener.local_addr().unwrap();
    let pool = ReusePool::with_limits(
        server_addr,
        shared_secret(TEST_PSK),
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
            let payload = timeout(
                Duration::from_secs(1),
                read_snell_frame_payload(&mut reader),
            )
            .await
            .unwrap()
            .unwrap();
            let request = parse_client_request(&payload).unwrap();
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
            write_snell_tunnel_reply_message(&mut server_writer, reply)
                .await
                .unwrap();
            server_writer.write_zero_chunk().await.unwrap();

            std::assert_matches!(
                read_snell_frame_payload(&mut reader).await,
                Err(Error::ZeroChunk)
            );
        }

        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    };

    let client = async {
        let mut first = pool.open("one.example", 443).await.unwrap();
        assert_next_payload!(&mut first, b"one");
        assert!(read_reuse_to_end(&mut first).await.unwrap().is_empty());
        close_reuse_writer(&mut first).await.unwrap();
        pool.put(first);
        assert_eq!(idle_len(&pool), 1);

        let mut second = pool.open("two.example", 443).await.unwrap();
        assert_next_payload!(&mut second, b"two");
        assert!(read_reuse_to_end(&mut second).await.unwrap().is_empty());
        close_reuse_writer(&mut second).await.unwrap();
        pool.put(second);
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
        shared_secret(TEST_PSK),
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
            let payload = timeout(
                Duration::from_secs(1),
                read_snell_frame_payload(&mut reader),
            )
            .await
            .unwrap()
            .unwrap();
            let request = parse_client_request(&payload).unwrap();
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
            write_snell_tunnel_reply_message(&mut server_writer, reply)
                .await
                .unwrap();
            server_writer.write_zero_chunk().await.unwrap();

            std::assert_matches!(
                read_snell_frame_payload(&mut reader).await,
                Err(Error::ZeroChunk)
            );
        }

        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    };

    let client = async {
        let mut first = pool.open("one.example", 443).await.unwrap();
        assert_next_payload!(&mut first, b"one");
        assert!(read_reuse_to_end(&mut first).await.unwrap().is_empty());
        close_reuse_writer(&mut first).await.unwrap();
        pool.put(first);
        assert_eq!(idle_len(&pool), 1);

        let mut second = pool.open("two.example", 443).await.unwrap();
        assert_next_payload!(&mut second, b"two");
        assert!(read_reuse_to_end(&mut second).await.unwrap().is_empty());
        close_reuse_writer(&mut second).await.unwrap();
        pool.put(second);
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
        shared_secret(TEST_PSK),
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
            let payload = read_snell_frame_payload(&mut reader).await.unwrap();
            let request = parse_client_request(&payload).unwrap();
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
            write_snell_tunnel_reply_message(&mut server_writer, b"ok")
                .await
                .unwrap();
            server_writer.write_zero_chunk().await.unwrap();
            std::assert_matches!(
                read_snell_frame_payload(&mut reader).await,
                Err(Error::ZeroChunk)
            );
        }
    };

    let client = async {
        let mut old = pool.open("old.example", 443).await.unwrap();
        read_ok_and_close(&mut old).await;

        let mut new = pool.open("new.example", 443).await.unwrap();
        read_ok_and_close(&mut new).await;

        pool.put(old);
        {
            let mut idle = pool.idle.lock().expect("reuse pool mutex poisoned");
            idle.front_mut().unwrap().idle_since = Instant::now() - Duration::from_secs(61);
        }
        pool.put(new);

        let retained = pool.take().expect("fresh idle connection retained");
        assert_eq!(idle_len(&pool), 0);
        drop(retained);
    };

    let ((), ()) = tokio::join!(server, client);
}

#[tokio::test]
async fn reuse_pool_drops_idle_expired_connection() {
    let (pool, conn) = completed_pool_conn().await;
    pool.put(conn);
    {
        let mut idle = pool.idle.lock().expect("reuse pool mutex poisoned");
        idle.front_mut().unwrap().idle_since = Instant::now() - Duration::from_secs(61);
    }

    assert!(pool.take().is_none());
    assert_eq!(idle_len(&pool), 0);
}

#[tokio::test]
async fn reuse_pool_close_idle_drains_idle_connections() {
    let (pool, conn) = completed_pool_conn().await;
    pool.put(conn);
    assert_eq!(idle_len(&pool), 1);

    pool.close_idle();

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
        shared_secret(TEST_PSK),
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
            let payload = read_snell_frame_payload(&mut reader).await.unwrap();
            let request = parse_client_request(&payload).unwrap();
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
            write_snell_tunnel_reply_message(&mut server_writer, b"ok")
                .await
                .unwrap();
            server_writer.write_zero_chunk().await.unwrap();
            std::assert_matches!(
                read_snell_frame_payload(&mut reader).await,
                Err(Error::ZeroChunk)
            );
        }
    };

    let client = async {
        let mut first = pool.open("one.example", 443).await.unwrap();
        read_ok_and_close(&mut first).await;

        let mut second = pool.open("two.example", 443).await.unwrap();
        read_ok_and_close(&mut second).await;

        pool.put(first);
        pool.put(second);
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

        pool.put(conn);
        assert_eq!(idle_len(&pool), expected_idle, "{case:?}");
    }
}

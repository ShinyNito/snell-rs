use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::service::runtime::net::connect_tcp;
use crate::transport::reuse::ReuseClientConn;
use crate::transport::tcp_stream::TcpClientStream;
use crate::transport::tokio_io::{V4StreamReader, V4StreamWriter};
use crate::{VERSION_4, VERSION_5};

const REUSE_POOL_MAX_SIZE: usize = 10;
const REUSE_POOL_MAX_IDLE_AGE: Duration = Duration::from_secs(15);

type FreshSnellTcp = TcpClientStream<OwnedReadHalf, OwnedWriteHalf>;
pub(crate) type ReusedSnellTcp = ReuseClientConn<OwnedReadHalf, OwnedWriteHalf>;

pub(crate) enum SnellTcpConnect {
    Fresh(FreshSnellTcp),
    Reused {
        conn: ReusedSnellTcp,
        pool: Arc<ReusePool>,
    },
}

pub(crate) struct SnellClientOutbound {
    server_addr: SocketAddr,
    psk: Zeroizing<Vec<u8>>,
    version: u8,
    reuse: bool,
    pool: Option<Arc<ReusePool>>,
}

impl SnellClientOutbound {
    pub(crate) fn new(
        server_addr: SocketAddr,
        psk: Vec<u8>,
        reuse: bool,
        version: u8,
    ) -> Result<Self> {
        let pool = if reuse {
            Some(Arc::new(ReusePool::new(server_addr, psk.clone(), version)?))
        } else {
            None
        };
        Ok(Self {
            server_addr,
            psk: Zeroizing::new(psk),
            version,
            reuse,
            pool,
        })
    }

    pub(crate) async fn open_tcp(&self, host: String, port: u16) -> Result<SnellTcpConnect> {
        match &self.pool {
            Some(pool) => open_reuse_tcp_connect(host, port, pool.clone()).await,
            None => {
                open_tcp_connect(
                    host,
                    port,
                    self.server_addr,
                    &self.psk,
                    self.reuse,
                    self.version,
                )
                .await
            }
        }
    }

    pub(crate) fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    pub(crate) fn psk(&self) -> &[u8] {
        &self.psk
    }

    pub(crate) fn version(&self) -> u8 {
        self.version
    }
}

pub(crate) struct ReusePool {
    server_addr: SocketAddr,
    psk: Zeroizing<Vec<u8>>,
    version: u8,
    max_size: usize,
    max_idle_age: Duration,
    idle: Mutex<VecDeque<IdleReuseConn>>,
}

struct IdleReuseConn {
    conn: ReusedSnellTcp,
    idle_since: Instant,
}

impl IdleReuseConn {
    fn new(conn: ReusedSnellTcp) -> Self {
        Self {
            conn,
            idle_since: Instant::now(),
        }
    }

    fn is_expired(&self, max_idle_age: Duration) -> bool {
        self.idle_since.elapsed() > max_idle_age
    }
}

impl ReusePool {
    pub(crate) fn new(server_addr: SocketAddr, psk: Vec<u8>, version: u8) -> Result<Self> {
        Self::with_limits(
            server_addr,
            psk,
            version,
            REUSE_POOL_MAX_SIZE,
            REUSE_POOL_MAX_IDLE_AGE,
        )
    }

    fn with_limits(
        server_addr: SocketAddr,
        psk: Vec<u8>,
        version: u8,
        max_size: usize,
        max_idle_age: Duration,
    ) -> Result<Self> {
        if !matches!(version, VERSION_4 | VERSION_5) {
            return Err(Error::UnsupportedVersion(version));
        }
        Ok(Self {
            server_addr,
            psk: Zeroizing::new(psk),
            version,
            max_size,
            max_idle_age,
            idle: Mutex::new(VecDeque::with_capacity(max_size)),
        })
    }

    pub(crate) async fn open(&self, host: &str, port: u16) -> Result<ReusedSnellTcp> {
        let mut conn = match self.take() {
            Some(conn) => conn,
            None => {
                let stream = connect_tcp(self.server_addr).await?;
                stream.set_nodelay(true)?;
                let (reader_io, writer_io) = stream.into_split();
                let reader = V4StreamReader::new(reader_io, &self.psk)?;
                let writer = V4StreamWriter::new(writer_io, &self.psk)?;
                ReuseClientConn::from_parts(reader, writer)
            }
        };
        conn.start_request(host, port, self.version).await?;
        Ok(conn)
    }

    pub(crate) async fn put(&self, mut conn: ReusedSnellTcp) {
        if !conn.can_reuse() {
            conn.shutdown().await;
            return;
        }

        conn.reset_request_state();
        conn.compact_buffers_for_reuse();
        let mut close_conn = Some(conn);
        {
            let mut idle = self.idle.lock().expect("reuse pool mutex poisoned");
            if idle.len() < self.max_size {
                idle.push_back(IdleReuseConn::new(
                    close_conn.take().expect("conn available"),
                ));
            }
        }
        if let Some(mut conn) = close_conn {
            conn.shutdown().await;
        }
    }

    fn take(&self) -> Option<ReusedSnellTcp> {
        let mut idle = self.idle.lock().expect("reuse pool mutex poisoned");
        while let Some(idle_conn) = idle.pop_front() {
            if !idle_conn.is_expired(self.max_idle_age) {
                return Some(idle_conn.conn);
            }
        }
        None
    }
}

pub(crate) async fn open_tcp_connect(
    host: String,
    port: u16,
    server_addr: SocketAddr,
    psk: &[u8],
    reuse: bool,
    version: u8,
) -> Result<SnellTcpConnect> {
    open_tcp_client_stream(server_addr, psk, &host, port, version, reuse)
        .await
        .map(SnellTcpConnect::Fresh)
}

async fn open_tcp_client_stream(
    server_addr: SocketAddr,
    psk: &[u8],
    host: &str,
    port: u16,
    version: u8,
    reuse: bool,
) -> Result<FreshSnellTcp> {
    let stream = connect_tcp(server_addr).await?;
    stream.set_nodelay(true)?;
    let (reader, writer) = stream.into_split();
    TcpClientStream::open_io(reader, writer, psk, host, port, version, reuse).await
}

pub(crate) async fn open_reuse_tcp_connect(
    host: String,
    port: u16,
    pool: Arc<ReusePool>,
) -> Result<SnellTcpConnect> {
    let conn = pool.open(&host, port).await?;
    Ok(SnellTcpConnect::Reused { conn, pool })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use tokio::net::TcpListener;
    use tokio::time::timeout;

    use super::{ReusePool, ReusedSnellTcp};
    use crate::error::Error;
    use crate::protocol::request::ClientRequest;
    use crate::transport::tokio_io::{V4StreamReader, V4StreamWriter};

    macro_rules! assert_next_payload {
        ($conn:expr, $expected:expr) => {{
            let payload = $conn
                .reader_mut()
                .read_payload_chunk()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(payload, $expected);
            let len = payload.len();
            $conn.reader_mut().consume_payload_chunk(len);
        }};
    }

    fn idle_len(pool: &ReusePool) -> usize {
        pool.idle.lock().expect("reuse pool mutex poisoned").len()
    }

    async fn pool_conn_after_reply(
        psk: &[u8],
        reply: &'static [u8],
        send_server_zero: bool,
        consume_len: usize,
        read_until_done: bool,
    ) -> (ReusePool, ReusedSnellTcp) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let pool = ReusePool::with_limits(
            server_addr,
            psk.to_vec(),
            crate::VERSION_4,
            4,
            Duration::from_secs(60),
        )
        .unwrap();

        let server = async {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader_io, writer_io) = stream.into_split();
            let mut reader = V4StreamReader::new(reader_io, psk).unwrap();
            let mut server_writer = V4StreamWriter::new(writer_io, psk).unwrap();
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

            server_writer.write_tunnel_reply(reply).await.unwrap();
            if send_server_zero {
                server_writer.write_zero_chunk().await.unwrap();
            }

            assert!(matches!(
                reader.read_frame_payload().await,
                Err(Error::ZeroChunk)
            ));
        };

        let client = async {
            let mut conn = pool.open("example.com", 443).await.unwrap();
            let payload = conn
                .reader_mut()
                .read_payload_chunk()
                .await
                .unwrap()
                .unwrap();
            let len = consume_len.min(payload.len());
            conn.reader_mut().consume_payload_chunk(len);
            if read_until_done {
                assert!(
                    conn.reader_mut()
                        .read_payload_chunk()
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

    async fn completed_pool_conn(psk: &[u8]) -> (ReusePool, ReusedSnellTcp) {
        pool_conn_after_reply(psk, b"ok", true, usize::MAX, true).await
    }

    async fn read_ok_and_close(conn: &mut ReusedSnellTcp) {
        assert_next_payload!(conn, b"ok");
        assert!(
            conn.reader_mut()
                .read_payload_chunk()
                .await
                .unwrap()
                .is_none()
        );
        conn.writer_mut().close_write().await.unwrap();
    }

    #[tokio::test]
    async fn reuse_pool_reuses_completed_stream() {
        let psk = b"test psk";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let pool = ReusePool::with_limits(
            server_addr,
            psk.to_vec(),
            crate::VERSION_4,
            2,
            Duration::from_secs(60),
        )
        .unwrap();

        let server = async {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader_io, writer_io) = stream.into_split();
            let mut reader = V4StreamReader::new(reader_io, psk).unwrap();
            let mut server_writer = V4StreamWriter::new(writer_io, psk).unwrap();

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
                        rest_offset: 17,
                        rest: b"",
                    }
                );
                server_writer.write_tunnel_reply(reply).await.unwrap();
                server_writer.write_zero_chunk().await.unwrap();

                assert!(matches!(
                    reader.read_frame_payload().await,
                    Err(Error::ZeroChunk)
                ));
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
                    .read_payload_chunk()
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
                    .read_payload_chunk()
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
    async fn reuse_pool_drops_idle_expired_connection() {
        let psk = b"test psk";
        let (pool, conn) = completed_pool_conn(psk).await;
        pool.put(conn).await;
        {
            let mut idle = pool.idle.lock().expect("reuse pool mutex poisoned");
            idle.front_mut().unwrap().idle_since = Instant::now() - Duration::from_secs(61);
        }

        assert!(pool.take().is_none());
        assert_eq!(idle_len(&pool), 0);
    }

    #[tokio::test]
    async fn reuse_conn_total_age_does_not_block_reuse() {
        let psk = b"test psk";
        let (_pool, conn) = completed_pool_conn(psk).await;

        assert!(conn.can_reuse());
    }

    #[tokio::test]
    async fn reuse_pool_keeps_only_max_size_connections() {
        let psk = b"test psk";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let pool = ReusePool::with_limits(
            server_addr,
            psk.to_vec(),
            crate::VERSION_4,
            1,
            Duration::from_secs(60),
        )
        .unwrap();

        let server = async {
            for host in ["one.example", "two.example"] {
                let (stream, _) = listener.accept().await.unwrap();
                let (reader_io, writer_io) = stream.into_split();
                let mut reader = V4StreamReader::new(reader_io, psk).unwrap();
                let mut server_writer = V4StreamWriter::new(writer_io, psk).unwrap();
                let request = reader.read_client_request().await.unwrap();
                assert_eq!(
                    request,
                    ClientRequest::Connect {
                        reuse: true,
                        host,
                        port: 443,
                        rest_offset: 17,
                        rest: b"",
                    }
                );
                server_writer.write_tunnel_reply(b"ok").await.unwrap();
                server_writer.write_zero_chunk().await.unwrap();
                assert!(matches!(
                    reader.read_frame_payload().await,
                    Err(Error::ZeroChunk)
                ));
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

        let psk = b"test psk";
        for case in [Case::Complete, Case::PendingPayload, Case::ServerStillOpen] {
            let (pool, conn) = match case {
                Case::PendingPayload => {
                    pool_conn_after_reply(psk, b"pending", true, 2, false).await
                }
                Case::ServerStillOpen => {
                    pool_conn_after_reply(psk, b"ok", false, usize::MAX, false).await
                }
                Case::Complete => completed_pool_conn(psk).await,
            };

            let expected_idle = match case {
                Case::Complete => 1,
                Case::PendingPayload | Case::ServerStillOpen => 0,
            };

            pool.put(conn).await;
            assert_eq!(idle_len(&pool), expected_idle, "{case:?}");
        }
    }
}

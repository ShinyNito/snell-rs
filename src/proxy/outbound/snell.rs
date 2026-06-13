use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use zeroize::Zeroizing;

use crate::ProtocolVersion;
use crate::error::{Error, Result};
use crate::framed::{SnellStreamReader, SnellStreamWriter};
use crate::net::connect::connect_tcp;
use crate::session::reuse::ReuseClientConn;
use crate::session::tcp::TcpClientStream;

const REUSE_POOL_MAX_SIZE: usize = 10;
const REUSE_POOL_MAX_IDLE_AGE: Duration = Duration::from_secs(15);

type SharedPsk = Arc<Zeroizing<Vec<u8>>>;
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
    psk: SharedPsk,
    version: ProtocolVersion,
    pool: Option<Arc<ReusePool>>,
}

impl SnellClientOutbound {
    pub(crate) fn new(
        server_addr: SocketAddr,
        psk: Vec<u8>,
        reuse: bool,
        version: ProtocolVersion,
    ) -> Result<Self> {
        let psk = Arc::new(Zeroizing::new(psk));
        let pool = if reuse {
            Some(Arc::new(ReusePool::new(server_addr, psk.clone(), version)?))
        } else {
            None
        };
        Ok(Self {
            server_addr,
            psk,
            version,
            pool,
        })
    }

    pub(crate) async fn open_tcp(&self, host: &str, port: u16) -> Result<SnellTcpConnect> {
        match &self.pool {
            Some(pool) => open_reuse_tcp_connect(host, port, pool.clone()).await,
            None => open_tcp_connect(host, port, self.server_addr, self.psk(), self.version).await,
        }
    }

    pub(crate) fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    pub(crate) fn psk(&self) -> &[u8] {
        self.psk.as_slice()
    }

    pub(crate) fn version(&self) -> ProtocolVersion {
        self.version
    }

    pub(crate) async fn close_idle_connections(&self) {
        if let Some(pool) = &self.pool {
            pool.close_idle().await;
        }
    }
}

pub(crate) struct ReusePool {
    server_addr: SocketAddr,
    psk: SharedPsk,
    version: ProtocolVersion,
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
    fn new(server_addr: SocketAddr, psk: SharedPsk, version: ProtocolVersion) -> Result<Self> {
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
        psk: SharedPsk,
        version: ProtocolVersion,
        max_size: usize,
        max_idle_age: Duration,
    ) -> Result<Self> {
        if !matches!(
            version,
            ProtocolVersion::V4 | ProtocolVersion::V5 | ProtocolVersion::V6
        ) {
            return Err(Error::UnsupportedVersion(version.as_u8()));
        }
        Ok(Self {
            server_addr,
            psk,
            version,
            max_size,
            max_idle_age,
            idle: Mutex::new(VecDeque::with_capacity(max_size)),
        })
    }

    pub(crate) async fn open(&self, host: &str, port: u16) -> Result<ReusedSnellTcp> {
        if let Some(mut conn) = self.take().await {
            match conn.start_request(host, port).await {
                Ok(()) => return Ok(conn),
                Err(err) if err.is_closed_io() => {
                    conn.close_whole_connection().await;
                }
                Err(err) => return Err(err),
            }
        }

        let mut conn = self.open_fresh().await?;
        conn.start_request(host, port).await?;
        Ok(conn)
    }

    async fn open_fresh(&self) -> Result<ReusedSnellTcp> {
        let stream = connect_tcp(self.server_addr).await?;
        stream.set_nodelay(true)?;
        let (reader_io, writer_io) = stream.into_split();
        let reader = SnellStreamReader::new(reader_io, self.psk.as_slice(), self.version);
        let writer = SnellStreamWriter::new(writer_io, self.psk.as_slice(), self.version)?;
        Ok(ReuseClientConn::from_parts(reader, writer))
    }

    pub(crate) async fn put(&self, mut conn: ReusedSnellTcp) {
        if !conn.can_reuse() {
            conn.close_whole_connection().await;
            return;
        }

        conn.reset_request_state();
        conn.compact_buffers_for_reuse();
        let (close_conn, expired) = self.push_idle_pruning_expired(conn);
        for conn in expired {
            conn.close_whole_connection().await;
        }
        if let Some(conn) = close_conn {
            conn.close_whole_connection().await;
        }
    }

    async fn take(&self) -> Option<ReusedSnellTcp> {
        let (reusable, expired) = self.take_idle();
        for conn in expired {
            conn.close_whole_connection().await;
        }
        reusable
    }

    pub(crate) async fn close_idle(&self) {
        for conn in self.drain_idle() {
            conn.close_whole_connection().await;
        }
    }

    // The idle mutex only protects queue state. Connection I/O must happen after
    // these synchronous helpers return.
    fn push_idle_pruning_expired(
        &self,
        conn: ReusedSnellTcp,
    ) -> (Option<ReusedSnellTcp>, Vec<ReusedSnellTcp>) {
        let mut idle = self.idle.lock().expect("reuse pool mutex poisoned");
        let expired = self.drain_expired_front_locked(&mut idle);
        if idle.len() < self.max_size {
            idle.push_back(IdleReuseConn::new(conn));
            (None, expired)
        } else {
            (Some(conn), expired)
        }
    }

    fn take_idle(&self) -> (Option<ReusedSnellTcp>, Vec<ReusedSnellTcp>) {
        let mut idle = self.idle.lock().expect("reuse pool mutex poisoned");
        let expired = self.drain_expired_front_locked(&mut idle);
        let reusable = idle.pop_front().map(|idle_conn| idle_conn.conn);
        (reusable, expired)
    }

    fn drain_idle(&self) -> Vec<ReusedSnellTcp> {
        let mut idle = self.idle.lock().expect("reuse pool mutex poisoned");
        idle.drain(..).map(|idle_conn| idle_conn.conn).collect()
    }

    fn drain_expired_front_locked(
        &self,
        idle: &mut VecDeque<IdleReuseConn>,
    ) -> Vec<ReusedSnellTcp> {
        let mut expired = Vec::new();
        while let Some(idle_conn) =
            idle.pop_front_if(|idle_conn| idle_conn.is_expired(self.max_idle_age))
        {
            expired.push(idle_conn.conn);
        }
        expired
    }
}

pub(crate) async fn open_tcp_connect(
    host: &str,
    port: u16,
    server_addr: SocketAddr,
    psk: &[u8],
    version: ProtocolVersion,
) -> Result<SnellTcpConnect> {
    open_tcp_client_stream(server_addr, psk, host, port, version)
        .await
        .map(SnellTcpConnect::Fresh)
}

async fn open_tcp_client_stream(
    server_addr: SocketAddr,
    psk: &[u8],
    host: &str,
    port: u16,
    version: ProtocolVersion,
) -> Result<FreshSnellTcp> {
    let stream = connect_tcp(server_addr).await?;
    stream.set_nodelay(true)?;
    let (reader, writer) = stream.into_split();
    TcpClientStream::open_io(reader, writer, psk, host, port, version, false).await
}

pub(crate) async fn open_reuse_tcp_connect(
    host: &str,
    port: u16,
    pool: Arc<ReusePool>,
) -> Result<SnellTcpConnect> {
    let conn = pool.open(host, port).await?;
    Ok(SnellTcpConnect::Reused { conn, pool })
}

#[cfg(test)]
mod tests;

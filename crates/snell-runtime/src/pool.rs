use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use snell_protocol::{
    CLIENT_POOL_MAX_IDLE_SECS, CLIENT_POOL_MAX_SIZE, V4Decoder, V4Encoder, V6ShapedDecoder,
    V6ShapedEncoder, V6UnshapedDecoder, V6UnshapedEncoder,
};
use tokio::net::TcpStream;

#[allow(clippy::large_enum_variant)]
pub(crate) enum PooledCodec {
    V4 {
        encoder: V4Encoder,
        decoder: V4Decoder,
    },
    V6Shaped {
        encoder: V6ShapedEncoder,
        decoder: V6ShapedDecoder,
    },
    V6Unshaped {
        encoder: V6UnshapedEncoder,
        decoder: V6UnshapedDecoder,
    },
}

pub(crate) struct PooledConn {
    pub stream: TcpStream,
    pub codec: PooledCodec,
}

struct PooledEntry {
    conn: PooledConn,
    returned_at: Instant,
}

/// Client reuse pool: bounded VecDeque, short std Mutex, entries carry return time.
#[derive(Clone)]
pub struct ReusePool {
    inner: Arc<Mutex<VecDeque<PooledEntry>>>,
    max_size: usize,
    max_idle: Duration,
}

impl Default for ReusePool {
    fn default() -> Self {
        Self::new()
    }
}

impl ReusePool {
    pub fn new() -> Self {
        Self::with_limits(
            CLIENT_POOL_MAX_SIZE,
            Duration::from_secs(CLIENT_POOL_MAX_IDLE_SECS),
        )
    }

    pub(crate) fn with_limits(max_size: usize, max_idle: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(max_size))),
            max_size,
            max_idle,
        }
    }

    pub(crate) fn take(&self) -> Option<PooledConn> {
        let mut entries = self.lock();
        while let Some(entry) = entries.pop_front() {
            if entry.returned_at.elapsed() >= self.max_idle {
                continue;
            }
            if socket_dead(&entry.conn.stream) {
                continue;
            }
            return Some(entry.conn);
        }
        None
    }

    pub(crate) fn put(&self, conn: PooledConn) -> bool {
        if self.max_size == 0 || socket_dead(&conn.stream) {
            return false;
        }
        let mut entries = self.lock();
        if entries.len() >= self.max_size {
            return false;
        }
        entries.push_back(PooledEntry {
            conn,
            returned_at: Instant::now(),
        });
        true
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<PooledEntry>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn socket_dead(stream: &TcpStream) -> bool {
    let mut buf = [0u8; 1];
    match stream.try_read(&mut buf) {
        Ok(0) => true,
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use tokio::net::TcpListener;

    #[test]
    fn drops_when_full() {
        let pool = ReusePool::with_limits(0, Duration::from_secs(300));
        assert_eq!(pool.len(), 0);
    }

    #[tokio::test]
    async fn drops_expired_and_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).await.unwrap();
        let _peer = listener.accept().await.unwrap().0;
        let psk = snell_protocol::Psk::new(b"0123456789abcdef").unwrap();
        let encoder = V4Encoder::os(&psk).unwrap();
        let decoder = V4Decoder::new(psk);
        let pool = ReusePool::with_limits(2, Duration::from_millis(1));
        assert!(pool.put(PooledConn {
            stream,
            codec: PooledCodec::V4 { encoder, decoder },
        }));
        thread::sleep(Duration::from_millis(3));
        assert!(pool.take().is_none());
        assert_eq!(pool.len(), 0);
    }

    #[tokio::test]
    async fn drops_already_closed_on_take() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).await.unwrap();
        let peer = listener.accept().await.unwrap().0;
        let psk = snell_protocol::Psk::new(b"0123456789abcdef").unwrap();
        let encoder = V4Encoder::os(&psk).unwrap();
        let decoder = V4Decoder::new(psk);
        let pool = ReusePool::with_limits(2, Duration::from_secs(300));
        assert!(pool.put(PooledConn {
            stream,
            codec: PooledCodec::V4 { encoder, decoder },
        }));
        drop(peer);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(pool.take().is_none());
        assert_eq!(pool.len(), 0);
    }
}

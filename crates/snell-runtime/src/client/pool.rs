use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use snell_protocol::{CLIENT_POOL_MAX_IDLE_SECS, CLIENT_POOL_MAX_SIZE};
use tokio::net::TcpStream;

use crate::codec::Codec;

/// An authenticated client connection to the server and its session codec.
pub(crate) struct Connection {
    pub stream: TcpStream,
    pub codec: Codec,
}

struct PooledEntry {
    conn: Connection,
    returned_at: Instant,
}

/// Client reuse pool: bounded VecDeque, short std Mutex, entries carry return time.
#[derive(Clone)]
pub struct ReusePool {
    inner: Arc<Mutex<VecDeque<PooledEntry>>>,
    max_size: usize,
    max_idle: Duration,
}

impl std::fmt::Debug for ReusePool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReusePool")
            .field("len", &self.len())
            .field("max_size", &self.max_size)
            .field("max_idle", &self.max_idle)
            .finish()
    }
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

    pub(crate) fn take(&self) -> Option<Connection> {
        let mut entries = self.lock();
        std::iter::from_fn(|| entries.pop_front())
            .find(|entry| {
                entry.returned_at.elapsed() < self.max_idle && !socket_dead(&entry.conn.stream)
            })
            .map(|entry| entry.conn)
    }

    pub(crate) fn put(&self, conn: Connection) -> bool {
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

    /// Drive from the listener's maintenance tick, including when unused.
    pub fn expire(&self) {
        self.lock()
            .retain(|entry| entry.returned_at.elapsed() < self.max_idle);
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

/// An idle pooled socket must have nothing to read: EOF, stray bytes, and
/// errors all mean it can no longer carry a fresh session.
fn socket_dead(stream: &TcpStream) -> bool {
    !matches!(
        stream.try_read(&mut [0u8; 1]),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use snell_protocol::{Psk, V4Decoder, V4Encoder};
    use std::thread;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn drops_when_full() {
        use tokio::io::AsyncReadExt;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pool = ReusePool::with_limits(1, Duration::from_secs(300));
        let mut peers = Vec::new();
        for accepted in [true, false] {
            let stream = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (mut peer, _) = listener.accept().await.unwrap();
            let psk = Psk::new(b"0123456789abcdef").unwrap();
            assert_eq!(
                pool.put(Connection {
                    stream,
                    codec: Codec::V4 {
                        encoder: V4Encoder::os(&psk).unwrap(),
                        decoder: V4Decoder::new(psk),
                    }
                }),
                accepted
            );
            assert_eq!(pool.len(), 1);
            if !accepted {
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(1), peer.read(&mut [0]))
                        .await
                        .unwrap()
                        .unwrap(),
                    0
                );
            } else {
                // Keep the accepted socket live until the second insertion.
                peers.push(peer);
            }
        }
    }

    #[tokio::test]
    async fn drops_expired_and_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).await.unwrap();
        let _peer = listener.accept().await.unwrap().0;
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let encoder = V4Encoder::os(&psk).unwrap();
        let decoder = V4Decoder::new(psk);
        let pool = ReusePool::with_limits(2, Duration::from_millis(1));
        assert!(pool.put(Connection {
            stream,
            codec: Codec::V4 { encoder, decoder },
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
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let encoder = V4Encoder::os(&psk).unwrap();
        let decoder = V4Decoder::new(psk);
        let pool = ReusePool::with_limits(2, Duration::from_secs(300));
        assert!(pool.put(Connection {
            stream,
            codec: Codec::V4 { encoder, decoder },
        }));
        drop(peer);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(pool.take().is_none());
        assert_eq!(pool.len(), 0);
    }
}

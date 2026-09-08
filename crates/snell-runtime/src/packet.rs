//! UDP in-flight quotas. Backing storage belongs to the shared BufferPool.
use crate::SessionError;
use crate::buffer::{BufferPool, PooledBuffer};
use std::sync::{Arc, Mutex};

pub(crate) struct PacketBuf {
    data: PooledBuffer,
    quota: Arc<PacketQuota>,
}

impl PacketBuf {
    pub fn as_slice(&self) -> &[u8] {
        self.data.filled()
    }
    #[cfg(test)]
    pub fn extend(&mut self, bytes: &[u8]) -> Result<(), SessionError> {
        // Acquisition fixed both byte quota and storage capacity.
        self.data.extend_from_slice(bytes)?;
        Ok(())
    }
}
impl Drop for PacketBuf {
    fn drop(&mut self) {
        let mut held = self.quota.held.lock().expect("UDP quota lock");
        held.0 -= 1;
        held.1 -= self.data.capacity();
    }
}

pub(crate) struct PacketQuota {
    pub(crate) buffers: Arc<BufferPool>,
    held: Mutex<(usize, usize)>,
    max_bufs: usize,
    max_bytes: usize,
}
impl PacketQuota {
    pub fn new(buffers: Arc<BufferPool>, max_bufs: usize, max_bytes: usize) -> Self {
        Self {
            buffers,
            held: Mutex::new((0, 0)),
            max_bufs,
            max_bytes,
        }
    }
    pub fn acquire(self: &Arc<Self>, min: usize) -> Option<PacketBuf> {
        let mut data = self.buffers.get(snell_protocol::UDP_DATAGRAM_MAX);
        data.ensure(min).ok()?;
        let mut held = self.held.lock().expect("UDP quota lock");
        if held.0 >= self.max_bufs || data.capacity() > self.max_bytes.saturating_sub(held.1) {
            return None;
        }
        held.0 += 1;
        held.1 += data.capacity();
        Some(PacketBuf {
            data,
            quota: Arc::clone(self),
        })
    }
    pub async fn recv_from(
        self: &Arc<Self>,
        socket: &tokio::net::UdpSocket,
    ) -> Result<Option<(PacketBuf, std::net::SocketAddr)>, SessionError> {
        std::future::poll_fn(|cx| {
            use std::task::Poll;
            match socket.poll_recv_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Pending => return Poll::Pending,
            }
            let Some(mut packet) = self.acquire(snell_protocol::UDP_DATAGRAM_MAX) else {
                return Poll::Ready(Ok(None));
            };
            crate::bufio::poll_recv_datagram(socket, &mut packet.data, cx)
                .map(|result| result.map(|peer| Some((packet, peer))))
        })
        .await
    }
    #[cfg(test)]
    pub fn live(&self) -> usize {
        self.held.lock().unwrap().0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quota_and_storage_return_on_dirty_drop() {
        let buffers = Arc::new(BufferPool::default());
        let pool = Arc::new(PacketQuota::new(buffers.clone(), 1, 128));
        let mut a = pool.acquire(100).unwrap();
        a.extend(b"old packet").unwrap();
        assert!(pool.acquire(1).is_none());
        drop(a);
        assert_eq!(pool.live(), 0);
        let b = pool.acquire(100).unwrap();
        assert!(b.as_slice().is_empty());
        assert!(pool.acquire(129).is_none());
        drop(b);
        assert_eq!(buffers.leased_bytes(), 0);
    }
    #[tokio::test]
    async fn receiver_drop_releases_queued_datagrams() {
        let pool = Arc::new(PacketQuota::new(Arc::default(), 2, 256));
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        tx.try_send(pool.acquire(100).unwrap()).ok().unwrap();
        tx.try_send(pool.acquire(100).unwrap()).ok().unwrap();
        assert_eq!(pool.live(), 2);
        drop(rx);
        assert_eq!(pool.live(), 0);
    }
}

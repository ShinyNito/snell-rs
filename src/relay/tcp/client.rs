use std::{io, marker::PhantomData, net::SocketAddr, sync::Arc};

use compio::{io::AsyncRead, net::TcpStream};

use crate::protocol::{
    address::Address,
    snell::{self, COMMAND_ERROR, COMMAND_TUNNEL, SnellMode, SnellTcpDecoder, SnellTcpEncoder},
};
use crate::{
    keepalive::apply_tcp_keepalive,
    timeout::{with_tcp_connect_timeout, with_tcp_timeout},
};

use super::{
    driver::{SnellStreamReader, SnellStreamWriter},
    pool::ConnectionPool,
    transport::{CopyBidirectional, Outbound, copy_bidirectional},
};

pub struct SnellConnector<M>
where
    M: SnellMode,
{
    server: SocketAddr,
    psk: Arc<[u8]>,
    pool: Option<ConnectionPool<SnellTransport<M>>>,
    mode: PhantomData<M>,
}

pub struct SnellTransport<M>
where
    M: SnellMode,
{
    pub(crate) reader: SnellStreamReader<TcpStream, M::Decoder>,
    pub(crate) writer: SnellStreamWriter<TcpStream, M::Encoder>,
}

pub struct PooledSnellTransport<M>
where
    M: SnellMode,
{
    transport: SnellTransport<M>,
    pool: Arc<SnellConnector<M>>,
}

impl<M> SnellConnector<M>
where
    M: SnellMode + Send + Sync + 'static,
    M::Encoder: Send,
    M::Decoder: Send,
    <M::Encoder as SnellTcpEncoder>::Reservation: Send,
{
    pub fn new(server: SocketAddr, psk: impl Into<Arc<[u8]>>, reuse: bool) -> Self {
        Self {
            server,
            psk: psk.into(),
            pool: if reuse {
                Some(ConnectionPool::new())
            } else {
                None
            },
            mode: PhantomData,
        }
    }

    pub async fn connect(
        self: &Arc<Self>,
        destination: &Address,
    ) -> io::Result<PooledSnellTransport<M>> {
        if let Some(pool) = &self.pool
            && let Some(transport) = pool.take()
        {
            match self.open_request(transport, destination).await {
                Ok(transport) => {
                    tracing::debug!(%destination, "reused snell upstream connection");
                    return Ok(PooledSnellTransport {
                        transport,
                        pool: self.clone(),
                    });
                }
                Err(error) if is_retriable_pool_error(&error) => {
                    tracing::debug!(%error, "discarding stale snell reuse connection");
                }
                Err(error) => {
                    return Err(error);
                }
            }
        }

        tracing::debug!(server = %self.server, %destination, "opening new snell upstream connection");
        let transport = self
            .open_request(self.dial_transport().await?, destination)
            .await?;
        Ok(PooledSnellTransport {
            transport,
            pool: self.clone(),
        })
    }

    pub(crate) async fn connect_udp(self: &Arc<Self>) -> io::Result<SnellTransport<M>> {
        let mut transport = self.dial_transport().await?;
        with_tcp_timeout(
            async move {
                transport
                    .writer
                    .write_with(3, snell::encode_udp_setup_request_into)
                    .await?;
                read_server_reply(&mut transport.reader).await?;
                Ok(transport)
            },
            "snell udp setup",
        )
        .await
    }

    async fn dial_transport(&self) -> io::Result<SnellTransport<M>> {
        let stream =
            with_tcp_connect_timeout(TcpStream::connect(self.server), "snell tcp connect").await?;
        apply_tcp_keepalive(&stream)?;
        stream.set_nodelay(true)?;
        let (read_half, write_half) = stream.into_split();
        Ok(SnellTransport {
            reader: SnellStreamReader::new::<M>(read_half, self.psk.clone()),
            writer: SnellStreamWriter::new::<M>(write_half, self.psk.clone())?,
        })
    }

    async fn open_request(
        &self,
        mut transport: SnellTransport<M>,
        destination: &Address,
    ) -> io::Result<SnellTransport<M>> {
        let destination = destination.as_view();
        let reuse = self.reuse_enabled();
        with_tcp_timeout(
            async move {
                transport
                    .writer
                    .write_with(snell::connect_request_len(destination)?, |slot| {
                        snell::encode_connect_request_into(slot, destination, reuse)
                    })
                    .await?;
                read_server_reply(&mut transport.reader).await?;
                Ok(transport)
            },
            "snell connect request",
        )
        .await
    }

    fn put(&self, transport: SnellTransport<M>) {
        let Some(pool) = &self.pool else {
            return;
        };

        if pool.put(transport) {
            tracing::debug!("snell upstream connection returned to pool");
        } else {
            tracing::debug!("snell pool full, closing connection");
        }
    }

    fn reuse_enabled(&self) -> bool {
        self.pool.is_some()
    }
}

impl<M> Outbound for Arc<SnellConnector<M>>
where
    M: SnellMode + Send + Sync + 'static,
    M::Encoder: Send,
    M::Decoder: Send,
    <M::Encoder as SnellTcpEncoder>::Reservation: Send,
{
    type Transport = PooledSnellTransport<M>;

    async fn connect(&self, destination: &Address) -> io::Result<Self::Transport> {
        SnellConnector::connect(self, destination).await
    }
}

impl<M> SnellTransport<M>
where
    M: SnellMode,
{
    pub(crate) fn new(
        reader: SnellStreamReader<TcpStream, M::Decoder>,
        writer: SnellStreamWriter<TcpStream, M::Encoder>,
    ) -> Self {
        Self { reader, writer }
    }
}

impl<M> CopyBidirectional for PooledSnellTransport<M>
where
    M: SnellMode + Send + Sync + 'static + Unpin,
    M::Encoder: Send + Unpin,
    M::Decoder: Send + Unpin,
    <M::Encoder as SnellTcpEncoder>::Reservation: Send,
{
    type Peer = TcpStream;
    type Output = ();

    async fn copy_bidirectional(self, local: TcpStream) -> io::Result<()> {
        let transport = copy_bidirectional(self.transport, local).await?;
        if self.pool.reuse_enabled() {
            self.pool.put(transport);
        }
        Ok(())
    }
}

fn is_retriable_pool_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut
    )
}

async fn read_server_reply<R, D>(reader: &mut SnellStreamReader<R, D>) -> io::Result<()>
where
    R: AsyncRead + Unpin + 'static,
    D: SnellTcpDecoder,
{
    let mut command = [0u8; 1];
    reader.read_exact_plain(&mut command).await?;
    match command[0] {
        COMMAND_TUNNEL => Ok(()),
        COMMAND_ERROR => {
            let mut head = [0u8; 2];
            reader.read_exact_plain(&mut head).await?;
            let mut message = vec![0u8; head[1] as usize];
            reader.read_exact_plain(&mut message).await?;
            Err(io::Error::other(format!(
                "snell server error {}: {}",
                head[0],
                String::from_utf8_lossy(&message)
            )))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected snell reply command: {other}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use compio::{
        io::{AsyncRead, AsyncWrite},
        net::{TcpListener, TcpStream},
        runtime,
    };

    use super::*;
    use crate::protocol::{
        address::Address,
        snell::{self, COMMAND_TUNNEL, MAX_CONNECT_REQUEST_LEN, V4Mode},
    };

    #[compio::test]
    async fn reuses_one_upstream_tcp_for_two_transports() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let destination = Address::domain("example.com", 443).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let server_accepts = accepts.clone();
        let server_psk = psk.clone();

        let server = runtime::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server_accepts.fetch_add(1, Ordering::SeqCst);
            let mut transport = snell_transport::<V4Mode>(stream, server_psk);

            for _ in 0..2 {
                let request = read_connect_request(&mut transport).await;
                assert!(request.reuse);
                transport
                    .writer
                    .write_frame(&[COMMAND_TUNNEL])
                    .await
                    .unwrap();
                transport = relay_closed_peer_transport(transport).await;
            }
        });

        let client = Arc::new(SnellConnector::<V4Mode>::new(server_addr, psk, true));
        for _ in 0..2 {
            run_closed_peer_transport(&client, &destination).await;
        }

        server.await.unwrap();
        assert_eq!(accepts.load(Ordering::SeqCst), 1);
    }

    #[compio::test]
    async fn resume_disabled_opens_new_upstream_for_each_transport() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let destination = Address::domain("example.com", 443).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let server_accepts = accepts.clone();
        let server_psk = psk.clone();

        let server = runtime::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                server_accepts.fetch_add(1, Ordering::SeqCst);
                let mut transport = snell_transport::<V4Mode>(stream, server_psk.clone());
                let request = read_connect_request(&mut transport).await;
                assert!(!request.reuse);
                transport
                    .writer
                    .write_frame(&[COMMAND_TUNNEL])
                    .await
                    .unwrap();
                let _ = relay_closed_peer_transport(transport).await;
            }
        });

        let client = Arc::new(SnellConnector::<V4Mode>::new(server_addr, psk, false));
        for _ in 0..2 {
            run_closed_peer_transport(&client, &destination).await;
        }

        server.await.unwrap();
        assert_eq!(accepts.load(Ordering::SeqCst), 2);
    }

    async fn run_closed_peer_transport(
        client: &Arc<SnellConnector<V4Mode>>,
        destination: &Address,
    ) {
        let transport = Outbound::connect(client, destination).await.unwrap();
        let (local, mut peer) = tcp_pair().await;
        let relay = runtime::spawn(copy_bidirectional(transport, local));
        peer.shutdown().await.unwrap();

        let mut buf = [0u8; 1];
        assert_eq!(read_once(&mut peer, &mut buf).await.unwrap(), 0);
        relay.await.unwrap().unwrap();
    }

    fn snell_transport<M>(stream: TcpStream, psk: Arc<[u8]>) -> SnellTransport<M>
    where
        M: SnellMode,
    {
        let (read_half, write_half) = stream.into_split();
        SnellTransport::new(
            SnellStreamReader::new::<M>(read_half, psk.clone()),
            SnellStreamWriter::new::<M>(write_half, psk).unwrap(),
        )
    }

    async fn read_connect_request<M>(transport: &mut SnellTransport<M>) -> snell::ConnectRequest
    where
        M: SnellMode,
    {
        let mut head = [0u8; 3];
        transport.reader.read_exact_plain(&mut head).await.unwrap();

        let client_id_len = head[2] as usize;
        let mut client_id_and_host_len = [0u8; 255 + 1];
        transport
            .reader
            .read_exact_plain(&mut client_id_and_host_len[..client_id_len + 1])
            .await
            .unwrap();

        let host_len = client_id_and_host_len[client_id_len] as usize;
        let mut host_and_port = [0u8; 255 + 2];
        transport
            .reader
            .read_exact_plain(&mut host_and_port[..host_len + 2])
            .await
            .unwrap();

        let len = 3 + client_id_len + 1 + host_len + 2;
        let mut buf = [0u8; MAX_CONNECT_REQUEST_LEN];
        buf[..3].copy_from_slice(&head);
        buf[3..3 + client_id_len + 1].copy_from_slice(&client_id_and_host_len[..client_id_len + 1]);
        buf[3 + client_id_len + 1..len].copy_from_slice(&host_and_port[..host_len + 2]);
        snell::decode_connect_request(&buf[..len]).unwrap()
    }

    async fn relay_closed_peer_transport<M>(transport: SnellTransport<M>) -> SnellTransport<M>
    where
        M: SnellMode + Send + Sync + 'static + Unpin,
        M::Encoder: Send + Unpin,
        M::Decoder: Send + Unpin,
        <M::Encoder as SnellTcpEncoder>::Reservation: Send,
    {
        let (target, mut peer) = tcp_pair().await;
        peer.shutdown().await.unwrap();
        copy_bidirectional(transport, target).await.unwrap()
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, server) = futures::future::try_join(TcpStream::connect(addr), async {
            let (stream, _) = listener.accept().await?;
            Ok::<_, io::Error>(stream)
        })
        .await
        .unwrap();
        (server, client)
    }

    async fn read_once<R>(reader: &mut R, dst: &mut [u8]) -> io::Result<usize>
    where
        R: AsyncRead + 'static,
    {
        let (result, buf) = reader
            .read(Vec::with_capacity(dst.len()))
            .await
            .into_parts();
        let n = result?;
        dst[..n].copy_from_slice(&buf[..n]);
        Ok(n)
    }
}

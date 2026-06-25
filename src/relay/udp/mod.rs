use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use lru_time_cache::LruCache;
use tokio::{
    io::{AsyncRead, ReadBuf},
    net::{TcpStream, UdpSocket},
};

use crate::{
    protocol::{
        address::Address,
        snell::{self, SnellMode, SnellTcpEncoder},
        socks5,
    },
    relay::tcp::{
        client::{SnellConnector, SnellTransport},
        driver::WriteFrameState,
    },
};

pub(crate) const UDP_ASSOCIATION_TTL: Duration = Duration::from_mins(5);
pub(crate) const MAX_UDP_DATAGRAM_LEN: usize = 65_535;

pub(crate) trait Outbound {
    type Transport: DatagramTransport;

    async fn connect_udp(&self) -> io::Result<Self::Transport>;
}

pub(crate) trait DatagramTransport {
    type SendState: Default;

    fn poll_send_to(
        &mut self,
        cx: &mut Context<'_>,
        destination: &Address,
        payload: &[u8],
        state: &mut Self::SendState,
    ) -> Poll<io::Result<usize>>;

    fn poll_recv_from(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, Address)>>;
}

pub(crate) fn relay_snell_udp<M, O>(
    transport: SnellTransport<M>,
    outbound: O,
) -> impl Future<Output = io::Result<()>>
where
    M: SnellMode + Unpin,
    M::Encoder: Send + Unpin,
    M::Decoder: Send + Unpin,
    <M::Encoder as SnellTcpEncoder>::Reservation: Send,
    O: DatagramTransport + Unpin,
    O::SendState: Unpin,
{
    let mut relay = SnellUdpRelay {
        snell: transport,
        outbound,
        outbound_in: vec![0; MAX_UDP_DATAGRAM_LEN],
        pending_to_snell: None,
        outbound_send_state: O::SendState::default(),
        snell_write_state: WriteFrameState::default(),
    };
    poll_fn(move |cx| relay.poll(cx))
}

struct SnellUdpRelay<M, O>
where
    M: SnellMode,
    O: DatagramTransport,
{
    snell: SnellTransport<M>,
    outbound: O,
    outbound_in: Vec<u8>,
    pending_to_snell: Option<Vec<u8>>,
    outbound_send_state: O::SendState,
    snell_write_state: WriteFrameState,
}

impl<M, O> SnellUdpRelay<M, O>
where
    M: SnellMode + Unpin,
    M::Encoder: Send + Unpin,
    M::Decoder: Send + Unpin,
    <M::Encoder as SnellTcpEncoder>::Reservation: Send,
    O: DatagramTransport + Unpin,
    O::SendState: Unpin,
{
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut progressed = false;

            match self.poll_snell_to_outbound(cx) {
                Poll::Ready(Ok(true)) => progressed = true,
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(error)) if is_clean_udp_close(&error) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }

            match self.poll_outbound_to_snell(cx) {
                Poll::Ready(Ok(true)) => progressed = true,
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(error)) if is_clean_udp_close(&error) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }

            if !progressed {
                return Poll::Pending;
            }
        }
    }
}

impl<M, O> SnellUdpRelay<M, O>
where
    M: SnellMode + Unpin,
    M::Encoder: Send + Unpin,
    M::Decoder: Send + Unpin,
    <M::Encoder as SnellTcpEncoder>::Reservation: Send,
    O: DatagramTransport + Unpin,
    O::SendState: Unpin,
{
    fn poll_snell_to_outbound(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let outbound = &mut self.outbound;
        let send_state = &mut self.outbound_send_state;
        self.snell
            .reader
            .poll_drain_frame_plaintext_with(cx, |cx, plaintext| {
                let packet = snell::decode_udp_request_packet(plaintext)?;
                let destination = packet.address.into_owned();
                let sent =
                    ready!(outbound.poll_send_to(cx, &destination, packet.payload, send_state))?;
                if sent != packet.payload.len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "udp outbound sent a partial datagram",
                    )));
                }
                Poll::Ready(Ok(()))
            })
    }

    fn poll_outbound_to_snell(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            if let Some(packet) = &self.pending_to_snell {
                ready!(self.snell.writer.poll_write_frame(
                    cx,
                    packet,
                    &mut self.snell_write_state,
                ))?;
                self.pending_to_snell = None;
                return Poll::Ready(Ok(true));
            }

            let (n, source) = ready!(self.outbound.poll_recv_from(cx, &mut self.outbound_in))?;
            let source = source.as_view();
            let header_len = snell::udp_response_addr_len(source)?;
            let mut packet = vec![0u8; header_len + n];
            snell::encode_udp_response_addr(&mut packet, source)?;
            packet[header_len..].copy_from_slice(&self.outbound_in[..n]);
            self.pending_to_snell = Some(packet);
        }
    }
}

pub(crate) fn relay_socks5_udp<M>(
    control: TcpStream,
    socket: UdpSocket,
    connector: Arc<SnellConnector<M>>,
) -> impl Future<Output = io::Result<()>>
where
    M: SnellMode + Send + Sync + 'static + Unpin,
    M::Encoder: Send + Unpin,
    M::Decoder: Send + Unpin,
    <M::Encoder as SnellTcpEncoder>::Reservation: Send,
{
    let mut relay = Socks5UdpRelay {
        control,
        socket,
        connector,
        nat: LruCache::with_expiry_duration(UDP_ASSOCIATION_TTL),
        client_in: vec![0; MAX_UDP_DATAGRAM_LEN],
        control_buf: [0],
    };
    poll_fn(move |cx| relay.poll(cx))
}

struct Socks5UdpRelay<M>
where
    M: SnellMode,
{
    control: TcpStream,
    socket: UdpSocket,
    connector: Arc<SnellConnector<M>>,
    nat: LruCache<SocketAddr, RefCell<ClientUdpAssociation<M>>>,
    client_in: Vec<u8>,
    control_buf: [u8; 1],
}

impl<M> Socks5UdpRelay<M>
where
    M: SnellMode + Send + Sync + 'static + Unpin,
    M::Encoder: Send + Unpin,
    M::Decoder: Send + Unpin,
    <M::Encoder as SnellTcpEncoder>::Reservation: Send,
{
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut progressed = false;

            match self.poll_control(cx) {
                Poll::Ready(Ok(true)) => progressed = true,
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }

            match self.poll_client_udp(cx) {
                Poll::Ready(Ok(true)) => progressed = true,
                Poll::Ready(Ok(false)) | Poll::Pending => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }

            let keys: Vec<_> = self.nat.peek_iter().map(|(key, _)| *key).collect();
            for key in keys {
                let result = if let Some(cell) = self.nat.peek(&key) {
                    cell.borrow_mut().poll(cx, &self.socket)
                } else {
                    continue;
                };

                match result {
                    Poll::Ready(Ok(true)) => progressed = true,
                    Poll::Ready(Ok(false)) => {
                        self.nat.remove(&key);
                        progressed = true;
                    }
                    Poll::Ready(Err(error)) if is_clean_udp_close(&error) => {
                        self.nat.remove(&key);
                        progressed = true;
                    }
                    Poll::Ready(Err(error)) => {
                        self.nat.remove(&key);
                        tracing::debug!(peer = %key, %error, "SOCKS5 UDP association ended");
                        progressed = true;
                    }
                    Poll::Pending => {}
                }
            }

            if !progressed {
                return Poll::Pending;
            }
        }
    }
}

impl<M> Socks5UdpRelay<M>
where
    M: SnellMode + Send + Sync + 'static + Unpin,
    M::Encoder: Send + Unpin,
    M::Decoder: Send + Unpin,
    <M::Encoder as SnellTcpEncoder>::Reservation: Send,
{
    fn poll_control(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let mut buf = ReadBuf::new(&mut self.control_buf);
        ready!(Pin::new(&mut self.control).poll_read(cx, &mut buf))?;
        Poll::Ready(Ok(!buf.filled().is_empty()))
    }

    fn poll_client_udp(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let mut buf = ReadBuf::new(&mut self.client_in);
        let peer = ready!(self.socket.poll_recv_from(cx, &mut buf))?;
        let n = buf.filled().len();
        let Ok(packet) = socks5::parse_udp_packet(&self.client_in[..n]) else {
            return Poll::Ready(Ok(true));
        };
        if packet.frag != 0 {
            return Poll::Ready(Ok(true));
        }

        let destination = packet.destination.into_owned();
        if self.nat.get(&peer).is_none() {
            self.nat.insert(
                peer,
                RefCell::new(ClientUdpAssociation::new(peer, self.connector.clone())),
            );
        }
        if let Some(association) = self.nat.get(&peer) {
            association
                .borrow_mut()
                .queue_to_snell(&destination, packet.payload)?;
        }
        Poll::Ready(Ok(true))
    }
}

type ConnectFuture<M> = Pin<Box<dyn Future<Output = io::Result<SnellTransport<M>>> + Send>>;

enum ClientUdpTransport<M>
where
    M: SnellMode,
{
    Connecting(ConnectFuture<M>),
    Ready(SnellTransport<M>),
}

struct ClientUdpAssociation<M>
where
    M: SnellMode,
{
    peer: SocketAddr,
    transport: ClientUdpTransport<M>,
    pending_to_snell: Option<Vec<u8>>,
    pending_to_client: Option<Vec<u8>>,
    snell_in: Vec<u8>,
    snell_write_state: WriteFrameState,
    client_send_state: UdpSendState,
}

impl<M> ClientUdpAssociation<M>
where
    M: SnellMode + Send + Sync + 'static + Unpin,
    M::Encoder: Send + Unpin,
    M::Decoder: Send + Unpin,
    <M::Encoder as SnellTcpEncoder>::Reservation: Send,
{
    fn new(peer: SocketAddr, connector: Arc<SnellConnector<M>>) -> Self {
        let future = Box::pin(async move { connector.connect_udp().await });
        Self {
            peer,
            transport: ClientUdpTransport::Connecting(future),
            pending_to_snell: None,
            pending_to_client: None,
            snell_in: Vec::with_capacity(MAX_UDP_DATAGRAM_LEN),
            snell_write_state: WriteFrameState::default(),
            client_send_state: UdpSendState::default(),
        }
    }

    fn queue_to_snell(&mut self, destination: &Address, payload: &[u8]) -> io::Result<()> {
        if self.pending_to_snell.is_some() {
            return Ok(());
        }

        let destination = destination.as_view();
        let header_len = snell::udp_request_addr_len(destination)?;
        let mut packet = vec![0u8; header_len + payload.len()];
        snell::encode_udp_request_addr(&mut packet, destination)?;
        packet[header_len..].copy_from_slice(payload);
        self.pending_to_snell = Some(packet);
        Ok(())
    }

    fn poll(&mut self, cx: &mut Context<'_>, socket: &UdpSocket) -> Poll<io::Result<bool>> {
        loop {
            let transport = match &mut self.transport {
                ClientUdpTransport::Connecting(future) => {
                    let transport = ready!(future.as_mut().poll(cx))?;
                    self.transport = ClientUdpTransport::Ready(transport);
                    return Poll::Ready(Ok(true));
                }
                ClientUdpTransport::Ready(transport) => transport,
            };

            if let Some(packet) = &self.pending_to_client {
                ready!(poll_udp_send_to(
                    socket,
                    cx,
                    self.peer,
                    packet,
                    &mut self.client_send_state,
                ))?;
                self.pending_to_client = None;
                return Poll::Ready(Ok(true));
            }

            if let Some(packet) = &self.pending_to_snell {
                ready!(
                    transport
                        .writer
                        .poll_write_frame(cx, packet, &mut self.snell_write_state,)
                )?;
                self.pending_to_snell = None;
                return Poll::Ready(Ok(true));
            }

            match transport.reader.poll_read_frame_vec(cx, &mut self.snell_in) {
                Poll::Ready(Ok(true)) => {
                    let packet = snell::decode_udp_response_packet(&self.snell_in)?;
                    let header_len = socks5::udp_header_len(packet.address)?;
                    let mut response = vec![0u8; header_len + packet.payload.len()];
                    socks5::encode_udp_header(&mut response, 0, packet.address)?;
                    response[header_len..].copy_from_slice(packet.payload);
                    self.pending_to_client = Some(response);
                }
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(false)),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn is_clean_udp_close(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::TimedOut
    )
}

#[derive(Default)]
enum UdpSendState {
    #[default]
    Ready,
    Sending,
}

fn poll_udp_send_to(
    socket: &UdpSocket,
    cx: &mut Context<'_>,
    destination: SocketAddr,
    packet: &[u8],
    state: &mut UdpSendState,
) -> Poll<io::Result<()>> {
    loop {
        match state {
            UdpSendState::Ready => *state = UdpSendState::Sending,
            UdpSendState::Sending => {
                let n = ready!(socket.poll_send_to(cx, packet, destination))?;
                *state = UdpSendState::Ready;
                if n != packet.len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "udp socket sent a partial datagram",
                    )));
                }
                return Poll::Ready(Ok(()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tokio::net::TcpListener;

    use super::*;
    use crate::{
        protocol::snell::V4Mode,
        relay::tcp::{
            client::SnellTransport,
            driver::{SnellStreamReader, SnellStreamWriter},
        },
    };

    #[tokio::test]
    async fn snell_udp_keeps_plaintext_pending_when_outbound_send_pends() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        let client = client.await.unwrap();

        let (server_read, server_write) = server.into_split();
        let server_transport: SnellTransport<V4Mode> = SnellTransport::new(
            SnellStreamReader::new::<V4Mode>(server_read, psk.clone()),
            SnellStreamWriter::new::<V4Mode>(server_write, psk.clone()).unwrap(),
        );
        let (_, client_write) = client.into_split();
        let mut client_writer = SnellStreamWriter::new::<V4Mode>(client_write, psk).unwrap();

        let state = Arc::new(Mutex::new(PendingOnceState::default()));
        let outbound = PendingOnceOutbound {
            state: state.clone(),
        };
        let relay = tokio::spawn(relay_snell_udp(server_transport, outbound));

        let destination = Address::from(SocketAddr::from(([127, 0, 0, 1], 53)));
        let destination_view = destination.as_view();
        let header_len = snell::udp_request_addr_len(destination_view).unwrap();
        let mut packet = vec![0u8; header_len + 4];
        snell::encode_udp_request_addr(&mut packet, destination_view).unwrap();
        packet[header_len..].copy_from_slice(b"ping");
        client_writer.write_frame(&packet).await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if state.lock().unwrap().payload.is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        {
            let state = state.lock().unwrap();
            assert_eq!(state.attempts, 2);
            assert_eq!(state.destination, Some(destination));
            assert_eq!(state.payload.as_deref(), Some(&b"ping"[..]));
        }

        relay.abort();
        let _ = relay.await;
    }

    #[derive(Default)]
    struct PendingOnceState {
        attempts: usize,
        destination: Option<Address>,
        payload: Option<Vec<u8>>,
    }

    struct PendingOnceOutbound {
        state: Arc<Mutex<PendingOnceState>>,
    }

    impl DatagramTransport for PendingOnceOutbound {
        type SendState = ();

        fn poll_send_to(
            &mut self,
            cx: &mut Context<'_>,
            destination: &Address,
            payload: &[u8],
            _state: &mut Self::SendState,
        ) -> Poll<io::Result<usize>> {
            let mut state = self.state.lock().unwrap();
            state.attempts += 1;
            if state.attempts == 1 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            state.destination = Some(destination.clone());
            state.payload = Some(payload.to_vec());
            Poll::Ready(Ok(payload.len()))
        }

        fn poll_recv_from(
            &mut self,
            _cx: &mut Context<'_>,
            _buf: &mut [u8],
        ) -> Poll<io::Result<(usize, Address)>> {
            Poll::Pending
        }
    }
}

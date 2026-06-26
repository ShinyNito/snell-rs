use std::{
    cell::RefCell,
    collections::VecDeque,
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll, ready},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use compio::{
    buf::BufResult,
    driver::op::RecvFromMultiResult,
    io::AsyncRead,
    net::{TcpStream, UdpSocket},
};
use futures::{Stream, StreamExt};
use lru_time_cache::LruCache;

use crate::{
    protocol::{
        address::Address,
        snell::{self, SnellMode},
        socks5,
    },
    relay::tcp::{
        client::{SnellConnector, SnellTransport},
        driver::WriteFrameState,
    },
};

pub(crate) const UDP_ASSOCIATION_TTL: Duration = Duration::from_mins(5);
pub(crate) const MAX_UDP_DATAGRAM_LEN: usize = 65_535;
pub(crate) const UDP_ASSOCIATION_SEND_QUEUE_LIMIT: usize = 1024;

type TcpReadFuture = Pin<Box<dyn Future<Output = (TcpStream, BufResult<usize, Vec<u8>>)>>>;
type UdpSendFuture = Pin<Box<dyn Future<Output = BufResult<usize, Bytes>>>>;
type UdpRecvBatch = VecDeque<UdpRecvPacket>;
type UdpRecvBatchFuture = Pin<Box<dyn Future<Output = io::Result<UdpRecvBatch>>>>;

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

    fn poll_recv_from(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<ReceivedDatagram>>;
}

pub(crate) struct ReceivedDatagram {
    source: Address,
    packet: UdpRecvPacket,
    payload_offset: usize,
}

impl ReceivedDatagram {
    pub(crate) fn new(source: Address, packet: UdpRecvPacket) -> Self {
        Self {
            source,
            packet,
            payload_offset: 0,
        }
    }

    pub(crate) fn with_payload_offset(
        source: Address,
        packet: UdpRecvPacket,
        payload_offset: usize,
    ) -> io::Result<Self> {
        if payload_offset > packet.payload().len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "udp payload offset is outside packet",
            ));
        }
        Ok(Self {
            source,
            packet,
            payload_offset,
        })
    }

    pub(crate) fn source(&self) -> &Address {
        &self.source
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.packet.payload()[self.payload_offset..]
    }
}

pub(crate) struct UdpRecvPacket {
    source: SocketAddr,
    packet: RecvFromMultiResult,
}

impl UdpRecvPacket {
    pub(crate) fn source(&self) -> SocketAddr {
        self.source
    }

    pub(crate) fn payload(&self) -> &[u8] {
        self.packet.data()
    }
}

pub(crate) fn relay_snell_udp<M, O>(
    transport: SnellTransport<M>,
    outbound: O,
) -> impl Future<Output = io::Result<()>>
where
    M: SnellMode + Unpin,
    M::Encoder: Unpin,
    M::Decoder: Unpin,
    O: DatagramTransport + Unpin,
    O::SendState: Unpin,
{
    let mut relay = SnellUdpRelay {
        snell: transport,
        outbound,
        pending_to_snell: VecDeque::new(),
        pending_to_outbound: VecDeque::new(),
        snell_to_outbound_closed: false,
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
    pending_to_snell: VecDeque<BytesMut>,
    pending_to_outbound: VecDeque<Bytes>,
    snell_to_outbound_closed: bool,
    outbound_send_state: O::SendState,
    snell_write_state: WriteFrameState,
}

impl<M, O> SnellUdpRelay<M, O>
where
    M: SnellMode + Unpin,
    M::Encoder: Unpin,
    M::Decoder: Unpin,
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

    fn poll_snell_to_outbound(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if self.pending_to_outbound.is_empty() {
            if self.snell_to_outbound_closed {
                return Poll::Ready(Ok(false));
            }
            match ready!(self.snell.reader.poll_read_frame_batch(cx))? {
                Some(batch) => {
                    self.snell_to_outbound_closed = batch.ends_stream();
                    self.pending_to_outbound.extend(batch.into_frames());
                    if self.pending_to_outbound.is_empty() && self.snell_to_outbound_closed {
                        return Poll::Ready(Ok(false));
                    }
                }
                None => return Poll::Ready(Ok(false)),
            }
        }

        let frame = self
            .pending_to_outbound
            .front()
            .expect("pending outbound frame");
        let packet = snell::decode_udp_request_packet(frame)?;
        let destination = packet.address.into_owned();
        let payload = packet.payload;
        let payload_len = payload.len();
        let sent = ready!(self.outbound.poll_send_to(
            cx,
            &destination,
            payload,
            &mut self.outbound_send_state
        ))?;
        if sent != payload_len {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "udp outbound sent a partial datagram",
            )));
        }
        self.pending_to_outbound.pop_front();
        Poll::Ready(Ok(true))
    }

    fn poll_outbound_to_snell(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            if matches!(self.snell_write_state, WriteFrameState::Flushing) {
                ready!(
                    self.snell
                        .writer
                        .poll_flush_frame(cx, &mut self.snell_write_state)
                )?;
                return Poll::Ready(Ok(true));
            }

            if let Some(packet) = self.pending_to_snell.pop_front() {
                ready!(self.snell.writer.poll_write_owned_frame(
                    cx,
                    packet,
                    &mut self.snell_write_state,
                ))?;
                return Poll::Ready(Ok(true));
            }

            let datagram = ready!(self.outbound.poll_recv_from(cx))?;
            let source = datagram.source().as_view();
            let payload = datagram.payload();
            let header_len = snell::udp_response_addr_len(source)?;
            let mut packet = BytesMut::zeroed(header_len + payload.len());
            snell::encode_udp_response_addr(&mut packet, source)?;
            packet[header_len..].copy_from_slice(payload);
            self.queue_to_snell(packet)?;
        }
    }

    fn queue_to_snell(&mut self, packet: BytesMut) -> io::Result<()> {
        if self.pending_to_snell.len() >= UDP_ASSOCIATION_SEND_QUEUE_LIMIT {
            return Err(io::Error::other("udp relay channel full"));
        }
        self.pending_to_snell.push_back(packet);
        Ok(())
    }
}

pub(crate) fn relay_socks5_udp<M>(
    control: TcpStream,
    socket: UdpSocket,
    connector: Rc<SnellConnector<M>>,
) -> impl Future<Output = io::Result<()>>
where
    M: SnellMode + 'static + Unpin,
    M::Encoder: Unpin,
    M::Decoder: Unpin,
{
    let mut relay = Socks5UdpRelay {
        control: TcpControlState::new(control),
        socket,
        connector,
        nat: LruCache::with_expiry_duration(UDP_ASSOCIATION_TTL),
        client_recv_state: UdpRecvState::default(),
    };
    poll_fn(move |cx| relay.poll(cx))
}

struct Socks5UdpRelay<M>
where
    M: SnellMode,
{
    control: TcpControlState,
    socket: UdpSocket,
    connector: Rc<SnellConnector<M>>,
    nat: LruCache<SocketAddr, RefCell<ClientUdpAssociation<M>>>,
    client_recv_state: UdpRecvState,
}

impl<M> Socks5UdpRelay<M>
where
    M: SnellMode + 'static + Unpin,
    M::Encoder: Unpin,
    M::Decoder: Unpin,
{
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut progressed = false;

            match self.control.poll(cx) {
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

    fn poll_client_udp(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let datagram = ready!(poll_udp_recv_from(
            &self.socket,
            cx,
            &mut self.client_recv_state,
        ))?;
        let peer = datagram.source();
        let Ok(packet) = socks5::parse_udp_packet(datagram.payload()) else {
            return Poll::Ready(Ok(true));
        };
        if packet.frag != 0 {
            return Poll::Ready(Ok(true));
        }

        let destination = packet.destination.into_owned();
        if self.nat.get(&peer).is_none() {
            tracing::debug!(%peer, "SOCKS5 UDP association created");
            self.nat.insert(
                peer,
                RefCell::new(ClientUdpAssociation::new(peer, self.connector.clone())),
            );
        }
        if let Some(association) = self.nat.get(&peer)
            && let Err(error) = association
                .borrow_mut()
                .queue_to_snell(&destination, packet.payload)
        {
            tracing::debug!(
                %peer,
                %destination,
                %error,
                "SOCKS5 UDP packet dropped"
            );
        }
        Poll::Ready(Ok(true))
    }
}

enum TcpControlState {
    Idle(Option<TcpStream>),
    Reading(TcpReadFuture),
}

impl TcpControlState {
    fn new(control: TcpStream) -> Self {
        Self::Idle(Some(control))
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            match self {
                Self::Idle(control) => {
                    let mut control = control.take().expect("control stream missing");
                    let future = Box::pin(async move {
                        let result = control.read(Vec::with_capacity(1)).await;
                        (control, result)
                    });
                    *self = Self::Reading(future);
                }
                Self::Reading(future) => {
                    let (control, BufResult(result, _buf)) = ready!(future.as_mut().poll(cx));
                    *self = Self::Idle(Some(control));
                    return Poll::Ready(result.map(|n| n != 0));
                }
            }
        }
    }
}

type ConnectFuture<M> = Pin<Box<dyn Future<Output = io::Result<SnellTransport<M>>>>>;

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
    pending_to_snell: VecDeque<BytesMut>,
    pending_to_client: VecDeque<BytesMut>,
    snell_to_client_closed: bool,
    snell_write_state: WriteFrameState,
    client_send_state: UdpSendState,
}

impl<M> ClientUdpAssociation<M>
where
    M: SnellMode + 'static + Unpin,
    M::Encoder: Unpin,
    M::Decoder: Unpin,
{
    fn new(peer: SocketAddr, connector: Rc<SnellConnector<M>>) -> Self {
        let future = Box::pin(async move { connector.connect_udp().await });
        Self {
            peer,
            transport: ClientUdpTransport::Connecting(future),
            pending_to_snell: VecDeque::new(),
            pending_to_client: VecDeque::new(),
            snell_to_client_closed: false,
            snell_write_state: WriteFrameState::default(),
            client_send_state: UdpSendState::default(),
        }
    }

    fn queue_to_snell(&mut self, destination: &Address, payload: &[u8]) -> io::Result<()> {
        if self.pending_to_snell.len() >= UDP_ASSOCIATION_SEND_QUEUE_LIMIT {
            return Err(io::Error::other("udp relay channel full"));
        }

        let destination = destination.as_view();
        let header_len = snell::udp_request_addr_len(destination)?;
        let mut packet = BytesMut::zeroed(header_len + payload.len());
        snell::encode_udp_request_addr(&mut packet, destination)?;
        packet[header_len..].copy_from_slice(payload);
        self.pending_to_snell.push_back(packet);
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

            if self.client_send_state.is_sending() {
                let mut packet = None;
                ready!(poll_udp_send_bytes_to(
                    socket,
                    cx,
                    self.peer,
                    &mut packet,
                    &mut self.client_send_state,
                ))?;
                return Poll::Ready(Ok(true));
            }

            if let Some(packet) = self.pending_to_client.pop_front() {
                let mut packet = Some(packet.freeze());
                ready!(poll_udp_send_bytes_to(
                    socket,
                    cx,
                    self.peer,
                    &mut packet,
                    &mut self.client_send_state,
                ))?;
                return Poll::Ready(Ok(true));
            }

            if self.snell_to_client_closed {
                return Poll::Ready(Ok(false));
            }

            if matches!(self.snell_write_state, WriteFrameState::Flushing) {
                ready!(
                    transport
                        .writer
                        .poll_flush_frame(cx, &mut self.snell_write_state)
                )?;
                return Poll::Ready(Ok(true));
            }

            if let Some(packet) = self.pending_to_snell.pop_front() {
                ready!(transport.writer.poll_write_owned_frame(
                    cx,
                    packet,
                    &mut self.snell_write_state,
                ))?;
                return Poll::Ready(Ok(true));
            }

            match transport.reader.poll_read_frame_batch(cx) {
                Poll::Ready(Ok(Some(batch))) => {
                    self.snell_to_client_closed = batch.ends_stream();
                    for frame in batch.into_frames() {
                        let packet = snell::decode_udp_response_packet(&frame)?;
                        let header_len = socks5::udp_header_len(packet.address)?;
                        let mut response = BytesMut::zeroed(header_len + packet.payload.len());
                        socks5::encode_udp_header(&mut response, 0, packet.address)?;
                        response[header_len..].copy_from_slice(packet.payload);
                        if self.pending_to_client.len() >= UDP_ASSOCIATION_SEND_QUEUE_LIMIT {
                            return Poll::Ready(Err(io::Error::other("udp relay channel full")));
                        }
                        self.pending_to_client.push_back(response);
                    }
                    if self.pending_to_client.is_empty() && self.snell_to_client_closed {
                        return Poll::Ready(Ok(false));
                    }
                }
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(false)),
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
pub(crate) enum UdpSendState {
    #[default]
    Ready,
    Sending {
        len: usize,
        future: UdpSendFuture,
    },
}

impl UdpSendState {
    fn is_sending(&self) -> bool {
        matches!(self, Self::Sending { .. })
    }
}

#[derive(Default)]
pub(crate) struct UdpRecvState {
    packets: UdpRecvBatch,
    receiving: Option<UdpRecvBatchFuture>,
}

pub(crate) fn poll_udp_send_to(
    socket: &UdpSocket,
    cx: &mut Context<'_>,
    destination: SocketAddr,
    packet: &[u8],
    state: &mut UdpSendState,
) -> Poll<io::Result<()>> {
    let mut owned = if state.is_sending() {
        None
    } else {
        Some(Bytes::copy_from_slice(packet))
    };
    poll_udp_send_bytes_to(socket, cx, destination, &mut owned, state)
}

pub(crate) fn poll_udp_send_bytes_to(
    socket: &UdpSocket,
    cx: &mut Context<'_>,
    destination: SocketAddr,
    packet: &mut Option<Bytes>,
    state: &mut UdpSendState,
) -> Poll<io::Result<()>> {
    loop {
        match state {
            UdpSendState::Ready => {
                let socket = socket.clone();
                let packet = packet
                    .take()
                    .ok_or_else(|| io::Error::other("udp send packet missing"))?;
                let len = packet.len();
                let future = Box::pin(async move { socket.send_to(packet, destination).await });
                *state = UdpSendState::Sending { len, future };
            }
            UdpSendState::Sending { len, future } => {
                let len = *len;
                let BufResult(result, _packet) = ready!(future.as_mut().poll(cx));
                *state = UdpSendState::Ready;
                if result? != len {
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

pub(crate) fn poll_udp_recv_from(
    socket: &UdpSocket,
    cx: &mut Context<'_>,
    state: &mut UdpRecvState,
) -> Poll<io::Result<UdpRecvPacket>> {
    loop {
        if let Some(packet) = state.packets.pop_front() {
            return Poll::Ready(Ok(packet));
        }

        if state.receiving.is_none() {
            state.receiving = Some(Box::pin(recv_udp_batch(socket.clone())));
        }

        let mut packets = ready!(
            state
                .receiving
                .as_mut()
                .expect("udp recv batch future missing")
                .as_mut()
                .poll(cx)
        )?;
        state.receiving = None;
        state.packets.append(&mut packets);
    }
}

async fn recv_udp_batch(socket: UdpSocket) -> io::Result<UdpRecvBatch> {
    let mut packets = VecDeque::new();
    let stream = socket.recv_from_multi();
    futures::pin_mut!(stream);

    let first = stream.next().await.ok_or_else(|| {
        io::Error::new(io::ErrorKind::UnexpectedEof, "udp recv_multi stream ended")
    })??;
    queue_udp_recv_packet(&mut packets, first)?;

    poll_fn(|cx| {
        while packets.len() < UDP_ASSOCIATION_SEND_QUEUE_LIMIT {
            match stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(packet))) => {
                    if let Err(error) = queue_udp_recv_packet(&mut packets, packet) {
                        return Poll::Ready(Err(error));
                    }
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error)),
                Poll::Ready(None) | Poll::Pending => return Poll::Ready(Ok(())),
            }
        }
        Poll::Ready(Ok(()))
    })
    .await?;

    Ok(packets)
}

fn queue_udp_recv_packet(
    packets: &mut UdpRecvBatch,
    packet: RecvFromMultiResult,
) -> io::Result<()> {
    if packets.len() >= UDP_ASSOCIATION_SEND_QUEUE_LIMIT {
        return Err(io::Error::other("udp recv queue full"));
    }
    let payload = packet.data();
    let source = udp_recv_packet_source(&packet)?;
    if payload.len() > MAX_UDP_DATAGRAM_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "udp packet is larger than maximum datagram size",
        ));
    }
    packets.push_back(UdpRecvPacket { source, packet });
    Ok(())
}

fn udp_recv_packet_source(packet: &RecvFromMultiResult) -> io::Result<SocketAddr> {
    packet
        .addr()
        .and_then(|addr| addr.as_socket())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "udp packet missing source"))
}

#[cfg(test)]
mod tests {
    use std::{
        future::poll_fn,
        rc::Rc,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use compio::{
        net::{TcpListener, TcpStream, UdpSocket},
        runtime, time,
    };

    use super::*;
    use crate::{
        protocol::snell::V4Mode,
        relay::tcp::{
            client::SnellTransport,
            driver::{SnellStreamReader, SnellStreamWriter},
        },
    };

    #[compio::test]
    async fn snell_udp_keeps_plaintext_pending_when_outbound_send_pends() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) =
            futures::future::try_join(TcpStream::connect(addr), listener.accept())
                .await
                .unwrap();
        let (server, _) = accepted;

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
        let relay = runtime::spawn(relay_snell_udp(server_transport, outbound));

        let destination = Address::from(SocketAddr::from(([127, 0, 0, 1], 53)));
        let destination_view = destination.as_view();
        let header_len = snell::udp_request_addr_len(destination_view).unwrap();
        let mut packet = vec![0u8; header_len + 4];
        snell::encode_udp_request_addr(&mut packet, destination_view).unwrap();
        packet[header_len..].copy_from_slice(b"ping");
        client_writer.write_frame(&packet).await.unwrap();

        time::timeout(Duration::from_secs(1), async {
            loop {
                if state.lock().unwrap().payload.is_some() {
                    break;
                }
                time::sleep(Duration::from_millis(1)).await;
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

        drop(relay);
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

        fn poll_recv_from(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<ReceivedDatagram>> {
            Poll::Pending
        }
    }

    #[test]
    fn client_udp_association_queues_multiple_packets() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let server = SocketAddr::from(([127, 0, 0, 1], 12345));
        let connector = Rc::new(SnellConnector::<V4Mode>::new(server, psk, false));
        let mut association =
            ClientUdpAssociation::new(SocketAddr::from(([127, 0, 0, 1], 1080)), connector);
        let destination = Address::from(SocketAddr::from(([127, 0, 0, 1], 53)));

        association.queue_to_snell(&destination, b"one").unwrap();
        association.queue_to_snell(&destination, b"two").unwrap();

        assert_eq!(association.pending_to_snell.len(), 2);
        let first = association.pending_to_snell.pop_front().unwrap();
        let second = association.pending_to_snell.pop_front().unwrap();
        assert_eq!(
            snell::decode_udp_request_packet(&first).unwrap().payload,
            b"one"
        );
        assert_eq!(
            snell::decode_udp_request_packet(&second).unwrap().payload,
            b"two"
        );
    }

    #[test]
    fn client_udp_association_reports_full_queue() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let server = SocketAddr::from(([127, 0, 0, 1], 12345));
        let connector = Rc::new(SnellConnector::<V4Mode>::new(server, psk, false));
        let mut association =
            ClientUdpAssociation::new(SocketAddr::from(([127, 0, 0, 1], 1080)), connector);
        let destination = Address::from(SocketAddr::from(([127, 0, 0, 1], 53)));

        for _ in 0..UDP_ASSOCIATION_SEND_QUEUE_LIMIT {
            association.queue_to_snell(&destination, b"packet").unwrap();
        }

        let error = association
            .queue_to_snell(&destination, b"overflow")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            association.pending_to_snell.len(),
            UDP_ASSOCIATION_SEND_QUEUE_LIMIT
        );
    }

    #[compio::test]
    async fn udp_recv_from_reads_multiple_datagrams() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let sender_addr = sender.local_addr().unwrap();
        sender.send_to(b"one", receiver_addr).await.unwrap();
        sender.send_to(b"two", receiver_addr).await.unwrap();

        let mut state = UdpRecvState::default();
        let packet = poll_fn(|cx| poll_udp_recv_from(&receiver, cx, &mut state))
            .await
            .unwrap();
        assert_eq!(packet.source(), sender_addr);
        let first = packet.payload().to_vec();

        let packet = poll_fn(|cx| poll_udp_recv_from(&receiver, cx, &mut state))
            .await
            .unwrap();
        assert_eq!(packet.source(), sender_addr);
        let second = packet.payload().to_vec();

        let mut payloads = vec![first, second];
        payloads.sort();
        assert_eq!(payloads, vec![b"one".to_vec(), b"two".to_vec()]);
    }

    #[compio::test]
    async fn client_udp_association_drains_batched_snell_frames_individually() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) =
            futures::future::try_join(TcpStream::connect(addr), listener.accept())
                .await
                .unwrap();
        let (server, _) = accepted;

        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let (client_read, client_write) = client.into_split();
        let mut association: ClientUdpAssociation<V4Mode> = ClientUdpAssociation {
            peer: peer_addr,
            transport: ClientUdpTransport::Ready(SnellTransport::<V4Mode>::new(
                SnellStreamReader::new::<V4Mode>(client_read, psk.clone()),
                SnellStreamWriter::new::<V4Mode>(client_write, psk.clone()).unwrap(),
            )),
            pending_to_snell: VecDeque::new(),
            pending_to_client: VecDeque::new(),
            snell_to_client_closed: false,
            snell_write_state: WriteFrameState::default(),
            client_send_state: UdpSendState::default(),
        };

        let (_server_read, server_write) = server.into_split();
        let mut server_writer = SnellStreamWriter::new::<V4Mode>(server_write, psk).unwrap();
        let source = Address::from(SocketAddr::from(([8, 8, 8, 8], 53)));
        server_writer
            .write_frame(&snell_udp_response(&source, b"one"))
            .await
            .unwrap();
        server_writer
            .write_frame(&snell_udp_response(&source, b"two"))
            .await
            .unwrap();

        let task = runtime::spawn(async move {
            loop {
                poll_fn(|cx| association.poll(cx, &socket)).await.unwrap();
            }
        });

        let mut payloads = time::timeout(Duration::from_secs(1), async {
            let mut payloads = Vec::new();
            for _ in 0..2 {
                let (result, buf) = peer
                    .recv_from(Vec::with_capacity(MAX_UDP_DATAGRAM_LEN))
                    .await
                    .into_parts();
                let (n, _) = result.unwrap();
                let packet = socks5::parse_udp_packet(&buf[..n]).unwrap();
                payloads.push(packet.payload.to_vec());
            }
            payloads
        })
        .await
        .unwrap();
        payloads.sort();
        assert_eq!(payloads, vec![b"one".to_vec(), b"two".to_vec()]);

        drop(task);
    }

    fn snell_udp_response(source: &Address, payload: &[u8]) -> BytesMut {
        let source = source.as_view();
        let header_len = snell::udp_response_addr_len(source).unwrap();
        let mut packet = BytesMut::zeroed(header_len + payload.len());
        snell::encode_udp_response_addr(&mut packet, source).unwrap();
        packet[header_len..].copy_from_slice(payload);
        packet
    }
}

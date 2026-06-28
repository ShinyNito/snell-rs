use std::{io, net::SocketAddr, rc::Rc, time::Duration};

use bytes::BytesMut;
use compio::{
    buf::{BufResult, IoBuf, IoVectoredBuf},
    driver::{
        BufferPool, BufferRef, SharedFd, ToSharedFd,
        op::{RecvFlags, RecvFromMulti, RecvFromMultiResult},
    },
    io::{AsyncRead, AsyncReadManaged},
    net::{TcpStream, UdpSocket},
    runtime::{self, JoinHandle, Runtime, SubmitMultiManaged},
};
use futures::{
    StreamExt,
    channel::mpsc,
    future::{self, Either},
};
use lru_time_cache::LruCache;

use crate::{
    protocol::{
        address::Address,
        snell::{self, SnellBuffer, SnellMode},
        socks5,
    },
    relay::tcp::client::{SnellConnector, SnellTransport},
};

pub(crate) const UDP_ASSOCIATION_TTL: Duration = Duration::from_mins(5);
pub(crate) const MAX_UDP_DATAGRAM_LEN: usize = 65_535;
pub(crate) const UDP_ASSOCIATION_SEND_QUEUE_LIMIT: usize = 1024;
const UDP_ASSOCIATION_PAYLOAD_CACHE_LIMIT: usize = 64;

pub(crate) trait Outbound {
    type Transport: DatagramTransport;

    async fn connect_udp(&self) -> io::Result<Self::Transport>;
}

pub(crate) trait DatagramTransport {
    type Sender: DatagramSender;
    type Receiver: DatagramReceiver;

    fn split(self) -> (Self::Sender, Self::Receiver);
}

pub(crate) trait DatagramSender {
    async fn send_to(&mut self, destination: Address, payload: SnellBuffer) -> io::Result<usize>;
}

pub(crate) trait DatagramReceiver {
    async fn recv_from(&mut self) -> io::Result<ReceivedDatagram>;
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
    payload: RecvFromMultiResult,
}

impl UdpRecvPacket {
    pub(crate) fn source(&self) -> SocketAddr {
        self.source
    }

    pub(crate) fn payload(&self) -> &[u8] {
        self.payload.data()
    }
}

type UdpRecvOp = SubmitMultiManaged<RecvFromMulti<SharedFd<socket2::Socket>>, RecvFromMultiResult>;

pub(crate) struct UdpRecvStream {
    fd: SharedFd<socket2::Socket>,
    runtime: Runtime,
    pool: BufferPool,
    op: Option<UdpRecvOp>,
}

impl UdpRecvStream {
    fn new(socket: &UdpSocket) -> io::Result<Self> {
        let runtime = Runtime::current();
        let pool = runtime.buffer_pool()?;
        Ok(Self {
            fd: socket.to_shared_fd(),
            runtime,
            pool,
            op: None,
        })
    }

    fn new_op(&self) -> io::Result<UdpRecvOp> {
        let op = RecvFromMulti::new(self.fd.clone(), &self.pool, RecvFlags::empty())?;
        Ok(self
            .runtime
            .submit_multi(op)
            .into_managed(self.pool.clone()))
    }

    async fn next(&mut self) -> io::Result<RecvFromMultiResult> {
        loop {
            if self.op.is_none() {
                self.op = Some(self.new_op()?);
            }
            match self.op.as_mut().expect("udp receive op").next().await {
                Some(Ok(Some(packet))) if !packet.data().is_empty() => return Ok(packet),
                // Some drivers finish a managed multishot op after one result.
                Some(Ok(Some(_))) | Some(Ok(None)) | None => self.op = None,
                Some(Err(error)) => return Err(error),
            }
        }
    }
}

pub(crate) async fn relay_snell_udp<M, O>(
    transport: SnellTransport<M>,
    outbound: O,
) -> io::Result<()>
where
    M: SnellMode + Unpin,
    M::Encoder: Unpin,
    M::Decoder: Unpin,
    O: DatagramTransport,
{
    let SnellTransport { reader, writer } = transport;
    let (sender, receiver) = outbound.split();
    let to_outbound = relay_snell_to_outbound(reader, sender);
    let to_snell = relay_outbound_to_snell(receiver, writer);
    futures::pin_mut!(to_outbound, to_snell);

    match future::select(to_outbound, to_snell).await {
        Either::Left((result, _)) | Either::Right((result, _)) => clean_udp_result(result),
    }
}

async fn relay_snell_to_outbound<R, D, S>(
    mut reader: crate::relay::tcp::driver::SnellStreamReader<R, D>,
    mut sender: S,
) -> io::Result<()>
where
    R: AsyncRead + AsyncReadManaged<Buffer = BufferRef> + 'static,
    D: crate::protocol::snell::SnellTcpDecoder,
    S: DatagramSender,
{
    while let Some(mut frame) = reader.read_plain_frame().await? {
        let packet = snell::decode_udp_request_packet(frame.as_slice())?;
        let destination = packet.address.into_owned();
        let header_len = packet.header_len;
        frame.advance(header_len);
        let payload_len = frame.len();
        let sent = sender.send_to(destination, frame).await?;
        if sent != payload_len {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "udp outbound sent a partial datagram",
            ));
        }
    }
    Ok(())
}

async fn relay_outbound_to_snell<W, E, R>(
    mut receiver: R,
    mut writer: crate::relay::tcp::driver::SnellStreamWriter<W, E>,
) -> io::Result<()>
where
    W: compio::io::AsyncWrite + 'static,
    E: crate::protocol::snell::SnellTcpEncoder,
    R: DatagramReceiver,
{
    loop {
        let datagram = receiver.recv_from().await?;
        let source = datagram.source().as_view();
        let payload = datagram.payload();
        let header_len = snell::udp_response_addr_len(source)?;
        writer
            .write_with(header_len + payload.len(), |packet| {
                snell::encode_udp_response_addr(packet, source)?;
                packet[header_len..header_len + payload.len()].copy_from_slice(payload);
                Ok(header_len + payload.len())
            })
            .await?;
    }
}

pub(crate) async fn relay_socks5_udp<M>(
    control: TcpStream,
    socket: UdpSocket,
    connector: Rc<SnellConnector<M>>,
) -> io::Result<()>
where
    M: SnellMode + 'static + Unpin,
    M::Encoder: Unpin,
    M::Decoder: Unpin,
{
    let control = watch_tcp_control(control);
    let client_udp = relay_socks5_client_udp(socket, connector);
    futures::pin_mut!(control, client_udp);

    match future::select(control, client_udp).await {
        Either::Left((result, _)) | Either::Right((result, _)) => result,
    }
}

async fn watch_tcp_control(mut control: TcpStream) -> io::Result<()> {
    while let Some(buf) = control.read_managed(1).await? {
        if buf.is_empty() {
            return Ok(());
        }
    }
    Ok(())
}

async fn relay_socks5_client_udp<M>(
    socket: UdpSocket,
    connector: Rc<SnellConnector<M>>,
) -> io::Result<()>
where
    M: SnellMode + 'static + Unpin,
    M::Encoder: Unpin,
    M::Decoder: Unpin,
{
    let mut nat = LruCache::with_expiry_duration(UDP_ASSOCIATION_TTL);
    let mut packets = recv_udp_stream(&socket)?;
    loop {
        let datagram = recv_udp_packet(&mut packets).await?;
        let peer = datagram.source();
        let Ok(packet) = socks5::parse_udp_packet(datagram.payload()) else {
            continue;
        };
        if packet.frag != 0 {
            continue;
        }

        let destination = packet.destination.into_owned();
        if nat.get(&peer).is_none() {
            tracing::debug!(%peer, "SOCKS5 UDP association created");
            nat.insert(
                peer,
                spawn_client_udp_association::<M>(peer, connector.clone(), socket.clone()),
            );
        }

        let Some(association) = nat.get_mut(&peer) else {
            continue;
        };
        if let Err(error) = association.send(destination, packet.payload) {
            tracing::debug!(
                %peer,
                %error,
                "SOCKS5 UDP packet dropped"
            );
            if association.is_closed() {
                nat.remove(&peer);
            }
        }
    }
}

struct AssociationHandle {
    sender: mpsc::Sender<ClientUdpRequest>,
    recycler: mpsc::Receiver<BytesMut>,
    payload_cache: Vec<BytesMut>,
    _task: JoinHandle<io::Result<()>>,
    closed: bool,
}

impl AssociationHandle {
    fn send(&mut self, destination: Address, payload: &[u8]) -> io::Result<()> {
        self.collect_recycled_payloads();
        let request = ClientUdpRequest {
            destination,
            payload: self.payload_buffer(payload),
        };
        match self.sender.try_send(request) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.closed = error.is_disconnected();
                self.recycle_payload_buffer(error.into_inner().payload);
                Err(io::Error::other("udp relay channel full"))
            }
        }
    }

    fn is_closed(&self) -> bool {
        self.closed
    }

    fn collect_recycled_payloads(&mut self) {
        while let Ok(buf) = self.recycler.try_recv() {
            self.recycle_payload_buffer(buf);
        }
    }

    fn payload_buffer(&mut self, payload: &[u8]) -> BytesMut {
        let mut buf = self.payload_cache.pop().unwrap_or_default();
        if buf.capacity() < payload.len() {
            buf.reserve(payload.len() - buf.capacity());
        }
        buf.clear();
        buf.extend_from_slice(payload);
        buf
    }

    fn recycle_payload_buffer(&mut self, mut buf: BytesMut) {
        if self.payload_cache.len() < UDP_ASSOCIATION_PAYLOAD_CACHE_LIMIT {
            buf.clear();
            self.payload_cache.push(buf);
        }
    }
}

struct ClientUdpRequest {
    destination: Address,
    payload: BytesMut,
}

fn spawn_client_udp_association<M>(
    peer: SocketAddr,
    connector: Rc<SnellConnector<M>>,
    socket: UdpSocket,
) -> AssociationHandle
where
    M: SnellMode + 'static + Unpin,
    M::Encoder: Unpin,
    M::Decoder: Unpin,
{
    let (sender, receiver) = mpsc::channel(UDP_ASSOCIATION_SEND_QUEUE_LIMIT);
    let (recycler_sender, recycler) = mpsc::channel(UDP_ASSOCIATION_PAYLOAD_CACHE_LIMIT);
    let task = runtime::spawn(async move {
        let transport = connector.connect_udp().await?;
        run_client_udp_association(peer, socket, transport, receiver, recycler_sender).await
    });
    AssociationHandle {
        sender,
        recycler,
        payload_cache: Vec::new(),
        _task: task,
        closed: false,
    }
}

async fn run_client_udp_association<M>(
    peer: SocketAddr,
    socket: UdpSocket,
    transport: SnellTransport<M>,
    receiver: mpsc::Receiver<ClientUdpRequest>,
    recycler: mpsc::Sender<BytesMut>,
) -> io::Result<()>
where
    M: SnellMode + Unpin,
    M::Encoder: Unpin,
    M::Decoder: Unpin,
{
    let SnellTransport { reader, writer } = transport;
    let to_snell = association_client_to_snell(writer, receiver, recycler);
    let to_client = association_snell_to_client(reader, socket, peer);
    futures::pin_mut!(to_snell, to_client);

    match future::select(to_snell, to_client).await {
        Either::Left((result, _)) | Either::Right((result, _)) => clean_udp_result(result),
    }
}

async fn association_client_to_snell<W, E>(
    mut writer: crate::relay::tcp::driver::SnellStreamWriter<W, E>,
    mut receiver: mpsc::Receiver<ClientUdpRequest>,
    mut recycler: mpsc::Sender<BytesMut>,
) -> io::Result<()>
where
    W: compio::io::AsyncWrite + 'static,
    E: crate::protocol::snell::SnellTcpEncoder,
{
    while let Some(request) = receiver.next().await {
        let ClientUdpRequest {
            destination,
            mut payload,
        } = request;
        let destination = destination.as_view();
        let payload_slice = &payload[..];
        let header_len = snell::udp_request_addr_len(destination)?;
        writer
            .write_with(header_len + payload_slice.len(), |packet| {
                snell::encode_udp_request_addr(packet, destination)?;
                packet[header_len..header_len + payload_slice.len()].copy_from_slice(payload_slice);
                Ok(header_len + payload_slice.len())
            })
            .await?;
        payload.clear();
        let _ = recycler.try_send(payload);
    }
    Ok(())
}

async fn association_snell_to_client<R, D>(
    mut reader: crate::relay::tcp::driver::SnellStreamReader<R, D>,
    socket: UdpSocket,
    peer: SocketAddr,
) -> io::Result<()>
where
    R: AsyncRead + AsyncReadManaged<Buffer = BufferRef> + 'static,
    D: crate::protocol::snell::SnellTcpDecoder,
{
    let mut response_header = BytesMut::with_capacity(socks5::MAX_UDP_HEADER_LEN);
    while let Some(mut frame) = reader.read_plain_frame().await? {
        let packet = snell::decode_udp_response_packet(frame.as_slice())?;
        let header_len = socks5::udp_header_len(packet.address)?;
        let snell_header_len = packet.header_len;
        response_header.clear();
        response_header.resize(header_len, 0);
        socks5::encode_udp_header(&mut response_header, 0, packet.address)?;
        frame.advance(snell_header_len);
        let (header, (_frame,)) =
            send_udp_vectored_to(&socket, peer, (response_header, (frame,))).await?;
        response_header = header;
    }
    Ok(())
}

fn clean_udp_result(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if is_clean_udp_close(&error) => Ok(()),
        result => result,
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

pub(crate) async fn send_udp_bytes_to<T>(
    socket: &UdpSocket,
    destination: SocketAddr,
    packet: T,
) -> io::Result<()>
where
    T: IoBuf,
{
    let len = packet.as_init().len();
    let BufResult(result, _packet) = socket.send_to(packet, destination).await;
    if result? != len {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "udp socket sent a partial datagram",
        ));
    }
    Ok(())
}

pub(crate) async fn send_udp_vectored_to<T>(
    socket: &UdpSocket,
    destination: SocketAddr,
    packet: T,
) -> io::Result<T>
where
    T: IoVectoredBuf,
{
    let len = packet.total_len();
    let BufResult(result, _packet) = socket.send_to_vectored(packet, destination).await;
    if result? != len {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "udp socket sent a partial datagram",
        ));
    }
    Ok(_packet)
}

pub(crate) fn recv_udp_stream(socket: &UdpSocket) -> io::Result<UdpRecvStream> {
    UdpRecvStream::new(socket)
}

pub(crate) async fn recv_udp_packet(stream: &mut UdpRecvStream) -> io::Result<UdpRecvPacket> {
    udp_packet_from_multi(stream.next().await?)
}

fn udp_packet_from_multi(payload: RecvFromMultiResult) -> io::Result<UdpRecvPacket> {
    if payload.data().len() > MAX_UDP_DATAGRAM_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "udp packet is larger than maximum datagram size",
        ));
    }
    let source = payload
        .addr()
        .and_then(|addr| addr.as_socket())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "udp packet has no source"))?;
    Ok(UdpRecvPacket { source, payload })
}

#[cfg(test)]
mod tests {
    use std::{
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
    async fn snell_udp_keeps_plaintext_pending_while_outbound_send_awaits() {
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

        let state = Arc::new(Mutex::new(PendingSendState::default()));
        let outbound = PendingOnceOutbound {
            state: state.clone(),
        };
        let relay = runtime::spawn(relay_snell_udp(server_transport, outbound));

        let destination = Address::from(SocketAddr::from(([127, 0, 0, 1], 53)));
        write_udp_request_frame(&mut client_writer, &destination, b"ping").await;

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
            assert_eq!(state.attempts, 1);
            assert_eq!(state.destination, Some(destination));
            assert_eq!(state.payload.as_deref(), Some(&b"ping"[..]));
        }

        drop(relay);
    }

    #[derive(Default)]
    struct PendingSendState {
        attempts: usize,
        destination: Option<Address>,
        payload: Option<Vec<u8>>,
    }

    struct PendingOnceOutbound {
        state: Arc<Mutex<PendingSendState>>,
    }

    struct PendingOnceSender {
        state: Arc<Mutex<PendingSendState>>,
    }

    struct PendingReceiver;

    impl DatagramTransport for PendingOnceOutbound {
        type Sender = PendingOnceSender;
        type Receiver = PendingReceiver;

        fn split(self) -> (Self::Sender, Self::Receiver) {
            (PendingOnceSender { state: self.state }, PendingReceiver)
        }
    }

    impl DatagramSender for PendingOnceSender {
        async fn send_to(
            &mut self,
            destination: Address,
            payload: SnellBuffer,
        ) -> io::Result<usize> {
            self.state.lock().unwrap().attempts += 1;
            time::sleep(Duration::from_millis(10)).await;
            let mut state = self.state.lock().unwrap();
            state.destination = Some(destination);
            state.payload = Some(payload.as_slice().to_vec());
            Ok(payload.len())
        }
    }

    impl DatagramReceiver for PendingReceiver {
        async fn recv_from(&mut self) -> io::Result<ReceivedDatagram> {
            future::pending().await
        }
    }

    #[compio::test]
    async fn association_client_to_snell_encodes_requests_in_order() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) =
            futures::future::try_join(TcpStream::connect(addr), listener.accept())
                .await
                .unwrap();
        let (server, _) = accepted;

        let (_, client_write) = client.into_split();
        let (server_read, _) = server.into_split();
        let client_writer = SnellStreamWriter::new::<V4Mode>(client_write, psk.clone()).unwrap();
        let mut server_reader = SnellStreamReader::new::<V4Mode>(server_read, psk);
        let (mut sender, receiver) = mpsc::channel(UDP_ASSOCIATION_SEND_QUEUE_LIMIT);
        let (recycler_sender, mut recycler) = mpsc::channel(UDP_ASSOCIATION_PAYLOAD_CACHE_LIMIT);
        let destination = Address::from(SocketAddr::from(([127, 0, 0, 1], 53)));

        let task = runtime::spawn(association_client_to_snell(
            client_writer,
            receiver,
            recycler_sender,
        ));
        assert!(
            sender
                .try_send(client_udp_request_for_destination(&destination, b"one"))
                .is_ok()
        );
        assert!(
            sender
                .try_send(client_udp_request_for_destination(&destination, b"two"))
                .is_ok()
        );
        drop(sender);

        let first = server_reader.read_plain_frame().await.unwrap().unwrap();
        let first = snell::decode_udp_request_packet(first.as_slice()).unwrap();
        assert_eq!(first.address.into_owned(), destination);
        assert_eq!(first.payload, b"one");

        let second = server_reader.read_plain_frame().await.unwrap().unwrap();
        let second = snell::decode_udp_request_packet(second.as_slice()).unwrap();
        assert_eq!(second.address.into_owned(), destination);
        assert_eq!(second.payload, b"two");

        task.await.unwrap().unwrap();
        let mut recycled = 0;
        while let Ok(_buf) = recycler.try_recv() {
            recycled += 1;
        }
        assert_eq!(recycled, 2);
    }

    #[compio::test]
    async fn association_handle_reports_full_queue() {
        let (sender, _receiver) = mpsc::channel(1);
        let (_recycler_sender, recycler) = mpsc::channel(UDP_ASSOCIATION_PAYLOAD_CACHE_LIMIT);
        let task = runtime::spawn(future::pending::<io::Result<()>>());
        let mut association = AssociationHandle {
            sender,
            recycler,
            payload_cache: Vec::new(),
            _task: task,
            closed: false,
        };
        let destination = Address::from(SocketAddr::from(([127, 0, 0, 1], 53)));

        let mut error = None;
        for _ in 0..8 {
            if let Err(send_error) = association.send(destination.clone(), b"packet") {
                error = Some(send_error);
                break;
            }
        }
        assert_eq!(
            error.expect("queue should become full").kind(),
            io::ErrorKind::Other
        );
    }

    #[compio::test]
    async fn association_handle_reuses_recycled_payload_buffer() {
        let (sender, mut receiver) = mpsc::channel(1);
        let (mut recycler_sender, recycler) = mpsc::channel(UDP_ASSOCIATION_PAYLOAD_CACHE_LIMIT);
        let mut recycled = BytesMut::with_capacity(128);
        recycled.extend_from_slice(b"old");
        assert!(recycler_sender.try_send(recycled).is_ok());

        let task = runtime::spawn(future::pending::<io::Result<()>>());
        let mut association = AssociationHandle {
            sender,
            recycler,
            payload_cache: Vec::new(),
            _task: task,
            closed: false,
        };
        let destination = Address::from(SocketAddr::from(([127, 0, 0, 1], 53)));

        association.send(destination.clone(), b"new").unwrap();
        let request = receiver.next().await.expect("queued request");
        assert_eq!(request.destination, destination);
        assert_eq!(&request.payload[..], b"new");
        assert!(request.payload.capacity() >= 128);
    }

    fn client_udp_request_for_destination(
        destination: &Address,
        payload: &[u8],
    ) -> ClientUdpRequest {
        ClientUdpRequest {
            destination: destination.clone(),
            payload: BytesMut::from(payload),
        }
    }

    #[compio::test]
    async fn udp_recv_packet_reads_multiple_datagrams() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let sender_addr = sender.local_addr().unwrap();
        sender.send_to(b"one", receiver_addr).await.unwrap();
        sender.send_to(b"two", receiver_addr).await.unwrap();

        let mut packets = recv_udp_stream(&receiver).unwrap();
        let packet = recv_udp_packet(&mut packets).await.unwrap();
        assert_eq!(packet.source(), sender_addr);
        let first = packet.payload().to_vec();

        let packet = recv_udp_packet(&mut packets).await.unwrap();
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
        let transport: SnellTransport<V4Mode> = SnellTransport::new(
            SnellStreamReader::new::<V4Mode>(client_read, psk.clone()),
            SnellStreamWriter::new::<V4Mode>(client_write, psk.clone()).unwrap(),
        );
        let (_sender, receiver) = mpsc::channel(UDP_ASSOCIATION_SEND_QUEUE_LIMIT);
        let (recycler_sender, _recycler) = mpsc::channel(UDP_ASSOCIATION_PAYLOAD_CACHE_LIMIT);
        let task = runtime::spawn(run_client_udp_association(
            peer_addr,
            socket,
            transport,
            receiver,
            recycler_sender,
        ));

        let (_server_read, server_write) = server.into_split();
        let mut server_writer = SnellStreamWriter::new::<V4Mode>(server_write, psk).unwrap();
        let source = Address::from(SocketAddr::from(([8, 8, 8, 8], 53)));
        write_udp_response_frame(&mut server_writer, &source, b"one").await;
        write_udp_response_frame(&mut server_writer, &source, b"two").await;

        let mut payloads = time::timeout(Duration::from_secs(1), async {
            let mut packets = recv_udp_stream(&peer).unwrap();
            let mut payloads = Vec::new();
            for _ in 0..2 {
                let packet = recv_udp_packet(&mut packets).await.unwrap();
                let packet = socks5::parse_udp_packet(packet.payload()).unwrap();
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

    async fn write_udp_request_frame<W, E>(
        writer: &mut SnellStreamWriter<W, E>,
        destination: &Address,
        payload: &[u8],
    ) where
        W: compio::io::AsyncWrite + 'static,
        E: crate::protocol::snell::SnellTcpEncoder,
    {
        let destination = destination.as_view();
        let header_len = snell::udp_request_addr_len(destination).unwrap();
        writer
            .write_with(header_len + payload.len(), |packet| {
                snell::encode_udp_request_addr(packet, destination)?;
                packet[header_len..header_len + payload.len()].copy_from_slice(payload);
                Ok(header_len + payload.len())
            })
            .await
            .unwrap();
    }

    async fn write_udp_response_frame<W, E>(
        writer: &mut SnellStreamWriter<W, E>,
        source: &Address,
        payload: &[u8],
    ) where
        W: compio::io::AsyncWrite + 'static,
        E: crate::protocol::snell::SnellTcpEncoder,
    {
        let source = source.as_view();
        let header_len = snell::udp_response_addr_len(source).unwrap();
        writer
            .write_with(header_len + payload.len(), |packet| {
                snell::encode_udp_response_addr(packet, source)?;
                packet[header_len..header_len + payload.len()].copy_from_slice(payload);
                Ok(header_len + payload.len())
            })
            .await
            .unwrap();
    }
}

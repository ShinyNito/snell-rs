use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, Sleep, sleep};

use crate::error::{Error, Result};
use crate::net::connect::connect_tcp;
use crate::protocol::psk::SnellPsk;
use crate::protocol::quic_proxy::{
    encode_init_datagram, is_quic_initial, is_quic_initial_packet, is_quic_looking,
    is_quic_short_header,
};
use crate::protocol::socks5::{SocksReply, parse_udp_packet, write_udp_packet};
use crate::protocol::udp::{AddressRef, write_udp_request_prefix};
use crate::proxy::outbound::RelayStats;
use crate::proxy::socks5::inbound::{write_reply_and_shutdown, write_reply_with_bind};
use crate::relay::activity::RelayActivity;
use crate::relay::udp::association::{
    ClientPeerByUdpTarget, OwnedUdpTarget, Socks5ClientUdpSeed, UdpRelayDriver, UdpRelayStats,
    is_allowed_socks_udp_peer, quic_init_host,
};
use crate::relay::udp::io::{MAX_SOCKS_UDP_HEADER, UdpRecvBatch, UdpSendBatch};
use crate::transport::udp::stream::UdpClientStream;
use crate::{MAX_PACKET_SIZE, ProtocolVersion};

const SOCKS5_UDP_ASSOCIATION_TIMEOUT: Duration = Duration::from_mins(1);
const SOCKS5_UDP_BUFFER_SIZE: usize = MAX_PACKET_SIZE + 512;
const MAX_QUIC_SOCKS_UDP_DATAGRAM: usize = MAX_SOCKS_UDP_HEADER + SOCKS5_UDP_BUFFER_SIZE;

struct FirstSocksUdpBuffers {
    socks_in: UdpRecvBatch,
}

struct FirstSocksDatagram {
    peer: SocketAddr,
    target: OwnedUdpTarget,
    payload_start: usize,
    payload_len: usize,
    datagram: BytesMut,
}

impl FirstSocksDatagram {
    /// The client payload (after the SOCKS5 UDP header) carried by this datagram.
    fn payload(&self) -> &[u8] {
        &self.datagram[self.payload_start..self.payload_start + self.payload_len]
    }
}

struct SnellUdpStartupBuffers {
    datagram: BytesMut,
    socks_header: BytesMut,
}

struct LazyQuicUdpBuffers {
    first_datagram: BytesMut,
    socks_in: UdpRecvBatch,
    quic_in: UdpRecvBatch,
    socks_header: BytesMut,
    plaintext: BytesMut,
    wire: BytesMut,
    quic_host_scratch: String,
}

impl FirstSocksUdpBuffers {
    fn new() -> Self {
        Self {
            socks_in: UdpRecvBatch::with_capacity(SOCKS5_UDP_BUFFER_SIZE, 1),
        }
    }
}

impl SnellUdpStartupBuffers {
    fn new(datagram: BytesMut) -> Self {
        Self {
            datagram,
            socks_header: BytesMut::with_capacity(MAX_SOCKS_UDP_HEADER),
        }
    }
}

impl LazyQuicUdpBuffers {
    fn new(first_datagram: BytesMut) -> Self {
        Self {
            first_datagram,
            socks_in: UdpRecvBatch::with_capacity(SOCKS5_UDP_BUFFER_SIZE, 1),
            quic_in: UdpRecvBatch::with_capacity(MAX_PACKET_SIZE + 512, 1),
            socks_header: BytesMut::with_capacity(MAX_SOCKS_UDP_HEADER),
            plaintext: BytesMut::with_capacity(MAX_PACKET_SIZE),
            wire: BytesMut::with_capacity(MAX_PACKET_SIZE + 512),
            quic_host_scratch: String::with_capacity(39),
        }
    }
}

pub(crate) async fn relay_socks5_udp_association(
    mut control: TcpStream,
    server_addr: SocketAddr,
    secret: SnellPsk,
    version: ProtocolVersion,
    quic_proxy: bool,
) -> Result<RelayStats> {
    if quic_proxy && version == ProtocolVersion::V5 {
        return relay_socks5_udp_association_lazy_quic(control, server_addr, secret).await;
    }

    let control_peer_ip = control.peer_addr()?.ip();
    let udp_socket = Arc::new(bind_socks5_udp_socket(control.local_addr()?).await?);
    let udp_bind_addr = udp_socket.local_addr()?;
    let snell_tcp = match connect_tcp(server_addr).await {
        Ok(stream) => {
            stream.set_nodelay(true)?;
            stream
        }
        Err(err) => {
            write_reply_and_shutdown(&mut control, SocksReply::GeneralFailure).await;
            return Err(err.into());
        }
    };
    let (snell_reader_io, snell_writer_io) = snell_tcp.into_split();
    let snell =
        match UdpClientStream::open_io(snell_reader_io, snell_writer_io, &secret, version).await {
            Ok(snell) => snell,
            Err(err) => {
                write_reply_and_shutdown(&mut control, SocksReply::GeneralFailure).await;
                return Err(err);
            }
        };

    write_reply_with_bind(&mut control, SocksReply::Succeeded, udp_bind_addr).await?;

    let (control_reader, _control_writer) = control.into_split();
    let (snell_reader, snell_writer) = snell.into_parts();
    let (activity, _last_activity) = RelayActivity::new();
    let driver = UdpRelayDriver::from_socks5_client_parts(
        snell_reader,
        snell_writer,
        control_reader,
        udp_socket,
        control_peer_ip,
        Socks5ClientUdpSeed::default(),
        &activity,
    );
    tokio::pin!(driver);
    driver.await.map(UdpRelayStats::into_relay_stats)
}

/// SOCKS5 UDP associate that only opens the snell/quic-proxy path after the
/// first client datagram arrives, so an idle association costs nothing.
///
/// Dispatch is driven by the first byte of that datagram: a QUIC Initial
/// takes the lazy QUIC-proxy path, anything else opens a snell UDP tunnel.
async fn relay_socks5_udp_association_lazy_quic(
    mut control: TcpStream,
    server_addr: SocketAddr,
    secret: SnellPsk,
) -> Result<RelayStats> {
    let control_peer_ip = control.peer_addr()?.ip();
    let udp_socket = Arc::new(bind_socks5_udp_socket(control.local_addr()?).await?);
    let udp_bind_addr = udp_socket.local_addr()?;
    write_reply_with_bind(&mut control, SocksReply::Succeeded, udp_bind_addr).await?;

    let (control_reader, _control_writer) = control.into_split();
    tokio::pin!(control_reader);

    let first_datagram =
        recv_first_lazy_quic_datagram(control_reader.as_mut(), &udp_socket, control_peer_ip);
    tokio::pin!(first_datagram);
    let Some(first) = first_datagram.await? else {
        return Ok(RelayStats::default());
    };

    if first
        .payload()
        .first()
        .is_some_and(|byte| is_quic_initial(*byte))
    {
        let quic_socket = UdpSocket::bind(quic_bind_addr(server_addr)).await?;
        let relay = relay_lazy_quic_proxy_packets(
            control_reader.as_mut(),
            &udp_socket,
            &quic_socket,
            server_addr,
            control_peer_ip,
            &secret,
            first,
        )?;
        tokio::pin!(relay);
        relay.await
    } else {
        relay_lazy_quic_first_over_snell(
            control_reader.as_mut(),
            udp_socket,
            control_peer_ip,
            server_addr,
            &secret,
            first,
        )
        .await
    }
}

/// Waits for the first client datagram. Returns `None` when the control
/// connection closes or the association idles out before any data arrives.
fn recv_first_lazy_quic_datagram<'a, R>(
    control_reader: Pin<&'a mut R>,
    udp_socket: &'a UdpSocket,
    control_peer_ip: IpAddr,
) -> FirstLazyQuicDatagramFuture<'a, R>
where
    R: AsyncRead,
{
    FirstLazyQuicDatagramFuture::new(control_reader, udp_socket, control_peer_ip)
}

pin_project! {
    struct FirstLazyQuicDatagramFuture<'a, R> {
        control_reader: Pin<&'a mut R>,
        udp_socket: &'a UdpSocket,
        control_peer_ip: IpAddr,
        control_buf: [u8; 128],
        buffers: Box<FirstSocksUdpBuffers>,
        #[pin]
        idle: Sleep,
    }
}

impl<'a, R> FirstLazyQuicDatagramFuture<'a, R> {
    fn new(
        control_reader: Pin<&'a mut R>,
        udp_socket: &'a UdpSocket,
        control_peer_ip: IpAddr,
    ) -> Self {
        Self {
            control_reader,
            udp_socket,
            control_peer_ip,
            control_buf: [0; 128],
            buffers: Box::new(FirstSocksUdpBuffers::new()),
            idle: sleep(SOCKS5_UDP_ASSOCIATION_TIMEOUT),
        }
    }
}

impl<R> Future for FirstLazyQuicDatagramFuture<'_, R>
where
    R: AsyncRead,
{
    type Output = Result<Option<FirstSocksDatagram>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        loop {
            let mut out = ReadBuf::new(this.control_buf);
            match this.control_reader.as_mut().poll_read(cx, &mut out) {
                Poll::Ready(Ok(())) if out.filled().is_empty() => return Poll::Ready(Ok(None)),
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err.into())),
                Poll::Pending => break,
            }
        }

        match this.buffers.socks_in.poll_recv_from(this.udp_socket, cx) {
            Poll::Ready(Ok(_)) => {
                let Some(entry) = this.buffers.socks_in.get(0) else {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                };
                if entry.is_oversized() {
                    tracing::debug!("ignored oversized socks5 udp datagram");
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let peer = entry.peer();
                if !is_allowed_socks_udp_peer(*this.control_peer_ip, peer) {
                    tracing::debug!(%peer, control_peer_ip = %this.control_peer_ip, "ignored socks5 udp datagram from unexpected source ip");
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let (target, payload_start, payload_len) = {
                    let packet = match parse_udp_packet(entry.payload()) {
                        Ok(packet) => packet,
                        Err(err) => {
                            tracing::debug!(%err, "ignored invalid socks5 udp datagram");
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                    };
                    (
                        OwnedUdpTarget::from_ref(packet.address, packet.port),
                        packet.payload_span.start,
                        packet.payload.len(),
                    )
                };
                let datagram = BytesMut::from(entry.payload());
                return Poll::Ready(Ok(Some(FirstSocksDatagram {
                    peer,
                    target,
                    payload_start,
                    payload_len,
                    datagram,
                })));
            }
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => {}
        }

        if this.idle.poll(cx).is_ready() {
            tracing::debug!("snell socks5 udp association idle timed out");
            return Poll::Ready(Ok(None));
        }

        Poll::Pending
    }
}

/// Non-QUIC first datagram: open a snell UDP tunnel and forward the first
/// packet before entering the shared snell-over-udp relay loop.
async fn relay_lazy_quic_first_over_snell<R>(
    control_reader: Pin<&mut R>,
    udp_socket: Arc<UdpSocket>,
    control_peer_ip: IpAddr,
    server_addr: SocketAddr,
    secret: &SnellPsk,
    first: FirstSocksDatagram,
) -> Result<RelayStats>
where
    R: AsyncRead,
{
    let FirstSocksDatagram {
        peer: first_peer,
        target,
        payload_start,
        payload_len,
        datagram,
    } = first;

    let mut buffers = Box::new(SnellUdpStartupBuffers::new(datagram));
    let snell_tcp = connect_tcp(server_addr).await?;
    snell_tcp.set_nodelay(true)?;
    let (snell_reader_io, snell_writer_io) = snell_tcp.into_split();
    let snell = UdpClientStream::open_io(
        snell_reader_io,
        snell_writer_io,
        secret,
        ProtocolVersion::V5,
    )
    .await?;
    let (snell_reader, mut snell_writer) = snell.into_parts();
    let mut client_peer_by_target = ClientPeerByUdpTarget::new();
    client_peer_by_target.insert(target.clone(), first_peer);

    rewrite_socks_datagram_as_snell_request(
        &mut buffers.datagram,
        payload_start,
        payload_len,
        target.address_ref(),
        target.port(),
        &mut buffers.socks_header,
    )?;
    if buffers.datagram.len() > snell_writer.max_udp_application_payload_len() {
        return Err(Error::PayloadTooLarge);
    }
    snell_writer
        .write_payload_from_buffer(&mut buffers.datagram)
        .await?;

    let (activity, _last_activity) = RelayActivity::new();
    let driver = UdpRelayDriver::from_socks5_client_parts(
        snell_reader,
        snell_writer,
        control_reader,
        udp_socket,
        control_peer_ip,
        Socks5ClientUdpSeed {
            client_addr: Some(first_peer),
            client_peer_by_target,
            uploaded: payload_len as u64,
        },
        &activity,
    );
    tokio::pin!(driver);
    driver.await.map(UdpRelayStats::into_relay_stats)
}

/// QUIC Initial first datagram: run the lazy QUIC-proxy relay, encoding
/// snell-over-quic datagrams toward `server_addr` and bridging responses
/// back to the socks5 client.
fn relay_lazy_quic_proxy_packets<'a, R>(
    control_reader: Pin<&'a mut R>,
    udp_socket: &'a UdpSocket,
    quic_socket: &'a UdpSocket,
    server_addr: SocketAddr,
    control_peer_ip: IpAddr,
    secret: &'a SnellPsk,
    first: FirstSocksDatagram,
) -> Result<LazyQuicProxyRelayFuture<'a, R>>
where
    R: AsyncRead,
{
    LazyQuicProxyRelayFuture::new(
        control_reader,
        udp_socket,
        quic_socket,
        server_addr,
        control_peer_ip,
        secret,
        first,
    )
}

#[derive(Clone, Copy)]
enum LazyQuicSendSocket {
    SocksClient,
    QuicServer,
}

struct LazyQuicPendingSend {
    socket: LazyQuicSendSocket,
    batch: UdpSendBatch,
    uploaded: u64,
    downloaded: u64,
}

enum LazyQuicDatagramAction {
    Activity { uploaded: u64 },
    Send(LazyQuicPendingSend),
}

pin_project! {
    struct LazyQuicProxyRelayFuture<'a, R> {
        control_reader: Pin<&'a mut R>,
        udp_socket: &'a UdpSocket,
        quic_socket: &'a UdpSocket,
        server_addr: SocketAddr,
        control_peer_ip: IpAddr,
        secret: &'a SnellPsk,
        target: OwnedUdpTarget,
        client_addr: Option<SocketAddr>,
        uploaded: u64,
        downloaded: u64,
        quic_handshake_done: bool,
        control_buf: [u8; 128],
        buffers: Box<LazyQuicUdpBuffers>,
        pending_send: Option<LazyQuicPendingSend>,
        #[pin]
        idle: Sleep,
    }
}

impl LazyQuicPendingSend {
    fn to_quic_server(batch: UdpSendBatch, uploaded: u64) -> Self {
        Self {
            socket: LazyQuicSendSocket::QuicServer,
            batch,
            uploaded,
            downloaded: 0,
        }
    }

    fn to_socks_client(batch: UdpSendBatch, downloaded: u64) -> Self {
        Self {
            socket: LazyQuicSendSocket::SocksClient,
            batch,
            uploaded: 0,
            downloaded,
        }
    }
}

impl<'a, R> LazyQuicProxyRelayFuture<'a, R> {
    fn new(
        control_reader: Pin<&'a mut R>,
        udp_socket: &'a UdpSocket,
        quic_socket: &'a UdpSocket,
        server_addr: SocketAddr,
        control_peer_ip: IpAddr,
        secret: &'a SnellPsk,
        first: FirstSocksDatagram,
    ) -> Result<Self> {
        let FirstSocksDatagram {
            peer: first_peer,
            target,
            payload_start,
            payload_len,
            datagram,
        } = first;

        let mut buffers = Box::new(LazyQuicUdpBuffers::new(datagram));
        let first_payload = &buffers.first_datagram[payload_start..payload_start + payload_len];
        let quic_handshake_done = first_payload
            .first()
            .is_some_and(|first| is_quic_short_header(*first));
        encode_init_datagram(
            secret.as_bytes(),
            target.quic_init_host(&mut buffers.quic_host_scratch),
            target.port(),
            first_payload,
            &mut buffers.plaintext,
            &mut buffers.wire,
        )?;
        let batch = UdpSendBatch::single(
            take_bytes(&mut buffers.wire),
            server_addr,
            MAX_PACKET_SIZE + 512,
        );

        Ok(Self {
            control_reader,
            udp_socket,
            quic_socket,
            server_addr,
            control_peer_ip,
            secret,
            target,
            client_addr: Some(first_peer),
            uploaded: 0,
            downloaded: 0,
            quic_handshake_done,
            control_buf: [0; 128],
            buffers,
            pending_send: Some(LazyQuicPendingSend::to_quic_server(
                batch,
                payload_len as u64,
            )),
            idle: sleep(SOCKS5_UDP_ASSOCIATION_TIMEOUT),
        })
    }
}

impl<R> Future for LazyQuicProxyRelayFuture<'_, R>
where
    R: AsyncRead,
{
    type Output = Result<RelayStats>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        loop {
            if this.pending_send.is_some() {
                let (uploaded, downloaded) = {
                    let pending = this.pending_send.as_mut().expect("checked above");
                    let socket = match pending.socket {
                        LazyQuicSendSocket::SocksClient => *this.udp_socket,
                        LazyQuicSendSocket::QuicServer => *this.quic_socket,
                    };
                    ready!(pending.batch.poll_send(socket, cx))?;
                    (pending.uploaded, pending.downloaded)
                };
                *this.pending_send = None;
                *this.uploaded += uploaded;
                *this.downloaded += downloaded;
                this.idle
                    .as_mut()
                    .reset(Instant::now() + SOCKS5_UDP_ASSOCIATION_TIMEOUT);
                continue;
            }

            loop {
                let mut out = ReadBuf::new(this.control_buf);
                match this.control_reader.as_mut().poll_read(cx, &mut out) {
                    Poll::Ready(Ok(())) if out.filled().is_empty() => {
                        return Poll::Ready(Ok(RelayStats {
                            uploaded: *this.uploaded,
                            downloaded: *this.downloaded,
                        }));
                    }
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err.into())),
                    Poll::Pending => break,
                }
            }

            match this.buffers.socks_in.poll_recv_from(this.udp_socket, cx) {
                Poll::Ready(Ok(_)) => {
                    match handle_lazy_quic_socks_datagram(
                        this.buffers,
                        this.target,
                        this.client_addr,
                        this.quic_handshake_done,
                        *this.control_peer_ip,
                        *this.server_addr,
                        this.secret,
                    )? {
                        Some(LazyQuicDatagramAction::Activity { uploaded }) => {
                            *this.uploaded += uploaded;
                            this.idle
                                .as_mut()
                                .reset(Instant::now() + SOCKS5_UDP_ASSOCIATION_TIMEOUT);
                        }
                        Some(LazyQuicDatagramAction::Send(pending)) => {
                            *this.pending_send = Some(pending);
                        }
                        None => {}
                    }
                    continue;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {}
            }

            match this.buffers.quic_in.poll_recv_from(this.quic_socket, cx) {
                Poll::Ready(Ok(_)) => {
                    if let Some(pending) = handle_lazy_quic_response_datagram(
                        this.buffers,
                        this.target,
                        *this.client_addr,
                        *this.server_addr,
                    )? {
                        *this.pending_send = Some(pending);
                    }
                    continue;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {}
            }

            if this.idle.as_mut().poll(cx).is_ready() {
                tracing::debug!("snell socks5 udp association idle timed out");
                return Poll::Ready(Ok(RelayStats {
                    uploaded: *this.uploaded,
                    downloaded: *this.downloaded,
                }));
            }

            return Poll::Pending;
        }
    }
}

fn handle_lazy_quic_socks_datagram(
    buffers: &mut LazyQuicUdpBuffers,
    target: &mut OwnedUdpTarget,
    client_addr: &mut Option<SocketAddr>,
    quic_handshake_done: &mut bool,
    control_peer_ip: IpAddr,
    server_addr: SocketAddr,
    secret: &SnellPsk,
) -> Result<Option<LazyQuicDatagramAction>> {
    let Some(entry) = buffers.socks_in.get(0) else {
        return Ok(None);
    };
    if entry.is_oversized() {
        tracing::debug!("ignored oversized socks5 udp datagram");
        return Ok(None);
    }
    let peer = entry.peer();
    if !is_allowed_socks_udp_peer(control_peer_ip, peer) {
        tracing::debug!(%peer, %control_peer_ip, "ignored socks5 udp datagram from unexpected source ip");
        return Ok(None);
    }
    let packet = match parse_udp_packet(entry.payload()) {
        Ok(packet) => packet,
        Err(err) => {
            tracing::debug!(%err, "ignored invalid socks5 udp datagram");
            return Ok(None);
        }
    };
    *client_addr = Some(peer);
    let uploaded = packet.payload.len() as u64;
    let raw_quic_payload = packet.payload.first().copied().is_some_and(|first| {
        if !is_quic_looking(first) {
            return false;
        }
        if is_quic_short_header(first) {
            *quic_handshake_done = true;
            return true;
        }
        !(is_quic_initial_packet(first) && *quic_handshake_done)
    });

    if raw_quic_payload {
        target.update(packet.address, packet.port);
        let batch = UdpSendBatch::single(
            Bytes::copy_from_slice(packet.payload),
            server_addr,
            MAX_PACKET_SIZE + 512,
        );
        return Ok(Some(LazyQuicDatagramAction::Send(
            LazyQuicPendingSend::to_quic_server(batch, uploaded),
        )));
    }

    if !packet.payload.is_empty() {
        encode_init_datagram(
            secret.as_bytes(),
            quic_init_host(packet.address, &mut buffers.quic_host_scratch),
            packet.port,
            packet.payload,
            &mut buffers.plaintext,
            &mut buffers.wire,
        )?;
        target.update(packet.address, packet.port);
        let batch = UdpSendBatch::single(
            take_bytes(&mut buffers.wire),
            server_addr,
            MAX_PACKET_SIZE + 512,
        );
        return Ok(Some(LazyQuicDatagramAction::Send(
            LazyQuicPendingSend::to_quic_server(batch, uploaded),
        )));
    }

    target.update(packet.address, packet.port);
    Ok(Some(LazyQuicDatagramAction::Activity { uploaded }))
}

fn handle_lazy_quic_response_datagram(
    buffers: &mut LazyQuicUdpBuffers,
    target: &OwnedUdpTarget,
    client_addr: Option<SocketAddr>,
    server_addr: SocketAddr,
) -> Result<Option<LazyQuicPendingSend>> {
    let Some(entry) = buffers.quic_in.get(0) else {
        return Ok(None);
    };
    if entry.is_oversized() {
        tracing::debug!("ignored oversized quic proxy response");
        return Ok(None);
    }
    let peer = entry.peer();
    if peer != server_addr {
        tracing::debug!(%peer, server = %server_addr, "ignored quic proxy response from unexpected peer");
        return Ok(None);
    }
    let Some(peer) = client_addr else {
        return Ok(None);
    };

    buffers.socks_header.clear();
    write_udp_packet(
        &mut buffers.socks_header,
        target.address_ref(),
        target.port(),
        &[],
    )?;
    let batch = UdpSendBatch::parts(
        take_bytes(&mut buffers.socks_header),
        Bytes::copy_from_slice(entry.payload()),
        peer,
        MAX_QUIC_SOCKS_UDP_DATAGRAM,
    );
    Ok(Some(LazyQuicPendingSend::to_socks_client(
        batch,
        entry.payload_len() as u64,
    )))
}

fn take_bytes(buffer: &mut BytesMut) -> Bytes {
    buffer.split_to(buffer.len()).freeze()
}

fn quic_bind_addr(server_addr: SocketAddr) -> SocketAddr {
    let bind_ip = if server_addr.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    SocketAddr::new(bind_ip, 0)
}

fn rewrite_socks_datagram_as_snell_request(
    datagram: &mut BytesMut,
    payload_start: usize,
    payload_len: usize,
    address: AddressRef<'_>,
    port: u16,
    prefix: &mut BytesMut,
) -> Result<()> {
    prefix.clear();
    write_udp_request_prefix(prefix, address, port)?;
    let Some(prefix_start) = payload_start.checked_sub(prefix.len()) else {
        return Err(Error::InvalidSocksRequest);
    };

    datagram[prefix_start..payload_start].copy_from_slice(prefix);
    datagram.advance(prefix_start);
    datagram.truncate(prefix.len() + payload_len);
    Ok(())
}

async fn bind_socks5_udp_socket(control_addr: SocketAddr) -> Result<UdpSocket> {
    Ok(UdpSocket::bind(SocketAddr::new(control_addr.ip(), 0)).await?)
}

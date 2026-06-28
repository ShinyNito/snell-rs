use std::{
    cell::Cell,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    rc::Rc,
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use compio::{
    driver::BufferRef,
    io::{AsyncReadManaged, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, ToSocketAddrsAsync, UdpSocket},
    time,
};
use futures::future::{self, Either};

use crate::{
    keepalive::apply_tcp_keepalive,
    protocol::{
        ParseState,
        address::{Address, AddressRef},
        socks5::{self, Command, METHOD_NO_AUTH, Reply},
    },
    relay::tcp::driver::read_exact_managed,
    relay::udp::{
        DatagramReceiver, DatagramSender, DatagramTransport, ReceivedDatagram, UDP_ASSOCIATION_TTL,
        UdpRecvStream, recv_udp_packet, recv_udp_stream, send_udp_bytes_to,
    },
    timeout::{with_tcp_connect_timeout, with_tcp_timeout},
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Outbound {
    #[default]
    Direct,
    Socks5 {
        server: SocketAddr,
    },
}

impl crate::relay::tcp::transport::Outbound for Outbound {
    type Transport = TcpStream;

    async fn connect(&self, destination: &Address) -> io::Result<Self::Transport> {
        match self {
            Self::Direct => connect_direct(destination).await,
            Self::Socks5 { server } => connect_socks5(*server, destination).await,
        }
    }
}

impl crate::relay::udp::Outbound for Outbound {
    type Transport = UdpOutbound;

    async fn connect_udp(&self) -> io::Result<Self::Transport> {
        match self {
            Self::Direct => Ok(UdpOutbound::Direct(connect_direct_udp().await?)),
            Self::Socks5 { server } => Ok(UdpOutbound::Socks5(connect_socks5_udp(*server).await?)),
        }
    }
}

// ponytail: connection-level enum; boxing this would add allocation to shrink a cold value.
#[allow(clippy::large_enum_variant)]
pub(crate) enum UdpOutbound {
    Direct(DirectUdpOutbound),
    Socks5(Socks5UdpOutbound),
}

pub(crate) enum UdpOutboundSender {
    Direct(DirectUdpSender),
    Socks5(Socks5UdpSender),
}

// ponytail: keep concrete receive streams here instead of heap-indirecting the hot UDP path.
#[allow(clippy::large_enum_variant)]
pub(crate) enum UdpOutboundReceiver {
    Direct(DirectUdpReceiver),
    Socks5(Socks5UdpReceiver),
}

impl DatagramTransport for UdpOutbound {
    type Sender = UdpOutboundSender;
    type Receiver = UdpOutboundReceiver;

    fn split(self) -> (Self::Sender, Self::Receiver) {
        match self {
            Self::Direct(transport) => {
                let (sender, receiver) = transport.split();
                (
                    UdpOutboundSender::Direct(sender),
                    UdpOutboundReceiver::Direct(receiver),
                )
            }
            Self::Socks5(transport) => {
                let (sender, receiver) = transport.split();
                (
                    UdpOutboundSender::Socks5(sender),
                    UdpOutboundReceiver::Socks5(receiver),
                )
            }
        }
    }
}

impl DatagramSender for UdpOutboundSender {
    async fn send_to(&mut self, destination: Address, payload: Bytes) -> io::Result<usize> {
        match self {
            Self::Direct(sender) => sender.send_to(destination, payload).await,
            Self::Socks5(sender) => sender.send_to(destination, payload).await,
        }
    }
}

impl DatagramReceiver for UdpOutboundReceiver {
    async fn recv_from(&mut self) -> io::Result<ReceivedDatagram> {
        match self {
            Self::Direct(receiver) => receiver.recv_from().await,
            Self::Socks5(receiver) => receiver.recv_from().await,
        }
    }
}

async fn connect_direct(destination: &Address) -> io::Result<TcpStream> {
    let stream = with_tcp_connect_timeout(
        async {
            match destination {
                Address::Ip(addr) => TcpStream::connect(*addr).await,
                Address::Domain { host, port } => TcpStream::connect((host.clone(), *port)).await,
            }
        },
        "direct tcp connect",
    )
    .await
    .map_err(|error| {
        tracing::debug!(%destination, %error, "direct outbound dial failed");
        error
    })?;
    apply_tcp_keepalive(&stream)?;
    Ok(stream)
}

async fn connect_direct_udp() -> io::Result<DirectUdpOutbound> {
    let v4 = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await?;
    let v6 = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
        .await
        .ok();
    let v4_recv = recv_udp_stream(&v4)?;
    let v6_recv = v6.as_ref().map(recv_udp_stream).transpose()?;
    Ok(DirectUdpOutbound {
        v4,
        v6,
        v4_recv,
        v6_recv,
    })
}

async fn connect_socks5(server: SocketAddr, destination: &Address) -> io::Result<TcpStream> {
    let stream =
        with_tcp_connect_timeout(TcpStream::connect(server), "socks5 outbound tcp connect").await;
    let mut stream = match stream {
        Ok(stream) => stream,
        Err(error) => {
            tracing::debug!(server = %server, %destination, %error, "socks5 outbound dial failed");
            return Err(error);
        }
    };
    apply_tcp_keepalive(&stream)?;
    let destination = destination.clone();
    let log_destination = destination.clone();
    with_tcp_timeout(
        async move {
            let mut buf = [0u8; socks5::MAX_REQUEST_LEN];

            let n = socks5::encode_no_auth_greeting(&mut buf)?;
            write_all_bytes(&mut stream, &buf[..n]).await?;

            read_exact_into(&mut stream, &mut buf[..2]).await?;
            let selection = match socks5::method_selection_need(&buf[..2])? {
                ParseState::Done(selection) => selection,
                ParseState::Need(_) => unreachable!("method selection buffer is exactly 2 bytes"),
            };
            if selection.method != METHOD_NO_AUTH {
                return Err(io::Error::other("socks5 outbound no-auth rejected"));
            }

            let n = socks5::encode_request(&mut buf, Command::Connect, destination.as_view())?;
            write_all_bytes(&mut stream, &buf[..n]).await?;

            let reply = read_reply(&mut stream, &mut buf).await?;
            if reply != Reply::Succeeded {
                return Err(io::Error::other(format!(
                    "socks5 outbound connect failed: {reply:?}"
                )));
            }

            Ok(stream)
        },
        "socks5 outbound connect handshake",
    )
    .await
    .map_err(|error| {
        tracing::debug!(server = %server, destination = %log_destination, %error, "socks5 outbound handshake failed");
        error
    })
}

async fn connect_socks5_udp(server: SocketAddr) -> io::Result<Socks5UdpOutbound> {
    let mut control =
        with_tcp_connect_timeout(TcpStream::connect(server), "socks5 udp control tcp connect")
            .await?;
    apply_tcp_keepalive(&control)?;
    let socket = UdpSocket::bind(udp_bind_addr_for(server)).await?;
    let local_addr = socket.local_addr()?;
    let (control, relay) = with_tcp_timeout(
        async move {
            let mut buf = [0u8; socks5::MAX_REQUEST_LEN];

            let n = socks5::encode_no_auth_greeting(&mut buf)?;
            write_all_bytes(&mut control, &buf[..n]).await?;

            read_exact_into(&mut control, &mut buf[..2]).await?;
            let selection = match socks5::method_selection_need(&buf[..2])? {
                ParseState::Done(selection) => selection,
                ParseState::Need(_) => unreachable!("method selection buffer is exactly 2 bytes"),
            };
            if selection.method != METHOD_NO_AUTH {
                return Err(io::Error::other("socks5 outbound no-auth rejected"));
            }

            let n = socks5::encode_request(
                &mut buf,
                Command::UdpAssociate,
                AddressRef::Ip(local_addr),
            )?;
            write_all_bytes(&mut control, &buf[..n]).await?;

            let reply = read_reply_message(&mut control, &mut buf).await?;
            if reply.reply != Reply::Succeeded {
                return Err(io::Error::other(format!(
                    "socks5 outbound udp associate failed: {:?}",
                    reply.reply
                )));
            }

            let relay = socks5_udp_relay_addr(server, reply.bind).await?;
            Ok((control, relay))
        },
        "socks5 udp associate handshake",
    )
    .await?;
    let recv = recv_udp_stream(&socket)?;
    Ok(Socks5UdpOutbound {
        control: Rc::new(control),
        socket,
        relay,
        recv,
        last_activity: Rc::new(Cell::new(Instant::now())),
    })
}

async fn read_reply<R>(stream: &mut R, buf: &mut [u8]) -> io::Result<Reply>
where
    R: AsyncReadManaged<Buffer = BufferRef> + 'static,
{
    Ok(read_reply_message(stream, buf).await?.reply)
}

async fn read_reply_message<R>(stream: &mut R, buf: &mut [u8]) -> io::Result<socks5::ReplyMessage>
where
    R: AsyncReadManaged<Buffer = BufferRef> + 'static,
{
    let mut filled = 0;
    loop {
        match socks5::reply_need(&buf[..filled])? {
            ParseState::Done(reply) => return Ok(reply.into_owned()),
            ParseState::Need(total) => {
                if total > buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "socks5 reply too large",
                    ));
                }
                read_exact_into(stream, &mut buf[filled..total]).await?;
                filled = total;
            }
        }
    }
}

async fn read_exact_into<R>(reader: &mut R, dst: &mut [u8]) -> io::Result<()>
where
    R: AsyncReadManaged<Buffer = BufferRef> + 'static,
{
    read_exact_managed(reader, dst).await
}

async fn write_all_bytes<W>(writer: &mut W, bytes: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + 'static,
{
    let (result, _buf) = writer.write_all(bytes.to_vec()).await.into_parts();
    result
}

fn udp_bind_addr_for(server: SocketAddr) -> SocketAddr {
    if server.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    }
}

async fn socks5_udp_relay_addr(server: SocketAddr, bind: Address) -> io::Result<SocketAddr> {
    match bind {
        Address::Ip(addr) => {
            let ip = if addr.ip().is_unspecified() {
                server.ip()
            } else {
                addr.ip()
            };
            let port = if addr.port() == 0 {
                server.port()
            } else {
                addr.port()
            };
            Ok(SocketAddr::new(ip, port))
        }
        Address::Domain { host, port } => (host, port)
            .to_socket_addrs_async()
            .await?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "socks5 udp relay not found")),
    }
}

pub(crate) struct DirectUdpOutbound {
    v4: UdpSocket,
    v6: Option<UdpSocket>,
    v4_recv: UdpRecvStream,
    v6_recv: Option<UdpRecvStream>,
}

pub(crate) struct DirectUdpSender {
    v4: UdpSocket,
    v6: Option<UdpSocket>,
}

pub(crate) struct DirectUdpReceiver {
    v4_recv: UdpRecvStream,
    v6_recv: Option<UdpRecvStream>,
}

impl DirectUdpOutbound {
    fn split(self) -> (DirectUdpSender, DirectUdpReceiver) {
        (
            DirectUdpSender {
                v4: self.v4.clone(),
                v6: self.v6.clone(),
            },
            DirectUdpReceiver {
                v4_recv: self.v4_recv,
                v6_recv: self.v6_recv,
            },
        )
    }
}

impl DatagramSender for DirectUdpSender {
    async fn send_to(&mut self, destination: Address, payload: Bytes) -> io::Result<usize> {
        let addr = resolve_udp_destination(destination).await?;
        let len = payload.len();
        send_udp_bytes_to(self.socket_for(addr)?, addr, payload).await?;
        Ok(len)
    }
}

impl DatagramReceiver for DirectUdpReceiver {
    async fn recv_from(&mut self) -> io::Result<ReceivedDatagram> {
        let packet = if let Some(v6_recv) = &mut self.v6_recv {
            let v4_next = recv_udp_packet(&mut self.v4_recv);
            let v6_next = recv_udp_packet(v6_recv);
            futures::pin_mut!(v4_next, v6_next);
            match future::select(v4_next, v6_next).await {
                Either::Left((result, _)) | Either::Right((result, _)) => result?,
            }
        } else {
            recv_udp_packet(&mut self.v4_recv).await?
        };
        Ok(ReceivedDatagram::new(Address::Ip(packet.source()), packet))
    }
}

impl DirectUdpSender {
    fn socket_for(&self, destination: SocketAddr) -> io::Result<&UdpSocket> {
        if destination.is_ipv4() {
            Ok(&self.v4)
        } else {
            self.v6.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "ipv6 udp socket unavailable",
                )
            })
        }
    }
}

async fn resolve_udp_destination(destination: Address) -> io::Result<SocketAddr> {
    match destination {
        Address::Ip(addr) => Ok(addr),
        Address::Domain { host, port } => (host, port)
            .to_socket_addrs_async()
            .await?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "udp destination not found")),
    }
}

pub(crate) struct Socks5UdpOutbound {
    control: Rc<TcpStream>,
    socket: UdpSocket,
    relay: SocketAddr,
    recv: UdpRecvStream,
    last_activity: Rc<Cell<Instant>>,
}

pub(crate) struct Socks5UdpSender {
    _control: Rc<TcpStream>,
    socket: UdpSocket,
    relay: SocketAddr,
    last_activity: Rc<Cell<Instant>>,
}

pub(crate) struct Socks5UdpReceiver {
    _control: Rc<TcpStream>,
    relay: SocketAddr,
    recv: UdpRecvStream,
    last_activity: Rc<Cell<Instant>>,
}

impl Socks5UdpOutbound {
    fn split(self) -> (Socks5UdpSender, Socks5UdpReceiver) {
        (
            Socks5UdpSender {
                _control: self.control.clone(),
                socket: self.socket.clone(),
                relay: self.relay,
                last_activity: self.last_activity.clone(),
            },
            Socks5UdpReceiver {
                _control: self.control,
                relay: self.relay,
                recv: self.recv,
                last_activity: self.last_activity,
            },
        )
    }
}

impl DatagramSender for Socks5UdpSender {
    async fn send_to(&mut self, destination: Address, payload: Bytes) -> io::Result<usize> {
        let destination = destination.as_view();
        let header_len = socks5::udp_header_len(destination)?;
        let mut packet = BytesMut::zeroed(header_len + payload.len());
        socks5::encode_udp_header(&mut packet, 0, destination)?;
        packet[header_len..].copy_from_slice(&payload);
        let payload_len = payload.len();
        let timeout = remaining_udp_ttl(&self.last_activity)?;
        time::timeout(
            timeout,
            send_udp_bytes_to(&self.socket, self.relay, packet.freeze()),
        )
        .await
        .map_err(|_| socks5_udp_idle_timeout())??;
        self.last_activity.set(Instant::now());
        Ok(payload_len)
    }
}

impl DatagramReceiver for Socks5UdpReceiver {
    async fn recv_from(&mut self) -> io::Result<ReceivedDatagram> {
        loop {
            let timeout = remaining_udp_ttl(&self.last_activity)?;
            let packet = time::timeout(timeout, recv_udp_packet(&mut self.recv))
                .await
                .map_err(|_| socks5_udp_idle_timeout())??;
            if packet.source() != self.relay {
                continue;
            }
            let (destination, payload_offset) = {
                let Ok(parsed) = socks5::parse_udp_packet(packet.payload()) else {
                    continue;
                };
                if parsed.frag != 0 {
                    continue;
                }
                (parsed.destination.into_owned(), parsed.payload_offset)
            };
            self.last_activity.set(Instant::now());
            return ReceivedDatagram::with_payload_offset(destination, packet, payload_offset);
        }
    }
}

fn remaining_udp_ttl(last_activity: &Cell<Instant>) -> io::Result<Duration> {
    let elapsed = last_activity.get().elapsed();
    if elapsed >= UDP_ASSOCIATION_TTL {
        return Err(socks5_udp_idle_timeout());
    }
    Ok(UDP_ASSOCIATION_TTL - elapsed)
}

fn socks5_udp_idle_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "socks5 udp outbound idle timeout")
}

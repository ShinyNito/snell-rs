use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll, ready},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf},
    net::{TcpStream, UdpSocket, lookup_host},
    time::{Instant, Sleep},
};

use crate::{
    keepalive::apply_tcp_keepalive,
    protocol::{
        ParseState,
        address::{Address, AddressRef},
        socks5::{self, Command, METHOD_NO_AUTH, Reply},
    },
    relay::udp::UDP_ASSOCIATION_TTL,
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

pub(crate) enum UdpOutbound {
    Direct(DirectUdpOutbound),
    Socks5(Socks5UdpOutbound),
}

#[derive(Default)]
pub(crate) struct UdpOutboundSendState {
    direct: DirectUdpSendState,
    socks5: Socks5UdpSendState,
}

impl crate::relay::udp::DatagramTransport for UdpOutbound {
    type SendState = UdpOutboundSendState;

    fn poll_send_to(
        &mut self,
        cx: &mut Context<'_>,
        destination: &Address,
        payload: &[u8],
        state: &mut Self::SendState,
    ) -> Poll<io::Result<usize>> {
        match self {
            Self::Direct(transport) => {
                transport.poll_send_to(cx, destination, payload, &mut state.direct)
            }
            Self::Socks5(transport) => {
                transport.poll_send_to(cx, destination, payload, &mut state.socks5)
            }
        }
    }

    fn poll_recv_from(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, Address)>> {
        match self {
            Self::Direct(transport) => transport.poll_recv_from(cx, buf),
            Self::Socks5(transport) => transport.poll_recv_from(cx, buf),
        }
    }
}

async fn connect_direct(destination: &Address) -> io::Result<TcpStream> {
    let stream = with_tcp_connect_timeout(
        async {
            match destination {
                Address::Ip(addr) => TcpStream::connect(addr).await,
                Address::Domain { host, port } => TcpStream::connect((host.as_str(), *port)).await,
            }
        },
        "direct tcp connect",
    )
    .await?;
    apply_tcp_keepalive(&stream)?;
    Ok(stream)
}

async fn connect_direct_udp() -> io::Result<DirectUdpOutbound> {
    let v4 = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await?;
    let v6 = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
        .await
        .ok();
    Ok(DirectUdpOutbound { v4, v6 })
}

async fn connect_socks5(server: SocketAddr, destination: &Address) -> io::Result<TcpStream> {
    let stream =
        with_tcp_connect_timeout(TcpStream::connect(server), "socks5 outbound tcp connect").await?;
    apply_tcp_keepalive(&stream)?;
    let destination = destination.clone();
    with_tcp_timeout(
        async move {
            let mut stream = stream;
            let mut buf = [0u8; socks5::MAX_REQUEST_LEN];

            let n = socks5::encode_no_auth_greeting(&mut buf)?;
            stream.write_all(&buf[..n]).await?;

            stream.read_exact(&mut buf[..2]).await?;
            let selection = match socks5::method_selection_need(&buf[..2])? {
                ParseState::Done(selection) => selection,
                ParseState::Need(_) => unreachable!("method selection buffer is exactly 2 bytes"),
            };
            if selection.method != METHOD_NO_AUTH {
                return Err(io::Error::other("socks5 outbound no-auth rejected"));
            }

            let n = socks5::encode_request(&mut buf, Command::Connect, destination.as_view())?;
            stream.write_all(&buf[..n]).await?;

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
}

async fn connect_socks5_udp(server: SocketAddr) -> io::Result<Socks5UdpOutbound> {
    let control =
        with_tcp_connect_timeout(TcpStream::connect(server), "socks5 udp control tcp connect")
            .await?;
    apply_tcp_keepalive(&control)?;
    let socket = UdpSocket::bind(udp_bind_addr_for(server)).await?;
    let local_addr = socket.local_addr()?;
    let (control, relay) = with_tcp_timeout(
        async move {
            let mut control = control;
            let mut buf = [0u8; socks5::MAX_REQUEST_LEN];

            let n = socks5::encode_no_auth_greeting(&mut buf)?;
            control.write_all(&buf[..n]).await?;

            control.read_exact(&mut buf[..2]).await?;
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
            control.write_all(&buf[..n]).await?;

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
    Ok(Socks5UdpOutbound {
        _control: control,
        socket,
        relay,
        recv_buf: vec![0; crate::relay::udp::MAX_UDP_DATAGRAM_LEN],
        control_ttl: Box::pin(tokio::time::sleep(UDP_ASSOCIATION_TTL)),
    })
}

async fn read_reply<R>(stream: &mut R, buf: &mut [u8]) -> io::Result<Reply>
where
    R: AsyncRead + Unpin,
{
    Ok(read_reply_message(stream, buf).await?.reply)
}

async fn read_reply_message<R>(stream: &mut R, buf: &mut [u8]) -> io::Result<socks5::ReplyMessage>
where
    R: AsyncRead + Unpin,
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
                stream.read_exact(&mut buf[filled..total]).await?;
                filled = total;
            }
        }
    }
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
        Address::Domain { host, port } => lookup_host((host, port))
            .await?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "socks5 udp relay not found")),
    }
}

pub(crate) struct DirectUdpOutbound {
    v4: UdpSocket,
    v6: Option<UdpSocket>,
}

type ResolveFuture = Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>>;

#[derive(Default)]
enum DirectUdpSendState {
    #[default]
    Ready,
    Resolving(ResolveFuture),
    Sending(SocketAddr),
}

impl DirectUdpOutbound {
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        destination: &Address,
        payload: &[u8],
        state: &mut DirectUdpSendState,
    ) -> Poll<io::Result<usize>> {
        loop {
            match state {
                DirectUdpSendState::Ready => match destination {
                    Address::Ip(addr) => *state = DirectUdpSendState::Sending(*addr),
                    Address::Domain { host, port } => {
                        let host = host.clone();
                        let port = *port;
                        *state = DirectUdpSendState::Resolving(Box::pin(async move {
                            Ok(lookup_host((host, port)).await?.collect())
                        }));
                    }
                },
                DirectUdpSendState::Resolving(future) => {
                    let mut addrs = ready!(future.as_mut().poll(cx))?;
                    let addr = addrs.drain(..).next().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "udp destination not found")
                    })?;
                    *state = DirectUdpSendState::Sending(addr);
                }
                DirectUdpSendState::Sending(addr) => {
                    let socket = self.socket_for(*addr)?;
                    let n = ready!(socket.poll_send_to(cx, payload, *addr))?;
                    *state = DirectUdpSendState::Ready;
                    if n != payload.len() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "udp socket sent a partial datagram",
                        )));
                    }
                    return Poll::Ready(Ok(n));
                }
            }
        }
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, Address)>> {
        {
            let mut read = ReadBuf::new(buf);
            match self.v4.poll_recv_from(cx, &mut read) {
                Poll::Ready(Ok(source)) => {
                    return Poll::Ready(Ok((read.filled().len(), Address::Ip(source))));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }
        }

        if let Some(v6) = &self.v6 {
            let mut read = ReadBuf::new(buf);
            match v6.poll_recv_from(cx, &mut read) {
                Poll::Ready(Ok(source)) => {
                    return Poll::Ready(Ok((read.filled().len(), Address::Ip(source))));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }
        }

        Poll::Pending
    }

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

pub(crate) struct Socks5UdpOutbound {
    _control: TcpStream,
    socket: UdpSocket,
    relay: SocketAddr,
    recv_buf: Vec<u8>,
    control_ttl: Pin<Box<Sleep>>,
}

#[derive(Default)]
enum Socks5UdpSendState {
    #[default]
    Ready,
    Sending {
        packet: Vec<u8>,
        payload_len: usize,
    },
}

impl Socks5UdpOutbound {
    fn check_control_ttl(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.control_ttl.as_mut().poll(cx).is_ready() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "socks5 udp outbound idle timeout",
            ));
        }
        Ok(())
    }

    fn refresh_control_ttl(&mut self) {
        self.control_ttl
            .as_mut()
            .reset(Instant::now() + UDP_ASSOCIATION_TTL);
    }

    fn poll_send_to(
        &mut self,
        cx: &mut Context<'_>,
        destination: &Address,
        payload: &[u8],
        state: &mut Socks5UdpSendState,
    ) -> Poll<io::Result<usize>> {
        self.check_control_ttl(cx)?;
        loop {
            match state {
                Socks5UdpSendState::Ready => {
                    let destination = destination.as_view();
                    let header_len = socks5::udp_header_len(destination)?;
                    let mut packet = vec![0u8; header_len + payload.len()];
                    socks5::encode_udp_header(&mut packet, 0, destination)?;
                    packet[header_len..].copy_from_slice(payload);
                    *state = Socks5UdpSendState::Sending {
                        packet,
                        payload_len: payload.len(),
                    };
                }
                Socks5UdpSendState::Sending {
                    packet,
                    payload_len,
                } => {
                    let n = ready!(self.socket.poll_send_to(cx, packet, self.relay))?;
                    if n != packet.len() {
                        *state = Socks5UdpSendState::Ready;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "socks5 udp outbound sent a partial datagram",
                        )));
                    }
                    let payload_len = *payload_len;
                    *state = Socks5UdpSendState::Ready;
                    self.refresh_control_ttl();
                    return Poll::Ready(Ok(payload_len));
                }
            }
        }
    }

    fn poll_recv_from(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, Address)>> {
        self.check_control_ttl(cx)?;
        loop {
            let (n, source) = {
                let mut read = ReadBuf::new(&mut self.recv_buf);
                let source = ready!(self.socket.poll_recv_from(cx, &mut read))?;
                (read.filled().len(), source)
            };
            if source != self.relay {
                continue;
            }
            let Ok(packet) = socks5::parse_udp_packet(&self.recv_buf[..n]) else {
                continue;
            };
            if packet.frag != 0 {
                continue;
            }
            if packet.payload.len() > buf.len() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "socks5 udp outbound packet too large",
                )));
            }
            let payload_len = packet.payload.len();
            let destination = packet.destination.into_owned();
            buf[..payload_len].copy_from_slice(packet.payload);
            self.refresh_control_ttl();
            return Poll::Ready(Ok((payload_len, destination)));
        }
    }
}

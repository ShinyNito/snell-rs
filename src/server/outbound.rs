use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{Bytes, BytesMut};
use compio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, ToSocketAddrsAsync, UdpSocket},
    time,
};

use crate::{
    keepalive::apply_tcp_keepalive,
    protocol::{
        ParseState,
        address::{Address, AddressRef},
        socks5::{self, Command, METHOD_NO_AUTH, Reply},
    },
    relay::udp::{
        DatagramTransport, ReceivedDatagram, UDP_ASSOCIATION_TTL, UdpRecvState, UdpSendState,
        poll_udp_recv_from, poll_udp_send_bytes_to, poll_udp_send_to,
    },
    timeout::{with_tcp_connect_timeout, with_tcp_timeout},
};

type ResolveFuture = Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>>>>;
type TimerFuture = Pin<Box<dyn Future<Output = ()>>>;

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

impl DatagramTransport for UdpOutbound {
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

    fn poll_recv_from(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<ReceivedDatagram>> {
        match self {
            Self::Direct(transport) => transport.poll_recv_from(cx),
            Self::Socks5(transport) => transport.poll_recv_from(cx),
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
    Ok(DirectUdpOutbound {
        v4,
        v6,
        v4_recv_state: UdpRecvState::default(),
        v6_recv_state: UdpRecvState::default(),
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
    Ok(Socks5UdpOutbound {
        _control: control,
        socket,
        relay,
        recv_state: UdpRecvState::default(),
        control_ttl: ttl_timer(),
    })
}

async fn read_reply<R>(stream: &mut R, buf: &mut [u8]) -> io::Result<Reply>
where
    R: AsyncRead + 'static,
{
    Ok(read_reply_message(stream, buf).await?.reply)
}

async fn read_reply_message<R>(stream: &mut R, buf: &mut [u8]) -> io::Result<socks5::ReplyMessage>
where
    R: AsyncRead + 'static,
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
    R: AsyncRead + 'static,
{
    let (result, buf) = reader
        .read_exact(Vec::with_capacity(dst.len()))
        .await
        .into_parts();
    result?;
    dst.copy_from_slice(&buf);
    Ok(())
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
    v4_recv_state: UdpRecvState,
    v6_recv_state: UdpRecvState,
}

#[derive(Default)]
enum DirectUdpSendState {
    #[default]
    Ready,
    Resolving(ResolveFuture),
    Sending {
        addr: SocketAddr,
        state: UdpSendState,
    },
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
                    Address::Ip(addr) => {
                        *state = DirectUdpSendState::Sending {
                            addr: *addr,
                            state: UdpSendState::default(),
                        };
                    }
                    Address::Domain { host, port } => {
                        let host = host.clone();
                        let port = *port;
                        *state = DirectUdpSendState::Resolving(Box::pin(async move {
                            Ok((host, port).to_socket_addrs_async().await?.collect())
                        }));
                    }
                },
                DirectUdpSendState::Resolving(future) => {
                    let mut addrs = ready!(future.as_mut().poll(cx))?;
                    let addr = addrs.drain(..).next().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "udp destination not found")
                    })?;
                    *state = DirectUdpSendState::Sending {
                        addr,
                        state: UdpSendState::default(),
                    };
                }
                DirectUdpSendState::Sending { addr, state: send } => {
                    let payload_len = payload.len();
                    ready!(poll_udp_send_to(
                        self.socket_for(*addr)?,
                        cx,
                        *addr,
                        payload,
                        send,
                    ))?;
                    *state = DirectUdpSendState::Ready;
                    return Poll::Ready(Ok(payload_len));
                }
            }
        }
    }

    fn poll_recv_from(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<ReceivedDatagram>> {
        match poll_udp_recv_from(&self.v4, cx, &mut self.v4_recv_state) {
            Poll::Ready(Ok(packet)) => {
                return Poll::Ready(Ok(ReceivedDatagram::new(
                    Address::Ip(packet.source()),
                    packet,
                )));
            }
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => {}
        }

        if let Some(v6) = &self.v6 {
            match poll_udp_recv_from(v6, cx, &mut self.v6_recv_state) {
                Poll::Ready(Ok(packet)) => {
                    return Poll::Ready(Ok(ReceivedDatagram::new(
                        Address::Ip(packet.source()),
                        packet,
                    )));
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
    recv_state: UdpRecvState,
    control_ttl: TimerFuture,
}

#[derive(Default)]
enum Socks5UdpSendState {
    #[default]
    Ready,
    Sending {
        packet: Option<Bytes>,
        payload_len: usize,
        state: UdpSendState,
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
        self.control_ttl = ttl_timer();
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
                    let mut packet = BytesMut::zeroed(header_len + payload.len());
                    socks5::encode_udp_header(&mut packet, 0, destination)?;
                    packet[header_len..].copy_from_slice(payload);
                    *state = Socks5UdpSendState::Sending {
                        packet: Some(packet.freeze()),
                        payload_len: payload.len(),
                        state: UdpSendState::default(),
                    };
                }
                Socks5UdpSendState::Sending {
                    packet,
                    payload_len,
                    state: send_state,
                } => {
                    let payload_len = *payload_len;
                    ready!(poll_udp_send_bytes_to(
                        &self.socket,
                        cx,
                        self.relay,
                        packet,
                        send_state,
                    ))?;
                    *state = Socks5UdpSendState::Ready;
                    self.refresh_control_ttl();
                    return Poll::Ready(Ok(payload_len));
                }
            }
        }
    }

    fn poll_recv_from(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<ReceivedDatagram>> {
        self.check_control_ttl(cx)?;
        loop {
            let packet = ready!(poll_udp_recv_from(&self.socket, cx, &mut self.recv_state))?;
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
            self.refresh_control_ttl();
            return Poll::Ready(ReceivedDatagram::with_payload_offset(
                destination,
                packet,
                payload_offset,
            ));
        }
    }
}

fn ttl_timer() -> TimerFuture {
    Box::pin(time::sleep(UDP_ASSOCIATION_TTL))
}

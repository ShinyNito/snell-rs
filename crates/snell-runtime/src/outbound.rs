use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use snell_protocol::socks5::{self, Command, METHOD_NO_AUTH, Reply};
use snell_protocol::{
    Address, AddressRef, Error, MAX_UDP_PACKET_ADDR_LEN, ParseState, TCP_CONNECT_TIMEOUT_SECS,
    UDP_DATAGRAM_MAX,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::connect_tcp;
use crate::dns::DnsResolver;
use crate::error::SessionError;
use crate::platform::prepare_session_stream;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outbound {
    Direct,
    Socks5 { server: SocketAddr },
}

impl Outbound {
    pub async fn connect(self, destination: &Address) -> Result<TcpStream, SessionError> {
        match self {
            Self::Direct => connect_direct(destination).await,
            Self::Socks5 { server } => connect_socks5(server, destination).await,
        }
    }

    pub(crate) async fn open_udp(self, dns: &DnsResolver) -> Result<UdpFlow, SessionError> {
        match self {
            Self::Direct => UdpFlow::direct().await,
            Self::Socks5 { server } => UdpFlow::socks5(server, dns).await,
        }
    }
}

pub(crate) struct UdpRecv<'a> {
    pub addr: Address,
    pub payload: &'a [u8],
}

/// Per-association UDP buffers hold capacity only; datagrams are received
/// with `recv_buf_from` (uninit append) and sends are built with
/// `extend_from_slice`, so only bytes actually carried are ever dirtied.
pub(crate) enum UdpFlow {
    Direct {
        socket: UdpSocket,
        recv: Vec<u8>,
    },
    Socks5 {
        _control: TcpStream,
        socket: UdpSocket,
        relay: SocketAddr,
        send: Vec<u8>,
        recv: Vec<u8>,
    },
}

impl UdpFlow {
    async fn direct() -> Result<Self, SessionError> {
        let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await?;
        Ok(Self::Direct {
            socket,
            recv: Vec::with_capacity(UDP_DATAGRAM_MAX),
        })
    }

    async fn socks5(server: SocketAddr, dns: &DnsResolver) -> Result<Self, SessionError> {
        let mut stream = connect_tcp(server).await?;
        let bind = socks5_udp_associate(&mut stream, dns).await?;
        let relay = rewrite_unspecified(bind, server);
        let local = if relay.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        };
        let socket = UdpSocket::bind(local).await?;
        Ok(Self::Socks5 {
            _control: stream,
            socket,
            relay,
            send: Vec::with_capacity(UDP_DATAGRAM_MAX),
            recv: Vec::with_capacity(UDP_DATAGRAM_MAX),
        })
    }

    pub(crate) async fn send(
        &mut self,
        dest: AddressRef<'_>,
        payload: &[u8],
        dns: &DnsResolver,
    ) -> Result<(), SessionError> {
        match self {
            Self::Direct { socket, .. } => {
                let addr = match dest {
                    AddressRef::Ip(addr) => addr,
                    AddressRef::Domain { host, port } => dns.resolve(host, port).await?,
                };
                socket.send_to(payload, addr).await?;
                Ok(())
            }
            Self::Socks5 {
                socket,
                relay,
                send,
                ..
            } => {
                let mut hdr = [0u8; 3 + MAX_UDP_PACKET_ADDR_LEN];
                let hdr_len = socks5::encode_udp_header(&mut hdr, 0, dest)?;
                if hdr_len.saturating_add(payload.len()) > UDP_DATAGRAM_MAX {
                    return Err(Error::PayloadTooLarge.into());
                }
                send.clear();
                send.extend_from_slice(&hdr[..hdr_len]);
                send.extend_from_slice(payload);
                socket.send_to(send, *relay).await?;
                Ok(())
            }
        }
    }

    pub(crate) async fn recv(
        &mut self,
        frag_dropped: &AtomicU64,
        invalid: &AtomicU64,
    ) -> Result<UdpRecv<'_>, SessionError> {
        match self {
            Self::Direct { socket, recv } => {
                recv.clear();
                let (_, from) = socket.recv_buf_from(recv).await?;
                Ok(UdpRecv {
                    addr: Address::Ip(from),
                    payload: recv.as_slice(),
                })
            }
            Self::Socks5 { socket, recv, .. } => loop {
                recv.clear();
                socket.recv_buf_from(recv).await?;
                let packet = match socks5::parse_udp_packet(recv) {
                    Ok(packet) => packet,
                    Err(_) => {
                        invalid.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                if packet.frag != 0 {
                    frag_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let header_len = packet.header_len;
                let addr = packet.destination.into_owned();
                return Ok(UdpRecv {
                    addr,
                    payload: &recv[header_len..],
                });
            },
        }
    }
}

fn rewrite_unspecified(bind: SocketAddr, server: SocketAddr) -> SocketAddr {
    if match bind.ip() {
        IpAddr::V4(ip) => ip.is_unspecified(),
        IpAddr::V6(ip) => ip.is_unspecified(),
    } {
        SocketAddr::new(server.ip(), bind.port())
    } else {
        bind
    }
}

async fn socks5_udp_associate(
    stream: &mut TcpStream,
    dns: &DnsResolver,
) -> Result<SocketAddr, SessionError> {
    let mut buf = [0u8; 3 + 1 + 1 + 255 + 2];
    let n = socks5::encode_greeting(&mut buf, &[METHOD_NO_AUTH])?;
    stream.write_all(&buf[..n]).await?;
    stream.read_exact(&mut buf[..2]).await?;
    match socks5::method_selection_need(&buf[..2])? {
        ParseState::Need(_) => {
            return Err(SessionError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "socks5 method selection truncated",
            )));
        }
        ParseState::Done(method) if method == METHOD_NO_AUTH => {}
        ParseState::Done(_) => return Err(SessionError::NoAcceptableMethod),
    }

    let dest = AddressRef::Ip(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
    let n = socks5::encode_request(&mut buf, Command::UdpAssociate, dest)?;
    stream.write_all(&buf[..n]).await?;

    let mut filled = 0;
    loop {
        match socks5::reply_need(&buf[..filled])? {
            ParseState::Need(total) => {
                if total > buf.len() {
                    return Err(SessionError::Protocol(snell_protocol::Error::Malformed(
                        "oversized socks5 udp associate reply",
                    )));
                }
                stream.read_exact(&mut buf[filled..total]).await?;
                filled = total;
            }
            ParseState::Done(reply) => {
                if reply.reply != Reply::Succeeded {
                    return Err(SessionError::Io(std::io::Error::other(format!(
                        "socks5 outbound udp associate failed: {:?}",
                        reply.reply
                    ))));
                }
                return match reply.bind {
                    AddressRef::Ip(addr) => Ok(addr),
                    AddressRef::Domain { host, port } => dns.resolve(host, port).await,
                };
            }
        }
    }
}

async fn connect_direct(destination: &Address) -> Result<TcpStream, SessionError> {
    match destination {
        Address::Ip(addr) => connect_tcp(*addr).await,
        Address::Domain { host, port } => {
            let connect = TcpStream::connect((host.as_str(), *port));
            match timeout(Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS), connect).await {
                Ok(Ok(stream)) => {
                    prepare_session_stream(&stream)?;
                    Ok(stream)
                }
                Ok(Err(error)) => Err(error.into()),
                Err(_) => Err(SessionError::ConnectTimeout),
            }
        }
    }
}

async fn connect_socks5(
    server: SocketAddr,
    destination: &Address,
) -> Result<TcpStream, SessionError> {
    let stream = connect_tcp(server).await?;
    socks5_connect_handshake(stream, destination.as_view()).await
}

async fn socks5_connect_handshake(
    mut stream: TcpStream,
    destination: AddressRef<'_>,
) -> Result<TcpStream, SessionError> {
    let mut buf = [0u8; 3 + 1 + 1 + 255 + 2];
    let n = socks5::encode_greeting(&mut buf, &[METHOD_NO_AUTH])?;
    stream.write_all(&buf[..n]).await?;
    stream.read_exact(&mut buf[..2]).await?;
    match socks5::method_selection_need(&buf[..2])? {
        ParseState::Need(_) => {
            return Err(SessionError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "socks5 method selection truncated",
            )));
        }
        ParseState::Done(method) if method == METHOD_NO_AUTH => {}
        ParseState::Done(_) => return Err(SessionError::NoAcceptableMethod),
    }

    let n = socks5::encode_request(&mut buf, Command::Connect, destination)?;
    stream.write_all(&buf[..n]).await?;

    let mut filled = 0;
    loop {
        match socks5::reply_need(&buf[..filled])? {
            ParseState::Need(total) => {
                stream.read_exact(&mut buf[filled..total]).await?;
                filled = total;
            }
            ParseState::Done(reply) => {
                if reply.reply != Reply::Succeeded {
                    return Err(SessionError::Io(std::io::Error::other(format!(
                        "socks5 outbound connect failed: {:?}",
                        reply.reply
                    ))));
                }
                return Ok(stream);
            }
        }
    }
}

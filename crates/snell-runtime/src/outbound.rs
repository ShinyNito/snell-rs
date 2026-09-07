use crate::buffer::{BufferPool, PooledBuffer};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
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

    pub(crate) async fn open_udp(
        self,
        dns: &DnsResolver,
        buffers: &Arc<BufferPool>,
    ) -> Result<UdpFlow, SessionError> {
        match self {
            Self::Direct => UdpFlow::direct(buffers).await,
            Self::Socks5 { server } => UdpFlow::socks5(server, dns, buffers).await,
        }
    }
}

pub(crate) struct UdpRecv {
    pub addr: Address,
    buffer: PooledBuffer,
    header_len: usize,
}

impl UdpRecv {
    pub(crate) fn payload(&self) -> &[u8] {
        &self.buffer.filled()[self.header_len..]
    }
}

/// Sockets and routing state only; every datagram owns its processing lease.
pub(crate) enum UdpFlow {
    Direct {
        socket: UdpSocket,
        buffers: Arc<BufferPool>,
    },
    Socks5 {
        _control: TcpStream,
        socket: UdpSocket,
        relay: SocketAddr,
        buffers: Arc<BufferPool>,
    },
}

impl UdpFlow {
    async fn direct(buffers: &Arc<BufferPool>) -> Result<Self, SessionError> {
        let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await?;
        Ok(Self::Direct {
            socket,
            buffers: Arc::clone(buffers),
        })
    }

    async fn socks5(
        server: SocketAddr,
        dns: &DnsResolver,
        buffers: &Arc<BufferPool>,
    ) -> Result<Self, SessionError> {
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
            buffers: Arc::clone(buffers),
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
                buffers,
                ..
            } => {
                let mut send = buffers.get(UDP_DATAGRAM_MAX);
                let mut hdr = [0u8; 3 + MAX_UDP_PACKET_ADDR_LEN];
                let hdr_len = socks5::encode_udp_header(&mut hdr, 0, dest)?;
                if hdr_len.saturating_add(payload.len()) > UDP_DATAGRAM_MAX {
                    return Err(Error::PayloadTooLarge.into());
                }
                send.extend(&hdr[..hdr_len])?;
                send.extend(payload)?;
                socket.send_to(send.filled(), *relay).await?;
                Ok(())
            }
        }
    }

    pub(crate) async fn recv(
        &mut self,
        frag_dropped: &AtomicU64,
        invalid: &AtomicU64,
    ) -> Result<UdpRecv, SessionError> {
        match self {
            Self::Direct { socket, buffers } => {
                let (buffer, from) = crate::bufio::recv_datagram(socket, buffers).await?;
                Ok(UdpRecv {
                    addr: Address::Ip(from),
                    buffer,
                    header_len: 0,
                })
            }
            Self::Socks5 {
                socket, buffers, ..
            } => loop {
                let (buffer, _) = crate::bufio::recv_datagram(socket, buffers).await?;
                let packet = match socks5::parse_udp_packet(buffer.filled()) {
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
                    buffer,
                    header_len,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::{Context, Waker};

    #[tokio::test]
    async fn received_datagram_owns_its_lease_and_idle_flow_holds_none() {
        let buffers = Arc::new(BufferPool::default());
        let mut flow = UdpFlow::direct(&buffers).await.unwrap();
        let UdpFlow::Direct { socket, .. } = &flow else {
            unreachable!()
        };
        let destination =
            SocketAddr::from((Ipv4Addr::LOCALHOST, socket.local_addr().unwrap().port()));
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let frag = AtomicU64::new(0);
        let invalid = AtomicU64::new(0);
        for payload in [b"first".as_slice(), b"second"] {
            {
                let recv = flow.recv(&frag, &invalid);
                tokio::pin!(recv);
                assert!(
                    recv.as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
                assert_eq!(buffers.leased_bytes(), 0);
            }
            peer.send_to(payload, destination).await.unwrap();
            let packet = flow.recv(&frag, &invalid).await.unwrap();
            assert_eq!(packet.payload(), payload);
            assert!(buffers.leased_bytes() > 0);
            drop(packet);
            assert_eq!(buffers.leased_bytes(), 0);
        }
    }
}

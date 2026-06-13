use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{Error, Result};
use crate::net::connect::connect_tcp;
use crate::protocol::socks5::{
    COMMAND_CONNECT, COMMAND_UDP_ASSOCIATE, METHOD_NO_ACCEPTABLE, METHOD_NO_AUTH, SOCKS_VERSION,
    SocksAddress, SocksAddressContext, SocksBoundAddr, SocksReply, read_address_port,
    write_address,
};
use crate::protocol::udp::AddressRef;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Socks5Command {
    Connect,
    UdpAssociate,
}

impl Socks5Command {
    fn code(self) -> u8 {
        match self {
            Self::Connect => COMMAND_CONNECT,
            Self::UdpAssociate => COMMAND_UDP_ASSOCIATE,
        }
    }
}

#[must_use = "dropping this value closes the SOCKS5 UDP association control connection"]
pub struct Socks5UdpAssociation {
    pub control: TcpStream,
    pub(crate) relay_endpoint: Socks5UdpRelayEndpoint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Socks5UdpRelayEndpoint {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

pub async fn connect_tcp_via_socks5(
    proxy_addr: SocketAddr,
    address: AddressRef<'_>,
    port: u16,
) -> Result<TcpStream> {
    let mut stream = connect_tcp(proxy_addr).await?;
    stream.set_nodelay(true)?;
    request_socks5_command(&mut stream, Socks5Command::Connect, address, port).await?;
    Ok(stream)
}

pub async fn open_udp_associate_via_socks5(proxy_addr: SocketAddr) -> Result<Socks5UdpAssociation> {
    let mut control = connect_tcp(proxy_addr).await?;
    control.set_nodelay(true)?;
    let bind_ip = if proxy_addr.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    let bound = request_socks5_command(
        &mut control,
        Socks5Command::UdpAssociate,
        AddressRef::Ip(bind_ip),
        0,
    )
    .await?;
    Ok(Socks5UdpAssociation {
        control,
        relay_endpoint: udp_relay_endpoint_from_bound(proxy_addr, bound),
    })
}

async fn request_socks5_command<S>(
    stream: &mut S,
    command: Socks5Command,
    address: AddressRef<'_>,
    port: u16,
) -> Result<SocksBoundAddr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_no_auth_greeting(stream).await?;
    read_method_selection(stream).await?;
    write_command_request(stream, command, address, port).await?;
    read_command_reply(stream).await
}

async fn write_no_auth_greeting<S>(stream: &mut S) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[SOCKS_VERSION, 1, METHOD_NO_AUTH])
        .await?;
    Ok(())
}

async fn read_method_selection<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut selection = [0; 2];
    stream.read_exact(&mut selection).await?;
    if selection[0] != SOCKS_VERSION {
        return Err(Error::InvalidSocksResponse);
    }
    match selection[1] {
        METHOD_NO_AUTH => Ok(()),
        METHOD_NO_ACCEPTABLE => Err(Error::Socks5NoAcceptableAuthMethod),
        method => Err(Error::UnsupportedSocks5AuthMethod(method)),
    }
}

async fn write_command_request<S>(
    stream: &mut S,
    command: Socks5Command,
    address: AddressRef<'_>,
    port: u16,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut out = Vec::with_capacity(command_request_capacity(address)?);
    out.extend_from_slice(&[SOCKS_VERSION, command.code(), 0]);
    write_address(&mut out, address, port)?;
    stream.write_all(&out).await?;
    Ok(())
}

fn command_request_capacity(address: AddressRef<'_>) -> Result<usize> {
    const PREFIX_LEN: usize = 3;
    const ATYP_LEN: usize = 1;
    const PORT_LEN: usize = 2;

    let addr_len = match address {
        AddressRef::Ip(IpAddr::V4(_)) => 4,
        AddressRef::Ip(IpAddr::V6(_)) => 16,
        AddressRef::Domain(host) => {
            if host.is_empty() {
                return Err(Error::EmptyHost);
            }
            if host.len() > u8::MAX as usize {
                return Err(Error::HostTooLong);
            }
            1 + host.len()
        }
    };

    Ok(PREFIX_LEN + ATYP_LEN + addr_len + PORT_LEN)
}

async fn read_command_reply<S>(stream: &mut S) -> Result<SocksBoundAddr>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION || header[2] != 0 {
        return Err(Error::InvalidSocksResponse);
    }
    let (address, port) =
        read_address_port(stream, header[3], SocksAddressContext::Response).await?;
    let bound = SocksBoundAddr { address, port };
    if header[1] != SocksReply::Succeeded as u8 {
        return Err(Error::Socks5Reply(header[1]));
    }
    Ok(bound)
}

fn udp_relay_endpoint_from_bound(
    proxy_addr: SocketAddr,
    bound: SocksBoundAddr,
) -> Socks5UdpRelayEndpoint {
    match bound.address {
        SocksAddress::Ip(ip) => {
            let ip = if ip.is_unspecified() {
                proxy_addr.ip()
            } else {
                ip
            };
            Socks5UdpRelayEndpoint::Ip(SocketAddr::new(ip, bound.port))
        }
        SocksAddress::Domain(host) => Socks5UdpRelayEndpoint::Domain {
            host,
            port: bound.port,
        },
    }
}

#[cfg(test)]
mod tests;

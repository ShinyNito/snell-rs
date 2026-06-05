use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, lookup_host};

use crate::error::{Error, Result};
use crate::parse::{read_array, read_be_u16, take_bytes};
use crate::protocol::socks5::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, COMMAND_CONNECT, COMMAND_UDP_ASSOCIATE, METHOD_NO_AUTH,
    SOCKS_VERSION, SocksAddress, SocksBoundAddr, SocksReply, write_address,
};
use crate::protocol::udp::AddressRef;
use crate::service::runtime::net::connect_tcp;

pub struct Socks5UdpAssociation {
    pub control: TcpStream,
    pub relay_addr: SocketAddr,
}

pub async fn connect_tcp_via_socks5(
    proxy_addr: SocketAddr,
    address: AddressRef<'_>,
    port: u16,
) -> Result<TcpStream> {
    let mut stream = connect_tcp(proxy_addr).await?;
    stream.set_nodelay(true)?;
    request_socks5_command(&mut stream, COMMAND_CONNECT, address, port).await?;
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
        COMMAND_UDP_ASSOCIATE,
        AddressRef::Ip(bind_ip),
        0,
    )
    .await?;
    let relay_addr = resolve_udp_relay_addr(proxy_addr, bound).await?;
    Ok(Socks5UdpAssociation {
        control,
        relay_addr,
    })
}

pub async fn request_socks5_command<S>(
    stream: &mut S,
    command: u8,
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
    if selection != [SOCKS_VERSION, METHOD_NO_AUTH] {
        return Err(Error::InvalidSocksRequest);
    }
    Ok(())
}

async fn write_command_request<S>(
    stream: &mut S,
    command: u8,
    address: AddressRef<'_>,
    port: u16,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut out = Vec::with_capacity(22);
    out.put_u8(SOCKS_VERSION);
    out.put_u8(command);
    out.put_u8(0);
    write_address(&mut out, address, port)?;
    stream.write_all(&out).await?;
    Ok(())
}

async fn read_command_reply<S>(stream: &mut S) -> Result<SocksBoundAddr>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION || header[2] != 0 {
        return Err(Error::InvalidSocksRequest);
    }
    let (address, port) = read_address_port(stream, header[3]).await?;
    let bound = SocksBoundAddr { address, port };
    if header[1] != SocksReply::Succeeded as u8 {
        return Err(Error::Socks5Reply(header[1]));
    }
    Ok(bound)
}

async fn read_address_port<S>(stream: &mut S, atyp: u8) -> Result<(SocksAddress, u16)>
where
    S: AsyncRead + Unpin,
{
    match atyp {
        ATYP_IPV4 => {
            let mut raw = [0; 6];
            stream.read_exact(&mut raw).await?;
            let mut input = &raw[..];
            let octets = read_array::<4>(&mut input, Error::InvalidSocksRequest)?;
            let port = read_be_u16(&mut input, Error::InvalidSocksRequest)?;
            Ok((SocksAddress::Ip(IpAddr::V4(Ipv4Addr::from(octets))), port))
        }
        ATYP_DOMAIN => {
            let mut len = [0; 1];
            stream.read_exact(&mut len).await?;
            let host_len = len[0] as usize;
            if host_len == 0 {
                return Err(Error::EmptyHost);
            }

            let mut raw = [0; u8::MAX as usize + 2];
            stream.read_exact(&mut raw[..host_len + 2]).await?;
            let mut input = &raw[..host_len + 2];
            let host = take_bytes(&mut input, host_len, Error::InvalidSocksRequest)?;
            let port = read_be_u16(&mut input, Error::InvalidSocksRequest)?;
            Ok((
                SocksAddress::Domain(std::str::from_utf8(host)?.to_owned()),
                port,
            ))
        }
        ATYP_IPV6 => {
            let mut raw = [0; 18];
            stream.read_exact(&mut raw).await?;
            let mut input = &raw[..];
            let octets = read_array::<16>(&mut input, Error::InvalidSocksRequest)?;
            let port = read_be_u16(&mut input, Error::InvalidSocksRequest)?;
            Ok((SocksAddress::Ip(IpAddr::V6(Ipv6Addr::from(octets))), port))
        }
        _ => Err(Error::InvalidSocksRequest),
    }
}

async fn resolve_udp_relay_addr(
    proxy_addr: SocketAddr,
    bound: SocksBoundAddr,
) -> Result<SocketAddr> {
    match bound.address {
        SocksAddress::Ip(ip) => {
            let ip = if ip.is_unspecified() {
                proxy_addr.ip()
            } else {
                ip
            };
            Ok(SocketAddr::new(ip, bound.port))
        }
        SocksAddress::Domain(host) => {
            let addrs = lookup_host((host.as_str(), bound.port)).await?;
            select_udp_relay_addr(proxy_addr, addrs)
        }
    }
}

fn select_udp_relay_addr(
    proxy_addr: SocketAddr,
    addrs: impl IntoIterator<Item = SocketAddr>,
) -> Result<SocketAddr> {
    let mut first = None;
    for addr in addrs {
        if first.is_none() {
            first = Some(addr);
        }
        if addr.is_ipv4() == proxy_addr.is_ipv4() {
            return Ok(addr);
        }
    }
    first.ok_or(Error::InvalidAddressType)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::{request_socks5_command, resolve_udp_relay_addr, select_udp_relay_addr};
    use crate::error::Error;
    use crate::protocol::socks5::{COMMAND_CONNECT, SocksAddress, SocksBoundAddr};
    use crate::protocol::udp::AddressRef;

    #[tokio::test]
    async fn client_command_writes_no_auth_connect_request() {
        let (mut client, mut server) = duplex(128);

        let client_task = async {
            let bound = request_socks5_command(
                &mut client,
                COMMAND_CONNECT,
                AddressRef::Domain("example.com"),
                443,
            )
            .await
            .unwrap();
            assert_eq!(
                bound,
                SocksBoundAddr {
                    address: SocksAddress::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                    port: 0
                }
            );
        };

        let server_task = async {
            let mut greeting = [0; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            server.write_all(&[5, 0]).await.unwrap();

            let mut request = [0; 18];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(
                request,
                [
                    5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
                    b'm', 0x01, 0xbb
                ]
            );
            server
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        };

        let ((), ()) = tokio::join!(client_task, server_task);
    }

    #[tokio::test]
    async fn client_command_surfaces_socks5_reply_error() {
        let (mut client, mut server) = duplex(128);

        let client_task = async {
            assert!(matches!(
                request_socks5_command(
                    &mut client,
                    COMMAND_CONNECT,
                    AddressRef::Domain("example.com"),
                    443,
                )
                .await,
                Err(Error::Socks5Reply(5))
            ));
            let mut marker = [0; 1];
            client.read_exact(&mut marker).await.unwrap();
            assert_eq!(marker, [0xaa]);
        };

        let server_task = async {
            let mut greeting = [0; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 18];
            server.read_exact(&mut request).await.unwrap();
            server
                .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            server.write_all(&[0xaa]).await.unwrap();
        };

        let ((), ()) = tokio::join!(client_task, server_task);
    }

    #[tokio::test]
    async fn udp_associate_uses_proxy_ip_for_unspecified_bound_addr() {
        let proxy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)), 1080);
        let relay_addr = resolve_udp_relay_addr(
            proxy_addr,
            SocksBoundAddr {
                address: SocksAddress::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                port: 5353,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            relay_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)), 5353)
        );
    }

    #[test]
    fn udp_relay_addr_prefers_proxy_address_family_for_domains() {
        let proxy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080);
        let v6 = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 5353);
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 5353);

        assert_eq!(select_udp_relay_addr(proxy_addr, [v6, v4]).unwrap(), v4);
    }
}

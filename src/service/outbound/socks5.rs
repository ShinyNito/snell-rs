use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{Error, Result};
use crate::protocol::socks5::{
    COMMAND_CONNECT, COMMAND_UDP_ASSOCIATE, METHOD_NO_ACCEPTABLE, METHOD_NO_AUTH, SOCKS_VERSION,
    SocksAddress, SocksAddressContext, SocksBoundAddr, SocksReply, read_address_port,
    write_address,
};
use crate::protocol::udp::AddressRef;
use crate::service::runtime::net::connect_tcp;

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
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::{
        Socks5Command, Socks5UdpRelayEndpoint, command_request_capacity, request_socks5_command,
        udp_relay_endpoint_from_bound,
    };
    use crate::error::Error;
    use crate::protocol::socks5::{SocksAddress, SocksBoundAddr};
    use crate::protocol::udp::AddressRef;

    async fn run_method_selection_error(selection: [u8; 2]) -> Error {
        let (mut client, mut server) = duplex(128);

        let client_task = async {
            request_socks5_command(
                &mut client,
                Socks5Command::Connect,
                AddressRef::Domain("example.com"),
                443,
            )
            .await
            .unwrap_err()
        };

        let server_task = async {
            let mut greeting = [0; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            server.write_all(&selection).await.unwrap();
        };

        let (err, ()) = tokio::join!(client_task, server_task);
        err
    }

    async fn run_command_reply_error(reply: &'static [u8]) -> Error {
        let (mut client, mut server) = duplex(128);

        let client_task = async {
            request_socks5_command(
                &mut client,
                Socks5Command::Connect,
                AddressRef::Domain("example.com"),
                443,
            )
            .await
            .unwrap_err()
        };

        let server_task = async {
            let mut greeting = [0; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server.write_all(&[5, 0]).await.unwrap();

            let mut request = [0; 18];
            server.read_exact(&mut request).await.unwrap();
            server.write_all(reply).await.unwrap();
        };

        let (err, ()) = tokio::join!(client_task, server_task);
        err
    }

    #[test]
    fn command_request_capacity_matches_address_shape() {
        assert_eq!(
            command_request_capacity(AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))).unwrap(),
            10
        );
        assert_eq!(
            command_request_capacity(AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))).unwrap(),
            22
        );

        let max_host = "a".repeat(u8::MAX as usize);
        assert_eq!(
            command_request_capacity(AddressRef::Domain(&max_host)).unwrap(),
            262
        );

        std::assert_matches!(
            command_request_capacity(AddressRef::Domain("")),
            Err(Error::EmptyHost)
        );
        let too_long_host = "a".repeat(u8::MAX as usize + 1);
        std::assert_matches!(
            command_request_capacity(AddressRef::Domain(&too_long_host)),
            Err(Error::HostTooLong)
        );
    }

    #[tokio::test]
    async fn client_command_writes_no_auth_connect_request() {
        let (mut client, mut server) = duplex(128);

        let client_task = async {
            let bound = request_socks5_command(
                &mut client,
                Socks5Command::Connect,
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
    async fn client_command_classifies_method_selection_errors() {
        let err = run_method_selection_error([4, 0]).await;
        std::assert_matches!(err, Error::InvalidSocksResponse);

        let err = run_method_selection_error([5, 0xff]).await;
        std::assert_matches!(err, Error::Socks5NoAcceptableAuthMethod);

        let err = run_method_selection_error([5, 2]).await;
        std::assert_matches!(err, Error::UnsupportedSocks5AuthMethod(2));
    }

    #[tokio::test]
    async fn client_command_classifies_invalid_command_replies() {
        let err = run_command_reply_error(&[4, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        std::assert_matches!(err, Error::InvalidSocksResponse);

        let err = run_command_reply_error(&[5, 0, 1, 1, 0, 0, 0, 0, 0, 0]).await;
        std::assert_matches!(err, Error::InvalidSocksResponse);

        let err = run_command_reply_error(&[5, 0, 0, 9]).await;
        std::assert_matches!(err, Error::InvalidSocksResponse);

        let err = run_command_reply_error(&[5, 0, 0, 3, 0]).await;
        std::assert_matches!(err, Error::InvalidSocksResponse);
    }

    #[tokio::test]
    async fn client_command_surfaces_socks5_reply_error() {
        let (mut client, mut server) = duplex(128);

        let client_task = async {
            std::assert_matches!(
                request_socks5_command(
                    &mut client,
                    Socks5Command::Connect,
                    AddressRef::Domain("example.com"),
                    443,
                )
                .await,
                Err(Error::Socks5Reply(5))
            );
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
        let relay_endpoint = udp_relay_endpoint_from_bound(
            proxy_addr,
            SocksBoundAddr {
                address: SocksAddress::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                port: 5353,
            },
        );

        assert_eq!(
            relay_endpoint,
            Socks5UdpRelayEndpoint::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)),
                5353
            ))
        );
    }

    #[test]
    fn udp_associate_preserves_domain_bound_addr() {
        let proxy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080);
        let relay_endpoint = udp_relay_endpoint_from_bound(
            proxy_addr,
            SocksBoundAddr {
                address: SocksAddress::Domain("relay.example".to_owned()),
                port: 5353,
            },
        );

        assert_eq!(
            relay_endpoint,
            Socks5UdpRelayEndpoint::Domain {
                host: "relay.example".to_owned(),
                port: 5353,
            }
        );
    }
}

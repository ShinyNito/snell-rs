use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{Error, Result};
use crate::protocol::socks5::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, COMMAND_CONNECT, COMMAND_UDP_ASSOCIATE,
    METHOD_NO_ACCEPTABLE, METHOD_NO_AUTH, SOCKS_VERSION, SocksAddress, SocksAddressContext,
    SocksReply, SocksRequest, SocksTarget, read_address_port, write_address,
};
use crate::protocol::udp::AddressRef;
use crate::proxy::outbound::RelayStats;
use crate::proxy::outbound::snell::{SnellClientOutbound, SnellTcpConnect};
use crate::proxy::snell::server::{
    V6_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED, V6_ERROR_CONNECTION_REFUSED, V6_ERROR_DNS_FAILED,
    V6_ERROR_HOST_UNREACHABLE, V6_ERROR_NETWORK_DOWN, V6_ERROR_NETWORK_UNREACHABLE,
    V6_ERROR_TIMED_OUT,
};
use crate::proxy::snell::tcp::relay_tcp_connect;
use crate::proxy::socks5::udp::relay_socks5_udp_association;

pub(crate) async fn relay_socks5_connection(
    mut local: TcpStream,
    outbound: Arc<SnellClientOutbound>,
    quic_proxy: bool,
) -> Result<RelayStats> {
    local.set_nodelay(true)?;
    let request = match read_client_request(&mut local).await {
        Ok(request) => request,
        Err(err) => {
            let _ = local.shutdown().await;
            return Err(err);
        }
    };
    match request {
        SocksRequest::Connect(target) => relay_socks5_tcp_connect(local, outbound, target).await,
        SocksRequest::UdpAssociate(_) => {
            relay_socks5_udp_associate(local, outbound, quic_proxy).await
        }
    }
}

async fn relay_socks5_tcp_connect(
    mut local: TcpStream,
    outbound: Arc<SnellClientOutbound>,
    target: SocksTarget,
) -> Result<RelayStats> {
    let mut connect = match outbound.open_tcp(&target.host, target.port).await {
        Ok(connect) => connect,
        Err(err) => {
            write_reply_and_shutdown(&mut local, socks_reply_for_connect_error(&err)).await;
            return Err(err);
        }
    };
    if let Err(err) = accept_socks5_connect(&mut connect).await {
        write_reply_and_shutdown(&mut local, socks_reply_for_connect_error(&err)).await;
        return Err(err);
    }
    write_reply(&mut local, SocksReply::Succeeded).await?;
    relay_tcp_connect(local, connect).await
}

async fn accept_socks5_connect(connect: &mut SnellTcpConnect) -> Result<()> {
    connect.accept_tunnel_reply().await
}

fn socks_reply_for_connect_error(err: &Error) -> SocksReply {
    match err {
        Error::Server { code, .. } => socks_reply_for_snell_server_error(*code),
        Error::Dns(_) | Error::DnsTimeout | Error::DnsUnavailable => SocksReply::HostUnreachable,
        Error::Ipv6Disabled | Error::InvalidAddressType => SocksReply::AddressTypeNotSupported,
        Error::Io(err) => socks_reply_for_io_error(err),
        _ => SocksReply::GeneralFailure,
    }
}

const fn socks_reply_for_snell_server_error(code: u8) -> SocksReply {
    match code {
        V6_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED => SocksReply::AddressTypeNotSupported,
        V6_ERROR_NETWORK_DOWN | V6_ERROR_NETWORK_UNREACHABLE => SocksReply::NetworkUnreachable,
        V6_ERROR_HOST_UNREACHABLE | V6_ERROR_DNS_FAILED => SocksReply::HostUnreachable,
        V6_ERROR_CONNECTION_REFUSED => SocksReply::ConnectionRefused,
        V6_ERROR_TIMED_OUT => SocksReply::TtlExpired,
        _ => SocksReply::GeneralFailure,
    }
}

fn socks_reply_for_io_error(err: &std::io::Error) -> SocksReply {
    match err.kind() {
        std::io::ErrorKind::ConnectionRefused => SocksReply::ConnectionRefused,
        std::io::ErrorKind::TimedOut => SocksReply::TtlExpired,
        std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::InvalidInput => {
            SocksReply::AddressTypeNotSupported
        }
        std::io::ErrorKind::NotFound => SocksReply::HostUnreachable,
        _ => SocksReply::GeneralFailure,
    }
}

fn socks_reply_for_request_error(err: &Error) -> SocksReply {
    match err {
        Error::InvalidAddressType | Error::Ipv6Disabled => SocksReply::AddressTypeNotSupported,
        _ => SocksReply::GeneralFailure,
    }
}

#[derive(Clone, Copy)]
enum SocksRequestCommand {
    Connect,
    UdpAssociate,
}

impl SocksRequestCommand {
    const fn into_request(self, target: SocksTarget) -> SocksRequest {
        match self {
            Self::Connect => SocksRequest::Connect(target),
            Self::UdpAssociate => SocksRequest::UdpAssociate(target),
        }
    }
}

async fn relay_socks5_udp_associate(
    local: TcpStream,
    outbound: Arc<SnellClientOutbound>,
    quic_proxy: bool,
) -> Result<RelayStats> {
    relay_socks5_udp_association(
        local,
        outbound.server_addr(),
        outbound.secret(),
        outbound.version(),
        quic_proxy,
    )
    .await
}

pub(crate) async fn read_client_request<S>(stream: &mut S) -> Result<SocksRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    read_greeting(stream).await?;
    read_request(stream).await
}

pub(crate) async fn write_reply<S>(stream: &mut S, reply: SocksReply) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_reply_with_bind(
        stream,
        reply,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    )
    .await
}

pub(crate) async fn write_reply_and_shutdown<S>(stream: &mut S, reply: SocksReply)
where
    S: AsyncWrite + Unpin,
{
    let _ = write_reply(stream, reply).await;
    let _ = stream.shutdown().await;
}

pub(crate) async fn write_reply_with_bind<S>(
    stream: &mut S,
    reply: SocksReply,
    bind_addr: SocketAddr,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let out = reply_bytes(reply, bind_addr)?;
    stream.write_all(&out).await?;
    Ok(())
}

fn reply_bytes(reply: SocksReply, bind_addr: SocketAddr) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(262);
    out.put_u8(SOCKS_VERSION);
    out.put_u8(reply as u8);
    out.put_u8(0);
    write_address(&mut out, AddressRef::Ip(bind_addr.ip()), bind_addr.port())?;
    Ok(out)
}

async fn read_greeting<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION || header[1] == 0 {
        write_method_selection(stream, METHOD_NO_ACCEPTABLE).await?;
        return Err(Error::InvalidSocksRequest);
    }

    let mut methods = [0; u8::MAX as usize];
    let method_count = header[1] as usize;
    stream.read_exact(&mut methods[..method_count]).await?;
    if !methods[..method_count].contains(&METHOD_NO_AUTH) {
        write_method_selection(stream, METHOD_NO_ACCEPTABLE).await?;
        return Err(Error::InvalidSocksRequest);
    }

    write_method_selection(stream, METHOD_NO_AUTH).await
}

async fn write_method_selection<S>(stream: &mut S, method: u8) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&[SOCKS_VERSION, method]).await?;
    Ok(())
}

async fn read_request<S>(stream: &mut S) -> Result<SocksRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION || header[2] != 0 {
        write_reply(stream, SocksReply::GeneralFailure).await?;
        return Err(Error::InvalidSocksRequest);
    }
    let command = match header[1] {
        COMMAND_CONNECT => SocksRequestCommand::Connect,
        COMMAND_UDP_ASSOCIATE => SocksRequestCommand::UdpAssociate,
        _ => {
            write_reply(stream, SocksReply::CommandNotSupported).await?;
            return Err(Error::InvalidSocksRequest);
        }
    };
    let (address, port) = match header[3] {
        ATYP_IPV4 | ATYP_DOMAIN | ATYP_IPV6 => {
            match read_address_port(stream, header[3], SocksAddressContext::Request).await {
                Ok(address) => address,
                Err(err) => {
                    write_reply(stream, socks_reply_for_request_error(&err)).await?;
                    return Err(err);
                }
            }
        }
        _ => {
            write_reply(stream, SocksReply::AddressTypeNotSupported).await?;
            return Err(Error::InvalidSocksRequest);
        }
    };
    let host = match address {
        SocksAddress::Ip(ip) => ip.to_string(),
        SocksAddress::Domain(host) => host,
    };
    let target = SocksTarget { host, port };
    Ok(command.into_request(target))
}

#[cfg(test)]
mod tests;

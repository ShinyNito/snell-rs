use std::net::{Ipv4Addr, SocketAddr};

use snell_protocol::socks5::{self, Command, METHOD_NO_ACCEPTABLE, METHOD_NO_AUTH, Reply};
use snell_protocol::{Address, AddressRef, ParseState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::SessionError;

pub(crate) enum Socks5Command {
    Connect(Address),
    UdpAssociate,
}

pub(crate) async fn accept_socks5(stream: &mut TcpStream) -> Result<Socks5Command, SessionError> {
    let mut buf = [0u8; 2 + 255];
    let mut filled = 0;
    loop {
        match socks5::greeting_need(&buf[..filled])? {
            ParseState::Need(total) => {
                if total > buf.len() {
                    return Err(SessionError::Protocol(snell_protocol::Error::Malformed(
                        "oversized socks5 greeting",
                    )));
                }
                stream.read_exact(&mut buf[filled..total]).await?;
                filled = total;
            }
            ParseState::Done(greeting) => {
                if !greeting.supports(METHOD_NO_AUTH) {
                    write_method(stream, METHOD_NO_ACCEPTABLE).await?;
                    return Err(SessionError::NoAcceptableMethod);
                }
                break;
            }
        }
    }
    write_method(stream, METHOD_NO_AUTH).await?;

    let mut buf = [0u8; 3 + 1 + 1 + 255 + 2];
    let mut filled = 0;
    loop {
        match socks5::request_need(&buf[..filled])? {
            ParseState::Need(total) => {
                if total > buf.len() {
                    return Err(SessionError::Protocol(snell_protocol::Error::Malformed(
                        "oversized socks5 request",
                    )));
                }
                stream.read_exact(&mut buf[filled..total]).await?;
                filled = total;
            }
            ParseState::Done(request) => {
                return match request.command {
                    Command::Connect => {
                        Ok(Socks5Command::Connect(request.destination.into_owned()))
                    }
                    Command::UdpAssociate => Ok(Socks5Command::UdpAssociate),
                    _ => {
                        write_socks5_reply(stream, Reply::CommandNotSupported).await?;
                        Err(SessionError::CommandNotSupported)
                    }
                };
            }
        }
    }
}

async fn write_method(stream: &mut TcpStream, method: u8) -> Result<(), SessionError> {
    let mut buf = [0u8; 2];
    let n = socks5::encode_method_selection(&mut buf, method)?;
    stream.write_all(&buf[..n]).await?;
    Ok(())
}

pub(crate) async fn write_socks5_reply(
    stream: &mut TcpStream,
    reply: Reply,
) -> Result<(), SessionError> {
    write_socks5_reply_bind(stream, reply, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await
}

pub(crate) async fn write_socks5_reply_bind(
    stream: &mut TcpStream,
    reply: Reply,
    bind: SocketAddr,
) -> Result<(), SessionError> {
    let mut buf = [0u8; 3 + 1 + 1 + 255 + 2];
    let n = socks5::encode_reply(&mut buf, reply, AddressRef::Ip(bind))?;
    stream.write_all(&buf[..n]).await?;
    Ok(())
}

pub(crate) fn socks5_reply_from_error(error: &SessionError) -> Reply {
    match error {
        SessionError::CommandNotSupported => Reply::CommandNotSupported,
        SessionError::ConnectTimeout | SessionError::HandshakeTimeout => Reply::TtlExpired,
        SessionError::Io(io) => Reply::from_io_error(io),
        _ => Reply::GeneralFailure,
    }
}

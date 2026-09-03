use std::net::SocketAddr;
use std::time::Duration;

use snell_protocol::socks5::{self, Command, METHOD_NO_AUTH, Reply};
use snell_protocol::{Address, AddressRef, ParseState, TCP_CONNECT_TIMEOUT_SECS};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::error::{SessionError, TimeoutKind};

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
}

async fn connect_direct(destination: &Address) -> Result<TcpStream, SessionError> {
    let connect = async {
        match destination {
            Address::Ip(addr) => TcpStream::connect(*addr).await,
            Address::Domain { host, port } => TcpStream::connect((host.as_str(), *port)).await,
        }
    };
    match timeout(Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS), connect).await {
        Ok(Ok(stream)) => {
            stream.set_nodelay(true)?;
            Ok(stream)
        }
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err(SessionError::from_timeout(TimeoutKind::Connect)),
    }
}

async fn connect_socks5(
    server: SocketAddr,
    destination: &Address,
) -> Result<TcpStream, SessionError> {
    let stream = match timeout(
        Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS),
        TcpStream::connect(server),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => return Err(error.into()),
        Err(_) => return Err(SessionError::from_timeout(TimeoutKind::Connect)),
    };
    stream.set_nodelay(true)?;
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

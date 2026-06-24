use std::{error::Error, io::Result, net::SocketAddr, sync::Arc};

use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::{io::AsyncWriteExt, time};

use crate::{
    protocol::{
        address::AddressRef,
        snell::{
            SnellMode, SnellTcpEncoder, V4Mode, V6ShapedMode, V6UnsafeRawMode, V6UnshapedMode,
            version::{ProtocolVersion, V6Mode},
        },
        socks5::{self, Command},
    },
    relay::tcp::{
        client::SnellConnector,
        handshake::accept_socks5_request,
        transport::{Outbound as OutboundTrait, Transport as TransportTrait},
    },
    relay::udp::relay_socks5_udp,
    timeout::{TCP_TIMEOUT, timed_out},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientConfig {
    pub listen: SocketAddr,
    pub server: SocketAddr,
    pub psk: Vec<u8>,
    pub resume: bool,
    pub version: ProtocolVersion,
}

pub async fn bind_tcp_listener(config: ClientConfig) -> Result<()> {
    let socket = if config.listen.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.set_nodelay(true)?;
    socket.bind(config.listen)?;
    let listener = socket.listen(4096)?;
    match config.version {
        ProtocolVersion::V4 | ProtocolVersion::V5 => {
            serve_socks5_listener_typed::<V4Mode>(
                listener,
                config.server,
                config.psk,
                config.resume,
            )
            .await
        }
        ProtocolVersion::V6(V6Mode::Default) => {
            serve_socks5_listener_typed::<V6ShapedMode>(
                listener,
                config.server,
                config.psk,
                config.resume,
            )
            .await
        }
        ProtocolVersion::V6(V6Mode::Unshaped) => {
            serve_socks5_listener_typed::<V6UnshapedMode>(
                listener,
                config.server,
                config.psk,
                config.resume,
            )
            .await
        }
        ProtocolVersion::V6(V6Mode::UnsafeRaw) => {
            serve_socks5_listener_typed::<V6UnsafeRawMode>(
                listener,
                config.server,
                config.psk,
                config.resume,
            )
            .await
        }
    }
}

async fn serve_socks5_listener_typed<M>(
    listener: TcpListener,
    server: SocketAddr,
    psk: Vec<u8>,
    resume: bool,
) -> Result<()>
where
    M: SnellMode + Send + Sync + 'static + Unpin,
    M::Encoder: Send + Unpin,
    M::Decoder: Send + Unpin,
    <M::Encoder as SnellTcpEncoder>::Reservation: Send + Unpin,
{
    let snell_client = Arc::new(SnellConnector::<M>::new(server, psk, resume));
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let snell_client = snell_client.clone();
        tokio::spawn(async move {
            match serve_socks5_inbound(stream, snell_client).await {
                Ok(()) => tracing::debug!(%peer_addr, "客户端入站结束"),
                Err(error) => tracing::debug!(%peer_addr, %error, "客户端入站失败"),
            }
        });
    }
}

async fn serve_socks5_inbound<M>(
    stream: TcpStream,
    snell_client: Arc<SnellConnector<M>>,
) -> std::result::Result<(), Box<dyn Error + Send + Sync>>
where
    M: SnellMode + Send + Sync + 'static + Unpin,
    M::Encoder: Send + Unpin,
    M::Decoder: Send + Unpin,
    <M::Encoder as SnellTcpEncoder>::Reservation: Send + Unpin,
{
    let mut stream = stream;
    let (command, destination) = time::timeout(TCP_TIMEOUT, accept_socks5_request(&mut stream))
        .await
        .map_err(|_| timed_out("socks5 inbound handshake"))??;

    match command {
        Command::Connect => {
            tracing::debug!(%destination, "SOCKS5 CONNECT 握手完成");
            let transport = match OutboundTrait::connect(&snell_client, &destination).await {
                Ok(transport) => transport,
                Err(error) => {
                    let _ =
                        write_socks5_reply(&mut stream, socks5::Reply::from_io_error(&error)).await;
                    return Err(error.into());
                }
            };

            write_socks5_reply(&mut stream, socks5::Reply::Succeeded).await?;
            TransportTrait::relay(transport, stream).await?;
        }
        Command::UdpAssociate => {
            let udp = UdpSocket::bind(SocketAddr::new(stream.local_addr()?.ip(), 0)).await?;
            let bind = udp.local_addr()?;
            tracing::debug!(%bind, "SOCKS5 UDP_ASSOCIATE 握手完成");
            write_socks5_reply_with_bind(
                &mut stream,
                socks5::Reply::Succeeded,
                AddressRef::Ip(bind),
            )
            .await?;
            relay_socks5_udp(stream, udp, snell_client).await?;
        }
        other => {
            write_socks5_reply(&mut stream, socks5::Reply::CommandNotSupported).await?;
            return Err(format!("unsupported SOCKS5 command: {other:?}").into());
        }
    }
    Ok(())
}

async fn write_socks5_reply(stream: &mut TcpStream, reply: socks5::Reply) -> Result<()> {
    write_socks5_reply_with_bind(stream, reply, socks5::unspecified_ipv4_bind()).await
}

async fn write_socks5_reply_with_bind(
    stream: &mut TcpStream,
    reply: socks5::Reply,
    bind: AddressRef<'_>,
) -> Result<()> {
    let mut buf = [0u8; socks5::MAX_REPLY_LEN];
    let n = socks5::encode_reply(&mut buf, reply, bind)?;
    stream.write_all(&buf[..n]).await
}

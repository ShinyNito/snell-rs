#[cfg(windows)]
use std::net::TcpListener as StdTcpListener;
#[cfg(windows)]
use std::sync::Arc;
use std::{error::Error, io::Result, net::SocketAddr, rc::Rc};

use compio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    runtime, time,
};

use crate::{
    keepalive::apply_tcp_keepalive,
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
        transport::{Outbound as OutboundTrait, copy_bidirectional},
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
    let listener = bind_listener(config.listen).await?;
    serve_socks5_listener(listener, config).await
}

async fn bind_listener(listen: SocketAddr) -> Result<TcpListener> {
    let socket = if listen.is_ipv4() {
        TcpSocket::new_v4().await?
    } else {
        TcpSocket::new_v6().await?
    };
    socket.set_reuseaddr(true)?;
    #[cfg(all(
        unix,
        not(target_os = "solaris"),
        not(target_os = "illumos"),
        not(target_os = "cygwin"),
    ))]
    socket.set_reuseport(true)?;
    socket.set_nodelay(true)?;
    socket.bind(listen).await?;
    socket.listen(4096).await
}

async fn serve_socks5_listener(listener: TcpListener, config: ClientConfig) -> Result<()> {
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

#[cfg(windows)]
pub async fn bind_tcp_listener_with_dispatcher(
    config: ClientConfig,
    dispatcher: Arc<compio::dispatcher::Dispatcher>,
) -> Result<()> {
    let listener = bind_std_listener(config.listen)?;
    match config.version {
        ProtocolVersion::V4 | ProtocolVersion::V5 => {
            serve_socks5_listener_typed_with_dispatcher::<V4Mode>(
                listener,
                config.server,
                config.psk,
                config.resume,
                dispatcher,
            )
            .await
        }
        ProtocolVersion::V6(V6Mode::Default) => {
            serve_socks5_listener_typed_with_dispatcher::<V6ShapedMode>(
                listener,
                config.server,
                config.psk,
                config.resume,
                dispatcher,
            )
            .await
        }
        ProtocolVersion::V6(V6Mode::Unshaped) => {
            serve_socks5_listener_typed_with_dispatcher::<V6UnshapedMode>(
                listener,
                config.server,
                config.psk,
                config.resume,
                dispatcher,
            )
            .await
        }
        ProtocolVersion::V6(V6Mode::UnsafeRaw) => {
            serve_socks5_listener_typed_with_dispatcher::<V6UnsafeRawMode>(
                listener,
                config.server,
                config.psk,
                config.resume,
                dispatcher,
            )
            .await
        }
    }
}

#[cfg(windows)]
fn bind_std_listener(listen: SocketAddr) -> Result<StdTcpListener> {
    StdTcpListener::bind(listen)
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
    <M::Encoder as SnellTcpEncoder>::Reservation: Send,
{
    let snell_client = Rc::new(SnellConnector::<M>::new(server, psk, resume));
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        if let Err(error) = apply_tcp_keepalive(&stream) {
            tracing::warn!(%peer_addr, %error, "SOCKS5 inbound tcp keepalive could not be enabled");
        }
        let snell_client = snell_client.clone();
        runtime::spawn(async move {
            match serve_socks5_inbound(stream, snell_client).await {
                Ok(()) => tracing::info!(%peer_addr, "client inbound ended"),
                Err(error) => tracing::info!(%peer_addr, %error, "client inbound failed"),
            }
        })
        .detach();
    }
}

#[cfg(windows)]
async fn serve_socks5_listener_typed_with_dispatcher<M>(
    listener: StdTcpListener,
    server: SocketAddr,
    psk: Vec<u8>,
    resume: bool,
    dispatcher: Arc<compio::dispatcher::Dispatcher>,
) -> Result<()>
where
    M: SnellMode + Send + Sync + 'static + Unpin,
    M::Encoder: Send + Unpin,
    M::Decoder: Send + Unpin,
    <M::Encoder as SnellTcpEncoder>::Reservation: Send,
{
    let psk: Arc<[u8]> = Arc::from(psk.into_boxed_slice());
    loop {
        let (stream, peer_addr) = listener.accept()?;
        let psk = psk.clone();
        std::mem::drop(
            dispatcher
            .dispatch(move || async move {
                // ponytail: per-connection on Windows; add worker-local pools if resume throughput matters.
                let snell_client = Rc::new(SnellConnector::<M>::new(server, psk, resume));
                let stream = match TcpStream::from_std(stream) {
                    Ok(stream) => stream,
                    Err(error) => {
                        tracing::info!(%peer_addr, %error, "client inbound attach failed");
                        return;
                    }
                };
                if let Err(error) = apply_tcp_keepalive(&stream) {
                    tracing::warn!(%peer_addr, %error, "SOCKS5 inbound tcp keepalive could not be enabled");
                }
                match serve_socks5_inbound(stream, snell_client).await {
                    Ok(()) => tracing::info!(%peer_addr, "client inbound ended"),
                    Err(error) => tracing::info!(%peer_addr, %error, "client inbound failed"),
                }
            })
            .map_err(|_| std::io::Error::other("dispatcher workers stopped"))?,
        );
    }
}

async fn serve_socks5_inbound<M>(
    stream: TcpStream,
    snell_client: Rc<SnellConnector<M>>,
) -> std::result::Result<(), Box<dyn Error + Send + Sync>>
where
    M: SnellMode + Send + Sync + 'static + Unpin,
    M::Encoder: Send + Unpin,
    M::Decoder: Send + Unpin,
    <M::Encoder as SnellTcpEncoder>::Reservation: Send,
{
    let mut stream = stream;
    let (command, destination) = time::timeout(TCP_TIMEOUT, accept_socks5_request(&mut stream))
        .await
        .map_err(|_| timed_out("socks5 inbound handshake"))??;

    match command {
        Command::Connect => {
            tracing::info!(%destination, "SOCKS5 CONNECT received");
            let transport = match OutboundTrait::connect(&snell_client, &destination).await {
                Ok(transport) => transport,
                Err(error) => {
                    tracing::debug!(%destination, %error, "upstream connect failed");
                    let _ =
                        write_socks5_reply(&mut stream, socks5::Reply::from_io_error(&error)).await;
                    return Err(error.into());
                }
            };

            write_socks5_reply(&mut stream, socks5::Reply::Succeeded).await?;
            copy_bidirectional(transport, stream).await?;
        }
        Command::UdpAssociate => {
            let udp = UdpSocket::bind(SocketAddr::new(stream.local_addr()?.ip(), 0)).await?;
            let bind = udp.local_addr()?;
            tracing::info!(%bind, "SOCKS5 UDP_ASSOCIATE received");
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
    let (result, _buf) = stream.write_all(buf[..n].to_vec()).await.into_parts();
    result
}

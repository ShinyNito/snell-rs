use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use snell_protocol::socks5::Reply;
use snell_protocol::{
    Address, EncodeBuffer, ProtocolFlavor, Psk, RecvBuffer, TCP_CONNECT_TIMEOUT_SECS, V4Decoder,
    V4Encoder, V6ShapedDecoder, V6ShapedEncoder, V6UnshapedDecoder, V6UnshapedEncoder,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::codec::{TcpDecoder, TcpEncoder};
use crate::error::{SessionError, TimeoutKind};
use crate::session::{
    new_encode, new_recv, read_server_tunnel, relay, with_handshake_timeout, write_connect,
};
use crate::socks::{accept_socks5_connect, socks5_reply_from_error, write_socks5_reply};
use crate::{bind_listener, set_nodelay};

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub listen: SocketAddr,
    pub server: SocketAddr,
    pub psk: Psk,
    pub version: ProtocolFlavor,
}

pub async fn run_client(config: ClientConfig) -> Result<(), SessionError> {
    let listener = bind_listener(config.listen)?;
    serve_client(listener, config, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

pub async fn serve_client(
    listener: TcpListener,
    config: ClientConfig,
    shutdown: impl Future<Output = ()>,
) -> Result<(), SessionError> {
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let config = config.clone();
                tokio::spawn(async move {
                    let _ = handle_client(stream, config).await;
                });
            }
        }
    }
}

async fn handle_client(mut local: TcpStream, config: ClientConfig) -> Result<(), SessionError> {
    set_nodelay(&local)?;
    let destination = with_handshake_timeout(accept_socks5_connect(&mut local)).await?;
    client_handshake_and_relay(&mut local, config, &destination).await
}

async fn client_handshake_and_relay(
    local: &mut TcpStream,
    config: ClientConfig,
    destination: &Address,
) -> Result<(), SessionError> {
    let snell = match timeout(
        Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS),
        TcpStream::connect(config.server),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            return Err(write_socks5_fail(local, SessionError::from(error)).await);
        }
        Err(_) => {
            return Err(
                write_socks5_fail(local, SessionError::from_timeout(TimeoutKind::Connect)).await,
            );
        }
    };
    match config.version {
        ProtocolFlavor::V4 | ProtocolFlavor::V5 => {
            let encoder = match V4Encoder::os(&config.psk) {
                Ok(encoder) => encoder,
                Err(error) => return Err(write_socks5_fail(local, error).await),
            };
            let decoder = V4Decoder::new(config.psk.clone());
            client_session(local, snell, encoder, decoder, destination).await
        }
        ProtocolFlavor::V6Shaped => {
            let encoder = match V6ShapedEncoder::os(&config.psk) {
                Ok(encoder) => encoder,
                Err(error) => return Err(write_socks5_fail(local, error).await),
            };
            let decoder = match V6ShapedDecoder::new(config.psk.clone()) {
                Ok(decoder) => decoder,
                Err(error) => return Err(write_socks5_fail(local, error).await),
            };
            client_session(local, snell, encoder, decoder, destination).await
        }
        ProtocolFlavor::V6Unshaped => {
            let encoder = match V6UnshapedEncoder::os(&config.psk) {
                Ok(encoder) => encoder,
                Err(error) => return Err(write_socks5_fail(local, error).await),
            };
            let decoder = V6UnshapedDecoder::new(config.psk.clone());
            client_session(local, snell, encoder, decoder, destination).await
        }
    }
}

async fn write_socks5_fail(local: &mut TcpStream, error: impl Into<SessionError>) -> SessionError {
    let error = error.into();
    let _ = write_socks5_reply(local, socks5_reply_from_error(&error)).await;
    error
}

async fn client_session<E: TcpEncoder, D: TcpDecoder>(
    local: &mut TcpStream,
    mut snell: TcpStream,
    mut encoder: E,
    mut decoder: D,
    destination: &Address,
) -> Result<(), SessionError> {
    let mut encode = new_encode();
    let mut recv = new_recv();
    let leftover = match open_tunnel(
        &mut snell,
        &mut encoder,
        &mut decoder,
        &mut encode,
        &mut recv,
        destination,
    )
    .await
    {
        Ok(leftover) => leftover,
        Err(error) => return Err(write_socks5_fail(local, error).await),
    };
    write_socks5_reply(local, Reply::Succeeded).await?;
    relay(
        &mut snell,
        local,
        &mut encoder,
        &mut decoder,
        &mut recv,
        &mut encode,
        &leftover,
        &[],
    )
    .await?;
    Ok(())
}

async fn open_tunnel<E: TcpEncoder, D: TcpDecoder>(
    snell: &mut TcpStream,
    encoder: &mut E,
    decoder: &mut D,
    encode: &mut EncodeBuffer,
    recv: &mut RecvBuffer,
    destination: &Address,
) -> Result<Vec<u8>, SessionError> {
    set_nodelay(snell)?;
    with_handshake_timeout(async {
        write_connect(encoder, encode, snell, destination.as_view()).await?;
        read_server_tunnel(decoder, recv, snell).await
    })
    .await
}

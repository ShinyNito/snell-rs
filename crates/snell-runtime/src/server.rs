use std::future::Future;
use std::net::SocketAddr;

use snell_protocol::{
    ProtocolFlavor, Psk, V4Decoder, V4Encoder, V6ShapedDecoder, V6ShapedEncoder, V6UnshapedDecoder,
    V6UnshapedEncoder,
};
use tokio::net::{TcpListener, TcpStream};

use crate::codec::{TcpDecoder, TcpEncoder};
use crate::error::SessionError;
use crate::outbound::Outbound;
use crate::session::{
    new_encode, new_recv, read_server_connect, relay, with_handshake_timeout, write_reject,
    write_tunnel,
};
use crate::{bind_listener, set_nodelay};

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub psk: Psk,
    pub version: ProtocolFlavor,
    pub outbound: Outbound,
}

pub async fn run_server(config: ServerConfig) -> Result<(), SessionError> {
    let listener = bind_listener(config.listen)?;
    serve_server(listener, config, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

pub async fn serve_server(
    listener: TcpListener,
    config: ServerConfig,
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
                    let _ = handle_server(stream, config).await;
                });
            }
        }
    }
}

async fn handle_server(snell: TcpStream, config: ServerConfig) -> Result<(), SessionError> {
    set_nodelay(&snell)?;
    match config.version {
        ProtocolFlavor::V4 | ProtocolFlavor::V5 => {
            let encoder = V4Encoder::os(&config.psk)?;
            let decoder = V4Decoder::new(config.psk.clone());
            server_session(snell, encoder, decoder, config.outbound).await
        }
        ProtocolFlavor::V6Shaped => {
            let encoder = V6ShapedEncoder::os(&config.psk)?;
            let decoder = V6ShapedDecoder::new(config.psk.clone())?;
            server_session(snell, encoder, decoder, config.outbound).await
        }
        ProtocolFlavor::V6Unshaped => {
            let encoder = V6UnshapedEncoder::os(&config.psk)?;
            let decoder = V6UnshapedDecoder::new(config.psk.clone());
            server_session(snell, encoder, decoder, config.outbound).await
        }
    }
}

async fn server_session<E: TcpEncoder, D: TcpDecoder>(
    mut snell: TcpStream,
    mut encoder: E,
    mut decoder: D,
    outbound: Outbound,
) -> Result<(), SessionError> {
    let mut encode = new_encode();
    let mut recv = new_recv();
    let connect = match with_handshake_timeout(read_server_connect(
        &mut decoder,
        &mut recv,
        &mut snell,
    ))
    .await
    {
        Ok(connect) => connect,
        Err(error @ (SessionError::ReuseNotImplemented | SessionError::UdpNotImplemented)) => {
            let message = match error {
                SessionError::ReuseNotImplemented => "reuse is not implemented",
                _ => "udp is not implemented",
            };
            let _ = write_reject(&mut encoder, &mut encode, &mut snell, message).await;
            return Err(error);
        }
        Err(error) => return Err(error),
    };

    let mut remote = match with_handshake_timeout(async {
        let remote = outbound.connect(&connect.destination).await?;
        write_tunnel(&mut encoder, &mut encode, &mut snell).await?;
        Ok(remote)
    })
    .await
    {
        Ok(remote) => remote,
        Err(error) => {
            let _ = write_reject(&mut encoder, &mut encode, &mut snell, &error.to_string()).await;
            return Err(error);
        }
    };
    relay(
        &mut snell,
        &mut remote,
        &mut encoder,
        &mut decoder,
        &mut recv,
        &mut encode,
        &connect.leftover,
        &[],
    )
    .await?;
    Ok(())
}

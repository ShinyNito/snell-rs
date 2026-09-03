use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
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
use crate::kdf::KdfLimiter;
use crate::pool::{PooledCodec, PooledConn, ReusePool};
use crate::session::{
    client_may_pool, new_encode, new_recv, read_server_tunnel, relay, with_handshake_timeout,
    write_connect,
};
use crate::socks::{accept_socks5_connect, socks5_reply_from_error, write_socks5_reply};
use crate::{bind_listener, set_nodelay};

#[derive(Clone)]
pub struct ClientConfig {
    pub listen: SocketAddr,
    pub server: SocketAddr,
    pub psk: Psk,
    pub version: ProtocolFlavor,
    pub reuse: bool,
    pub pool: Option<ReusePool>,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("listen", &self.listen)
            .field("server", &self.server)
            .field("psk", &self.psk)
            .field("version", &self.version)
            .field("reuse", &self.reuse)
            .field("pool", &self.pool.as_ref().map(|_| "ReusePool"))
            .finish()
    }
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
    let kdf = Arc::new(KdfLimiter::new());
    let pool = if config.reuse {
        Some(config.pool.clone().unwrap_or_default())
    } else {
        None
    };
    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let config = config.clone();
                let kdf = kdf.clone();
                let pool = pool.clone();
                tokio::spawn(async move {
                    let _ = handle_client(stream, config, kdf, pool).await;
                });
            }
        }
    }
}

async fn handle_client(
    mut local: TcpStream,
    config: ClientConfig,
    kdf: Arc<KdfLimiter>,
    pool: Option<ReusePool>,
) -> Result<(), SessionError> {
    set_nodelay(&local)?;
    let destination = with_handshake_timeout(accept_socks5_connect(&mut local)).await?;
    client_handshake_and_relay(&mut local, config, &destination, &kdf, pool.as_ref()).await
}

async fn client_handshake_and_relay(
    local: &mut TcpStream,
    config: ClientConfig,
    destination: &Address,
    kdf: &KdfLimiter,
    pool: Option<&ReusePool>,
) -> Result<(), SessionError> {
    let reuse = pool.is_some();
    let mut from_pool = false;
    let (snell, codec) = if let Some(pool) = pool {
        if let Some(conn) = pool.take() {
            from_pool = true;
            (conn.stream, conn.codec)
        } else {
            match dial_and_codec(&config, kdf).await {
                Ok(pair) => pair,
                Err(error) => return Err(write_socks5_fail(local, error).await),
            }
        }
    } else {
        match dial_and_codec(&config, kdf).await {
            Ok(pair) => pair,
            Err(error) => return Err(write_socks5_fail(local, error).await),
        }
    };

    let opened = open_session(snell, codec, destination, reuse, kdf, &config.psk).await;
    let Opened {
        snell,
        codec,
        leftover,
        encode,
        recv,
    } = match opened {
        Ok(opened) => opened,
        Err(error) if from_pool && error.is_stale_pool_error() => {
            let (snell, codec) = match dial_and_codec(&config, kdf).await {
                Ok(pair) => pair,
                Err(error) => return Err(write_socks5_fail(local, error).await),
            };
            match open_session(snell, codec, destination, reuse, kdf, &config.psk).await {
                Ok(opened) => opened,
                Err(error) => return Err(write_socks5_fail(local, error).await),
            }
        }
        Err(error) => return Err(write_socks5_fail(local, error).await),
    };

    write_socks5_reply(local, Reply::Succeeded).await?;
    finish_session(local, snell, codec, leftover, encode, recv, reuse, pool).await
}

async fn dial_and_codec(
    config: &ClientConfig,
    kdf: &KdfLimiter,
) -> Result<(TcpStream, PooledCodec), SessionError> {
    let stream = match timeout(
        Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS),
        TcpStream::connect(config.server),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => return Err(error.into()),
        Err(_) => return Err(SessionError::from_timeout(TimeoutKind::Connect)),
    };
    set_nodelay(&stream)?;
    let codec = new_codec(config, kdf).await?;
    Ok((stream, codec))
}

async fn new_codec(config: &ClientConfig, kdf: &KdfLimiter) -> Result<PooledCodec, SessionError> {
    match config.version {
        ProtocolFlavor::V4 | ProtocolFlavor::V5 => {
            let psk = config.psk.clone();
            let encoder = kdf.run(move || V4Encoder::os(&psk)).await??;
            Ok(PooledCodec::V4 {
                encoder,
                decoder: V4Decoder::new(config.psk.clone()),
            })
        }
        ProtocolFlavor::V6Shaped => {
            let psk = config.psk.clone();
            let encoder = kdf.run(move || V6ShapedEncoder::os(&psk)).await??;
            let decoder = V6ShapedDecoder::new(config.psk.clone())?;
            Ok(PooledCodec::V6Shaped { encoder, decoder })
        }
        ProtocolFlavor::V6Unshaped => {
            let psk = config.psk.clone();
            let encoder = kdf.run(move || V6UnshapedEncoder::os(&psk)).await??;
            Ok(PooledCodec::V6Unshaped {
                encoder,
                decoder: V6UnshapedDecoder::new(config.psk.clone()),
            })
        }
    }
}

async fn write_socks5_fail(local: &mut TcpStream, error: impl Into<SessionError>) -> SessionError {
    let error = error.into();
    let _ = write_socks5_reply(local, socks5_reply_from_error(&error)).await;
    error
}

struct Opened {
    snell: TcpStream,
    codec: PooledCodec,
    leftover: Vec<u8>,
    encode: EncodeBuffer,
    recv: RecvBuffer,
}

async fn open_session(
    mut snell: TcpStream,
    mut codec: PooledCodec,
    destination: &Address,
    reuse: bool,
    kdf: &KdfLimiter,
    psk: &Psk,
) -> Result<Opened, SessionError> {
    let mut encode = new_encode();
    let mut recv = new_recv();
    let leftover = match &mut codec {
        PooledCodec::V4 { encoder, decoder } => {
            open_tunnel(
                &mut snell,
                encoder,
                decoder,
                &mut encode,
                &mut recv,
                destination,
                reuse,
                kdf,
                psk,
            )
            .await?
        }
        PooledCodec::V6Shaped { encoder, decoder } => {
            open_tunnel(
                &mut snell,
                encoder,
                decoder,
                &mut encode,
                &mut recv,
                destination,
                reuse,
                kdf,
                psk,
            )
            .await?
        }
        PooledCodec::V6Unshaped { encoder, decoder } => {
            open_tunnel(
                &mut snell,
                encoder,
                decoder,
                &mut encode,
                &mut recv,
                destination,
                reuse,
                kdf,
                psk,
            )
            .await?
        }
    };
    Ok(Opened {
        snell,
        codec,
        leftover,
        encode,
        recv,
    })
}

#[allow(clippy::too_many_arguments)]
async fn finish_session(
    local: &mut TcpStream,
    mut snell: TcpStream,
    codec: PooledCodec,
    leftover: Vec<u8>,
    mut encode: EncodeBuffer,
    mut recv: RecvBuffer,
    reuse: bool,
    pool: Option<&ReusePool>,
) -> Result<(), SessionError> {
    let back = match codec {
        PooledCodec::V4 {
            mut encoder,
            mut decoder,
        } => {
            let ends = relay(
                &mut snell,
                local,
                &mut encoder,
                &mut decoder,
                &mut recv,
                &mut encode,
                &leftover,
                &[],
                reuse,
            )
            .await?;
            if reuse && client_may_pool(ends, &encode, &recv, &decoder) {
                Some(PooledConn {
                    stream: snell,
                    codec: PooledCodec::V4 { encoder, decoder },
                })
            } else {
                None
            }
        }
        PooledCodec::V6Shaped {
            mut encoder,
            mut decoder,
        } => {
            let ends = relay(
                &mut snell,
                local,
                &mut encoder,
                &mut decoder,
                &mut recv,
                &mut encode,
                &leftover,
                &[],
                reuse,
            )
            .await?;
            if reuse && client_may_pool(ends, &encode, &recv, &decoder) {
                Some(PooledConn {
                    stream: snell,
                    codec: PooledCodec::V6Shaped { encoder, decoder },
                })
            } else {
                None
            }
        }
        PooledCodec::V6Unshaped {
            mut encoder,
            mut decoder,
        } => {
            let ends = relay(
                &mut snell,
                local,
                &mut encoder,
                &mut decoder,
                &mut recv,
                &mut encode,
                &leftover,
                &[],
                reuse,
            )
            .await?;
            if reuse && client_may_pool(ends, &encode, &recv, &decoder) {
                Some(PooledConn {
                    stream: snell,
                    codec: PooledCodec::V6Unshaped { encoder, decoder },
                })
            } else {
                None
            }
        }
    };
    if let (Some(pool), Some(conn)) = (pool, back) {
        let _ = pool.put(conn);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn open_tunnel<E: TcpEncoder, D: TcpDecoder>(
    snell: &mut TcpStream,
    encoder: &mut E,
    decoder: &mut D,
    encode: &mut EncodeBuffer,
    recv: &mut RecvBuffer,
    destination: &Address,
    reuse: bool,
    kdf: &KdfLimiter,
    psk: &Psk,
) -> Result<Vec<u8>, SessionError> {
    set_nodelay(snell)?;
    with_handshake_timeout(async {
        write_connect(encoder, encode, snell, destination.as_view(), reuse).await?;
        read_server_tunnel(decoder, recv, snell, kdf, psk).await
    })
    .await
}

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use snell_protocol::socks5::Reply;
use snell_protocol::{
    Address, EncodeBuffer, ProtocolFlavor, Psk, RecvBuffer, V4Decoder, V4Encoder, V6ShapedDecoder,
    V6ShapedEncoder, V6UnshapedDecoder, V6UnshapedEncoder,
};
use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, debug, info, warn};

use crate::codec::{TcpDecoder, TcpEncoder};
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::platform::AcceptLoop;
use crate::pool::{PooledCodec, PooledConn, ReusePool};
use crate::session::{
    client_may_pool, new_encode, new_recv, read_server_tunnel, relay, with_handshake_timeout,
    write_connect,
};
use crate::socks::{Socks5Command, accept_socks5, socks5_reply_from_error, write_socks5_reply};
use crate::udp::{UdpHub, UdpOptions};
use crate::{bind_listener, connect_tcp, prepare_session_stream};

#[derive(Clone)]
pub struct ClientConfig {
    pub listen: SocketAddr,
    pub server: SocketAddr,
    pub psk: Psk,
    pub version: ProtocolFlavor,
    pub reuse: bool,
    pub pool: Option<ReusePool>,
    pub udp: UdpOptions,
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
            .field("udp", &self.udp)
            .finish()
    }
}

pub async fn run_client(config: ClientConfig) -> Result<(), SessionError> {
    let listener = bind_listener(config.listen).inspect_err(|error| {
        tracing::error!(error = %error, listen = %config.listen, "bind failed");
    })?;
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
    let hub = UdpHub::start(listener.local_addr()?, config.clone(), kdf.clone()).await?;
    let mut accept = AcceptLoop::new(&listener);
    let session_ids = AtomicU64::new(1);
    info!(listen = %listener.local_addr()?, "client started");
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("client shutting down");
                return Ok(());
            }
            accepted = accept.next() => {
                let (stream, peer) = accepted?;
                let config = config.clone();
                let kdf = kdf.clone();
                let pool = pool.clone();
                let hub = hub.clone();
                let id = session_ids.fetch_add(1, Ordering::Relaxed);
                let span = tracing::info_span!("session", id, peer = %peer);
                tokio::spawn(async move {
                    debug!("accepted");
                    match handle_client(stream, config, kdf, pool, hub).await {
                        Ok(()) => debug!("session finished"),
                        Err(error) if error.is_peer_closed() => {
                            debug!(error = %error, "session closed by peer");
                        }
                        Err(error) => {
                            warn!(error = %error, "session terminated with unexpected error");
                        }
                    }
                }.instrument(span));
            }
        }
    }
}

async fn handle_client(
    mut local: TcpStream,
    config: ClientConfig,
    kdf: Arc<KdfLimiter>,
    pool: Option<ReusePool>,
    hub: UdpHub,
) -> Result<(), SessionError> {
    prepare_session_stream(&local)?;
    match with_handshake_timeout(accept_socks5(&mut local)).await? {
        Socks5Command::Connect(destination) => {
            client_handshake_and_relay(&mut local, config, &destination, &kdf, pool.as_ref()).await
        }
        Socks5Command::UdpAssociate => hub.handle_associate(local).await,
    }
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
            debug!(
                pool_len = pool.len(),
                "checked out connection from reuse pool"
            );
            (conn.stream, conn.codec)
        } else {
            match dial_and_codec(config.server, &config.psk, config.version, kdf).await {
                Ok(pair) => pair,
                Err(error) => return Err(write_socks5_fail(local, error).await),
            }
        }
    } else {
        match dial_and_codec(config.server, &config.psk, config.version, kdf).await {
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
            from_pool = false;
            let (snell, codec) =
                match dial_and_codec(config.server, &config.psk, config.version, kdf).await {
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
    info!(
        target = %destination,
        version = ?config.version,
        reused = from_pool,
        "handshake completed, tunnel established"
    );
    finish_session(local, snell, codec, leftover, encode, recv, reuse, pool).await
}

pub(crate) async fn dial_and_codec(
    server: SocketAddr,
    psk: &Psk,
    version: ProtocolFlavor,
    kdf: &KdfLimiter,
) -> Result<(TcpStream, PooledCodec), SessionError> {
    let stream = connect_tcp(server).await?;
    let codec = new_codec(psk, version, kdf).await?;
    Ok((stream, codec))
}

async fn new_codec(
    psk: &Psk,
    version: ProtocolFlavor,
    kdf: &KdfLimiter,
) -> Result<PooledCodec, SessionError> {
    match version {
        ProtocolFlavor::V4 | ProtocolFlavor::V5 => {
            let psk_enc = psk.clone();
            let encoder = kdf.run(move || V4Encoder::os(&psk_enc)).await??;
            Ok(PooledCodec::V4 {
                encoder,
                decoder: V4Decoder::new(psk.clone()),
            })
        }
        ProtocolFlavor::V6Shaped => {
            let psk_enc = psk.clone();
            let encoder = kdf.run(move || V6ShapedEncoder::os(&psk_enc)).await??;
            let decoder = V6ShapedDecoder::new(psk.clone())?;
            Ok(PooledCodec::V6Shaped { encoder, decoder })
        }
        ProtocolFlavor::V6Unshaped => {
            let psk_enc = psk.clone();
            let encoder = kdf.run(move || V6UnshapedEncoder::os(&psk_enc)).await??;
            Ok(PooledCodec::V6Unshaped {
                encoder,
                decoder: V6UnshapedDecoder::new(psk.clone()),
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
    if let (Some(pool), Some(conn)) = (pool, back)
        && pool.put(conn)
    {
        debug!(pool_len = pool.len(), "returned connection to reuse pool");
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
    prepare_session_stream(snell)?;
    with_handshake_timeout(async {
        write_connect(encoder, encode, snell, destination.as_view(), reuse).await?;
        read_server_tunnel(decoder, recv, snell, kdf, psk).await
    })
    .await
}

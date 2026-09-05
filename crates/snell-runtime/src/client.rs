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
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{Instrument, debug, info, warn};

use crate::admission::Handshake;
use crate::codec::{TcpDecoder, TcpEncoder};
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::platform::{AcceptLoop, prepare_session_stream};
use crate::pool::{PooledCodec, PooledConn, ReusePool};
use crate::session::{
    client_may_pool, new_encode, new_recv, read_server_tunnel, relay, write_connect,
};
use crate::socks::{Socks5Command, accept_socks5, socks5_reply_from_error, write_socks5_reply};
use crate::udp::{UdpHub, UdpOptions};
use crate::{bind_listener, connect_tcp};

#[derive(Clone)]
pub struct ClientConfig {
    pub limits: crate::TcpLimits,
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
            .field("limits", &self.limits)
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
    config.limits.validate()?;
    let config = Arc::new(config);
    tokio::pin!(shutdown);
    let handshakes = Arc::new(Semaphore::new(config.limits.max_handshakes));
    let mut sessions = JoinSet::new();
    let kdf = Arc::new(KdfLimiter::new());
    let pool = if config.reuse {
        Some(config.pool.clone().unwrap_or_default())
    } else {
        None
    };
    let hub = UdpHub::start(listener.local_addr()?, &config, kdf.clone()).await?;
    let mut accept = AcceptLoop::new(&listener);
    let session_ids = AtomicU64::new(1);
    info!(listen = %listener.local_addr()?, "client started");
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("client shutting down");
                sessions.shutdown().await;
                return Ok(());
            }
            joined = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Err(error)) = joined { warn!(%error, "session task failed"); }
            }
            _ = async { if let Some(pool) = &pool { pool.expire_idle().await; } else { std::future::pending().await } } => {}
            accepted = accept.next() => {
                let (stream, peer) = accepted?;
                if sessions.len() >= config.limits.max_connections { continue; }
                let Ok(permit) = handshakes.clone().try_acquire_owned() else { continue; };
                let handshake = Handshake::new(Some(permit));
                let config = config.clone();
                let kdf = kdf.clone();
                let pool = pool.clone();
                let hub = hub.clone();
                let id = session_ids.fetch_add(1, Ordering::Relaxed);
                let span = tracing::info_span!("session", id, peer = %peer);
                sessions.spawn(async move {
                    debug!("accepted");
                    match handle_client(stream, config, kdf, pool, hub, handshake).await {
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
    config: Arc<ClientConfig>,
    kdf: Arc<KdfLimiter>,
    pool: Option<ReusePool>,
    hub: UdpHub,
    handshake: Handshake,
) -> Result<(), SessionError> {
    prepare_session_stream(&local)?;
    match handshake.run(accept_socks5(&mut local)).await?? {
        Socks5Command::Connect(destination) => {
            client_handshake_and_relay(
                &mut local,
                &config,
                &destination,
                &kdf,
                pool.as_ref(),
                handshake,
            )
            .await
        }
        Socks5Command::UdpAssociate => hub.handle_associate(local, handshake).await,
    }
}

async fn client_handshake_and_relay(
    local: &mut TcpStream,
    config: &ClientConfig,
    destination: &Address,
    kdf: &KdfLimiter,
    pool: Option<&ReusePool>,
    mut handshake: Handshake,
) -> Result<(), SessionError> {
    let reuse = pool.is_some();
    let setup = handshake
        .run(async {
            let mut pooled = pool.and_then(ReusePool::take);
            let (opened, from_pool) = loop {
                let from_pool = pooled.is_some();
                let (snell, codec) = match pooled.take() {
                    Some(conn) => (conn.stream, conn.codec),
                    None => dial_and_codec(config.server, &config.psk, config.version, kdf).await?,
                };
                match open_session(snell, codec, destination, reuse, kdf, &config.psk).await {
                    // The single pool entry is consumed, so only one retry is possible.
                    Err(error) if from_pool && error.is_stale_pool_error() => continue,
                    result => break (result?, from_pool),
                }
            };
            write_socks5_reply(local, Reply::Succeeded).await?;
            Ok((opened, from_pool))
        })
        .await?;
    let (opened, from_pool) = match setup {
        Ok(opened) => opened,
        Err(error) => {
            let _ = handshake
                .run(write_socks5_reply(local, socks5_reply_from_error(&error)))
                .await?;
            return Err(error);
        }
    };
    handshake.finish();
    info!(target = %destination, version = ?config.version, reused = from_pool,
        "handshake completed, tunnel established");
    let Opened {
        snell,
        codec,
        leftover,
        encode,
        recv,
    } = opened;
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
    mut codec: PooledCodec,
    leftover: Vec<u8>,
    mut encode: EncodeBuffer,
    mut recv: RecvBuffer,
    reuse: bool,
    pool: Option<&ReusePool>,
) -> Result<(), SessionError> {
    let may_pool = match &mut codec {
        PooledCodec::V4 { encoder, decoder } => {
            relay(
                &mut snell,
                local,
                encoder,
                decoder,
                &mut recv,
                &mut encode,
                leftover,
                false,
                reuse,
            )
            .await?;
            client_may_pool(&encode, &recv, decoder)
        }
        PooledCodec::V6Shaped { encoder, decoder } => {
            relay(
                &mut snell,
                local,
                encoder,
                decoder,
                &mut recv,
                &mut encode,
                leftover,
                false,
                reuse,
            )
            .await?;
            client_may_pool(&encode, &recv, decoder)
        }
        PooledCodec::V6Unshaped { encoder, decoder } => {
            relay(
                &mut snell,
                local,
                encoder,
                decoder,
                &mut recv,
                &mut encode,
                leftover,
                false,
                reuse,
            )
            .await?;
            client_may_pool(&encode, &recv, decoder)
        }
    };
    if reuse
        && may_pool
        && let Some(pool) = pool
        && pool.put(PooledConn {
            stream: snell,
            codec,
        })
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
    write_connect(encoder, encode, snell, destination.as_view(), reuse).await?;
    read_server_tunnel(decoder, recv, snell, kdf, psk).await
}

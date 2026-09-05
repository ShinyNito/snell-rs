use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use snell_protocol::{
    EncodeBuffer, ProtocolFlavor, ProtocolSelection, Psk, RecvBuffer, V4Decoder, V4Encoder,
    V6ShapedDecoder, V6ShapedEncoder, V6UnshapedDecoder, V6UnshapedEncoder,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{Instrument, debug, info, warn};

use crate::admission::Handshake;
use crate::auto::{Detected, detect_protocol};
use crate::bind_listener;
use crate::codec::{TcpDecoder, TcpEncoder};
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::outbound::Outbound;
use crate::platform::{self, AcceptLoop, TcpBrutal, prepare_session_stream};
use crate::replay::ReplayCache;
use crate::session::{
    ServerFirst, new_encode, new_recv, read_server_connect, relay, server_may_reuse,
    wait_reuse_idle, write_reject, write_tunnel,
};
use crate::udp::{UdpOptions, run_server_udp};

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub limits: crate::TcpLimits,
    pub listen: SocketAddr,
    pub psk: Psk,
    pub selection: ProtocolSelection,
    pub outbound: Outbound,
    pub udp: UdpOptions,
    pub tcp_brutal: Option<TcpBrutal>,
}

pub async fn run_server(config: ServerConfig) -> Result<(), SessionError> {
    let listener = bind_listener(config.listen).inspect_err(|error| {
        tracing::error!(error = %error, listen = %config.listen, "bind failed");
    })?;
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
    // Select before spawning: exact sessions never carry all probe/codec
    // variants in every per-connection future allocation.
    match config.selection {
        ProtocolSelection::Exact(ProtocolFlavor::V4 | ProtocolFlavor::V5) => {
            serve_with(
                listener,
                config,
                shutdown,
                handle_exact::<V4Encoder, V4Decoder>,
            )
            .await
        }
        ProtocolSelection::Exact(ProtocolFlavor::V6Shaped) => {
            serve_with(
                listener,
                config,
                shutdown,
                handle_exact::<V6ShapedEncoder, V6ShapedDecoder>,
            )
            .await
        }
        ProtocolSelection::Exact(ProtocolFlavor::V6Unshaped) => {
            serve_with(
                listener,
                config,
                shutdown,
                handle_exact::<V6UnshapedEncoder, V6UnshapedDecoder>,
            )
            .await
        }
        ProtocolSelection::Auto => serve_with(listener, config, shutdown, handle_auto).await,
    }
}

async fn serve_with<H, F>(
    listener: TcpListener,
    config: ServerConfig,
    shutdown: impl Future<Output = ()>,
    handle: H,
) -> Result<(), SessionError>
where
    H: Fn(TcpStream, Arc<ServerConfig>, Arc<KdfLimiter>, Arc<ReplayCache>, Handshake) -> F
        + Copy
        + Send
        + 'static,
    F: Future<Output = Result<(), SessionError>> + Send + 'static,
{
    config.limits.validate()?;
    let config = Arc::new(config);
    tokio::pin!(shutdown);
    let handshakes = Arc::new(Semaphore::new(config.limits.max_handshakes));
    let mut sessions = JoinSet::new();
    let kdf = Arc::new(KdfLimiter::new());
    let replay = Arc::new(ReplayCache::new());
    let mut accept = AcceptLoop::new(&listener);
    let session_ids = AtomicU64::new(1);
    info!(listen = %listener.local_addr()?, "server started");
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("server shutting down");
                sessions.shutdown().await;
                return Ok(());
            }
            joined = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Err(error)) = joined { warn!(%error, "session task failed"); }
            }
            accepted = accept.next() => {
                let (stream, peer) = accepted?;
                if sessions.len() >= config.limits.max_connections { continue; }
                let Ok(permit) = handshakes.clone().try_acquire_owned() else { continue; };
                let handshake = Handshake::new(Some(permit));
                let config = config.clone();
                let kdf = kdf.clone();
                let replay = replay.clone();
                let id = session_ids.fetch_add(1, Ordering::Relaxed);
                let span = tracing::info_span!("session", id, peer = %peer);
                sessions.spawn(async move {
                    debug!("accepted");
                    match handle(stream, config, kdf, replay, handshake).await {
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

fn prepare_server_stream(snell: &TcpStream, config: &ServerConfig) -> Result<(), SessionError> {
    prepare_session_stream(snell)?;
    if let Some(params) = config.tcp_brutal
        && let Err(error) = platform::apply_tcp_brutal(snell, params)
    {
        warn!(error = %error, "tcp_brutal unavailable; continuing without it");
    }
    Ok(())
}

async fn handle_exact<E: TcpEncoder + Send + 'static, D: TcpDecoder + Send>(
    mut snell: TcpStream,
    config: Arc<ServerConfig>,
    kdf: Arc<KdfLimiter>,
    replay: Arc<ReplayCache>,
    handshake: Handshake,
) -> Result<(), SessionError> {
    prepare_server_stream(&snell, &config)?;
    let mut recv = new_recv();
    let mut decoder = D::from_psk(config.psk.clone())?;
    let mut first = handshake
        .run(read_server_connect(
            &mut decoder,
            &mut recv,
            &mut snell,
            &kdf,
            &config.psk,
            Some(&replay),
        ))
        .await??;
    let psk = config.psk.clone();
    let mut encoder = handshake
        .run(kdf.run(move || E::from_psk(&psk)))
        .await???;
    server_session(
        &mut snell,
        &mut encoder,
        &mut decoder,
        config.outbound,
        &kdf,
        &config.psk,
        &mut recv,
        &mut new_encode(),
        &mut first,
        handshake,
        &config.udp,
    )
    .await
}

async fn handle_auto(
    mut snell: TcpStream,
    config: Arc<ServerConfig>,
    kdf: Arc<KdfLimiter>,
    replay: Arc<ReplayCache>,
    handshake: Handshake,
) -> Result<(), SessionError> {
    prepare_server_stream(&snell, &config)?;
    let mut detected = handshake
        .run(detect_protocol(
            &mut snell,
            config.psk.clone(),
            &kdf,
            &replay,
        ))
        .await??;
    match &mut detected {
        Detected::V4 {
            encoder,
            decoder,
            recv,
            first,
        } => {
            server_session(
                &mut snell,
                encoder,
                decoder,
                config.outbound,
                &kdf,
                &config.psk,
                recv,
                &mut new_encode(),
                first,
                handshake,
                &config.udp,
            )
            .await
        }
        Detected::V6Shaped {
            encoder,
            decoder,
            recv,
            first,
        } => {
            server_session(
                &mut snell,
                encoder,
                decoder,
                config.outbound,
                &kdf,
                &config.psk,
                recv,
                &mut new_encode(),
                first,
                handshake,
                &config.udp,
            )
            .await
        }
    }
}

// Test harnesses that count accepted sockets use the same production handlers.
#[cfg(test)]
pub(crate) async fn handle_server(
    snell: TcpStream,
    config: Arc<ServerConfig>,
    kdf: Arc<KdfLimiter>,
    replay: Arc<ReplayCache>,
    handshake: Handshake,
) -> Result<(), SessionError> {
    match config.selection {
        ProtocolSelection::Exact(ProtocolFlavor::V4 | ProtocolFlavor::V5) => {
            handle_exact::<V4Encoder, V4Decoder>(snell, config, kdf, replay, handshake).await
        }
        ProtocolSelection::Exact(ProtocolFlavor::V6Shaped) => {
            handle_exact::<V6ShapedEncoder, V6ShapedDecoder>(snell, config, kdf, replay, handshake)
                .await
        }
        ProtocolSelection::Exact(ProtocolFlavor::V6Unshaped) => {
            handle_exact::<V6UnshapedEncoder, V6UnshapedDecoder>(
                snell, config, kdf, replay, handshake,
            )
            .await
        }
        ProtocolSelection::Auto => handle_auto(snell, config, kdf, replay, handshake).await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn server_session<E: TcpEncoder, D: TcpDecoder>(
    snell: &mut TcpStream,
    encoder: &mut E,
    decoder: &mut D,
    outbound: Outbound,
    kdf: &KdfLimiter,
    psk: &Psk,
    recv: &mut RecvBuffer,
    encode: &mut EncodeBuffer,
    command: &mut ServerFirst,
    mut handshake: Handshake,
    udp: &UdpOptions,
) -> Result<(), SessionError> {
    let mut reused = false;
    recv.raise_limit(snell_protocol::V6_WIRE_CAP);
    loop {
        let connect = match command {
            ServerFirst::Connect(connect) => connect,
            ServerFirst::Udp => {
                return run_server_udp(
                    snell, encoder, decoder, outbound, kdf, psk, recv, encode, udp, handshake,
                )
                .await;
            }
        };

        let mut remote = match handshake
            .run(async {
                let remote = outbound.connect(&connect.destination).await?;
                write_tunnel(encoder, encode, snell).await?;
                Ok(remote)
            })
            .await?
        {
            Ok(remote) => remote,
            Err(error) => {
                let _ = handshake
                    .run(write_reject(encoder, encode, snell, &error.to_string()))
                    .await?;
                return Err(error);
            }
        };
        handshake.finish();
        info!(
            target = %connect.destination,
            reused,
            "handshake completed, tunnel established"
        );

        relay(
            snell,
            &mut remote,
            encoder,
            decoder,
            recv,
            encode,
            std::mem::take(&mut connect.leftover),
            connect.early_eof,
            connect.reuse,
        )
        .await?;
        if !connect.reuse {
            return Ok(());
        }
        if !server_may_reuse(encode, decoder) {
            return Ok(());
        }
        wait_reuse_idle(snell, recv, encode).await?;
        handshake = Handshake::new(None);
        *command = handshake
            .run(read_server_connect(decoder, recv, snell, kdf, psk, None))
            .await??;
        reused = true;
    }
}

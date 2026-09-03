use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use snell_protocol::{
    EncodeBuffer, ProtocolFlavor, ProtocolSelection, Psk, RecvBuffer, V4Decoder, V4Encoder,
    V6ShapedDecoder, V6ShapedEncoder, V6UnshapedDecoder, V6UnshapedEncoder,
};
use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, debug, info, warn};

use crate::auto::{Detected, detect_protocol};
use crate::codec::{TcpDecoder, TcpEncoder};
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::outbound::Outbound;
use crate::platform::{self, AcceptLoop, TcpBrutal};
use crate::replay::ReplayCache;
use crate::session::{
    ServerFirst, ensure_bulk, new_encode, new_recv, read_server_connect, relay, release_bulk,
    server_may_reuse, wait_reuse_idle, with_handshake_timeout, write_reject, write_tunnel,
};
use crate::udp::{UdpOptions, run_server_udp};
use crate::{bind_listener, prepare_session_stream};

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub psk: Psk,
    pub selection: ProtocolSelection,
    pub outbound: Outbound,
    pub udp: UdpOptions,
    pub tcp_brutal: Option<TcpBrutal>,
}

pub async fn run_server(config: ServerConfig) -> Result<(), SessionError> {
    let listener = match bind_listener(config.listen) {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(error = %error, listen = %config.listen, "bind failed");
            return Err(error.into());
        }
    };
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
    if let Some(params) = config.tcp_brutal {
        platform::require_tcp_brutal(params)?;
    }
    tokio::pin!(shutdown);
    let kdf = Arc::new(KdfLimiter::new());
    let replay = Arc::new(ReplayCache::new());
    let mut accept = AcceptLoop::new(&listener);
    let session_ids = AtomicU64::new(1);
    info!(listen = %listener.local_addr()?, "server started");
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("server shutting down");
                return Ok(());
            }
            accepted = accept.next() => {
                let (stream, peer) = accepted?;
                let config = config.clone();
                let kdf = kdf.clone();
                let replay = replay.clone();
                let id = session_ids.fetch_add(1, Ordering::Relaxed);
                let span = tracing::info_span!("session", id, peer = %peer);
                tokio::spawn(async move {
                    debug!("accepted");
                    match handle_server(stream, config, kdf, replay).await {
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

pub(crate) async fn handle_server(
    snell: TcpStream,
    config: ServerConfig,
    kdf: Arc<KdfLimiter>,
    replay: Arc<ReplayCache>,
) -> Result<(), SessionError> {
    prepare_session_stream(&snell)?;
    if let Some(params) = config.tcp_brutal {
        platform::apply_tcp_brutal(&snell, params)?;
    }
    match config.selection {
        ProtocolSelection::Exact(ProtocolFlavor::V4 | ProtocolFlavor::V5) => {
            let psk = config.psk.clone();
            let encoder = kdf.run(move || V4Encoder::os(&psk)).await??;
            let decoder = V4Decoder::new(config.psk.clone());
            server_session(
                snell,
                encoder,
                decoder,
                config.outbound,
                &kdf,
                &config.psk,
                None,
                new_recv(),
                new_encode(),
                None,
                &config.udp,
            )
            .await
        }
        ProtocolSelection::Exact(ProtocolFlavor::V6Shaped) => {
            let psk = config.psk.clone();
            let encoder = kdf.run(move || V6ShapedEncoder::os(&psk)).await??;
            let decoder = V6ShapedDecoder::new(config.psk.clone())?;
            server_session(
                snell,
                encoder,
                decoder,
                config.outbound,
                &kdf,
                &config.psk,
                Some(replay.as_ref()),
                new_recv(),
                new_encode(),
                None,
                &config.udp,
            )
            .await
        }
        ProtocolSelection::Exact(ProtocolFlavor::V6Unshaped) => {
            let psk = config.psk.clone();
            let encoder = kdf.run(move || V6UnshapedEncoder::os(&psk)).await??;
            let decoder = V6UnshapedDecoder::new(config.psk.clone());
            server_session(
                snell,
                encoder,
                decoder,
                config.outbound,
                &kdf,
                &config.psk,
                Some(replay.as_ref()),
                new_recv(),
                new_encode(),
                None,
                &config.udp,
            )
            .await
        }
        ProtocolSelection::Auto => {
            let mut snell = snell;
            match detect_protocol(&mut snell, config.psk.clone(), &kdf, &replay).await? {
                Detected::V4 {
                    encoder,
                    decoder,
                    recv,
                    first,
                } => {
                    server_session(
                        snell,
                        encoder,
                        decoder,
                        config.outbound,
                        &kdf,
                        &config.psk,
                        None,
                        recv,
                        new_encode(),
                        Some(first),
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
                        snell,
                        encoder,
                        decoder,
                        config.outbound,
                        &kdf,
                        &config.psk,
                        None,
                        recv,
                        new_encode(),
                        Some(first),
                        &config.udp,
                    )
                    .await
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn server_session<E: TcpEncoder, D: TcpDecoder>(
    mut snell: TcpStream,
    mut encoder: E,
    mut decoder: D,
    outbound: Outbound,
    kdf: &KdfLimiter,
    psk: &Psk,
    mut replay: Option<&ReplayCache>,
    mut recv: RecvBuffer,
    mut encode: EncodeBuffer,
    mut pending: Option<ServerFirst>,
    udp: &UdpOptions,
) -> Result<(), SessionError> {
    let mut first = true;
    loop {
        let connect = if let Some(first_cmd) = pending.take() {
            match first_cmd {
                ServerFirst::Connect(connect) => connect,
                ServerFirst::Udp => {
                    return run_server_udp(
                        snell, encoder, decoder, outbound, kdf, psk, recv, encode, udp,
                    )
                    .await;
                }
            }
        } else {
            if !first {
                wait_reuse_idle(&mut snell, &mut recv).await?;
            }
            match with_handshake_timeout(read_server_connect(
                &mut decoder,
                &mut recv,
                &mut snell,
                kdf,
                psk,
                replay,
            ))
            .await
            {
                Ok(ServerFirst::Connect(connect)) => connect,
                Ok(ServerFirst::Udp) => {
                    return run_server_udp(
                        snell, encoder, decoder, outbound, kdf, psk, recv, encode, udp,
                    )
                    .await;
                }
                Err(error) => return Err(error),
            }
        };
        let reused = !first;
        first = false;
        replay = None;

        let mut remote = match with_handshake_timeout(async {
            let remote = outbound.connect(&connect.destination).await?;
            write_tunnel(&mut encoder, &mut encode, &mut snell).await?;
            Ok(remote)
        })
        .await
        {
            Ok(remote) => remote,
            Err(error) => {
                let _ =
                    write_reject(&mut encoder, &mut encode, &mut snell, &error.to_string()).await;
                return Err(error);
            }
        };
        info!(
            target = %connect.destination,
            reused,
            "handshake completed, tunnel established"
        );

        recv = ensure_bulk(recv)?;
        encode = new_encode();
        let ends = relay(
            &mut snell,
            &mut remote,
            &mut encoder,
            &mut decoder,
            &mut recv,
            &mut encode,
            &connect.leftover,
            &[],
            connect.reuse,
        )
        .await?;
        if !connect.reuse {
            return Ok(());
        }
        if !server_may_reuse(ends, &encode, &decoder) {
            return Ok(());
        }
        let released = release_bulk(recv, encode)?;
        recv = released.0;
        encode = released.1;
    }
}

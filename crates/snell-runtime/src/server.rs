use crate::buffer::{BufferPool, OwnedBuffer};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use snell_protocol::{
    Error as ProtocolError, ProtocolFlavor, ProtocolSelection, Psk, V4Decoder, V4Encoder,
    V6ShapedDecoder, V6ShapedEncoder, V6UnshapedDecoder, V6UnshapedEncoder,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{Instrument, debug, info, warn};

use crate::auto::{Detected, detect_protocol};
use crate::bind_listener;
use crate::codec::{TcpDecoder, TcpEncoder};
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::outbound::Outbound;
use crate::platform::{self, AcceptLoop, TcpBrutal, prepare_session_stream};
use crate::replay::ReplayCache;
use crate::session::{
    ServerConnect, ServerFirst, read_server_connect, relay, server_may_reuse, wait_reuse_idle,
    with_handshake_timeout, write_reject, write_tunnel,
};
use crate::udp::{UdpOptions, run_server_udp};

// Admission applies only until the first request has authenticated.
const SERVER_MAX_HANDSHAKES: usize = 512;

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub psk: Psk,
    pub selection: ProtocolSelection,
    pub outbound: Outbound,
    pub udp: UdpOptions,
    pub buffers: Arc<BufferPool>,
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
    tokio::pin!(shutdown);
    let kdf = Arc::new(KdfLimiter::new());
    let replay = Arc::new(ReplayCache::new());
    let mut accept = AcceptLoop::new(&listener);
    let handshakes = Arc::new(Semaphore::new(SERVER_MAX_HANDSHAKES));
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
                let Ok(handshake) = handshakes.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let config = config.clone();
                let kdf = kdf.clone();
                let replay = replay.clone();
                let id = session_ids.fetch_add(1, Ordering::Relaxed);
                let span = tracing::info_span!("session", id, peer = %peer);
                tokio::spawn(async move {
                    debug!("accepted");
                    match handle_server(stream, config, kdf, replay, handshake).await {
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
    mut snell: TcpStream,
    config: ServerConfig,
    kdf: Arc<KdfLimiter>,
    replay: Arc<ReplayCache>,
    handshake: OwnedSemaphorePermit,
) -> Result<(), SessionError> {
    prepare_session_stream(&snell)?;
    if let Some(params) = config.tcp_brutal
        && let Err(error) = platform::apply_tcp_brutal(&snell, params)
    {
        warn!(error = %error, "tcp_brutal unavailable; continuing without it");
    }
    match config.selection {
        ProtocolSelection::Exact(ProtocolFlavor::V4 | ProtocolFlavor::V5) => {
            let psk = config.psk.clone();
            let decoder = V4Decoder::new(config.psk.clone());
            exact_session(snell, decoder, config, &kdf, None, handshake, move || {
                V4Encoder::os(&psk)
            })
            .await
        }
        ProtocolSelection::Exact(ProtocolFlavor::V6Shaped) => {
            let psk = config.psk.clone();
            let decoder = V6ShapedDecoder::new(config.psk.clone())?;
            exact_session(
                snell,
                decoder,
                config,
                &kdf,
                Some(replay.as_ref()),
                handshake,
                move || V6ShapedEncoder::os(&psk),
            )
            .await
        }
        ProtocolSelection::Exact(ProtocolFlavor::V6Unshaped) => {
            let psk = config.psk.clone();
            let decoder = V6UnshapedDecoder::new(config.psk.clone());
            exact_session(
                snell,
                decoder,
                config,
                &kdf,
                Some(replay.as_ref()),
                handshake,
                move || V6UnshapedEncoder::os(&psk),
            )
            .await
        }
        ProtocolSelection::Auto => {
            let detected = detect_protocol(
                &mut snell,
                config.psk.clone(),
                &kdf,
                &replay,
                &config.buffers,
            )
            .await?;
            drop(handshake);
            match detected {
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
                        recv,
                        OwnedBuffer::new(&config.buffers, snell_protocol::V6_WIRE_CAP),
                        first,
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
                        recv,
                        OwnedBuffer::new(&config.buffers, snell_protocol::V6_WIRE_CAP),
                        first,
                        &config.udp,
                    )
                    .await
                }
            }
        }
    }
}

// All exact flavors authenticate before deriving a response key, under one deadline.
async fn exact_session<E, D, F>(
    mut snell: TcpStream,
    mut decoder: D,
    config: ServerConfig,
    kdf: &KdfLimiter,
    replay: Option<&ReplayCache>,
    handshake: OwnedSemaphorePermit,
    make_encoder: F,
) -> Result<(), SessionError>
where
    D: TcpDecoder,
    E: TcpEncoder + Send + 'static,
    F: FnOnce() -> Result<E, ProtocolError> + Send + 'static,
{
    let mut recv = OwnedBuffer::new(&config.buffers, snell_protocol::V6_WIRE_CAP);
    let (first, encoder) = with_handshake_timeout(async {
        let first = read_server_connect(
            &mut decoder,
            &mut recv,
            &mut snell,
            kdf,
            &config.psk,
            replay,
        )
        .await?;
        let encoder = kdf.run(make_encoder).await??;
        Ok((first, encoder))
    })
    .await?;
    drop(handshake);
    server_session(
        snell,
        encoder,
        decoder,
        config.outbound,
        kdf,
        &config.psk,
        recv,
        OwnedBuffer::new(&config.buffers, snell_protocol::V6_WIRE_CAP),
        first,
        &config.udp,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn server_session<E: TcpEncoder, D: TcpDecoder>(
    mut snell: TcpStream,
    mut encoder: E,
    mut decoder: D,
    outbound: Outbound,
    kdf: &KdfLimiter,
    psk: &Psk,
    mut recv: OwnedBuffer,
    mut encode: OwnedBuffer,
    mut command: ServerFirst,
    udp: &UdpOptions,
) -> Result<(), SessionError> {
    let mut reused = false;
    loop {
        let connect = match command {
            ServerFirst::Connect(connect) => connect,
            ServerFirst::Udp => {
                return run_server_udp(
                    snell, encoder, decoder, outbound, kdf, psk, recv, encode, udp,
                )
                .await;
            }
        };
        let ServerConnect {
            destination,
            leftover,
            reuse,
        } = connect;

        let mut remote = match with_handshake_timeout(async {
            let remote = outbound.connect(&destination).await?;
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
            target = %destination,
            reused,
            "handshake completed, tunnel established"
        );

        drop(destination);
        relay(
            &mut snell,
            &mut remote,
            &mut encoder,
            &mut decoder,
            &mut recv,
            &mut encode,
            leftover,
            reuse,
        )
        .await?;
        if !reuse {
            return Ok(());
        }
        if !server_may_reuse(&encode, &decoder) {
            return Ok(());
        }
        recv.release_empty();
        encode.release_empty();
        wait_reuse_idle(&mut snell, &mut recv).await?;
        command = with_handshake_timeout(read_server_connect(
            &mut decoder,
            &mut recv,
            &mut snell,
            kdf,
            psk,
            None,
        ))
        .await?;
        reused = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::{Context, Waker};

    #[tokio::test]
    async fn silent_peer_does_not_queue_response_kdf() {
        for flavor in [
            ProtocolFlavor::V4,
            ProtocolFlavor::V6Shaped,
            ProtocolFlavor::V6Unshaped,
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let _peer = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let kdf = Arc::new(KdfLimiter::new());
            let _blocked = kdf.block_for_test();
            let buffers = Arc::new(BufferPool::default());
            let config = ServerConfig {
                listen: listener.local_addr().unwrap(),
                psk: Psk::new(b"0123456789abcdef").unwrap(),
                selection: ProtocolSelection::Exact(flavor),
                outbound: Outbound::Direct,
                udp: UdpOptions::default(),
                buffers: buffers.clone(),
                tcp_brutal: None,
            };
            let handshakes = Arc::new(Semaphore::new(1));
            let mut session = Box::pin(handle_server(
                stream,
                config,
                kdf.clone(),
                Arc::new(ReplayCache::new()),
                handshakes.clone().try_acquire_owned().unwrap(),
            ));
            assert!(
                session
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            assert_eq!(
                kdf.queued_for_test(),
                0,
                "{flavor:?}: no response KDF before request"
            );
            assert_eq!(buffers.stats().leased_bytes, 0);
            assert_eq!(handshakes.available_permits(), 0);
            drop(session);
            assert_eq!(handshakes.available_permits(), 1);
        }
    }

    #[tokio::test]
    async fn authenticated_relay_releases_handshake_permit() {
        use crate::session::{read_server_tunnel, write_connect};
        for selection in [
            ProtocolSelection::Exact(ProtocolFlavor::V4),
            ProtocolSelection::Auto,
        ] {
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut peer = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let psk = Psk::new(b"0123456789abcdef").unwrap();
            let buffers = Arc::new(BufferPool::default());
            let handshakes = Arc::new(Semaphore::new(1));
            let config = ServerConfig {
                listen: listener.local_addr().unwrap(),
                psk: psk.clone(),
                selection,
                outbound: Outbound::Direct,
                udp: UdpOptions::default(),
                buffers: buffers.clone(),
                tcp_brutal: None,
            };
            let task = tokio::spawn(handle_server(
                stream,
                config,
                Arc::new(KdfLimiter::new()),
                Arc::new(ReplayCache::new()),
                handshakes.clone().try_acquire_owned().unwrap(),
            ));
            let mut encoder = V4Encoder::os(&psk).unwrap();
            let mut decoder = V4Decoder::new(psk.clone());
            let client_buffers = Arc::new(BufferPool::default());
            let mut send = OwnedBuffer::new(&client_buffers, snell_protocol::V6_WIRE_CAP);
            let mut recv = OwnedBuffer::new(&client_buffers, snell_protocol::V6_WIRE_CAP);
            let target = snell_protocol::Address::from(upstream.local_addr().unwrap());
            write_connect(&mut encoder, &mut send, &mut peer, target.as_view(), false)
                .await
                .unwrap();
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                read_server_tunnel(&mut decoder, &mut recv, &mut peer, &KdfLimiter::new(), &psk),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(!task.is_finished(), "relay must still be alive");
            assert_eq!(handshakes.available_permits(), 1);
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert_eq!(buffers.stats().leased_bytes, 0);
        }
    }
}

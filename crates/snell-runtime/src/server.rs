use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use snell_protocol::{
    ConnectRequest, Error as ProtocolError, ProtocolFlavor, ProtocolSelection, Psk, RecordDecoder,
    RecordEncoder, V4Decoder, V4Encoder, V6ShapedDecoder, V6ShapedEncoder, V6UnshapedDecoder,
    V6UnshapedEncoder,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{Instrument, debug, info, warn};

use crate::auto::detect_protocol;
use crate::bind_listener;
use crate::buffer::{BufferPool, PooledBuffer};
use crate::codec::with_codec;
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::outbound::Outbound;
use crate::platform::{self, AcceptLoop, TcpBrutal, prepare_session_stream};
use crate::replay::ReplayCache;
use crate::session::{
    ServerFirst, read_server_connect, relay, wait_reuse_idle, with_handshake_timeout, write_reject,
    write_tunnel,
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
    let config = Arc::new(config);
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
                let Ok(handshake) = Arc::clone(&handshakes).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let config = Arc::clone(&config);
                let kdf = Arc::clone(&kdf);
                let replay = Arc::clone(&replay);
                let id = session_ids.fetch_add(1, Ordering::Relaxed);
                let span = tracing::info_span!("session", id, peer = %peer);
                tokio::spawn(async move {
                    debug!("accepted");
                    match handle_server(stream, &config, &kdf, &replay, handshake).await {
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
    config: &ServerConfig,
    kdf: &KdfLimiter,
    replay: &ReplayCache,
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
            let session = ExactSession {
                make_decoder: V4Decoder::new,
                make_encoder: V4Encoder::os,
                replay: None,
            };
            session.run(snell, config, kdf, handshake).await
        }
        ProtocolSelection::Exact(ProtocolFlavor::V6Shaped) => {
            let session = ExactSession {
                make_decoder: V6ShapedDecoder::new,
                make_encoder: V6ShapedEncoder::os,
                replay: Some(replay),
            };
            session.run(snell, config, kdf, handshake).await
        }
        ProtocolSelection::Exact(ProtocolFlavor::V6Unshaped) => {
            let session = ExactSession {
                make_decoder: V6UnshapedDecoder::new,
                make_encoder: V6UnshapedEncoder::os,
                replay: Some(replay),
            };
            session.run(snell, config, kdf, handshake).await
        }
        ProtocolSelection::Auto => auto_session(snell, config, kdf, replay, handshake).await,
    }
}

async fn auto_session(
    mut snell: TcpStream,
    config: &ServerConfig,
    kdf: &KdfLimiter,
    replay: &ReplayCache,
    handshake: OwnedSemaphorePermit,
) -> Result<(), SessionError> {
    // Boxed: detection state is large and needed only until the first request
    // authenticates, not for the session's lifetime.
    let detect = detect_protocol(&mut snell, &config.psk, kdf, replay, &config.buffers);
    let (mut codec, recv, first) = Box::pin(detect).await?;
    drop(handshake);
    with_codec!(&mut codec, |encoder, decoder| {
        server_session(snell, encoder, decoder, config, kdf, recv, first).await
    })
}

/// One exact flavor: how to build its codec, and whether salts are replay-checked.
struct ExactSession<'a, D, E> {
    make_decoder: fn(Psk) -> D,
    make_encoder: fn(&Psk) -> Result<E, ProtocolError>,
    replay: Option<&'a ReplayCache>,
}

impl<D: RecordDecoder, E: RecordEncoder + Send + 'static> ExactSession<'_, D, E> {
    /// Authenticate the first request, then derive the response key, under
    /// one deadline. The codec is built here rather than passed in, so the
    /// future holds a single copy of it.
    async fn run(
        self,
        mut snell: TcpStream,
        config: &ServerConfig,
        kdf: &KdfLimiter,
        handshake: OwnedSemaphorePermit,
    ) -> Result<(), SessionError> {
        let mut decoder = (self.make_decoder)(config.psk.clone());
        let mut recv = config.buffers.get(snell_protocol::V6_WIRE_CAP);
        let (first, mut encoder) = with_handshake_timeout(async {
            let first = read_server_connect(
                &mut decoder,
                &mut recv,
                &mut snell,
                kdf,
                &config.psk,
                self.replay,
            )
            .await?;
            let encoder = kdf.derive(&config.psk, self.make_encoder).await?;
            Ok((first, encoder))
        })
        .await?;
        drop(handshake);
        server_session(snell, &mut encoder, &mut decoder, config, kdf, recv, first).await
    }
}

/// Serve requests on an authenticated session: UDP, or CONNECTs until the
/// client stops reusing the connection.
async fn server_session<E: RecordEncoder, D: RecordDecoder>(
    mut snell: TcpStream,
    encoder: &mut E,
    decoder: &mut D,
    config: &ServerConfig,
    kdf: &KdfLimiter,
    mut recv: PooledBuffer,
    mut command: ServerFirst,
) -> Result<(), SessionError> {
    let buffers = &config.buffers;
    let mut reused = false;
    loop {
        let (ConnectRequest { destination, reuse }, leftover) = match command {
            ServerFirst::Connect { request, leftover } => (request, leftover),
            ServerFirst::Udp => {
                return run_server_udp(snell, encoder, decoder, config, kdf, recv).await;
            }
        };

        let mut remote = match with_handshake_timeout(async {
            let remote = config.outbound.connect(&destination).await?;
            write_tunnel(encoder, buffers, &mut snell).await?;
            Ok(remote)
        })
        .await
        {
            Ok(remote) => remote,
            Err(error) => {
                let _ = write_reject(encoder, buffers, &mut snell, &error.to_string()).await;
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
            encoder,
            decoder,
            &mut recv,
            leftover,
            reuse,
        )
        .await?;
        if !reuse || decoder.has_unconsumed_plaintext() {
            return Ok(());
        }
        recv.release_empty();
        wait_reuse_idle(&mut snell, &mut recv).await?;
        command = with_handshake_timeout(read_server_connect(
            decoder,
            &mut recv,
            &mut snell,
            kdf,
            &config.psk,
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
        for selection in [
            ProtocolSelection::Exact(ProtocolFlavor::V4),
            ProtocolSelection::Exact(ProtocolFlavor::V6Shaped),
            ProtocolSelection::Exact(ProtocolFlavor::V6Unshaped),
            ProtocolSelection::Auto,
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let _peer = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let kdf = Arc::new(KdfLimiter::new());
            let _blocked = kdf.block_for_test();
            let buffers = Arc::new(BufferPool::default());
            for _ in 0..4 {
                let mut buffer = buffers.get(snell_protocol::V6_WIRE_CAP);
                buffer.ensure(4096).unwrap();
            }
            let config = ServerConfig {
                listen: listener.local_addr().unwrap(),
                psk: Psk::new(b"0123456789abcdef").unwrap(),
                selection,
                outbound: Outbound::Direct,
                udp: UdpOptions::new().unwrap(),
                buffers: buffers.clone(),
                tcp_brutal: None,
            };
            let handshakes = Arc::new(Semaphore::new(1));
            let replay = ReplayCache::new();
            let mut session = Box::pin(handle_server(
                stream,
                &config,
                &kdf,
                &replay,
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
                "{selection:?}: no response KDF before request"
            );
            assert_eq!(buffers.leased_bytes(), 0);
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
                udp: UdpOptions::new().unwrap(),
                buffers: buffers.clone(),
                tcp_brutal: None,
            };
            let handshake = handshakes.clone().try_acquire_owned().unwrap();
            let task = tokio::spawn(async move {
                let (kdf, replay) = (KdfLimiter::new(), ReplayCache::new());
                handle_server(stream, &config, &kdf, &replay, handshake).await
            });
            let mut encoder = V4Encoder::os(&psk).unwrap();
            let mut decoder = V4Decoder::new(psk.clone());
            let client_buffers = Arc::new(BufferPool::default());
            let mut recv = client_buffers.get(snell_protocol::V6_WIRE_CAP);
            let target = snell_protocol::Address::from(upstream.local_addr().unwrap());
            write_connect(
                &mut encoder,
                &client_buffers,
                &mut peer,
                target.as_view(),
                false,
            )
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
            assert_eq!(buffers.leased_bytes(), 0);
        }
    }
}

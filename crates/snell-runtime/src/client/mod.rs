//! Client: a local SOCKS5 proxy that tunnels CONNECT and UDP ASSOCIATE
//! through Snell, reusing pooled connections when enabled.

mod pool;
mod socks;
mod udp;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use snell_protocol::socks5::Reply;
use snell_protocol::{
    Address, ProtocolFlavor, Psk, RecordDecoder, V4Decoder, V4Encoder, V6ShapedDecoder,
    V6ShapedEncoder, V6UnshapedDecoder, V6UnshapedEncoder,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{Instrument, debug, info, warn};

use crate::buffer::{BufferPool, PooledBuffer};
use crate::codec::{Codec, with_codec};
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::platform::{AcceptLoop, prepare_session_stream};
use crate::session::{read_server_tunnel, relay, with_handshake_timeout, write_connect};
use crate::udp::UdpOptions;
use crate::{bind_listener, connect_tcp};
pub(crate) use pool::Connection;
pub use pool::ReusePool;
use socks::{Socks5Command, accept_socks5, socks5_reply_from_error, write_socks5_reply};

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub listen: SocketAddr,
    pub server: SocketAddr,
    pub psk: Psk,
    pub version: ProtocolFlavor,
    /// CONNECT_V2 reuse through this pool; `None` opens one-shot sessions.
    pub pool: Option<ReusePool>,
    pub udp: UdpOptions,
    pub buffers: Arc<BufferPool>,
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
    let config = Arc::new(config);
    let kdf = Arc::new(KdfLimiter::new());
    let udp_controls = Arc::new(Semaphore::new(config.udp.limits.max_controls));
    let mut reuse_maintenance = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut accept = AcceptLoop::new(&listener);
    let session_ids = AtomicU64::new(1);
    info!(listen = %listener.local_addr()?, "client started");
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("client shutting down");
                return Ok(());
            }
            _ = reuse_maintenance.tick(), if config.pool.is_some() => {
                if let Some(pool) = &config.pool { pool.expire(); }
            }
            accepted = accept.next() => {
                let (stream, peer) = accepted?;
                let config = Arc::clone(&config);
                let kdf = Arc::clone(&kdf);
                let udp_controls = Arc::clone(&udp_controls);
                let id = session_ids.fetch_add(1, Ordering::Relaxed);
                let span = tracing::info_span!("session", id, peer = %peer);
                tokio::spawn(async move {
                    debug!("accepted");
                    match handle_client(stream, &config, &kdf, &udp_controls).await {
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
    config: &ClientConfig,
    kdf: &KdfLimiter,
    udp_controls: &Semaphore,
) -> Result<(), SessionError> {
    prepare_session_stream(&local)?;
    // Boxed: SOCKS5 negotiation state is larger than a relay's and dead
    // once the request is parsed.
    match Box::pin(with_handshake_timeout(accept_socks5(&mut local))).await? {
        Socks5Command::Connect(destination) => connect(&mut local, config, &destination, kdf).await,
        // Boxed: only UDP associations pay for UDP relay state.
        Socks5Command::UdpAssociate => {
            Box::pin(udp::associate(local, config, kdf, udp_controls)).await
        }
    }
}

/// CONNECT `destination` over a pooled or freshly dialed Snell connection,
/// relay `local` through it, and return it to the pool when reusable.
///
/// Establishing is boxed: its state is needed only until the tunnel opens,
/// and would otherwise stay reserved for the whole relay.
async fn connect(
    local: &mut TcpStream,
    config: &ClientConfig,
    destination: &Address,
    kdf: &KdfLimiter,
) -> Result<(), SessionError> {
    let Tunnel {
        mut conn,
        mut recv,
        leftover,
        reused,
    } = match Box::pin(establish(config, destination, kdf)).await {
        Ok(tunnel) => tunnel,
        Err(error) => return Err(write_socks5_fail(local, error).await),
    };
    write_socks5_reply(local, Reply::Succeeded).await?;
    info!(
        target = %destination,
        version = ?config.version,
        reused,
        "handshake completed, tunnel established"
    );

    let reuse = config.pool.is_some();
    let Connection { stream, codec } = &mut conn;
    let reusable = with_codec!(codec, |encoder, decoder| {
        relay(stream, local, encoder, decoder, &mut recv, leftover, reuse).await?;
        reuse && recv.is_empty() && !decoder.has_unconsumed_plaintext()
    });
    if reusable
        && let Some(pool) = &config.pool
        && pool.put(conn)
    {
        debug!(pool_len = pool.len(), "returned connection to reuse pool");
    }
    Ok(())
}

/// An open tunnel: the connection, its receive lease, and stream bytes that
/// arrived with the server's reply.
struct Tunnel {
    conn: Connection,
    recv: PooledBuffer,
    leftover: Vec<u8>,
    reused: bool,
}

/// Open a tunnel over a pooled connection, or over a fresh one when none is
/// idle or the pooled one turns out stale. Each attempt owns its connection
/// in its own scope, so the future holds at most one.
async fn establish(
    config: &ClientConfig,
    destination: &Address,
    kdf: &KdfLimiter,
) -> Result<Tunnel, SessionError> {
    let reuse = config.pool.is_some();
    if let Some(mut conn) = config.pool.as_ref().and_then(ReusePool::take) {
        let mut recv = config.buffers.get(snell_protocol::V6_WIRE_CAP);
        match open_tunnel(&mut conn, &mut recv, destination, reuse, config, kdf).await {
            Ok(leftover) => {
                return Ok(Tunnel {
                    conn,
                    recv,
                    leftover,
                    reused: true,
                });
            }
            Err(error) if error.is_stale_pool_error() => {}
            Err(error) => return Err(error),
        }
    }
    let mut conn = dial(config, kdf).await?;
    let mut recv = config.buffers.get(snell_protocol::V6_WIRE_CAP);
    let leftover = open_tunnel(&mut conn, &mut recv, destination, reuse, config, kdf).await?;
    Ok(Tunnel {
        conn,
        recv,
        leftover,
        reused: false,
    })
}

/// Dial the server and set up the configured codec. The response encoder's
/// key derivation runs on the bounded KDF pool.
pub(crate) async fn dial(
    config: &ClientConfig,
    kdf: &KdfLimiter,
) -> Result<Connection, SessionError> {
    let stream = connect_tcp(config.server).await?;
    let psk = &config.psk;
    let codec = match config.version {
        ProtocolFlavor::V4 | ProtocolFlavor::V5 => Codec::V4 {
            encoder: kdf.derive(psk, V4Encoder::os).await?,
            decoder: V4Decoder::new(psk.clone()),
        },
        ProtocolFlavor::V6Shaped => Codec::V6Shaped {
            encoder: kdf.derive(psk, V6ShapedEncoder::os).await?,
            decoder: V6ShapedDecoder::new(psk.clone()),
        },
        ProtocolFlavor::V6Unshaped => Codec::V6Unshaped {
            encoder: kdf.derive(psk, V6UnshapedEncoder::os).await?,
            decoder: V6UnshapedDecoder::new(psk.clone()),
        },
    };
    Ok(Connection { stream, codec })
}

/// Send CONNECT and wait for the server's Tunnel reply; returns any stream
/// bytes that arrived with it.
async fn open_tunnel(
    conn: &mut Connection,
    recv: &mut PooledBuffer,
    destination: &Address,
    reuse: bool,
    config: &ClientConfig,
    kdf: &KdfLimiter,
) -> Result<Vec<u8>, SessionError> {
    // `connect_tcp` already set the socket options of dialed connections.
    let Connection { stream, codec } = conn;
    with_codec!(codec, |encoder, decoder| {
        with_handshake_timeout(async {
            write_connect(
                encoder,
                &config.buffers,
                stream,
                destination.as_view(),
                reuse,
            )
            .await?;
            read_server_tunnel(decoder, recv, stream, kdf, &config.psk).await
        })
        .await
    })
}

async fn write_socks5_fail(local: &mut TcpStream, error: impl Into<SessionError>) -> SessionError {
    let error = error.into();
    let _ = write_socks5_reply(local, socks5_reply_from_error(&error)).await;
    error
}

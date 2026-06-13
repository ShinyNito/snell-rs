use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;
use zeroize::Zeroizing;

use crate::MAX_PACKET_SIZE;
use crate::error::Result;
use crate::protocol::quic_proxy::{decode_init_datagram, is_quic_looking};
use crate::proxy::outbound::{RelayOptions, open_quic_udp, run_quic_proxy_response_session};

pub const QUIC_PROXY_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Per-session queue of payloads awaiting the session task. A full queue drops
/// the datagram (UDP loss semantics) instead of stalling every other client on
/// the shared socket.
const SESSION_QUEUE_CAPACITY: usize = 256;
const RECV_BUFFER_CAPACITY: usize = MAX_PACKET_SIZE + 512;
const PAYLOAD_SCRATCH_CAPACITY: usize = 64 * 1024;

pub(crate) async fn serve_quic_proxy_socket(
    socket: UdpSocket,
    psk: Vec<u8>,
    options: RelayOptions,
    idle_timeout: Duration,
    shutdown: CancellationToken,
) -> Result<()> {
    let psk = Zeroizing::new(psk);
    let socket = Arc::new(socket);
    let mut sessions = HashMap::<SocketAddr, QuicProxySession>::new();
    let mut buf = BytesMut::with_capacity(RECV_BUFFER_CAPACITY);
    let mut scratch = BytesMut::with_capacity(PAYLOAD_SCRATCH_CAPACITY);
    let cleanup = sleep(idle_timeout);
    tokio::pin!(cleanup);

    loop {
        buf.clear();
        tokio::select! {
            () = shutdown.cancelled() => break,
            recv_result = socket.recv_buf_from(&mut buf) => {
                let (n, client_addr) = recv_result?;
                if n == 0 {
                    continue;
                }
                let first_byte = buf[0];
                if sessions
                    .get(&client_addr)
                    .is_some_and(QuicProxySession::is_closed)
                {
                    sessions.remove(&client_addr);
                }
                if let Some(session) = sessions.get_mut(&client_addr) {
                    let payload = if is_quic_looking(first_byte) {
                        copy_payload(&mut scratch, &buf[..n])
                    } else {
                        let init = match decode_init_datagram(&psk, &mut buf[..n]) {
                            Ok(init) => init,
                            Err(err) => {
                                tracing::debug!(%err, %client_addr, "ignored invalid quic proxy datagram");
                                continue;
                            }
                        };
                        let span = init.payload_span;
                        copy_payload(&mut scratch, &buf[span.start..span.end])
                    };
                    session.last_activity = Instant::now();
                    match session.queue.try_send(payload) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            tracing::debug!(%client_addr, "quic proxy session queue full, dropped datagram");
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            sessions.remove(&client_addr);
                        }
                    }
                    continue;
                }

                if is_quic_looking(first_byte) {
                    tracing::debug!(%client_addr, "dropped raw quic proxy packet without session");
                    continue;
                }

                let (host, port, first_payload) = {
                    let init = match decode_init_datagram(&psk, &mut buf[..n]) {
                        Ok(init) => init,
                        Err(err) => {
                            tracing::debug!(%err, %client_addr, "ignored invalid quic proxy init");
                            continue;
                        }
                    };
                    let span = init.payload_span;
                    (
                        init.host.to_owned(),
                        init.port,
                        copy_payload(&mut scratch, &buf[span.start..span.end]),
                    )
                };
                let (queue, payloads) = mpsc::channel(SESSION_QUEUE_CAPACITY);
                let task = tokio::spawn(run_quic_proxy_session(
                    socket.clone(),
                    client_addr,
                    host,
                    port,
                    options.clone(),
                    first_payload,
                    payloads,
                ));
                sessions.insert(client_addr, QuicProxySession {
                    queue,
                    task,
                    last_activity: Instant::now(),
                });
            }
            _ = &mut cleanup => {
                let now = Instant::now();
                sessions.retain(|_, session| {
                    let keep = now.duration_since(session.last_activity) <= idle_timeout
                        && !session.is_closed();
                    if !keep {
                        session.task.abort();
                    }
                    keep
                });
                cleanup.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
        }
    }

    drain_quic_proxy_sessions(sessions).await;
    Ok(())
}

/// Owns the upstream relay for one client address. Opening the relay (DNS,
/// socket binds, optional SOCKS5 handshake) and every upstream send happen
/// here, so a slow or stalled session never blocks the shared receive loop.
async fn run_quic_proxy_session(
    server_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    host: String,
    port: u16,
    options: RelayOptions,
    first_payload: Bytes,
    mut payloads: mpsc::Receiver<Bytes>,
) {
    let mut relay = match open_quic_udp(host, port, options).await {
        Ok(relay) => relay,
        Err(err) => {
            tracing::debug!(%err, %client_addr, "quic proxy session open failed");
            return;
        }
    };
    // Abort-on-drop: if this session task is itself aborted (idle eviction,
    // shutdown drain), the response task must not outlive it holding sockets.
    let mut response_task = AbortOnDropHandle::new(tokio::spawn(run_quic_proxy_response_session(
        server_socket,
        client_addr,
        relay.response_relay(),
    )));

    let send_payloads = async {
        let mut payload = first_payload;
        loop {
            if let Err(err) = relay.send_payload(&payload).await {
                tracing::debug!(%err, %client_addr, "quic proxy session send failed");
                return;
            }
            match payloads.recv().await {
                Some(next) => payload = next,
                None => return,
            }
        }
    };
    tokio::pin!(send_payloads);

    tokio::select! {
        () = &mut send_payloads => {
            response_task.abort();
            log_quic_proxy_response_task_result(client_addr, response_task.await);
        }
        result = &mut response_task => {
            log_quic_proxy_response_task_result(client_addr, result);
        }
    }
}

fn log_quic_proxy_response_task_result(
    client_addr: SocketAddr,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::debug!(%err, %client_addr, "quic proxy response task failed");
        }
        Err(err) if err.is_cancelled() => {}
        Err(err) => {
            tracing::debug!(%err, %client_addr, "quic proxy response task ended unexpectedly");
        }
    }
}

struct QuicProxySession {
    queue: mpsc::Sender<Bytes>,
    task: JoinHandle<()>,
    last_activity: Instant,
}

impl QuicProxySession {
    fn is_closed(&self) -> bool {
        self.queue.is_closed() || self.task.is_finished()
    }
}

/// Copies one datagram payload out of the shared receive buffer so it can be
/// queued to the session task. Carves `Bytes` out of a large scratch block to
/// amortize allocations across packets.
fn copy_payload(scratch: &mut BytesMut, payload: &[u8]) -> Bytes {
    if scratch.capacity() < payload.len() {
        *scratch = BytesMut::with_capacity(PAYLOAD_SCRATCH_CAPACITY.max(payload.len()));
    }
    scratch.extend_from_slice(payload);
    scratch.split().freeze()
}

async fn drain_quic_proxy_sessions(sessions: HashMap<SocketAddr, QuicProxySession>) {
    for session in sessions.values() {
        session.task.abort();
    }
    for (client_addr, session) in sessions {
        match session.task.await {
            Ok(()) => {}
            Err(err) if err.is_cancelled() => {}
            Err(err) => {
                tracing::debug!(%err, %client_addr, "quic proxy session task ended unexpectedly");
            }
        }
    }
}

#[cfg(test)]
mod tests;

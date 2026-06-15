use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use pin_project_lite::pin_project;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, Sleep, sleep};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use tokio_util::task::AbortOnDropHandle;
use zeroize::Zeroizing;

use crate::MAX_PACKET_SIZE;
use crate::error::Result;
use crate::protocol::quic_proxy::{decode_init_datagram, is_quic_looking};
use crate::proxy::outbound::{
    QuicProxyRelay, RelayOptions, open_quic_udp, relay_quic_proxy_responses,
};
use crate::relay::udp::io::{UdpRecvBatch, UdpSendBatch};

pub const QUIC_PROXY_FLOW_IDLE_TIMEOUT: Duration = Duration::from_mins(1);

/// Per-flow queue of payloads awaiting the flow task. A full queue drops
/// the datagram (UDP loss semantics) instead of stalling every other client on
/// the shared socket.
const FLOW_QUEUE_CAPACITY: usize = 256;
const RECV_BUFFER_CAPACITY: usize = MAX_PACKET_SIZE + 512;
const PAYLOAD_SCRATCH_CAPACITY: usize = 64 * 1024;

struct QuicProxySocketBuffers {
    recv_batch: UdpRecvBatch,
    scratch: BytesMut,
}

impl QuicProxySocketBuffers {
    fn new() -> Self {
        Self {
            recv_batch: UdpRecvBatch::new(RECV_BUFFER_CAPACITY),
            scratch: BytesMut::with_capacity(PAYLOAD_SCRATCH_CAPACITY),
        }
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn serve_quic_proxy_socket(
    socket: UdpSocket,
    psk: Vec<u8>,
    options: RelayOptions,
    idle_timeout: Duration,
    shutdown: CancellationToken,
) -> Result<()> {
    let driver = QuicProxySocketDriver::new(socket, psk, options, idle_timeout, shutdown);
    tokio::pin!(driver);
    driver.await
}

pin_project! {
    struct QuicProxySocketDriver {
        socket: Arc<UdpSocket>,
        psk: Zeroizing<Vec<u8>>,
        options: RelayOptions,
        idle_timeout: Duration,
        #[pin]
        shutdown: WaitForCancellationFutureOwned,
        flows: HashMap<SocketAddr, QuicProxyFlow>,
        buffers: Box<QuicProxySocketBuffers>,
        #[pin]
        cleanup: Sleep,
        drain: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    }
}

impl QuicProxySocketDriver {
    fn new(
        socket: UdpSocket,
        psk: Vec<u8>,
        options: RelayOptions,
        idle_timeout: Duration,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            socket: Arc::new(socket),
            psk: Zeroizing::new(psk),
            options,
            idle_timeout,
            shutdown: shutdown.cancelled_owned(),
            flows: HashMap::new(),
            buffers: Box::new(QuicProxySocketBuffers::new()),
            cleanup: sleep(idle_timeout),
            drain: None,
        }
    }
}

impl Future for QuicProxySocketDriver {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        loop {
            if let Some(drain) = this.drain.as_mut() {
                ready!(drain.as_mut().poll(cx));
                return Poll::Ready(Ok(()));
            }

            if this.shutdown.as_mut().poll(cx).is_ready() {
                let flows = std::mem::take(this.flows);
                *this.drain = Some(Box::pin(drain_quic_proxy_flows(flows)));
                continue;
            }

            if this.cleanup.as_mut().poll(cx).is_ready() {
                cleanup_idle_quic_proxy_flows(this.flows, *this.idle_timeout);
                this.cleanup
                    .as_mut()
                    .reset(Instant::now() + *this.idle_timeout);
                continue;
            }

            match this.buffers.recv_batch.poll_recv_from(this.socket, cx) {
                Poll::Ready(Ok(count)) => {
                    process_quic_proxy_recv_batch(
                        this.socket,
                        this.psk.as_slice(),
                        this.options,
                        this.flows,
                        this.buffers,
                        count,
                    );
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn process_quic_proxy_recv_batch(
    socket: &Arc<UdpSocket>,
    psk: &[u8],
    options: &RelayOptions,
    flows: &mut HashMap<SocketAddr, QuicProxyFlow>,
    buffers: &mut QuicProxySocketBuffers,
    count: usize,
) {
    for index in 0..count {
        let Some(entry) = buffers.recv_batch.get(index) else {
            continue;
        };
        if entry.is_oversized() || entry.payload_len() == 0 {
            continue;
        }
        let client_addr = entry.peer();
        let first_byte = entry.payload()[0];
        if flows
            .get(&client_addr)
            .is_some_and(QuicProxyFlow::is_closed)
        {
            flows.remove(&client_addr);
        }
        if flows.contains_key(&client_addr) {
            let payload = if is_quic_looking(first_byte) {
                copy_payload(&mut buffers.scratch, entry.payload())
            } else {
                let mut entry = buffers
                    .recv_batch
                    .get_mut(index)
                    .expect("checked UDP batch index must exist");
                let init = match decode_init_datagram(psk, entry.payload_mut()) {
                    Ok(init) => init,
                    Err(err) => {
                        tracing::debug!(%err, %client_addr, "ignored invalid quic proxy datagram");
                        continue;
                    }
                };
                let span = init.payload_span;
                copy_payload(
                    &mut buffers.scratch,
                    &entry.payload_mut()[span.start..span.end],
                )
            };
            let Some(flow) = flows.get_mut(&client_addr) else {
                continue;
            };
            flow.last_activity = Instant::now();
            match flow.queue.try_send(payload) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::debug!(%client_addr, "quic proxy flow queue full, dropped datagram");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    flows.remove(&client_addr);
                }
            }
            continue;
        }

        if is_quic_looking(first_byte) {
            tracing::debug!(%client_addr, "dropped raw quic proxy packet without flow");
            continue;
        }

        let (host, port, first_payload) = {
            let mut entry = buffers
                .recv_batch
                .get_mut(index)
                .expect("checked UDP batch index must exist");
            let init = match decode_init_datagram(psk, entry.payload_mut()) {
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
                copy_payload(
                    &mut buffers.scratch,
                    &entry.payload_mut()[span.start..span.end],
                ),
            )
        };
        let (queue, payloads) = mpsc::channel(FLOW_QUEUE_CAPACITY);
        let task = tokio::spawn(run_quic_proxy_flow(
            socket.clone(),
            client_addr,
            host,
            port,
            options.clone(),
            first_payload,
            payloads,
        ));
        flows.insert(
            client_addr,
            QuicProxyFlow {
                queue,
                task,
                last_activity: Instant::now(),
            },
        );
    }
}

fn cleanup_idle_quic_proxy_flows(
    flows: &mut HashMap<SocketAddr, QuicProxyFlow>,
    idle_timeout: Duration,
) {
    let now = Instant::now();
    flows.retain(|_, flow| {
        let keep = now.duration_since(flow.last_activity) <= idle_timeout && !flow.is_closed();
        if !keep {
            flow.task.abort();
        }
        keep
    });
}

/// Owns the upstream relay for one client address. Opening the relay (DNS,
/// socket binds, optional SOCKS5 handshake) and every upstream send happen
/// here, so a slow or stalled flow never blocks the shared receive loop.
fn run_quic_proxy_flow(
    server_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    host: String,
    port: u16,
    options: RelayOptions,
    first_payload: Bytes,
    payloads: mpsc::Receiver<Bytes>,
) -> QuicProxyFlowDriver {
    QuicProxyFlowDriver {
        client_addr,
        server_socket,
        state: QuicProxyFlowState::Opening {
            open: Box::pin(open_quic_udp(host, port, options)),
            first_payload: Some(first_payload),
            payloads: Some(payloads),
        },
    }
}

type QuicProxyOpenFuture = Pin<Box<dyn Future<Output = Result<QuicProxyRelay>> + Send>>;
type QuicProxyResponseTask = Pin<Box<AbortOnDropHandle<Result<()>>>>;

pin_project! {
    struct QuicProxyFlowDriver {
        client_addr: SocketAddr,
        server_socket: Arc<UdpSocket>,
        state: QuicProxyFlowState,
    }
}

enum QuicProxyFlowState {
    Opening {
        open: QuicProxyOpenFuture,
        first_payload: Option<Bytes>,
        payloads: Option<mpsc::Receiver<Bytes>>,
    },
    Running {
        relay: QuicProxyRelay,
        response_task: QuicProxyResponseTask,
        payloads: mpsc::Receiver<Bytes>,
        pending_payload: Option<Bytes>,
        pending_send: Option<UdpSendBatch>,
    },
    Draining {
        response_task: QuicProxyResponseTask,
    },
    Done,
}

impl Future for QuicProxyFlowDriver {
    type Output = ();

    #[allow(clippy::too_many_lines)]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        loop {
            let state = std::mem::replace(this.state, QuicProxyFlowState::Done);
            match state {
                QuicProxyFlowState::Opening {
                    mut open,
                    mut first_payload,
                    mut payloads,
                } => match open.as_mut().poll(cx) {
                    Poll::Ready(Ok(relay)) => {
                        let response_task = Box::pin(AbortOnDropHandle::new(tokio::spawn(
                            relay_quic_proxy_responses(
                                this.server_socket.clone(),
                                *this.client_addr,
                                relay.response_relay(),
                            ),
                        )));
                        *this.state = QuicProxyFlowState::Running {
                            relay,
                            response_task,
                            payloads: payloads
                                .take()
                                .expect("opening quic proxy flow must own payload receiver"),
                            pending_payload: first_payload.take(),
                            pending_send: None,
                        };
                    }
                    Poll::Ready(Err(err)) => {
                        tracing::debug!(%err, client_addr = %*this.client_addr, "quic proxy flow open failed");
                        return Poll::Ready(());
                    }
                    Poll::Pending => {
                        *this.state = QuicProxyFlowState::Opening {
                            open,
                            first_payload,
                            payloads,
                        };
                        return Poll::Pending;
                    }
                },
                QuicProxyFlowState::Running {
                    mut relay,
                    mut response_task,
                    mut payloads,
                    mut pending_payload,
                    mut pending_send,
                } => {
                    if let Poll::Ready(result) = response_task.as_mut().poll(cx) {
                        log_quic_proxy_response_task_result(*this.client_addr, result);
                        return Poll::Ready(());
                    }

                    if let Some(send) = pending_send.as_mut() {
                        match send.poll_send(relay.outbound_socket(), cx) {
                            Poll::Ready(Ok(_)) => {
                                pending_send = None;
                                *this.state = QuicProxyFlowState::Running {
                                    relay,
                                    response_task,
                                    payloads,
                                    pending_payload,
                                    pending_send,
                                };
                                continue;
                            }
                            Poll::Ready(Err(err)) => {
                                tracing::debug!(%err, client_addr = %*this.client_addr, "quic proxy flow send failed");
                                response_task.abort();
                                *this.state = QuicProxyFlowState::Draining { response_task };
                                continue;
                            }
                            Poll::Pending => {
                                *this.state = QuicProxyFlowState::Running {
                                    relay,
                                    response_task,
                                    payloads,
                                    pending_payload,
                                    pending_send,
                                };
                                return Poll::Pending;
                            }
                        }
                    }

                    if let Some(payload) = pending_payload.take() {
                        match relay.prepare_send_payload(&payload) {
                            Ok(send) => {
                                pending_send = Some(send);
                                *this.state = QuicProxyFlowState::Running {
                                    relay,
                                    response_task,
                                    payloads,
                                    pending_payload,
                                    pending_send,
                                };
                                continue;
                            }
                            Err(err) => {
                                tracing::debug!(%err, client_addr = %*this.client_addr, "quic proxy flow send failed");
                                response_task.abort();
                                *this.state = QuicProxyFlowState::Draining { response_task };
                                continue;
                            }
                        }
                    }

                    match payloads.poll_recv(cx) {
                        Poll::Ready(Some(payload)) => {
                            pending_payload = Some(payload);
                            *this.state = QuicProxyFlowState::Running {
                                relay,
                                response_task,
                                payloads,
                                pending_payload,
                                pending_send,
                            };
                        }
                        Poll::Ready(None) => {
                            response_task.abort();
                            *this.state = QuicProxyFlowState::Draining { response_task };
                        }
                        Poll::Pending => {
                            *this.state = QuicProxyFlowState::Running {
                                relay,
                                response_task,
                                payloads,
                                pending_payload,
                                pending_send,
                            };
                            return Poll::Pending;
                        }
                    }
                }
                QuicProxyFlowState::Draining { mut response_task } => {
                    match response_task.as_mut().poll(cx) {
                        Poll::Ready(result) => {
                            log_quic_proxy_response_task_result(*this.client_addr, result);
                            return Poll::Ready(());
                        }
                        Poll::Pending => {
                            *this.state = QuicProxyFlowState::Draining { response_task };
                            return Poll::Pending;
                        }
                    }
                }
                QuicProxyFlowState::Done => return Poll::Ready(()),
            }
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

struct QuicProxyFlow {
    queue: mpsc::Sender<Bytes>,
    task: JoinHandle<()>,
    last_activity: Instant,
}

impl QuicProxyFlow {
    fn is_closed(&self) -> bool {
        self.queue.is_closed() || self.task.is_finished()
    }
}

/// Copies one datagram payload out of the shared receive buffer so it can be
/// queued to the flow task. Carves `Bytes` out of a large scratch block to
/// amortize allocations across packets.
fn copy_payload(scratch: &mut BytesMut, payload: &[u8]) -> Bytes {
    if scratch.capacity() < payload.len() {
        *scratch = BytesMut::with_capacity(PAYLOAD_SCRATCH_CAPACITY.max(payload.len()));
    }
    scratch.extend_from_slice(payload);
    scratch.split().freeze()
}

async fn drain_quic_proxy_flows(flows: HashMap<SocketAddr, QuicProxyFlow>) {
    for flow in flows.values() {
        flow.task.abort();
    }
    for (client_addr, flow) in flows {
        match flow.task.await {
            Ok(()) => {}
            Err(err) if err.is_cancelled() => {}
            Err(err) => {
                tracing::debug!(%err, %client_addr, "quic proxy flow task ended unexpectedly");
            }
        }
    }
}

#[cfg(test)]
mod tests;

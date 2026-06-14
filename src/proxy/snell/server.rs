use std::future::{Future, poll_fn};
use std::task::{Context, Poll, ready};
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::Duration;

use crate::MAX_PACKET_SIZE;
use crate::error::{Error, Result};
use crate::framed::{SnellStreamReader, SnellStreamWriter};
use crate::protocol::psk::SnellPsk;
use crate::protocol::request::{ClientRequest, parse_client_request};
use crate::protocol::v6::V6SaltReplayCache;
use crate::proxy::outbound::{RelayOptions, RelayStats, open_udp};
use crate::session::activity::{RelayActivity, RelayActivityTimeouts, wait_relay_idle};
use crate::session::tcp::TcpServerStream;
use crate::session::tcp::TcpTarget;
use crate::session::tcp::relay::{
    PlainUploadBatch, PrefixedRead, relay_bidirectional_until_right_closed,
};
use crate::session::udp::association::relay_udp_server_stream_prepared;
use crate::session::udp::stream::UdpServerStream;

pub(crate) const CONNECT_FAILED_CODE: u8 = 1;
pub(crate) const CONNECT_FAILED_MESSAGE: &str = "connect failed";
pub(crate) const V6_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED: u8 = 0x01;
pub(crate) const V6_ERROR_NETWORK_DOWN: u8 = 0x02;
pub(crate) const V6_ERROR_NETWORK_UNREACHABLE: u8 = 0x03;
pub(crate) const V6_ERROR_CONNECTION_RESET: u8 = 0x04;
pub(crate) const V6_ERROR_TIMED_OUT: u8 = 0x05;
pub(crate) const V6_ERROR_CONNECTION_REFUSED: u8 = 0x06;
pub(crate) const V6_ERROR_HOST_UNREACHABLE: u8 = 0x08;
pub(crate) const V6_ERROR_DNS_FAILED: u8 = 0x64;
pub(crate) const V6_ERROR_REMOTE_EOF: u8 = 0x65;
pub(crate) const V6_ERROR_FALLBACK: u8 = 0xff;
const V6_ERROR_DNS_FAILED_MESSAGE: &str = "DNS Failed";
const V6_ERROR_REMOTE_EOF_MESSAGE: &str = "remote eof";
const SERVER_FAST_OPEN_BUFFER_LIMIT: usize = 64 * 1024;
const SERVER_TCP_INITIAL_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const SERVER_TCP_ESTABLISHED_IDLE_TIMEOUT: Duration = Duration::from_hours(1);
pub(crate) const SERVER_TCP_ACTIVITY_TIMEOUTS: RelayActivityTimeouts = RelayActivityTimeouts::new(
    SERVER_TCP_INITIAL_IDLE_TIMEOUT,
    SERVER_TCP_ESTABLISHED_IDLE_TIMEOUT,
);

pub(crate) async fn open_tcp_target(target: TcpTarget, options: RelayOptions) -> Result<TcpStream> {
    crate::proxy::outbound::open_tcp(&target.host, target.port, options).await
}

pub(crate) async fn serve_server_connection<F, Fut>(
    client: TcpStream,
    secret: SnellPsk,
    options: RelayOptions,
    v6_salt_replay_cache: V6SaltReplayCache,
    open_target: F,
    timeouts: RelayActivityTimeouts,
) -> Result<()>
where
    F: FnMut(TcpTarget, RelayOptions) -> Fut + Send + 'static,
    Fut: Future<Output = Result<TcpStream>> + Send + 'static,
{
    client.set_nodelay(true)?;
    let (activity, last_activity) = RelayActivity::new();
    let worker_activity = activity.clone();
    let _activity_guard = activity;
    let mut connection = tokio::spawn(run_server_connection(
        client,
        secret,
        options,
        v6_salt_replay_cache,
        open_target,
        worker_activity,
    ));

    tokio::select! {
        result = &mut connection => result?,
        () = wait_relay_idle(last_activity, timeouts) => {
            connection.abort();
            tracing::debug!(
                initial_idle_timeout_ms = timeouts.initial.as_millis(),
                idle_timeout_ms = timeouts.idle.as_millis(),
                "snell tcp server idle timed out"
            );
            Err(Error::SnellServerTcpIdleTimeout)
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run_server_connection<F, Fut>(
    client: TcpStream,
    secret: SnellPsk,
    options: RelayOptions,
    v6_salt_replay_cache: V6SaltReplayCache,
    mut open_target: F,
    activity: RelayActivity,
) -> Result<()>
where
    F: FnMut(TcpTarget, RelayOptions) -> Fut,
    Fut: Future<Output = Result<TcpStream>>,
{
    let (client_reader, client_writer) = client.into_split();
    let (mut frame_reader, frame_family) =
        SnellStreamReader::auto_detect_server(client_reader, &secret, v6_salt_replay_cache, || {
            activity.record();
        })
        .await?;
    let mut frame_writer =
        SnellStreamWriter::new(client_writer, &secret, frame_family.writer_version())?;

    loop {
        let initial =
            match poll_fn(|cx| poll_read_initial_request(&mut frame_reader, &activity, cx)).await {
                Ok(initial) => initial,
                Err(Error::Io(err))
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe
                    ) =>
                {
                    return Ok(());
                }
                Err(err) => {
                    tracing::debug!(
                        %err,
                        frame_family = ?frame_family,
                        "snell server failed to read client request"
                    );
                    return Err(err);
                }
            };

        match initial {
            InitialRequest::Tcp(target, pending) => {
                let started = Instant::now();
                let keep_alive = target.reuse;
                let snell =
                    TcpServerStream::from_parts_with_pending(frame_reader, frame_writer, pending);
                let connect = open_target(target, options.clone());
                let result = if frame_family.uses_v6_frames() {
                    relay_tcp_server_stream_v6_connect_then_accept(
                        snell,
                        connect,
                        keep_alive,
                        activity.clone(),
                    )
                    .await
                } else {
                    relay_tcp_server_stream_fast_open(snell, connect, keep_alive, activity.clone())
                        .await
                };
                let (stats, next_reader, next_writer) = match result {
                    Ok(result) => result,
                    Err(err) => {
                        tracing::debug!(
                            %err,
                            duration_ms = started.elapsed().as_millis(),
                            "snell tcp server relay failed"
                        );
                        return Err(err);
                    }
                };
                tracing::debug!(
                    uploaded = stats.uploaded,
                    downloaded = stats.downloaded,
                    duration_ms = started.elapsed().as_millis(),
                    "snell tcp server relay finished"
                );
                if !keep_alive {
                    return Ok(());
                }
                frame_reader = next_reader;
                frame_writer = next_writer;
            }
            InitialRequest::Udp => {
                let started = Instant::now();
                let prepared = match open_udp(options.clone()).await {
                    Ok(prepared) => prepared,
                    Err(err) => {
                        frame_writer
                            .write_error_reply(CONNECT_FAILED_CODE, CONNECT_FAILED_MESSAGE)
                            .await?;
                        activity.record();
                        tracing::debug!(
                            %err,
                            duration_ms = started.elapsed().as_millis(),
                            "snell udp server open failed"
                        );
                        return Err(err);
                    }
                };
                let udp = UdpServerStream::accept(frame_reader, frame_writer).await?;
                activity.record();
                let stats =
                    match relay_udp_server_stream_prepared(udp, options, prepared, &activity).await
                    {
                        Ok(stats) => stats,
                        Err(err) => {
                            tracing::debug!(
                                %err,
                                duration_ms = started.elapsed().as_millis(),
                                "snell udp server relay failed"
                            );
                            return Err(err);
                        }
                    };
                tracing::debug!(
                    packets_sent = stats.packets_sent,
                    packets_received = stats.packets_received,
                    bytes_sent = stats.bytes_sent,
                    bytes_received = stats.bytes_received,
                    duration_ms = started.elapsed().as_millis(),
                    "snell udp server relay finished"
                );
                return Ok(());
            }
            InitialRequest::Ping => {
                let started = Instant::now();
                frame_writer.write_pong_reply().await?;
                activity.record();
                tracing::debug!(
                    duration_ms = started.elapsed().as_millis(),
                    "snell ping handled"
                );
                return Ok(());
            }
        }
    }
}

enum InitialRequest {
    Tcp(TcpTarget, Bytes),
    Udp,
    Ping,
}

enum ParsedInitialRequest {
    Tcp(TcpTarget, usize),
    Udp,
    Ping,
}

fn poll_read_initial_request<R>(
    frame_reader: &mut SnellStreamReader<R>,
    activity: &RelayActivity,
    cx: &mut Context<'_>,
) -> Poll<Result<InitialRequest>>
where
    R: AsyncRead + Unpin,
{
    let parsed = {
        let payload = ready!(frame_reader.poll_read_frame_payload(cx))?;
        activity.record();
        match parse_client_request(payload)? {
            ClientRequest::Connect {
                reuse,
                host,
                port,
                rest_span,
                ..
            } => ParsedInitialRequest::Tcp(
                TcpTarget {
                    host: host.to_owned(),
                    port,
                    reuse,
                },
                rest_span.start,
            ),
            ClientRequest::Udp { rest: [], .. } => ParsedInitialRequest::Udp,
            ClientRequest::Ping => ParsedInitialRequest::Ping,
            ClientRequest::Udp { .. } => return Poll::Ready(Err(Error::InvalidClientRequest)),
        }
    };

    let initial = match parsed {
        ParsedInitialRequest::Tcp(target, rest_start) => {
            InitialRequest::Tcp(target, frame_reader.take_payload_from(rest_start))
        }
        ParsedInitialRequest::Udp => InitialRequest::Udp,
        ParsedInitialRequest::Ping => InitialRequest::Ping,
    };
    Poll::Ready(Ok(initial))
}

async fn relay_tcp_server_stream_fast_open<R, W, Fut>(
    mut snell: TcpServerStream<R, W>,
    connect: Fut,
    keep_alive: bool,
    activity: RelayActivity,
) -> Result<(RelayStats, SnellStreamReader<R>, SnellStreamWriter<W>)>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
    Fut: Future<Output = Result<TcpStream>>,
{
    snell.accept().await?;
    activity.record();
    let mut snell = snell;
    let mut early_payload = PlainUploadBatch::new();
    let upstream = buffer_fast_open_payload_until_connected(
        &mut snell,
        connect,
        &mut early_payload,
        &activity,
    )
    .await?;

    relay_tcp_server_stream_reusable(snell, upstream, keep_alive, early_payload, activity).await
}

async fn relay_tcp_server_stream_v6_connect_then_accept<R, W, Fut>(
    snell: TcpServerStream<R, W>,
    connect: Fut,
    keep_alive: bool,
    activity: RelayActivity,
) -> Result<(RelayStats, SnellStreamReader<R>, SnellStreamWriter<W>)>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
    Fut: Future<Output = Result<TcpStream>>,
{
    let mut snell = snell;
    let mut early_payload = PlainUploadBatch::new();
    let upstream = match buffer_fast_open_payload_until_connected(
        &mut snell,
        connect,
        &mut early_payload,
        &activity,
    )
    .await
    {
        Ok(upstream) => upstream,
        Err(err) => {
            let (code, message) = v6_server_error_reply(&err);
            snell.reject(code, &message).await?;
            activity.record();
            return Err(err);
        }
    };

    snell.accept().await?;
    activity.record();
    relay_tcp_server_stream_reusable(snell, upstream, keep_alive, early_payload, activity).await
}

async fn buffer_fast_open_payload_until_connected<S, Fut, T>(
    snell: &mut S,
    connect: Fut,
    early_payload: &mut PlainUploadBatch,
    activity: &RelayActivity,
) -> Result<T>
where
    S: AsyncRead + Unpin,
    Fut: Future<Output = Result<T>>,
{
    let mut upload_done = false;
    let mut buffer = BytesMut::with_capacity(MAX_PACKET_SIZE);
    tokio::pin!(connect);

    loop {
        if upload_done
            || early_payload.len().saturating_add(MAX_PACKET_SIZE) > SERVER_FAST_OPEN_BUFFER_LIMIT
        {
            return connect.await;
        }

        tokio::select! {
            biased;
            result = &mut connect => return result,
            result = snell.read_buf(&mut buffer) => {
                let n = result?;
                if n == 0 {
                    upload_done = true;
                    continue;
                }
                if early_payload.len().saturating_add(n) > SERVER_FAST_OPEN_BUFFER_LIMIT {
                    return Err(Error::PayloadTooLarge);
                }
                activity.record();
                early_payload.push(buffer.split_to(n).freeze());
            }
        }
    }
}

fn v6_server_error_reply(err: &Error) -> (u8, String) {
    match err {
        Error::Dns(_) | Error::DnsUnavailable | Error::DnsTimeout => {
            (V6_ERROR_DNS_FAILED, V6_ERROR_DNS_FAILED_MESSAGE.to_owned())
        }
        Error::Io(io) => {
            let code = match io.kind() {
                std::io::ErrorKind::InvalidInput | std::io::ErrorKind::AddrNotAvailable => {
                    V6_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED
                }
                std::io::ErrorKind::NetworkDown => V6_ERROR_NETWORK_DOWN,
                std::io::ErrorKind::NetworkUnreachable => V6_ERROR_NETWORK_UNREACHABLE,
                std::io::ErrorKind::ConnectionReset => V6_ERROR_CONNECTION_RESET,
                std::io::ErrorKind::TimedOut => V6_ERROR_TIMED_OUT,
                std::io::ErrorKind::ConnectionRefused => V6_ERROR_CONNECTION_REFUSED,
                std::io::ErrorKind::HostUnreachable => V6_ERROR_HOST_UNREACHABLE,
                std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::NotConnected => V6_ERROR_REMOTE_EOF,
                _ => V6_ERROR_FALLBACK,
            };
            let message = if code == V6_ERROR_REMOTE_EOF {
                V6_ERROR_REMOTE_EOF_MESSAGE.to_owned()
            } else {
                io.to_string()
            };
            (code, message)
        }
        _ => (V6_ERROR_FALLBACK, err.to_string()),
    }
}

async fn relay_tcp_server_stream_reusable<R, W>(
    snell: TcpServerStream<R, W>,
    upstream: TcpStream,
    keep_alive: bool,
    early_payload: PlainUploadBatch,
    activity: RelayActivity,
) -> Result<(RelayStats, SnellStreamReader<R>, SnellStreamWriter<W>)>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    let mut snell = PrefixedRead::new(snell, early_payload);
    let mut upstream = upstream;
    let stats =
        relay_bidirectional_until_right_closed(&mut snell, &mut upstream, &activity).await?;
    drop(upstream);
    let mut snell = snell.into_inner();

    if keep_alive {
        drain_tcp_stream(&mut snell, &activity).await?;
    }

    let (mut frame_reader, mut frame_writer) = snell.into_frame_parts();
    frame_reader.compact_buffers_for_reuse();
    frame_writer.compact_buffers_for_reuse();
    Ok((stats, frame_reader, frame_writer))
}

async fn drain_tcp_stream<S>(snell: &mut S, activity: &RelayActivity) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = [0; 8192];
    while snell.read(&mut buffer).await? != 0 {
        activity.record();
    }
    Ok(())
}

#[cfg(test)]
mod tests;

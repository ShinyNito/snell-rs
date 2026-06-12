use std::future::Future;
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::MAX_PACKET_SIZE;
use crate::error::{Error, Result};
use crate::framed::{SnellStreamReader, SnellStreamWriter};
use crate::protocol::request::ClientRequest;
use crate::protocol::v6::V6SaltReplayCache;
use crate::proxy::outbound::{RelayOptions, RelayStats, open_udp};
use crate::session::tcp::relay::relay_tcp_reader_to_plain_counted;
use crate::session::tcp::{TcpReader, TcpServerStream, TcpServerWriter, TcpTarget};
use crate::session::udp::association::{
    UDP_ASSOCIATION_IDLE_TIMEOUT, relay_udp_server_stream_prepared,
};
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

#[cfg(test)]
pub(crate) async fn serve_server_connection(
    client: TcpStream,
    psk: &[u8],
    options: RelayOptions,
) -> Result<()> {
    serve_server_connection_with_salt_replay_cache(
        client,
        psk,
        options,
        V6SaltReplayCache::default(),
    )
    .await
}

pub(crate) async fn serve_server_connection_with_salt_replay_cache(
    client: TcpStream,
    psk: &[u8],
    options: RelayOptions,
    v6_salt_replay_cache: V6SaltReplayCache,
) -> Result<()> {
    client.set_nodelay(true)?;
    serve_server_connection_with_target_opener_and_salt_replay_cache(
        client,
        psk,
        options,
        v6_salt_replay_cache,
        open_target_stream,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn serve_server_connection_with_target_opener<F, Fut>(
    client: TcpStream,
    psk: &[u8],
    options: RelayOptions,
    open_target: F,
) -> Result<()>
where
    F: FnMut(TcpTarget, RelayOptions) -> Fut,
    Fut: Future<Output = Result<TcpStream>>,
{
    serve_server_connection_with_target_opener_and_salt_replay_cache(
        client,
        psk,
        options,
        V6SaltReplayCache::default(),
        open_target,
    )
    .await
}

pub(crate) async fn serve_server_connection_with_target_opener_and_salt_replay_cache<F, Fut>(
    client: TcpStream,
    psk: &[u8],
    options: RelayOptions,
    v6_salt_replay_cache: V6SaltReplayCache,
    mut open_target: F,
) -> Result<()>
where
    F: FnMut(TcpTarget, RelayOptions) -> Fut,
    Fut: Future<Output = Result<TcpStream>>,
{
    let (client_reader, client_writer) = client.into_split();
    let (mut frame_reader, frame_family) =
        SnellStreamReader::auto_detect_server(client_reader, psk, v6_salt_replay_cache).await?;
    let mut frame_writer =
        SnellStreamWriter::new(client_writer, psk, frame_family.writer_version())?;

    loop {
        let initial = match frame_reader.read_client_request().await {
            Ok(ClientRequest::Connect {
                reuse,
                host,
                port,
                rest_span,
                ..
            }) => {
                let target = TcpTarget {
                    host: host.to_owned(),
                    port,
                    reuse,
                };
                let pending = frame_reader.take_payload_from(rest_span.start);
                InitialRequest::Tcp(target, pending)
            }
            Ok(ClientRequest::Udp { rest: [], .. }) => InitialRequest::Udp,
            Ok(ClientRequest::Ping) => InitialRequest::Ping,
            Ok(ClientRequest::Udp { .. }) => return Err(Error::InvalidClientRequest),
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
                    relay_tcp_server_stream_v6_connect_then_accept(snell, connect, keep_alive).await
                } else {
                    relay_tcp_server_stream_fast_open(snell, connect, keep_alive).await
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
                        tracing::debug!(
                            %err,
                            duration_ms = started.elapsed().as_millis(),
                            "snell udp server open failed"
                        );
                        return Err(err);
                    }
                };
                let udp = UdpServerStream::accept(frame_reader, frame_writer).await?;
                let stats = match relay_udp_server_stream_prepared(
                    udp,
                    options,
                    UDP_ASSOCIATION_IDLE_TIMEOUT,
                    prepared,
                )
                .await
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

async fn open_target_stream(target: TcpTarget, options: RelayOptions) -> Result<TcpStream> {
    crate::proxy::outbound::open_tcp(&target.host, target.port, options).await
}

async fn relay_tcp_server_stream_fast_open<R, W, Fut>(
    mut snell: TcpServerStream<R, W>,
    connect: Fut,
    keep_alive: bool,
) -> Result<(RelayStats, SnellStreamReader<R>, SnellStreamWriter<W>)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    Fut: Future<Output = Result<TcpStream>>,
{
    snell.accept().await?;
    let (mut snell_reader, snell_writer) = snell.into_split();
    let mut early_payload = BytesMut::new();
    let upstream =
        buffer_fast_open_payload_until_connected(&mut snell_reader, connect, &mut early_payload)
            .await?;

    relay_tcp_server_split_reusable(
        snell_reader,
        snell_writer,
        upstream,
        keep_alive,
        early_payload,
    )
    .await
}

async fn relay_tcp_server_stream_v6_connect_then_accept<R, W, Fut>(
    snell: TcpServerStream<R, W>,
    connect: Fut,
    keep_alive: bool,
) -> Result<(RelayStats, SnellStreamReader<R>, SnellStreamWriter<W>)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    Fut: Future<Output = Result<TcpStream>>,
{
    let (mut snell_reader, mut snell_writer) = snell.into_split();
    let mut early_payload = BytesMut::new();
    let upstream = match buffer_fast_open_payload_until_connected(
        &mut snell_reader,
        connect,
        &mut early_payload,
    )
    .await
    {
        Ok(upstream) => upstream,
        Err(err) => {
            let (code, message) = v6_server_error_reply(&err);
            snell_writer.reject(code, &message).await?;
            return Err(err);
        }
    };

    snell_writer.open_tunnel().await?;
    relay_tcp_server_split_reusable(
        snell_reader,
        snell_writer,
        upstream,
        keep_alive,
        early_payload,
    )
    .await
}

async fn buffer_fast_open_payload_until_connected<R, Fut, T>(
    snell: &mut TcpReader<R>,
    connect: Fut,
    early_payload: &mut BytesMut,
) -> Result<T>
where
    R: AsyncRead + Unpin,
    Fut: Future<Output = Result<T>>,
{
    let mut upload_done = false;
    tokio::pin!(connect);

    loop {
        if upload_done || !can_buffer_more_fast_open_payload(early_payload.len()) {
            return connect.await;
        }

        tokio::select! {
            biased;
            result = &mut connect => return result,
            result = snell.read_payload_chunk() => {
                let Some(payload) = result? else {
                    upload_done = true;
                    continue;
                };
                let n = payload.len();
                if early_payload.len().saturating_add(n) > SERVER_FAST_OPEN_BUFFER_LIMIT {
                    return Err(Error::PayloadTooLarge);
                }
                early_payload.extend_from_slice(payload);
                snell.consume_payload_chunk(n);
            }
        }
    }
}

fn can_buffer_more_fast_open_payload(buffered: usize) -> bool {
    buffered.saturating_add(MAX_PACKET_SIZE) <= SERVER_FAST_OPEN_BUFFER_LIMIT
}

fn v6_server_error_reply(err: &Error) -> (u8, String) {
    match err {
        Error::Dns(_) | Error::DnsUnavailable | Error::DnsTimeout => {
            (V6_ERROR_DNS_FAILED, V6_ERROR_DNS_FAILED_MESSAGE.to_owned())
        }
        Error::Io(io) => v6_io_error_reply(io),
        _ => (V6_ERROR_FALLBACK, err.to_string()),
    }
}

fn v6_io_error_reply(io: &std::io::Error) -> (u8, String) {
    let message = io.to_string();
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
        message
    };
    (code, message)
}

#[cfg(test)]
async fn relay_tcp_server_stream_reusable<R, W>(
    snell: TcpServerStream<R, W>,
    upstream: TcpStream,
    keep_alive: bool,
) -> Result<(RelayStats, SnellStreamReader<R>, SnellStreamWriter<W>)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (snell_reader, snell_writer) = snell.into_split();
    relay_tcp_server_split_reusable(
        snell_reader,
        snell_writer,
        upstream,
        keep_alive,
        BytesMut::new(),
    )
    .await
}

async fn relay_tcp_server_split_reusable<R, W>(
    mut snell_reader: TcpReader<R>,
    mut snell_writer: TcpServerWriter<W>,
    upstream: TcpStream,
    keep_alive: bool,
    early_payload: BytesMut,
) -> Result<(RelayStats, SnellStreamReader<R>, SnellStreamWriter<W>)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut upstream_reader, mut upstream_writer) = upstream.into_split();

    let mut uploaded = 0;
    let mut downloaded = 0;
    let end = {
        let upload = relay_tcp_reader_to_plain_counted_with_initial(
            &mut snell_reader,
            &mut upstream_writer,
            &mut uploaded,
            early_payload,
        );
        let download = relay_plain_to_server_writer_counted(
            &mut upstream_reader,
            &mut snell_writer,
            &mut downloaded,
        );
        tokio::pin!(upload);
        tokio::pin!(download);

        tokio::select! {
            result = &mut upload => {
                result?;
                download.await?;
                ServerRelayEnd::SnellClosed
            }
            result = &mut download => {
                result?;
                ServerRelayEnd::UpstreamClosed
            }
        }
    };

    if end == ServerRelayEnd::UpstreamClosed {
        drop(upstream_reader);
        drop(upstream_writer);
        if keep_alive {
            drain_tcp_reader(&mut snell_reader).await?;
        }
    }

    let mut frame_reader = snell_reader.into_frame_reader();
    let mut frame_writer = snell_writer.into_frame_writer();
    frame_reader.compact_buffers_for_reuse();
    frame_writer.compact_buffers_for_reuse();
    Ok((
        RelayStats {
            uploaded,
            downloaded,
        },
        frame_reader,
        frame_writer,
    ))
}

async fn relay_tcp_reader_to_plain_counted_with_initial<R, W>(
    snell: &mut TcpReader<R>,
    plain: &mut W,
    total: &mut u64,
    early_payload: BytesMut,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if !early_payload.is_empty() {
        plain.write_all(&early_payload).await?;
        *total += early_payload.len() as u64;
    }
    relay_tcp_reader_to_plain_counted(snell, plain, total).await
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServerRelayEnd {
    SnellClosed,
    UpstreamClosed,
}

async fn relay_plain_to_server_writer_counted<R, W>(
    plain: &mut R,
    snell: &mut TcpServerWriter<W>,
    total: &mut u64,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        match snell.write_payload_from_reader(plain).await? {
            Some(n) => *total += n as u64,
            None => {
                snell.close_write().await?;
                return Ok(());
            }
        }
    }
}

async fn drain_tcp_reader<R>(snell: &mut TcpReader<R>) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let n = match snell.read_payload_chunk().await? {
            Some(payload) => payload.len(),
            None => return Ok(()),
        };
        snell.consume_payload_chunk(n);
    }
}

#[cfg(test)]
mod tests;

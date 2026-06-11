use std::future::Future;
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::MAX_PACKET_SIZE;
use crate::error::{Error, Result};
use crate::protocol::request::ClientRequest;
use crate::relay::tcp::relay_tcp_reader_to_plain_counted;
use crate::service::outbound::{RelayOptions, RelayStats, open_udp};
use crate::service::session::udp_association::{
    UDP_ASSOCIATION_IDLE_TIMEOUT, relay_udp_server_stream_prepared,
};
use crate::transport::tcp_stream::{TcpReader, TcpServerStream, TcpServerWriter, TcpTarget};
use crate::transport::tokio_io::{V4StreamReader, V4StreamWriter};
use crate::transport::udp_stream::UdpServerStream;

pub(crate) const CONNECT_FAILED_CODE: u8 = 1;
pub(crate) const CONNECT_FAILED_MESSAGE: &str = "connect failed";
const SERVER_FAST_OPEN_BUFFER_LIMIT: usize = 64 * 1024;

pub(crate) async fn serve_server_connection(
    client: TcpStream,
    psk: &[u8],
    options: RelayOptions,
) -> Result<()> {
    client.set_nodelay(true)?;
    serve_server_connection_with_target_opener(client, psk, options, open_target_stream).await
}

pub(crate) async fn serve_server_connection_with_target_opener<F, Fut>(
    client: TcpStream,
    psk: &[u8],
    options: RelayOptions,
    mut open_target: F,
) -> Result<()>
where
    F: FnMut(TcpTarget, RelayOptions) -> Fut,
    Fut: Future<Output = Result<TcpStream>>,
{
    let (client_reader, client_writer) = client.into_split();
    let mut frame_reader = V4StreamReader::new(client_reader, psk)?;
    let mut frame_writer = V4StreamWriter::new(client_writer, psk)?;

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
            Err(err) => return Err(err),
        };

        match initial {
            InitialRequest::Tcp(target, pending) => {
                let started = Instant::now();
                let keep_alive = target.reuse;
                let snell =
                    TcpServerStream::from_parts_with_pending(frame_reader, frame_writer, pending);
                let connect = open_target(target, options.clone());
                let (stats, next_reader, next_writer) =
                    match relay_tcp_server_stream_fast_open(snell, connect, keep_alive).await {
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
    crate::service::outbound::open_tcp(&target.host, target.port, options).await
}

async fn relay_tcp_server_stream_fast_open<R, W, Fut>(
    mut snell: TcpServerStream<R, W>,
    connect: Fut,
    keep_alive: bool,
) -> Result<(RelayStats, V4StreamReader<R>, V4StreamWriter<W>)>
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

#[cfg(test)]
async fn relay_tcp_server_stream_reusable<R, W>(
    snell: TcpServerStream<R, W>,
    upstream: TcpStream,
    keep_alive: bool,
) -> Result<(RelayStats, V4StreamReader<R>, V4StreamWriter<W>)>
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
) -> Result<(RelayStats, V4StreamReader<R>, V4StreamWriter<W>)>
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
mod tests {
    use core::range::Range;

    use bytes::{Bytes, BytesMut};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio::time::{Duration, timeout};

    use super::{
        SERVER_FAST_OPEN_BUFFER_LIMIT, buffer_fast_open_payload_until_connected,
        relay_tcp_server_stream_reusable,
    };
    use crate::error::Error;
    use crate::protocol::request::{ClientRequest, ServerReply};
    use crate::transport::tcp_stream::{TcpPayloadReader, TcpServerStream};
    use crate::transport::tokio_io::{
        STREAM_BUFFER_INITIAL_CAPACITY, STREAM_BUFFER_RETAIN_CAPACITY, V4StreamReader,
        V4StreamWriter,
    };
    use crate::{MAX_PACKET_SIZE, VERSION_4};

    #[tokio::test]
    async fn reusable_relay_compacts_stream_buffers_after_request() {
        let psk = b"test psk";
        let upload = vec![0x51; STREAM_BUFFER_INITIAL_CAPACITY * 4];
        let download = vec![0x52; STREAM_BUFFER_INITIAL_CAPACITY * 4];
        let upload_len = upload.len();
        let download_len = download.len();

        let (client_upload, server_upload) = duplex(32 * 1024);
        let (server_download, client_download) = duplex(32 * 1024);
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = TcpStream::connect(upstream_listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut target, _) = upstream_listener.accept().await.unwrap();

        let client = async {
            let mut writer = V4StreamWriter::new(client_upload, psk).unwrap();
            writer.write_test_frame(&upload).await.unwrap();
            writer.write_zero_chunk().await.unwrap();

            let mut reader =
                TcpPayloadReader::client(V4StreamReader::new(client_download, psk).unwrap());
            reader.read_tunnel_reply().await.unwrap();

            let mut received = Vec::new();
            while let Some(payload) = reader.read_payload_chunk_strict().await.unwrap() {
                received.extend_from_slice(payload);
                let len = payload.len();
                reader.consume_payload_chunk(len);
            }
            assert_eq!(received, download);
        };

        let target = async {
            let mut received = Vec::new();
            target.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, upload);
            target.write_all(&download).await.unwrap();
            target.shutdown().await.unwrap();
        };

        let server = async {
            let reader = V4StreamReader::new(server_upload, psk).unwrap();
            let writer = V4StreamWriter::new(server_download, psk).unwrap();
            let snell = TcpServerStream::from_parts_with_pending(reader, writer, Bytes::new());

            let (stats, reader, writer) = relay_tcp_server_stream_reusable(snell, upstream, true)
                .await
                .unwrap();

            assert_eq!(stats.uploaded, upload_len as u64);
            assert_eq!(stats.downloaded, download_len as u64);
            assert!(reader.body_capacity() > STREAM_BUFFER_INITIAL_CAPACITY);
            assert!(reader.body_capacity() <= STREAM_BUFFER_RETAIN_CAPACITY);
            assert!(writer.frame_capacity() > STREAM_BUFFER_INITIAL_CAPACITY);
            assert!(writer.frame_capacity() <= STREAM_BUFFER_RETAIN_CAPACITY);
        };

        let ((), (), ()) = tokio::join!(client, target, server);
    }

    #[tokio::test]
    async fn fast_open_buffer_stops_before_next_frame_could_exceed_limit() {
        let psk = b"test psk";
        let (client_upload, server_upload) = duplex(4096);

        let mut writer = V4StreamWriter::new(client_upload, psk).unwrap();
        writer.write_test_frame(b"held").await.unwrap();

        let reader = V4StreamReader::new(server_upload, psk).unwrap();
        let writer = V4StreamWriter::new(tokio::io::sink(), psk).unwrap();
        let snell = TcpServerStream::from_parts_with_pending(reader, writer, Bytes::new());
        let (mut snell_reader, _) = snell.into_split();
        let mut early_payload = BytesMut::new();
        let initial_len = SERVER_FAST_OPEN_BUFFER_LIMIT - MAX_PACKET_SIZE + 1;
        early_payload.resize(initial_len, 0);

        let (connect_tx, connect_rx) = oneshot::channel();
        let connect = async {
            connect_rx.await.unwrap();
            Ok::<_, Error>(())
        };
        {
            let fast_open = buffer_fast_open_payload_until_connected(
                &mut snell_reader,
                connect,
                &mut early_payload,
            );
            tokio::pin!(fast_open);

            assert!(
                timeout(Duration::from_millis(50), &mut fast_open)
                    .await
                    .is_err()
            );
            connect_tx.send(()).unwrap();
            fast_open.await.unwrap();
        }
        assert_eq!(early_payload.len(), initial_len);
    }

    #[tokio::test]
    async fn reusable_relay_releases_upstream_when_upstream_closes_first() {
        let psk = b"test psk";
        let (client_upload, server_upload) = duplex(4096);
        let (server_download, client_download) = duplex(4096);
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = TcpStream::connect(upstream_listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut target, _) = upstream_listener.accept().await.unwrap();
        let (released_tx, released_rx) = oneshot::channel();

        let target = async {
            target.shutdown().await.unwrap();

            let mut buf = [0; 1];
            let n = timeout(Duration::from_secs(1), target.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(n, 0);
            released_tx.send(()).unwrap();
        };

        let client = async {
            let mut reader = V4StreamReader::new(client_download, psk).unwrap();
            let mut writer = V4StreamWriter::new(client_upload, psk).unwrap();

            assert!(matches!(
                reader.read_server_reply().await,
                Ok(ServerReply::Tunnel {
                    payload_span: Range { start: 1, end: 1 },
                    payload: []
                })
            ));
            assert!(matches!(
                reader.read_frame_payload().await,
                Err(Error::ZeroChunk)
            ));

            timeout(Duration::from_secs(1), released_rx)
                .await
                .unwrap()
                .unwrap();
            writer.write_zero_chunk().await.unwrap();
            writer
                .write_tcp_request("next.example", 443, VERSION_4, true)
                .await
                .unwrap();
        };

        let server = async {
            let reader = V4StreamReader::new(server_upload, psk).unwrap();
            let writer = V4StreamWriter::new(server_download, psk).unwrap();
            let snell = TcpServerStream::from_parts_with_pending(reader, writer, Bytes::new());

            let (stats, mut reader, _) = relay_tcp_server_stream_reusable(snell, upstream, true)
                .await
                .unwrap();

            assert_eq!(stats.uploaded, 0);
            assert_eq!(stats.downloaded, 0);
            assert_eq!(
                reader.read_client_request().await.unwrap(),
                ClientRequest::Connect {
                    reuse: true,
                    host: "next.example",
                    port: 443,
                    rest_span: Range { start: 18, end: 18 },
                    rest: b"",
                }
            );
        };

        let ((), (), ()) = tokio::join!(client, target, server);
    }
}

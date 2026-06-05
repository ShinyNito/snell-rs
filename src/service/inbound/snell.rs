use std::future::Future;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::error::{Error, Result};
use crate::protocol::request::ClientRequest;
use crate::relay::tcp::{relay_plain_to_server_writer, relay_tcp_reader_to_plain};
use crate::service::outbound::{RelayOptions, RelayStats, open_udp};
use crate::service::session::udp_association::{
    UDP_ASSOCIATION_IDLE_TIMEOUT, relay_udp_server_stream_prepared,
};
use crate::transport::tcp_stream::{TcpServerStream, TcpTarget};
use crate::transport::tokio_io::{V4StreamReader, V4StreamWriter};
use crate::transport::udp_stream::UdpServerStream;

pub(crate) const CONNECT_FAILED_CODE: u8 = 1;
pub(crate) const CONNECT_FAILED_MESSAGE: &str = "connect failed";

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
                rest_offset,
                ..
            }) => {
                let target = TcpTarget {
                    host: host.to_owned(),
                    port,
                    reuse,
                };
                let pending = frame_reader.take_payload_from(rest_offset);
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
                let keep_alive = target.reuse;
                let snell =
                    TcpServerStream::from_parts_with_pending(frame_reader, frame_writer, pending);
                let upstream = match open_target(target, options).await {
                    Ok(upstream) => upstream,
                    Err(err) => {
                        snell
                            .reject(CONNECT_FAILED_CODE, CONNECT_FAILED_MESSAGE)
                            .await?;
                        return Err(err);
                    }
                };
                let (_, next_reader, next_writer) =
                    relay_tcp_server_stream_reusable(snell, upstream).await?;
                if !keep_alive {
                    return Ok(());
                }
                frame_reader = next_reader;
                frame_writer = next_writer;
            }
            InitialRequest::Udp => {
                let prepared = match open_udp(options).await {
                    Ok(prepared) => prepared,
                    Err(err) => {
                        frame_writer
                            .write_error_reply(CONNECT_FAILED_CODE, CONNECT_FAILED_MESSAGE)
                            .await?;
                        return Err(err);
                    }
                };
                let udp = UdpServerStream::accept(frame_reader, frame_writer).await?;
                relay_udp_server_stream_prepared(
                    udp,
                    options,
                    UDP_ASSOCIATION_IDLE_TIMEOUT,
                    prepared,
                )
                .await?;
                return Ok(());
            }
            InitialRequest::Ping => {
                frame_writer.write_pong_reply().await?;
                return Ok(());
            }
        }
    }
}

enum InitialRequest {
    Tcp(TcpTarget, BytesMut),
    Udp,
    Ping,
}

async fn open_target_stream(target: TcpTarget, options: RelayOptions) -> Result<TcpStream> {
    crate::service::outbound::open_tcp(&target.host, target.port, options).await
}

async fn relay_tcp_server_stream_reusable<R, W>(
    snell: TcpServerStream<R, W>,
    upstream: TcpStream,
) -> Result<(RelayStats, V4StreamReader<R>, V4StreamWriter<W>)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut snell_reader, mut snell_writer) = snell.into_split();
    let (mut upstream_reader, mut upstream_writer) = upstream.into_split();

    let (uploaded, downloaded) = tokio::try_join!(
        relay_tcp_reader_to_plain(&mut snell_reader, &mut upstream_writer),
        relay_plain_to_server_writer(&mut upstream_reader, &mut snell_writer),
    )?;

    let frame_reader = snell_reader.into_frame_reader();
    let frame_writer = snell_writer.into_frame_writer();
    Ok((
        RelayStats {
            uploaded,
            downloaded,
        },
        frame_reader,
        frame_writer,
    ))
}

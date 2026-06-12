use tokio::io::{AsyncRead, AsyncWrite};

use crate::VERSION_4;
use crate::error::{Error, Result};
use crate::protocol::request::ClientRequest;
use crate::protocol::udp::{UdpPacketRef, parse_udp_request, parse_udp_response};
use crate::transport::tokio_io::{SnellStreamReader, SnellStreamWriter};
use crate::transport::udp_stream::UdpServerStream;

pub(crate) async fn accept_udp_server_stream<R, W>(
    reader_io: R,
    writer_io: W,
    psk: &[u8],
) -> Result<UdpServerStream<R, W>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    accept_udp_server_stream_for_version(reader_io, writer_io, psk, VERSION_4).await
}

pub(crate) async fn accept_udp_server_stream_for_version<R, W>(
    reader_io: R,
    writer_io: W,
    psk: &[u8],
    version: u8,
) -> Result<UdpServerStream<R, W>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = SnellStreamReader::new(reader_io, psk, version)?;
    match reader.read_client_request().await? {
        ClientRequest::Udp { rest: [], .. } => {}
        ClientRequest::Udp { .. } => return Err(Error::InvalidClientRequest),
        ClientRequest::Ping | ClientRequest::Connect { .. } => {
            return Err(Error::InvalidClientRequest);
        }
    }
    let writer = SnellStreamWriter::new(writer_io, psk, version)?;
    UdpServerStream::accept(reader, writer).await
}

pub(crate) async fn read_udp_request_frame<R>(
    reader: &mut SnellStreamReader<R>,
) -> Result<Option<UdpPacketRef<'_>>>
where
    R: AsyncRead + Unpin,
{
    match reader.read_frame_payload().await {
        Ok(payload) => Ok(Some(parse_udp_request(payload)?)),
        Err(Error::ZeroChunk) => Ok(None),
        Err(err) => Err(err),
    }
}

pub(crate) async fn read_udp_response_frame<R>(
    reader: &mut SnellStreamReader<R>,
) -> Result<Option<UdpPacketRef<'_>>>
where
    R: AsyncRead + Unpin,
{
    match reader.read_frame_payload().await {
        Ok(payload) => Ok(Some(parse_udp_response(payload)?)),
        Err(Error::ZeroChunk) => Ok(None),
        Err(err) => Err(err),
    }
}

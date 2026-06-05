use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};
use crate::protocol::request::ClientRequest;
use crate::protocol::udp::{UdpPacketRef, parse_udp_request, parse_udp_response};
use crate::transport::tokio_io::{V4StreamReader, V4StreamWriter};
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
    let mut reader = V4StreamReader::new(reader_io, psk)?;
    match reader.read_client_request().await? {
        ClientRequest::Udp { rest: [], .. } => {}
        ClientRequest::Udp { .. } => return Err(Error::InvalidClientRequest),
        ClientRequest::Ping | ClientRequest::Connect { .. } => {
            return Err(Error::InvalidClientRequest);
        }
    }
    let writer = V4StreamWriter::new(writer_io, psk)?;
    UdpServerStream::accept(reader, writer).await
}

pub(crate) async fn read_udp_request_frame<R>(
    reader: &mut V4StreamReader<R>,
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
    reader: &mut V4StreamReader<R>,
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

use std::net::IpAddr;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::ProtocolVersion;
use crate::error::{Error, Result};
use crate::framed::{SnellStreamReader, SnellStreamWriter};
use crate::protocol::request::ClientRequest;
use crate::protocol::udp::{AddressRef, UdpPacketRef, parse_udp_request, parse_udp_response};
use crate::session::udp::stream::UdpServerStream;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TestUdpPacket {
    pub(crate) address: TestUdpAddress,
    pub(crate) port: u16,
    pub(crate) payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TestUdpAddress {
    Domain(String),
    Ip(IpAddr),
}

impl TestUdpAddress {
    fn from_ref(address: AddressRef<'_>) -> Self {
        match address {
            AddressRef::Domain(host) => Self::Domain(host.to_owned()),
            AddressRef::Ip(ip) => Self::Ip(ip),
        }
    }
}

impl TestUdpPacket {
    fn from_ref(packet: UdpPacketRef<'_>) -> Self {
        Self {
            address: TestUdpAddress::from_ref(packet.address),
            port: packet.port,
            payload: packet.payload.to_vec(),
        }
    }
}

pub(crate) async fn accept_udp_server_stream<R, W>(
    reader_io: R,
    writer_io: W,
    psk: &[u8],
    version: ProtocolVersion,
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
) -> Result<Option<TestUdpPacket>>
where
    R: AsyncRead + Unpin,
{
    let mut scratch = BytesMut::new();
    let Some(message) = reader.read_udp_request_message(&mut scratch).await? else {
        return Ok(None);
    };
    Ok(Some(TestUdpPacket::from_ref(parse_udp_request(&message)?)))
}

pub(crate) async fn read_udp_response_frame<R>(
    reader: &mut SnellStreamReader<R>,
) -> Result<Option<TestUdpPacket>>
where
    R: AsyncRead + Unpin,
{
    let mut scratch = BytesMut::new();
    let Some(message) = reader.read_udp_response_message(&mut scratch).await? else {
        return Ok(None);
    };
    Ok(Some(TestUdpPacket::from_ref(parse_udp_response(&message)?)))
}

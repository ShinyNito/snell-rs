use std::net::IpAddr;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, duplex};
use tokio::net::{TcpListener, UdpSocket};

use crate::ProtocolVersion;
use crate::error::{Error, Result};
use crate::framed::{SnellStreamReader, SnellStreamWriter};
use crate::protocol::request::{ClientRequest, parse_client_request};
use crate::protocol::udp::{
    AddressRef, UdpPacketRef, write_udp_request_prefix, write_udp_response_prefix,
};
use crate::session::udp::stream::UdpServerStream;

pub(crate) const TEST_PSK: &[u8] = b"test psk";
pub(crate) const TEST_VERSION: ProtocolVersion = ProtocolVersion::V4;
pub(crate) const TEST_DUPLEX_CAPACITY: usize = 4096;

pub(crate) fn test_duplex_pair() -> (DuplexStream, DuplexStream) {
    duplex(TEST_DUPLEX_CAPACITY)
}

pub(crate) async fn test_tcp_listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test_tcp_listener should bind an ephemeral localhost TCP port")
}

pub(crate) async fn test_udp_socket() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("test_udp_socket should bind an ephemeral localhost UDP port")
}

pub(crate) fn test_snell_reader<R>(io: R) -> SnellStreamReader<R>
where
    R: AsyncRead + Unpin,
{
    test_snell_reader_with_version(io, TEST_VERSION)
}

pub(crate) fn test_snell_reader_with_version<R>(
    io: R,
    version: ProtocolVersion,
) -> SnellStreamReader<R>
where
    R: AsyncRead + Unpin,
{
    SnellStreamReader::new(io, TEST_PSK, version)
}

pub(crate) fn test_snell_writer<W>(io: W) -> SnellStreamWriter<W>
where
    W: AsyncWrite + Unpin,
{
    test_snell_writer_with_version(io, TEST_VERSION)
}

pub(crate) fn test_snell_writer_with_version<W>(
    io: W,
    version: ProtocolVersion,
) -> SnellStreamWriter<W>
where
    W: AsyncWrite + Unpin,
{
    SnellStreamWriter::new(io, TEST_PSK, version).unwrap()
}

pub(crate) async fn write_snell_payload_message<W>(
    writer: &mut SnellStreamWriter<W>,
    payload: &[u8],
) -> Result<usize>
where
    W: AsyncWrite + Unpin,
{
    let mut plain = BytesMut::from(payload);
    Ok(writer
        .write_payload_message_from_buffer(&mut plain)
        .await?
        .unwrap_or(0))
}

pub(crate) async fn write_snell_tunnel_reply_message<W>(
    writer: &mut SnellStreamWriter<W>,
    payload: &[u8],
) -> Result<usize>
where
    W: AsyncWrite + Unpin,
{
    if payload.is_empty() {
        writer.write_empty_tunnel_reply().await?;
        return Ok(0);
    }

    let mut plain = BytesMut::from(payload);
    Ok(writer
        .write_tunnel_reply_message_from_buffer(&mut plain)
        .await?
        .unwrap_or(0))
}

pub(crate) async fn write_snell_udp_packet<W>(
    writer: &mut SnellStreamWriter<W>,
    address: AddressRef<'_>,
    port: u16,
    payload: &[u8],
) -> Result<usize>
where
    W: AsyncWrite + Unpin,
{
    let mut plain = BytesMut::new();
    write_udp_request_prefix(&mut plain, address, port)?;
    plain.extend_from_slice(payload);
    let message_len = plain.len();
    if message_len > writer.max_udp_application_payload_len() {
        return Err(Error::PayloadTooLarge);
    }
    assert_eq!(
        writer.write_payload_message_from_buffer(&mut plain).await?,
        Some(message_len)
    );
    Ok(payload.len())
}

pub(crate) async fn write_snell_udp_response<W>(
    writer: &mut SnellStreamWriter<W>,
    address: AddressRef<'_>,
    port: u16,
    payload: &[u8],
) -> Result<usize>
where
    W: AsyncWrite + Unpin,
{
    let mut plain = BytesMut::new();
    write_udp_response_prefix(&mut plain, address, port)?;
    plain.extend_from_slice(payload);
    let message_len = plain.len();
    if message_len > writer.max_udp_application_payload_len() {
        return Err(Error::PayloadTooLarge);
    }
    assert_eq!(
        writer.write_payload_message_from_buffer(&mut plain).await?,
        Some(message_len)
    );
    Ok(payload.len())
}

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
    pub(crate) fn from_ref(packet: UdpPacketRef<'_>) -> Self {
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
    let mut reader = SnellStreamReader::new(reader_io, psk, version);
    let payload = reader.read_frame_payload().await?;
    match parse_client_request(payload)? {
        ClientRequest::Udp { rest: [], .. } => {}
        ClientRequest::Udp { .. } => return Err(Error::InvalidClientRequest),
        ClientRequest::Ping | ClientRequest::Connect { .. } => {
            return Err(Error::InvalidClientRequest);
        }
    }
    let writer = SnellStreamWriter::new(writer_io, psk, version)?;
    UdpServerStream::accept(reader, writer).await
}

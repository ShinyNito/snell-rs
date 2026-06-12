use std::sync::Arc;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::UdpSocket;

use crate::error::{Error, Result};
use crate::protocol::socks5::write_udp_packet as write_socks_udp_packet;
use crate::protocol::udp::{UdpPacketRef, parse_udp_request};
use crate::service::outbound::{RelayOptions, send_udp_payload, validate_proxy_udp_target};
use crate::service::session::udp_io::{
    MAX_SOCKS_UDP_HEADER, MAX_VALID_SOCKS_UDP_DATAGRAM, SnellUdpPacketKind, parse_socks_udp_header,
    recv_socks_udp_datagram_into, reframe_socks_udp_packet, send_udp_parts,
};
use crate::transport::tokio_io::{SnellStreamReader, SnellStreamWriter};

use super::udp_association::UdpAssociationState;
use super::udp_socket::{UdpSockets, resolve_udp_target};

pub(super) async fn relay_snell_to_udp<R>(
    reader: &mut SnellStreamReader<R>,
    sockets: UdpSockets,
    options: RelayOptions,
    state: Arc<UdpAssociationState>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let resolver = options.resolver.clone();
    while let Some(packet) = read_udp_request_frame(reader).await? {
        let target =
            resolve_udp_target(packet, options.ipv6, options.dns_ip_preference, &resolver).await?;
        let socket = sockets.socket_for(target)?;
        send_udp_payload(&socket, packet.payload, target).await?;
        state.add_sent(packet.payload.len() as u64);
    }

    Ok(())
}

pub(super) async fn relay_snell_to_proxy_udp<R>(
    reader: &mut SnellStreamReader<R>,
    socket: Arc<UdpSocket>,
    relay_addr: std::net::SocketAddr,
    options: RelayOptions,
    state: Arc<UdpAssociationState>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut proxy_header = BytesMut::with_capacity(MAX_SOCKS_UDP_HEADER);
    let mut proxy_packet = BytesMut::new();

    while let Some(packet) = read_udp_request_frame(reader).await? {
        validate_proxy_udp_target(packet, options.ipv6)?;
        proxy_header.clear();
        write_socks_udp_packet(&mut proxy_header, packet.address, packet.port, &[])?;
        send_udp_parts(
            &socket,
            &proxy_header,
            packet.payload,
            relay_addr,
            MAX_VALID_SOCKS_UDP_DATAGRAM,
            &mut proxy_packet,
        )
        .await?;
        state.add_sent(packet.payload.len() as u64);
    }

    Ok(())
}

pub(super) async fn relay_proxy_udp_to_snell<W>(
    writer: &mut SnellStreamWriter<W>,
    socket: Arc<UdpSocket>,
    relay_addr: std::net::SocketAddr,
    state: Arc<UdpAssociationState>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    loop {
        match write_proxy_udp_packet_response(writer, &socket, relay_addr).await? {
            WriteBackStatus::Written(n) => state.add_received(n as u64),
            WriteBackStatus::Closed => return Ok(()),
            WriteBackStatus::Dropped => {}
            WriteBackStatus::WouldBlock => {}
        }
    }
}

pub(super) async fn relay_udp_to_snell<W>(
    writer: &mut SnellStreamWriter<W>,
    sockets: UdpSockets,
    state: Arc<UdpAssociationState>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            ready_result = sockets.v4.readable() => {
                ready_result?;
                match write_ipv4_udp_response(writer, &sockets.v4).await? {
                    WriteBackStatus::Written(n) => state.add_received(n as u64),
                    WriteBackStatus::Closed => return Ok(()),
                    WriteBackStatus::Dropped => {}
                    WriteBackStatus::WouldBlock => continue,
                }
            }
            ready_result = readable_optional(sockets.v6.as_deref()), if sockets.v6.is_some() => {
                ready_result?;
                let Some(socket) = sockets.v6.as_deref() else {
                    continue;
                };
                match write_ipv6_udp_response(writer, socket).await? {
                    WriteBackStatus::Written(n) => state.add_received(n as u64),
                    WriteBackStatus::Closed => return Ok(()),
                    WriteBackStatus::Dropped => {}
                    WriteBackStatus::WouldBlock => continue,
                }
            }
        }
    }
}

pub(super) async fn write_zero_chunk<W>(writer: &mut SnellStreamWriter<W>) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    match writer.write_zero_chunk().await {
        Ok(()) => Ok(()),
        Err(err) if err.is_closed_io() => Ok(()),
        Err(err) => Err(err),
    }
}

pub(super) async fn wait_proxy_control_closed<R>(control: &mut R) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0; 128];
    loop {
        let n = control.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
    }
}

async fn read_udp_request_frame<R>(
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

async fn write_ipv4_udp_response<W>(
    writer: &mut SnellStreamWriter<W>,
    socket: &UdpSocket,
) -> Result<WriteBackStatus>
where
    W: AsyncWrite + Unpin,
{
    match writer.try_write_ipv4_udp_response_from_socket(socket).await {
        Ok(Some((payload_len, _peer))) => Ok(WriteBackStatus::Written(payload_len)),
        Ok(None) => Ok(WriteBackStatus::WouldBlock),
        Err(Error::PayloadTooLarge) => {
            tracing::debug!("dropped oversized udp response");
            Ok(WriteBackStatus::Dropped)
        }
        Err(err) if err.is_closed_io() => Ok(WriteBackStatus::Closed),
        Err(err) => Err(err),
    }
}

async fn write_ipv6_udp_response<W>(
    writer: &mut SnellStreamWriter<W>,
    socket: &UdpSocket,
) -> Result<WriteBackStatus>
where
    W: AsyncWrite + Unpin,
{
    match writer.try_write_ipv6_udp_response_from_socket(socket).await {
        Ok(Some((payload_len, _peer))) => Ok(WriteBackStatus::Written(payload_len)),
        Ok(None) => Ok(WriteBackStatus::WouldBlock),
        Err(Error::PayloadTooLarge) => {
            tracing::debug!("dropped oversized udp response");
            Ok(WriteBackStatus::Dropped)
        }
        Err(err) if err.is_closed_io() => Ok(WriteBackStatus::Closed),
        Err(err) => Err(err),
    }
}

async fn write_proxy_udp_packet_response<W>(
    writer: &mut SnellStreamWriter<W>,
    socket: &UdpSocket,
    relay_addr: std::net::SocketAddr,
) -> Result<WriteBackStatus>
where
    W: AsyncWrite + Unpin,
{
    let frame_len;
    let payload_len;
    {
        let frame = writer.start_payload_frame();
        let (datagram_len, peer) = match recv_socks_udp_datagram_into(socket, frame).await {
            Ok(result) => result,
            Err(Error::PayloadTooLarge) => {
                tracing::debug!("dropped oversized proxy udp response");
                return Ok(WriteBackStatus::Dropped);
            }
            Err(err) if err.is_closed_io() => return Ok(WriteBackStatus::Closed),
            Err(err) => return Err(err),
        };
        if peer != relay_addr {
            tracing::debug!(%peer, %relay_addr, "ignored udp packet from unexpected proxy peer");
            return Ok(WriteBackStatus::Dropped);
        }

        let header = match parse_socks_udp_header(&frame[..datagram_len]) {
            Ok(header) => header,
            Err(err) => {
                tracing::debug!(%err, "ignored invalid proxy udp response");
                return Ok(WriteBackStatus::Dropped);
            }
        };
        payload_len = header.payload_len();
        let prefix_start =
            match reframe_socks_udp_packet(frame, &header, SnellUdpPacketKind::Response) {
                Ok(prefix_start) => prefix_start,
                Err(Error::PayloadTooLarge) => {
                    tracing::debug!(payload_len, "dropped oversized proxy udp response");
                    return Ok(WriteBackStatus::Dropped);
                }
                Err(err) => return Err(err),
            };
        frame.advance(prefix_start);
        frame_len = frame.len();
    }

    match writer.finish_payload_frame(frame_len).await {
        Ok(_) => Ok(WriteBackStatus::Written(payload_len)),
        Err(Error::PayloadTooLarge) => {
            tracing::debug!(payload_len, "dropped oversized proxy udp response");
            Ok(WriteBackStatus::Dropped)
        }
        Err(err) if err.is_closed_io() => Ok(WriteBackStatus::Closed),
        Err(err) => Err(err),
    }
}

async fn readable_optional(socket: Option<&UdpSocket>) -> std::io::Result<()> {
    match socket {
        Some(socket) => socket.readable().await,
        None => std::future::pending().await,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteBackStatus {
    Written(usize),
    Closed,
    Dropped,
    WouldBlock,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::VERSION_4;
    use crate::error::Error;
    use crate::protocol::udp::{AddressRef, parse_udp_response};
    use crate::transport::tokio_io::{SnellStreamReader, SnellStreamWriter};

    const UDP_IPV4_RESPONSE_OVERHEAD: usize = 1 + 4 + 2;
    const UDP_IPV6_RESPONSE_OVERHEAD: usize = 1 + 16 + 2;
    const UDP_MAX_IPV4_RESPONSE_PAYLOAD: usize =
        crate::MAX_PACKET_SIZE - UDP_IPV4_RESPONSE_OVERHEAD;
    const UDP_MAX_IPV6_RESPONSE_PAYLOAD: usize =
        crate::MAX_PACKET_SIZE - UDP_IPV6_RESPONSE_OVERHEAD;

    #[tokio::test]
    async fn udp_response_accepts_largest_payloads_that_fit_frame() {
        let psk = b"test psk";
        let v4_payload = vec![0x42; UDP_MAX_IPV4_RESPONSE_PAYLOAD];
        let v6_payload = vec![0x43; UDP_MAX_IPV6_RESPONSE_PAYLOAD];

        let read_v4 = async {
            let (writer_io, reader_io) = tokio::io::duplex(crate::MAX_PACKET_SIZE + 2048);
            let mut reader = SnellStreamReader::new(reader_io, psk, VERSION_4).unwrap();
            let mut writer = SnellStreamWriter::new(writer_io, psk, VERSION_4).unwrap();
            let write = writer.write_test_udp_response(
                AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                53,
                &v4_payload,
            );
            let read = async {
                let frame = reader.read_frame_payload().await.unwrap();
                let response = parse_udp_response(frame).unwrap();
                assert_eq!(response.payload.len(), UDP_MAX_IPV4_RESPONSE_PAYLOAD);
                frame.len()
            };

            let (write_result, read_result) = tokio::join!(write, read);
            assert_eq!(write_result.unwrap(), UDP_MAX_IPV4_RESPONSE_PAYLOAD);
            assert_eq!(read_result, crate::MAX_PACKET_SIZE);
        };

        let read_v6 = async {
            let (writer_io, reader_io) = tokio::io::duplex(crate::MAX_PACKET_SIZE + 2048);
            let mut reader = SnellStreamReader::new(reader_io, psk, VERSION_4).unwrap();
            let mut writer = SnellStreamWriter::new(writer_io, psk, VERSION_4).unwrap();
            let write = writer.write_test_udp_response(
                AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                53,
                &v6_payload,
            );
            let read = async {
                let frame = reader.read_frame_payload().await.unwrap();
                let response = parse_udp_response(frame).unwrap();
                assert_eq!(response.payload.len(), UDP_MAX_IPV6_RESPONSE_PAYLOAD);
                frame.len()
            };

            let (write_result, read_result) = tokio::join!(write, read);
            assert_eq!(write_result.unwrap(), UDP_MAX_IPV6_RESPONSE_PAYLOAD);
            assert_eq!(read_result, crate::MAX_PACKET_SIZE);
        };

        tokio::join!(read_v4, read_v6);
    }

    #[tokio::test]
    async fn udp_response_rejects_payload_too_large_for_frame() {
        let psk = b"test psk";
        let v4_payload = vec![0x42; UDP_MAX_IPV4_RESPONSE_PAYLOAD + 1];
        let v6_payload = vec![0x43; UDP_MAX_IPV6_RESPONSE_PAYLOAD + 1];
        let mut v4_writer = SnellStreamWriter::new(tokio::io::sink(), psk, VERSION_4).unwrap();
        let mut v6_writer = SnellStreamWriter::new(tokio::io::sink(), psk, VERSION_4).unwrap();

        assert!(matches!(
            v4_writer
                .write_test_udp_response(
                    AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    53,
                    &v4_payload,
                )
                .await,
            Err(Error::PayloadTooLarge)
        ));
        assert!(matches!(
            v6_writer
                .write_test_udp_response(
                    AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                    53,
                    &v6_payload,
                )
                .await,
            Err(Error::PayloadTooLarge)
        ));
    }

    #[test]
    fn udp_response_payload_limits_leave_room_for_address_headers() {
        assert_eq!(
            UDP_MAX_IPV4_RESPONSE_PAYLOAD + 1 + 4 + 2,
            crate::MAX_PACKET_SIZE
        );
        assert_eq!(
            UDP_MAX_IPV6_RESPONSE_PAYLOAD + 1 + 16 + 2,
            crate::MAX_PACKET_SIZE
        );
    }

    #[test]
    fn udp_send_short_write_is_rejected() {
        assert!(crate::service::outbound::udp::ensure_full_datagram_sent(4, 5).is_err());
        crate::service::outbound::udp::ensure_full_datagram_sent(5, 5).unwrap();
    }
}

use std::sync::Arc;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::UdpSocket;

use crate::MAX_PACKET_SIZE;
use crate::error::{Error, Result};
use crate::protocol::socks5::{
    SocksUdpPacketRef, parse_udp_packet as parse_socks_udp_packet,
    write_udp_packet as write_socks_udp_packet,
};
use crate::protocol::udp::{UdpPacketRef, parse_udp_request};
use crate::service::outbound::{RelayOptions, send_udp_payload, validate_proxy_udp_target};
use crate::transport::tokio_io::{V4StreamReader, V4StreamWriter};

use super::udp_association::UdpAssociationState;
use super::udp_socket::{UdpSockets, resolve_udp_target};

pub(super) async fn relay_snell_to_udp<R>(
    reader: &mut V4StreamReader<R>,
    sockets: UdpSockets,
    options: RelayOptions,
    state: Arc<UdpAssociationState>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let resolver = options.resolver.clone();
    while let Some(packet) = read_udp_request_frame(reader).await? {
        let target = resolve_udp_target(packet, options.ipv6, &resolver).await?;
        let socket = sockets.socket_for(target)?;
        send_udp_payload(&socket, packet.payload, target).await?;
        state.add_sent(packet.payload.len() as u64);
    }

    Ok(())
}

pub(super) async fn relay_snell_to_proxy_udp<R>(
    reader: &mut V4StreamReader<R>,
    socket: Arc<UdpSocket>,
    relay_addr: std::net::SocketAddr,
    options: RelayOptions,
    state: Arc<UdpAssociationState>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut proxy_packet = BytesMut::with_capacity(MAX_PACKET_SIZE + 512);

    while let Some(packet) = read_udp_request_frame(reader).await? {
        validate_proxy_udp_target(packet, options.ipv6)?;
        proxy_packet.clear();
        write_socks_udp_packet(
            &mut proxy_packet,
            packet.address,
            packet.port,
            packet.payload,
        )?;
        send_udp_payload(&socket, &proxy_packet, relay_addr).await?;
        state.add_sent(packet.payload.len() as u64);
    }

    Ok(())
}

pub(super) async fn relay_proxy_udp_to_snell<W>(
    writer: &mut V4StreamWriter<W>,
    socket: Arc<UdpSocket>,
    relay_addr: std::net::SocketAddr,
    state: Arc<UdpAssociationState>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut response = [0; MAX_PACKET_SIZE + 512];

    loop {
        let (n, peer) = socket.recv_from(&mut response).await?;
        if peer != relay_addr {
            tracing::debug!(%peer, %relay_addr, "ignored udp packet from unexpected proxy peer");
            continue;
        }

        let packet = match parse_socks_udp_packet(&response[..n]) {
            Ok(packet) => packet,
            Err(err) => {
                tracing::debug!(%err, "ignored invalid proxy udp response");
                continue;
            }
        };
        match write_proxy_udp_packet_response(writer, packet).await? {
            WriteBackStatus::Written(n) => state.add_received(n as u64),
            WriteBackStatus::Closed => return Ok(()),
            WriteBackStatus::Dropped => {}
            WriteBackStatus::WouldBlock => {}
        }
    }
}

pub(super) async fn relay_udp_to_snell<W>(
    writer: &mut V4StreamWriter<W>,
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

pub(super) async fn write_zero_chunk<W>(writer: &mut V4StreamWriter<W>) -> Result<()>
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

async fn write_ipv4_udp_response<W>(
    writer: &mut V4StreamWriter<W>,
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
    writer: &mut V4StreamWriter<W>,
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
    writer: &mut V4StreamWriter<W>,
    packet: SocksUdpPacketRef<'_>,
) -> Result<WriteBackStatus>
where
    W: AsyncWrite + Unpin,
{
    match writer
        .write_udp_response(packet.address, packet.port, packet.payload)
        .await
    {
        Ok(_) => Ok(WriteBackStatus::Written(packet.payload.len())),
        Err(Error::PayloadTooLarge) => {
            tracing::debug!(
                payload_len = packet.payload.len(),
                "dropped oversized proxy udp response"
            );
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

    use crate::error::Error;
    use crate::protocol::udp::{AddressRef, parse_udp_response};
    use crate::transport::tokio_io::{V4StreamReader, V4StreamWriter};

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
            let mut reader = V4StreamReader::new(reader_io, psk).unwrap();
            let mut writer = V4StreamWriter::new(writer_io, psk).unwrap();
            let write = writer.write_udp_response(
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
            let mut reader = V4StreamReader::new(reader_io, psk).unwrap();
            let mut writer = V4StreamWriter::new(writer_io, psk).unwrap();
            let write = writer.write_udp_response(
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
        let mut v4_writer = V4StreamWriter::new(tokio::io::sink(), psk).unwrap();
        let mut v6_writer = V4StreamWriter::new(tokio::io::sink(), psk).unwrap();

        assert!(matches!(
            v4_writer
                .write_udp_response(
                    AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    53,
                    &v4_payload,
                )
                .await,
            Err(Error::PayloadTooLarge)
        ));
        assert!(matches!(
            v6_writer
                .write_udp_response(
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

use std::sync::Arc;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::UdpSocket;

use crate::error::{Error, Result};
use crate::framed::{SnellStreamReader, SnellStreamWriter};
use crate::protocol::socks5::write_udp_packet as write_socks_udp_packet;
use crate::protocol::udp::parse_udp_request;
use crate::proxy::outbound::{RelayOptions, send_udp_payload, validate_proxy_udp_target};
use crate::session::udp::io::{
    MAX_SOCKS_UDP_HEADER, SnellUdpPacketKind, max_socks_udp_datagram_len, parse_socks_udp_header,
    recv_socks_udp_datagram_into, reframe_socks_udp_packet, send_udp_parts,
};

use super::association::UdpAssociationState;
use super::socket::{UdpSockets, resolve_udp_target};

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
    let mut udp_message = BytesMut::new();
    while let Some(message) = reader.read_udp_request_message(&mut udp_message).await? {
        let packet = parse_udp_request(&message)?;
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
    let mut udp_message = BytesMut::new();

    while let Some(message) = reader.read_udp_request_message(&mut udp_message).await? {
        let packet = parse_udp_request(&message)?;
        validate_proxy_udp_target(packet, options.ipv6)?;
        proxy_header.clear();
        write_socks_udp_packet(&mut proxy_header, packet.address, packet.port, &[])?;
        send_udp_parts(
            &socket,
            &proxy_header,
            packet.payload,
            relay_addr,
            max_socks_udp_datagram_len(crate::MAX_V6_RECORD_PAYLOAD_LEN),
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

pub(crate) async fn write_zero_chunk<W>(writer: &mut SnellStreamWriter<W>) -> Result<()>
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
    let max_snell_udp_payload_len = writer.max_udp_application_payload_len();
    let socks_udp_limit = max_socks_udp_datagram_len(max_snell_udp_payload_len);
    {
        let frame = writer.start_payload_frame();
        let (datagram_len, peer) =
            match recv_socks_udp_datagram_into(socket, frame, socks_udp_limit).await {
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
        let prefix_start = match reframe_socks_udp_packet(
            frame,
            &header,
            SnellUdpPacketKind::Response,
            max_snell_udp_payload_len,
        ) {
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

    match writer.finish_udp_payload_message(frame_len).await {
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
mod tests;

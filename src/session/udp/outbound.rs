use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::UdpSocket;

use crate::error::{Error, Result};
use crate::framed::{SnellStreamReader, SnellStreamWriter};
use crate::protocol::udp::{AddressRef, parse_udp_request, write_udp_response_prefix};
use crate::proxy::outbound::RelayOptions;
use crate::session::udp::io::{UdpRecvBatch, UdpSendPacket, send_udp_batch};

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
    while let Some(message) = reader.read_udp_request_message().await? {
        let packet = parse_udp_request(&message)?;
        let target =
            resolve_udp_target(packet, options.ipv6, options.dns_ip_preference, &resolver).await?;
        let socket = sockets.socket_for(target)?;
        send_udp_batch(
            &socket,
            &[UdpSendPacket::single(packet.payload, target)],
            crate::MAX_PACKET_SIZE,
        )
        .await?;
        state.add_sent(packet.payload.len() as u64);
    }

    Ok(())
}

pub(super) async fn relay_udp_to_snell<W>(
    writer: &mut SnellStreamWriter<W>,
    sockets: UdpSockets,
    state: Arc<UdpAssociationState>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buffers = Box::new(UdpToSnellBuffers::new(
        writer.max_udp_application_payload_len(),
    ));
    loop {
        tokio::select! {
            ready_result = sockets.v4.readable() => {
                ready_result?;
                match write_udp_responses(writer, &sockets.v4, &mut buffers.recv_v4, UdpResponseIpVersion::V4).await? {
                    WriteBackStatus::Written(n) => state.add_received(n as u64),
                    WriteBackStatus::Closed => return Ok(()),
                    WriteBackStatus::Dropped | WriteBackStatus::WouldBlock => {}
                }
            }
            ready_result = readable_optional(sockets.v6.as_deref()), if sockets.v6.is_some() => {
                ready_result?;
                let Some(socket) = sockets.v6.as_deref() else {
                    continue;
                };
                match write_udp_responses(writer, socket, &mut buffers.recv_v6, UdpResponseIpVersion::V6).await? {
                    WriteBackStatus::Written(n) => state.add_received(n as u64),
                    WriteBackStatus::Closed => return Ok(()),
                    WriteBackStatus::Dropped | WriteBackStatus::WouldBlock => {}
                }
            }
        }
    }
}

struct UdpToSnellBuffers {
    recv_v4: UdpRecvBatch,
    recv_v6: UdpRecvBatch,
}

impl UdpToSnellBuffers {
    fn new(max_udp_application_payload_len: usize) -> Self {
        Self {
            recv_v4: UdpRecvBatch::new(max_udp_application_payload_len),
            recv_v6: UdpRecvBatch::new(max_udp_application_payload_len),
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

async fn write_udp_responses<W>(
    writer: &mut SnellStreamWriter<W>,
    socket: &UdpSocket,
    recv_batch: &mut UdpRecvBatch,
    ip_version: UdpResponseIpVersion,
) -> Result<WriteBackStatus>
where
    W: AsyncWrite + Unpin,
{
    let prefix_len = ip_version.prefix_len();
    let payload_limit = writer
        .max_udp_application_payload_len()
        .checked_sub(prefix_len)
        .ok_or(Error::PayloadTooLarge)?;
    let count = match recv_batch
        .recv_from_with_headroom(socket, prefix_len, payload_limit)
        .await
    {
        Ok(count) => count,
        Err(err) if err.is_closed_io() => return Ok(WriteBackStatus::Closed),
        Err(err) => return Err(err),
    };
    if count == 0 {
        return Ok(WriteBackStatus::WouldBlock);
    }

    let mut written = 0;
    let mut dropped = false;
    for index in 0..count {
        let Some(entry) = recv_batch.get(index) else {
            continue;
        };
        let peer = entry.peer();
        let payload_len = entry.payload_len();
        if entry.is_oversized() {
            tracing::debug!("dropped oversized udp response");
            dropped = true;
            continue;
        }
        if !ip_version.matches(peer.ip()) {
            tracing::debug!(%peer, "ignored udp response from unexpected address family");
            dropped = true;
            continue;
        }

        {
            let mut entry = recv_batch
                .get_mut(index)
                .expect("checked UDP batch index must exist");
            let mut prefix = &mut entry.datagram_mut()[..prefix_len];
            write_udp_response_prefix(&mut prefix, AddressRef::Ip(peer.ip()), peer.port())?;
            debug_assert!(prefix.is_empty());
            if let Err(err) = writer
                .write_payload_message_from_buffer(entry.datagram_mut())
                .await
            {
                if err.is_closed_io() {
                    return Ok(WriteBackStatus::Closed);
                }
                return Err(err);
            }
        }
        written += payload_len;
    }

    if written > 0 {
        Ok(WriteBackStatus::Written(written))
    } else if dropped {
        Ok(WriteBackStatus::Dropped)
    } else {
        Ok(WriteBackStatus::WouldBlock)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpResponseIpVersion {
    V4,
    V6,
}

impl UdpResponseIpVersion {
    const fn prefix_len(self) -> usize {
        match self {
            Self::V4 => 1 + 4 + 2,
            Self::V6 => 1 + 16 + 2,
        }
    }

    const fn matches(self, ip: std::net::IpAddr) -> bool {
        matches!(
            (self, ip),
            (Self::V4, std::net::IpAddr::V4(_)) | (Self::V6, std::net::IpAddr::V6(_))
        )
    }
}

#[cfg(test)]
mod tests;

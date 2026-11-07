//! Server side of Snell UDP: one association per Snell connection, relayed
//! through the configured outbound.

use std::sync::atomic::Ordering;

use snell_protocol::{Error, RecordDecoder, RecordEncoder, decode_udp_request};
use tokio::net::TcpStream;
use tokio::time::Instant;

use super::outbound::UdpFlow;
use crate::ServerConfig;
use crate::buffer::PooledBuffer;
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::session::{RecordEvent, decode_once, write_reject, write_tunnel, write_udp_response};

/// Relay one Snell UDP association through the server's outbound.
pub(crate) async fn run_server_udp<E: RecordEncoder, D: RecordDecoder>(
    snell: &mut TcpStream,
    encoder: &mut E,
    decoder: &mut D,
    config: &ServerConfig,
    kdf: &KdfLimiter,
    recv: &mut PooledBuffer,
) -> Result<(), SessionError> {
    let (buffers, udp) = (&config.buffers, &config.udp);
    let Some(_slot) = udp.metrics.admit(udp.limits.max_associations) else {
        let _ = write_reject(encoder, buffers, snell, "udp association limit").await;
        return Err(SessionError::UdpLimit);
    };

    let mut flow = match UdpFlow::open(config.outbound, &udp.dns).await {
        Ok(flow) => flow,
        Err(error) => {
            let _ = write_reject(encoder, buffers, snell, &error.to_string()).await;
            return Err(error);
        }
    };
    write_tunnel(encoder, buffers, snell).await?;
    // `peer` comes from the enclosing `session` span.
    tracing::info!(outbound = ?config.outbound, "udp association established");

    let (mut snell_r, mut snell_w) = snell.split();
    let sleep = tokio::time::sleep(udp.limits.idle);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            _ = &mut sleep => {
                udp.metrics.idle_expired.fetch_add(1, Ordering::Relaxed);
                tracing::debug!("udp association expired after idle timeout");
                return Ok(());
            }
            record = decode_once(decoder, recv, &mut snell_r, kdf, &config.psk) => {
                sleep.as_mut().reset(Instant::now() + udp.limits.idle);
                let RecordEvent::Data(record) = record? else {
                    return Ok(());
                };
                let sent = match decode_udp_request(record.plaintext(recv.filled())) {
                    Ok(packet) => {
                        let dest = packet.address;
                        tracing::trace!(%dest, len = packet.payload.len(), "udp send");
                        flow.send(dest, packet.payload, &udp.dns)
                            .await
                            .inspect_err(|error| tracing::debug!(%dest, %error, "udp send failed"))
                    }
                    Err(error) => {
                        tracing::debug!(%error, "malformed udp request");
                        Err(error.into())
                    }
                };
                if sent.is_err() {
                    udp.metrics.invalid.fetch_add(1, Ordering::Relaxed);
                }
                decoder.consume(recv, &record)?;
            }
            reply = flow.recv(buffers, &udp.metrics) => {
                sleep.as_mut().reset(Instant::now() + udp.limits.idle);
                let reply = reply?;
                match write_udp_response(encoder, buffers, &mut snell_w, reply.addr, reply.payload())
                    .await
                {
                    Err(SessionError::Protocol(Error::PayloadTooLarge)) => {
                        udp.metrics.oversize.fetch_add(1, Ordering::Relaxed);
                    }
                    result => result?,
                }
            }
        }
    }
}

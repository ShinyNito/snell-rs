//! Server side of Snell UDP: one association per Snell connection, relayed
//! through the configured outbound.

use std::sync::atomic::Ordering;

use snell_protocol::{Error, RecordDecoder, RecordEncoder, decode_udp_request};
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::ServerConfig;
use crate::buffer::PooledBuffer;
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::session::{RecordEvent, decode_once, write_reject, write_tunnel, write_udp_response};
use crate::udp::UdpMetrics;

struct AssocGuard<'a>(&'a UdpMetrics);

impl Drop for AssocGuard<'_> {
    fn drop(&mut self) {
        self.0.associations.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Relay one Snell UDP association through the server's outbound.
pub(crate) async fn run_server_udp<E: RecordEncoder, D: RecordDecoder>(
    mut snell: TcpStream,
    encoder: &mut E,
    decoder: &mut D,
    config: &ServerConfig,
    kdf: &KdfLimiter,
    mut recv: PooledBuffer,
) -> Result<(), SessionError> {
    let (buffers, udp) = (&config.buffers, &config.udp);
    let max = udp.limits.max_associations as u64;
    let admitted = udp
        .metrics
        .associations
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            (n < max).then_some(n + 1)
        });
    if admitted.is_err() {
        udp.metrics.map_full.fetch_add(1, Ordering::Relaxed);
        let _ = write_reject(encoder, buffers, &mut snell, "udp association limit").await;
        return Err(SessionError::UdpLimit);
    }
    let _guard = AssocGuard(&udp.metrics);

    let flow = match config.outbound.open_udp(&udp.dns).await {
        Ok(flow) => flow,
        Err(error) => {
            let _ = write_reject(encoder, buffers, &mut snell, &error.to_string()).await;
            return Err(error);
        }
    };
    write_tunnel(encoder, buffers, &mut snell).await?;

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
            record = decode_once(decoder, &mut recv, &mut snell_r, kdf, &config.psk) => {
                sleep.as_mut().reset(Instant::now() + udp.limits.idle);
                let RecordEvent::Data(record) = record? else {
                    return Ok(());
                };
                let sent = match decode_udp_request(record.plaintext(recv.filled())) {
                    Ok(packet) => flow.send(packet.address, packet.payload, &udp.dns).await,
                    Err(error) => Err(error.into()),
                };
                if sent.is_err() {
                    udp.metrics.invalid.fetch_add(1, Ordering::Relaxed);
                }
                decoder.consume(&mut recv, &record)?;
            }
            reply = flow.recv(buffers, &udp.metrics.frag_dropped, &udp.metrics.invalid) => {
                sleep.as_mut().reset(Instant::now() + udp.limits.idle);
                let reply = reply?;
                let address = reply.addr.as_view();
                match write_udp_response(encoder, buffers, &mut snell_w, address, reply.payload())
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

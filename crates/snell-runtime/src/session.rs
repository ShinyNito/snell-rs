use crate::buffer::{BufferPool, PooledBuffer};
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use snell_protocol::{
    Address, AddressRef, COMMAND_UDP, DecodeStatus, Error, MAX_CONNECT_REQUEST_LEN,
    MAX_PACKET_SIZE_V6, ParseState, PlainStream, Psk, REUSE_IDLE_TIMEOUT_SECS, RecordKind,
    SERVER_EARLY_PAYLOAD_MAX, ServerReply, TCP_HANDSHAKE_TIMEOUT_SECS, aead_key,
    encode_connect_request, encode_reject, encode_tunnel_reply, encode_udp_request,
    encode_udp_response, encode_udp_setup, udp_request_len, udp_response_len,
};
use tokio::io::AsyncWrite;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::bufio::{READ_WINDOW, ReadReady, TcpReservation, poll_read_into, poll_read_record};
use crate::bufio::{drain_encode, read_into_recv};
use crate::codec::{TcpDecoder, TcpEncoder};
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::replay::ReplayCache;

const RECORD_HINT: usize = MAX_PACKET_SIZE_V6;
pub(crate) const HANDSHAKE_PLAIN_MAX: usize = MAX_CONNECT_REQUEST_LEN + MAX_PACKET_SIZE_V6;

pub(crate) async fn with_handshake_timeout<F, T>(fut: F) -> Result<T, SessionError>
where
    F: Future<Output = Result<T, SessionError>>,
{
    match timeout(Duration::from_secs(TCP_HANDSHAKE_TIMEOUT_SECS), fut).await {
        Ok(result) => result,
        Err(_) => Err(SessionError::HandshakeTimeout),
    }
}

pub(crate) async fn with_reuse_idle_timeout<F, T>(fut: F) -> Result<T, SessionError>
where
    F: Future<Output = Result<T, SessionError>>,
{
    match timeout(Duration::from_secs(REUSE_IDLE_TIMEOUT_SECS), fut).await {
        Ok(result) => result,
        Err(_) => Err(SessionError::ReuseIdleTimeout),
    }
}

pub(crate) async fn write_udp_setup<E: TcpEncoder, W: AsyncWrite + Unpin>(
    encoder: &mut E,
    buffers: &Arc<BufferPool>,
    writer: &mut W,
) -> Result<(), SessionError> {
    let mut req = [0u8; 3];
    let n = encode_udp_setup(&mut req)?;
    write_plain_records(encoder, buffers, writer, &req[..n]).await
}

pub(crate) async fn write_udp_request<E: TcpEncoder, W: AsyncWrite + Unpin>(
    encoder: &mut E,
    buffers: &Arc<BufferPool>,
    writer: &mut W,
    address: AddressRef<'_>,
    payload: &[u8],
) -> Result<(), SessionError> {
    let needed = udp_request_len(address, payload.len())?;
    write_udp_plain(encoder, buffers, writer, needed, |dst| {
        encode_udp_request(dst, address, payload)
    })
    .await
}

pub(crate) async fn write_udp_response<E: TcpEncoder, W: AsyncWrite + Unpin>(
    encoder: &mut E,
    buffers: &Arc<BufferPool>,
    writer: &mut W,
    address: AddressRef<'_>,
    payload: &[u8],
) -> Result<(), SessionError> {
    let needed = udp_response_len(address, payload.len())?;
    write_udp_plain(encoder, buffers, writer, needed, |dst| {
        encode_udp_response(dst, address, payload)
    })
    .await
}

async fn write_udp_plain<E, W, F>(
    encoder: &mut E,
    buffers: &Arc<BufferPool>,
    writer: &mut W,
    needed: usize,
    fill: F,
) -> Result<(), SessionError>
where
    E: TcpEncoder,
    W: AsyncWrite + Unpin,
    F: FnOnce(&mut [u8]) -> snell_protocol::Result<usize>,
{
    let mut encode = buffers.get(snell_protocol::V6_WIRE_CAP);
    encode_record(encoder, &mut encode, needed, |slot| {
        if slot.len() < needed {
            return Err(Error::PayloadTooLarge);
        }
        fill(slot)
    })?;
    drain_encode(writer, &mut encode).await
}

// Let the codec report the exact required capacity. This keeps protocol
// overhead calculations out of the runtime, including shaped padding.
fn encode_record<E: TcpEncoder>(
    encoder: &mut E,
    encode: &mut PooledBuffer,
    hint: usize,
    fill: impl FnOnce(&mut [u8]) -> snell_protocol::Result<usize>,
) -> Result<usize, SessionError> {
    loop {
        let needed = match encoder.reserve(encode, &[], hint) {
            Err(Error::BufferTooSmall { needed, .. }) => needed,
            Err(error) => return Err(error.into()),
            Ok(mut reservation) => {
                let n = fill(reservation.payload_mut())?;
                reservation.seal(n)?;
                return Ok(n);
            }
        };
        encode.ensure(needed)?;
    }
}

pub(crate) async fn write_connect<E: TcpEncoder, W: AsyncWrite + Unpin>(
    encoder: &mut E,
    buffers: &Arc<BufferPool>,
    writer: &mut W,
    destination: AddressRef<'_>,
    reuse: bool,
) -> Result<(), SessionError> {
    let mut req = [0u8; MAX_CONNECT_REQUEST_LEN];
    let n = encode_connect_request(&mut req, destination, reuse)?;
    write_plain_records(encoder, buffers, writer, &req[..n]).await
}

pub(crate) async fn write_tunnel<E: TcpEncoder, W: AsyncWrite + Unpin>(
    encoder: &mut E,
    buffers: &Arc<BufferPool>,
    writer: &mut W,
) -> Result<(), SessionError> {
    let mut buf = [0u8; 1];
    let n = encode_tunnel_reply(&mut buf)?;
    write_plain_records(encoder, buffers, writer, &buf[..n]).await
}

pub(crate) async fn write_reject<E: TcpEncoder, W: AsyncWrite + Unpin>(
    encoder: &mut E,
    buffers: &Arc<BufferPool>,
    writer: &mut W,
    message: &str,
) -> Result<(), SessionError> {
    let mut buf = [0u8; 3 + 255];
    let n = encode_reject(&mut buf, message)?;
    write_plain_records(encoder, buffers, writer, &buf[..n]).await
}

async fn write_plain_records<E: TcpEncoder, W: AsyncWrite + Unpin>(
    encoder: &mut E,
    buffers: &Arc<BufferPool>,
    writer: &mut W,
    mut src: &[u8],
) -> Result<(), SessionError> {
    let mut encode = buffers.get(snell_protocol::V6_WIRE_CAP);
    while !src.is_empty() {
        if !encode.is_empty() {
            drain_encode(writer, &mut encode).await?;
        }
        let take = encode_record(encoder, &mut encode, src.len(), |slot| {
            let take = slot.len().min(src.len());
            if take == 0 {
                return Err(Error::PayloadTooLarge);
            }
            slot[..take].copy_from_slice(&src[..take]);
            Ok(take)
        })?;
        src = &src[take..];
    }
    drain_encode(writer, &mut encode).await?;
    Ok(())
}

pub(crate) async fn read_server_tunnel<D: TcpDecoder, R: ReadReady + Unpin>(
    decoder: &mut D,
    recv: &mut PooledBuffer,
    reader: &mut R,
    kdf: &KdfLimiter,
    psk: &Psk,
) -> Result<Vec<u8>, SessionError> {
    let mut plain = PlainStream::new(HANDSHAKE_PLAIN_MAX);
    loop {
        match decode_once(decoder, recv, reader, kdf, psk).await? {
            RecordEvent::Zero => {
                return Err(SessionError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "zero chunk before tunnel",
                )));
            }
            RecordEvent::Data(record) => {
                plain.push(record.plaintext(recv.filled()))?;
                decoder.consume(recv, &record)?;
                match plain.server_reply()? {
                    ParseState::Need(_) => {}
                    ParseState::Done((ServerReply::Tunnel, n)) => {
                        return Ok(plain.filled()[n..].to_vec());
                    }
                    ParseState::Done((ServerReply::Error { code, .. }, _)) => {
                        return Err(SessionError::ServerReject { code });
                    }
                }
            }
        }
    }
}

pub(crate) struct ServerConnect {
    pub destination: Address,
    pub leftover: Vec<u8>,
    pub reuse: bool,
}

pub(crate) enum ServerFirst {
    Connect(ServerConnect),
    Udp,
}

pub(crate) async fn read_server_connect<D: TcpDecoder, R: ReadReady + Unpin>(
    decoder: &mut D,
    recv: &mut PooledBuffer,
    reader: &mut R,
    kdf: &KdfLimiter,
    psk: &Psk,
    replay: Option<&ReplayCache>,
) -> Result<ServerFirst, SessionError> {
    let mut plain = PlainStream::new(HANDSHAKE_PLAIN_MAX);
    let mut replay_checked = replay.is_none();
    loop {
        match decode_once(decoder, recv, reader, kdf, psk).await? {
            RecordEvent::Zero => {
                return Err(SessionError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "zero chunk before CONNECT",
                )));
            }
            RecordEvent::Data(record) => {
                if !replay_checked {
                    replay_checked = true;
                    if let (Some(cache), Some(id)) = (replay, decoder.replay_identity()) {
                        cache.insert(id)?;
                    }
                }
                plain.push(record.plaintext(recv.filled()))?;
                decoder.consume(recv, &record)?;
                match plain.connect() {
                    Ok(ParseState::Need(_)) => {}
                    Ok(ParseState::Done((request, n))) => {
                        let mut leftover = plain.filled()[n..].to_vec();
                        drain_early_payload(decoder, recv, reader, kdf, psk, &mut leftover).await?;
                        if leftover.len() > SERVER_EARLY_PAYLOAD_MAX {
                            return Err(SessionError::EarlyPayloadTooLarge);
                        }
                        return Ok(ServerFirst::Connect(ServerConnect {
                            destination: request.destination,
                            leftover,
                            reuse: request.reuse,
                        }));
                    }
                    Err(Error::UnknownCommand(COMMAND_UDP)) => match plain.udp_setup()? {
                        ParseState::Need(_) => {}
                        ParseState::Done(n) => {
                            if plain.filled().len() != n {
                                return Err(SessionError::Protocol(Error::Malformed(
                                    "udp setup must occupy the whole record",
                                )));
                            }
                            return Ok(ServerFirst::Udp);
                        }
                    },
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
}

/// One decoded record. `Data` borrows from the receive buffer: the caller
/// processes `record.plaintext(recv.filled())` and then calls
/// `decoder.consume(recv, &record)` exactly once before the next decode.
/// `Zero` is already consumed. No owned copy in steady state.
pub(crate) enum RecordEvent {
    Zero,
    Data(snell_protocol::DecodedRecord),
}

async fn drain_early_payload<D: TcpDecoder, R: ReadReady + Unpin>(
    decoder: &mut D,
    recv: &mut PooledBuffer,
    reader: &mut R,
    kdf: &KdfLimiter,
    psk: &Psk,
    leftover: &mut Vec<u8>,
) -> Result<(), SessionError> {
    loop {
        if leftover.len() > SERVER_EARLY_PAYLOAD_MAX {
            return Err(SessionError::EarlyPayloadTooLarge);
        }
        maybe_install_kdf(decoder, recv, kdf, psk).await?;
        match decoder.decode(recv) {
            Ok(DecodeStatus::NeedMore { minimum }) => {
                // Drain only currently ready input: never wait for more early
                // payload before opening the upstream connection.
                let read =
                    poll_fn(|cx| Poll::Ready(poll_read_into(reader, recv, minimum, 4096, cx)))
                        .await;
                match read {
                    Poll::Pending | Poll::Ready(Ok(0)) => return Ok(()),
                    Poll::Ready(Ok(_)) => continue,
                    Poll::Ready(Err(e)) => return Err(e),
                }
            }
            Ok(DecodeStatus::Record(record)) => {
                if record.kind == RecordKind::ZeroChunk {
                    decoder.consume(recv, &record)?;
                    return Ok(());
                }
                let bytes = record.plaintext(recv.filled());
                if bytes.len() > SERVER_EARLY_PAYLOAD_MAX - leftover.len() {
                    return Err(SessionError::EarlyPayloadTooLarge);
                }
                leftover.extend_from_slice(bytes);
                decoder.consume(recv, &record)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

pub(crate) async fn decode_once<D: TcpDecoder, R: ReadReady + Unpin>(
    decoder: &mut D,
    recv: &mut PooledBuffer,
    reader: &mut R,
    kdf: &KdfLimiter,
    psk: &Psk,
) -> Result<RecordEvent, SessionError> {
    loop {
        maybe_install_kdf(decoder, recv, kdf, psk).await?;
        match decoder.decode(recv)? {
            DecodeStatus::NeedMore { minimum } => {
                fill_until(reader, recv, minimum).await?;
            }
            DecodeStatus::Record(record) => {
                if record.kind == RecordKind::ZeroChunk {
                    decoder.consume(recv, &record)?;
                    return Ok(RecordEvent::Zero);
                }
                return Ok(RecordEvent::Data(record));
            }
        }
    }
}

pub(crate) async fn maybe_install_kdf<D: TcpDecoder>(
    decoder: &mut D,
    recv: &PooledBuffer,
    kdf: &KdfLimiter,
    psk: &Psk,
) -> Result<(), SessionError> {
    let need = decoder.kdf_need();
    if need == 0 || recv.len() < need {
        return Ok(());
    }
    let salt = decoder.kdf_salt(recv)?;
    let psk_bytes = psk.as_bytes().to_vec();
    let key = kdf.run(move || aead_key(&psk_bytes, &salt)).await??;
    decoder.install_aead(salt, key)?;
    Ok(())
}

pub(crate) async fn wait_reuse_idle<R: ReadReady + Unpin>(
    reader: &mut R,
    recv: &mut PooledBuffer,
) -> Result<(), SessionError> {
    if !recv.is_empty() {
        return Ok(());
    }
    with_reuse_idle_timeout(async {
        if read_into_recv(reader, recv, 1).await? == 0 {
            return Err(
                io::Error::new(io::ErrorKind::UnexpectedEof, "eof during reuse idle").into(),
            );
        }
        Ok(())
    })
    .await
}

pub(crate) fn client_may_pool<D: TcpDecoder>(recv: &PooledBuffer, decoder: &D) -> bool {
    recv.is_empty() && !decoder.has_unconsumed_plaintext()
}

pub(crate) fn server_may_reuse<D: TcpDecoder>(decoder: &D) -> bool {
    !decoder.has_unconsumed_plaintext()
}

async fn fill_until<R: ReadReady + Unpin>(
    reader: &mut R,
    recv: &mut PooledBuffer,
    minimum: usize,
) -> Result<(), SessionError> {
    while recv.len() < minimum {
        let n = read_into_recv(reader, recv, minimum).await?;
        if n == 0 {
            return Err(SessionError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof during handshake",
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay<E: TcpEncoder, D: TcpDecoder>(
    snell: &mut TcpStream,
    plain: &mut TcpStream,
    encoder: &mut E,
    decoder: &mut D,
    recv: &mut PooledBuffer,
    initial_to_plain: Vec<u8>,
    keep_snell_open: bool,
) -> Result<(), SessionError> {
    if !initial_to_plain.is_empty() {
        tokio::io::AsyncWriteExt::write_all(plain, &initial_to_plain).await?;
    }

    drop(initial_to_plain);
    let (mut snell_r, mut snell_w) = snell.split();
    let (mut plain_r, mut plain_w) = plain.split();
    let buffers = Arc::clone(recv.pool());
    tokio::try_join!(
        pump_plain_to_snell(
            &mut plain_r,
            &mut snell_w,
            encoder,
            &buffers,
            keep_snell_open,
        ),
        pump_snell_to_plain(&mut snell_r, &mut plain_w, decoder, recv),
    )?;
    Ok(())
}

async fn pump_plain_to_snell<R, W, E>(
    reader: &mut R,
    writer: &mut W,
    encoder: &mut E,
    buffers: &Arc<BufferPool>,
    keep_snell_open: bool,
) -> Result<(), SessionError>
where
    R: ReadReady + Unpin,
    W: AsyncWrite + Unpin,
    E: TcpEncoder,
{
    let mut encode = buffers.get(snell_protocol::V6_WIRE_CAP);
    let mut local_eof = false;
    let mut zero_sent = false;
    let mut shutting_down = false;
    poll_fn(|cx| {
        loop {
            if shutting_down {
                return match Pin::new(&mut *writer).poll_shutdown(cx) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
                    Poll::Pending => Poll::Pending,
                };
            }

            if !local_eof && encode.is_empty() {
                loop {
                    let had_pending = !encode.is_empty();
                    match reader.poll_ready(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                        Poll::Pending => {
                            if !had_pending {
                                encode.release_empty();
                                return Poll::Pending;
                            }
                            break;
                        }
                    }
                    if let Err(e) = encode.ensure(encode.max()) {
                        return Poll::Ready(Err(e));
                    }
                    let hint = RECORD_HINT;
                    let read = loop {
                        let needed = match encoder.reserve(&mut encode, &[], hint) {
                            Err(Error::BufferTooSmall { needed, .. }) => needed,
                            Err(error) => break Poll::Ready(Err(error.into())),
                            Ok(reservation) => break poll_read_record(reader, reservation, cx),
                        };
                        if let Err(error) = encode.ensure(needed) {
                            break Poll::Ready(Err(error));
                        }
                    };
                    match read {
                        Poll::Ready(Ok(0)) => {
                            local_eof = true;
                            break;
                        }
                        Poll::Ready(Ok(_)) => {}
                        Poll::Ready(Err(SessionError::Protocol(Error::PayloadTooLarge)))
                            if had_pending =>
                        {
                            break;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => {
                            if !had_pending {
                                encode.release_empty();
                                return Poll::Pending;
                            }
                            break;
                        }
                    }
                }
            }

            if local_eof && !zero_sent {
                let had_pending = !encode.is_empty();
                match encode_record(encoder, &mut encode, 0, |_| Ok(0)) {
                    Ok(_) => zero_sent = true,
                    Err(SessionError::Protocol(Error::PayloadTooLarge)) => {
                        if !had_pending {
                            return Poll::Ready(Err(Error::PayloadTooLarge.into()));
                        }
                    }
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }

            if !encode.is_empty() {
                match Pin::new(&mut *writer).poll_write(cx, encode.filled()) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(SessionError::Io(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "snell write returned zero",
                        ))));
                    }
                    Poll::Ready(Ok(n)) => {
                        if let Err(error) = encode.consume(n) {
                            return Poll::Ready(Err(error.into()));
                        }
                        encode.release_empty();
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Pending => return Poll::Pending,
                }
                continue;
            }

            if local_eof && zero_sent {
                encode.release_empty();
                if keep_snell_open {
                    return Poll::Ready(Ok(()));
                }
                shutting_down = true;
                continue;
            }

            return Poll::Pending;
        }
    })
    .await
}

/// Vectored-write fan-in limit: at most this many decoded records are
/// flushed per `writev`. Sized so max-size v4 records can fill the batch
/// without exceeding the receive buffer.
const WRITE_BATCH_MAX: usize = 16;

async fn pump_snell_to_plain<R, W, D>(
    reader: &mut R,
    writer: &mut W,
    decoder: &mut D,
    recv: &mut PooledBuffer,
) -> Result<(), SessionError>
where
    R: ReadReady + Unpin,
    W: AsyncWrite + Unpin,
    D: TcpDecoder,
{
    // Decoded-ahead records not yet written: their plaintext ranges stay
    // valid against the unmoved `filled()` view until any is consumed, so
    // the batch is flushed with one vectored write, then consumed FIFO.
    // Batch metadata uses fixed-size slots.
    let mut batch: [Option<snell_protocol::DecodedRecord>; WRITE_BATCH_MAX] = Default::default();
    let mut batch_count = 0usize;
    let mut batch_len = 0usize;
    let mut write_off = 0usize;
    let mut end_after_batch = false;
    let mut deferred: Option<SessionError> = None;
    let mut protocol_end = false;
    let mut shutting_down = false;
    poll_fn(|cx| {
        loop {
            if shutting_down {
                recv.release_empty();
                return match Pin::new(&mut *writer).poll_shutdown(cx) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
                    Poll::Pending => Poll::Pending,
                };
            }

            if batch_count > 0 {
                if write_off < batch_len {
                    let filled = recv.filled();
                    let mut slices = [io::IoSlice::new(&[]); WRITE_BATCH_MAX];
                    let mut count = 0usize;
                    let mut skip = write_off;
                    for record in batch[..batch_count].iter().flatten() {
                        let plain = record.plaintext(filled);
                        if skip >= plain.len() {
                            skip -= plain.len();
                            continue;
                        }
                        slices[count] = io::IoSlice::new(&plain[skip..]);
                        skip = 0;
                        count += 1;
                    }
                    match Pin::new(&mut *writer).poll_write_vectored(cx, &slices[..count]) {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(SessionError::Io(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "plain write returned zero",
                            ))));
                        }
                        Poll::Ready(Ok(n)) => {
                            write_off += n;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                        Poll::Pending => return Poll::Pending,
                    }
                    continue;
                }
                for slot in batch[..batch_count].iter_mut() {
                    if let Some(record) = slot.take()
                        && let Err(error) = decoder.consume(recv, &record)
                    {
                        return Poll::Ready(Err(error.into()));
                    }
                }
                batch_count = 0;
                batch_len = 0;
                write_off = 0;
                if let Some(error) = deferred.take() {
                    return Poll::Ready(Err(error));
                }
                if end_after_batch {
                    protocol_end = true;
                }
                continue;
            }

            if protocol_end {
                shutting_down = true;
                continue;
            }

            // Fill a batch by decode-ahead. No reads happen mid-batch, so no
            // compaction can move the plaintext under the collected ranges.
            loop {
                match decoder.decode(recv) {
                    Ok(DecodeStatus::NeedMore { minimum }) => {
                        if batch_count > 0 {
                            // Flush what is ready before reading more.
                            break;
                        }
                        let n = match poll_read_into(reader, recv, minimum, READ_WINDOW, cx) {
                            Poll::Ready(Ok(n)) => n,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => {
                                recv.release_empty();
                                return Poll::Pending;
                            }
                        };
                        if n == 0 {
                            if recv.is_empty() {
                                protocol_end = false;
                                shutting_down = true;
                                break;
                            }
                            return Poll::Ready(Err(SessionError::Io(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "eof mid-record",
                            ))));
                        }
                    }
                    Ok(DecodeStatus::Record(record)) => {
                        if record.kind == RecordKind::ZeroChunk {
                            if batch_count == 0 {
                                if let Err(error) = decoder.consume(recv, &record) {
                                    return Poll::Ready(Err(error.into()));
                                }
                                protocol_end = true;
                            } else {
                                // Consumed FIFO with the batch, then end.
                                batch[batch_count] = Some(record);
                                batch_count += 1;
                                end_after_batch = true;
                            }
                            break;
                        }
                        batch_len += record.plaintext.len();
                        batch[batch_count] = Some(record);
                        batch_count += 1;
                        if batch_count == WRITE_BATCH_MAX {
                            break;
                        }
                    }
                    Err(error) => {
                        if batch_count == 0 {
                            return Poll::Ready(Err(error.into()));
                        }
                        // Flush decoded records before surfacing the error,
                        // matching the former write-per-record order.
                        deferred = Some(error.into());
                        break;
                    }
                }
            }
        }
    })
    .await
}

#[cfg(test)]
mod buffer_tests {
    use super::*;
    use crate::buffer::BufferPool;
    use std::sync::Arc;
    use std::task::Context;
    use tokio::io::{AsyncRead, ReadBuf};

    struct Input<'a> {
        bytes: &'a [u8],
        reads: usize,
    }
    impl AsyncRead for Input<'_> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let n = self.bytes.len().min(buf.remaining());
            if n > 0 {
                self.reads += 1;
            }
            buf.put_slice(&self.bytes[..n]);
            self.bytes = &self.bytes[n..];
            Poll::Ready(Ok(()))
        }
    }
    impl ReadReady for Input<'_> {
        fn poll_ready(&self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    struct Output {
        bytes: Vec<u8>,
        limit: usize,
        writes: usize,
        pending: bool,
    }
    impl AsyncWrite for Output {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.poll_write_vectored(cx, &[io::IoSlice::new(bytes)])
        }
        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            slices: &[io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            if self.pending {
                self.pending = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let mut written = 0;
            for bytes in slices {
                let n = bytes.len().min(self.limit - written);
                self.bytes.extend_from_slice(&bytes[..n]);
                written += n;
                if written == self.limit {
                    break;
                }
            }
            self.pending = self.limit != usize::MAX;
            self.writes += 1;
            Poll::Ready(Ok(written))
        }
        fn is_write_vectored(&self) -> bool {
            true
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            panic!("relay must not issue per-record flushes")
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn one_bulk_read_decodes_many_records_and_survives_short_writes() {
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let mut encoder = snell_protocol::V4Encoder::os(&psk).unwrap();
        let mut wire = snell_protocol::Buffer::new(snell_protocol::V6_WIRE_CAP);
        let mut expected = Vec::new();
        for byte in [1, 2, 3] {
            let mut r = encoder.reserve(&mut wire, &[], 1460).unwrap();
            let n = r.capacity();
            r.payload_mut()[..n].fill(byte);
            r.seal(n).unwrap();
            expected.extend(std::iter::repeat_n(byte, n));
        }
        encoder.reserve(&mut wire, &[], 0).unwrap().seal(0).unwrap();
        for limit in [usize::MAX, 7] {
            let pool = Arc::new(BufferPool::default());
            let mut recv = pool.get(snell_protocol::V6_WIRE_CAP);
            let mut decoder = snell_protocol::V4Decoder::new(psk.clone());
            let mut input = Input {
                bytes: wire.filled(),
                reads: 0,
            };
            let mut output = Output {
                bytes: Vec::new(),
                limit,
                writes: 0,
                pending: false,
            };
            pump_snell_to_plain(&mut input, &mut output, &mut decoder, &mut recv)
                .await
                .unwrap();
            assert_eq!(output.bytes, expected);
            assert_eq!(input.reads, 1, "bulk read must span all records");
            if limit == usize::MAX {
                assert_eq!(output.writes, 1, "decode-ahead must produce one writev");
            }
            drop(recv);
            assert_eq!(pool.leased_bytes(), 0);
        }
    }

    #[tokio::test]
    async fn incremental_prefix_read_grows_past_handshake_window() {
        let pool = Arc::new(BufferPool::default());
        let mut recv = pool.get(8192);
        recv.extend(&[0x55; 4096]).unwrap();
        let mut input = Input {
            bytes: b"next",
            reads: 0,
        };
        assert_eq!(read_into_recv(&mut input, &mut recv, 1).await.unwrap(), 4);
        assert_eq!(recv.len(), 4100);
        assert_eq!(&recv.filled()[4096..], b"next");
        assert!(recv.filled()[..4096].iter().all(|&b| b == 0x55));
    }

    #[tokio::test]
    async fn maximum_records_survive_partial_writes_across_batches() {
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let mut encoder = snell_protocol::V4Encoder::os(&psk).unwrap();
        let mut wire = snell_protocol::Buffer::new(snell_protocol::V6_WIRE_CAP);
        // V4 increases its record budget after successful records.
        for _ in 0..16 {
            let mut record = encoder.reserve(&mut wire, &[], 1).unwrap();
            record.payload_mut()[0] = 0x55;
            record.seal(1).unwrap();
        }
        let mut record = encoder
            .reserve(&mut wire, &[], snell_protocol::MAX_PACKET_SIZE)
            .unwrap();
        assert_eq!(record.capacity(), snell_protocol::MAX_PACKET_SIZE);
        record.payload_mut().fill(0x55);
        record.seal(snell_protocol::MAX_PACKET_SIZE).unwrap();
        encoder.reserve(&mut wire, &[], 0).unwrap().seal(0).unwrap();
        let pool = Arc::new(BufferPool::default());
        for _ in 0..2 {
            let mut recv = pool.get(snell_protocol::V6_WIRE_CAP);
            let mut decoder = snell_protocol::V4Decoder::new(psk.clone());
            let mut input = Input {
                bytes: wire.filled(),
                reads: 0,
            };
            let mut output = Output {
                bytes: Vec::new(),
                limit: 257,
                writes: 0,
                pending: false,
            };
            pump_snell_to_plain(&mut input, &mut output, &mut decoder, &mut recv)
                .await
                .unwrap();
            assert_eq!(
                output.bytes,
                vec![0x55; 16 + snell_protocol::MAX_PACKET_SIZE]
            );
            assert_eq!(pool.leased_bytes(), 0);
        }
    }

    struct GatedOutput {
        open: Arc<std::sync::atomic::AtomicBool>,
        bytes: Vec<u8>,
    }
    impl AsyncWrite for GatedOutput {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if !self.open.load(std::sync::atomic::Ordering::Relaxed) {
                return Poll::Pending;
            }
            self.bytes.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            panic!("unexpected flush")
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn backpressure_keeps_ciphertext_and_plaintext_until_written() {
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let pool = Arc::new(BufferPool::default());
        let open = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut output = GatedOutput {
            open: Arc::clone(&open),
            bytes: Vec::new(),
        };
        let mut encoder = snell_protocol::V4Encoder::os(&psk).unwrap();
        let mut buffer = pool.get(snell_protocol::V6_WIRE_CAP);
        let expected = vec![0x53; 20_000];
        let mut input = Input {
            bytes: &expected,
            reads: 0,
        };
        let mut cx = Context::from_waker(std::task::Waker::noop());
        {
            let pump = pump_plain_to_snell(&mut input, &mut output, &mut encoder, &pool, false);
            tokio::pin!(pump);
            assert!(pump.as_mut().poll(&mut cx).is_pending());
            let leased = pool.leased_bytes();
            assert!(leased > 0);
            tokio::time::advance(Duration::from_secs(5)).await;
            assert!(pump.as_mut().poll(&mut cx).is_pending());
            assert_eq!(pool.leased_bytes(), leased);
            open.store(true, std::sync::atomic::Ordering::Relaxed);
            pump.await.unwrap();
        }
        assert_eq!(pool.leased_bytes(), 0);
        let wire = output.bytes;
        let mut input = Input {
            bytes: &wire,
            reads: 0,
        };
        let mut decoder = snell_protocol::V4Decoder::new(psk);
        open.store(false, std::sync::atomic::Ordering::Relaxed);
        let mut output = GatedOutput {
            open: Arc::clone(&open),
            bytes: Vec::new(),
        };
        {
            let pump = pump_snell_to_plain(&mut input, &mut output, &mut decoder, &mut buffer);
            tokio::pin!(pump);
            assert!(pump.as_mut().poll(&mut cx).is_pending());
            let leased = pool.leased_bytes();
            assert!(leased > 0);
            tokio::time::advance(Duration::from_secs(5)).await;
            assert!(pump.as_mut().poll(&mut cx).is_pending());
            assert_eq!(pool.leased_bytes(), leased);
            open.store(true, std::sync::atomic::Ordering::Relaxed);
            pump.await.unwrap();
        }
        assert_eq!(output.bytes, expected);
        assert_eq!(pool.leased_bytes(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn partial_record_survives_pause_and_resumes() {
        // Keep a prefix while the peer pauses, then provide the remaining bytes.
        struct PausedInput<'a> {
            first: &'a [u8],
            rest: &'a [u8],
            open: Arc<std::sync::atomic::AtomicBool>,
        }
        impl ReadReady for PausedInput<'_> {
            fn poll_ready(&self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                if !self.first.is_empty() || self.open.load(std::sync::atomic::Ordering::Relaxed) {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
        }
        impl AsyncRead for PausedInput<'_> {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                dst: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let bytes = if !self.first.is_empty() {
                    &mut self.first
                } else if self.open.load(std::sync::atomic::Ordering::Relaxed) {
                    &mut self.rest
                } else {
                    return Poll::Pending;
                };
                let n = bytes.len().min(dst.remaining());
                dst.put_slice(&bytes[..n]);
                *bytes = &bytes[n..];
                Poll::Ready(Ok(()))
            }
        }
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let mut encoder = snell_protocol::V4Encoder::os(&psk).unwrap();
        let mut wire = snell_protocol::Buffer::new(snell_protocol::V6_WIRE_CAP);
        let mut r = encoder.reserve(&mut wire, &[], 128).unwrap();
        r.payload_mut()[..128].fill(0x69);
        r.seal(128).unwrap();
        encoder.reserve(&mut wire, &[], 0).unwrap().seal(0).unwrap();
        let open = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut input = PausedInput {
            first: &wire.filled()[..40],
            rest: &wire.filled()[40..],
            open: Arc::clone(&open),
        };
        let mut output = Output {
            bytes: Vec::new(),
            limit: usize::MAX,
            writes: 0,
            pending: false,
        };
        let pool = Arc::new(BufferPool::default());
        let mut buffer = pool.get(snell_protocol::V6_WIRE_CAP);
        let mut decoder = snell_protocol::V4Decoder::new(psk);
        {
            let pump = pump_snell_to_plain(&mut input, &mut output, &mut decoder, &mut buffer);
            tokio::pin!(pump);
            let mut cx = Context::from_waker(std::task::Waker::noop());
            assert!(pump.as_mut().poll(&mut cx).is_pending());
            let leased = pool.leased_bytes();
            assert!(leased > 0);
            tokio::time::advance(Duration::from_secs(5)).await;
            assert!(pump.as_mut().poll(&mut cx).is_pending());
            assert_eq!(pool.leased_bytes(), leased);
            open.store(true, std::sync::atomic::Ordering::Relaxed);
            pump.await.unwrap();
        }
        assert_eq!(output.bytes, vec![0x69; 128]);
        assert_eq!(pool.leased_bytes(), 0);
    }

    struct NotReady(bool);
    impl AsyncRead for NotReady {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl ReadReady for NotReady {
        fn poll_ready(&self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.0 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }

    #[tokio::test]
    async fn completed_batches_return_storage_while_the_connection_stays_open() {
        struct Burst<'a>(&'a [u8]);
        impl ReadReady for Burst<'_> {
            fn poll_ready(&self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                if self.0.is_empty() {
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(()))
                }
            }
        }
        impl AsyncRead for Burst<'_> {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                dst: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if self.0.is_empty() {
                    return Poll::Pending;
                }
                let n = self.0.len().min(dst.remaining());
                dst.put_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Poll::Ready(Ok(()))
            }
        }
        let pool = Arc::new(BufferPool::default());
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let mut encoder = snell_protocol::V4Encoder::os(&psk).unwrap();
        let mut decoder = snell_protocol::V4Decoder::new(psk);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        for fill in [0x41, 0x42, 0x43] {
            let payload = vec![fill; 20_000];
            let mut input = Burst(&payload);
            let mut output = GatedOutput {
                open: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                bytes: Vec::new(),
            };
            {
                let pump = pump_plain_to_snell(&mut input, &mut output, &mut encoder, &pool, false);
                tokio::pin!(pump);
                assert!(pump.as_mut().poll(&mut cx).is_pending());
                assert_eq!(
                    pool.leased_bytes(),
                    0,
                    "completed write batch must return before another read"
                );
            }
            let mut input = Burst(&output.bytes);
            let mut output = GatedOutput {
                open: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                bytes: Vec::new(),
            };
            let mut recv = pool.get(snell_protocol::V6_WIRE_CAP);
            {
                let pump = pump_snell_to_plain(&mut input, &mut output, &mut decoder, &mut recv);
                tokio::pin!(pump);
                assert!(pump.as_mut().poll(&mut cx).is_pending());
                assert_eq!(
                    pool.leased_bytes(),
                    0,
                    "consumed read batch must return without EOF or timer"
                );
            }
            assert_eq!(output.bytes, payload);
        }
    }

    #[tokio::test]
    async fn empty_directions_return_leases_immediately() {
        async fn check(pump: impl Future<Output = Result<(), SessionError>>, pool: &BufferPool) {
            tokio::pin!(pump);
            let mut cx = Context::from_waker(std::task::Waker::noop());
            for _ in 0..3 {
                assert!(pump.as_mut().poll(&mut cx).is_pending());
                assert_eq!(
                    pool.leased_bytes(),
                    0,
                    "empty Pending must return its lease without a timer"
                );
            }
        }
        let pool = Arc::new(BufferPool::default());
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let mut encoder = snell_protocol::V4Encoder::os(&psk).unwrap();
        let mut decoder = snell_protocol::V4Decoder::new(psk);
        let mut reader = NotReady(true);
        let mut writer = tokio::io::sink();
        {
            let mut warm = pool.get(snell_protocol::V6_WIRE_CAP);
            warm.ensure(snell_protocol::V6_WIRE_CAP).unwrap();
        }
        check(
            pump_plain_to_snell(&mut reader, &mut writer, &mut encoder, &pool, false),
            &pool,
        )
        .await;
        let mut buffer = pool.get(snell_protocol::V6_WIRE_CAP);
        check(
            pump_snell_to_plain(&mut reader, &mut writer, &mut decoder, &mut buffer),
            &pool,
        )
        .await;
        assert_eq!(buffer.capacity(), 0);
    }
}

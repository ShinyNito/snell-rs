use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use snell_protocol::{
    Address, AddressRef, COMMAND_UDP, DecodeStatus, EncodeBuffer, Error, MAX_CONNECT_REQUEST_LEN,
    MAX_PACKET_SIZE, MAX_PACKET_SIZE_V6, ParseState, PlainStream, Psk, REUSE_IDLE_TIMEOUT_SECS,
    RecordKind, RecvBuffer, SERVER_EARLY_PAYLOAD_MAX, ServerReply, V6_WIRE_CAP, aead_key,
    encode_connect_request, encode_reject, encode_tunnel_reply, encode_udp_request,
    encode_udp_response, encode_udp_setup, udp_request_len, udp_response_len,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::bufio::{drain_encode, poll_read_buf, read_into_recv};
use crate::codec::{TcpDecoder, TcpEncoder, TcpReservation};
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::replay::ReplayCache;

const RECORD_HINT: usize = MAX_PACKET_SIZE;
pub(crate) const HANDSHAKE_PLAIN_MAX: usize = MAX_CONNECT_REQUEST_LEN + MAX_PACKET_SIZE_V6;

/// Lazy buffers grow only on demand, with one maximum shaped record as the
/// hard limit. Idle shrinking never changes the accepted protocol lengths.
pub(crate) fn new_recv() -> RecvBuffer {
    RecvBuffer::new(V6_WIRE_CAP)
}

pub(crate) fn new_encode() -> EncodeBuffer {
    EncodeBuffer::new(V6_WIRE_CAP)
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
    encode: &mut EncodeBuffer,
    writer: &mut W,
) -> Result<(), SessionError> {
    let mut req = [0u8; 3];
    let n = encode_udp_setup(&mut req)?;
    write_plain_records(encoder, encode, writer, &req[..n]).await
}

pub(crate) async fn write_udp_request<E: TcpEncoder, W: AsyncWrite + Unpin>(
    encoder: &mut E,
    encode: &mut EncodeBuffer,
    writer: &mut W,
    address: AddressRef<'_>,
    payload: &[u8],
) -> Result<(), SessionError> {
    let needed = udp_request_len(address, payload.len())?;
    write_udp_plain(encoder, encode, writer, needed, |dst| {
        encode_udp_request(dst, address, payload)
    })
    .await
}

pub(crate) async fn write_udp_response<E: TcpEncoder, W: AsyncWrite + Unpin>(
    encoder: &mut E,
    encode: &mut EncodeBuffer,
    writer: &mut W,
    address: AddressRef<'_>,
    payload: &[u8],
) -> Result<(), SessionError> {
    let needed = udp_response_len(address, payload.len())?;
    write_udp_plain(encoder, encode, writer, needed, |dst| {
        encode_udp_response(dst, address, payload)
    })
    .await
}

async fn write_udp_plain<E, W, F>(
    encoder: &mut E,
    encode: &mut EncodeBuffer,
    writer: &mut W,
    needed: usize,
    fill: F,
) -> Result<(), SessionError>
where
    E: TcpEncoder,
    W: AsyncWrite + Unpin,
    F: FnOnce(&mut [u8]) -> snell_protocol::Result<usize>,
{
    drain_encode(writer, encode).await?;
    let mut reservation = match encoder.reserve(encode, &[], needed) {
        Ok(reservation) => reservation,
        Err(Error::PayloadTooLarge) => return Err(SessionError::Protocol(Error::PayloadTooLarge)),
        Err(error) => return Err(error.into()),
    };
    if reservation.capacity() < needed {
        drop(reservation);
        return Err(SessionError::Protocol(Error::PayloadTooLarge));
    }
    let n = fill(reservation.payload_mut())?;
    reservation.seal(n)?;
    drain_encode(writer, encode).await?;
    Ok(())
}

pub(crate) async fn write_connect<E: TcpEncoder, W: AsyncWrite + Unpin>(
    encoder: &mut E,
    encode: &mut EncodeBuffer,
    writer: &mut W,
    destination: AddressRef<'_>,
    reuse: bool,
) -> Result<(), SessionError> {
    let mut req = [0u8; MAX_CONNECT_REQUEST_LEN];
    let n = encode_connect_request(&mut req, destination, reuse)?;
    write_plain_records(encoder, encode, writer, &req[..n]).await
}

pub(crate) async fn write_tunnel<E: TcpEncoder, W: AsyncWrite + Unpin>(
    encoder: &mut E,
    encode: &mut EncodeBuffer,
    writer: &mut W,
) -> Result<(), SessionError> {
    let mut buf = [0u8; 1];
    let n = encode_tunnel_reply(&mut buf)?;
    write_plain_records(encoder, encode, writer, &buf[..n]).await
}

pub(crate) async fn write_reject<E: TcpEncoder, W: AsyncWrite + Unpin>(
    encoder: &mut E,
    encode: &mut EncodeBuffer,
    writer: &mut W,
    message: &str,
) -> Result<(), SessionError> {
    let mut buf = [0u8; 3 + 255];
    let n = encode_reject(&mut buf, message)?;
    write_plain_records(encoder, encode, writer, &buf[..n]).await
}

async fn write_plain_records<E: TcpEncoder, W: AsyncWrite + Unpin>(
    encoder: &mut E,
    encode: &mut EncodeBuffer,
    writer: &mut W,
    mut src: &[u8],
) -> Result<(), SessionError> {
    while !src.is_empty() {
        drain_encode(writer, encode).await?;
        let mut reservation = encoder.reserve(encode, &[], src.len())?;
        let take = reservation.capacity().min(src.len());
        if take == 0 {
            drop(reservation);
            return Err(SessionError::Protocol(Error::PayloadTooLarge));
        }
        reservation.payload_mut()[..take].copy_from_slice(&src[..take]);
        reservation.seal(take)?;
        src = &src[take..];
    }
    drain_encode(writer, encode).await?;
    Ok(())
}

pub(crate) async fn read_server_tunnel<D: TcpDecoder, R: AsyncRead + Unpin>(
    decoder: &mut D,
    recv: &mut RecvBuffer,
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
    pub early_eof: bool,
    pub reuse: bool,
}

pub(crate) enum ServerFirst {
    Connect(ServerConnect),
    Udp,
}

pub(crate) async fn read_server_connect<D: TcpDecoder, R: AsyncRead + Unpin>(
    decoder: &mut D,
    recv: &mut RecvBuffer,
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
                        let early_eof =
                            drain_early_payload(decoder, recv, reader, &mut leftover).await?;
                        if leftover.len() > SERVER_EARLY_PAYLOAD_MAX {
                            return Err(SessionError::EarlyPayloadTooLarge);
                        }
                        return Ok(ServerFirst::Connect(ServerConnect {
                            destination: request.destination,
                            leftover,
                            early_eof,
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

/// Prefetch only bytes already ready after CONNECT authentication. The wire
/// budget bounds CPU work even for padding-heavy records. Pending never delays
/// the outbound connection, and a consumed zero chunk remains visible to relay.
async fn drain_early_payload<D: TcpDecoder, R: AsyncRead + Unpin>(
    decoder: &mut D,
    recv: &mut RecvBuffer,
    reader: &mut R,
    leftover: &mut Vec<u8>,
) -> Result<bool, SessionError> {
    let mut read_bytes = 0usize;
    loop {
        match decoder.decode(recv)? {
            DecodeStatus::NeedMore { minimum } => {
                if read_bytes >= 2 * V6_WIRE_CAP {
                    return Ok(false);
                }
                recv.spare_capacity_mut(minimum.saturating_sub(recv.len()).max(1))?;
                match poll_fn(|cx| Poll::Ready(poll_read_buf(reader, recv, cx))).await {
                    Poll::Pending => return Ok(false),
                    Poll::Ready(Ok(0)) if recv.is_empty() => return Ok(true),
                    Poll::Ready(Ok(0)) => {
                        return Err(
                            io::Error::new(io::ErrorKind::UnexpectedEof, "eof mid-record").into(),
                        );
                    }
                    Poll::Ready(Ok(n)) => read_bytes += n,
                    Poll::Ready(Err(error)) => return Err(error),
                }
            }
            DecodeStatus::Record(record) => {
                if record.kind == RecordKind::ZeroChunk {
                    decoder.consume(recv, &record)?;
                    return Ok(true);
                }
                let payload = record.plaintext(recv.filled());
                if payload.len() > SERVER_EARLY_PAYLOAD_MAX.saturating_sub(leftover.len()) {
                    return Err(SessionError::EarlyPayloadTooLarge);
                }
                leftover.extend_from_slice(payload);
                decoder.consume(recv, &record)?;
            }
        }
    }
}

pub(crate) async fn decode_once<D: TcpDecoder, R: AsyncRead + Unpin>(
    decoder: &mut D,
    recv: &mut RecvBuffer,
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
    recv: &RecvBuffer,
    kdf: &KdfLimiter,
    psk: &Psk,
) -> Result<(), SessionError> {
    let need = decoder.kdf_need();
    if need == 0 || recv.len() < need {
        return Ok(());
    }
    let salt = decoder.kdf_salt(recv)?;
    let psk = psk.clone();
    let key = kdf.run(move || aead_key(psk.as_bytes(), &salt)).await??;
    decoder.install_aead(salt, key)?;
    Ok(())
}

pub(crate) async fn wait_reuse_idle<R: AsyncRead + Unpin>(
    reader: &mut R,
    recv: &mut RecvBuffer,
    encode: &mut EncodeBuffer,
) -> Result<(), SessionError> {
    if !recv.is_empty() {
        return Ok(());
    }
    with_reuse_idle_timeout(async {
        let result = tokio::select! {
            result = read_into_recv(reader, recv) => result,
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                recv.shrink_idle();
                encode.shrink_idle();
                read_into_recv(reader, recv).await
            }
        }?;
        if result == 0 {
            return Err(
                io::Error::new(io::ErrorKind::UnexpectedEof, "eof during reuse idle").into(),
            );
        }
        Ok(())
    })
    .await
}

pub(crate) fn client_may_pool<D: TcpDecoder>(
    encode: &EncodeBuffer,
    recv: &RecvBuffer,
    decoder: &D,
) -> bool {
    encode.is_empty() && recv.is_empty() && !decoder.has_unconsumed_plaintext()
}

pub(crate) fn server_may_reuse<D: TcpDecoder>(encode: &EncodeBuffer, decoder: &D) -> bool {
    encode.is_empty() && !decoder.has_unconsumed_plaintext()
}

async fn fill_until<R: AsyncRead + Unpin>(
    reader: &mut R,
    recv: &mut RecvBuffer,
    minimum: usize,
) -> Result<(), SessionError> {
    while recv.len() < minimum {
        recv.spare_capacity_mut(minimum - recv.len())?;
        let n = read_into_recv(reader, recv).await?;
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
    recv: &mut RecvBuffer,
    encode: &mut EncodeBuffer,
    initial_to_plain: Vec<u8>,
    initial_eof: bool,
    keep_snell_open: bool,
) -> Result<(), SessionError> {
    if !initial_to_plain.is_empty() {
        tokio::io::AsyncWriteExt::write_all(plain, &initial_to_plain).await?;
    }
    // The early-payload owner must not live across the steady-state relay.
    drop(initial_to_plain);

    let (mut snell_r, mut snell_w) = snell.split();
    let (mut plain_r, mut plain_w) = plain.split();
    tokio::try_join!(
        pump_plain_to_snell(&mut plain_r, &mut snell_w, encoder, encode, keep_snell_open,),
        pump_snell_to_plain(&mut snell_r, &mut plain_w, decoder, recv, initial_eof),
    )?;
    Ok(())
}

async fn pump_plain_to_snell<R, W, E>(
    reader: &mut R,
    writer: &mut W,
    encoder: &mut E,
    encode: &mut EncodeBuffer,
    keep_snell_open: bool,
) -> Result<(), SessionError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    E: TcpEncoder,
{
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

            if !local_eof {
                loop {
                    let had_pending = !encode.is_empty();
                    match encoder.reserve(encode, &[], RECORD_HINT) {
                        Err(Error::PayloadTooLarge) => {
                            if !had_pending {
                                return Poll::Ready(Err(Error::PayloadTooLarge.into()));
                            }
                            break;
                        }
                        Err(error) => return Poll::Ready(Err(error.into())),
                        Ok(mut reservation) => {
                            if reservation.capacity() == 0 {
                                break;
                            }
                            let read = poll_read_buf(reader, &mut reservation, cx);
                            match read {
                                Poll::Ready(Ok(0)) => {
                                    local_eof = true;
                                    break;
                                }
                                Poll::Ready(Ok(n)) => {
                                    if let Err(error) = reservation.seal(n) {
                                        return Poll::Ready(Err(error.into()));
                                    }
                                }
                                Poll::Ready(Err(error)) => {
                                    return Poll::Ready(Err(error));
                                }
                                Poll::Pending => {
                                    if !had_pending {
                                        return Poll::Pending;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if local_eof && !zero_sent {
                let had_pending = !encode.is_empty();
                match encoder.reserve(encode, &[], 0).and_then(|r| r.seal(0)) {
                    Ok(()) => zero_sent = true,
                    Err(Error::PayloadTooLarge) => {
                        if !had_pending {
                            return Poll::Ready(Err(Error::PayloadTooLarge.into()));
                        }
                    }
                    Err(error) => return Poll::Ready(Err(error.into())),
                }
            }

            if !encode.is_empty() {
                match Pin::new(&mut *writer).poll_write(cx, encode.pending()) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(SessionError::Io(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "snell write returned zero",
                        ))));
                    }
                    Poll::Ready(Ok(n)) => {
                        if let Err(error) = encode.advance(n) {
                            return Poll::Ready(Err(error.into()));
                        }
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Pending => return Poll::Pending,
                }
                continue;
            }

            if local_eof && zero_sent {
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
    recv: &mut RecvBuffer,
    initial_eof: bool,
) -> Result<(), SessionError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    D: TcpDecoder,
{
    // Decoded-ahead records not yet written: their plaintext ranges stay
    // valid against the unmoved `filled()` view until any is consumed, so
    // the batch is flushed with one vectored write, then consumed FIFO.
    // Fixed-size slots: the TCP path allocates nothing per record.
    let mut batch: [Option<snell_protocol::DecodedRecord>; WRITE_BATCH_MAX] = Default::default();
    let mut batch_count = 0usize;
    let mut batch_len = 0usize;
    let mut write_off = 0usize;
    let mut end_after_batch = false;
    let mut deferred: Option<SessionError> = None;
    let mut protocol_end = initial_eof;
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
                        Poll::Ready(Ok(n)) => write_off += n,
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
                        if recv.len() >= minimum {
                            return Poll::Ready(Err(SessionError::Protocol(Error::Malformed(
                                "decoder need exceeds filled",
                            ))));
                        }
                        // No batch is outstanding here, so growth/compaction is safe.
                        if let Err(error) = recv.spare_capacity_mut(minimum - recv.len()) {
                            return Poll::Ready(Err(error.into()));
                        }
                        let n = match poll_read_buf(reader, recv, cx) {
                            Poll::Ready(Ok(n)) => n,
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                            Poll::Pending => return Poll::Pending,
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
mod tests {
    use super::*;
    use bytes::BufMut;
    use snell_protocol::{FixedClock, RepeatEntropy, V4Decoder, V4Encoder};
    use tokio::io::{AsyncWriteExt, duplex};

    #[tokio::test(start_paused = true)]
    async fn idle_releases_bulk_after_grace_and_preserves_next_bytes() {
        let (mut reader, mut writer) = duplex(128);
        let mut recv = new_recv();
        let mut encode = new_encode();
        recv.put_slice(&vec![1; 60_000]);
        recv.consume(60_000).unwrap();
        encode.reserve_zeroed(60_000).unwrap();
        encode.advance(60_000).unwrap();
        let incoming = async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            writer.write_all(b"next").await.unwrap();
        };
        let (result, ()) = tokio::join!(
            wait_reuse_idle(&mut reader, &mut recv, &mut encode),
            incoming
        );
        result.unwrap();
        assert_eq!(recv.filled(), b"next");
        assert!(recv.capacity() <= 4096);
        assert_eq!(encode.capacity(), 0);
        assert_eq!(recv.max(), V6_WIRE_CAP);
    }

    #[tokio::test]
    async fn pipelined_reuse_does_not_shrink_or_discard_live_bytes() {
        let (mut reader, _writer) = duplex(1);
        let mut recv = new_recv();
        let mut encode = new_encode();
        recv.put_slice(&vec![9; 60_000]);
        let capacity = recv.capacity();
        wait_reuse_idle(&mut reader, &mut recv, &mut encode)
            .await
            .unwrap();
        assert_eq!(recv.capacity(), capacity);
        assert_eq!(recv.filled(), vec![9; 60_000]);
    }

    #[tokio::test]
    async fn early_zero_chunk_preserves_next_connect_and_half_close() {
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let mut encoder = V4Encoder::with_salt(
            &psk,
            [7; 16],
            0,
            RepeatEntropy { byte: 0x3c },
            FixedClock::new(0),
        )
        .unwrap();
        let mut decoder = V4Decoder::new(psk.clone());
        let mut encoded = new_encode();
        let dest = Address::from("127.0.0.1:8080".parse::<std::net::SocketAddr>().unwrap());
        let mut req = [0; MAX_CONNECT_REQUEST_LEN];
        let n = encode_connect_request(&mut req, dest.as_view(), true).unwrap();
        let mut first = encoder.reserve(&mut encoded, &req[..n], 5).unwrap();
        first.put_slice(b"hello");
        first.seal(5).unwrap();
        encoder
            .reserve(&mut encoded, &[], 0)
            .unwrap()
            .seal(0)
            .unwrap();
        encoder
            .reserve(&mut encoded, &req[..n], 0)
            .unwrap()
            .seal(0)
            .unwrap();
        let (mut reader, mut writer) = duplex(4096);
        writer.write_all(encoded.pending()).await.unwrap();
        let mut recv = new_recv();
        let kdf = KdfLimiter::new();
        let first = read_server_connect(&mut decoder, &mut recv, &mut reader, &kdf, &psk, None)
            .await
            .unwrap();
        let ServerFirst::Connect(first) = first else {
            panic!("CONNECT");
        };
        assert!(first.early_eof);
        assert_eq!(first.leftover, b"hello");
        let second = read_server_connect(&mut decoder, &mut recv, &mut reader, &kdf, &psk, None)
            .await
            .unwrap();
        let ServerFirst::Connect(second) = second else {
            panic!("CONNECT");
        };
        assert_eq!(second.destination, dest);
        assert!(!second.early_eof);
        assert!(second.leftover.is_empty());
    }
}

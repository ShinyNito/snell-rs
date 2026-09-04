use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use snell_protocol::{
    Address, AddressRef, COMMAND_UDP, DecodeStatus, ENCODE_BUFFER_MAX, EncodeBuffer, Error,
    MAX_CONNECT_REQUEST_LEN, MAX_PACKET_SIZE, MAX_PACKET_SIZE_V6, ParseState, PlainStream, Psk,
    REUSE_IDLE_TIMEOUT_SECS, RecordKind, RecvBuffer, SERVER_EARLY_PAYLOAD_MAX, ServerReply,
    TCP_HANDSHAKE_TIMEOUT_SECS, V6_WIRE_CAP, aead_key, encode_connect_request, encode_reject,
    encode_tunnel_reply, encode_udp_request, encode_udp_response, encode_udp_setup,
    udp_request_len, udp_response_len,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::bufio::{drain_encode, read_into_recv};
use crate::codec::{TcpDecoder, TcpEncoder, TcpReservation};
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::replay::ReplayCache;

const RECORD_HINT: usize = MAX_PACKET_SIZE;
pub(crate) const HANDSHAKE_PLAIN_MAX: usize = MAX_CONNECT_REQUEST_LEN + MAX_PACKET_SIZE_V6;

pub(crate) fn new_recv() -> RecvBuffer {
    RecvBuffer::new(ENCODE_BUFFER_MAX)
}

pub(crate) fn new_encode() -> EncodeBuffer {
    EncodeBuffer::new(ENCODE_BUFFER_MAX)
}

pub(crate) fn new_udp_recv() -> RecvBuffer {
    RecvBuffer::new(V6_WIRE_CAP)
}

pub(crate) fn new_udp_encode() -> EncodeBuffer {
    EncodeBuffer::new(V6_WIRE_CAP)
}

pub(crate) fn ensure_udp(recv: RecvBuffer) -> Result<RecvBuffer, SessionError> {
    let live = recv.filled().to_vec();
    drop(recv);
    let mut next = RecvBuffer::new(V6_WIRE_CAP);
    next.extend_from_slice(&live)?;
    Ok(next)
}

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
                        drain_early_payload(decoder, recv, kdf, psk, &mut leftover).await?;
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

async fn drain_early_payload<D: TcpDecoder>(
    decoder: &mut D,
    recv: &mut RecvBuffer,
    kdf: &KdfLimiter,
    psk: &Psk,
    leftover: &mut Vec<u8>,
) -> Result<(), SessionError> {
    loop {
        if leftover.len() > SERVER_EARLY_PAYLOAD_MAX {
            return Ok(());
        }
        maybe_install_kdf(decoder, recv, kdf, psk).await?;
        match decoder.decode(recv) {
            Ok(DecodeStatus::NeedMore { .. }) => return Ok(()),
            Ok(DecodeStatus::Record(record)) => {
                if record.kind == RecordKind::ZeroChunk {
                    decoder.consume(recv, &record)?;
                    return Ok(());
                }
                leftover.extend_from_slice(record.plaintext(recv.filled()));
                decoder.consume(recv, &record)?;
            }
            Err(error) => return Err(error.into()),
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
    let psk_bytes = psk.as_bytes().to_vec();
    let key = kdf.run(move || aead_key(&psk_bytes, &salt)).await??;
    decoder.install_aead(salt, key)?;
    Ok(())
}

pub(crate) async fn wait_reuse_idle<R: AsyncRead + Unpin>(
    reader: &mut R,
    recv: &mut RecvBuffer,
) -> Result<(), SessionError> {
    if !recv.is_empty() {
        return Ok(());
    }
    with_reuse_idle_timeout(async {
        loop {
            let n = read_into_recv(reader, recv).await?;
            if n == 0 {
                return Err(SessionError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "eof during reuse idle",
                )));
            }
            if !recv.is_empty() {
                return Ok(());
            }
        }
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

pub(crate) fn release_bulk(
    recv: RecvBuffer,
    encode: EncodeBuffer,
) -> Result<(RecvBuffer, EncodeBuffer), SessionError> {
    let live = recv.filled().to_vec();
    drop(recv);
    drop(encode);
    let cap = live.len().clamp(V6_WIRE_CAP, ENCODE_BUFFER_MAX);
    let mut next = RecvBuffer::new(cap);
    next.extend_from_slice(&live)?;
    Ok((next, EncodeBuffer::new(V6_WIRE_CAP)))
}

pub(crate) fn ensure_bulk(recv: RecvBuffer) -> Result<RecvBuffer, SessionError> {
    if recv.max() >= ENCODE_BUFFER_MAX {
        return Ok(recv);
    }
    let live = recv.filled().to_vec();
    let mut next = RecvBuffer::new(ENCODE_BUFFER_MAX);
    next.extend_from_slice(&live)?;
    Ok(next)
}

async fn fill_until<R: AsyncRead + Unpin>(
    reader: &mut R,
    recv: &mut RecvBuffer,
    minimum: usize,
) -> Result<(), SessionError> {
    while recv.len() < minimum {
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
    initial_to_plain: &[u8],
    initial_to_snell: &[u8],
    keep_snell_open: bool,
) -> Result<(), SessionError> {
    if !initial_to_plain.is_empty() {
        tokio::io::AsyncWriteExt::write_all(plain, initial_to_plain).await?;
    }
    if !initial_to_snell.is_empty() {
        write_plain_records(encoder, encode, snell, initial_to_snell).await?;
    }

    let (mut snell_r, mut snell_w) = snell.split();
    let (mut plain_r, mut plain_w) = plain.split();
    tokio::try_join!(
        pump_plain_to_snell(&mut plain_r, &mut snell_w, encoder, encode, keep_snell_open,),
        pump_snell_to_plain(&mut snell_r, &mut plain_w, decoder, recv),
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
                            let read = {
                                // Uninit payload slot: the kernel writes it, so the
                                // reserve path never zero-fills the payload region.
                                let mut read_buf = ReadBuf::uninit(reservation.payload_uninit());
                                match Pin::new(&mut *reader).poll_read(cx, &mut read_buf) {
                                    Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                                    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                                    Poll::Pending => Poll::Pending,
                                }
                            };
                            match read {
                                Poll::Ready(Ok(0)) => {
                                    local_eof = true;
                                    break;
                                }
                                Poll::Ready(Ok(n)) => {
                                    if let Err(error) = reservation.seal_init(n) {
                                        return Poll::Ready(Err(error.into()));
                                    }
                                }
                                Poll::Ready(Err(error)) => {
                                    return Poll::Ready(Err(error.into()));
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
    let mut protocol_end = false;
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
                        let n = {
                            let spare = match recv.spare_capacity_mut(1) {
                                Ok(spare) => spare,
                                Err(error) => return Poll::Ready(Err(error.into())),
                            };
                            let mut buf = ReadBuf::uninit(spare);
                            match Pin::new(&mut *reader).poll_read(cx, &mut buf) {
                                Poll::Ready(Ok(())) => buf.filled().len(),
                                Poll::Ready(Err(error)) => {
                                    return Poll::Ready(Err(error.into()));
                                }
                                Poll::Pending => return Poll::Pending,
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
                        if let Err(error) = recv.commit_init(n) {
                            return Poll::Ready(Err(error.into()));
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

use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use snell_protocol::{
    Address, AddressRef, COMMAND_UDP, DecodeStatus, ENCODE_BUFFER_MAX, EncodeBuffer, Error,
    MAX_CONNECT_REQUEST_LEN, MAX_PACKET_SIZE_V6, ParseState, PlainStream, Psk,
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
use crate::error::{DirectionEnd, SessionError, TimeoutKind};
use crate::kdf::KdfLimiter;
use crate::replay::ReplayCache;

const RECORD_HINT: usize = 8 * 1024;
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
        Err(_) => Err(SessionError::from_timeout(TimeoutKind::Handshake)),
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
            HandshakeRecord::Zero => {
                return Err(SessionError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "zero chunk before tunnel",
                )));
            }
            HandshakeRecord::Data(plain_bytes) => {
                plain.push(&plain_bytes)?;
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
            HandshakeRecord::Zero => {
                return Err(SessionError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "zero chunk before CONNECT",
                )));
            }
            HandshakeRecord::Data(plain_bytes) => {
                if !replay_checked {
                    replay_checked = true;
                    if let (Some(cache), Some(id)) = (replay, decoder.replay_identity()) {
                        cache.insert(id)?;
                    }
                }
                plain.push(&plain_bytes)?;
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

pub(crate) enum HandshakeRecord {
    Zero,
    Data(Vec<u8>),
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
) -> Result<HandshakeRecord, SessionError> {
    loop {
        maybe_install_kdf(decoder, recv, kdf, psk).await?;
        match decoder.decode(recv)? {
            DecodeStatus::NeedMore { minimum } => {
                fill_until(reader, recv, minimum).await?;
            }
            DecodeStatus::Record(record) => {
                if record.kind == RecordKind::ZeroChunk {
                    decoder.consume(recv, &record)?;
                    return Ok(HandshakeRecord::Zero);
                }
                let plain = record.plaintext(recv.filled()).to_vec();
                decoder.consume(recv, &record)?;
                return Ok(HandshakeRecord::Data(plain));
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
    ends: (DirectionEnd, DirectionEnd),
    encode: &EncodeBuffer,
    recv: &RecvBuffer,
    decoder: &D,
) -> bool {
    clean_ends(ends) && encode.is_empty() && recv.is_empty() && !decoder.has_unconsumed_plaintext()
}

pub(crate) fn server_may_reuse<D: TcpDecoder>(
    ends: (DirectionEnd, DirectionEnd),
    encode: &EncodeBuffer,
    decoder: &D,
) -> bool {
    clean_ends(ends) && encode.is_empty() && !decoder.has_unconsumed_plaintext()
}

fn clean_ends(ends: (DirectionEnd, DirectionEnd)) -> bool {
    fn one(end: DirectionEnd) -> bool {
        matches!(end, DirectionEnd::CleanEof | DirectionEnd::ProtocolEnd)
    }
    one(ends.0) && one(ends.1)
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
) -> Result<(DirectionEnd, DirectionEnd), SessionError> {
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
    )
}

async fn pump_plain_to_snell<R, W, E>(
    reader: &mut R,
    writer: &mut W,
    encoder: &mut E,
    encode: &mut EncodeBuffer,
    keep_snell_open: bool,
) -> Result<DirectionEnd, SessionError>
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
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(if zero_sent {
                        DirectionEnd::ProtocolEnd
                    } else {
                        DirectionEnd::CleanEof
                    })),
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
                                let mut read_buf = ReadBuf::new(reservation.payload_mut());
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
                                    if let Err(error) = reservation.seal(n) {
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
                    return Poll::Ready(Ok(DirectionEnd::ProtocolEnd));
                }
                shutting_down = true;
                continue;
            }

            return Poll::Pending;
        }
    })
    .await
}

async fn pump_snell_to_plain<R, W, D>(
    reader: &mut R,
    writer: &mut W,
    decoder: &mut D,
    recv: &mut RecvBuffer,
) -> Result<DirectionEnd, SessionError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    D: TcpDecoder,
{
    let mut write_off = 0usize;
    let mut current: Option<snell_protocol::DecodedRecord> = None;
    let mut protocol_end = false;
    let mut shutting_down = false;
    poll_fn(|cx| {
        loop {
            if shutting_down {
                return match Pin::new(&mut *writer).poll_shutdown(cx) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(if protocol_end {
                        DirectionEnd::ProtocolEnd
                    } else {
                        DirectionEnd::CleanEof
                    })),
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
                    Poll::Pending => Poll::Pending,
                };
            }

            if let Some(record) = current.as_ref() {
                let plain = record.plaintext(recv.filled());
                if write_off < plain.len() {
                    match Pin::new(&mut *writer).poll_write(cx, &plain[write_off..]) {
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
                if let Err(error) = decoder.consume(recv, record) {
                    return Poll::Ready(Err(error.into()));
                }
                current = None;
                write_off = 0;
                continue;
            }

            if protocol_end {
                shutting_down = true;
                continue;
            }

            match decoder.decode(recv) {
                Ok(DecodeStatus::NeedMore { minimum }) => {
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
                            continue;
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
                        if let Err(error) = decoder.consume(recv, &record) {
                            return Poll::Ready(Err(error.into()));
                        }
                        protocol_end = true;
                        continue;
                    }
                    current = Some(record);
                }
                Err(error) => return Poll::Ready(Err(error.into())),
            }
        }
    })
    .await
}

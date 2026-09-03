use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use snell_protocol::{
    Address, AddressRef, COMMAND_UDP, DecodeStatus, ENCODE_BUFFER_MAX, EncodeBuffer, Error,
    MAX_CONNECT_REQUEST_LEN, MAX_PACKET_SIZE_V6, ParseState, PlainStream, RecordKind, RecvBuffer,
    ServerReply, TCP_HANDSHAKE_TIMEOUT_SECS, encode_connect_request, encode_reject,
    encode_tunnel_reply,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::bufio::{drain_encode, read_into_recv};
use crate::codec::{TcpDecoder, TcpEncoder, TcpReservation};
use crate::error::{DirectionEnd, SessionError, TimeoutKind};

const RECORD_HINT: usize = 8 * 1024;
const HANDSHAKE_PLAIN_MAX: usize = MAX_CONNECT_REQUEST_LEN + MAX_PACKET_SIZE_V6;

pub(crate) fn new_recv() -> RecvBuffer {
    RecvBuffer::new(ENCODE_BUFFER_MAX)
}

pub(crate) fn new_encode() -> EncodeBuffer {
    EncodeBuffer::new(ENCODE_BUFFER_MAX)
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

pub(crate) async fn write_connect<E: TcpEncoder, W: AsyncWrite + Unpin>(
    encoder: &mut E,
    encode: &mut EncodeBuffer,
    writer: &mut W,
    destination: AddressRef<'_>,
) -> Result<(), SessionError> {
    let mut req = [0u8; MAX_CONNECT_REQUEST_LEN];
    let n = encode_connect_request(&mut req, destination, false)?;
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
) -> Result<Vec<u8>, SessionError> {
    let mut plain = PlainStream::new(HANDSHAKE_PLAIN_MAX);
    loop {
        match decoder.decode(recv)? {
            DecodeStatus::NeedMore { minimum } => {
                fill_until(reader, recv, minimum).await?;
            }
            DecodeStatus::Record(record) => {
                if record.kind == RecordKind::ZeroChunk {
                    decoder.consume(recv, &record)?;
                    return Err(SessionError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "zero chunk before tunnel",
                    )));
                }
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
}

pub(crate) async fn read_server_connect<D: TcpDecoder, R: AsyncRead + Unpin>(
    decoder: &mut D,
    recv: &mut RecvBuffer,
    reader: &mut R,
) -> Result<ServerConnect, SessionError> {
    let mut plain = PlainStream::new(HANDSHAKE_PLAIN_MAX);
    loop {
        match decoder.decode(recv)? {
            DecodeStatus::NeedMore { minimum } => {
                fill_until(reader, recv, minimum).await?;
            }
            DecodeStatus::Record(record) => {
                if record.kind == RecordKind::ZeroChunk {
                    decoder.consume(recv, &record)?;
                    return Err(SessionError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "zero chunk before CONNECT",
                    )));
                }
                plain.push(record.plaintext(recv.filled()))?;
                decoder.consume(recv, &record)?;
                match plain.connect() {
                    Ok(ParseState::Need(_)) => {}
                    Ok(ParseState::Done((request, n))) => {
                        if request.reuse {
                            return Err(SessionError::ReuseNotImplemented);
                        }
                        return Ok(ServerConnect {
                            destination: request.destination,
                            leftover: plain.filled()[n..].to_vec(),
                        });
                    }
                    Err(Error::UnknownCommand(COMMAND_UDP)) => match plain.udp_setup()? {
                        ParseState::Need(_) => {}
                        ParseState::Done(_) => return Err(SessionError::UdpNotImplemented),
                    },
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
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
        pump_plain_to_snell(&mut plain_r, &mut snell_w, encoder, encode),
        pump_snell_to_plain(&mut snell_r, &mut plain_w, decoder, recv),
    )
}

async fn pump_plain_to_snell<R, W, E>(
    reader: &mut R,
    writer: &mut W,
    encoder: &mut E,
    encode: &mut EncodeBuffer,
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

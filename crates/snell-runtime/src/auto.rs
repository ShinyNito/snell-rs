use snell_protocol::{
    AUTO_DETECT_PREFIX_MAX, AUTO_DETECT_TIMEOUT_SECS, COMMAND_UDP, DecodeStatus, Error, ParseState,
    PlainStream, Psk, RecordKind, RecvBuffer, SERVER_EARLY_PAYLOAD_MAX, V4Decoder, V4Encoder,
    V6ShapedDecoder, V6ShapedEncoder,
};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

use crate::bufio::read_into_recv;
use crate::codec::TcpDecoder;
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::replay::ReplayCache;
use crate::session::{HANDSHAKE_PLAIN_MAX, ServerConnect, ServerFirst, maybe_install_kdf};

enum Cand {
    NeedMore,
    Match(ServerFirst),
    Invalid,
}

/// Incremental auto-detect: v4 and v6-shaped only. One prefix buffer. No peek/sleep.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Detected {
    V4 {
        encoder: V4Encoder,
        decoder: V4Decoder,
        recv: RecvBuffer,
        first: ServerFirst,
    },
    V6Shaped {
        encoder: V6ShapedEncoder,
        decoder: V6ShapedDecoder,
        recv: RecvBuffer,
        first: ServerFirst,
    },
}

pub(crate) async fn detect_protocol(
    stream: &mut TcpStream,
    psk: Psk,
    kdf: &KdfLimiter,
    replay: &ReplayCache,
) -> Result<Detected, SessionError> {
    match timeout(
        Duration::from_secs(AUTO_DETECT_TIMEOUT_SECS),
        detect_inner(stream, psk, kdf, replay),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(SessionError::HandshakeTimeout),
    }
}

async fn detect_inner(
    stream: &mut TcpStream,
    psk: Psk,
    kdf: &KdfLimiter,
    replay: &ReplayCache,
) -> Result<Detected, SessionError> {
    let mut prefix = RecvBuffer::new(AUTO_DETECT_PREFIX_MAX);
    let mut v4 = V4Decoder::new(psk.clone());
    let mut v4_recv = RecvBuffer::new(AUTO_DETECT_PREFIX_MAX);
    let mut v4_fed = 0usize;
    let mut v4_plain = PlainStream::new(HANDSHAKE_PLAIN_MAX);
    let mut v4_state = Cand::NeedMore;

    let mut v6 = V6ShapedDecoder::new(psk.clone())?;
    let mut v6_recv = RecvBuffer::new(AUTO_DETECT_PREFIX_MAX);
    let mut v6_fed = 0usize;
    let mut v6_plain = PlainStream::new(HANDSHAKE_PLAIN_MAX);
    let mut v6_state = Cand::NeedMore;

    loop {
        feed(&mut v4_recv, &mut v4_fed, &prefix)?;
        feed(&mut v6_recv, &mut v6_fed, &prefix)?;
        advance(
            &mut v4,
            &mut v4_recv,
            &mut v4_plain,
            &mut v4_state,
            kdf,
            &psk,
        )
        .await?;
        advance(
            &mut v6,
            &mut v6_recv,
            &mut v6_plain,
            &mut v6_state,
            kdf,
            &psk,
        )
        .await?;

        match (&v4_state, &v6_state) {
            (Cand::Match(_), Cand::Match(_)) => return Err(SessionError::AmbiguousProtocol),
            (Cand::Match(_), _) => {
                let Cand::Match(first) = std::mem::replace(&mut v4_state, Cand::Invalid) else {
                    unreachable!();
                };
                let psk_enc = psk.clone();
                let encoder = kdf.run(move || V4Encoder::os(&psk_enc)).await??;
                return Ok(Detected::V4 {
                    encoder,
                    decoder: v4,
                    recv: v4_recv,
                    first,
                });
            }
            (_, Cand::Match(_)) => {
                let Cand::Match(first) = std::mem::replace(&mut v6_state, Cand::Invalid) else {
                    unreachable!();
                };
                if let Some(id) = v6.replay_identity() {
                    replay.insert(id)?;
                }
                let psk_enc = psk.clone();
                let encoder = kdf.run(move || V6ShapedEncoder::os(&psk_enc)).await??;
                return Ok(Detected::V6Shaped {
                    encoder,
                    decoder: v6,
                    recv: v6_recv,
                    first,
                });
            }
            (Cand::Invalid, Cand::Invalid) => return Err(SessionError::Aead),
            _ => {
                if prefix.len() >= prefix.max() {
                    return Err(SessionError::Aead);
                }
                let n = read_into_recv(stream, &mut prefix).await?;
                if n == 0 {
                    return Err(SessionError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "eof during auto-detect",
                    )));
                }
            }
        }
    }
}

fn feed(dst: &mut RecvBuffer, fed: &mut usize, prefix: &RecvBuffer) -> Result<(), SessionError> {
    if *fed >= prefix.len() {
        return Ok(());
    }
    dst.extend_from_slice(&prefix.filled()[*fed..])?;
    *fed = prefix.len();
    Ok(())
}

async fn advance<D: TcpDecoder>(
    decoder: &mut D,
    recv: &mut RecvBuffer,
    plain: &mut PlainStream,
    state: &mut Cand,
    kdf: &KdfLimiter,
    psk: &Psk,
) -> Result<(), SessionError> {
    if !matches!(state, Cand::NeedMore) {
        return Ok(());
    }
    loop {
        maybe_install_kdf(decoder, recv, kdf, psk).await?;
        match decoder.decode(recv) {
            Ok(DecodeStatus::NeedMore { minimum }) => {
                if recv.len() >= minimum {
                    *state = Cand::Invalid;
                }
                return Ok(());
            }
            Ok(DecodeStatus::Record(record)) => {
                if record.kind == RecordKind::ZeroChunk {
                    decoder.consume(recv, &record)?;
                    *state = Cand::Invalid;
                    return Ok(());
                }
                let pushed = plain.push(record.plaintext(recv.filled()));
                decoder.consume(recv, &record)?;
                if pushed.is_err() {
                    *state = Cand::Invalid;
                    return Ok(());
                }
                match interpret_plain(plain) {
                    Interpret::Need => {}
                    Interpret::Match(first) => {
                        *state = Cand::Match(first);
                        return Ok(());
                    }
                    Interpret::Invalid => {
                        *state = Cand::Invalid;
                        return Ok(());
                    }
                    Interpret::EarlyPayload => return Err(SessionError::EarlyPayloadTooLarge),
                }
            }
            Err(_) => {
                *state = Cand::Invalid;
                return Ok(());
            }
        }
    }
}

enum Interpret {
    Need,
    Match(ServerFirst),
    Invalid,
    EarlyPayload,
}

fn interpret_plain(plain: &PlainStream) -> Interpret {
    match plain.connect() {
        Ok(ParseState::Need(_)) => Interpret::Need,
        Ok(ParseState::Done((request, n))) => {
            let leftover = plain.filled()[n..].to_vec();
            if leftover.len() > SERVER_EARLY_PAYLOAD_MAX {
                return Interpret::EarlyPayload;
            }
            Interpret::Match(ServerFirst::Connect(ServerConnect {
                destination: request.destination,
                leftover,
                early_eof: false,
                reuse: request.reuse,
            }))
        }
        Err(Error::UnknownCommand(COMMAND_UDP)) => match plain.udp_setup() {
            Ok(ParseState::Need(_)) => Interpret::Need,
            Ok(ParseState::Done(n)) => {
                if plain.filled().len() != n {
                    Interpret::Invalid
                } else {
                    Interpret::Match(ServerFirst::Udp)
                }
            }
            Err(_) => Interpret::Invalid,
        },
        Err(_) => Interpret::Invalid,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn auto_probe_has_no_sleep_or_peek_loop() {
        let src = include_str!("auto.rs");
        let prod = src.split("#[cfg(test)]").next().expect("prod");
        assert!(
            !prod.contains("stream.peek"),
            "auto-detect must not peek the socket"
        );
        assert!(
            !prod.contains("time::sleep"),
            "auto-detect must not sleep-poll"
        );
        assert!(
            !prod.contains("tokio::time::sleep"),
            "auto-detect must not sleep-poll"
        );
    }
}

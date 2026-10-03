use std::sync::Arc;

use snell_protocol::{
    AUTO_DETECT_PREFIX_MAX, AUTO_DETECT_TIMEOUT_SECS, DecodeStatus, ParseState, PlainStream, Psk,
    RecordDecoder, RecordKind, SERVER_EARLY_PAYLOAD_MAX, V4Decoder, V4Encoder, V6ShapedDecoder,
    V6ShapedEncoder,
};
use tokio::net::TcpStream;

use crate::buffer::{BufferPool, PooledBuffer};
use crate::bufio::read_into_recv;
use crate::codec::Codec;
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::replay::ReplayCache;
use crate::session::{
    FirstRequest, HANDSHAKE_PLAIN_MAX, ServerFirst, maybe_install_kdf, parse_first_request,
    with_timeout,
};

enum Cand {
    NeedMore,
    Match(ServerFirst),
    Invalid,
}

/// One protocol candidate fed from the shared prefix buffer.
struct Candidate<D> {
    decoder: D,
    recv: PooledBuffer,
    fed: usize,
    plain: PlainStream,
    state: Cand,
}

impl<D: RecordDecoder> Candidate<D> {
    fn new(decoder: D, buffers: &Arc<BufferPool>) -> Self {
        Self {
            decoder,
            recv: buffers.get_empty(snell_protocol::V6_WIRE_CAP),
            fed: 0,
            plain: PlainStream::new(HANDSHAKE_PLAIN_MAX),
            state: Cand::NeedMore,
        }
    }

    /// Copy prefix bytes this candidate has not seen yet, then decode them.
    async fn advance(
        &mut self,
        prefix: &PooledBuffer,
        kdf: &KdfLimiter,
        psk: &Psk,
    ) -> Result<(), SessionError> {
        if self.fed < prefix.len() {
            self.recv.extend(&prefix.filled()[self.fed..])?;
            self.fed = prefix.len();
        }
        if matches!(self.state, Cand::NeedMore) {
            self.state = self.decode(kdf, psk).await?;
        }
        Ok(())
    }

    async fn decode(&mut self, kdf: &KdfLimiter, psk: &Psk) -> Result<Cand, SessionError> {
        let (decoder, recv) = (&mut self.decoder, &mut self.recv);
        loop {
            maybe_install_kdf(decoder, recv, kdf, psk).await?;
            let record = match decoder.decode(recv) {
                Ok(DecodeStatus::NeedMore { minimum }) => {
                    recv.release_empty();
                    return Ok(if recv.len() >= minimum {
                        Cand::Invalid
                    } else {
                        Cand::NeedMore
                    });
                }
                Ok(DecodeStatus::Record(record)) => record,
                Err(_) => return Ok(Cand::Invalid),
            };
            if record.kind == RecordKind::ZeroChunk {
                decoder.consume(recv, &record)?;
                return Ok(Cand::Invalid);
            }
            let pushed = self.plain.push(record.plaintext(recv.filled()));
            decoder.consume(recv, &record)?;
            if pushed.is_err() {
                return Ok(Cand::Invalid);
            }
            match parse_first_request(&self.plain) {
                Ok(ParseState::Need(_)) => {}
                Ok(ParseState::Done(FirstRequest::Connect(request, n))) => {
                    let leftover = &self.plain.filled()[n..];
                    if leftover.len() > SERVER_EARLY_PAYLOAD_MAX {
                        return Err(SessionError::EarlyPayloadTooLarge);
                    }
                    let leftover = leftover.to_vec();
                    return Ok(Cand::Match(ServerFirst::Connect { request, leftover }));
                }
                Ok(ParseState::Done(FirstRequest::Udp)) => {
                    return Ok(Cand::Match(ServerFirst::Udp));
                }
                Err(_) => return Ok(Cand::Invalid),
            }
        }
    }

    fn take_match(&mut self) -> Option<ServerFirst> {
        match std::mem::replace(&mut self.state, Cand::Invalid) {
            Cand::Match(first) => Some(first),
            other => {
                self.state = other;
                None
            }
        }
    }
}

/// Incremental auto-detect: v4 and v6-shaped only. One prefix buffer. No peek/sleep.
pub(crate) async fn detect_protocol(
    stream: &mut TcpStream,
    psk: &Psk,
    kdf: &KdfLimiter,
    replay: &ReplayCache,
    buffers: &Arc<BufferPool>,
) -> Result<(Codec, PooledBuffer, ServerFirst), SessionError> {
    let detect = detect_inner(stream, psk, kdf, replay, buffers);
    with_timeout(
        AUTO_DETECT_TIMEOUT_SECS,
        SessionError::HandshakeTimeout,
        detect,
    )
    .await
}

async fn detect_inner(
    stream: &mut TcpStream,
    psk: &Psk,
    kdf: &KdfLimiter,
    replay: &ReplayCache,
    buffers: &Arc<BufferPool>,
) -> Result<(Codec, PooledBuffer, ServerFirst), SessionError> {
    let mut prefix = buffers.get(AUTO_DETECT_PREFIX_MAX);
    let mut v4 = Candidate::new(V4Decoder::new(psk.clone()), buffers);
    let mut v6 = Candidate::new(V6ShapedDecoder::new(psk.clone()), buffers);
    loop {
        v4.advance(&prefix, kdf, psk).await?;
        v6.advance(&prefix, kdf, psk).await?;

        match (&v4.state, &v6.state) {
            (Cand::Match(_), Cand::Match(_)) => return Err(SessionError::AmbiguousProtocol),
            (Cand::Invalid, Cand::Invalid) => return Err(SessionError::Aead),
            _ => {}
        }
        if let Some(first) = v4.take_match() {
            let encoder = kdf.derive(psk, V4Encoder::os).await?;
            let codec = Codec::V4 {
                encoder,
                decoder: v4.decoder,
            };
            return Ok((codec, v4.recv, first));
        }
        if let Some(first) = v6.take_match() {
            if let Some(id) = v6.decoder.replay_identity() {
                replay.insert(id)?;
            }
            let encoder = kdf.derive(psk, V6ShapedEncoder::os).await?;
            let codec = Codec::V6Shaped {
                encoder,
                decoder: v6.decoder,
            };
            return Ok((codec, v6.recv, first));
        }
        if prefix.len() >= prefix.max() {
            return Err(SessionError::Aead);
        }
        if read_into_recv(stream, &mut prefix, 1).await? == 0 {
            return Err(SessionError::eof("eof during auto-detect"));
        }
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
    }
}

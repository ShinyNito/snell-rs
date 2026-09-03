use crate::control::{
    ConnectRequest, ServerReply, decode_connect_request_prefix, decode_server_reply,
    decode_udp_setup_prefix,
};
use crate::{Error, ParseState, RecvBuffer, Result};

/// Handshake-only assembler: concatenates record plaintext across records.
///
/// Bulk TCP after Tunnel/CONNECT must not go through this type.
pub struct PlainStream {
    buf: RecvBuffer,
}

impl PlainStream {
    pub fn new(max: usize) -> Self {
        Self {
            buf: RecvBuffer::new(max),
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        self.buf.extend_from_slice(bytes)
    }

    pub fn filled(&self) -> &[u8] {
        self.buf.filled()
    }

    pub fn consume(&mut self, n: usize) -> Result<()> {
        self.buf.consume(n)
    }

    pub fn connect(&self) -> Result<ParseState<(ConnectRequest, usize)>> {
        match decode_connect_request_prefix(self.buf.filled()) {
            Err(Error::Truncated) => Ok(ParseState::Need(self.buf.len().saturating_add(1))),
            Ok((request, n)) => Ok(ParseState::Done((request, n))),
            Err(error) => Err(error),
        }
    }

    pub fn udp_setup(&self) -> Result<ParseState<usize>> {
        match decode_udp_setup_prefix(self.buf.filled()) {
            Err(Error::Truncated) => Ok(ParseState::Need(self.buf.len().saturating_add(1))),
            Ok(n) => Ok(ParseState::Done(n)),
            Err(error) => Err(error),
        }
    }

    pub fn server_reply(&self) -> Result<ParseState<(ServerReply<'_>, usize)>> {
        decode_server_reply(self.buf.filled())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{COMMAND_ERROR, COMMAND_TUNNEL, COMMAND_UDP, ERROR_REJECT, PROTOCOL_VERSION};

    #[test]
    fn connect_spans_pushes() {
        let mut stream = PlainStream::new(64);
        stream.push(b"\x01\x01\x00").unwrap();
        assert!(matches!(stream.connect().unwrap(), ParseState::Need(_)));
        stream.push(b"\x0bexample.com\x01\xbbhello").unwrap();
        match stream.connect().unwrap() {
            ParseState::Done((request, n)) => {
                assert!(!request.reuse);
                assert_eq!(&stream.filled()[n..], b"hello");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn consume_past_filled_is_err() {
        let mut stream = PlainStream::new(32);
        stream.push(b"ab").unwrap();
        assert!(stream.consume(3).is_err());
        stream.consume(2).unwrap();
        assert!(stream.filled().is_empty());
    }

    #[test]
    fn udp_setup_and_server_reply() {
        let mut stream = PlainStream::new(32);
        stream.push(&[PROTOCOL_VERSION, COMMAND_UDP, 0]).unwrap();
        assert_eq!(stream.udp_setup().unwrap(), ParseState::Done(3));
        stream.consume(3).unwrap();
        stream.push(&[COMMAND_TUNNEL, b'x']).unwrap();
        match stream.server_reply().unwrap() {
            ParseState::Done((ServerReply::Tunnel, 1)) => {
                assert_eq!(&stream.filled()[1..], b"x");
            }
            other => panic!("{other:?}"),
        }
        stream.consume(stream.filled().len()).unwrap();
        stream
            .push(&[COMMAND_ERROR, ERROR_REJECT, 3, b'e', b'r', b'r'])
            .unwrap();
        match stream.server_reply().unwrap() {
            ParseState::Done((ServerReply::Error { code, message }, 6)) => {
                assert_eq!(code, ERROR_REJECT);
                assert_eq!(message, b"err");
            }
            other => panic!("{other:?}"),
        }
    }
}

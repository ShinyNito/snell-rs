use bytes::BufMut;
use core::range::Range;

use crate::error::{Error, Result};
use crate::parse::{read_be_u16, read_u8, take_bytes};
use crate::protocol::header::{
    COMMAND_CONNECT, COMMAND_CONNECT_V2, COMMAND_ERROR, COMMAND_PING, COMMAND_PONG, COMMAND_TUNNEL,
    COMMAND_UDP, PROTOCOL_VERSION,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientRequest<'a> {
    Ping,
    Connect {
        reuse: bool,
        host: &'a str,
        port: u16,
        rest_span: Range<usize>,
        rest: &'a [u8],
    },
    Udp {
        rest_span: Range<usize>,
        rest: &'a [u8],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerReply<'a> {
    Tunnel {
        payload_span: Range<usize>,
        payload: &'a [u8],
    },
    Pong,
    Error {
        code: u8,
        message: &'a str,
    },
}

/// Parses a client request as a borrowed view into `input`.
///
/// `host`, `rest`, and spans refer to the original frame payload. Convert the
/// fields that must survive another read or await boundary to owned values at
/// the runtime edge.
///
/// # Errors
///
/// Returns an error if the request is truncated, has an unsupported protocol
/// version or command, has an empty host, or contains invalid UTF-8.
pub fn parse_client_request(input: &[u8]) -> Result<ClientRequest<'_>> {
    let original_len = input.len();
    let mut input = input;
    let version = read_u8(&mut input, Error::TruncatedRequest)?;
    if version != PROTOCOL_VERSION {
        return Err(Error::InvalidProtocolVersion(version));
    }

    let command = read_u8(&mut input, Error::TruncatedRequest)?;
    if command == COMMAND_PING {
        return Ok(ClientRequest::Ping);
    }

    let client_id_len = read_u8(&mut input, Error::TruncatedRequest)? as usize;
    take_bytes(&mut input, client_id_len, Error::TruncatedRequest)?;

    match command {
        COMMAND_CONNECT | COMMAND_CONNECT_V2 => {
            let host_len = read_u8(&mut input, Error::TruncatedRequest)? as usize;
            if host_len == 0 {
                return Err(Error::EmptyHost);
            }
            let host =
                std::str::from_utf8(take_bytes(&mut input, host_len, Error::TruncatedRequest)?)?;
            let port = read_be_u16(&mut input, Error::TruncatedRequest)?;
            let rest_start = original_len - input.len();
            Ok(ClientRequest::Connect {
                reuse: command == COMMAND_CONNECT_V2,
                host,
                port,
                rest_span: Range {
                    start: rest_start,
                    end: original_len,
                },
                rest: input,
            })
        }
        COMMAND_UDP => {
            let rest_start = original_len - input.len();
            Ok(ClientRequest::Udp {
                rest_span: Range {
                    start: rest_start,
                    end: original_len,
                },
                rest: input,
            })
        }
        other => Err(Error::UnknownCommand(other)),
    }
}

/// Parses a server reply as a borrowed view into `input`.
///
/// `payload` and `message` borrow from the original frame payload.
///
/// # Errors
///
/// Returns an error if the reply is truncated, has an invalid command, or
/// contains invalid UTF-8 in an error message.
pub fn parse_server_reply(input: &[u8]) -> Result<ServerReply<'_>> {
    let original_len = input.len();
    let mut input = input;

    match read_u8(&mut input, Error::TruncatedServerReply)? {
        COMMAND_TUNNEL => Ok(ServerReply::Tunnel {
            payload_span: Range {
                start: 1,
                end: original_len,
            },
            payload: input,
        }),
        COMMAND_PONG => Ok(ServerReply::Pong),
        COMMAND_ERROR => {
            let code = read_u8(&mut input, Error::TruncatedServerReply)?;
            let msg_len = read_u8(&mut input, Error::TruncatedServerReply)? as usize;
            let message = take_bytes(&mut input, msg_len, Error::TruncatedServerReply)?;
            Ok(ServerReply::Error {
                code,
                message: std::str::from_utf8(message)?,
            })
        }
        _ => Err(Error::InvalidServerReply),
    }
}

pub fn write_tunnel_reply(out: &mut impl BufMut, payload: &[u8]) {
    out.put_u8(COMMAND_TUNNEL);
    out.put_slice(payload);
}

pub fn write_pong_reply(out: &mut impl BufMut) {
    out.put_u8(COMMAND_PONG);
}

pub fn write_error_reply(out: &mut impl BufMut, code: u8, message: &str) {
    let bytes = message.as_bytes();
    let msg_len = u8::try_from(bytes.len()).unwrap_or(u8::MAX);
    out.put_u8(COMMAND_ERROR);
    out.put_u8(code);
    out.put_u8(msg_len);
    out.put_slice(&bytes[..usize::from(msg_len)]);
}

#[cfg(test)]
mod tests {
    use core::range::Range;

    use bytes::BytesMut;

    use super::{
        ClientRequest, ServerReply, parse_client_request, parse_server_reply, write_error_reply,
        write_pong_reply, write_tunnel_reply,
    };
    use crate::ProtocolVersion;
    use crate::error::Error;
    use crate::protocol::header::{
        PROTOCOL_VERSION, write_tcp_request_header, write_udp_request_header,
    };

    #[test]
    fn parses_tcp_request_as_borrowed_view() {
        let mut input = BytesMut::new();
        write_tcp_request_header(&mut input, "example.com", 443, ProtocolVersion::V4, true)
            .unwrap();
        input.extend_from_slice(b"early-data");

        let parsed = parse_client_request(&input).unwrap();
        assert_eq!(
            parsed,
            ClientRequest::Connect {
                reuse: true,
                host: "example.com",
                port: 443,
                rest_span: Range { start: 17, end: 27 },
                rest: b"early-data",
            }
        );
    }

    #[test]
    fn parses_udp_request_header() {
        let mut input = BytesMut::new();
        write_udp_request_header(&mut input, ProtocolVersion::V4).unwrap();
        input.extend_from_slice(b"packet");

        assert_eq!(
            parse_client_request(&input).unwrap(),
            ClientRequest::Udp {
                rest_span: Range { start: 3, end: 9 },
                rest: b"packet"
            }
        );
    }

    #[test]
    fn parses_tunnel_reply_with_payload() {
        let mut input = BytesMut::new();
        write_tunnel_reply(&mut input, b"hello");
        assert_eq!(
            parse_server_reply(&input).unwrap(),
            ServerReply::Tunnel {
                payload_span: Range { start: 1, end: 6 },
                payload: b"hello"
            }
        );
    }

    #[test]
    fn parses_pong_reply() {
        let mut input = BytesMut::new();
        write_pong_reply(&mut input);
        assert_eq!(parse_server_reply(&input).unwrap(), ServerReply::Pong);
    }

    #[test]
    fn parses_error_reply() {
        let mut input = BytesMut::new();
        write_error_reply(&mut input, 7, "blocked");
        let reply = parse_server_reply(&input).unwrap();

        assert_eq!(
            reply,
            ServerReply::Error {
                code: 7,
                message: "blocked"
            }
        );
    }

    #[test]
    fn maps_client_request_parse_errors() {
        assert!(matches!(
            parse_client_request(&[PROTOCOL_VERSION, 0xee, 0]),
            Err(Error::UnknownCommand(0xee))
        ));
        assert!(matches!(
            parse_client_request(&[PROTOCOL_VERSION, crate::protocol::header::COMMAND_CONNECT]),
            Err(Error::TruncatedRequest)
        ));
    }

    #[test]
    fn maps_server_reply_parse_errors() {
        assert!(matches!(
            parse_server_reply(&[crate::protocol::header::COMMAND_ERROR, 7, 4, b'o']),
            Err(Error::TruncatedServerReply)
        ));
        assert!(matches!(
            parse_server_reply(&[0xee]),
            Err(Error::InvalidServerReply)
        ));
    }
}

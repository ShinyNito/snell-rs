use bytes::BufMut;

use crate::error::{Error, Result};
use crate::{VERSION_1, VERSION_2, VERSION_3, VERSION_4, VERSION_5, VERSION_6};

pub const COMMAND_PING: u8 = 0;
pub const COMMAND_CONNECT: u8 = 1;
pub const COMMAND_CONNECT_V2: u8 = 5;
pub const COMMAND_UDP: u8 = 6;

pub const COMMAND_TUNNEL: u8 = 0;
pub const COMMAND_PONG: u8 = 1;
pub const COMMAND_ERROR: u8 = 2;
pub const COMMAND_UDP_FORWARD: u8 = 1;

pub const PROTOCOL_VERSION: u8 = 1;

pub fn write_tcp_request_header(
    out: &mut impl BufMut,
    host: &str,
    port: u16,
    snell_version: u8,
    reuse: bool,
) -> Result<()> {
    validate_version(snell_version)?;
    if host.is_empty() {
        return Err(Error::EmptyHost);
    }
    if host.len() > u8::MAX as usize {
        return Err(Error::HostTooLong);
    }

    out.put_u8(PROTOCOL_VERSION);
    if snell_version == VERSION_2 || reuse {
        out.put_u8(COMMAND_CONNECT_V2);
    } else {
        out.put_u8(COMMAND_CONNECT);
    }
    out.put_u8(0);
    out.put_u8(host.len() as u8);
    out.put_slice(host.as_bytes());
    out.put_u16(port);
    Ok(())
}

pub fn write_udp_request_header(out: &mut impl BufMut, snell_version: u8) -> Result<()> {
    validate_version(snell_version)?;
    if snell_version < VERSION_3 {
        return Err(Error::UnsupportedVersion(snell_version));
    }
    out.put_slice(&[PROTOCOL_VERSION, COMMAND_UDP, 0]);
    Ok(())
}

pub fn validate_version(version: u8) -> Result<()> {
    match version {
        VERSION_1 | VERSION_2 | VERSION_3 | VERSION_4 | VERSION_5 | VERSION_6 => Ok(()),
        other => Err(Error::UnsupportedVersion(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        COMMAND_CONNECT, COMMAND_CONNECT_V2, COMMAND_UDP, PROTOCOL_VERSION,
        write_tcp_request_header, write_udp_request_header,
    };
    use crate::{VERSION_1, VERSION_4, VERSION_6};

    #[test]
    fn writes_tcp_connect_header() {
        let mut out = Vec::new();
        write_tcp_request_header(&mut out, "example.com", 443, VERSION_4, false).unwrap();
        assert_eq!(out[0], PROTOCOL_VERSION);
        assert_eq!(out[1], COMMAND_CONNECT);
        assert_eq!(out[2], 0);
        assert_eq!(out[3], 11);
        assert_eq!(&out[4..15], b"example.com");
        assert_eq!(&out[15..17], &443u16.to_be_bytes());
    }

    #[test]
    fn writes_reuse_header() {
        let mut out = Vec::new();
        write_tcp_request_header(&mut out, "example.com", 443, VERSION_4, true).unwrap();
        assert_eq!(out[1], COMMAND_CONNECT_V2);
    }

    #[test]
    fn writes_udp_header_for_v3_plus() {
        let mut out = Vec::new();
        write_udp_request_header(&mut out, VERSION_4).unwrap();
        assert_eq!(out, [PROTOCOL_VERSION, COMMAND_UDP, 0]);
        assert!(write_udp_request_header(&mut out, VERSION_1).is_err());
    }

    #[test]
    fn accepts_version_6_headers() {
        let mut tcp = Vec::new();
        write_tcp_request_header(&mut tcp, "example.com", 443, VERSION_6, false).unwrap();
        assert_eq!(tcp[1], COMMAND_CONNECT);

        let mut udp = Vec::new();
        write_udp_request_header(&mut udp, VERSION_6).unwrap();
        assert_eq!(udp, [PROTOCOL_VERSION, COMMAND_UDP, 0]);
    }
}

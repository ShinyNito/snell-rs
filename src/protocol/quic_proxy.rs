use bytes::BytesMut;
use core::range::Range;

use crate::MAX_PACKET_SIZE;
use crate::error::{Error, Result};
use crate::parse::{read_be_u16, read_u8, take_bytes};
use crate::protocol::crypto::{AEAD_TAG_SIZE, Aes128GcmCrypto, SALT_SIZE};
use crate::protocol::frame_v4::{V4_HEADER_CIPHER_SIZE, V4_HEADER_PLAIN_SIZE};
use crate::protocol::header::PROTOCOL_VERSION;
use crate::protocol::nonce::Nonce12;
use crate::protocol::random::fill_random;

pub const QUIC_PROXY_MAX_PAYLOAD: usize = 1417;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicProxyInitRef<'a> {
    pub host: &'a str,
    pub port: u16,
    pub payload_span: Range<usize>,
    pub payload: &'a [u8],
}

pub fn is_quic_looking(first_byte: u8) -> bool {
    (0x40..=0x7f).contains(&first_byte) || first_byte >= 0xc0
}

pub fn is_quic_initial(first_byte: u8) -> bool {
    first_byte & 0x80 != 0 && first_byte & 0x40 != 0
}

pub fn is_quic_short_header(first_byte: u8) -> bool {
    first_byte & 0xc0 == 0x40
}

pub fn is_quic_initial_packet(first_byte: u8) -> bool {
    first_byte & 0xf0 == 0xc0
}

pub fn fill_quic_proxy_salt(salt: &mut [u8; SALT_SIZE]) -> Result<()> {
    loop {
        fill_random(salt)?;
        if !is_quic_looking(salt[0]) {
            return Ok(());
        }
    }
}

fn write_init_prefix(out: &mut BytesMut, host: &str, port: u16) -> Result<usize> {
    if host.is_empty() {
        return Err(Error::EmptyHost);
    }
    if host.len() > u8::MAX as usize {
        return Err(Error::HostTooLong);
    }
    let total_len = 1 + 1 + 1 + host.len() + 2;
    if total_len > QUIC_PROXY_MAX_PAYLOAD {
        return Err(Error::PayloadTooLarge);
    }

    let start = out.len();
    out.extend_from_slice(&[PROTOCOL_VERSION, 0, host.len() as u8]);
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out.len() - start)
}

fn parse_init_plaintext(input: &[u8]) -> Result<QuicProxyInitRef<'_>> {
    if input.len() < 5 {
        return Err(Error::TruncatedRequest);
    }
    let original_len = input.len();
    let mut input = input;
    let version = read_u8(&mut input, Error::TruncatedRequest)?;
    if version != PROTOCOL_VERSION {
        return Err(Error::InvalidProtocolVersion(version));
    }

    let client_id_len = read_u8(&mut input, Error::TruncatedRequest)? as usize;
    take_bytes(&mut input, client_id_len, Error::TruncatedRequest)?;

    let host_len = read_u8(&mut input, Error::TruncatedRequest)? as usize;
    if host_len == 0 {
        return Err(Error::EmptyHost);
    }
    let host = std::str::from_utf8(take_bytes(&mut input, host_len, Error::TruncatedRequest)?)?;
    let port = read_be_u16(&mut input, Error::TruncatedRequest)?;
    let payload_start = original_len - input.len();

    Ok(QuicProxyInitRef {
        host,
        port,
        payload_span: Range {
            start: payload_start,
            end: original_len,
        },
        payload: input,
    })
}

struct QuicProxyEncoder {
    crypto: Aes128GcmCrypto,
    nonce: Nonce12,
    salt: [u8; SALT_SIZE],
    salt_sent: bool,
}

impl QuicProxyEncoder {
    fn new(psk: &[u8]) -> Result<Self> {
        let mut salt = [0; SALT_SIZE];
        fill_quic_proxy_salt(&mut salt)?;
        Self::with_salt(psk, salt)
    }

    fn with_salt(psk: &[u8], salt: [u8; SALT_SIZE]) -> Result<Self> {
        if is_quic_looking(salt[0]) {
            return Err(Error::InvalidUdpPacket);
        }
        Ok(Self {
            crypto: Aes128GcmCrypto::from_psk_and_salt(psk, &salt)?,
            nonce: Nonce12::new(),
            salt,
            salt_sent: false,
        })
    }

    fn encode_init_frame_parts(
        &mut self,
        payload_parts: &[&[u8]],
        out: &mut BytesMut,
    ) -> Result<usize> {
        self.encode_frame_parts(payload_parts, true, out)
    }

    fn encode_frame_parts(
        &mut self,
        payload_parts: &[&[u8]],
        include_salt: bool,
        out: &mut BytesMut,
    ) -> Result<usize> {
        let payload_len = payload_parts.iter().map(|part| part.len()).sum::<usize>();
        if payload_len > MAX_PACKET_SIZE {
            return Err(Error::PayloadTooLarge);
        }
        let start = out.len();
        if include_salt && !self.salt_sent {
            out.extend_from_slice(&self.salt);
            self.salt_sent = true;
        }

        let mut header = [0u8; V4_HEADER_PLAIN_SIZE];
        header[0] = 4;
        header[5..7].copy_from_slice(&(payload_len as u16).to_be_bytes());

        let header_tag = self
            .crypto
            .encrypt_detached(self.nonce.as_bytes(), &mut header)?;
        self.nonce.increment();
        out.extend_from_slice(&header);
        out.extend_from_slice(&header_tag);

        if payload_len != 0 {
            let payload_start = out.len();
            for part in payload_parts {
                out.extend_from_slice(part);
            }
            let payload_end = payload_start + payload_len;
            let payload_tag = self
                .crypto
                .encrypt_detached(self.nonce.as_bytes(), &mut out[payload_start..payload_end])?;
            self.nonce.increment();
            out.extend_from_slice(&payload_tag);
        }

        Ok(out.len() - start)
    }
}

struct QuicProxyDecoder {
    crypto: Aes128GcmCrypto,
    nonce: Nonce12,
}

impl QuicProxyDecoder {
    fn new(psk: &[u8], salt: [u8; SALT_SIZE]) -> Result<Self> {
        Ok(Self {
            crypto: Aes128GcmCrypto::from_psk_and_salt(psk, &salt)?,
            nonce: Nonce12::new(),
        })
    }

    fn decode_frame_payload_in_place<'a>(&mut self, frame: &'a mut [u8]) -> Result<&'a mut [u8]> {
        if frame.len() < V4_HEADER_CIPHER_SIZE {
            return Err(Error::FrameTooShort);
        }

        let mut header = [0u8; V4_HEADER_CIPHER_SIZE];
        header.copy_from_slice(&frame[..V4_HEADER_CIPHER_SIZE]);
        let decrypt_result = self
            .crypto
            .decrypt_within(self.nonce.as_bytes(), &mut header, 0..);
        self.nonce.increment();
        let header = decrypt_result?;

        if header[0] != 4 {
            return Err(Error::InvalidV4Header);
        }
        let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
        if padding_len != 0 {
            return Err(Error::InvalidV4Header);
        }
        if payload_len == 0 {
            return Err(Error::ZeroChunk);
        }
        let expected_len = V4_HEADER_CIPHER_SIZE + payload_len + AEAD_TAG_SIZE;
        if frame.len() != expected_len {
            return Err(Error::FrameLengthMismatch);
        }

        let payload_and_tag = &mut frame[V4_HEADER_CIPHER_SIZE..expected_len];
        let decrypt_result =
            self.crypto
                .decrypt_within(self.nonce.as_bytes(), payload_and_tag, 0..);
        self.nonce.increment();
        let payload = decrypt_result?;

        Ok(payload)
    }
}

pub fn encode_init_datagram(
    psk: &[u8],
    host: &str,
    port: u16,
    payload: &[u8],
    plaintext: &mut BytesMut,
    out: &mut BytesMut,
) -> Result<usize> {
    plaintext.clear();
    out.clear();
    write_init_prefix(plaintext, host, port)?;
    if plaintext.len() + payload.len() > QUIC_PROXY_MAX_PAYLOAD {
        return Err(Error::PayloadTooLarge);
    }

    let mut encoder = QuicProxyEncoder::new(psk)?;
    encoder.encode_init_frame_parts(&[&plaintext[..], payload], out)
}

pub fn decode_init_datagram<'a>(
    psk: &[u8],
    datagram: &'a mut [u8],
) -> Result<QuicProxyInitRef<'a>> {
    if datagram.len() < SALT_SIZE + V4_HEADER_CIPHER_SIZE {
        return Err(Error::FrameTooShort);
    }

    let mut salt = [0; SALT_SIZE];
    salt.copy_from_slice(&datagram[..SALT_SIZE]);
    let mut decoder = QuicProxyDecoder::new(psk, salt)?;
    let plaintext = decoder.decode_frame_payload_in_place(&mut datagram[SALT_SIZE..])?;
    let mut init = parse_init_plaintext(plaintext)?;
    init.payload_span.start += SALT_SIZE + V4_HEADER_CIPHER_SIZE;
    init.payload_span.end += SALT_SIZE + V4_HEADER_CIPHER_SIZE;
    Ok(init)
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::{
        QuicProxyDecoder, QuicProxyEncoder, decode_init_datagram, encode_init_datagram,
        fill_quic_proxy_salt, is_quic_initial, is_quic_initial_packet, is_quic_looking,
        is_quic_short_header, parse_init_plaintext, write_init_prefix,
    };
    use crate::error::Error;
    use crate::protocol::frame_v4::{V4FrameEncoder, split_salt};
    use crate::protocol::header::PROTOCOL_VERSION;

    #[test]
    fn classifies_quic_looking_packets() {
        assert!(!is_quic_looking(0x00));
        assert!(!is_quic_looking(0x3f));
        assert!(is_quic_looking(0x40));
        assert!(is_quic_looking(0x7f));
        assert!(!is_quic_looking(0x80));
        assert!(is_quic_looking(0xc0));

        assert!(!is_quic_initial(0x7f));
        assert!(is_quic_initial(0xc0));
        assert!(is_quic_initial(0xff));

        assert!(is_quic_short_header(0x40));
        assert!(is_quic_short_header(0x7f));
        assert!(!is_quic_short_header(0x80));
        assert!(!is_quic_short_header(0xc0));

        assert!(is_quic_initial_packet(0xc0));
        assert!(is_quic_initial_packet(0xcf));
        assert!(!is_quic_initial_packet(0xd0));
        assert!(!is_quic_initial_packet(0x40));
    }

    #[test]
    fn generates_salt_that_does_not_look_like_quic() {
        for _ in 0..32 {
            let mut salt = [0; 16];
            fill_quic_proxy_salt(&mut salt).unwrap();
            assert!(!is_quic_looking(salt[0]));
        }
    }

    #[test]
    fn writes_and_parses_init_plaintext() {
        let mut out = BytesMut::new();
        write_init_prefix(&mut out, "example.com", 443).unwrap();
        out.extend_from_slice(b"initial");
        let parsed = parse_init_plaintext(&out).unwrap();
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.payload, b"initial");
    }

    #[test]
    fn maps_init_plaintext_parse_errors() {
        assert!(matches!(
            parse_init_plaintext(&[PROTOCOL_VERSION, 0, 3, b'a']),
            Err(Error::TruncatedRequest)
        ));
        assert!(matches!(
            parse_init_plaintext(&[0xee, 0, 1, b'a', 0, 53]),
            Err(Error::InvalidProtocolVersion(0xee))
        ));
        assert!(matches!(
            parse_init_plaintext(&[PROTOCOL_VERSION, 0, 0, 0, 53]),
            Err(Error::EmptyHost)
        ));
        assert!(matches!(
            parse_init_plaintext(&[PROTOCOL_VERSION, 0, 3, b'a', b'b']),
            Err(Error::TruncatedRequest)
        ));
    }

    #[test]
    fn encodes_and_decodes_init_datagram() {
        let psk = b"test psk";
        let mut plaintext = BytesMut::new();
        let mut wire = BytesMut::new();

        encode_init_datagram(
            psk,
            "example.com",
            443,
            b"quic initial",
            &mut plaintext,
            &mut wire,
        )
        .unwrap();
        assert!(!is_quic_looking(wire[0]));

        let parsed = decode_init_datagram(psk, &mut wire).unwrap();
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.payload, b"quic initial");
    }

    #[test]
    fn encoder_rejects_quic_looking_salt() {
        let salt = [0xc0; 16];
        assert!(matches!(
            QuicProxyEncoder::with_salt(b"test psk", salt),
            Err(Error::InvalidUdpPacket)
        ));
    }

    #[test]
    fn decoder_rejects_padding() {
        let psk = b"test psk";
        let salt = [0x22; 16];
        let mut payload = BytesMut::new();
        write_init_prefix(&mut payload, "example.com", 443).unwrap();
        payload.extend_from_slice(b"payload");

        let mut padded_encoder =
            V4FrameEncoder::with_salt_and_initial_padding(psk, salt, 4).unwrap();
        let mut wire = BytesMut::new();
        padded_encoder
            .encode_frame_with_padding(&payload, 4, &mut wire)
            .unwrap();
        let (_, frame) = split_salt(&wire).unwrap();
        let mut frame = BytesMut::from(frame);

        let mut decoder = QuicProxyDecoder::new(psk, salt).unwrap();
        assert!(matches!(
            decoder.decode_frame_payload_in_place(&mut frame),
            Err(Error::InvalidV4Header)
        ));
    }
}

//! Runtime-free Snell protocol helpers.
//!
//! This module intentionally does not depend on Tokio, async traits, or any
//! concrete buffer type. Runtime code should exact-read/write around these
//! helpers via the [`SnellTcpEncoder`] / [`SnellTcpDecoder`] traits.
//!
//! Design constraints:
//! - The connect request must not read-ahead into application payload.
//! - Encryption/decryption is record-oriented; each frame is a header plus an
//!   optional payload, both AEAD-protected.
//! - Four transport shapes coexist here:
//!   - V4 ([`V4Encoder`]/[`V4Decoder`]): legacy protocol with Argon2id KDF,
//!     padding, and congestion control.
//!   - V6 unshaped ([`V6UnshapedEncoder`]/[`V6UnshapedDecoder`]): V4's framing
//!     without traffic shaping, shared KDF.
//!   - V6 shaped ([`V6ShapedEncoder`]/[`V6ShapedDecoder`]): profile-driven
//!     obfuscation with salt blocks, per-record prefixes, and active shaping.
//!   - V6 unsafe-raw ([`V6UnsafeRawEncoder`]/[`V6UnsafeRawDecoder`]):
//!     unencrypted pass-through for local debugging only.
//! - Encoding writes into caller-provided buffers via a reservation slot.
//!
//! # Connect request layout
//!
//! The first plaintext bytes a client sends. `CMD` selects one-shot vs
//! reusable transports:
//!
//! ```text
//! [VERSION][CMD][CLIENT_ID_LEN][CLIENT_ID...][HOST_LEN][HOST...][PORT_BE]
//!
//!   VERSION       = 0x01 PROTOCOL_VERSION
//!   CMD           = 0x01 CONNECT / 0x05 CONNECT_V2 (reuse)
//!   CLIENT_ID_LEN = byte length of opaque client id (0..=255)
//!   HOST_LEN      = byte length of HOST (1..=255), after CLIENT_ID
//!   HOST          = domain name or IP literal bytes
//!   PORT_BE       = destination port
//! ```
//!
//! # Record layout
//!
//! After the connect request, the stream is a sequence of AEAD records. The
//! first record carries the salt that seeds the session key; V6 shaped swaps
//! the salt for a profile-derived salt block. Body bytes depend on the variant:
//!
//! ```text
//!   first record:   SALT(16)  HEADER_CIPHER  BODY?
//!   subsequent:               HEADER_CIPHER  BODY?
//!
//!   HEADER_CIPHER   = HEADER_PLAIN(7) || TAG(16)        // AES-128-GCM
//!   HEADER_PLAIN    = VER(4) RSV RSV PADDING(2) PAYLOAD(2)
//!
//!   V4 BODY         = PADDING || PAYLOAD_CIPHER || TAG   // interleaved
//!   V6 unshaped BODY= PAYLOAD_CIPHER || TAG              // padding == 0
//!   V6 shaped BODY  = PADDING || PAYLOAD_CIPHER || TAG   // profile-driven
//!   V6 unsafe-raw   = PAYLOAD (plaintext, no tag)        // debug only
//!
//!   zero chunk      = payload_len == 0  -> no BODY, used as keepalive/end
//! ```
//!
//! # Encode flow (writer side)
//!
//! ```text
//!   begin_plain_reservation(prefix, hint)
//!        |
//!        v
//!   +-----------------------+   prefix copied into payload region,
//!   | reserve record sized  |   slot = max_chunk(hint) - prefix.len()
//!   | for prefix + payload  |   (first record: inject salt + init padding)
//!   +-----------------------+
//!        |
//!        v
//!   plain_slot(reservation) -----> caller writes payload bytes
//!        |
//!        v
//!   finish_plain_reservation(reservation, payload_len)
//!        |
//!        | write header (padding/payload lens) -> seal header (AEAD, nonce++)
//!        | seal payload (AEAD, nonce++)         -> make/swap padding (V4/shaped)
//!        v
//!   pending_wire() / advance_wire(n) -----> vectored flush to socket
//! ```
//!
//! # Decode flow (reader side)
//!
//! ```text
//!   loop {
//!     next_ciphertext_slot()
//!        |
//!        +-- Read(slice)            caller reads ciphertext into slice
//!        |        |
//!        |        v
//!        |   commit_ciphertext(n)
//!        |        |
//!        |        v
//!        +-- BlockedByPlaintext    previous record's plaintext not drained
//!                 |
//!                 v
//!            pending_plaintext() / advance_plaintext(n)
//!
//!     commit_ciphertext returns DecodeEvent:
//!        NeedMore       -> need more bytes, loop again
//!        PlainData      -> plaintext ready, drain via pending_plaintext
//!        ZeroChunk      -> protocol keepalive / end marker
//!        ServerTunnel / ServerError / Ping / Pong -> control frames
//!   }
//! ```
//!
//! State machine inside a decoder:
//!
//! ```text
//!   Salt/SaltBlock -> Header -> (body_len == 0 ? emit event : Body) -> Header
//!          ^                                              |
//!          |______________________________________________|
//!             (reset and wait for the next record)
//! ```

use std::{
    io::{self, IoSlice},
    net::{IpAddr, SocketAddr},
    str,
    sync::Arc,
};

use crate::protocol::address::{Address, AddressRef};

mod common;
pub(crate) mod crypto;
mod profile;
mod salt;
#[cfg(test)]
mod tests;
mod v4;
mod v6;
pub mod version;

pub use v4::{V4Decoder, V4Encoder};
pub use v6::{
    V6ShapedDecoder, V6ShapedEncoder, V6UnsafeRawDecoder, V6UnsafeRawEncoder, V6UnshapedDecoder,
    V6UnshapedEncoder,
};

/// Snell connect handshake version byte.
pub const PROTOCOL_VERSION: u8 = 0x01;
/// Connect command (one-shot session, no multiplexing).
pub const COMMAND_CONNECT: u8 = 0x01;
/// Connect command with session reuse (v2 handshake).
pub const COMMAND_CONNECT_V2: u8 = 0x05;
/// UDP setup command.
pub const COMMAND_UDP: u8 = 0x06;
/// UDP packet command inside an established UDP stream.
pub const COMMAND_UDP_FORWARD: u8 = 0x01;
/// Server-side tunnel frame: relay application payload downstream.
pub const COMMAND_TUNNEL: u8 = 0x00;
/// Server-side error frame carrying a reason code and message.
pub const COMMAND_ERROR: u8 = 0x02;

/// Salt length in bytes, fed into the per-session KDF.
pub const SALT_LEN: usize = 16;
/// AEAD nonce length (AES-128-GCM) in bytes.
pub const NONCE_LEN: usize = 12;
/// Plaintext frame header: `VER RSV RSV PADDING(2) PAYLOAD(2)`.
pub const HEADER_PLAIN_LEN: usize = 7;
/// AEAD authentication tag length in bytes.
pub const TAG_LEN: usize = 16;
/// Ciphertext frame header: plaintext header + tag.
pub const HEADER_CIPHER_LEN: usize = HEADER_PLAIN_LEN + TAG_LEN;
/// V4 / V6-unshaped maximum payload per record (fits one TCP segment).
pub const MAX_PACKET_SIZE: usize = 0x3fff;
/// V6 shaped / unsafe-raw maximum payload per record (`u16` range).
pub const MAX_PACKET_SIZE_V6: usize = u16::MAX as usize;
/// Largest Snell CONNECT control payload.
pub const MAX_CONNECT_REQUEST_LEN: usize = 3 + 255 + 1 + 255 + 2;
/// Largest Snell UDP packet address prefix.
pub const MAX_UDP_PACKET_ADDR_LEN: usize = 1 + 1 + 255 + 2;

const MIX_HANDSHAKE_DOMAIN: u32 = 0x51A7;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectRequest {
    pub destination: Address,
    pub reuse: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpPacket<'a> {
    pub address: AddressRef<'a>,
    pub payload: &'a [u8],
    pub header_len: usize,
}

/// Encoded length of a Snell connect request for `destination`.
///
/// Layout: `VER CMD CLIENT_ID_LEN HOST_LEN HOST PORT` for the client-id-free
/// request we emit.
///
/// ```text
///  +---+---+---+---+----------------+--------+
///  | V | C | 0 | L | HOST (L bytes)  | PORT   |
///  +---+---+---+---+----------------+--------+
///   0   1   2   3   4 .. 3+L         4+L 5+L
/// ```
pub fn connect_request_len(destination: AddressRef<'_>) -> io::Result<usize> {
    let host = destination.host();
    if host.is_empty() || host.len() > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "snell host length must be 1..=255",
        ));
    }
    Ok(4 + host.len() + 2)
}

/// Encode a Snell connect request into `dst`.
///
/// Layout: `VER CMD CLIENT_ID_LEN HOST_LEN HOST PORT`, where CMD is
/// [`COMMAND_CONNECT_V2`] when `reuse` is set and [`COMMAND_CONNECT`]
/// otherwise. This client sends an empty client id.
///
/// ```text
///  dst[0]   = PROTOCOL_VERSION (0x01)
///  dst[1]   = COMMAND_CONNECT_V2 (0x05) if reuse else COMMAND_CONNECT (0x01)
///  dst[2]   = 0x00 (client_id_len)
///  dst[3]   = host length
///  dst[4..] = host bytes
///  dst[end-2..end] = port (big-endian)
/// ```
///
/// Returns the number of bytes written. Useful for the Snell outbound client.
///
/// Handshake order on the wire:
/// ```text
///   client -> server:  first AEAD record, payload begins with this CONNECT request
///   server -> client:  reply / tunnel frames
/// ```
pub fn encode_connect_request_into(
    dst: &mut [u8],
    destination: AddressRef<'_>,
    reuse: bool,
) -> io::Result<usize> {
    let needed = connect_request_len(destination)?;
    if dst.len() < needed {
        return Err(common::invalid_input(
            "snell connect request buffer too small",
        ));
    }

    let host = destination.host();
    let host = host.as_bytes();
    dst[0] = PROTOCOL_VERSION;
    dst[1] = if reuse {
        COMMAND_CONNECT_V2
    } else {
        COMMAND_CONNECT
    };
    dst[2] = 0;
    dst[3] = host.len() as u8;
    dst[4..4 + host.len()].copy_from_slice(host);
    dst[4 + host.len()..needed].copy_from_slice(&destination.port().to_be_bytes());
    Ok(needed)
}

pub fn decode_connect_request(src: &[u8]) -> io::Result<ConnectRequest> {
    let (request, consumed) = decode_connect_request_prefix(src)?;
    if src.len() != consumed {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snell connect request has trailing bytes",
        ));
    }
    Ok(request)
}

pub(crate) fn decode_connect_request_prefix(src: &[u8]) -> io::Result<(ConnectRequest, usize)> {
    if src.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "snell connect request header too short",
        ));
    }
    if src[0] != PROTOCOL_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snell invalid connect version",
        ));
    }
    let reuse = match src[1] {
        COMMAND_CONNECT => false,
        COMMAND_CONNECT_V2 => true,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "snell invalid connect command",
            ));
        }
    };

    let client_id_len = src[2] as usize;
    let host_len_offset = 3 + client_id_len;
    if src.len() <= host_len_offset {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "snell connect request client id too short",
        ));
    }

    let host_len = src[host_len_offset] as usize;
    if host_len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snell empty connect host",
        ));
    }
    let host_offset = host_len_offset + 1;
    let needed = host_offset + host_len + 2;
    if src.len() < needed {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "snell connect request body too short",
        ));
    }

    let host = str::from_utf8(&src[host_offset..host_offset + host_len]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "snell connect host is not utf-8",
        )
    })?;
    let port = u16::from_be_bytes([src[host_offset + host_len], src[host_offset + host_len + 1]]);
    let destination = if let Ok(ip) = host.parse::<IpAddr>() {
        Address::Ip(SocketAddr::new(ip, port))
    } else {
        Address::domain(host.to_owned(), port)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("snell {error}")))?
    };
    Ok((ConnectRequest { destination, reuse }, needed))
}

pub fn encode_udp_setup_request_into(dst: &mut [u8]) -> io::Result<usize> {
    if dst.len() < 3 {
        return Err(common::invalid_input("snell udp setup buffer too small"));
    }
    dst[0] = PROTOCOL_VERSION;
    dst[1] = COMMAND_UDP;
    dst[2] = 0;
    Ok(3)
}

pub fn decode_udp_setup_request_prefix(src: &[u8]) -> io::Result<usize> {
    if src.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "snell udp setup header too short",
        ));
    }
    if src[0] != PROTOCOL_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snell invalid udp setup version",
        ));
    }
    if src[1] != COMMAND_UDP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snell invalid udp setup command",
        ));
    }
    let client_id_len = src[2] as usize;
    let needed = 3 + client_id_len;
    if src.len() < needed {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "snell udp setup client id too short",
        ));
    }
    Ok(needed)
}

pub fn udp_request_addr_len(address: AddressRef<'_>) -> io::Result<usize> {
    match address {
        AddressRef::Domain { host, .. } => {
            if host.is_empty() || host.len() > u8::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "snell udp domain length must be 1..=255",
                ));
            }
            Ok(1 + 1 + host.len() + 2)
        }
        AddressRef::Ip(SocketAddr::V4(_)) => Ok(1 + 1 + 1 + 4 + 2),
        AddressRef::Ip(SocketAddr::V6(_)) => Ok(1 + 1 + 1 + 16 + 2),
    }
}

pub fn encode_udp_request_addr(dst: &mut [u8], address: AddressRef<'_>) -> io::Result<usize> {
    let needed = udp_request_addr_len(address)?;
    if dst.len() < needed {
        return Err(common::invalid_input(
            "snell udp request address buffer too small",
        ));
    }

    match address {
        AddressRef::Domain { host, port } => {
            let host = host.as_bytes();
            dst[0] = COMMAND_UDP_FORWARD;
            dst[1] = host.len() as u8;
            dst[2..2 + host.len()].copy_from_slice(host);
            dst[2 + host.len()..needed].copy_from_slice(&port.to_be_bytes());
        }
        AddressRef::Ip(SocketAddr::V4(addr)) => {
            dst[0] = COMMAND_UDP_FORWARD;
            dst[1] = 0;
            dst[2] = 0x04;
            dst[3..7].copy_from_slice(&addr.ip().octets());
            dst[7..9].copy_from_slice(&addr.port().to_be_bytes());
        }
        AddressRef::Ip(SocketAddr::V6(addr)) => {
            dst[0] = COMMAND_UDP_FORWARD;
            dst[1] = 0;
            dst[2] = 0x06;
            dst[3..19].copy_from_slice(&addr.ip().octets());
            dst[19..21].copy_from_slice(&addr.port().to_be_bytes());
        }
    }
    Ok(needed)
}

pub fn decode_udp_request_packet(src: &[u8]) -> io::Result<UdpPacket<'_>> {
    let (address, header_len) = decode_udp_request_addr(src)?;
    Ok(UdpPacket {
        address,
        payload: &src[header_len..],
        header_len,
    })
}

fn decode_udp_request_addr(src: &[u8]) -> io::Result<(AddressRef<'_>, usize)> {
    if src.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "snell udp request address too short",
        ));
    }
    if src[0] != COMMAND_UDP_FORWARD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snell udp invalid forward command",
        ));
    }

    if src[1] == 0 {
        if src.len() < 3 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "snell udp request ip type missing",
            ));
        }
        return match src[2] {
            0x04 => {
                if src.len() < 9 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "snell udp request ipv4 truncated",
                    ));
                }
                let ip = std::net::Ipv4Addr::new(src[3], src[4], src[5], src[6]);
                let port = u16::from_be_bytes([src[7], src[8]]);
                Ok((AddressRef::Ip(SocketAddr::new(IpAddr::V4(ip), port)), 9))
            }
            0x06 => {
                if src.len() < 21 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "snell udp request ipv6 truncated",
                    ));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&src[3..19]);
                let port = u16::from_be_bytes([src[19], src[20]]);
                Ok((
                    AddressRef::Ip(SocketAddr::new(IpAddr::V6(octets.into()), port)),
                    21,
                ))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "snell udp request invalid ip type",
            )),
        };
    }

    let host_len = src[1] as usize;
    let needed = 2 + host_len + 2;
    if src.len() < needed {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "snell udp request domain truncated",
        ));
    }
    let host = str::from_utf8(&src[2..2 + host_len]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "snell udp request domain is not utf-8",
        )
    })?;
    let port = u16::from_be_bytes([src[2 + host_len], src[2 + host_len + 1]]);
    let address = AddressRef::domain(host, port)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("snell {error}")))?;
    Ok((address, needed))
}

pub fn udp_response_addr_len(address: AddressRef<'_>) -> io::Result<usize> {
    match address {
        AddressRef::Domain { host, .. } => {
            if host.is_empty() || host.len() > u8::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "snell udp domain length must be 1..=255",
                ));
            }
            Ok(1 + 1 + host.len() + 2)
        }
        AddressRef::Ip(SocketAddr::V4(_)) => Ok(1 + 4 + 2),
        AddressRef::Ip(SocketAddr::V6(_)) => Ok(1 + 16 + 2),
    }
}

pub fn encode_udp_response_addr(dst: &mut [u8], address: AddressRef<'_>) -> io::Result<usize> {
    let needed = udp_response_addr_len(address)?;
    if dst.len() < needed {
        return Err(common::invalid_input(
            "snell udp response address buffer too small",
        ));
    }

    match address {
        AddressRef::Domain { host, port } => {
            let host = host.as_bytes();
            dst[0] = 0x03;
            dst[1] = host.len() as u8;
            dst[2..2 + host.len()].copy_from_slice(host);
            dst[2 + host.len()..needed].copy_from_slice(&port.to_be_bytes());
        }
        AddressRef::Ip(SocketAddr::V4(addr)) => {
            dst[0] = 0x04;
            dst[1..5].copy_from_slice(&addr.ip().octets());
            dst[5..7].copy_from_slice(&addr.port().to_be_bytes());
        }
        AddressRef::Ip(SocketAddr::V6(addr)) => {
            dst[0] = 0x06;
            dst[1..17].copy_from_slice(&addr.ip().octets());
            dst[17..19].copy_from_slice(&addr.port().to_be_bytes());
        }
    }
    Ok(needed)
}

pub fn decode_udp_response_packet(src: &[u8]) -> io::Result<UdpPacket<'_>> {
    let (address, header_len) = decode_udp_response_addr(src)?;
    Ok(UdpPacket {
        address,
        payload: &src[header_len..],
        header_len,
    })
}

fn decode_udp_response_addr(src: &[u8]) -> io::Result<(AddressRef<'_>, usize)> {
    if src.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "snell udp response address too short",
        ));
    }

    match src[0] {
        0x03 => {
            if src.len() < 2 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell udp response domain length missing",
                ));
            }
            let host_len = src[1] as usize;
            let needed = 2 + host_len + 2;
            if src.len() < needed {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell udp response domain truncated",
                ));
            }
            let host = str::from_utf8(&src[2..2 + host_len]).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snell udp response domain is not utf-8",
                )
            })?;
            let port = u16::from_be_bytes([src[2 + host_len], src[2 + host_len + 1]]);
            let address = AddressRef::domain(host, port).map_err(|error| {
                io::Error::new(io::ErrorKind::InvalidData, format!("snell {error}"))
            })?;
            Ok((address, needed))
        }
        0x04 => {
            if src.len() < 7 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell udp response ipv4 truncated",
                ));
            }
            let ip = std::net::Ipv4Addr::new(src[1], src[2], src[3], src[4]);
            let port = u16::from_be_bytes([src[5], src[6]]);
            Ok((AddressRef::Ip(SocketAddr::new(IpAddr::V4(ip), port)), 7))
        }
        0x06 => {
            if src.len() < 19 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell udp response ipv6 truncated",
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&src[1..17]);
            let port = u16::from_be_bytes([src[17], src[18]]);
            Ok((
                AddressRef::Ip(SocketAddr::new(IpAddr::V6(octets.into()), port)),
                19,
            ))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snell udp response invalid address type",
        )),
    }
}

/// Layout of a record reserved inside an encoder's wire buffer.
///
/// Callers receive this from `begin_*_reservation`, write payload bytes into
/// the slot reported by `plain_slot`, then hand it back to
/// `finish_*_reservation` for encryption. All offsets are relative to the
/// encoder's internal `wire` buffer.
#[derive(Clone, Copy, Debug)]
pub struct WriteReservation {
    /// Bytes of the caller-provided plaintext prefix already written.
    plain_prefix_len: usize,
    /// Start of the record head (salt block / padding prefix origin).
    head_start: usize,
    /// Start of the obfuscation prefix for this record.
    prefix_start: usize,
    /// Length of the obfuscation prefix.
    prefix_len: usize,
    /// Start of the AEAD-protected frame header.
    header_start: usize,
    /// Start of the padding region.
    padding_start: usize,
    /// Length of the padding region.
    padding_len: usize,
    /// Start of the plaintext payload slot exposed to the caller.
    payload_start: usize,
    /// Maximum payload bytes the caller may write into the slot.
    max_payload_len: usize,
}

/// Decoded plaintext frame header returned by the decoders.
///
/// Derived from `HEADER_PLAIN` (`VER RSV RSV PADDING(2) PAYLOAD(2)`):
///
/// ```text
///   HEADER_PLAIN:  4 | 0 | 0 | PADDING_HI PADDING_LO | PAYLOAD_HI PAYLOAD_LO
///                        ^^^^^^^^^^^^^^^^^            ^^^^^^^^^^^^^^^^^^^^^^
///                        padding_len                  payload_len
///
///   body_len = padding_len
///            + (payload_len == 0 ? 0 : payload_len + TAG_LEN)
/// ```
#[derive(Clone, Copy, Debug)]
pub struct DecodedHeader {
    /// Padding length preceding the AEAD-sealed payload.
    pub padding_len: usize,
    /// Plaintext application payload length.
    pub payload_len: usize,
    /// Total body bytes that follow the header on the wire
    /// (`padding + payload + tag`, with tag omitted for zero chunks).
    pub body_len: usize,
}

/// Slot the runtime should fill with freshly read ciphertext.
///
/// `BlockedByPlaintext` tells the caller to drain [`SnellTcpDecoder::pending_plaintext`]
/// before more ciphertext can be accepted.
pub enum DecodeSlot<'a> {
    /// Read ciphertext into this slice.
    Read(&'a mut [u8]),
    /// Plaintext from a previous record is still pending; drain it first.
    BlockedByPlaintext,
}

/// Outcome of feeding ciphertext into a decoder.
///
/// The lifecycle is: feed bytes via [`DecodeSlot`] until a record completes,
/// then observe [`PlainData`](DecodeEvent::PlainData) or a control frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeEvent<'a> {
    /// More ciphertext is required to finish the current record.
    NeedMore,
    /// A record was decrypted and plaintext is now available to drain.
    PlainData,
    /// A zero-length chunk (protocol-level keepalive / end marker).
    ZeroChunk,
    /// Server relayed downstream tunnel payload.
    ServerTunnel,
    /// Server reported an error.
    ServerError {
        /// Error reason code.
        code: u8,
        /// Human-readable error message borrowed from the decoder buffer.
        message: &'a [u8],
    },
    /// Client-initiated ping keepalive.
    Ping,
    /// Server pong reply to a ping.
    Pong,
}

/// Borrowed plaintext bytes prepended to a record's payload slot.
///
/// Encoders copy this prefix into the reserved payload region before exposing
/// the remaining slot to the caller, so callers can frame commands without an
/// extra copy.
#[derive(Clone, Copy, Debug, Default)]
pub struct PlainPrefix<'a> {
    bytes: &'a [u8],
}

impl<'a> PlainPrefix<'a> {
    /// No prefix: the payload slot is entirely caller-owned.
    pub const fn none() -> Self {
        Self { bytes: &[] }
    }

    /// Wrap a borrowed prefix to prepend before the caller payload.
    pub const fn bytes(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn len(self) -> usize {
        self.bytes.len()
    }

    fn copy_to(self, dst: &mut [u8]) {
        dst[..self.bytes.len()].copy_from_slice(self.bytes);
    }
}

/// Streaming Snell TCP encoder.
///
/// The reservation lifecycle is:
/// 1. [`SnellTcpEncoder::begin_plain_reservation`] — reserve a record sized for
///    `prefix + payload_hint` and return a [`WriteReservation`].
/// 2. [`SnellTcpEncoder::plain_slot`] — borrow the writable payload region.
/// 3. [`SnellTcpEncoder::finish_plain_reservation`] — seal the record and move
///    it to the pending-wire queue.
/// 4. [`SnellTcpEncoder::pending_wire`] / [`SnellTcpEncoder::advance_wire`] —
///    vectored flush of sealed bytes to the socket.
pub trait SnellTcpEncoder {
    /// Opaque handle describing the reserved record.
    type Reservation;

    /// Reserve a record sized for `prefix.len() + payload_hint` and copy the
    /// prefix into the payload region.
    fn begin_plain_reservation(
        &mut self,
        prefix: PlainPrefix<'_>,
        payload_hint: usize,
    ) -> io::Result<Self::Reservation>;

    /// Borrow the caller-writable payload slot for this reservation.
    fn plain_slot(&mut self, reservation: &Self::Reservation) -> &mut [u8];

    /// Seal the record after the caller wrote `payload_len` bytes.
    fn finish_plain_reservation(
        &mut self,
        reservation: Self::Reservation,
        payload_len: usize,
    ) -> io::Result<()>;

    /// Discard a reservation without emitting a record.
    fn cancel_plain_reservation(&mut self, reservation: Self::Reservation);

    /// Collect sealed bytes pending flush into `out` as vectored slices.
    fn pending_wire<'a>(&'a self, out: &mut [IoSlice<'a>]) -> usize;

    /// Mark `written` bytes from the pending queue as flushed.
    fn advance_wire(&mut self, written: usize);

    /// Whether any sealed bytes are still awaiting flush.
    fn has_pending_wire(&self) -> bool {
        let mut tmp = [IoSlice::new(&[])];
        self.pending_wire(&mut tmp) != 0
    }
}

/// Streaming Snell TCP decoder.
///
/// The decode lifecycle is:
/// 1. [`SnellTcpDecoder::next_ciphertext_slot`] — borrow a slice to fill.
/// 2. [`SnellTcpDecoder::commit_ciphertext`] — report how many bytes arrived.
/// 3. On [`PlainData`](DecodeEvent::PlainData), drain plaintext via
///    [`SnellTcpDecoder::pending_plaintext`] /
///    [`SnellTcpDecoder::advance_plaintext`].
pub trait SnellTcpDecoder {
    /// Borrow the next ciphertext fill target, or signal a plaintext backpressure.
    fn next_ciphertext_slot(&mut self) -> DecodeSlot<'_>;

    /// Report `n` newly filled ciphertext bytes and advance the read state.
    fn commit_ciphertext(&mut self, n: usize) -> io::Result<DecodeEvent<'_>>;

    /// Collect decrypted plaintext pending drain into `out` as vectored slices.
    fn pending_plaintext<'a>(&'a self, out: &mut [IoSlice<'a>]) -> usize;

    /// Mark `n` bytes from the pending plaintext queue as consumed.
    fn advance_plaintext(&mut self, n: usize);

    /// Whether any decrypted plaintext is still awaiting drain.
    fn has_pending_plaintext(&self) -> bool {
        let mut tmp = [IoSlice::new(&[])];
        self.pending_plaintext(&mut tmp) != 0
    }
}

/// Binds a Snell transport shape to its encoder/decoder constructors.
///
/// Implemented by the zero-sized marker types below so runtime code can be
/// generic over [`V4Mode`], [`V6ShapedMode`], [`V6UnshapedMode`], and
/// [`V6UnsafeRawMode`].
pub trait SnellMode {
    /// Encoder type for this transport shape.
    type Encoder: SnellTcpEncoder;
    /// Decoder type for this transport shape.
    type Decoder: SnellTcpDecoder;

    /// Build an encoder from the pre-shared key.
    fn new_encoder(psk: &[u8]) -> io::Result<Self::Encoder>;
    /// Build a decoder from a shared, cloned pre-shared key.
    fn new_decoder(psk: Arc<[u8]>) -> Self::Decoder;
}

/// [`SnellMode`] marker selecting V4 (legacy, Argon2id, shaped).
#[derive(Clone, Copy, Debug)]
pub struct V4Mode;

/// [`SnellMode`] marker selecting V6 shaped (profile-driven obfuscation).
#[derive(Clone, Copy, Debug)]
pub struct V6ShapedMode;

/// [`SnellMode`] marker selecting V6 unshaped (V4 framing, no shaping).
#[derive(Clone, Copy, Debug)]
pub struct V6UnshapedMode;

/// [`SnellMode`] marker selecting V6 unsafe-raw (plaintext debug pass-through).
#[derive(Clone, Copy, Debug)]
pub struct V6UnsafeRawMode;

impl SnellMode for V4Mode {
    type Encoder = V4Encoder;
    type Decoder = V4Decoder;

    fn new_encoder(psk: &[u8]) -> io::Result<Self::Encoder> {
        V4Encoder::new(psk)
    }

    fn new_decoder(psk: Arc<[u8]>) -> Self::Decoder {
        V4Decoder::new(psk)
    }
}

impl SnellMode for V6ShapedMode {
    type Encoder = V6ShapedEncoder;
    type Decoder = V6ShapedDecoder;

    fn new_encoder(psk: &[u8]) -> io::Result<Self::Encoder> {
        V6ShapedEncoder::new(psk)
    }

    fn new_decoder(psk: Arc<[u8]>) -> Self::Decoder {
        V6ShapedDecoder::new(psk)
    }
}

impl SnellMode for V6UnshapedMode {
    type Encoder = V6UnshapedEncoder;
    type Decoder = V6UnshapedDecoder;

    fn new_encoder(psk: &[u8]) -> io::Result<Self::Encoder> {
        V6UnshapedEncoder::new(psk)
    }

    fn new_decoder(psk: Arc<[u8]>) -> Self::Decoder {
        V6UnshapedDecoder::new(psk)
    }
}

impl SnellMode for V6UnsafeRawMode {
    type Encoder = V6UnsafeRawEncoder;
    type Decoder = V6UnsafeRawDecoder;

    fn new_encoder(_psk: &[u8]) -> io::Result<Self::Encoder> {
        Ok(V6UnsafeRawEncoder::new())
    }

    fn new_decoder(_psk: Arc<[u8]>) -> Self::Decoder {
        V6UnsafeRawDecoder::new()
    }
}

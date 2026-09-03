//! Synchronous Snell protocol kernel.
//!
//! Runtime-free: no Tokio, sockets, logging, or global state.
//! v4/v5/v6 record codecs are implemented. `unsafe-raw` is feature-gated.

#![deny(unsafe_code)]

mod address;
mod aead;
mod buffer;
mod chunk;
mod clock;
mod control;
mod entropy;
mod error;
mod header;
mod kdf;
mod nonce;
mod padding;
mod parse;
mod prf;
mod profile;
mod record;
mod salt;
mod secret;
pub mod socks5;
mod stream;
mod v4;
mod v6;
mod v6_shaped;
mod v6_unshaped;

#[cfg(feature = "unsafe-raw")]
mod v6_raw;

#[cfg(test)]
mod fragment;

pub use address::{Address, AddressRef};
pub use buffer::{ENCODE_BUFFER_MAX, EncodeBuffer, RecvBuffer};
pub use chunk::next_v4_chunk_limit;
pub use clock::{Clock, FixedClock, UnixClock};
pub use control::{
    ConnectRequest, ServerReply, UdpPacket, connect_request_len, decode_connect_request,
    decode_connect_request_prefix, decode_server_reply, decode_udp_request, decode_udp_response,
    decode_udp_setup_prefix, encode_connect_request, encode_error_reply, encode_reject,
    encode_tunnel_reply, encode_udp_request, encode_udp_response, encode_udp_setup,
    udp_request_len, udp_response_len,
};
pub use entropy::{Entropy, OsEntropy, RepeatEntropy, SequenceEntropy};
pub use error::{Error, Result};
pub use header::{
    RecordHeader, parse_v4_plain_header, parse_v6_plain_header, write_v4_plain_header,
    write_v6_plain_header,
};
pub use kdf::{aead_key, aead_key_raw, profile_secret};
pub use nonce::Nonce;
pub use parse::ParseState;
pub use record::{DecodeStatus, DecodedRecord, RecordKind};
pub use secret::Psk;
pub use stream::PlainStream;
pub use v4::{V4, V4Decoder, V4Encoder, V4Reservation, V5, V5Decoder, V5Encoder};
pub use v6::{
    V6Shaped, V6ShapedDecoder, V6ShapedEncoder, V6ShapedReservation, V6Unshaped, V6UnshapedDecoder,
    V6UnshapedEncoder, V6UnshapedReservation,
};

/// Exact record-codec selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolFlavor {
    V4,
    V5,
    V6Shaped,
    V6Unshaped,
}

/// Server protocol selection. Exact never probes. Auto is v4 and v6-shaped only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolSelection {
    Exact(ProtocolFlavor),
    Auto,
}

#[cfg(feature = "unsafe-raw")]
pub use v6::{V6UnsafeRaw, V6UnsafeRawDecoder, V6UnsafeRawEncoder, V6UnsafeRawReservation};

/// Snell CONNECT / UDP-setup version byte. Distinct from the AEAD header marker.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Client CONNECT without reuse.
pub const COMMAND_CONNECT: u8 = 0x01;

/// Client CONNECT that may reuse the TCP session.
pub const COMMAND_CONNECT_V2: u8 = 0x05;

/// Client UDP association setup.
pub const COMMAND_UDP: u8 = 0x06;

/// Inner UDP-over-TCP request packet command.
pub const COMMAND_UDP_FORWARD: u8 = 0x01;

/// Server reply: tunnel established. Remaining plaintext is TCP stream data.
pub const COMMAND_TUNNEL: u8 = 0x00;

/// Server reply: error. Layout `code(1) msg_len(1) message`.
pub const COMMAND_ERROR: u8 = 0x02;

/// Server reject code used for outbound/connect failures.
pub const ERROR_REJECT: u8 = 0x01;

/// UDP request IPv4/IPv6 length sentinel (domain uses a non-zero host length).
pub const UDP_REQUEST_IP_LEN: u8 = 0x00;

/// UDP / SOCKS-style IPv4 address tag.
pub const ATYP_IPV4: u8 = 0x04;

/// UDP / SOCKS-style IPv6 address tag.
pub const ATYP_IPV6: u8 = 0x06;

/// UDP response domain address tag.
pub const ATYP_DOMAIN: u8 = 0x03;

/// Per-session salt length.
pub const SALT_LEN: usize = 16;

/// AES-128-GCM nonce length.
pub const NONCE_LEN: usize = 12;

/// AES-128-GCM tag length.
pub const TAG_LEN: usize = 16;

/// Plaintext record header length: `VER RSV RSV PADDING(2) PAYLOAD(2)`.
pub const HEADER_PLAIN_LEN: usize = 7;

/// Encrypted record header length: plaintext header plus tag.
pub const HEADER_CIPHER_LEN: usize = HEADER_PLAIN_LEN + TAG_LEN;

/// AEAD header marker used by v4 and v6 (`HEADER_PLAIN[0]`).
pub const HEADER_VERSION_MARKER: u8 = 4;

/// v4 / v6-unshaped maximum payload per record.
pub const MAX_PACKET_SIZE: usize = 0x3fff;

/// Maximum on-wire size of one v4 record, including first-record salt.
pub const V4_WIRE_CAP: usize =
    SALT_LEN + HEADER_CIPHER_LEN + MAX_PACKET_SIZE + MAX_PACKET_SIZE + TAG_LEN;

/// v6 shaped / unsafe-raw maximum payload (`u16` field).
pub const MAX_PACKET_SIZE_V6: usize = u16::MAX as usize;

/// Largest CONNECT control payload.
pub const MAX_CONNECT_REQUEST_LEN: usize = 3 + 255 + 1 + 255 + 2;

/// Largest UDP address prefix.
pub const MAX_UDP_PACKET_ADDR_LEN: usize = 1 + 1 + 255 + 2;

/// v6 salt block maximum length.
pub const MAX_SALT_BLOCK_LEN: usize = 256;

/// v6 shaped record prefix upper bound (`prefix_max` is clamped to this).
pub const V6_MAX_PREFIX_LEN: usize = 0x80;

/// v6 shaped reserved padding: `pad_max + extra target`, each ≤ `0x02da`.
pub const V6_MAX_PADDING_RESERVE: usize = 0x02da * 2;

/// Maximum on-wire size of one v6 shaped record, including the salt block.
pub const V6_WIRE_CAP: usize = MAX_SALT_BLOCK_LEN
    + V6_MAX_PREFIX_LEN
    + HEADER_CIPHER_LEN
    + V6_MAX_PADDING_RESERVE
    + MAX_PACKET_SIZE_V6
    + TAG_LEN;

/// v4 congestion MSS used when sizing the first records.
pub const V4_MSS_BASE: usize = 0x05b4;

/// Bytes subtracted from the MSS for the first v4 record.
pub const V4_FIRST_RECORD_OVERHEAD: usize = 0x37;

/// Bytes subtracted from the MSS after a v4 idle reset.
pub const V4_RESET_OVERHEAD: usize = 0x27;

/// Minimum padding on the first v4 record.
pub const V4_INITIAL_PADDING_MIN: usize = 0x100;

/// Exclusive upper bound added to [`V4_INITIAL_PADDING_MIN`].
pub const V4_INITIAL_PADDING_SPAN: u32 = 0x100;

/// Idle interval after which v4 chunk sizing resets.
pub const V4_IDLE_RESET_SECS: u64 = 30;

/// Argon2id memory cost in KiB.
pub const ARGON2_M_COST_KIB: u32 = 8;

/// Argon2id time cost.
pub const ARGON2_T_COST: u32 = 3;

/// Argon2id parallelism.
pub const ARGON2_P_COST: u32 = 1;

/// Argon2id output size; AES-128-GCM uses the first 16 bytes.
pub const ARGON2_OUTPUT_LEN: usize = 32;

/// AES-128-GCM key length.
pub const AES_128_KEY_LEN: usize = 16;

/// Minimum PSK length in bytes.
pub const PSK_MIN_LEN: usize = 16;

/// Maximum PSK length in bytes.
pub const PSK_MAX_LEN: usize = 255;

/// Host / domain length limit (one-byte length prefix).
pub const MAX_DOMAIN_LEN: usize = 255;

/// TCP connect timeout.
pub const TCP_CONNECT_TIMEOUT_SECS: u64 = 5;

/// First handshake / control timeout.
pub const TCP_HANDSHAKE_TIMEOUT_SECS: u64 = 15;

/// Server wait for the next CONNECT on a reused session.
pub const REUSE_IDLE_TIMEOUT_SECS: u64 = 3600;

/// Client reuse pool capacity.
pub const CLIENT_POOL_MAX_SIZE: usize = 10;

/// Client reuse pool max idle age.
pub const CLIENT_POOL_MAX_IDLE_SECS: u64 = 300;

/// UDP association idle timeout.
pub const UDP_ASSOCIATION_IDLE_SECS: u64 = 300;

/// Socket datagram cap. The encoded Snell datagram must still fit one record.
pub const UDP_DATAGRAM_MAX: usize = 65535;

/// Auto-detect deadline.
pub const AUTO_DETECT_TIMEOUT_SECS: u64 = 5;

/// Auto-detect prefix cap in bytes.
pub const AUTO_DETECT_PREFIX_MAX: usize = 4096;

/// Auto-detect candidate cap (v4 and v6-shaped).
pub const AUTO_DETECT_MAX_CANDIDATES: usize = 2;

/// Server early TCP payload after CONNECT, hard cap.
pub const SERVER_EARLY_PAYLOAD_MAX: usize = 64 * 1024;

/// v6 salt replay cache capacity.
pub const REPLAY_CACHE_CAPACITY: usize = 4096;

/// v6 salt replay cache entry TTL.
pub const REPLAY_CACHE_TTL_SECS: u64 = 3600;

/// Max concurrent Argon2id KDFs.
pub const KDF_MAX_INFLIGHT: usize = 8;

/// Max waiters for a KDF permit. Further attempts fail closed.
pub const KDF_MAX_QUEUED: usize = 32;

/// TCP keepalive idle.
pub const TCP_KEEPALIVE_IDLE_SECS: u64 = 300;

/// TCP keepalive probe interval.
pub const TCP_KEEPALIVE_INTERVAL_SECS: u64 = 75;

/// 24-byte seed prepended to the PSK before BLAKE2b-256 profile-secret derivation.
pub const PROFILE_SEED_24: [u8; 24] = [
    0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94, 0x33, 0x18, 0xc0, 0x6e,
    0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_constants_match_phase1() {
        assert_eq!(PROTOCOL_VERSION, 0x01);
        assert_eq!(COMMAND_CONNECT, 0x01);
        assert_eq!(COMMAND_CONNECT_V2, 0x05);
        assert_eq!(COMMAND_UDP, 0x06);
        assert_eq!(COMMAND_UDP_FORWARD, 0x01);
        assert_eq!(COMMAND_TUNNEL, 0x00);
        assert_eq!(COMMAND_ERROR, 0x02);
        assert_eq!(ERROR_REJECT, 0x01);
        assert_eq!(SALT_LEN, 16);
        assert_eq!(NONCE_LEN, 12);
        assert_eq!(TAG_LEN, 16);
        assert_eq!(HEADER_PLAIN_LEN, 7);
        assert_eq!(HEADER_CIPHER_LEN, 23);
        assert_eq!(V4_WIRE_CAP, 32821);
        assert_eq!(V6_WIRE_CAP, 67418);
        assert_eq!(HEADER_VERSION_MARKER, 4);
        assert_eq!(MAX_PACKET_SIZE, 16383);
        assert_eq!(V4_MSS_BASE, 1460);
        assert_eq!(V4_FIRST_RECORD_OVERHEAD, 55);
        assert_eq!(V4_RESET_OVERHEAD, 0x27);
        assert_eq!(MAX_SALT_BLOCK_LEN, 256);
        assert_eq!(MAX_CONNECT_REQUEST_LEN, 3 + 255 + 1 + 255 + 2);
        assert_eq!(V4_INITIAL_PADDING_MIN, 256);
        assert_eq!(ARGON2_M_COST_KIB, 8);
        assert_eq!(ARGON2_T_COST, 3);
        assert_eq!(ARGON2_P_COST, 1);
        assert_eq!(TCP_CONNECT_TIMEOUT_SECS, 5);
        assert_eq!(TCP_HANDSHAKE_TIMEOUT_SECS, 15);
        assert_eq!(REUSE_IDLE_TIMEOUT_SECS, 3600);
        assert_eq!(CLIENT_POOL_MAX_SIZE, 10);
        assert_eq!(CLIENT_POOL_MAX_IDLE_SECS, 300);
        assert_eq!(UDP_ASSOCIATION_IDLE_SECS, 300);
        assert_eq!(UDP_DATAGRAM_MAX, 65535);
        assert_eq!(AUTO_DETECT_TIMEOUT_SECS, 5);
        assert_eq!(AUTO_DETECT_PREFIX_MAX, 4096);
        assert_eq!(AUTO_DETECT_MAX_CANDIDATES, 2);
        assert_eq!(SERVER_EARLY_PAYLOAD_MAX, 64 * 1024);
        assert_eq!(REPLAY_CACHE_CAPACITY, 4096);
        assert_eq!(REPLAY_CACHE_TTL_SECS, 3600);
        assert_eq!(KDF_MAX_INFLIGHT, 8);
        assert_eq!(KDF_MAX_QUEUED, 32);
        assert_eq!(TCP_KEEPALIVE_IDLE_SECS, 300);
        assert_eq!(TCP_KEEPALIVE_INTERVAL_SECS, 75);
        assert_eq!(ProtocolSelection::Auto, ProtocolSelection::Auto);
        assert_eq!(
            ProtocolSelection::Exact(ProtocolFlavor::V4),
            ProtocolSelection::Exact(ProtocolFlavor::V4)
        );
        assert_eq!(
            PROFILE_SEED_24,
            [
                0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94, 0x33, 0x18,
                0xc0, 0x6e, 0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac
            ]
        );
        assert_ne!(ProtocolFlavor::V4, ProtocolFlavor::V5);
        assert_ne!(ProtocolFlavor::V6Shaped, ProtocolFlavor::V6Unshaped);
    }
}

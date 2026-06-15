//! Snell proxy implementation.

pub mod error;
pub(crate) mod parse;

pub mod client;
pub mod config;

pub mod protocol {
    pub mod crypto;
    pub mod header;
    pub mod nonce;
    pub(crate) mod psk;
    pub mod quic_proxy;
    pub(crate) mod random;
    pub mod request;
    pub mod socks5;
    pub mod udp;
    pub mod v4 {
        pub mod frame;
    }
    pub mod v6;
    pub mod version;
}

pub(crate) mod framed;

pub(crate) mod relay {
    pub(crate) mod activity;
    pub(crate) mod quic_proxy;
    pub(crate) mod tcp;
    pub(crate) mod udp {
        pub(crate) mod association;
        pub(crate) mod io;
        pub(crate) mod outbound;
        pub(crate) mod socket;
    }
}

pub(crate) mod transport {
    pub(crate) mod reuse;
    pub(crate) mod tcp;
    pub(crate) mod udp {
        pub(crate) mod stream;
    }
}

pub(crate) mod net {
    pub(crate) mod connect;
    pub(crate) mod dns;
    pub(crate) mod tcp_brutal;
}

pub(crate) mod proxy {
    pub(crate) mod outbound;
    pub(crate) mod snell {
        pub(crate) mod server;
        pub(crate) mod tcp;
    }
    pub(crate) mod socks5 {
        pub(crate) mod inbound;
        pub(crate) mod udp;
    }
}

pub mod server;

#[cfg(test)]
pub(crate) mod test_support;

pub use protocol::version::ProtocolVersion;

pub const MAX_PACKET_SIZE: usize = 0x3fff;
pub(crate) const MAX_V6_RECORD_PAYLOAD_LEN: usize = u16::MAX as usize;

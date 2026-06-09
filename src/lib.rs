//! Snell proxy implementation.

pub mod error;
pub(crate) mod parse;

pub mod protocol {
    pub mod crypto;
    pub mod frame_v4;
    pub mod header;
    pub mod nonce;
    pub mod quic_proxy;
    pub(crate) mod random;
    pub mod request;
    pub mod socks5;
    pub mod udp;
}

pub mod service {
    pub mod inbound {
        pub(crate) mod snell;
        pub mod socks5;
    }
    pub(crate) mod outbound;
    pub mod runtime {
        pub mod client;
        pub mod config;
        pub(crate) mod lifecycle;
        pub(crate) mod net;
        pub mod server;
        pub(crate) mod tcp_brutal;
    }
    pub(crate) mod session {
        pub(crate) mod quic_proxy;
        pub(crate) mod socks5_udp;
        pub(crate) mod udp_association;
        pub(crate) mod udp_outbound;
        pub(crate) mod udp_socket;
    }

    #[cfg(test)]
    pub(crate) mod test_support;
}

pub(crate) mod relay {
    pub(crate) mod snell_tcp;
    pub(crate) mod tcp;
}

pub mod transport {
    pub(crate) mod reuse;
    pub(crate) mod tcp_stream;
    pub(crate) mod tokio_io;
    pub(crate) mod udp_stream;
}

pub const VERSION_1: u8 = 1;
pub const VERSION_2: u8 = 2;
pub const VERSION_3: u8 = 3;
pub const VERSION_4: u8 = 4;
pub const VERSION_5: u8 = 5;

pub const DEFAULT_VERSION: u8 = VERSION_4;
pub const MAX_PACKET_SIZE: usize = 0x3fff;

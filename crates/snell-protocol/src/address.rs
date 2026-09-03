use std::borrow::Cow;
use std::fmt;
use std::net::SocketAddr;

use crate::{Error, MAX_DOMAIN_LEN, Result};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressRef<'a> {
    Ip(SocketAddr),
    Domain { host: &'a str, port: u16 },
}

impl Address {
    pub fn domain(host: impl Into<String>, port: u16) -> Result<Self> {
        let host = host.into();
        validate_domain(&host)?;
        Ok(Self::Domain { host, port })
    }

    pub fn as_view(&self) -> AddressRef<'_> {
        match self {
            Self::Ip(addr) => AddressRef::Ip(*addr),
            Self::Domain { host, port } => AddressRef::Domain { host, port: *port },
        }
    }

    pub fn port(&self) -> u16 {
        self.as_view().port()
    }
}

impl<'a> AddressRef<'a> {
    pub fn domain(host: &'a str, port: u16) -> Result<Self> {
        validate_domain(host)?;
        Ok(Self::Domain { host, port })
    }

    pub fn into_owned(self) -> Address {
        match self {
            Self::Ip(addr) => Address::Ip(addr),
            Self::Domain { host, port } => Address::Domain {
                host: host.to_owned(),
                port,
            },
        }
    }

    pub fn port(self) -> u16 {
        match self {
            Self::Ip(addr) => addr.port(),
            Self::Domain { port, .. } => port,
        }
    }

    pub fn host(self) -> Cow<'a, str> {
        match self {
            Self::Ip(SocketAddr::V4(v4)) => Cow::Owned(v4.ip().to_string()),
            Self::Ip(SocketAddr::V6(v6)) => Cow::Owned(v6.ip().to_string()),
            Self::Domain { host, .. } => Cow::Borrowed(host),
        }
    }
}

pub(crate) fn validate_domain(host: &str) -> Result<()> {
    if host.is_empty() {
        return Err(Error::EmptyHost);
    }
    if host.as_bytes().contains(&0) {
        return Err(Error::HostContainsNul);
    }
    if host.len() > MAX_DOMAIN_LEN {
        return Err(Error::HostTooLong);
    }
    Ok(())
}

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Self::Ip(addr)
    }
}

impl From<SocketAddr> for AddressRef<'_> {
    fn from(addr: SocketAddr) -> Self {
        Self::Ip(addr)
    }
}

impl<'a> From<&'a Address> for AddressRef<'a> {
    fn from(addr: &'a Address) -> Self {
        addr.as_view()
    }
}

impl fmt::Display for AddressRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Domain { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.as_view(), f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn domain_rejects_empty_and_long() {
        assert_eq!(Address::domain("", 80), Err(Error::EmptyHost));
        assert_eq!(
            Address::domain("a".repeat(MAX_DOMAIN_LEN + 1), 80),
            Err(Error::HostTooLong)
        );
    }

    #[test]
    fn display_matches_socketaddr() {
        let v4: SocketAddr = (Ipv4Addr::LOCALHOST, 1080).into();
        assert_eq!(Address::Ip(v4).to_string(), "127.0.0.1:1080");
    }
}

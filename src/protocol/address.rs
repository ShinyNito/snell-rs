//! 目标地址类型。
//!
//! Snell/SOCKS5 在线路上用 1 字节长度前缀编码域名，因此 host 必须 ≤ 255 字节；
//! 该约束在 [`Address::domain`] / [`AddressRef::domain`] 构造时统一兜底，
//! 解析器只需把字节交给构造函数即可获得校验。

use std::borrow::Cow;
use std::fmt;
use std::net::SocketAddr;

use thiserror::Error;

/// 协议线路上单字节长度前缀允许的最大 host 字节数。
pub const MAX_DOMAIN_LEN: usize = 255;

/// 构造 [`Address`] / [`AddressRef`] 时的校验错误。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddressError {
    #[error("domain is empty")]
    EmptyDomain,
    #[error("domain contains NUL byte")]
    DomainContainsNul,
    #[error("domain length {0} exceeds {MAX_DOMAIN_LEN}")]
    DomainTooLong(usize),
}

/// 拥有所有权的目标地址。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

/// 借用形态的目标地址，与 [`Address`] 同构，便于零拷贝传递。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressRef<'a> {
    Ip(SocketAddr),
    Domain { host: &'a str, port: u16 },
}

impl Address {
    /// 构造域名地址，校验长度落在 `1..=255` 字节范围内。
    pub fn domain(host: impl Into<String>, port: u16) -> Result<Self, AddressError> {
        let host = host.into();
        validate_domain(&host)?;
        Ok(Self::Domain { host, port })
    }

    /// 借用为 [`AddressRef`]。
    pub fn as_view(&self) -> AddressRef<'_> {
        match self {
            Address::Ip(addr) => AddressRef::Ip(*addr),
            Address::Domain { host, port } => AddressRef::Domain { host, port: *port },
        }
    }

    /// 端口号。
    pub fn port(&self) -> u16 {
        self.as_view().port()
    }
}

impl<'a> AddressRef<'a> {
    /// 借用切片构造域名地址，校验长度。
    pub fn domain(host: &'a str, port: u16) -> Result<Self, AddressError> {
        validate_domain(host)?;
        Ok(Self::Domain { host, port })
    }

    /// 升级为拥有所有权的 [`Address`]。
    pub fn into_owned(self) -> Address {
        match self {
            AddressRef::Ip(addr) => Address::Ip(addr),
            AddressRef::Domain { host, port } => Address::Domain {
                host: host.to_owned(),
                port,
            },
        }
    }

    pub fn port(self) -> u16 {
        match self {
            AddressRef::Ip(addr) => addr.port(),
            AddressRef::Domain { port, .. } => port,
        }
    }

    /// 取 host 部分；IP 时返回格式化后的字符串，域名时零拷贝借用。
    pub fn host(self) -> Cow<'a, str> {
        match self {
            AddressRef::Ip(SocketAddr::V4(v4)) => Cow::Owned(v4.ip().to_string()),
            AddressRef::Ip(SocketAddr::V6(v6)) => Cow::Owned(v6.ip().to_string()),
            AddressRef::Domain { host, .. } => Cow::Borrowed(host),
        }
    }
}

fn validate_domain(host: &str) -> Result<(), AddressError> {
    if host.is_empty() {
        return Err(AddressError::EmptyDomain);
    }
    if host.as_bytes().contains(&0) {
        return Err(AddressError::DomainContainsNul);
    }
    if host.len() > MAX_DOMAIN_LEN {
        return Err(AddressError::DomainTooLong(host.len()));
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
        // SocketAddr 自带的 Display 已经会用 `[::1]:port` 包裹 IPv6，直接复用。
        match self {
            AddressRef::Ip(addr) => write!(f, "{addr}"),
            AddressRef::Domain { host, port } => write!(f, "{host}:{port}"),
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
    fn domain_constructor_validates_length() {
        assert_eq!(Address::domain("", 80), Err(AddressError::EmptyDomain));
        let long = "a".repeat(MAX_DOMAIN_LEN + 1);
        assert_eq!(
            Address::domain(long, 80),
            Err(AddressError::DomainTooLong(MAX_DOMAIN_LEN + 1)),
        );
        assert!(Address::domain("example.com", 443).is_ok());
    }

    #[test]
    fn view_round_trips() {
        let owned = Address::domain("example.com", 443).unwrap();
        let view = owned.as_view();
        assert_eq!(view.port(), 443);
        assert_eq!(view.host(), "example.com");
        assert_eq!(view.into_owned(), owned);
    }

    #[test]
    fn display_formats_match_socketaddr() {
        let v4: SocketAddr = (Ipv4Addr::LOCALHOST, 1080).into();
        assert_eq!(Address::Ip(v4).to_string(), "127.0.0.1:1080");

        let v6: SocketAddr = "[::1]:1080".parse().unwrap();
        assert_eq!(Address::Ip(v6).to_string(), "[::1]:1080");

        let domain = Address::domain("example.com", 443).unwrap();
        assert_eq!(domain.to_string(), "example.com:443");
    }
}

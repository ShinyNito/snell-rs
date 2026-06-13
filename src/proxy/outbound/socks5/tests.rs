use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

use super::{
    Socks5Command, Socks5UdpRelayEndpoint, command_request_capacity, request_socks5_command,
    udp_relay_endpoint_from_bound,
};
use crate::error::Error;
use crate::protocol::socks5::{SocksAddress, SocksBoundAddr};
use crate::protocol::udp::AddressRef;

async fn run_method_selection_error(selection: [u8; 2]) -> Error {
    let (mut client, mut server) = duplex(128);

    let client_task = async {
        request_socks5_command(
            &mut client,
            Socks5Command::Connect,
            AddressRef::Domain("example.com"),
            443,
        )
        .await
        .unwrap_err()
    };

    let server_task = async {
        let mut greeting = [0; 3];
        server.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        server.write_all(&selection).await.unwrap();
    };

    let (err, ()) = tokio::join!(client_task, server_task);
    err
}

async fn run_command_reply_error(reply: &'static [u8]) -> Error {
    let (mut client, mut server) = duplex(128);

    let client_task = async {
        request_socks5_command(
            &mut client,
            Socks5Command::Connect,
            AddressRef::Domain("example.com"),
            443,
        )
        .await
        .unwrap_err()
    };

    let server_task = async {
        let mut greeting = [0; 3];
        server.read_exact(&mut greeting).await.unwrap();
        server.write_all(&[5, 0]).await.unwrap();

        let mut request = [0; 18];
        server.read_exact(&mut request).await.unwrap();
        server.write_all(reply).await.unwrap();
    };

    let (err, ()) = tokio::join!(client_task, server_task);
    err
}

#[test]
fn command_request_capacity_matches_address_shape() {
    assert_eq!(
        command_request_capacity(AddressRef::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))).unwrap(),
        10
    );
    assert_eq!(
        command_request_capacity(AddressRef::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))).unwrap(),
        22
    );

    let max_host = "a".repeat(u8::MAX as usize);
    assert_eq!(
        command_request_capacity(AddressRef::Domain(&max_host)).unwrap(),
        262
    );

    std::assert_matches!(
        command_request_capacity(AddressRef::Domain("")),
        Err(Error::EmptyHost)
    );
    let too_long_host = "a".repeat(u8::MAX as usize + 1);
    std::assert_matches!(
        command_request_capacity(AddressRef::Domain(&too_long_host)),
        Err(Error::HostTooLong)
    );
}

#[tokio::test]
async fn client_command_writes_no_auth_connect_request() {
    let (mut client, mut server) = duplex(128);

    let client_task = async {
        let bound = request_socks5_command(
            &mut client,
            Socks5Command::Connect,
            AddressRef::Domain("example.com"),
            443,
        )
        .await
        .unwrap();
        assert_eq!(
            bound,
            SocksBoundAddr {
                address: SocksAddress::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                port: 0
            }
        );
    };

    let server_task = async {
        let mut greeting = [0; 3];
        server.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        server.write_all(&[5, 0]).await.unwrap();

        let mut request = [0; 18];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(
            request,
            [
                5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
                0x01, 0xbb
            ]
        );
        server
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    };

    let ((), ()) = tokio::join!(client_task, server_task);
}

#[tokio::test]
async fn client_command_classifies_method_selection_errors() {
    let err = run_method_selection_error([4, 0]).await;
    std::assert_matches!(err, Error::InvalidSocksResponse);

    let err = run_method_selection_error([5, 0xff]).await;
    std::assert_matches!(err, Error::Socks5NoAcceptableAuthMethod);

    let err = run_method_selection_error([5, 2]).await;
    std::assert_matches!(err, Error::UnsupportedSocks5AuthMethod(2));
}

#[tokio::test]
async fn client_command_classifies_invalid_command_replies() {
    let err = run_command_reply_error(&[4, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
    std::assert_matches!(err, Error::InvalidSocksResponse);

    let err = run_command_reply_error(&[5, 0, 1, 1, 0, 0, 0, 0, 0, 0]).await;
    std::assert_matches!(err, Error::InvalidSocksResponse);

    let err = run_command_reply_error(&[5, 0, 0, 9]).await;
    std::assert_matches!(err, Error::InvalidSocksResponse);

    let err = run_command_reply_error(&[5, 0, 0, 3, 0]).await;
    std::assert_matches!(err, Error::InvalidSocksResponse);
}

#[tokio::test]
async fn client_command_surfaces_socks5_reply_error() {
    let (mut client, mut server) = duplex(128);

    let client_task = async {
        std::assert_matches!(
            request_socks5_command(
                &mut client,
                Socks5Command::Connect,
                AddressRef::Domain("example.com"),
                443,
            )
            .await,
            Err(Error::Socks5Reply(5))
        );
        let mut marker = [0; 1];
        client.read_exact(&mut marker).await.unwrap();
        assert_eq!(marker, [0xaa]);
    };

    let server_task = async {
        let mut greeting = [0; 3];
        server.read_exact(&mut greeting).await.unwrap();
        server.write_all(&[5, 0]).await.unwrap();
        let mut request = [0; 18];
        server.read_exact(&mut request).await.unwrap();
        server
            .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        server.write_all(&[0xaa]).await.unwrap();
    };

    let ((), ()) = tokio::join!(client_task, server_task);
}

#[tokio::test]
async fn udp_associate_uses_proxy_ip_for_unspecified_bound_addr() {
    let proxy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)), 1080);
    let relay_endpoint = udp_relay_endpoint_from_bound(
        proxy_addr,
        SocksBoundAddr {
            address: SocksAddress::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            port: 5353,
        },
    );

    assert_eq!(
        relay_endpoint,
        Socks5UdpRelayEndpoint::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)),
            5353
        ))
    );
}

#[test]
fn udp_associate_preserves_domain_bound_addr() {
    let proxy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080);
    let relay_endpoint = udp_relay_endpoint_from_bound(
        proxy_addr,
        SocksBoundAddr {
            address: SocksAddress::Domain("relay.example".to_owned()),
            port: 5353,
        },
    );

    assert_eq!(
        relay_endpoint,
        Socks5UdpRelayEndpoint::Domain {
            host: "relay.example".to_owned(),
            port: 5353,
        }
    );
}

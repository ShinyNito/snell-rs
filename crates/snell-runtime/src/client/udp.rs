//! Client side of Snell UDP: SOCKS5 UDP ASSOCIATE.
//!
//! Each association binds its own relay socket before replying, as RFC 1928
//! describes, so a client can never send a datagram the relay does not yet
//! know about. It relays datagrams only from the control connection's IP,
//! and only from the port the first one came from. That first datagram opens
//! a Snell UDP session, which closes after the idle limit and reopens on the
//! next datagram. The association ends with its control connection.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use snell_protocol::socks5::{self, Reply, UdpPacketRef};
use snell_protocol::{
    Error, MAX_UDP_PACKET_ADDR_LEN, RecordDecoder, RecordEncoder, UDP_DATAGRAM_MAX,
    decode_udp_response,
};
use tokio::io::{AsyncReadExt, AsyncWrite};
use tokio::net::tcp::ReadHalf;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::Instant;

use super::pool::Connection;
use super::socks::write_socks5_reply_bind;
use super::{ClientConfig, dial};
use crate::buffer::{BufferPool, PooledBuffer};
use crate::bufio::recv_datagram;
use crate::codec::with_codec;
use crate::error::SessionError;
use crate::kdf::KdfLimiter;
use crate::platform::send_udp_parts;
use crate::session::{
    RecordEvent, decode_once, read_server_tunnel, with_handshake_timeout, write_udp_request,
    write_udp_setup,
};
use crate::udp::UdpMetrics;

/// Serve one UDP ASSOCIATE request on `control` until the control
/// connection closes. `controls` caps how many are open at once.
pub(crate) async fn associate(
    mut control: TcpStream,
    config: &ClientConfig,
    kdf: &KdfLimiter,
    controls: &Semaphore,
) -> Result<(), SessionError> {
    let unspecified = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
    let Ok(_control_slot) = controls.try_acquire() else {
        write_socks5_reply_bind(&mut control, Reply::GeneralFailure, unspecified).await?;
        return Err(SessionError::UdpLimit);
    };
    // Bind where the client reached us, so the reply names a concrete relay
    // address even when the SOCKS5 listener is bound to a wildcard.
    let mut bind = control.local_addr()?;
    bind.set_port(0);
    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(error) => {
            write_socks5_reply_bind(&mut control, Reply::GeneralFailure, unspecified).await?;
            return Err(error.into());
        }
    };
    write_socks5_reply_bind(&mut control, Reply::Succeeded, socket.local_addr()?).await?;

    let mut association = Association {
        relay: Relay {
            socket,
            client_ip: control.peer_addr()?.ip(),
            client: None,
        },
        config,
        kdf,
    };
    tokio::select! {
        () = closed(&mut control) => Ok(()),
        result = association.run() => result,
    }
}

/// Resolves once the control connection closes or fails.
async fn closed(control: &mut TcpStream) {
    let mut byte = [0u8; 1];
    while control.read(&mut byte).await.is_ok_and(|n| n > 0) {}
}

struct Association<'a> {
    relay: Relay,
    config: &'a ClientConfig,
    kdf: &'a KdfLimiter,
}

/// The association's relay socket and the client it serves.
struct Relay {
    socket: UdpSocket,
    /// The control connection's IP; datagrams from other IPs are dropped.
    client_ip: IpAddr,
    /// Fixed by the first datagram; datagrams from other ports are dropped.
    client: Option<SocketAddr>,
}

impl Relay {
    /// The next datagram from the client, and the client's address.
    async fn recv(
        &mut self,
        buffers: &Arc<BufferPool>,
        metrics: &UdpMetrics,
    ) -> Result<(PooledBuffer, SocketAddr), SessionError> {
        loop {
            let (datagram, from) = recv_datagram(&self.socket, buffers).await?;
            let expected = match self.client {
                Some(client) => from == client,
                None => from.ip().to_canonical() == self.client_ip.to_canonical(),
            };
            if expected {
                self.client = Some(from);
                return Ok((datagram, from));
            }
            metrics.invalid.fetch_add(1, Ordering::Relaxed);
        }
    }
}

enum SessionEnd {
    Idle,
    Closed,
}

impl Association<'_> {
    async fn run(&mut self) -> Result<(), SessionError> {
        let udp = &self.config.udp;
        loop {
            let (first, client) = self.relay.recv(&self.config.buffers, &udp.metrics).await?;
            if client_packet(first.filled(), &udp.metrics).is_none() {
                continue;
            }
            let Some(_session_slot) = udp.metrics.admit(udp.limits.max_associations) else {
                continue;
            };
            match self.session(first, client).await {
                Ok(SessionEnd::Idle) => {
                    udp.metrics.idle_expired.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(client = %client, "udp session closed after idle timeout");
                }
                Ok(SessionEnd::Closed) => {}
                Err(error) => {
                    tracing::debug!(client = %client, error = %error, "udp session failed")
                }
            }
        }
    }

    /// Open a Snell UDP session, send `first` through it, and relay both ways
    /// until the session idles out or closes.
    async fn session(
        &mut self,
        first: PooledBuffer,
        client: SocketAddr,
    ) -> Result<SessionEnd, SessionError> {
        let config = self.config;
        // Boxed: dialing and the UDP handshake are finished before relaying
        // starts, so the relay does not reserve their space.
        let (mut conn, mut recv) = Box::pin(open_session(config, self.kdf)).await?;
        let Connection { stream, codec } = &mut conn;
        let (mut snell_r, mut snell_w) = stream.split();
        with_codec!(codec, |encoder, decoder| {
            forward(encoder, &mut snell_w, first.filled(), config).await?;
            drop(first);
            self.pump(
                &mut snell_r,
                &mut snell_w,
                encoder,
                decoder,
                &mut recv,
                client,
            )
            .await
        })
    }

    async fn pump<E: RecordEncoder, D: RecordDecoder>(
        &mut self,
        snell_r: &mut ReadHalf<'_>,
        snell_w: &mut (impl AsyncWrite + Unpin),
        encoder: &mut E,
        decoder: &mut D,
        recv: &mut PooledBuffer,
        client: SocketAddr,
    ) -> Result<SessionEnd, SessionError> {
        let config = self.config;
        let udp = &config.udp;
        let sleep = tokio::time::sleep(udp.limits.idle);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                () = &mut sleep => return Ok(SessionEnd::Idle),
                datagram = self.relay.recv(&config.buffers, &udp.metrics) => {
                    let (datagram, _) = datagram?;
                    sleep.as_mut().reset(Instant::now() + udp.limits.idle);
                    forward(encoder, snell_w, datagram.filled(), config).await?;
                }
                record = decode_once(decoder, recv, snell_r, self.kdf, &config.psk) => {
                    sleep.as_mut().reset(Instant::now() + udp.limits.idle);
                    let RecordEvent::Data(record) = record? else {
                        return Ok(SessionEnd::Closed);
                    };
                    let plain = record.plaintext(recv.filled());
                    send_socks_response(&self.relay.socket, client, plain, &udp.metrics).await?;
                    decoder.consume(recv, &record)?;
                }
            }
        }
    }
}

/// Dial the server and complete the Snell UDP setup handshake. Returns the
/// connection and its receive buffer.
async fn open_session(
    config: &ClientConfig,
    kdf: &KdfLimiter,
) -> Result<(Connection, PooledBuffer), SessionError> {
    let mut conn = dial(config, kdf).await?;
    let mut recv = config.buffers.get(snell_protocol::V6_WIRE_CAP);
    let Connection { stream, codec } = &mut conn;
    with_codec!(codec, |encoder, decoder| {
        with_handshake_timeout(async {
            write_udp_setup(encoder, &config.buffers, stream).await?;
            let leftover = read_server_tunnel(decoder, &mut recv, stream, kdf, &config.psk).await?;
            if !leftover.is_empty() {
                return Err(Error::Malformed("udp tunnel leftover").into());
            }
            Ok(())
        })
        .await
    })?;
    Ok((conn, recv))
}

/// The SOCKS5 UDP packet in a client datagram. Malformed and fragmented
/// datagrams are counted and dropped.
fn client_packet<'a>(datagram: &'a [u8], metrics: &UdpMetrics) -> Option<UdpPacketRef<'a>> {
    let Ok(packet) = socks5::parse_udp_packet(datagram) else {
        metrics.invalid.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    if packet.frag != 0 {
        metrics.frag_dropped.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    Some(packet)
}

/// Send one client datagram through the session; a datagram too large for a
/// record is counted and dropped.
async fn forward<E: RecordEncoder>(
    encoder: &mut E,
    snell: &mut (impl AsyncWrite + Unpin),
    datagram: &[u8],
    config: &ClientConfig,
) -> Result<(), SessionError> {
    let metrics = &config.udp.metrics;
    let Some(packet) = client_packet(datagram, metrics) else {
        return Ok(());
    };
    let address = packet.destination;
    match write_udp_request(encoder, &config.buffers, snell, address, packet.payload).await {
        Err(SessionError::Protocol(Error::PayloadTooLarge)) => {
            metrics.oversize.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        result => result,
    }
}

async fn send_socks_response(
    socket: &UdpSocket,
    client: SocketAddr,
    plain: &[u8],
    metrics: &UdpMetrics,
) -> Result<(), SessionError> {
    let pkt = match decode_udp_response(plain) {
        Ok(pkt) => pkt,
        Err(_) => {
            metrics.invalid.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    };
    // Keep the payload borrowed from the decoded record until the atomic send.
    let mut hdr = [0u8; 3 + MAX_UDP_PACKET_ADDR_LEN];
    let hdr_len = match socks5::encode_udp_header(&mut hdr, 0, pkt.address) {
        Ok(n) => n,
        Err(_) => {
            metrics.invalid.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    };
    let needed = hdr_len.saturating_add(pkt.payload.len());
    if needed > UDP_DATAGRAM_MAX {
        metrics.oversize.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }
    send_udp_parts(socket, client, &hdr[..hdr_len], pkt.payload).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udp::UdpOptions;
    use snell_protocol::{AddressRef, ParseState, ProtocolFlavor, Psk};
    use std::time::Duration;
    use tokio::net::TcpListener;

    fn config(server: SocketAddr) -> ClientConfig {
        ClientConfig {
            listen: server,
            server,
            psk: Psk::new(b"0123456789abcdef").unwrap(),
            version: ProtocolFlavor::V4,
            pool: None,
            udp: UdpOptions::new().unwrap(),
            buffers: Arc::default(),
        }
    }

    /// The proxy's and the client's ends of a control connection.
    async fn control_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (control, _) = listener.accept().await.unwrap();
        (control, client)
    }

    /// Read the reply to UDP ASSOCIATE: its code and bound address.
    async fn read_reply(client: &mut TcpStream) -> (Reply, SocketAddr) {
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        let ParseState::Done(reply) = socks5::reply_need(&reply).unwrap() else {
            panic!("short reply");
        };
        let AddressRef::Ip(bind) = reply.bind else {
            panic!("domain bind address");
        };
        (reply.reply, bind)
    }

    #[tokio::test]
    async fn relay_takes_the_control_ip_then_only_the_first_port() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = socket.local_addr().unwrap();
        let mut relay = Relay {
            socket,
            client_ip: Ipv4Addr::new(127, 0, 0, 2).into(),
            client: None,
        };
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first = UdpSocket::bind("127.0.0.2:0").await.unwrap();
        let other_port = UdpSocket::bind("127.0.0.2:0").await.unwrap();
        stranger.send_to(b"stranger", relay_addr).await.unwrap();
        first.send_to(b"one", relay_addr).await.unwrap();
        other_port.send_to(b"other", relay_addr).await.unwrap();
        first.send_to(b"two", relay_addr).await.unwrap();

        let (buffers, metrics) = (Arc::default(), UdpMetrics::default());
        for expected in [&b"one"[..], b"two"] {
            let (datagram, from) = relay.recv(&buffers, &metrics).await.unwrap();
            assert_eq!(datagram.filled(), expected);
            assert_eq!(from, first.local_addr().unwrap());
        }
        assert_eq!(metrics.invalid.load(Ordering::Relaxed), 2);
    }

    /// The relay socket exists before the reply names it, and the association
    /// and its control slot last exactly as long as the control connection.
    #[tokio::test]
    async fn association_lives_as_long_as_its_control() {
        let config = config("127.0.0.1:9".parse().unwrap());
        let kdf = KdfLimiter::new();
        let controls = Semaphore::new(1);
        let (control, mut client) = control_pair().await;
        let (result, ()) = tokio::join!(associate(control, &config, &kdf, &controls), async {
            let (reply, relay) = read_reply(&mut client).await;
            assert_eq!(reply, Reply::Succeeded);
            assert_eq!(relay.ip(), Ipv4Addr::LOCALHOST);
            let taken = UdpSocket::bind(relay).await.unwrap_err();
            assert_eq!(taken.kind(), std::io::ErrorKind::AddrInUse);

            let (second, mut second_client) = control_pair().await;
            let refused = associate(second, &config, &kdf, &controls).await;
            assert!(matches!(refused, Err(SessionError::UdpLimit)));
            assert_eq!(
                read_reply(&mut second_client).await.0,
                Reply::GeneralFailure
            );
            drop(client);
        });
        result.unwrap();
        assert_eq!(controls.available_permits(), 1);
    }

    #[tokio::test]
    async fn socks_responses_are_single_datagrams() {
        let metrics = UdpMetrics::default();
        let payload: Vec<u8> = (0..1400).map(|n| n as u8).collect();
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let sender = UdpSocket::bind(bind).await.unwrap();
            let receiver = UdpSocket::bind(bind).await.unwrap();
            for source in ["203.0.113.5:1234", "[2001:db8::5]:1234"] {
                let source = AddressRef::Ip(source.parse().unwrap());
                for payload in [b"".as_slice(), payload.as_slice()] {
                    let mut plain = vec![0; 1500];
                    let n =
                        snell_protocol::encode_udp_response(&mut plain, source, payload).unwrap();
                    send_socks_response(
                        &sender,
                        receiver.local_addr().unwrap(),
                        &plain[..n],
                        &metrics,
                    )
                    .await
                    .unwrap();
                    let mut received = [0; 1500];
                    let (n, peer) = tokio::time::timeout(
                        Duration::from_secs(1),
                        receiver.recv_from(&mut received),
                    )
                    .await
                    .expect("response must arrive as one datagram")
                    .unwrap();
                    assert_eq!(peer, sender.local_addr().unwrap());
                    let packet = socks5::parse_udp_packet(&received[..n]).unwrap();
                    assert_eq!(packet.frag, 0);
                    assert_eq!(packet.destination, source);
                    assert_eq!(&received[packet.header_len..n], payload);
                    assert_eq!(
                        receiver.try_recv_from(&mut received).unwrap_err().kind(),
                        std::io::ErrorKind::WouldBlock,
                        "header and payload must be sent in one datagram",
                    );
                }
            }
        }
        assert_eq!(metrics.invalid.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn socks_response_propagates_socket_error() {
        let metrics = UdpMetrics::default();
        let mut plain = [0; 64];
        let n = snell_protocol::encode_udp_response(
            &mut plain,
            AddressRef::Ip("127.0.0.1:9".parse().unwrap()),
            b"pong",
        )
        .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            send_socks_response(&socket, "[::1]:9".parse().unwrap(), &plain[..n], &metrics),
        )
        .await
        .expect("socket errors must not enter the readiness retry loop")
        .unwrap_err();
        assert!(matches!(error, SessionError::Io(_)));
    }

    #[tokio::test]
    async fn oversized_socks_response_does_not_send_a_header_datagram() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut plain = vec![0; UDP_DATAGRAM_MAX];
        // A Snell payload fits the runtime limit but exceeds IPv4's UDP limit
        // once the SOCKS5 header is included. The OS must reject the whole send.
        let payload = vec![0x5a; 65507];
        let n = snell_protocol::encode_udp_response(
            &mut plain,
            AddressRef::Ip("203.0.113.5:1234".parse().unwrap()),
            &payload,
        )
        .unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            send_socks_response(
                &sender,
                receiver.local_addr().unwrap(),
                &plain[..n],
                &UdpMetrics::default(),
            ),
        )
        .await
        .expect("an oversized datagram must not be retried")
        .unwrap_err();
        assert!(matches!(error, SessionError::Io(_)));
        assert_eq!(
            receiver.try_recv_from(&mut [0; 64]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
        );
    }
}

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpSocket, TcpStream},
    time,
};

use crate::{
    protocol::snell::{
        self, COMMAND_ERROR, COMMAND_TUNNEL, DecodeEvent, DecodeSlot, MAX_CONNECT_REQUEST_LEN,
        SnellMode, SnellTcpDecoder, SnellTcpEncoder, V4Mode, V6ShapedMode,
    },
    relay::tcp::{
        client::SnellTransport,
        driver::{TcpTunnelReader, TcpTunnelWriter},
        transport::{Inbound, InboundRequest, Outbound as _, Transport},
    },
    relay::udp::{Outbound as UdpOutbound, relay_snell_udp},
};

pub mod outbound;
pub use outbound::Outbound;

const PROBE_BUF_LEN: usize = 4096;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub psk: Vec<u8>,
    pub outbound: Outbound,
}

pub async fn bind_tcp_listener(config: ServerConfig) -> io::Result<()> {
    let socket = if config.listen.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.set_nodelay(true)?;
    socket.bind(config.listen)?;
    let listener = socket.listen(4096)?;
    let psk: Arc<[u8]> = Arc::from(config.psk.into_boxed_slice());
    let outbound = config.outbound;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let psk = psk.clone();
        let outbound = outbound.clone();
        tokio::spawn(async move {
            match serve_snell_inbound_auto(stream, psk, outbound).await {
                Ok(()) => tracing::debug!(%peer_addr, "Snell server inbound ended"),
                Err(error) => tracing::debug!(%peer_addr, %error, "Snell server inbound failed"),
            }
        });
    }
}

async fn serve_snell_inbound_auto(
    stream: TcpStream,
    psk: Arc<[u8]>,
    outbound: Outbound,
) -> io::Result<()> {
    match probe_snell_mode(&stream, psk.clone()).await? {
        DetectedMode::V6Shaped => {
            serve_snell_inbound_typed::<V6ShapedMode>(stream, psk, outbound).await
        }
        DetectedMode::V4 => serve_snell_inbound_typed::<V4Mode>(stream, psk, outbound).await,
    }
}

async fn serve_snell_inbound_typed<M>(
    stream: TcpStream,
    psk: Arc<[u8]>,
    outbound: Outbound,
) -> io::Result<()>
where
    M: SnellMode + Send + Sync + 'static + Unpin,
    M::Encoder: Send + Unpin,
    M::Decoder: Send + Unpin,
    <M::Encoder as SnellTcpEncoder>::Reservation: Send + Unpin,
{
    let (read_half, write_half) = stream.into_split();
    let transport: SnellTransport<M> = SnellTransport::new(
        TcpTunnelReader::new::<M>(read_half, psk.clone()),
        TcpTunnelWriter::new::<M>(write_half, psk)?,
    );
    let mut inbound = SnellInbound::new(transport);

    let first = inbound.receive_snell().await?;
    if let SnellInboundRequest::Udp = first {
        tracing::debug!("Snell UDP setup received");
        let target = match UdpOutbound::connect_udp(&outbound).await {
            Ok(target) => target,
            Err(error) => {
                inbound.reject(&error).await?;
                return Err(error);
            }
        };
        inbound.accept().await?;
        return relay_snell_udp(inbound.into_transport(), target).await;
    }

    let mut next = Some(first);
    loop {
        let request = match next.take() {
            Some(SnellInboundRequest::Connect(request)) => request,
            Some(SnellInboundRequest::Udp) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snell udp setup cannot appear in tcp reuse loop",
                ));
            }
            None => {
                let request = Inbound::receive(&mut inbound).await?;
                snell::ConnectRequest {
                    destination: request.destination,
                    reuse: request.reuse,
                }
            }
        };
        tracing::debug!(destination = %request.destination, reuse = request.reuse, "Snell CONNECT received");

        let target = match outbound.connect(&request.destination).await {
            Ok(target) => target,
            Err(error) => {
                inbound.reject(&error).await?;
                return Err(error);
            }
        };
        inbound.accept().await?;

        inbound = SnellInbound::new(inbound.into_transport().relay(target).await?);
        if !request.reuse {
            break;
        }
    }
    Ok(())
}

#[derive(Debug)]
enum SnellInboundRequest {
    Connect(snell::ConnectRequest),
    Udp,
}

async fn read_snell_request<R, D>(
    reader: &mut TcpTunnelReader<R, D>,
) -> io::Result<SnellInboundRequest>
where
    R: AsyncRead + Unpin,
    D: SnellTcpDecoder,
{
    let mut head = [0u8; 3];
    reader.read_exact_plain(&mut head).await?;

    if head[1] == snell::COMMAND_UDP {
        let client_id_len = head[2] as usize;
        let mut client_id = [0u8; 255];
        reader
            .read_exact_plain(&mut client_id[..client_id_len])
            .await?;
        let len = 3 + client_id_len;
        let mut buf = [0u8; 3 + 255];
        buf[..3].copy_from_slice(&head);
        buf[3..len].copy_from_slice(&client_id[..client_id_len]);
        snell::decode_udp_setup_request_prefix(&buf[..len])?;
        return Ok(SnellInboundRequest::Udp);
    }

    let client_id_len = head[2] as usize;
    let mut client_id_and_host_len = [0u8; 255 + 1];
    let client_id_and_host_len_end = client_id_len + 1;
    reader
        .read_exact_plain(&mut client_id_and_host_len[..client_id_and_host_len_end])
        .await?;

    let host_len = client_id_and_host_len[client_id_len] as usize;
    let mut host_and_port = [0u8; 255 + 2];
    reader
        .read_exact_plain(&mut host_and_port[..host_len + 2])
        .await?;

    let len = 3 + client_id_len + 1 + host_len + 2;
    let mut buf = [0u8; MAX_CONNECT_REQUEST_LEN];
    buf[..3].copy_from_slice(&head);
    let client_id_and_host_len_dst_end = 3 + client_id_and_host_len_end;
    buf[3..client_id_and_host_len_dst_end]
        .copy_from_slice(&client_id_and_host_len[..client_id_and_host_len_end]);
    buf[3 + client_id_len + 1..len].copy_from_slice(&host_and_port[..host_len + 2]);
    snell::decode_connect_request(&buf[..len]).map(SnellInboundRequest::Connect)
}

async fn write_server_error<W, E>(
    writer: &mut TcpTunnelWriter<W, E>,
    code: u8,
    message: &str,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    E: SnellTcpEncoder,
{
    let message = message.as_bytes();
    let len = message.len().min(255);
    let mut buf = [0u8; 3 + 255];
    buf[0] = COMMAND_ERROR;
    buf[1] = code;
    buf[2] = len as u8;
    buf[3..3 + len].copy_from_slice(&message[..len]);
    writer.write_frame(&buf[..3 + len]).await
}

struct SnellInbound<M>
where
    M: SnellMode,
{
    transport: SnellTransport<M>,
}

impl<M> SnellInbound<M>
where
    M: SnellMode,
{
    fn new(transport: SnellTransport<M>) -> Self {
        Self { transport }
    }

    async fn receive_snell(&mut self) -> io::Result<SnellInboundRequest>
    where
        M::Decoder: Send,
    {
        read_snell_request(&mut self.transport.reader).await
    }
}

impl<M> Inbound for SnellInbound<M>
where
    M: SnellMode,
    M::Encoder: Send,
    M::Decoder: Send,
    <M::Encoder as SnellTcpEncoder>::Reservation: Send,
{
    type Transport = SnellTransport<M>;

    async fn receive(&mut self) -> io::Result<InboundRequest> {
        match self.receive_snell().await? {
            SnellInboundRequest::Connect(request) => Ok(InboundRequest {
                destination: request.destination,
                reuse: request.reuse,
            }),
            SnellInboundRequest::Udp => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "snell udp setup is not a tcp inbound request",
            )),
        }
    }

    async fn accept(&mut self) -> io::Result<()> {
        self.transport.writer.write_frame(&[COMMAND_TUNNEL]).await
    }

    async fn reject(&mut self, error: &io::Error) -> io::Result<()> {
        write_server_error(&mut self.transport.writer, 1, &error.to_string()).await
    }

    fn into_transport(self) -> Self::Transport {
        self.transport
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DetectedMode {
    V6Shaped,
    V4,
}

async fn probe_snell_mode(stream: &TcpStream, psk: Arc<[u8]>) -> io::Result<DetectedMode> {
    time::timeout(PROBE_TIMEOUT, async {
        let mut buf = [0u8; PROBE_BUF_LEN];
        loop {
            let n = stream.peek(&mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell probe early eof",
                ));
            }

            let v6 = probe_mode::<V6ShapedMode>(psk.clone(), &buf[..n]);
            let v4 = probe_mode::<V4Mode>(psk.clone(), &buf[..n]);
            match (v6, v4) {
                (ProbeResult::Match, _) => return Ok(DetectedMode::V6Shaped),
                (_, ProbeResult::Match) => return Ok(DetectedMode::V4),
                (ProbeResult::NeedMore, _) | (_, ProbeResult::NeedMore) if n < buf.len() => {
                    time::sleep(Duration::from_millis(1)).await;
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "snell probe could not detect v6-default or v4/v5",
                    ));
                }
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "snell probe timed out"))?
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeResult {
    Match,
    NeedMore,
    Invalid,
}

fn probe_mode<M>(psk: Arc<[u8]>, bytes: &[u8]) -> ProbeResult
where
    M: SnellMode,
{
    let mut decoder = M::new_decoder(psk);
    let mut offset = 0;
    loop {
        match decoder.next_ciphertext_slot() {
            DecodeSlot::Read(slot) => {
                if offset == bytes.len() {
                    return ProbeResult::NeedMore;
                }
                let n = slot.len().min(bytes.len() - offset);
                slot[..n].copy_from_slice(&bytes[offset..offset + n]);
                offset += n;

                match decoder.commit_ciphertext(n) {
                    Ok(DecodeEvent::PlainData) => return probe_plaintext(&decoder),
                    Ok(DecodeEvent::ZeroChunk) | Err(_) => return ProbeResult::Invalid,
                    Ok(_) => {}
                }
            }
            DecodeSlot::BlockedByPlaintext => return probe_plaintext(&decoder),
        }
    }
}

fn probe_plaintext<D>(decoder: &D) -> ProbeResult
where
    D: SnellTcpDecoder,
{
    let mut pending = [std::io::IoSlice::new(&[]); 4];
    let nbufs = decoder.pending_plaintext(&mut pending);
    let mut buf = [0u8; MAX_CONNECT_REQUEST_LEN];
    let mut len = 0;
    for slice in &pending[..nbufs] {
        let remaining = buf.len() - len;
        let copied = slice.len().min(remaining);
        buf[len..len + copied].copy_from_slice(&slice[..copied]);
        len += copied;
        if len == buf.len() {
            break;
        }
    }
    probe_control_prefix(snell::decode_connect_request_prefix(&buf[..len]).map(|_| ()))
        .or_else(|| {
            probe_control_prefix(snell::decode_udp_setup_request_prefix(&buf[..len]).map(|_| ()))
        })
        .unwrap_or(ProbeResult::Invalid)
}

fn probe_control_prefix(result: io::Result<()>) -> Option<ProbeResult> {
    match result {
        Ok(()) => Some(ProbeResult::Match),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Some(ProbeResult::NeedMore),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::{
            ParseState,
            address::{Address, AddressRef},
            snell::{V4Mode, V6ShapedMode},
            socks5::{self, Command, METHOD_NO_AUTH, Reply},
        },
        relay::tcp::client::SnellConnector,
    };
    use tokio::{
        io::{self, AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket},
    };

    struct PendingPlaintext(Vec<u8>);

    impl SnellTcpDecoder for PendingPlaintext {
        fn next_ciphertext_slot(&mut self) -> DecodeSlot<'_> {
            DecodeSlot::BlockedByPlaintext
        }

        fn commit_ciphertext(&mut self, _n: usize) -> io::Result<DecodeEvent<'_>> {
            Ok(DecodeEvent::PlainData)
        }

        fn pending_plaintext<'a>(&'a self, out: &mut [std::io::IoSlice<'a>]) -> usize {
            if out.is_empty() {
                return 0;
            }
            out[0] = std::io::IoSlice::new(&self.0);
            1
        }

        fn advance_plaintext(&mut self, _n: usize) {}
    }

    #[tokio::test]
    async fn auto_server_accepts_v4_v5_tcp_codec() {
        auto_server_round_trip::<V4Mode>().await;
    }

    #[tokio::test]
    async fn auto_server_accepts_v6_default() {
        auto_server_round_trip::<V6ShapedMode>().await;
    }

    #[tokio::test]
    async fn server_relays_large_tcp_upload() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let total = 32 * 1024 * 1024;

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut received = 0;
            let mut buf = [0u8; 64 * 1024];
            while received < total {
                let n = stream.read(&mut buf).await.unwrap();
                assert_ne!(n, 0);
                received += n;
            }
            assert_eq!(received, total);
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server_psk = psk.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = server_listener.accept().await.unwrap();
            serve_snell_inbound_auto(stream, server_psk, Outbound::Direct)
                .await
                .unwrap();
        });

        let connector = Arc::new(SnellConnector::<V6ShapedMode>::new(server_addr, psk, false));
        let transport = connector
            .connect(&Address::from(target_addr))
            .await
            .unwrap();
        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (local, _) = local_listener.accept().await.unwrap();
            Transport::relay(transport, local).await.unwrap();
        });

        let mut local = TcpStream::connect(local_addr).await.unwrap();
        let chunk = vec![0x5a; 64 * 1024];
        let mut sent = 0;
        while sent < total {
            local.write_all(&chunk).await.unwrap();
            sent += chunk.len();
        }
        local.shutdown().await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), target)
            .await
            .unwrap()
            .unwrap();
        relay.await.unwrap();
        server.await.unwrap();
    }

    #[test]
    fn v6_probe_accepts_client_id_and_coalesced_payload() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let plaintext = b"\x01\x05\x03abc\x0bexample.com\x01\xbbhello";
        let mut encoder = V6ShapedMode::new_encoder(psk.as_ref()).unwrap();
        let reservation = encoder
            .begin_plain_reservation(snell::PlainPrefix::none(), plaintext.len())
            .unwrap();
        encoder.plain_slot(reservation)[..plaintext.len()].copy_from_slice(plaintext);
        encoder
            .finish_plain_reservation(reservation, plaintext.len())
            .unwrap();

        let mut wire = Vec::new();
        let mut pending = [std::io::IoSlice::new(&[]); 5];
        let nbufs = encoder.pending_wire(&mut pending);
        for slice in &pending[..nbufs] {
            wire.extend_from_slice(slice);
        }

        assert_eq!(probe_mode::<V6ShapedMode>(psk, &wire), ProbeResult::Match);
    }

    #[test]
    fn v6_probe_accepts_udp_setup() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let plaintext = [snell::PROTOCOL_VERSION, snell::COMMAND_UDP, 0];
        let mut encoder = V6ShapedMode::new_encoder(psk.as_ref()).unwrap();
        let reservation = encoder
            .begin_plain_reservation(snell::PlainPrefix::none(), plaintext.len())
            .unwrap();
        encoder.plain_slot(reservation).copy_from_slice(&plaintext);
        encoder
            .finish_plain_reservation(reservation, plaintext.len())
            .unwrap();

        let mut wire = Vec::new();
        let mut pending = [std::io::IoSlice::new(&[]); 5];
        let nbufs = encoder.pending_wire(&mut pending);
        for slice in &pending[..nbufs] {
            wire.extend_from_slice(slice);
        }

        assert_eq!(probe_mode::<V6ShapedMode>(psk, &wire), ProbeResult::Match);
    }

    #[test]
    fn probe_plaintext_accepts_large_coalesced_payload() {
        let mut plaintext = b"\x01\x05\x03abc\x0bexample.com\x01\xbb".to_vec();
        plaintext.resize(plaintext.len() + MAX_CONNECT_REQUEST_LEN, b'x');
        let decoder = PendingPlaintext(plaintext);

        assert_eq!(probe_plaintext(&decoder), ProbeResult::Match);
    }

    #[tokio::test]
    async fn server_uses_socks5_outbound() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let proxy = tokio::spawn(async move {
            let (stream, _) = socks_listener.accept().await.unwrap();
            serve_socks5_proxy_once(stream, target_addr).await.unwrap();
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server_psk = psk.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = server_listener.accept().await.unwrap();
            serve_snell_inbound_auto(stream, server_psk, Outbound::Socks5 { server: socks_addr })
                .await
                .unwrap();
        });

        run_client_round_trip::<V6ShapedMode>(server_addr, psk, Address::from(target_addr)).await;

        server.await.unwrap();
        proxy.await.unwrap();
        target.await.unwrap();
    }

    #[tokio::test]
    async fn server_relays_udp_direct() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);

        let target_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_socket.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (n, peer) = target_socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping");
            target_socket.send_to(b"pong", peer).await.unwrap();
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server_psk = psk.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = server_listener.accept().await.unwrap();
            let _ = serve_snell_inbound_auto(stream, server_psk, Outbound::Direct).await;
        });

        run_udp_client_round_trip::<V6ShapedMode>(server_addr, psk, Address::from(target_addr))
            .await;

        server.abort();
        let _ = server.await;
        target.await.unwrap();
    }

    #[tokio::test]
    async fn server_treats_udp_carrier_close_as_normal() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);

        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server_psk = psk.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = server_listener.accept().await.unwrap();
            serve_snell_inbound_auto(stream, server_psk, Outbound::Direct).await
        });

        let connector = Arc::new(SnellConnector::<V6ShapedMode>::new(server_addr, psk, false));
        let transport = connector.connect_udp().await.unwrap();
        drop(transport);

        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn server_relays_udp_via_socks5_outbound() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let target_addr = SocketAddr::from(([127, 0, 0, 1], 53053));

        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let proxy_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy_udp_addr = proxy_udp.local_addr().unwrap();
        let proxy = tokio::spawn(async move {
            let (stream, _) = socks_listener.accept().await.unwrap();
            serve_socks5_udp_proxy_once(stream, proxy_udp, proxy_udp_addr, target_addr)
                .await
                .unwrap();
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server_psk = psk.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = server_listener.accept().await.unwrap();
            let _ = serve_snell_inbound_auto(
                stream,
                server_psk,
                Outbound::Socks5 { server: socks_addr },
            )
            .await;
        });

        run_udp_client_round_trip::<V6ShapedMode>(server_addr, psk, Address::from(target_addr))
            .await;

        server.abort();
        let _ = server.await;
        proxy.await.unwrap();
    }

    async fn auto_server_round_trip<M>()
    where
        M: SnellMode + Send + Sync + 'static + Unpin,
        M::Encoder: Send + Unpin,
        M::Decoder: Send + Unpin,
        <M::Encoder as SnellTcpEncoder>::Reservation: Send + Unpin,
    {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server_psk = psk.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = server_listener.accept().await.unwrap();
            serve_snell_inbound_auto(stream, server_psk, Outbound::Direct)
                .await
                .unwrap();
        });

        run_client_round_trip::<M>(server_addr, psk, Address::from(target_addr)).await;

        server.await.unwrap();
        target.await.unwrap();
    }

    async fn run_client_round_trip<M>(server_addr: SocketAddr, psk: Arc<[u8]>, destination: Address)
    where
        M: SnellMode + Send + Sync + 'static + Unpin,
        M::Encoder: Send + Unpin,
        M::Decoder: Send + Unpin,
        <M::Encoder as SnellTcpEncoder>::Reservation: Send + Unpin,
    {
        let connector = Arc::new(SnellConnector::<M>::new(server_addr, psk, false));
        let transport = connector.connect(&destination).await.unwrap();

        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (local, _) = local_listener.accept().await.unwrap();
            Transport::relay(transport, local).await.unwrap();
        });

        let mut local = TcpStream::connect(local_addr).await.unwrap();
        local.write_all(b"ping").await.unwrap();
        local.shutdown().await.unwrap();
        let mut out = Vec::new();
        local.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"pong");

        relay.await.unwrap();
    }

    async fn run_udp_client_round_trip<M>(
        server_addr: SocketAddr,
        psk: Arc<[u8]>,
        destination: Address,
    ) where
        M: SnellMode + Send + Sync + 'static + Unpin,
        M::Encoder: Send + Unpin,
        M::Decoder: Send + Unpin,
        <M::Encoder as SnellTcpEncoder>::Reservation: Send + Unpin,
    {
        let connector = Arc::new(SnellConnector::<M>::new(server_addr, psk, false));
        let mut transport = connector.connect_udp().await.unwrap();

        let destination_view = destination.as_view();
        let header_len = snell::udp_request_addr_len(destination_view).unwrap();
        let mut packet = vec![0u8; header_len + 4];
        snell::encode_udp_request_addr(&mut packet, destination_view).unwrap();
        packet[header_len..].copy_from_slice(b"ping");
        transport.writer.write_frame(&packet).await.unwrap();

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            transport.reader.read_frame_vec(),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let response = snell::decode_udp_response_packet(&response).unwrap();

        assert_eq!(response.address.into_owned(), destination);
        assert_eq!(response.payload, b"pong");
    }

    async fn serve_socks5_proxy_once(
        mut inbound: TcpStream,
        target_addr: SocketAddr,
    ) -> io::Result<()> {
        let mut buf = [0u8; socks5::MAX_REQUEST_LEN];

        inbound.read_exact(&mut buf[..3]).await?;
        let ParseState::Done(greeting) = socks5::greeting_need(&buf[..3])? else {
            unreachable!("no-auth greeting is exactly 3 bytes");
        };
        assert!(greeting.supports(METHOD_NO_AUTH));

        let n = socks5::encode_method_selection(&mut buf, METHOD_NO_AUTH)?;
        inbound.write_all(&buf[..n]).await?;

        let mut filled = 0;
        loop {
            match socks5::request_need(&buf[..filled])? {
                ParseState::Done(request) => {
                    assert_eq!(request.command, Command::Connect);
                    assert_eq!(request.destination.into_owned(), Address::from(target_addr));
                    break;
                }
                ParseState::Need(total) => {
                    inbound.read_exact(&mut buf[filled..total]).await?;
                    filled = total;
                }
            }
        }

        let mut target = TcpStream::connect(target_addr).await?;
        let n = socks5::encode_reply(&mut buf, Reply::Succeeded, socks5::unspecified_ipv4_bind())?;
        inbound.write_all(&buf[..n]).await?;
        io::copy_bidirectional(&mut inbound, &mut target).await?;
        Ok(())
    }

    async fn serve_socks5_udp_proxy_once(
        mut inbound: TcpStream,
        udp: UdpSocket,
        udp_addr: SocketAddr,
        target_addr: SocketAddr,
    ) -> io::Result<()> {
        let mut buf = [0u8; socks5::MAX_REQUEST_LEN];

        inbound.read_exact(&mut buf[..3]).await?;
        let ParseState::Done(greeting) = socks5::greeting_need(&buf[..3])? else {
            unreachable!("no-auth greeting is exactly 3 bytes");
        };
        assert!(greeting.supports(METHOD_NO_AUTH));

        let n = socks5::encode_method_selection(&mut buf, METHOD_NO_AUTH)?;
        inbound.write_all(&buf[..n]).await?;

        let mut filled = 0;
        loop {
            match socks5::request_need(&buf[..filled])? {
                ParseState::Done(request) => {
                    assert_eq!(request.command, Command::UdpAssociate);
                    break;
                }
                ParseState::Need(total) => {
                    inbound.read_exact(&mut buf[filled..total]).await?;
                    filled = total;
                }
            }
        }

        let n = socks5::encode_reply(&mut buf, Reply::Succeeded, AddressRef::Ip(udp_addr))?;
        inbound.write_all(&buf[..n]).await?;

        let mut packet = [0u8; 1500];
        let (n, peer) = udp.recv_from(&mut packet).await?;
        let request = socks5::parse_udp_packet(&packet[..n])?;
        assert_eq!(request.frag, 0);
        assert_eq!(request.destination.into_owned(), Address::from(target_addr));
        assert_eq!(request.payload, b"ping");

        let header_len = socks5::udp_header_len(AddressRef::Ip(target_addr))?;
        let mut response = vec![0u8; header_len + 4];
        socks5::encode_udp_header(&mut response, 0, AddressRef::Ip(target_addr))?;
        response[header_len..].copy_from_slice(b"pong");
        udp.send_to(&response, peer).await?;
        Ok(())
    }
}

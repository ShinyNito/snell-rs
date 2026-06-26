#[cfg(windows)]
use std::net::TcpListener as StdTcpListener;
#[cfg(test)]
use std::rc::Rc;
use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::BytesMut;
use compio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpSocket, TcpStream},
    runtime, time,
};

use crate::{
    config::TcpBrutalConfig,
    keepalive::apply_tcp_keepalive,
    protocol::snell::{
        self, COMMAND_ERROR, COMMAND_TUNNEL, DecodeEvent, SnellMode, SnellTcpDecoder,
        SnellTcpEncoder, V4Decoder, V4Mode, V6ShapedDecoder, V6ShapedMode, V6UnsafeRawMode,
        V6UnshapedMode,
        version::{ProtocolVersion, V6Mode},
    },
    relay::tcp::{
        client::SnellTransport,
        driver::{SnellStreamReader, SnellStreamWriter},
        transport::{Inbound, InboundRequest, Outbound as _, copy_bidirectional},
    },
    relay::udp::{Outbound as UdpOutbound, relay_snell_udp},
    tcp_brutal::{apply_tcp_brutal, validate_tcp_brutal_available},
    timeout::{REUSE_IDLE_TIMEOUT, with_deadline},
};

pub mod outbound;
pub use outbound::Outbound;

const PROBE_BUF_LEN: usize = 4096;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub psk: Vec<u8>,
    pub protocol: Option<ProtocolVersion>,
    pub outbound: Outbound,
    pub tcp_brutal: Option<TcpBrutalConfig>,
}

pub async fn bind_tcp_listener(config: ServerConfig) -> io::Result<()> {
    validate_tcp_brutal_available(config.tcp_brutal).await?;
    let listener = bind_listener(config.listen).await?;
    serve_snell_listener(listener, config).await
}

async fn bind_listener(listen: SocketAddr) -> io::Result<TcpListener> {
    let socket = if listen.is_ipv4() {
        TcpSocket::new_v4().await?
    } else {
        TcpSocket::new_v6().await?
    };
    socket.set_reuseaddr(true)?;
    #[cfg(all(
        unix,
        not(target_os = "solaris"),
        not(target_os = "illumos"),
        not(target_os = "cygwin"),
    ))]
    socket.set_reuseport(true)?;
    socket.set_nodelay(true)?;
    socket.bind(listen).await?;
    socket.listen(4096).await
}

async fn serve_snell_listener(listener: TcpListener, config: ServerConfig) -> io::Result<()> {
    let psk: Arc<[u8]> = Arc::from(config.psk.into_boxed_slice());
    let protocol = config.protocol;
    let outbound = config.outbound;
    let tcp_brutal = config.tcp_brutal;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        if let Err(error) = apply_tcp_keepalive(&stream) {
            tracing::warn!(%peer_addr, %error, "snell inbound tcp keepalive could not be enabled");
        }
        if let Err(error) = apply_tcp_brutal(&stream, tcp_brutal) {
            tracing::warn!(%peer_addr, %error, "snell inbound tcp_brutal could not be enabled");
        }
        let psk = psk.clone();
        let outbound = outbound.clone();
        runtime::spawn(async move {
            match serve_snell_inbound(stream, psk, outbound, protocol, peer_addr).await {
                Ok(()) => tracing::info!(%peer_addr, "snell inbound ended"),
                Err(error) => tracing::info!(%peer_addr, %error, "snell inbound failed"),
            }
        })
        .detach();
    }
}

#[cfg(windows)]
pub async fn bind_tcp_listener_with_dispatcher(
    config: ServerConfig,
    dispatcher: Arc<compio::dispatcher::Dispatcher>,
) -> io::Result<()> {
    validate_tcp_brutal_available(config.tcp_brutal).await?;
    let listener = bind_std_listener(config.listen)?;
    let psk: Arc<[u8]> = Arc::from(config.psk.into_boxed_slice());
    let protocol = config.protocol;
    let outbound = config.outbound;
    let tcp_brutal = config.tcp_brutal;

    loop {
        let (stream, peer_addr) = listener.accept()?;
        let psk = psk.clone();
        let outbound = outbound.clone();
        std::mem::drop(
            dispatcher
            .dispatch(move || async move {
                let stream = match TcpStream::from_std(stream) {
                    Ok(stream) => stream,
                    Err(error) => {
                        tracing::info!(%peer_addr, %error, "snell inbound attach failed");
                        return;
                    }
                };
                if let Err(error) = apply_tcp_keepalive(&stream) {
                    tracing::warn!(%peer_addr, %error, "snell inbound tcp keepalive could not be enabled");
                }
                if let Err(error) = apply_tcp_brutal(&stream, tcp_brutal) {
                    tracing::warn!(%peer_addr, %error, "snell inbound tcp_brutal could not be enabled");
                }
                match serve_snell_inbound(stream, psk, outbound, protocol, peer_addr).await {
                    Ok(()) => tracing::info!(%peer_addr, "snell inbound ended"),
                    Err(error) => tracing::info!(%peer_addr, %error, "snell inbound failed"),
                }
            })
            .map_err(|_| io::Error::other("dispatcher workers stopped"))?,
        );
    }
}

#[cfg(windows)]
fn bind_std_listener(listen: SocketAddr) -> io::Result<StdTcpListener> {
    StdTcpListener::bind(listen)
}

async fn serve_snell_inbound(
    stream: TcpStream,
    psk: Arc<[u8]>,
    outbound: Outbound,
    protocol: Option<ProtocolVersion>,
    peer_addr: SocketAddr,
) -> io::Result<()> {
    match protocol {
        None => serve_snell_inbound_auto(stream, psk, outbound, peer_addr).await,
        Some(ProtocolVersion::V4 | ProtocolVersion::V5) => {
            serve_snell_inbound_typed::<V4Mode>(stream, psk, outbound, peer_addr).await
        }
        Some(ProtocolVersion::V6(V6Mode::Default)) => {
            serve_snell_inbound_typed::<V6ShapedMode>(stream, psk, outbound, peer_addr).await
        }
        Some(ProtocolVersion::V6(V6Mode::Unshaped)) => {
            serve_snell_inbound_typed::<V6UnshapedMode>(stream, psk, outbound, peer_addr).await
        }
        Some(ProtocolVersion::V6(V6Mode::UnsafeRaw)) => {
            serve_snell_inbound_typed::<V6UnsafeRawMode>(stream, psk, outbound, peer_addr).await
        }
    }
}

async fn serve_snell_inbound_typed<M>(
    stream: TcpStream,
    psk: Arc<[u8]>,
    outbound: Outbound,
    peer_addr: SocketAddr,
) -> io::Result<()>
where
    M: SnellMode + 'static + Unpin,
    M::Encoder: Unpin,
    M::Decoder: Unpin,
{
    let decoder = M::new_decoder(psk.clone());
    serve_snell_inbound_typed_with_decoder::<M>(stream, decoder, psk, outbound, peer_addr).await
}

async fn serve_snell_inbound_auto(
    stream: TcpStream,
    psk: Arc<[u8]>,
    outbound: Outbound,
    peer_addr: SocketAddr,
) -> io::Result<()> {
    let probed = probe_snell_mode(stream, psk.clone())
        .await
        .map_err(|error| {
            tracing::warn!(%peer_addr, %error, "snell probe failed");
            error
        })?;
    match probed {
        ProbedStream::V6Shaped { stream, decoder } => {
            serve_snell_inbound_typed_with_decoder::<V6ShapedMode>(
                stream, decoder, psk, outbound, peer_addr,
            )
            .await
        }
        ProbedStream::V4 { stream, decoder } => {
            serve_snell_inbound_typed_with_decoder::<V4Mode>(
                stream, decoder, psk, outbound, peer_addr,
            )
            .await
        }
    }
}

async fn serve_snell_inbound_typed_with_decoder<M>(
    stream: TcpStream,
    decoder: M::Decoder,
    psk: Arc<[u8]>,
    outbound: Outbound,
    peer_addr: SocketAddr,
) -> io::Result<()>
where
    M: SnellMode + 'static + Unpin,
    M::Encoder: Unpin,
    M::Decoder: Unpin,
{
    let (read_half, write_half) = stream.into_split();
    let transport: SnellTransport<M> = SnellTransport::new(
        SnellStreamReader::from_decoder(read_half, decoder),
        SnellStreamWriter::new::<M>(write_half, psk)?,
    );
    serve_snell_transport::<M>(transport, outbound, peer_addr).await
}

async fn serve_snell_transport<M>(
    transport: SnellTransport<M>,
    outbound: Outbound,
    peer_addr: SocketAddr,
) -> io::Result<()>
where
    M: SnellMode + 'static + Unpin,
    M::Encoder: Unpin,
    M::Decoder: Unpin,
{
    let mut inbound = SnellInbound::new(transport);

    let first = inbound.receive_snell().await?;
    if let SnellInboundRequest::Udp = first {
        tracing::info!(%peer_addr, "snell UDP setup received");
        let target = match UdpOutbound::connect_udp(&outbound).await {
            Ok(target) => target,
            Err(error) => {
                tracing::debug!(%peer_addr, %error, "snell UDP outbound connect failed");
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
                // 官方 v6：reuse 等下一条 S0 的 idle timer（1h，日志
                // "Connection idle before handshake"）。上一条 sub-stream 的双向
                // EOF（copy_bidirectional 要求收发两侧均关闭）结束后回到此处，若客户端在 1h
                // 内不发下一条 `01 05 ...`，服务端主动关闭，避免连接永久挂起。
                let request = with_deadline(
                    REUSE_IDLE_TIMEOUT,
                    Inbound::receive(&mut inbound),
                    "snell reuse idle",
                )
                .await?;
                snell::ConnectRequest {
                    destination: request.destination,
                    reuse: request.reuse,
                }
            }
        };
        tracing::info!(%peer_addr, destination = %request.destination, reuse = request.reuse, "snell CONNECT received");

        let target = match outbound.connect(&request.destination).await {
            Ok(target) => target,
            Err(error) => {
                tracing::debug!(%peer_addr, destination = %request.destination, %error, "outbound connect failed");
                inbound.reject(&error).await?;
                return Err(error);
            }
        };
        inbound.accept().await?;

        inbound = SnellInbound::new(copy_bidirectional(inbound.into_transport(), target).await?);
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
    reader: &mut SnellStreamReader<R, D>,
) -> io::Result<SnellInboundRequest>
where
    R: AsyncRead + Unpin + 'static,
    D: SnellTcpDecoder,
{
    let mut head = [0u8; 3];
    reader.read_exact_plain(&mut head).await?;

    if head[1] == snell::COMMAND_UDP {
        snell::read_udp_setup_request_with_head(reader, head).await?;
        return Ok(SnellInboundRequest::Udp);
    }

    snell::read_connect_request_with_head(reader, head)
        .await
        .map(SnellInboundRequest::Connect)
}

async fn write_server_error<W, E>(
    writer: &mut SnellStreamWriter<W, E>,
    code: u8,
    message: &str,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin + 'static,
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

    async fn receive_snell(&mut self) -> io::Result<SnellInboundRequest> {
        read_snell_request(&mut self.transport.reader).await
    }
}

impl<M> Inbound for SnellInbound<M>
where
    M: SnellMode,
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

enum ProbedStream {
    V6Shaped {
        stream: TcpStream,
        decoder: V6ShapedDecoder,
    },
    V4 {
        stream: TcpStream,
        decoder: V4Decoder,
    },
}

async fn probe_snell_mode(mut stream: TcpStream, psk: Arc<[u8]>) -> io::Result<ProbedStream> {
    time::timeout(PROBE_TIMEOUT, async {
        let mut acc = BytesMut::new();
        let mut v6 = ProbeCandidate::new(V6ShapedMode::new_decoder(psk.clone()));
        let mut v4 = ProbeCandidate::new(V4Mode::new_decoder(psk));
        loop {
            let (result, buf) = stream
                .read(BytesMut::with_capacity(PROBE_BUF_LEN))
                .await
                .into_parts();
            let n = result?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell probe early eof",
                ));
            }
            acc.extend_from_slice(&buf[..n]);

            if v6.possible {
                match v6.probe(&acc) {
                    ProbeResult::Match { .. } => {
                        let ProbeCandidate { decoder, .. } = v6;
                        return Ok(ProbedStream::V6Shaped { stream, decoder });
                    }
                    ProbeResult::NeedMore => {}
                    ProbeResult::Invalid => {}
                }
            }

            if v4.possible {
                match v4.probe(&acc) {
                    ProbeResult::Match { .. } => {
                        let ProbeCandidate { decoder, .. } = v4;
                        return Ok(ProbedStream::V4 { stream, decoder });
                    }
                    ProbeResult::NeedMore => {}
                    ProbeResult::Invalid => {}
                }
            }

            if !v6.possible && !v4.possible {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snell probe could not detect v6-default or v4/v5",
                ));
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "snell probe timed out"))?
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeResult {
    Match { consumed: usize },
    NeedMore,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbePlaintext {
    Match,
    NeedMore,
    Invalid,
}

struct ProbeCandidate<D> {
    decoder: D,
    consumed: usize,
    possible: bool,
}

impl<D> ProbeCandidate<D> {
    fn new(decoder: D) -> Self {
        Self {
            decoder,
            consumed: 0,
            possible: true,
        }
    }
}

impl<D> ProbeCandidate<D>
where
    D: SnellTcpDecoder,
{
    fn probe(&mut self, bytes: &[u8]) -> ProbeResult {
        if !self.decoder.pending_plain().is_empty() {
            return self.probe_pending_plaintext();
        }

        if self.consumed == bytes.len() {
            return ProbeResult::NeedMore;
        }

        let chunk = BytesMut::from(&bytes[self.consumed..]);
        self.consumed = bytes.len();
        match self.decoder.feed_owned(chunk) {
            Ok(DecodeEvent::PlainData) => self.probe_pending_plaintext(),
            Ok(DecodeEvent::NeedMore) => ProbeResult::NeedMore,
            Ok(DecodeEvent::ZeroChunk) | Err(_) => self.invalid(),
            Ok(_) => ProbeResult::NeedMore,
        }
    }

    fn probe_pending_plaintext(&mut self) -> ProbeResult {
        match probe_control_plaintext(self.decoder.pending_plain()) {
            ProbePlaintext::Match | ProbePlaintext::NeedMore => ProbeResult::Match {
                consumed: self.consumed,
            },
            ProbePlaintext::Invalid => self.invalid(),
        }
    }

    fn invalid(&mut self) -> ProbeResult {
        self.possible = false;
        ProbeResult::Invalid
    }
}

#[cfg(test)]
fn probe_mode<M>(psk: Arc<[u8]>, bytes: &[u8]) -> ProbeResult
where
    M: SnellMode,
{
    ProbeCandidate::new(M::new_decoder(psk)).probe(bytes)
}

fn probe_control_plaintext(buf: &[u8]) -> ProbePlaintext {
    if buf.is_empty() {
        return ProbePlaintext::NeedMore;
    }
    if buf[0] != snell::PROTOCOL_VERSION {
        return ProbePlaintext::Invalid;
    }
    if buf.len() == 1 {
        return ProbePlaintext::NeedMore;
    }

    match buf[1] {
        snell::COMMAND_CONNECT | snell::COMMAND_CONNECT_V2 => {
            probe_control_prefix(snell::decode_connect_request_prefix(buf).map(|_| ()))
                .unwrap_or(ProbePlaintext::Invalid)
        }
        snell::COMMAND_UDP => {
            probe_control_prefix(snell::decode_udp_setup_request_prefix(buf).map(|_| ()))
                .unwrap_or(ProbePlaintext::Invalid)
        }
        _ => ProbePlaintext::Invalid,
    }
}

fn probe_control_prefix(result: io::Result<()>) -> Option<ProbePlaintext> {
    match result {
        Ok(()) => Some(ProbePlaintext::Match),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Some(ProbePlaintext::NeedMore)
        }
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
    use std::io;

    fn flatten_wire(wire: Vec<bytes::Bytes>) -> Vec<u8> {
        let mut out = Vec::new();
        for s in wire {
            out.extend_from_slice(&s);
        }
        out
    }

    use compio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket},
        runtime, time,
    };

    fn encode_v6_shaped_connect_and_payload(
        psk: &[u8],
        destination: AddressRef<'_>,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut encoder = V6ShapedMode::new_encoder(psk).unwrap();
        let mut wire = Vec::new();

        let request_len = snell::connect_request_len(destination).unwrap();
        let mut request = BytesMut::with_capacity(request_len);
        request.resize(request_len, 0);
        let n = snell::encode_connect_request_into(&mut request, destination, false).unwrap();
        request.truncate(n);
        wire.extend_from_slice(&flatten_wire(encoder.seal_plain(request).unwrap()));

        wire.extend_from_slice(&flatten_wire(
            encoder.seal_plain(BytesMut::from(payload)).unwrap(),
        ));

        wire
    }

    #[compio::test]
    async fn auto_server_accepts_v4_v5_tcp_codec() {
        auto_server_round_trip::<V4Mode>().await;
    }

    #[compio::test]
    async fn auto_server_accepts_v6_default() {
        auto_server_round_trip::<V6ShapedMode>().await;
    }

    #[compio::test(with_proactor(
        buffer_pool_size = std::num::NonZero::<u16>::new(32).expect("nonzero buffer pool size"),
        buffer_pool_buffer_len = 64 * 1024
    ))]
    async fn server_relays_large_tcp_upload() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let total = 32 * 1024 * 1024;

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target = runtime::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut received = 0;
            let mut buf = [0u8; 64 * 1024];
            while received < total {
                let n = read_once(&mut stream, &mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received += n;
            }
            received
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server_psk = psk.clone();
        let server = runtime::spawn(async move {
            let (stream, peer_addr) = server_listener.accept().await.unwrap();
            serve_snell_inbound_auto(stream, server_psk, Outbound::Direct, peer_addr)
                .await
                .unwrap();
        });

        let connector = Rc::new(SnellConnector::<V6ShapedMode>::new(server_addr, psk, false));
        let transport = connector
            .connect(&Address::from(target_addr))
            .await
            .unwrap();
        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();
        let relay = runtime::spawn(async move {
            let (local, _) = local_listener.accept().await.unwrap();
            copy_bidirectional(transport, local).await.unwrap();
        });

        let mut local = TcpStream::connect(local_addr).await.unwrap();
        let chunk = vec![0x5a; 64 * 1024];
        let mut sent = 0;
        while sent < total {
            write_all_bytes(&mut local, &chunk).await.unwrap();
            sent += chunk.len();
        }
        local.shutdown().await.unwrap();

        let received = time::timeout(std::time::Duration::from_secs(5), target)
            .await
            .unwrap()
            .unwrap();
        relay.await.unwrap();
        server.await.unwrap();
        assert_eq!(received, total);
    }

    #[test]
    fn v6_probe_accepts_client_id_and_coalesced_payload() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let plaintext = b"\x01\x05\x03abc\x0bexample.com\x01\xbbhello";
        let mut encoder = V6ShapedMode::new_encoder(psk.as_ref()).unwrap();
        let wire = flatten_wire(encoder.seal_plain(BytesMut::from(&plaintext[..])).unwrap());

        assert_eq!(
            probe_mode::<V6ShapedMode>(psk, &wire),
            ProbeResult::Match {
                consumed: wire.len()
            }
        );
    }

    #[test]
    fn v6_probe_accepts_coalesced_records() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let destination = Address::domain("example.com", 443).unwrap();
        let wire =
            encode_v6_shaped_connect_and_payload(psk.as_ref(), destination.as_view(), b"ping");

        let ProbeResult::Match { .. } = probe_mode::<V6ShapedMode>(psk, &wire) else {
            panic!("probe should match v6 shaped connect request");
        };
    }

    #[test]
    fn v6_probe_accepts_udp_setup() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let plaintext = [snell::PROTOCOL_VERSION, snell::COMMAND_UDP, 0];
        let mut encoder = V6ShapedMode::new_encoder(psk.as_ref()).unwrap();
        let wire = flatten_wire(encoder.seal_plain(BytesMut::from(&plaintext[..])).unwrap());

        assert_eq!(
            probe_mode::<V6ShapedMode>(psk, &wire),
            ProbeResult::Match {
                consumed: wire.len()
            }
        );
    }

    #[test]
    fn probe_plaintext_accepts_large_coalesced_payload() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let destination = Address::domain("example.com", 443).unwrap();

        let mut encoder = V4Mode::new_encoder(psk.as_ref()).unwrap();
        let request_len = snell::connect_request_len(destination.as_view()).unwrap();
        let payload_len = encoder.next_plain_capacity() - request_len;
        let mut plaintext = BytesMut::with_capacity(request_len + payload_len);
        plaintext.resize(request_len, 0);
        let n = snell::encode_connect_request_into(&mut plaintext, destination.as_view(), false)
            .unwrap();
        plaintext.truncate(n);
        plaintext.resize(plaintext.len() + payload_len, b'x');

        let wire = flatten_wire(encoder.seal_plain(plaintext.clone()).unwrap());

        assert_eq!(
            probe_mode::<V4Mode>(psk, &wire),
            ProbeResult::Match {
                consumed: wire.len()
            }
        );
    }

    #[test]
    fn probe_streaming_split_reads_v6_shaped() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let plaintext = b"\x01\x05\x03abc\x0bexample.com\x01\xbbhello";
        let mut encoder = V6ShapedMode::new_encoder(psk.as_ref()).unwrap();
        let wire = flatten_wire(encoder.seal_plain(BytesMut::from(&plaintext[..])).unwrap());

        let split_points = [1, 5, 16, 30, wire.len() / 2, wire.len()];
        let mut acc = Vec::new();
        let mut candidate = ProbeCandidate::new(V6ShapedMode::new_decoder(psk));
        let mut prev = 0;
        for &end in split_points.iter().filter(|&&e| e > 0 && e <= wire.len()) {
            if end <= prev {
                continue;
            }
            acc.extend_from_slice(&wire[prev..end]);
            let result = candidate.probe(&acc);
            match result {
                ProbeResult::Match { .. } => return,
                ProbeResult::NeedMore => {}
                ProbeResult::Invalid => {
                    panic!(
                        "probe marked Invalid after accumulated split {prev}..{end} (wire len {})",
                        wire.len()
                    );
                }
            }
            prev = end;
        }
        panic!(
            "probe never matched across split reads; wire len {}",
            wire.len()
        );
    }

    #[compio::test]
    async fn probe_snell_mode_accepts_split_v6_salt_block() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_psk = psk.clone();
        let server = runtime::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            match probe_snell_mode(stream, server_psk).await.unwrap() {
                ProbedStream::V6Shaped { .. } => {}
                ProbedStream::V4 { .. } => panic!("split v6 probe matched v4"),
            }
        });

        let destination = Address::domain("example.com", 443).unwrap();
        let wire =
            encode_v6_shaped_connect_and_payload(psk.as_ref(), destination.as_view(), b"ping");
        let mut client = TcpStream::connect(addr).await.unwrap();
        write_all_bytes(&mut client, &wire[..8]).await.unwrap();
        time::sleep(std::time::Duration::from_millis(10)).await;
        write_all_bytes(&mut client, &wire[8..]).await.unwrap();

        time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[compio::test]
    async fn probe_accepts_connect_split_across_v6_records() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let destination = Address::domain("example.com", 443).unwrap();

        let request_len = snell::connect_request_len(destination.as_view()).unwrap();
        let mut request = BytesMut::with_capacity(request_len);
        request.resize(request_len, 0);
        let n =
            snell::encode_connect_request_into(&mut request, destination.as_view(), false).unwrap();
        request.truncate(n);

        let mut encoder = V6ShapedMode::new_encoder(psk.as_ref()).unwrap();
        let mut wire = Vec::new();
        let split = 5;
        wire.extend_from_slice(&flatten_wire(
            encoder.seal_plain(request[..split].into()).unwrap(),
        ));

        let mut rest = BytesMut::from(&request[split..]);
        rest.extend_from_slice(b"ping");
        wire.extend_from_slice(&flatten_wire(encoder.seal_plain(rest).unwrap()));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_psk = psk.clone();
        let server = runtime::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let ProbedStream::V6Shaped { stream, decoder } =
                probe_snell_mode(stream, server_psk).await.unwrap()
            else {
                panic!("split v6 probe matched v4");
            };

            let (read_half, _) = stream.into_split();
            let mut reader = SnellStreamReader::from_decoder(read_half, decoder);
            let request = read_snell_request(&mut reader).await.unwrap();
            let SnellInboundRequest::Connect(request) = request else {
                panic!("split connect probe returned udp request");
            };
            assert_eq!(request.destination, destination);
            assert!(!request.reuse);

            let batch = std::future::poll_fn(|cx| reader.poll_read_frame_batch(cx))
                .await
                .unwrap()
                .expect("coalesced payload");
            let mut frames = batch.into_frames();
            let payload = frames.next().expect("coalesced payload frame");
            assert!(frames.next().is_none());
            assert_eq!(payload.as_ref(), b"ping");
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        write_all_bytes(&mut client, &wire).await.unwrap();

        time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[compio::test]
    async fn auto_probe_preserves_coalesced_ciphertext_after_connect() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target = runtime::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            read_exact_into(&mut stream, &mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server_psk = psk.clone();
        let server = runtime::spawn(async move {
            let (stream, peer_addr) = server_listener.accept().await.unwrap();
            let _ = serve_snell_inbound_auto(stream, server_psk, Outbound::Direct, peer_addr).await;
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let wire = encode_v6_shaped_connect_and_payload(
            psk.as_ref(),
            AddressRef::Ip(target_addr),
            b"ping",
        );
        write_all_bytes(&mut client, &wire).await.unwrap();

        time::timeout(std::time::Duration::from_secs(5), target)
            .await
            .unwrap()
            .unwrap();
        drop(client);
        drop(server);
    }

    #[compio::test]
    async fn server_uses_socks5_outbound() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target = runtime::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            read_exact_into(&mut stream, &mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            write_all_bytes(&mut stream, b"pong").await.unwrap();
        });

        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let proxy = runtime::spawn(async move {
            let (stream, _) = socks_listener.accept().await.unwrap();
            serve_socks5_proxy_once(stream, target_addr).await.unwrap();
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server_psk = psk.clone();
        let server = runtime::spawn(async move {
            let (stream, peer_addr) = server_listener.accept().await.unwrap();
            serve_snell_inbound_auto(
                stream,
                server_psk,
                Outbound::Socks5 { server: socks_addr },
                peer_addr,
            )
            .await
            .unwrap();
        });

        run_client_round_trip::<V6ShapedMode>(server_addr, psk, Address::from(target_addr)).await;

        server.await.unwrap();
        proxy.await.unwrap();
        target.await.unwrap();
    }

    #[compio::test]
    async fn explicit_v6_unshaped_server_bypasses_probe() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target = runtime::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            read_exact_into(&mut stream, &mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            write_all_bytes(&mut stream, b"pong").await.unwrap();
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server_psk = psk.clone();
        let server = runtime::spawn(async move {
            let (stream, peer_addr) = server_listener.accept().await.unwrap();
            serve_snell_inbound(
                stream,
                server_psk,
                Outbound::Direct,
                Some(ProtocolVersion::V6(V6Mode::Unshaped)),
                peer_addr,
            )
            .await
            .unwrap();
        });

        run_client_round_trip::<V6UnshapedMode>(server_addr, psk, Address::from(target_addr)).await;

        target.await.unwrap();
        server.await.unwrap();
    }

    /// reuse 完成一条 sub-stream 后，客户端若不再发下一条 S0，服务端必须在
    /// `REUSE_IDLE_TIMEOUT`（1h）后主动关闭。用 `start_paused` 虚拟时钟，避免
    /// 真实等待 1h。注意：客户端 connector 必须保持 pool 里的连接活着（不要
    /// drop），否则服务端 read 会先 EOF 而不是 idle 超时。
    #[compio::test]
    #[ignore = "compio time has no paused-clock equivalent for the 1h reuse idle timeout"]
    async fn reuse_idle_times_out_when_no_next_s0_arrives() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target = runtime::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            read_exact_into(&mut stream, &mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            write_all_bytes(&mut stream, b"pong").await.unwrap();
            // 等客户端关 → sub-stream 双向 EOF（copy_bidirectional 要求两侧都关）。
            let mut tail = [0u8; 1];
            assert_eq!(read_once(&mut stream, &mut tail).await.unwrap(), 0);
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server_psk = psk.clone();
        let server = runtime::spawn(async move {
            let (stream, peer_addr) = server_listener.accept().await.unwrap();
            serve_snell_inbound_auto(stream, server_psk, Outbound::Direct, peer_addr).await
        });

        // reuse connector：跑一条 sub-stream（CONNECT → ping/pong → 双向 EOF）。
        // relay 结束后 transport 被归还到客户端 pool，socket 保持打开。
        let connector = Rc::new(SnellConnector::<V4Mode>::new(server_addr, psk, true));
        run_client_round_trip_with_connector(&connector, &Address::from(target_addr)).await;
        target.await.unwrap();

        // 服务端此刻挂在 reuse loop 的 `with_deadline(REUSE_IDLE_TIMEOUT, receive)`。
        // paused 运行时无就绪 IO，自动快进到 1h idle timer，返回 TimedOut。
        let result = server.await.unwrap();
        let err = result.unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::TimedOut,
            "reuse idle should time out, got: {err}"
        );
    }

    #[compio::test]
    async fn server_closes_socks5_connect_before_next_reused_substream() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target = runtime::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = target_listener.accept().await.unwrap();
                let mut buf = [0u8; 4];
                read_exact_into(&mut stream, &mut buf).await.unwrap();
                assert_eq!(&buf, b"ping");
                write_all_bytes(&mut stream, b"pong").await.unwrap();
            }
        });

        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let proxy = runtime::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = socks_listener.accept().await.unwrap();
                serve_socks5_proxy_once(stream, target_addr).await.unwrap();
            }
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server_psk = psk.clone();
        let server = runtime::spawn(async move {
            let (stream, peer_addr) = server_listener.accept().await.unwrap();
            let _ = serve_snell_inbound_auto(
                stream,
                server_psk,
                Outbound::Socks5 { server: socks_addr },
                peer_addr,
            )
            .await;
        });

        let connector = Rc::new(SnellConnector::<V6ShapedMode>::new(server_addr, psk, true));
        for _ in 0..2 {
            run_client_round_trip_with_connector(&connector, &Address::from(target_addr)).await;
        }

        time::timeout(std::time::Duration::from_secs(5), proxy)
            .await
            .unwrap()
            .unwrap();
        target.await.unwrap();
        drop(connector);
        drop(server);
    }

    #[compio::test]
    async fn server_relays_udp_direct() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);

        let target_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_socket.local_addr().unwrap();
        let target = runtime::spawn(async move {
            let mut buf = [0u8; 64];
            let (n, peer) = udp_recv_from(&target_socket, &mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping");
            udp_send_to(&target_socket, b"pong", peer).await.unwrap();
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server_psk = psk.clone();
        let server = runtime::spawn(async move {
            let (stream, peer_addr) = server_listener.accept().await.unwrap();
            let _ = serve_snell_inbound_auto(stream, server_psk, Outbound::Direct, peer_addr).await;
        });

        run_udp_client_round_trip::<V6ShapedMode>(server_addr, psk, Address::from(target_addr))
            .await;

        drop(server);
        target.await.unwrap();
    }

    #[compio::test]
    async fn server_treats_udp_carrier_close_as_normal() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);

        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server_psk = psk.clone();
        let server = runtime::spawn(async move {
            let (stream, peer_addr) = server_listener.accept().await.unwrap();
            serve_snell_inbound_auto(stream, server_psk, Outbound::Direct, peer_addr).await
        });

        let connector = Rc::new(SnellConnector::<V6ShapedMode>::new(server_addr, psk, false));
        let transport = connector.connect_udp().await.unwrap();
        drop(transport);

        time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[compio::test]
    async fn server_relays_udp_via_socks5_outbound() {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);
        let target_addr = SocketAddr::from(([127, 0, 0, 1], 53053));

        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let proxy_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy_udp_addr = proxy_udp.local_addr().unwrap();
        let proxy = runtime::spawn(async move {
            let (stream, _) = socks_listener.accept().await.unwrap();
            serve_socks5_udp_proxy_once(stream, proxy_udp, proxy_udp_addr, target_addr)
                .await
                .unwrap();
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server_psk = psk.clone();
        let server = runtime::spawn(async move {
            let (stream, peer_addr) = server_listener.accept().await.unwrap();
            let _ = serve_snell_inbound_auto(
                stream,
                server_psk,
                Outbound::Socks5 { server: socks_addr },
                peer_addr,
            )
            .await;
        });

        run_udp_client_round_trip::<V6ShapedMode>(server_addr, psk, Address::from(target_addr))
            .await;

        drop(server);
        proxy.await.unwrap();
    }

    async fn auto_server_round_trip<M>()
    where
        M: SnellMode + 'static + Unpin,
        M::Encoder: Unpin,
        M::Decoder: Unpin,
    {
        let psk: Arc<[u8]> = Arc::from(&b"0123456789abcdef"[..]);

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target = runtime::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            read_exact_into(&mut stream, &mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            write_all_bytes(&mut stream, b"pong").await.unwrap();
        });

        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server_psk = psk.clone();
        let server = runtime::spawn(async move {
            let (stream, peer_addr) = server_listener.accept().await.unwrap();
            serve_snell_inbound_auto(stream, server_psk, Outbound::Direct, peer_addr)
                .await
                .unwrap();
        });

        run_client_round_trip::<M>(server_addr, psk, Address::from(target_addr)).await;

        server.await.unwrap();
        target.await.unwrap();
    }

    async fn run_client_round_trip<M>(server_addr: SocketAddr, psk: Arc<[u8]>, destination: Address)
    where
        M: SnellMode + 'static + Unpin,
        M::Encoder: Unpin,
        M::Decoder: Unpin,
    {
        let connector = Rc::new(SnellConnector::<M>::new(server_addr, psk, false));
        run_client_round_trip_with_connector(&connector, &destination).await;
    }

    async fn run_client_round_trip_with_connector<M>(
        connector: &Rc<SnellConnector<M>>,
        destination: &Address,
    ) where
        M: SnellMode + 'static + Unpin,
        M::Encoder: Unpin,
        M::Decoder: Unpin,
    {
        let transport = connector.connect(destination).await.unwrap();

        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();
        let relay = runtime::spawn(async move {
            let (local, _) = local_listener.accept().await.unwrap();
            copy_bidirectional(transport, local).await.unwrap();
        });

        let mut local = TcpStream::connect(local_addr).await.unwrap();
        write_all_bytes(&mut local, b"ping").await.unwrap();
        local.shutdown().await.unwrap();
        let out = read_to_end_vec(&mut local).await.unwrap();
        assert_eq!(out, b"pong");

        relay.await.unwrap();
    }

    async fn run_udp_client_round_trip<M>(
        server_addr: SocketAddr,
        psk: Arc<[u8]>,
        destination: Address,
    ) where
        M: SnellMode + 'static + Unpin,
        M::Encoder: Unpin,
        M::Decoder: Unpin,
    {
        let connector = Rc::new(SnellConnector::<M>::new(server_addr, psk, false));
        let mut transport = connector.connect_udp().await.unwrap();

        let destination_view = destination.as_view();
        let header_len = snell::udp_request_addr_len(destination_view).unwrap();
        let mut packet = vec![0u8; header_len + 4];
        snell::encode_udp_request_addr(&mut packet, destination_view).unwrap();
        packet[header_len..].copy_from_slice(b"ping");
        transport.writer.write_frame(&packet).await.unwrap();

        let response = time::timeout(std::time::Duration::from_secs(2), async {
            let batch = std::future::poll_fn(|cx| transport.reader.poll_read_frame_batch(cx))
                .await?
                .expect("snell udp response frame");
            let mut frames = batch.into_frames();
            let response = frames.next().expect("snell udp response frame");
            assert!(frames.next().is_none());
            io::Result::Ok(response)
        })
        .await
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

        read_exact_into(&mut inbound, &mut buf[..3]).await?;
        let ParseState::Done(greeting) = socks5::greeting_need(&buf[..3])? else {
            unreachable!("no-auth greeting is exactly 3 bytes");
        };
        assert!(greeting.supports(METHOD_NO_AUTH));

        let n = socks5::encode_method_selection(&mut buf, METHOD_NO_AUTH)?;
        write_all_bytes(&mut inbound, &buf[..n]).await?;

        let mut filled = 0;
        loop {
            match socks5::request_need(&buf[..filled])? {
                ParseState::Done(request) => {
                    assert_eq!(request.command, Command::Connect);
                    assert_eq!(request.destination.into_owned(), Address::from(target_addr));
                    break;
                }
                ParseState::Need(total) => {
                    read_exact_into(&mut inbound, &mut buf[filled..total]).await?;
                    filled = total;
                }
            }
        }

        let mut target = TcpStream::connect(target_addr).await?;
        let n = socks5::encode_reply(&mut buf, Reply::Succeeded, socks5::unspecified_ipv4_bind())?;
        write_all_bytes(&mut inbound, &buf[..n]).await?;
        let mut request = [0u8; 1024];
        let n = read_once(&mut inbound, &mut request).await?;
        if n != 0 {
            write_all_bytes(&mut target, &request[..n]).await?;
            target.shutdown().await?;
        }
        let response = read_to_end_vec(&mut target).await?;
        write_all_bytes(&mut inbound, &response).await?;
        inbound.shutdown().await?;
        Ok(())
    }

    async fn serve_socks5_udp_proxy_once(
        mut inbound: TcpStream,
        udp: UdpSocket,
        udp_addr: SocketAddr,
        target_addr: SocketAddr,
    ) -> io::Result<()> {
        let mut buf = [0u8; socks5::MAX_REQUEST_LEN];

        read_exact_into(&mut inbound, &mut buf[..3]).await?;
        let ParseState::Done(greeting) = socks5::greeting_need(&buf[..3])? else {
            unreachable!("no-auth greeting is exactly 3 bytes");
        };
        assert!(greeting.supports(METHOD_NO_AUTH));

        let n = socks5::encode_method_selection(&mut buf, METHOD_NO_AUTH)?;
        write_all_bytes(&mut inbound, &buf[..n]).await?;

        let mut filled = 0;
        loop {
            match socks5::request_need(&buf[..filled])? {
                ParseState::Done(request) => {
                    assert_eq!(request.command, Command::UdpAssociate);
                    break;
                }
                ParseState::Need(total) => {
                    read_exact_into(&mut inbound, &mut buf[filled..total]).await?;
                    filled = total;
                }
            }
        }

        let n = socks5::encode_reply(&mut buf, Reply::Succeeded, AddressRef::Ip(udp_addr))?;
        write_all_bytes(&mut inbound, &buf[..n]).await?;

        let mut packet = [0u8; 1500];
        let (n, peer) = udp_recv_from(&udp, &mut packet).await?;
        let request = socks5::parse_udp_packet(&packet[..n])?;
        assert_eq!(request.frag, 0);
        assert_eq!(request.destination.into_owned(), Address::from(target_addr));
        assert_eq!(request.payload, b"ping");

        let header_len = socks5::udp_header_len(AddressRef::Ip(target_addr))?;
        let mut response = vec![0u8; header_len + 4];
        socks5::encode_udp_header(&mut response, 0, AddressRef::Ip(target_addr))?;
        response[header_len..].copy_from_slice(b"pong");
        udp_send_to(&udp, &response, peer).await?;
        Ok(())
    }

    async fn read_exact_into<R>(reader: &mut R, dst: &mut [u8]) -> io::Result<()>
    where
        R: AsyncRead + 'static,
    {
        let (result, buf) = reader
            .read_exact(Vec::with_capacity(dst.len()))
            .await
            .into_parts();
        result?;
        dst.copy_from_slice(&buf);
        Ok(())
    }

    async fn read_once<R>(reader: &mut R, dst: &mut [u8]) -> io::Result<usize>
    where
        R: AsyncRead + 'static,
    {
        let (result, buf) = reader
            .read(Vec::with_capacity(dst.len()))
            .await
            .into_parts();
        let n = result?;
        dst[..n].copy_from_slice(&buf[..n]);
        Ok(n)
    }

    async fn read_to_end_vec<R>(reader: &mut R) -> io::Result<Vec<u8>>
    where
        R: AsyncRead + 'static,
    {
        let (result, buf) = reader.read_to_end(Vec::new()).await.into_parts();
        result?;
        Ok(buf)
    }

    async fn write_all_bytes<W>(writer: &mut W, bytes: &[u8]) -> io::Result<()>
    where
        W: AsyncWrite + 'static,
    {
        let (result, _buf) = writer.write_all(bytes.to_vec()).await.into_parts();
        result
    }

    async fn udp_recv_from(socket: &UdpSocket, dst: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (result, buf) = socket
            .recv_from(Vec::with_capacity(dst.len()))
            .await
            .into_parts();
        let (n, peer) = result?;
        dst[..n].copy_from_slice(&buf[..n]);
        Ok((n, peer))
    }

    async fn udp_send_to(socket: &UdpSocket, payload: &[u8], peer: SocketAddr) -> io::Result<()> {
        let len = payload.len();
        let (result, _payload) = socket.send_to(payload.to_vec(), peer).await.into_parts();
        if result? != len {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "udp socket sent a partial datagram",
            ));
        }
        Ok(())
    }
}

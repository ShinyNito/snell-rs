use std::io::{self, IoSlice};
use std::net::SocketAddr;

use socket2::{SockAddr, SockRef};
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// Send borrowed header and payload as one datagram without a repack buffer.
pub(crate) async fn send_udp_parts(
    socket: &UdpSocket,
    peer: SocketAddr,
    header: &[u8],
    payload: &[u8],
) -> io::Result<()> {
    let bufs = [IoSlice::new(header), IoSlice::new(payload)];
    let address = SockAddr::from(peer);
    let socket_ref = SockRef::from(socket);
    loop {
        match socket
            .async_io(Interest::WRITABLE, || {
                socket_ref.send_to_vectored(&bufs, &address)
            })
            .await
        {
            Ok(n) if n == header.len() + payload.len() => return Ok(()),
            Ok(_) => return Err(io::Error::new(io::ErrorKind::WriteZero, "short UDP send")),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

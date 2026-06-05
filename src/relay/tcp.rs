use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::error::Result;
use crate::transport::tcp_stream::{TcpClientWriter, TcpReader, TcpServerWriter};

pub(crate) async fn relay_tcp_reader_to_plain<R, W>(
    snell: &mut TcpReader<R>,
    plain: &mut W,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0;

    loop {
        let n = match snell.read_payload_chunk().await? {
            Some(payload) => {
                let n = payload.len();
                plain.write_all(payload).await?;
                n
            }
            None => {
                plain.shutdown().await?;
                return Ok(total);
            }
        };
        snell.consume_payload_chunk(n);
        total += n as u64;
    }
}

macro_rules! define_plain_to_snell_writer_relay {
    ($fn_name:ident, $writer:ident) => {
        pub(crate) async fn $fn_name<R, W>(plain: &mut R, snell: &mut $writer<W>) -> Result<u64>
        where
            R: AsyncRead + Unpin,
            W: AsyncWrite + Unpin,
        {
            let mut total = 0;

            loop {
                match snell.write_payload_from_reader(plain).await? {
                    Some(n) => total += n as u64,
                    None => {
                        snell.close_write().await?;
                        return Ok(total);
                    }
                }
            }
        }
    };
}

define_plain_to_snell_writer_relay!(relay_plain_to_server_writer, TcpServerWriter);
define_plain_to_snell_writer_relay!(relay_plain_to_client_writer, TcpClientWriter);

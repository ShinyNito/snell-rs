use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::error::Result;
use crate::session::reuse::{ReuseClientReader, ReuseClientWriter};
use crate::session::tcp::{TcpClientWriter, TcpReader};

macro_rules! define_snell_reader_to_plain_relay {
    ($fn_vis:vis $fn_name:ident, $counted_vis:vis $counted_fn_name:ident, $reader:ident) => {
        $fn_vis async fn $fn_name<R, W>(snell: &mut $reader<R>, plain: &mut W) -> Result<u64>
        where
            R: AsyncRead + Unpin,
            W: AsyncWrite + Unpin,
        {
            let mut total = 0;
            $counted_fn_name(snell, plain, &mut total).await?;
            Ok(total)
        }

        $counted_vis async fn $counted_fn_name<R, W>(
            snell: &mut $reader<R>,
            plain: &mut W,
            total: &mut u64,
        ) -> Result<()>
        where
            R: AsyncRead + Unpin,
            W: AsyncWrite + Unpin,
        {
            loop {
                match snell.take_payload_chunk().await? {
                    Some(payload) => {
                        let n = payload.len();
                        plain.write_all(&payload).await?;
                        *total += n as u64;
                    }
                    None => {
                        plain.shutdown().await?;
                        return Ok(());
                    }
                };
            }
        }
    };
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
                match snell.write_next_payload_record_from_reader(plain).await? {
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

define_snell_reader_to_plain_relay!(
    pub(crate) relay_tcp_reader_to_plain,
    pub(crate) relay_tcp_reader_to_plain_counted,
    TcpReader
);
define_snell_reader_to_plain_relay!(
    pub(crate) relay_reuse_client_reader_to_plain,
    relay_reuse_client_reader_to_plain_counted,
    ReuseClientReader
);
define_plain_to_snell_writer_relay!(relay_plain_to_client_writer, TcpClientWriter);
define_plain_to_snell_writer_relay!(relay_plain_to_reuse_client_writer, ReuseClientWriter);

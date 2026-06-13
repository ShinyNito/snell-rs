use std::sync::Arc;

use tokio::net::TcpStream;

use crate::error::Result;
use crate::proxy::outbound::RelayStats;
use crate::proxy::outbound::snell::{ReusePool, ReusedSnellTcp, SnellTcpConnect};
use crate::session::reuse::ReuseClientConn;
use crate::session::tcp::relay::{
    PlainUploadBatch, relay_plain_to_client_writer, relay_plain_to_reuse_client_writer,
    relay_tcp_reader_to_plain,
};

pub(crate) async fn relay_tcp_connect(
    local: TcpStream,
    connect: SnellTcpConnect,
) -> Result<RelayStats> {
    match connect {
        SnellTcpConnect::Fresh(server) => {
            let (mut server_reader, mut server_writer) = server.into_split();
            let (mut local_reader, mut local_writer) = local.into_split();
            let mut downloaded = 0;

            let (uploaded, ()) = tokio::try_join!(
                relay_plain_to_client_writer(&mut local_reader, &mut server_writer),
                relay_tcp_reader_to_plain(
                    &mut server_reader,
                    &mut local_writer,
                    &mut downloaded,
                    PlainUploadBatch::new(),
                ),
            )?;

            Ok(RelayStats {
                uploaded,
                downloaded,
            })
        }
        SnellTcpConnect::Reused { conn, pool } => {
            relay_reuse_client_connection(local, conn, pool).await
        }
    }
}

async fn relay_reuse_client_connection(
    local: TcpStream,
    snell: ReusedSnellTcp,
    pool: Arc<ReusePool>,
) -> Result<RelayStats> {
    let (mut snell_reader, mut snell_writer) = snell.into_split();
    let (mut local_reader, mut local_writer) = local.into_split();
    let mut downloaded = 0;

    let result = tokio::try_join!(
        relay_plain_to_reuse_client_writer(&mut local_reader, &mut snell_writer),
        relay_tcp_reader_to_plain(
            &mut snell_reader,
            &mut local_writer,
            &mut downloaded,
            PlainUploadBatch::new(),
        ),
    );

    match result {
        Ok((uploaded, ())) => {
            pool.put(ReuseClientConn::from_split(snell_reader, snell_writer))
                .await;
            Ok(RelayStats {
                uploaded,
                downloaded,
            })
        }
        Err(err) => Err(err),
    }
}

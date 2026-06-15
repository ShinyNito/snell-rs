use std::future::Future;

use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::Duration;
use tokio::time::Instant;

use crate::error::{Error, Result};
use crate::proxy::outbound::RelayStats;
use crate::proxy::outbound::snell::SnellTcpConnect;
use crate::relay::activity::{RelayActivity, RelayActivityTimeouts, wait_relay_idle};
use crate::relay::tcp::{TcpClosePolicy, TcpRelayDriver};

const CLIENT_TCP_RELAY_IDLE_TIMEOUT: Duration = Duration::from_hours(1);
const CLIENT_TCP_ACTIVITY_TIMEOUTS: RelayActivityTimeouts =
    RelayActivityTimeouts::new(CLIENT_TCP_RELAY_IDLE_TIMEOUT, CLIENT_TCP_RELAY_IDLE_TIMEOUT);

pub(crate) async fn relay_tcp_connect(
    local: TcpStream,
    connect: SnellTcpConnect,
) -> Result<RelayStats> {
    let (activity, last_activity) = RelayActivity::new();
    let relay = relay_opened_tcp_connect(local, connect, &activity);
    relay_client_tcp_with_idle_timeout(relay, last_activity).await
}

async fn relay_opened_tcp_connect(
    local: TcpStream,
    connect: SnellTcpConnect,
    activity: &RelayActivity,
) -> Result<RelayStats> {
    match connect {
        SnellTcpConnect::Fresh(server) => {
            let relay = TcpRelayDriver::new(
                local,
                server,
                TcpClosePolicy::BothDirectionsClosed,
                activity.clone(),
            );
            tokio::pin!(relay);
            relay.as_mut().await
        }
        SnellTcpConnect::Reused { conn, pool } => {
            let local = local;
            tokio::pin!(local);
            let mut conn = Box::into_pin(conn);
            let stats = {
                let relay = TcpRelayDriver::new(
                    local.as_mut(),
                    conn.as_mut(),
                    TcpClosePolicy::BothDirectionsClosed,
                    activity.clone(),
                );
                tokio::pin!(relay);
                relay.as_mut().await?
            };
            let conn = std::pin::Pin::into_inner(conn);
            pool.put(conn);
            Ok(stats)
        }
    }
}

async fn relay_client_tcp_with_idle_timeout<F>(
    relay: F,
    last_activity: watch::Receiver<Instant>,
) -> Result<RelayStats>
where
    F: Future<Output = Result<RelayStats>>,
{
    tokio::pin!(relay);

    tokio::select! {
        result = &mut relay => result,
        () = wait_relay_idle(last_activity, CLIENT_TCP_ACTIVITY_TIMEOUTS) => {
            tracing::debug!(
                idle_timeout_ms = CLIENT_TCP_ACTIVITY_TIMEOUTS.idle.as_millis(),
                "snell tcp client relay idle timed out"
            );
            Err(Error::SnellClientTcpIdleTimeout)
        }
    }
}

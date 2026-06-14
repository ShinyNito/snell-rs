use tokio::net::TcpListener;
use tokio::task::JoinSet;

use crate::error::Result;
use crate::net::tcp_brutal::apply_tcp_brutal;
use crate::proxy::snell::server::{
    SERVER_TCP_ACTIVITY_TIMEOUTS, open_tcp_target, serve_server_connection,
};
use crate::server::shutdown::{drain_connection_tasks, log_connection_task_result};

use crate::server::TcpServerRuntime;

pub(crate) async fn serve_tcp_listeners_with_shutdown_and_timeout(
    listeners: Vec<TcpListener>,
    runtime: TcpServerRuntime,
) -> Result<()> {
    if listeners.len() <= 1 {
        if let Some(listener) = listeners.into_iter().next() {
            return serve_tcp_listener_with_shutdown_and_timeout(listener, runtime).await;
        }
        return Ok(());
    }

    let mut tasks = JoinSet::new();
    let shutdown = runtime.shutdown.clone();
    for listener in listeners {
        tasks.spawn(serve_tcp_listener_with_shutdown_and_timeout(
            listener,
            runtime.clone(),
        ));
    }

    let mut first_error = None;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                shutdown.cancel();
                first_error.get_or_insert(err);
            }
            Err(err) => {
                shutdown.cancel();
                first_error.get_or_insert_with(|| err.into());
            }
        }
    }

    if let Some(err) = first_error {
        Err(err)
    } else {
        Ok(())
    }
}

pub(crate) async fn serve_tcp_listener_with_shutdown_and_timeout(
    listener: TcpListener,
    runtime: TcpServerRuntime,
) -> Result<()> {
    let TcpServerRuntime {
        secret,
        options,
        tcp_brutal,
        v6_salt_replay_cache,
        shutdown,
        drain_timeout,
    } = runtime;
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            result = listener.accept() => {
                let (client, peer_addr) = result?;
                let secret = secret.clone();
                let options = options.clone();
                let v6_salt_replay_cache = v6_salt_replay_cache.clone();
                tasks.spawn(async move {
                    if let Err(err) = apply_tcp_brutal(&client, tcp_brutal) {
                        tracing::warn!(%err, %peer_addr, "snell tcp_brutal could not be enabled");
                        return;
                    }
                    let result = serve_server_connection(
                        client,
                        secret,
                        options,
                        v6_salt_replay_cache,
                        open_tcp_target,
                        SERVER_TCP_ACTIVITY_TIMEOUTS,
                    )
                    .await;
                    if let Err(err) = result {
                        tracing::debug!(%err, %peer_addr, "snell tcp server connection failed");
                    }
                });
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                log_connection_task_result(result);
            }
        }
    }
    drop(listener);

    drain_connection_tasks(tasks, drain_timeout).await;
    Ok(())
}

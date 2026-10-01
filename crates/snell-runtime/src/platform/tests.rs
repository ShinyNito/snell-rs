use std::time::{Duration, Instant};

use snell_protocol::{TCP_KEEPALIVE_IDLE_SECS, TCP_KEEPALIVE_INTERVAL_SECS};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time;

#[cfg(not(miri))]
use super::accept::{ACCEPT_BACKOFF_MIN, AcceptLoop, emfile_error};
use super::{
    PlatformError, apply_keepalive, read_keepalive, read_tcp_fastopen_connect,
    read_tcp_fastopen_listener, set_tcp_fastopen_connect, set_tcp_fastopen_listener,
};

#[cfg(not(miri))]
async fn connected_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
    let (server, _) = listener.accept().await.unwrap();
    (server, client.await.unwrap())
}

#[tokio::test]
#[cfg(not(miri))]
async fn keepalive_sets_idle_300_interval_75() {
    let (stream, _peer) = connected_pair().await;
    apply_keepalive(&stream).unwrap();
    let got = read_keepalive(&stream).expect("keepalive must be readable");
    assert!(got.enabled, "SO_KEEPALIVE must be on");
    assert_eq!(got.idle, Duration::from_secs(TCP_KEEPALIVE_IDLE_SECS));
    assert_eq!(
        got.interval,
        Duration::from_secs(TCP_KEEPALIVE_INTERVAL_SECS)
    );
}

#[test]
fn tfo_listener_supported_path_sets_option_or_unsupported() {
    let socket = TcpSocket::new_v4().unwrap();
    match set_tcp_fastopen_listener(&socket) {
        Ok(()) => {
            let value = read_tcp_fastopen_listener(&socket).expect("TFO was set");
            assert!(value > 0, "TFO claimed enabled but option is {value}");
        }
        Err(PlatformError::Unsupported(_)) => {}
        Err(error) => panic!("TFO must set the option or return Unsupported, got {error}"),
    }
}

#[test]
fn tfo_connect_supported_path_sets_option_or_unsupported() {
    let socket = TcpSocket::new_v4().unwrap();
    match set_tcp_fastopen_connect(&socket) {
        Ok(()) => {
            let value = read_tcp_fastopen_connect(&socket).expect("TFO connect was set");
            assert!(
                value > 0,
                "TFO connect claimed enabled but option is {value}"
            );
        }
        Err(PlatformError::Unsupported(_)) => {}
        Err(error) => panic!("TFO connect must set the option or return Unsupported, got {error}"),
    }
}

#[tokio::test]
#[cfg(not(miri))]
async fn accept_backs_off_on_emfile_and_keeps_serving() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut accept = AcceptLoop::new(&listener);
    accept.inject.push_back(emfile_error());
    accept.inject.push_back(emfile_error());
    let connector = tokio::spawn(async move { TcpStream::connect(addr).await });
    let started = Instant::now();
    let (stream, _) = time::timeout(Duration::from_secs(2), accept.next())
        .await
        .expect("accept loop must stay up")
        .expect("accept after EMFILE");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= ACCEPT_BACKOFF_MIN * 3,
        "backoff sleeps missing: {elapsed:?}"
    );
    assert!(stream.peer_addr().is_ok());
    connector.await.unwrap().unwrap();

    accept
        .inject
        .push_back(std::io::Error::other("listener broken"));
    assert!(accept.next().await.is_err(), "fatal errors end the loop");
}

//! Inline Argon2id vs spawn_blocking vs dedicated threads vs inflight caps.
//!
//! Run: `cargo bench -p snell-runtime --bench kdf_bound`

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use snell_protocol::{Psk, aead_key};
use tokio::sync::Semaphore;

const PSK: &[u8] = b"0123456789abcdef";
const ROUNDS: usize = 32;

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(run());
}

async fn run() {
    let psk = Psk::new(PSK.to_vec()).unwrap();
    let salt = [7u8; 16];

    for _ in 0..2 {
        let _ = aead_key(psk.as_bytes(), &salt).unwrap();
    }

    let inline_started = Instant::now();
    for i in 0..ROUNDS {
        let mut s = salt;
        s[0] = i as u8;
        let _ = aead_key(psk.as_bytes(), &s).unwrap();
    }
    let inline_elapsed = inline_started.elapsed();

    for _ in 0..2 {
        let psk_bytes = psk.as_bytes().to_vec();
        let _ = tokio::task::spawn_blocking(move || aead_key(&psk_bytes, &salt))
            .await
            .unwrap()
            .unwrap();
    }

    let spawn_started = Instant::now();
    for i in 0..ROUNDS {
        let mut s = salt;
        s[0] = i as u8;
        let psk_bytes = psk.as_bytes().to_vec();
        let _ = tokio::task::spawn_blocking(move || aead_key(&psk_bytes, &s))
            .await
            .unwrap()
            .unwrap();
    }
    let spawn_elapsed = spawn_started.elapsed();

    let dedicated_elapsed = dedicated_serial(&psk, salt);

    let concurrent_unlimited = concurrent_spawn(ROUNDS, ROUNDS, &psk, salt).await;
    let concurrent_8 = concurrent_spawn(8, ROUNDS, &psk, salt).await;
    let concurrent_1 = concurrent_spawn(1, ROUNDS, &psk, salt).await;
    let dedicated_8 = dedicated_pool(8, ROUNDS, &psk, salt);

    eprintln!(
        "kdf scheduling, Argon2id m=8KiB t=3 p=1 rounds={ROUNDS}\n\
         sequential inline: elapsed={inline_elapsed:?}\n\
         sequential spawn_blocking: elapsed={spawn_elapsed:?}\n\
         sequential dedicated thread: elapsed={dedicated_elapsed:?}\n\
         concurrent spawn_blocking inflight=32: elapsed={concurrent_unlimited:?}\n\
         concurrent spawn_blocking inflight=8: elapsed={concurrent_8:?}\n\
         concurrent spawn_blocking inflight=1: elapsed={concurrent_1:?}\n\
         concurrent dedicated pool threads=8 queue=32: elapsed={dedicated_8:?}"
    );
}

fn dedicated_serial(psk: &Psk, salt: [u8; 16]) -> std::time::Duration {
    let psk_bytes = psk.as_bytes().to_vec();
    let (tx, rx) = std::sync::mpsc::sync_channel::<([u8; 16], std::sync::mpsc::SyncSender<()>)>(32);
    let worker = thread::spawn(move || {
        while let Ok((s, done)) = rx.recv() {
            let _ = aead_key(&psk_bytes, &s).unwrap();
            let _ = done.send(());
        }
    });
    let start = Instant::now();
    for i in 0..ROUNDS {
        let mut s = salt;
        s[0] = i as u8;
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        tx.send((s, done_tx)).unwrap();
        done_rx.recv().unwrap();
    }
    drop(tx);
    worker.join().unwrap();
    start.elapsed()
}

fn dedicated_pool(threads: usize, tasks: usize, psk: &Psk, salt: [u8; 16]) -> std::time::Duration {
    let psk_bytes = Arc::new(psk.as_bytes().to_vec());
    let (tx, rx) = std::sync::mpsc::sync_channel::<([u8; 16], std::sync::mpsc::SyncSender<()>)>(32);
    let rx = Arc::new(Mutex::new(rx));
    let mut joins = Vec::with_capacity(threads);
    for _ in 0..threads {
        let rx = rx.clone();
        let psk_bytes = psk_bytes.clone();
        joins.push(thread::spawn(move || {
            loop {
                let job = rx.lock().unwrap().recv();
                match job {
                    Ok((s, done)) => {
                        let _ = aead_key(&psk_bytes, &s).unwrap();
                        let _ = done.send(());
                    }
                    Err(_) => break,
                }
            }
        }));
    }
    let start = Instant::now();
    let mut dones = Vec::with_capacity(tasks);
    for i in 0..tasks {
        let mut s = salt;
        s[0] = i as u8;
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        tx.send((s, done_tx)).unwrap();
        dones.push(done_rx);
    }
    for done in dones {
        done.recv().unwrap();
    }
    drop(tx);
    for join in joins {
        join.join().unwrap();
    }
    start.elapsed()
}

async fn concurrent_spawn(
    inflight: usize,
    tasks: usize,
    psk: &Psk,
    salt: [u8; 16],
) -> std::time::Duration {
    let sem = Arc::new(Semaphore::new(inflight));
    let start = Instant::now();
    let mut joins = Vec::with_capacity(tasks);
    for i in 0..tasks {
        let sem = sem.clone();
        let psk_bytes = psk.as_bytes().to_vec();
        let mut s = salt;
        s[0] = i as u8;
        joins.push(tokio::spawn(async move {
            let permit = sem.acquire_owned().await.unwrap();
            let out = tokio::task::spawn_blocking(move || aead_key(&psk_bytes, &s))
                .await
                .unwrap()
                .unwrap();
            drop(permit);
            out
        }));
    }
    for join in joins {
        let _ = join.await.unwrap();
    }
    start.elapsed()
}

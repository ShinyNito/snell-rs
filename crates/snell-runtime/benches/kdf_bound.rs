//! Inline Argon2id vs spawn_blocking. No performance claim; raw numbers only.
//!
//! Run: `cargo bench -p snell-runtime --bench kdf_bound`

use std::time::Instant;

use snell_protocol::{Psk, aead_key};

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

    eprintln!(
        "kdf bound comparison, Argon2id m=8KiB t=3 p=1\n\
         rounds={ROUNDS}\n\
         inline: elapsed={inline_elapsed:?}\n\
         spawn_blocking: elapsed={spawn_elapsed:?}"
    );
}

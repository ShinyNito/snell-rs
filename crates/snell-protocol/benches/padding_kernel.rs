//! Swap / popcount kernel microbench: scalar vs u64.
//!
//! Run: `cargo bench -p snell-protocol --bench padding_kernel`

use std::hint::black_box;
use std::time::Instant;

fn swap_scalar(padding: &mut [u8], payload_cipher: &mut [u8]) {
    let limit = padding.len().min(payload_cipher.len());
    for i in (0..limit).step_by(2) {
        core::mem::swap(&mut padding[i], &mut payload_cipher[i]);
    }
}

fn swap_u64(padding: &mut [u8], payload_cipher: &mut [u8]) {
    const MASK: u64 = u64::from_ne_bytes([0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0]);
    let limit = padding.len().min(payload_cipher.len());
    let padding = &mut padding[..limit];
    let payload_cipher = &mut payload_cipher[..limit];
    let (p_chunks, p_tail) = padding.as_chunks_mut::<8>();
    let (c_chunks, c_tail) = payload_cipher.as_chunks_mut::<8>();
    for (p, c) in p_chunks.iter_mut().zip(c_chunks) {
        let a = u64::from_ne_bytes(*p);
        let b = u64::from_ne_bytes(*c);
        let diff = (a ^ b) & MASK;
        *p = (a ^ diff).to_ne_bytes();
        *c = (b ^ diff).to_ne_bytes();
    }
    for i in (0..p_tail.len()).step_by(2) {
        core::mem::swap(&mut p_tail[i], &mut c_tail[i]);
    }
}

fn count_ones_scalar(bytes: &[u8]) -> usize {
    bytes[..bytes.len() & !3]
        .iter()
        .map(|byte| byte.count_ones() as usize)
        .sum()
}

fn count_ones_u64(bytes: &[u8]) -> usize {
    let slice = &bytes[..bytes.len() & !3];
    let (chunks, remainder) = slice.as_chunks::<8>();
    let mut total = chunks
        .iter()
        .map(|chunk| u64::from_ne_bytes(*chunk).count_ones() as usize)
        .sum::<usize>();
    for &byte in remainder {
        total += byte.count_ones() as usize;
    }
    total
}

fn time_swap(label: &str, rounds: usize, n: usize, mut body: impl FnMut(&mut [u8], &mut [u8])) {
    let mut padding = vec![0xA5u8; n];
    let mut cipher = vec![0x5Au8; n];
    body(&mut padding, &mut cipher);
    let start = Instant::now();
    for _ in 0..rounds {
        body(black_box(&mut padding), black_box(&mut cipher));
    }
    black_box((&padding, &cipher));
    eprintln!("swap {label} n={n} rounds={rounds} {:?}", start.elapsed());
}

fn time_ones(label: &str, rounds: usize, n: usize, mut body: impl FnMut(&[u8]) -> usize) {
    let bytes = vec![0xA5u8; n];
    let _ = body(&bytes);
    let start = Instant::now();
    let mut acc = 0usize;
    for _ in 0..rounds {
        acc ^= body(black_box(&bytes));
    }
    black_box(acc);
    eprintln!("ones {label} n={n} rounds={rounds} {:?}", start.elapsed());
}

fn main() {
    let n = 16383usize;
    let rounds = 50_000usize;

    let mut a = vec![1u8; n];
    let mut b = vec![2u8; n];
    let mut a2 = a.clone();
    let mut b2 = b.clone();
    swap_scalar(&mut a, &mut b);
    swap_u64(&mut a2, &mut b2);
    assert_eq!(a, a2);
    let ones = count_ones_scalar(&a);
    assert_eq!(ones, count_ones_u64(&a));

    time_swap("scalar", rounds, n, swap_scalar);
    time_swap("u64", rounds, n, swap_u64);

    time_ones("scalar", rounds, n, count_ones_scalar);
    time_ones("u64", rounds, n, count_ones_u64);
}

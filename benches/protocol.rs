use std::hint::black_box;
use std::time::Duration;

use bytes::BytesMut;
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use snell_rs::MAX_PACKET_SIZE;
use snell_rs::protocol::crypto::{AES_128_KEY_SIZE, Aes128GcmCrypto, SALT_SIZE, derive_aes128_key};
use snell_rs::protocol::frame_v4::{
    V4_HEADER_CIPHER_SIZE, V4FrameDecoder, V4FrameEncoder, split_salt,
};

const PSK: &[u8] = b"benchmark psk";
const SALT: [u8; SALT_SIZE] = [7; SALT_SIZE];
const INITIAL_PADDING_LEN: usize = 0x100;
const PAYLOAD_SIZES: [usize; 4] = [64, 1024, 8192, MAX_PACKET_SIZE];

fn benchmark_crypto(c: &mut Criterion) {
    c.bench_function("crypto/derive_aes128_key", |b| {
        b.iter(|| derive_aes128_key(black_box(PSK), black_box(&SALT)).unwrap());
    });

    let mut group = c.benchmark_group("crypto/aes128_gcm");
    let crypto = Aes128GcmCrypto::new([3; AES_128_KEY_SIZE]);
    let nonce = [9; 12];

    for size in PAYLOAD_SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("encrypt", size), &size, |b, &size| {
            b.iter_batched(
                || vec![0x42; size],
                |mut payload| {
                    let tag = crypto.encrypt_detached(&nonce, &mut payload).unwrap();
                    black_box(tag);
                    black_box(payload);
                },
                BatchSize::SmallInput,
            );
        });
        group.bench_with_input(BenchmarkId::new("decrypt", size), &size, |b, &size| {
            b.iter_batched(
                || {
                    let mut payload = vec![0x42; size];
                    let tag = crypto.encrypt_detached(&nonce, &mut payload).unwrap();
                    payload.extend_from_slice(&tag);
                    payload
                },
                |mut payload| {
                    let plaintext = crypto.decrypt_within(&nonce, &mut payload, 0..).unwrap();
                    black_box(plaintext.len());
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn benchmark_v4_frame_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol/v4_frame_encode");

    for size in PAYLOAD_SIZES {
        let payload = vec![0x42; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("first_frame", size), &size, |b, _| {
            b.iter_batched(
                || {
                    (
                        V4FrameEncoder::with_salt_and_initial_padding(
                            PSK,
                            SALT,
                            INITIAL_PADDING_LEN,
                        )
                        .unwrap(),
                        BytesMut::with_capacity(MAX_PACKET_SIZE + 512),
                    )
                },
                |(mut encoder, mut out)| {
                    let written = encoder.encode_frame(black_box(&payload), &mut out).unwrap();
                    black_box(written);
                    black_box(out);
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("steady_frame", size), &size, |b, _| {
            let mut encoder =
                V4FrameEncoder::with_salt_and_initial_padding(PSK, SALT, INITIAL_PADDING_LEN)
                    .unwrap();
            let mut out = BytesMut::with_capacity(MAX_PACKET_SIZE + 512);
            encoder.encode_frame(&[], &mut out).unwrap();
            b.iter(|| {
                out.clear();
                let written = encoder.encode_frame(black_box(&payload), &mut out).unwrap();
                black_box(written);
                black_box(out.len());
            });
        });
    }
    group.finish();
}

fn benchmark_v4_frame_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol/v4_frame_decode");

    for size in PAYLOAD_SIZES {
        let payload = vec![0x42; size];
        let first = first_frame(&payload);
        let steady = steady_frame(&payload);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("first_frame", size), &size, |b, _| {
            b.iter_batched(
                || {
                    let decoder = V4FrameDecoder::new(PSK, first.salt).unwrap();
                    let header = first.header;
                    let body = first.body.clone();
                    (decoder, header, body)
                },
                |(mut decoder, mut header, mut body)| {
                    let decoded = decoder.decode_header(&mut header).unwrap();
                    let payload = decoder.decode_payload_in_place(decoded, &mut body).unwrap();
                    black_box(payload.len());
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("steady_frame", size), &size, |b, _| {
            b.iter_batched(
                || {
                    let mut decoder = V4FrameDecoder::new(PSK, steady.salt).unwrap();
                    let mut warm_header = steady.warmup.header;
                    let mut warm_body = steady.warmup.body.clone();
                    let warm_decoded = decoder.decode_header(&mut warm_header).unwrap();
                    decoder
                        .decode_payload_in_place(warm_decoded, &mut warm_body)
                        .unwrap();

                    let header = steady.measured.header;
                    let body = steady.measured.body.clone();
                    (decoder, header, body)
                },
                |(mut decoder, mut header, mut body)| {
                    let decoded = decoder.decode_header(&mut header).unwrap();
                    let payload = decoder.decode_payload_in_place(decoded, &mut body).unwrap();
                    black_box(payload.len());
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

#[derive(Clone)]
struct FrameParts {
    salt: [u8; SALT_SIZE],
    header: [u8; V4_HEADER_CIPHER_SIZE],
    body: Vec<u8>,
}

struct SteadyFrame {
    salt: [u8; SALT_SIZE],
    warmup: FrameParts,
    measured: FrameParts,
}

fn first_frame(payload: &[u8]) -> FrameParts {
    let mut encoder =
        V4FrameEncoder::with_salt_and_initial_padding(PSK, SALT, INITIAL_PADDING_LEN).unwrap();
    let mut wire = BytesMut::new();
    encoder.encode_frame(payload, &mut wire).unwrap();

    let (salt, frame) = split_salt(&wire).unwrap();
    let (header, body) = split_frame(frame);
    FrameParts { salt, header, body }
}

fn steady_frame(payload: &[u8]) -> SteadyFrame {
    let mut encoder =
        V4FrameEncoder::with_salt_and_initial_padding(PSK, SALT, INITIAL_PADDING_LEN).unwrap();
    let mut warmup_wire = BytesMut::new();
    encoder.encode_frame(payload, &mut warmup_wire).unwrap();
    let (salt, warmup_frame) = split_salt(&warmup_wire).unwrap();
    let (warmup_header, warmup_body) = split_frame(warmup_frame);

    let mut measured_wire = BytesMut::new();
    encoder.encode_frame(payload, &mut measured_wire).unwrap();
    let (measured_header, measured_body) = split_frame(&measured_wire);

    SteadyFrame {
        salt,
        warmup: FrameParts {
            salt,
            header: warmup_header,
            body: warmup_body,
        },
        measured: FrameParts {
            salt,
            header: measured_header,
            body: measured_body,
        },
    }
}

fn split_frame(frame: &[u8]) -> ([u8; V4_HEADER_CIPHER_SIZE], Vec<u8>) {
    let mut header = [0; V4_HEADER_CIPHER_SIZE];
    header.copy_from_slice(&frame[..V4_HEADER_CIPHER_SIZE]);
    let body = frame[V4_HEADER_CIPHER_SIZE..].to_vec();
    (header, body)
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(4))
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = benchmark_crypto, benchmark_v4_frame_encode, benchmark_v4_frame_decode
}
criterion_main!(benches);

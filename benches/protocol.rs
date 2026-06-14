use std::hint::black_box;
use std::time::Duration;

use bytes::BytesMut;
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use snell_rs::MAX_PACKET_SIZE;
use snell_rs::protocol::crypto::{AES_128_KEY_SIZE, Aes128GcmCrypto, SALT_SIZE, derive_aes128_key};
use snell_rs::protocol::v4::frame::{V4_HEADER_CIPHER_SIZE, V4FrameDecoder, V4FrameEncoder};
use snell_rs::protocol::v6::{V6_HEADER_CIPHER_SIZE, V6FrameDecoder, V6FrameEncoder, V6Profile};

const PSK: &[u8] = b"benchmark psk";
const SALT: [u8; SALT_SIZE] = [7; SALT_SIZE];
const PAYLOAD_SIZES: [usize; 4] = [64, 1024, 8192, MAX_PACKET_SIZE];

fn encode_frame_in_place(
    encoder: &mut V4FrameEncoder,
    payload: &[u8],
    out: &mut BytesMut,
) -> usize {
    let start_len = out.len();
    let mut head = BytesMut::new();
    if payload.is_empty() {
        encoder.encode_empty_frame(&mut head).unwrap();
        out.extend_from_slice(&head);
    } else {
        let mut body = BytesMut::from(payload);
        encoder
            .encode_payload_in_place(&mut body, payload.len(), &mut head)
            .unwrap();
        out.extend_from_slice(&head);
        out.extend_from_slice(&body);
    }
    out.len() - start_len
}

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
                        V4FrameEncoder::new(PSK).unwrap(),
                        BytesMut::with_capacity(512),
                        BytesMut::from(payload.as_slice()),
                    )
                },
                |(mut encoder, mut head, mut body)| {
                    let payload_len = body.len();
                    let written = encoder
                        .encode_payload_in_place(black_box(&mut body), payload_len, &mut head)
                        .unwrap();
                    black_box(written);
                    black_box(head);
                    black_box(body);
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("steady_frame", size), &size, |b, _| {
            let mut encoder = V4FrameEncoder::new(PSK).unwrap();
            let mut head = BytesMut::with_capacity(512);
            encoder.encode_empty_frame(&mut head).unwrap();
            b.iter_batched(
                || BytesMut::from(payload.as_slice()),
                |mut body| {
                    head.clear();
                    let payload_len = body.len();
                    let written = encoder
                        .encode_payload_in_place(black_box(&mut body), payload_len, &mut head)
                        .unwrap();
                    black_box(written);
                    black_box(head.len() + body.len());
                },
                BatchSize::SmallInput,
            );
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

fn benchmark_v6_frame_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol/v6_frame_encode");

    for size in PAYLOAD_SIZES {
        let payload = vec![0x42; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("first_frame", size), &size, |b, _| {
            let profile = V6Profile::derive(PSK);
            b.iter_batched(
                || {
                    (
                        V6FrameEncoder::new(PSK).unwrap(),
                        BytesMut::with_capacity(2048),
                        BytesMut::from(payload.as_slice()),
                    )
                },
                |(mut encoder, mut head, mut body)| {
                    let payload_len = body.len();
                    let written = encoder
                        .encode_payload_in_place(
                            black_box(&profile),
                            black_box(&mut body),
                            payload_len,
                            &mut head,
                        )
                        .unwrap();
                    black_box(written);
                    black_box(head);
                    black_box(body);
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("steady_frame", size), &size, |b, _| {
            let profile = V6Profile::derive(PSK);
            let mut encoder = V6FrameEncoder::new(PSK).unwrap();
            let mut head = BytesMut::with_capacity(2048);
            let mut body = BytesMut::from(payload.as_slice());
            encoder
                .encode_payload_in_place(&profile, &mut body, payload.len(), &mut head)
                .unwrap();

            b.iter_batched(
                || BytesMut::from(payload.as_slice()),
                |mut body| {
                    head.clear();
                    let payload_len = body.len();
                    let written = encoder
                        .encode_payload_in_place(
                            black_box(&profile),
                            black_box(&mut body),
                            payload_len,
                            &mut head,
                        )
                        .unwrap();
                    black_box(written);
                    black_box(head.len() + body.len());
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn benchmark_v6_frame_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol/v6_frame_decode");

    for size in PAYLOAD_SIZES {
        let payload = vec![0x42; size];
        let first = v6_first_frame(&payload);
        let steady = v6_steady_frame(&payload);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("first_frame", size), &size, |b, _| {
            b.iter_batched(
                || {
                    let decoder = V6FrameDecoder::new(PSK, first.salt).unwrap();
                    let prefix = first.prefix.clone();
                    let header = first.header;
                    let body = first.body.clone();
                    (decoder, prefix, header, body)
                },
                |(mut decoder, prefix, mut header, mut body)| {
                    let decoded = decoder.decode_header(&prefix, &mut header).unwrap();
                    let payload = decoder
                        .decode_payload_in_place(&first.profile, decoded, &mut body)
                        .unwrap();
                    black_box(payload.len());
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("steady_frame", size), &size, |b, _| {
            b.iter_batched(
                || {
                    let mut decoder = V6FrameDecoder::new(PSK, steady.salt).unwrap();
                    let mut warm_header = steady.warmup.header;
                    let mut warm_body = steady.warmup.body.clone();
                    let warm_decoded = decoder
                        .decode_header(&steady.warmup.prefix, &mut warm_header)
                        .unwrap();
                    decoder
                        .decode_payload_in_place(&steady.profile, warm_decoded, &mut warm_body)
                        .unwrap();

                    let prefix = steady.measured.prefix.clone();
                    let header = steady.measured.header;
                    let body = steady.measured.body.clone();
                    (decoder, prefix, header, body)
                },
                |(mut decoder, prefix, mut header, mut body)| {
                    let decoded = decoder.decode_header(&prefix, &mut header).unwrap();
                    let payload = decoder
                        .decode_payload_in_place(&steady.profile, decoded, &mut body)
                        .unwrap();
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

#[derive(Clone)]
struct V6FrameParts {
    salt: [u8; SALT_SIZE],
    profile: V6Profile,
    prefix: Vec<u8>,
    header: [u8; V6_HEADER_CIPHER_SIZE],
    body: Vec<u8>,
}

struct V6SteadyFrame {
    salt: [u8; SALT_SIZE],
    profile: V6Profile,
    warmup: V6FrameParts,
    measured: V6FrameParts,
}

fn first_frame(payload: &[u8]) -> FrameParts {
    let mut encoder = V4FrameEncoder::new(PSK).unwrap();
    let mut wire = BytesMut::new();
    encode_frame_in_place(&mut encoder, payload, &mut wire);

    let (salt, frame) = split_v4_salt(&wire);
    let (header, body) = split_frame(frame);
    FrameParts { salt, header, body }
}

fn steady_frame(payload: &[u8]) -> SteadyFrame {
    let mut encoder = V4FrameEncoder::new(PSK).unwrap();
    let mut warmup_wire = BytesMut::new();
    encode_frame_in_place(&mut encoder, payload, &mut warmup_wire);
    let (salt, warmup_frame) = split_v4_salt(&warmup_wire);
    let (warmup_header, warmup_body) = split_frame(warmup_frame);

    let mut measured_wire = BytesMut::new();
    encode_frame_in_place(&mut encoder, payload, &mut measured_wire);
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

fn encode_v6_frame_in_place(
    profile: &V6Profile,
    encoder: &mut V6FrameEncoder,
    payload: &[u8],
    out: &mut BytesMut,
) -> usize {
    let start_len = out.len();
    let mut head = BytesMut::new();
    let mut body = BytesMut::from(payload);
    encoder
        .encode_payload_in_place(profile, &mut body, payload.len(), &mut head)
        .unwrap();
    out.extend_from_slice(&head);
    out.extend_from_slice(&body);
    out.len() - start_len
}

fn v6_first_frame(payload: &[u8]) -> V6FrameParts {
    let profile = V6Profile::derive(PSK);
    let mut encoder = V6FrameEncoder::new(PSK).unwrap();
    let mut wire = BytesMut::new();
    encode_v6_frame_in_place(&profile, &mut encoder, payload, &mut wire);

    let (salt, frame) = split_v6_salt_block(&profile, &wire);
    let (prefix, header, body) = split_v6_frame(frame, profile.record_prefix_len(0));
    V6FrameParts {
        salt,
        profile,
        prefix,
        header,
        body,
    }
}

fn v6_steady_frame(payload: &[u8]) -> V6SteadyFrame {
    let mut encoder = V6FrameEncoder::new(PSK).unwrap();
    let profile = V6Profile::derive(PSK);

    let mut warmup_wire = BytesMut::new();
    encode_v6_frame_in_place(&profile, &mut encoder, payload, &mut warmup_wire);
    let (salt, warmup_frame) = split_v6_salt_block(&profile, &warmup_wire);
    let (warmup_prefix, warmup_header, warmup_body) =
        split_v6_frame(warmup_frame, profile.record_prefix_len(0));

    let mut measured_wire = BytesMut::new();
    encode_v6_frame_in_place(&profile, &mut encoder, payload, &mut measured_wire);
    let (measured_prefix, measured_header, measured_body) =
        split_v6_frame(&measured_wire, profile.record_prefix_len(1));

    V6SteadyFrame {
        salt,
        profile: profile.clone(),
        warmup: V6FrameParts {
            salt,
            profile: profile.clone(),
            prefix: warmup_prefix,
            header: warmup_header,
            body: warmup_body,
        },
        measured: V6FrameParts {
            salt,
            profile,
            prefix: measured_prefix,
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

fn split_v4_salt(frame: &[u8]) -> ([u8; SALT_SIZE], &[u8]) {
    let mut salt = [0; SALT_SIZE];
    salt.copy_from_slice(&frame[..SALT_SIZE]);
    (salt, &frame[SALT_SIZE..])
}

fn split_v6_frame(
    frame: &[u8],
    prefix_len: usize,
) -> (Vec<u8>, [u8; V6_HEADER_CIPHER_SIZE], Vec<u8>) {
    let prefix = frame[..prefix_len].to_vec();
    let mut header = [0; V6_HEADER_CIPHER_SIZE];
    header.copy_from_slice(&frame[prefix_len..prefix_len + V6_HEADER_CIPHER_SIZE]);
    let body = frame[prefix_len + V6_HEADER_CIPHER_SIZE..].to_vec();
    (prefix, header, body)
}

fn split_v6_salt_block<'a>(profile: &V6Profile, frame: &'a [u8]) -> ([u8; SALT_SIZE], &'a [u8]) {
    let salt_block_len = profile.salt_block_len();
    let salt = profile.extract_salt(&frame[..salt_block_len]).unwrap();
    (salt, &frame[salt_block_len..])
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(4))
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = benchmark_crypto, benchmark_v4_frame_encode, benchmark_v4_frame_decode, benchmark_v6_frame_encode, benchmark_v6_frame_decode
}
criterion_main!(benches);

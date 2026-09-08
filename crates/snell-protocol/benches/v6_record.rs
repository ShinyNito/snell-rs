//! Steady-session v6 encode + receive-copy + decode benchmark.
//! KDF, buffer allocation and warmup are excluded. Every payload is fully
//! transferred and checked; shaped chunking may emit multiple records.
//! Run: `cargo bench -p snell-protocol --bench v6_record`

use std::hint::black_box;
use std::time::Instant;

use snell_protocol::{
    Buffer, DecodeStatus, FixedClock, Psk, RepeatEntropy, SALT_LEN, V6_WIRE_CAP, V6ShapedDecoder,
    V6ShapedEncoder, V6UnshapedDecoder, V6UnshapedEncoder,
};

const ROUNDS: usize = 20_000;
const WARMUP: usize = 128;

fn main() {
    let psk = Psk::new(b"0123456789abcdef").unwrap();
    for repetition in 0..6 {
        eprintln!("repetition={repetition} (0 is warmup; retain raw samples)");
        for size in [64, 256, 4096, 65536] {
            let payload: Vec<u8> = (0..size).map(|i| (i ^ (i >> 8)) as u8).collect();
            unshaped(&psk, &payload);
            for scattered in if repetition % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                shaped(&psk, &payload, scattered);
            }
        }
    }
}

fn measure(name: &str, payload: &[u8], mut transfer: impl FnMut(&[u8]) -> usize) {
    for _ in 0..WARMUP {
        black_box(transfer(black_box(payload)));
    }
    let started = Instant::now();
    let mut records = 0usize;
    for _ in 0..ROUNDS {
        records += transfer(black_box(payload));
    }
    let elapsed = started.elapsed();
    let bytes = payload.len() * ROUNDS;
    eprintln!(
        "{name}: payload={} rounds={ROUNDS} records={records} bytes={bytes} elapsed_ns={} payload_MiB_s={:.2}",
        payload.len(),
        elapsed.as_nanos(),
        bytes as f64 / 1048576.0 / elapsed.as_secs_f64()
    );
}

fn unshaped(psk: &Psk, payload: &[u8]) {
    let mut encoder = V6UnshapedEncoder::with_salt(
        psk,
        [7; SALT_LEN],
        RepeatEntropy { byte: 0x3c },
        FixedClock::new(0),
    )
    .unwrap();
    let mut decoder = V6UnshapedDecoder::new(psk.clone());
    let mut out = Buffer::new(V6_WIRE_CAP);
    let mut recv = Buffer::new(V6_WIRE_CAP);
    measure("v6-unshaped contiguous", payload, |mut remaining| {
        let mut records = 0;
        while !remaining.is_empty() {
            let mut reservation = encoder.reserve(&mut out, &[], remaining.len()).unwrap();
            let n = remaining.len().min(reservation.capacity());
            assert!(n > 0);
            reservation.payload_mut()[..n].copy_from_slice(&remaining[..n]);
            reservation.seal(n).unwrap();
            recv.extend_from_slice(out.filled()).unwrap();
            out.consume(out.len()).unwrap();
            let DecodeStatus::Record(record) = decoder.decode(&mut recv).unwrap() else {
                panic!("complete encoded record must decode");
            };
            assert_eq!(&recv.filled()[record.plaintext.clone()], &remaining[..n]);
            decoder.consume(&mut recv, &record).unwrap();
            assert!(recv.is_empty());
            remaining = &remaining[n..];
            records += 1;
        }
        records
    });
}

fn shaped(psk: &Psk, payload: &[u8], scattered: bool) {
    let mut encoder = V6ShapedEncoder::with_salt(
        psk,
        [7; SALT_LEN],
        RepeatEntropy { byte: 0x3c },
        FixedClock::new(0),
    )
    .unwrap();
    let mut decoder = V6ShapedDecoder::new(psk.clone()).unwrap();
    let mut out = Buffer::new(V6_WIRE_CAP);
    let mut recv = Buffer::new(V6_WIRE_CAP);
    let name = if scattered {
        "v6-shaped scatter"
    } else {
        "v6-shaped contiguous"
    };
    measure(name, payload, |mut remaining| {
        let mut records = 0;
        while !remaining.is_empty() {
            let mut reservation = if scattered {
                encoder.reserve_scattered(&mut out, &[], remaining.len())
            } else {
                encoder.reserve(&mut out, &[], remaining.len())
            }
            .unwrap();
            let n = remaining.len().min(reservation.capacity());
            assert!(n > 0);
            reservation.payload_mut()[..n].copy_from_slice(&remaining[..n]);
            let split = if scattered {
                reservation.seal_scattered(n).unwrap()
            } else {
                reservation.seal(n).unwrap();
                0
            };
            recv.extend_from_slice(&out.filled()[split..]).unwrap();
            recv.extend_from_slice(&out.filled()[..split]).unwrap();
            out.consume(out.len()).unwrap();
            let DecodeStatus::Record(record) = decoder.decode(&mut recv).unwrap() else {
                panic!("complete encoded record must decode");
            };
            assert_eq!(&recv.filled()[record.plaintext.clone()], &remaining[..n]);
            decoder.consume(&mut recv, &record).unwrap();
            assert!(recv.is_empty());
            remaining = &remaining[n..];
            records += 1;
        }
        records
    });
}

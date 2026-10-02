//! Steady-session v6 encode + receive-copy + decode benchmark.
//! KDF, buffer allocation and warmup are excluded. Every payload is fully
//! transferred and checked; shaped chunking may emit multiple records.
//! Run: `cargo bench -p snell-protocol --bench v6_record`

use std::hint::black_box;
use std::time::Instant;

use snell_protocol::{
    Buffer, DecodeStatus, FixedClock, Psk, RecordDecoder, RecordEncoder, SALT_LEN, V6_WIRE_CAP,
    V6ShapedDecoder, V6ShapedEncoder, V6UnshapedDecoder, V6UnshapedEncoder,
};

mod support {
    pub mod profile_cases;
}

const ROUNDS: usize = 20_000;
const WARMUP: usize = 128;

fn main() {
    let psk = Psk::new(b"0123456789abcdef").unwrap();
    for repetition in 0..6 {
        eprintln!("repetition={repetition} (0 is warmup; retain raw samples)");
        for size in [64, 256, 4096, 65536] {
            let payload: Vec<u8> = (0..size).map(|i| (i ^ (i >> 8)) as u8).collect();
            let encoder = V6UnshapedEncoder::with_salt(&psk, [7; SALT_LEN]).unwrap();
            let decoder = V6UnshapedDecoder::new(psk.clone());
            measure("v6-unshaped", &payload, encoder, decoder);
            for offset in 0..4 {
                let (generator, key) = support::profile_cases::CASES[(offset + repetition) % 4];
                let psk = Psk::new(key).unwrap();
                let encoder =
                    V6ShapedEncoder::with_salt(&psk, [7; SALT_LEN], FixedClock::new(0)).unwrap();
                let decoder = V6ShapedDecoder::new(psk);
                let name = format!("v6-shaped generator={generator}");
                measure(&name, &payload, encoder, decoder);
            }
        }
    }
}

/// Send `payload` as records and decode them back in wire order. Returns
/// the record count.
fn transfer(
    encoder: &mut impl RecordEncoder,
    decoder: &mut impl RecordDecoder,
    out: &mut Buffer,
    recv: &mut Buffer,
    mut remaining: &[u8],
) -> usize {
    let mut records = 0;
    while !remaining.is_empty() {
        let mut reservation = encoder.reserve(out, &[], remaining.len()).unwrap();
        let n = remaining.len().min(reservation.capacity());
        assert!(n > 0);
        reservation.payload_mut()[..n].copy_from_slice(&remaining[..n]);
        let split = reservation.seal(n).unwrap();
        recv.extend_from_slice(&out.filled()[split..]).unwrap();
        recv.extend_from_slice(&out.filled()[..split]).unwrap();
        out.consume(out.len()).unwrap();
        let DecodeStatus::Record(record) = decoder.decode(recv).unwrap() else {
            panic!("complete encoded record must decode");
        };
        assert_eq!(record.plaintext(recv.filled()), &remaining[..n]);
        decoder.consume(recv, &record).unwrap();
        assert!(recv.is_empty());
        remaining = &remaining[n..];
        records += 1;
    }
    records
}

fn measure(
    name: &str,
    payload: &[u8],
    mut encoder: impl RecordEncoder,
    mut decoder: impl RecordDecoder,
) {
    let mut out = Buffer::new(V6_WIRE_CAP);
    let mut recv = Buffer::new(V6_WIRE_CAP);
    let mut run = |payload| transfer(&mut encoder, &mut decoder, &mut out, &mut recv, payload);
    for _ in 0..WARMUP {
        black_box(run(black_box(payload)));
    }
    let started = Instant::now();
    let mut records = 0usize;
    for _ in 0..ROUNDS {
        records += run(black_box(payload));
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

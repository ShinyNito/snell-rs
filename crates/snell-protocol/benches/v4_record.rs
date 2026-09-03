//! Allocation / timing microbench for the v4 record codec.
//!
//! Run: `cargo bench -p snell-protocol --bench v4_record`

use std::time::Instant;

use snell_protocol::{
    DecodeStatus, EncodeBuffer, FixedClock, Psk, RecordKind, RecvBuffer, RepeatEntropy, SALT_LEN,
    V4_WIRE_CAP, V4Decoder, V4Encoder,
};

fn seal_and_take(
    encoder: &mut V4Encoder<RepeatEntropy, FixedClock>,
    buf: &mut EncodeBuffer,
    payload: &[u8],
) -> Vec<u8> {
    {
        let mut rec = encoder.reserve(buf, &[], payload.len()).unwrap();
        rec.payload_mut()[..payload.len()].copy_from_slice(payload);
        rec.seal(payload.len()).unwrap();
    }
    let wire = buf.pending().to_vec();
    buf.advance(wire.len()).unwrap();
    wire
}

fn decode_one(decoder: &mut V4Decoder, buf: &mut RecvBuffer, wire: &[u8]) -> usize {
    buf.extend_from_slice(wire).unwrap();
    let mut decoded = 0usize;
    loop {
        match decoder.decode(buf).unwrap() {
            DecodeStatus::NeedMore { .. } => break,
            DecodeStatus::Record(record) => {
                if record.kind == RecordKind::Data {
                    decoded += record.plaintext.len();
                }
                decoder.consume(buf, &record).unwrap();
            }
        }
        if buf.is_empty() {
            break;
        }
    }
    decoded
}

fn main() {
    let psk = Psk::new(b"0123456789abcdef").unwrap();
    let payload = [0xABu8; 1460];
    let mut encoder = V4Encoder::with_salt(
        &psk,
        [7; SALT_LEN],
        0,
        RepeatEntropy { byte: 0x3c },
        FixedClock::new(0),
    )
    .unwrap();
    let mut decoder = V4Decoder::new(psk);
    let mut recv = RecvBuffer::new(64 * 1024);
    let mut out = EncodeBuffer::new(V4_WIRE_CAP);

    let warmup = [0xABu8; 64];
    let first = seal_and_take(&mut encoder, &mut out, &warmup);
    let _ = decode_one(&mut decoder, &mut recv, &first);
    let cap = out.capacity();

    let rounds = 10_000usize;
    let start = Instant::now();
    let mut decoded = 0usize;
    for _ in 0..rounds {
        let wire = seal_and_take(&mut encoder, &mut out, &payload);
        assert_eq!(out.capacity(), cap);
        decoded += decode_one(&mut decoder, &mut recv, &wire);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "v4 encode+decode {rounds} steady-state records of {}B, decoded {decoded}B, wire_cap {cap}, {elapsed:?}",
        payload.len()
    );
}

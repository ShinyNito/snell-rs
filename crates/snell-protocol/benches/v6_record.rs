//! Allocation / timing microbench for the v6 unshaped and shaped codecs.
//!
//! Run: `cargo bench -p snell-protocol --bench v6_record`

use std::time::Instant;

use snell_protocol::{
    DecodeStatus, EncodeBuffer, FixedClock, Psk, RecordKind, RecvBuffer, RepeatEntropy, SALT_LEN,
    V4_WIRE_CAP, V6_WIRE_CAP, V6ShapedDecoder, V6ShapedEncoder, V6UnshapedDecoder,
    V6UnshapedEncoder,
};

fn main() {
    let psk = Psk::new(b"0123456789abcdef").unwrap();
    let payload = [0xABu8; 256];
    unshaped(&psk, &payload);
    shaped(&psk, &payload);
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
    let mut recv = RecvBuffer::new(64 * 1024);
    let mut out = EncodeBuffer::new(V4_WIRE_CAP);
    let warmup = [0xABu8; 64];
    drain(&mut encoder, &mut decoder, &mut out, &mut recv, &warmup);
    let cap = out.capacity();
    let rounds = 10_000usize;
    let start = Instant::now();
    let mut decoded = 0usize;
    for _ in 0..rounds {
        decoded += drain(&mut encoder, &mut decoder, &mut out, &mut recv, payload);
        assert_eq!(out.capacity(), cap);
    }
    eprintln!(
        "v6-unshaped encode+decode {rounds} records of {}B, decoded {decoded}B, {elapsed:?}",
        payload.len(),
        elapsed = start.elapsed()
    );
}

fn shaped(psk: &Psk, payload: &[u8]) {
    let mut encoder = V6ShapedEncoder::with_salt(
        psk,
        [7; SALT_LEN],
        RepeatEntropy { byte: 0x3c },
        FixedClock::new(0),
    )
    .unwrap();
    let mut decoder = V6ShapedDecoder::new(psk.clone()).unwrap();
    let mut recv = RecvBuffer::new(V6_WIRE_CAP);
    let mut out = EncodeBuffer::new(V6_WIRE_CAP);
    let warmup = [0xABu8; 64];
    drain_shaped(&mut encoder, &mut decoder, &mut out, &mut recv, &warmup);
    let cap = out.capacity();
    let rounds = 2_000usize;
    let start = Instant::now();
    let mut decoded = 0usize;
    for _ in 0..rounds {
        decoded += drain_shaped(&mut encoder, &mut decoder, &mut out, &mut recv, payload);
        assert_eq!(out.capacity(), cap);
    }
    eprintln!(
        "v6-shaped encode+decode {rounds} records of {}B, decoded {decoded}B, {elapsed:?}",
        payload.len(),
        elapsed = start.elapsed()
    );
}

fn drain(
    encoder: &mut V6UnshapedEncoder<RepeatEntropy, FixedClock>,
    decoder: &mut V6UnshapedDecoder,
    out: &mut EncodeBuffer,
    recv: &mut RecvBuffer,
    payload: &[u8],
) -> usize {
    {
        let mut rec = encoder.reserve(out, &[], payload.len()).unwrap();
        rec.payload_mut()[..payload.len()].copy_from_slice(payload);
        rec.seal(payload.len()).unwrap();
    }
    let wire = out.pending().to_vec();
    out.advance(wire.len()).unwrap();
    decode_one(decoder, recv, &wire)
}

fn drain_shaped(
    encoder: &mut V6ShapedEncoder<RepeatEntropy, FixedClock>,
    decoder: &mut V6ShapedDecoder,
    out: &mut EncodeBuffer,
    recv: &mut RecvBuffer,
    payload: &[u8],
) -> usize {
    {
        let mut rec = encoder.reserve(out, &[], payload.len()).unwrap();
        let n = payload.len().min(rec.capacity());
        rec.payload_mut()[..n].copy_from_slice(&payload[..n]);
        rec.seal(n).unwrap();
    }
    let wire = out.pending().to_vec();
    out.advance(wire.len()).unwrap();
    decode_one_shaped(decoder, recv, &wire)
}

fn decode_one(decoder: &mut V6UnshapedDecoder, buf: &mut RecvBuffer, wire: &[u8]) -> usize {
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

fn decode_one_shaped(decoder: &mut V6ShapedDecoder, buf: &mut RecvBuffer, wire: &[u8]) -> usize {
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

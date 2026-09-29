//! Decoders must yield the same record however the wire is split across reads.

use snell_protocol::{
    Buffer, DecodeStatus, FixedClock, Psk, RepeatEntropy, SALT_LEN, V4Decoder, V4Encoder,
    V6_WIRE_CAP, V6ShapedDecoder, V6ShapedEncoder, V6UnshapedDecoder, V6UnshapedEncoder,
};

fn psk() -> Psk {
    Psk::new(b"0123456789abcdef").unwrap()
}

/// Up to five chunks at pseudo-random offsets, always covering the whole wire.
fn random_cuts(len: usize) -> Vec<usize> {
    let mut seed = 0x9e37_79b9_u64;
    let mut cuts = vec![0, len];
    for _ in 0..4 {
        seed = seed.wrapping_mul(0x5851_f42d_4c95_7f2d).wrapping_add(1);
        cuts.push((seed as usize) % (len + 1));
    }
    cuts.sort_unstable();
    cuts.dedup();
    cuts
}

macro_rules! fragmentation_suite {
    ($codec:ident, $encoder:expr, $decoder:expr) => {
        mod $codec {
            use super::*;

            fn hello_wire() -> Vec<u8> {
                let mut encoder = $encoder;
                let mut out = Buffer::new(V6_WIRE_CAP);
                let mut rec = encoder.reserve(&mut out, &[], 5).unwrap();
                rec.payload_mut()[..5].copy_from_slice(b"hello");
                rec.seal(5).unwrap();
                out.filled().to_vec()
            }

            /// Feed `chunks` in order: every chunk but the last needs more.
            fn feed(chunks: &[&[u8]]) {
                let mut decoder = $decoder;
                let mut buf = Buffer::new(V6_WIRE_CAP);
                let (last, head) = chunks.split_last().unwrap();
                for chunk in head {
                    buf.extend_from_slice(chunk).unwrap();
                    match decoder.decode(&mut buf).unwrap() {
                        DecodeStatus::NeedMore { minimum } => assert!(minimum > buf.len()),
                        other => panic!("record before the last chunk: {other:?}"),
                    }
                }
                buf.extend_from_slice(last).unwrap();
                let DecodeStatus::Record(record) = decoder.decode(&mut buf).unwrap() else {
                    panic!("needed more after the last chunk");
                };
                assert_eq!(record.plaintext(buf.filled()), b"hello");
                decoder.consume(&mut buf, &record).unwrap();
                assert!(buf.is_empty());
            }

            #[test]
            fn byte_at_a_time() {
                let wire = hello_wire();
                feed(&wire.chunks(1).collect::<Vec<_>>());
            }

            #[test]
            fn every_single_cut() {
                let wire = hello_wire();
                for cut in 1..wire.len() {
                    let (head, tail) = wire.split_at(cut);
                    feed(&[head, tail]);
                }
            }

            #[test]
            fn random_multi_cut() {
                let wire = hello_wire();
                let chunks: Vec<&[u8]> = random_cuts(wire.len())
                    .windows(2)
                    .map(|pair| &wire[pair[0]..pair[1]])
                    .collect();
                feed(&chunks);
            }
        }
    };
}

fragmentation_suite!(
    v4,
    V4Encoder::with_salt(
        &psk(),
        [7; SALT_LEN],
        0,
        RepeatEntropy { byte: 0x3c },
        FixedClock::new(0),
    )
    .unwrap(),
    V4Decoder::new(psk())
);

fragmentation_suite!(
    v6_unshaped,
    V6UnshapedEncoder::with_salt(
        &psk(),
        [7; SALT_LEN],
        RepeatEntropy { byte: 0x3c },
        FixedClock::new(0),
    )
    .unwrap(),
    V6UnshapedDecoder::new(psk())
);

fragmentation_suite!(
    v6_shaped,
    V6ShapedEncoder::with_salt(
        &psk(),
        [7; SALT_LEN],
        RepeatEntropy { byte: 0x3c },
        FixedClock::new(0),
    )
    .unwrap(),
    V6ShapedDecoder::new(psk())
);

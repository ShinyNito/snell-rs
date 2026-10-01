//! Behavior every record codec shares, run once per codec: fragmentation,
//! decode-ahead, zero chunks, tamper detection, cancellation, and redaction.

use snell_protocol::{
    Buffer, DecodeStatus, Error, FixedClock, HEADER_CIPHER_LEN, Psk, RecordKind, RepeatEntropy,
    SALT_LEN, V4Decoder, V4Encoder, V6_WIRE_CAP, V6ShapedDecoder, V6ShapedEncoder,
    V6UnshapedDecoder, V6UnshapedEncoder,
};

const PSK: &[u8] = b"0123456789abcdef";

fn psk() -> Psk {
    Psk::new(PSK).unwrap()
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

/// `$zero_chunk_len` is the first zero chunk's wire length, when fixed.
macro_rules! codec_suite {
    ($codec:ident, $encoder:expr, $decoder:expr, $zero_chunk_len:expr) => {
        mod $codec {
            use super::*;

            /// Seal each payload as one record of a fresh session.
            fn wire(payloads: &[&[u8]]) -> Vec<u8> {
                let mut encoder = $encoder;
                let mut out = Buffer::new(V6_WIRE_CAP);
                for payload in payloads {
                    let mut rec = encoder.reserve(&mut out, &[], payload.len()).unwrap();
                    rec.payload_mut()[..payload.len()].copy_from_slice(payload);
                    rec.seal(payload.len()).unwrap();
                }
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
                let wire = wire(&[b"hello"]);
                feed(&wire.chunks(1).collect::<Vec<_>>());
            }

            #[test]
            fn every_single_cut() {
                let wire = wire(&[b"hello"]);
                for cut in 1..wire.len() {
                    let (head, tail) = wire.split_at(cut);
                    feed(&[head, tail]);
                }
            }

            #[test]
            fn random_multi_cut() {
                let wire = wire(&[b"hello"]);
                let chunks: Vec<&[u8]> = random_cuts(wire.len())
                    .windows(2)
                    .map(|pair| &wire[pair[0]..pair[1]])
                    .collect();
                feed(&chunks);
            }

            #[test]
            fn decode_ahead_keeps_ranges_until_fifo_consume() {
                let wire = wire(&[b"hello", b"world"]);
                let mut decoder = $decoder;
                let mut buf = Buffer::new(V6_WIRE_CAP);
                buf.extend_from_slice(&wire).unwrap();
                let DecodeStatus::Record(first) = decoder.decode(&mut buf).unwrap() else {
                    panic!("first record not ready");
                };
                let DecodeStatus::Record(second) = decoder.decode(&mut buf).unwrap() else {
                    panic!("second record not ready");
                };
                assert!(decoder.has_unconsumed_plaintext());
                // Both plaintexts stay valid against the same unmoved filled() view.
                assert_eq!(first.plaintext(buf.filled()), b"hello");
                assert_eq!(second.plaintext(buf.filled()), b"world");
                assert_eq!(first.consumed + second.consumed, wire.len());
                decoder.consume(&mut buf, &first).unwrap();
                decoder.consume(&mut buf, &second).unwrap();
                assert!(buf.is_empty());
                assert!(!decoder.has_unconsumed_plaintext());
                // Over-consuming past the outstanding records fails closed.
                assert_eq!(
                    decoder.consume(&mut buf, &second),
                    Err(Error::PlaintextNotDrained)
                );
                assert!(matches!(
                    decoder.decode(&mut buf).unwrap(),
                    DecodeStatus::NeedMore { .. }
                ));
            }

            #[test]
            fn zero_chunk_round_trips() {
                let wire = wire(&[b""]);
                if let Some(len) = $zero_chunk_len {
                    assert_eq!(wire.len(), len);
                }
                let mut decoder = $decoder;
                let mut buf = Buffer::new(V6_WIRE_CAP);
                buf.extend_from_slice(&wire).unwrap();
                let DecodeStatus::Record(record) = decoder.decode(&mut buf).unwrap() else {
                    panic!("zero chunk not decoded");
                };
                assert_eq!(record.kind, RecordKind::ZeroChunk);
                assert!(record.plaintext(buf.filled()).is_empty());
                decoder.consume(&mut buf, &record).unwrap();
                assert!(buf.is_empty());
            }

            #[test]
            fn tampered_tag_fails_closed() {
                let mut wire = wire(&[b"hello"]);
                *wire.last_mut().unwrap() ^= 1;
                let mut decoder = $decoder;
                let mut buf = Buffer::new(V6_WIRE_CAP);
                buf.extend_from_slice(&wire).unwrap();
                assert_eq!(decoder.decode(&mut buf), Err(Error::Aead));
            }

            #[test]
            fn dropped_reservation_cancels_without_side_effects() {
                let mut encoder = $encoder;
                let mut out = Buffer::new(V6_WIRE_CAP);
                {
                    let mut rec = encoder.reserve(&mut out, b"pfx", 8).unwrap();
                    rec.payload_mut()[0] = 1;
                }
                assert!(out.is_empty());
                let mut rec = encoder.reserve(&mut out, &[], 5).unwrap();
                rec.payload_mut()[..5].copy_from_slice(b"hello");
                rec.seal(5).unwrap();
                assert_eq!(out.filled(), wire(&[b"hello"]));
            }

            #[test]
            fn debug_hides_psk() {
                let secret = std::str::from_utf8(PSK).unwrap();
                assert!(!format!("{:?}", $encoder).contains(secret));
                assert!(!format!("{:?}", $decoder).contains(secret));
            }
        }
    };
}

codec_suite!(
    v4,
    V4Encoder::with_salt(
        &psk(),
        [7; SALT_LEN],
        0,
        RepeatEntropy { byte: 0x3c },
        FixedClock::new(0),
    )
    .unwrap(),
    V4Decoder::new(psk()),
    Some(SALT_LEN + HEADER_CIPHER_LEN)
);

codec_suite!(
    v6_unshaped,
    V6UnshapedEncoder::with_salt(&psk(), [7; SALT_LEN]).unwrap(),
    V6UnshapedDecoder::new(psk()),
    Some(SALT_LEN + HEADER_CIPHER_LEN)
);

codec_suite!(
    v6_shaped,
    V6ShapedEncoder::with_salt(&psk(), [7; SALT_LEN], FixedClock::new(0)).unwrap(),
    V6ShapedDecoder::new(psk()),
    None::<usize>
);

//! Behavior every record codec shares, run once per codec: fragmentation,
//! decode-ahead, zero chunks, tamper detection, cancellation, and redaction.

use std::fmt::Debug;

use snell_protocol::{
    Buffer, DecodeStatus, Error, FixedClock, HEADER_CIPHER_LEN, Psk, RecordDecoder, RecordEncoder,
    RecordKind, RepeatEntropy, SALT_LEN, V4Decoder, V4Encoder, V6_WIRE_CAP, V6ShapedDecoder,
    V6ShapedEncoder, V6UnshapedDecoder, V6UnshapedEncoder,
};
use snell_testkit::seal_records;

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

/// One codec under test: fresh session halves, and the wire length of a
/// first zero chunk when it is fixed.
struct Codec<E, D> {
    encoder: fn() -> E,
    decoder: fn() -> D,
    zero_chunk_len: Option<usize>,
}

impl<E: RecordEncoder + Debug, D: RecordDecoder + Debug> Codec<E, D> {
    /// Seal each payload as one record of a fresh session.
    fn wire(&self, payloads: &[&[u8]]) -> Vec<u8> {
        seal_records(&mut (self.encoder)(), payloads)
    }

    /// Feed `chunks` in order: every chunk but the last needs more.
    fn feed(&self, chunks: &[&[u8]]) {
        let mut decoder = (self.decoder)();
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

    fn byte_at_a_time(&self) {
        let wire = self.wire(&[b"hello"]);
        self.feed(&wire.chunks(1).collect::<Vec<_>>());
    }

    fn every_single_cut(&self) {
        let wire = self.wire(&[b"hello"]);
        for cut in 1..wire.len() {
            let (head, tail) = wire.split_at(cut);
            self.feed(&[head, tail]);
        }
    }

    fn random_multi_cut(&self) {
        let wire = self.wire(&[b"hello"]);
        let chunks: Vec<&[u8]> = random_cuts(wire.len())
            .windows(2)
            .map(|pair| &wire[pair[0]..pair[1]])
            .collect();
        self.feed(&chunks);
    }

    fn decode_ahead_keeps_ranges_until_fifo_consume(&self) {
        let wire = self.wire(&[b"hello", b"world"]);
        let mut decoder = (self.decoder)();
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

    fn zero_chunk_round_trips(&self) {
        let wire = self.wire(&[b""]);
        if let Some(len) = self.zero_chunk_len {
            assert_eq!(wire.len(), len);
        }
        let mut decoder = (self.decoder)();
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

    fn tampered_tag_fails_closed(&self) {
        let mut wire = self.wire(&[b"hello"]);
        *wire.last_mut().unwrap() ^= 1;
        let mut decoder = (self.decoder)();
        let mut buf = Buffer::new(V6_WIRE_CAP);
        buf.extend_from_slice(&wire).unwrap();
        assert_eq!(decoder.decode(&mut buf), Err(Error::Aead));
    }

    fn dropped_reservation_cancels_without_side_effects(&self) {
        let mut encoder = (self.encoder)();
        let mut out = Buffer::new(V6_WIRE_CAP);
        let mut rec = encoder.reserve(&mut out, b"pfx", 8).unwrap();
        rec.payload_mut()[0] = 1;
        drop(rec);
        assert!(out.is_empty());
        assert_eq!(
            seal_records(&mut encoder, &[b"hello"]),
            self.wire(&[b"hello"])
        );
    }

    fn debug_hides_psk(&self) {
        let secret = std::str::from_utf8(PSK).unwrap();
        assert!(!format!("{:?}", (self.encoder)()).contains(secret));
        assert!(!format!("{:?}", (self.decoder)()).contains(secret));
    }
}

/// Run every [`Codec`] check as its own test.
macro_rules! codec_tests {
    ($name:ident, $codec:expr) => {
        mod $name {
            use super::*;

            #[test]
            fn byte_at_a_time() {
                $codec.byte_at_a_time();
            }

            #[test]
            fn every_single_cut() {
                $codec.every_single_cut();
            }

            #[test]
            fn random_multi_cut() {
                $codec.random_multi_cut();
            }

            #[test]
            fn decode_ahead_keeps_ranges_until_fifo_consume() {
                $codec.decode_ahead_keeps_ranges_until_fifo_consume();
            }

            #[test]
            fn zero_chunk_round_trips() {
                $codec.zero_chunk_round_trips();
            }

            #[test]
            fn tampered_tag_fails_closed() {
                $codec.tampered_tag_fails_closed();
            }

            #[test]
            fn dropped_reservation_cancels_without_side_effects() {
                $codec.dropped_reservation_cancels_without_side_effects();
            }

            #[test]
            fn debug_hides_psk() {
                $codec.debug_hides_psk();
            }
        }
    };
}

const V4: Codec<V4Encoder<RepeatEntropy, FixedClock>, V4Decoder> = Codec {
    encoder: || {
        V4Encoder::with_salt(
            &psk(),
            [7; SALT_LEN],
            0,
            RepeatEntropy { byte: 0x3c },
            FixedClock::new(0),
        )
        .unwrap()
    },
    decoder: || V4Decoder::new(psk()),
    zero_chunk_len: Some(SALT_LEN + HEADER_CIPHER_LEN),
};

const V6_UNSHAPED: Codec<V6UnshapedEncoder, V6UnshapedDecoder> = Codec {
    encoder: || V6UnshapedEncoder::with_salt(&psk(), [7; SALT_LEN]).unwrap(),
    decoder: || V6UnshapedDecoder::new(psk()),
    zero_chunk_len: Some(SALT_LEN + HEADER_CIPHER_LEN),
};

const V6_SHAPED: Codec<V6ShapedEncoder<FixedClock>, V6ShapedDecoder> = Codec {
    encoder: || V6ShapedEncoder::with_salt(&psk(), [7; SALT_LEN], FixedClock::new(0)).unwrap(),
    decoder: || V6ShapedDecoder::new(psk()),
    zero_chunk_len: None,
};

codec_tests!(v4, V4);
codec_tests!(v6_unshaped, V6_UNSHAPED);
codec_tests!(v6_shaped, V6_SHAPED);

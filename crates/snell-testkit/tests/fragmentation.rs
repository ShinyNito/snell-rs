use snell_protocol::{
    DecodeStatus, EncodeBuffer, FixedClock, HEADER_CIPHER_LEN, MAX_PACKET_SIZE, Psk, RecvBuffer,
    RepeatEntropy, SALT_LEN, V4_WIRE_CAP, V4Decoder, V4Encoder, V6UnshapedDecoder,
    V6UnshapedEncoder, next_v4_chunk_limit,
};
use snell_testkit::FRAGMENTATION_CASES;

fn psk() -> Psk {
    Psk::new(b"0123456789abcdef").unwrap()
}

fn hello_encoder() -> V4Encoder<RepeatEntropy, FixedClock> {
    V4Encoder::with_salt(
        &psk(),
        [7; SALT_LEN],
        0,
        RepeatEntropy { byte: 0x3c },
        FixedClock::new(0),
    )
    .unwrap()
}

fn encode_buf() -> EncodeBuffer {
    EncodeBuffer::new(V4_WIRE_CAP)
}

fn v4_hello_wire() -> Vec<u8> {
    let mut encoder = hello_encoder();
    let mut out = encode_buf();
    {
        let mut rec = encoder.reserve(&mut out, &[], 5).unwrap();
        rec.payload_mut()[..5].copy_from_slice(b"hello");
        rec.seal(5).unwrap();
    }
    out.pending().to_vec()
}

fn push(buf: &mut RecvBuffer, bytes: &[u8]) {
    buf.extend_from_slice(bytes).unwrap();
}

fn decode_hello(decoder: &mut V4Decoder, buf: &mut RecvBuffer) {
    match decoder.decode(buf).unwrap() {
        DecodeStatus::Record(record) => {
            assert_eq!(record.plaintext(buf.filled()), b"hello");
            decoder.consume(buf, &record).unwrap();
        }
        other => panic!("{other:?}"),
    }
}

fn feed_chunks(chunks: &[&[u8]]) {
    let mut decoder = V4Decoder::new(psk());
    let mut buf = RecvBuffer::new(4096);
    let mut got = false;
    for (i, chunk) in chunks.iter().enumerate() {
        push(&mut buf, chunk);
        match decoder.decode(&mut buf).unwrap() {
            DecodeStatus::NeedMore { minimum } => {
                assert!(i + 1 < chunks.len(), "needed more after last chunk");
                assert!(minimum > buf.len() || minimum > 0);
            }
            DecodeStatus::Record(record) => {
                assert_eq!(record.plaintext(buf.filled()), b"hello");
                decoder.consume(&mut buf, &record).unwrap();
                got = true;
                assert_eq!(i + 1, chunks.len());
            }
        }
    }
    assert!(got);
    assert!(buf.is_empty());
}

fn byte_at_a_time() {
    let wire = v4_hello_wire();
    let mut decoder = V4Decoder::new(psk());
    let mut buf = RecvBuffer::new(4096);
    for (i, byte) in wire.iter().enumerate() {
        push(&mut buf, &[*byte]);
        match decoder.decode(&mut buf).unwrap() {
            DecodeStatus::NeedMore { minimum } => {
                assert!(i + 1 < wire.len());
                assert!(minimum > i + 1);
            }
            DecodeStatus::Record(record) => {
                assert_eq!(i + 1, wire.len());
                assert_eq!(record.plaintext(buf.filled()), b"hello");
                decoder.consume(&mut buf, &record).unwrap();
            }
        }
    }
}

fn all_single_cuts() {
    let wire = v4_hello_wire();
    assert_eq!(SALT_LEN, 16);
    assert_eq!(SALT_LEN + HEADER_CIPHER_LEN, 39);
    for cut in 0..=wire.len() {
        let mut decoder = V4Decoder::new(psk());
        let mut buf = RecvBuffer::new(4096);
        push(&mut buf, &wire[..cut]);
        if cut < wire.len() {
            match decoder.decode(&mut buf).unwrap() {
                DecodeStatus::NeedMore { minimum } => assert!(minimum > cut),
                other => panic!("cut {cut}: {other:?}"),
            }
            push(&mut buf, &wire[cut..]);
        }
        decode_hello(&mut decoder, &mut buf);
        assert!(buf.is_empty());
    }
}

fn random_multi_cut() {
    let wire = v4_hello_wire();
    let mut seed = 0x9e37_79b9_u64;
    let mut cuts = vec![0, wire.len()];
    for _ in 0..4 {
        seed = seed.wrapping_mul(0x5851_f42d_4c95_7f2d).wrapping_add(1);
        cuts.push((seed as usize) % (wire.len() + 1));
    }
    cuts.sort_unstable();
    cuts.dedup();
    let chunks: Vec<&[u8]> = cuts
        .windows(2)
        .map(|pair| &wire[pair[0]..pair[1]])
        .collect();
    feed_chunks(&chunks);
}

fn header_body_boundary() {
    let wire = v4_hello_wire();
    for cut in [16, 39] {
        feed_chunks(&[&wire[..cut], &wire[cut..]]);
    }
}

fn multi_record_read() {
    let mut encoder = hello_encoder();
    let mut out = encode_buf();
    {
        let mut rec = encoder.reserve(&mut out, &[], 5).unwrap();
        rec.payload_mut()[..5].copy_from_slice(b"hello");
        rec.seal(5).unwrap();
    }
    let first = out.pending().to_vec();
    out.advance(first.len()).unwrap();
    {
        let mut rec = encoder.reserve(&mut out, &[], 5).unwrap();
        rec.payload_mut()[..5].copy_from_slice(b"world");
        rec.seal(5).unwrap();
    }
    let second = out.pending().to_vec();
    let mut both = first;
    both.extend_from_slice(&second);

    let mut decoder = V4Decoder::new(psk());
    let mut buf = RecvBuffer::new(4096);
    push(&mut buf, &both);
    match decoder.decode(&mut buf).unwrap() {
        DecodeStatus::Record(record) => {
            assert_eq!(record.plaintext(buf.filled()), b"hello");
            decoder.consume(&mut buf, &record).unwrap();
        }
        other => panic!("{other:?}"),
    }
    match decoder.decode(&mut buf).unwrap() {
        DecodeStatus::Record(record) => {
            assert_eq!(record.plaintext(buf.filled()), b"world");
            decoder.consume(&mut buf, &record).unwrap();
        }
        other => panic!("{other:?}"),
    }
    assert!(buf.is_empty());
}

fn partial_write() {
    let mut encoder = hello_encoder();
    let mut out = encode_buf();
    {
        let mut rec = encoder.reserve(&mut out, &[], 5).unwrap();
        rec.payload_mut()[..5].copy_from_slice(b"hello");
        rec.seal(5).unwrap();
    }
    let wire = out.pending().to_vec();
    out.advance(3).unwrap();
    assert_eq!(out.pending(), &wire[3..]);
    out.advance(2).unwrap();
    assert_eq!(out.pending(), &wire[5..]);
    out.advance(out.pending().len()).unwrap();
    assert!(out.is_empty());
}

fn vectored_partial_write() {
    let mut encoder = hello_encoder();
    let mut out = encode_buf();
    {
        let mut rec = encoder.reserve(&mut out, &[], 5).unwrap();
        rec.payload_mut()[..5].copy_from_slice(b"hello");
        rec.seal(5).unwrap();
    }
    let first_len = out.pending().len();
    assert!(first_len > 1);
    out.advance(1).unwrap();
    assert_eq!(out.pending().len(), first_len - 1);
    out.advance(out.pending().len()).unwrap();
    assert!(out.is_empty());
}

fn cancellation() {
    let mut encoder = V4Encoder::with_salt(
        &psk(),
        [7; SALT_LEN],
        8,
        RepeatEntropy { byte: 0x11 },
        FixedClock::new(0),
    )
    .unwrap();
    let mut out = encode_buf();
    {
        let mut rec = encoder.reserve(&mut out, &[], 3).unwrap();
        rec.payload_mut()[..3].copy_from_slice(b"one");
        rec.seal(3).unwrap();
    }
    out.advance(out.pending().len()).unwrap();
    let cancelled_cap;
    {
        let rec = encoder.reserve(&mut out, &[], MAX_PACKET_SIZE).unwrap();
        cancelled_cap = rec.capacity();
    }
    let rec = encoder.reserve(&mut out, &[], MAX_PACKET_SIZE).unwrap();
    assert_eq!(rec.capacity(), cancelled_cap);
    assert_ne!(rec.capacity(), next_v4_chunk_limit(cancelled_cap));
}

#[test]
fn golden_hello_covers_fragmentation_cases() {
    for case in FRAGMENTATION_CASES {
        match case.id {
            "byte-at-a-time" => byte_at_a_time(),
            "all-single-cuts" => all_single_cuts(),
            "random-multi-cut" => random_multi_cut(),
            "header-body-boundary" => header_body_boundary(),
            "multi-record-read" => multi_record_read(),
            "partial-write" => partial_write(),
            "vectored-partial-write" => vectored_partial_write(),
            "cancellation" => cancellation(),
            other => panic!("unhandled fragmentation case {other}"),
        }
    }
}

fn v6_unshaped_hello_wire() -> Vec<u8> {
    let mut encoder = V6UnshapedEncoder::with_salt(
        &psk(),
        [7; SALT_LEN],
        RepeatEntropy { byte: 0x3c },
        FixedClock::new(0),
    )
    .unwrap();
    let mut out = encode_buf();
    {
        let mut rec = encoder.reserve(&mut out, &[], 5).unwrap();
        rec.payload_mut()[..5].copy_from_slice(b"hello");
        rec.seal(5).unwrap();
    }
    out.pending().to_vec()
}

#[test]
fn v6_unshaped_hello_byte_at_a_time() {
    let wire = v6_unshaped_hello_wire();
    let mut decoder = V6UnshapedDecoder::new(psk());
    let mut buf = RecvBuffer::new(4096);
    for (i, byte) in wire.iter().enumerate() {
        push(&mut buf, &[*byte]);
        match decoder.decode(&mut buf).unwrap() {
            DecodeStatus::NeedMore { minimum } => {
                assert!(i + 1 < wire.len());
                assert!(minimum > i + 1);
            }
            DecodeStatus::Record(record) => {
                assert_eq!(i + 1, wire.len());
                assert_eq!(record.plaintext(buf.filled()), b"hello");
                decoder.consume(&mut buf, &record).unwrap();
            }
        }
    }
}

#[test]
fn v6_unshaped_hello_every_cut() {
    let wire = v6_unshaped_hello_wire();
    for cut in 0..=wire.len() {
        let mut decoder = V6UnshapedDecoder::new(psk());
        let mut buf = RecvBuffer::new(4096);
        push(&mut buf, &wire[..cut]);
        if cut < wire.len() {
            match decoder.decode(&mut buf).unwrap() {
                DecodeStatus::NeedMore { minimum } => assert!(minimum > cut),
                other => panic!("cut {cut}: {other:?}"),
            }
            push(&mut buf, &wire[cut..]);
        }
        match decoder.decode(&mut buf).unwrap() {
            DecodeStatus::Record(record) => {
                assert_eq!(record.plaintext(buf.filled()), b"hello");
                decoder.consume(&mut buf, &record).unwrap();
            }
            other => panic!("{other:?}"),
        }
        assert!(buf.is_empty());
    }
}

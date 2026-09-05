#![no_main]
use bytes::BufMut;
use libfuzzer_sys::fuzz_target;
use snell_protocol::{
    DecodeStatus, EncodeBuffer, FixedClock, Psk, RecvBuffer, RepeatEntropy, V4Decoder, V4Encoder,
    V6_WIRE_CAP, V6ShapedDecoder, V6ShapedEncoder, V6UnshapedDecoder, V6UnshapedEncoder,
};

macro_rules! roundtrip {
    ($encoder:expr, $decoder:expr, $data:expr, $chunk:expr) => {{
        let mut encoder = $encoder;
        let mut decoder = $decoder;
        let mut out = EncodeBuffer::new(V6_WIRE_CAP);
        let mut recv = RecvBuffer::new(V6_WIRE_CAP);
        let mut expected = $data;
        while !expected.is_empty() {
            // A Pending read drops a reservation without consuming a nonce.
            drop(encoder.reserve(&mut out, &[], expected.len()).unwrap());
            let mut slot = encoder.reserve(&mut out, &[], expected.len()).unwrap();
            let n = slot.capacity().min(expected.len());
            assert!(n > 0);
            slot.put_slice(&expected[..n]);
            slot.seal(n).unwrap();
            let mut decoded = 0;
            for chunk in out.pending().chunks($chunk) {
                recv.extend_from_slice(chunk).unwrap();
                while let DecodeStatus::Record(record) = decoder.decode(&mut recv).unwrap() {
                    let plain = record.plaintext(recv.filled());
                    assert_eq!(plain, &expected[decoded..decoded + plain.len()]);
                    decoded += plain.len();
                    decoder.consume(&mut recv, &record).unwrap();
                }
            }
            assert_eq!(decoded, n);
            assert!(recv.is_empty());
            out.advance(out.len()).unwrap();
            expected = &expected[n..];
        }
        encoder.reserve(&mut out, &[], 0).unwrap().seal(0).unwrap();
        recv.extend_from_slice(out.pending()).unwrap();
        let DecodeStatus::Record(end) = decoder.decode(&mut recv).unwrap() else {
            panic!("zero chunk");
        };
        assert_eq!(end.kind, snell_protocol::RecordKind::ZeroChunk);
        decoder.consume(&mut recv, &end).unwrap();
        assert!(recv.is_empty());
    }};
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 || data.len() > 65_538 {
        return;
    }
    let psk = Psk::new([data[1]; 16]).unwrap();
    let chunk = usize::from(data[2]) + 1;
    let payload = &data[3..];
    let salt = [7; 16];
    let entropy = RepeatEntropy { byte: 0x3c };
    let clock = FixedClock::new(0);
    match data[0] % 3 {
        0 => roundtrip!(
            V4Encoder::with_salt(&psk, salt, usize::from(data[1]), entropy, clock).unwrap(),
            V4Decoder::new(psk.clone()),
            payload,
            chunk
        ),
        1 => roundtrip!(
            V6ShapedEncoder::with_salt(&psk, salt, entropy, clock).unwrap(),
            V6ShapedDecoder::new(psk.clone()).unwrap(),
            payload,
            chunk
        ),
        _ => roundtrip!(
            V6UnshapedEncoder::with_salt(&psk, salt, entropy, clock).unwrap(),
            V6UnshapedDecoder::new(psk.clone()),
            payload,
            chunk
        ),
    }
});

use crate::socks5::{self, Command};
use crate::{
    Address, AddressRef, DecodeStatus, EncodeBuffer, Error, FixedClock, HEADER_CIPHER_LEN,
    ParseState, Psk, RecvBuffer, RepeatEntropy, SALT_LEN, V4_WIRE_CAP, V4Decoder, V4Encoder,
    decode_connect_request_prefix, encode_connect_request,
};

#[test]
fn socks5_request_byte_at_a_time() {
    let mut buf = [0u8; 64];
    let n = socks5::encode_request(
        &mut buf,
        Command::Connect,
        AddressRef::Domain {
            host: "example.com",
            port: 443,
        },
    )
    .unwrap();
    let full = &buf[..n];
    for filled in 1..=n {
        match socks5::request_need(&full[..filled]).unwrap() {
            ParseState::Need(_) => assert!(filled < n),
            ParseState::Done(req) => {
                assert_eq!(req.header_len, n);
                assert_eq!(filled, n);
            }
        }
    }
}

#[test]
fn connect_prefix_survives_cuts() {
    let address = Address::domain("example.com", 443).unwrap();
    let mut buf = [0u8; 32];
    let n = encode_connect_request(&mut buf, address.as_view(), true).unwrap();
    for cut in 1..n {
        assert!(decode_connect_request_prefix(&buf[..cut]).is_err());
    }
    let (request, consumed) = decode_connect_request_prefix(&buf[..n]).unwrap();
    assert!(request.reuse);
    assert_eq!(consumed, n);
}

#[test]
fn random_peer_input_does_not_panic() {
    let mut seed = 0x9e37_79b9_u64;
    for _ in 0..256 {
        seed = seed.wrapping_mul(0x5851_f42d_4c95_7f2d).wrapping_add(1);
        let len = (seed % 64) as usize;
        let mut buf = vec![0u8; len];
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = (seed >> ((i % 8) * 8)) as u8;
        }
        let _ = crate::decode_udp_request(&buf);
        let _ = socks5::greeting_need(&buf);
        let _ = socks5::request_need(&buf);
        let _ = crate::parse_v4_plain_header(&buf);
        let _ = crate::parse_v6_plain_header(&buf);
        let _ = crate::decode_connect_request_prefix(&buf);
        let _ = crate::decode_server_reply(&buf);
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let mut v6u = crate::V6UnshapedDecoder::new(psk.clone());
        let mut recv = RecvBuffer::new(256);
        let _ = recv.extend_from_slice(&buf);
        match v6u.decode(&mut recv) {
            Ok(_)
            | Err(Error::Aead)
            | Err(Error::InvalidHeader)
            | Err(Error::PayloadTooLarge)
            | Err(Error::Kdf)
            | Err(Error::Truncated)
            | Err(Error::Malformed(_))
            | Err(Error::InvalidReserved(_)) => {}
            Err(error) => panic!("unexpected unshaped error {error:?}"),
        }
        if let Ok(mut v6s) = crate::V6ShapedDecoder::new(psk) {
            let mut recv = RecvBuffer::new(256);
            let _ = recv.extend_from_slice(&buf);
            match v6s.decode(&mut recv) {
                Ok(_)
                | Err(Error::Aead)
                | Err(Error::InvalidHeader)
                | Err(Error::PayloadTooLarge)
                | Err(Error::Kdf)
                | Err(Error::Truncated)
                | Err(Error::Malformed(_))
                | Err(Error::InvalidReserved(_)) => {}
                Err(error) => panic!("unexpected shaped error {error:?}"),
            }
        }
    }
}

fn v4_hello_wire() -> Vec<u8> {
    let psk = Psk::new(b"0123456789abcdef").unwrap();
    let mut encoder = V4Encoder::with_salt(
        &psk,
        [7; SALT_LEN],
        0,
        RepeatEntropy { byte: 0x3c },
        FixedClock::new(0),
    )
    .unwrap();
    let mut out = EncodeBuffer::new(V4_WIRE_CAP);
    {
        let mut rec = encoder.reserve(&mut out, &[], 5).unwrap();
        rec.payload_mut()[..5].copy_from_slice(b"hello");
        rec.seal(5).unwrap();
    }
    out.pending().to_vec()
}

#[test]
fn v4_record_byte_at_a_time() {
    let wire = v4_hello_wire();
    let psk = Psk::new(b"0123456789abcdef").unwrap();
    let mut decoder = V4Decoder::new(psk);
    let mut buf = RecvBuffer::new(4096);
    for (i, byte) in wire.iter().enumerate() {
        buf.extend_from_slice(&[*byte]).unwrap();
        match decoder.decode(&mut buf).unwrap() {
            DecodeStatus::NeedMore { minimum } => {
                assert!(i + 1 < wire.len(), "needed more after last byte");
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
fn v4_random_ciphertext_does_not_panic() {
    let mut seed = 0x9e37_79b9_u64;
    for _ in 0..8 {
        seed = seed.wrapping_mul(0x5851_f42d_4c95_7f2d).wrapping_add(1);
        let len = 16 + (seed % 48) as usize;
        let mut wire = vec![0u8; len];
        for (i, byte) in wire.iter_mut().enumerate() {
            *byte = (seed >> ((i % 8) * 8)) as u8;
        }
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let mut decoder = V4Decoder::new(psk);
        let mut buf = RecvBuffer::new(256);
        buf.extend_from_slice(&wire).unwrap();
        match decoder.decode(&mut buf) {
            Ok(DecodeStatus::NeedMore { .. })
            | Ok(DecodeStatus::Record(_))
            | Err(Error::Aead)
            | Err(Error::InvalidHeader)
            | Err(Error::ZeroChunkWithPadding)
            | Err(Error::PayloadTooLarge)
            | Err(Error::Kdf)
            | Err(Error::Truncated) => {}
            Err(error) => panic!("unexpected error {error:?}"),
        }
    }
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

#[test]
fn v4_hello_split_at_every_offset() {
    let wire = v4_hello_wire();
    assert_eq!(SALT_LEN, 16);
    assert_eq!(SALT_LEN + HEADER_CIPHER_LEN, 39);
    assert!(wire.len() > 39);
    let psk = Psk::new(b"0123456789abcdef").unwrap();
    for cut in 0..=wire.len() {
        let mut decoder = V4Decoder::new(psk.clone());
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

#[test]
fn v4_two_records_one_commit() {
    let psk = Psk::new(b"0123456789abcdef").unwrap();
    let mut encoder = V4Encoder::with_salt(
        &psk,
        [7; SALT_LEN],
        0,
        RepeatEntropy { byte: 0x3c },
        FixedClock::new(0),
    )
    .unwrap();
    let mut out = EncodeBuffer::new(V4_WIRE_CAP);
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

    let mut decoder = V4Decoder::new(psk);
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

use crate::socks5::{self, Command};
use crate::{
    Address, AddressRef, Buffer, DecodeStatus, Error, ParseState, Psk, V4Decoder,
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
        if let Some(header) = buf.first_chunk() {
            let _ = crate::header::parse_v4_plain_header(header);
            let _ = crate::header::parse_v6_plain_header(header);
        }
        let _ = crate::decode_connect_request_prefix(&buf);
        let _ = crate::decode_server_reply(&buf);
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let mut v6u = crate::V6UnshapedDecoder::new(psk.clone());
        let mut recv = Buffer::new(256);
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
        let mut v6s = crate::V6ShapedDecoder::new(psk);
        let mut recv = Buffer::new(256);
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
        let mut buf = Buffer::new(256);
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

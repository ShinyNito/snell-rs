use std::path::PathBuf;

use snell_protocol::{
    Address, Buffer, DecodeStatus, FixedClock, Psk, RecordDecoder, RecordEncoder, RepeatEntropy,
    SALT_LEN, V4Decoder, V4Encoder, V6_WIRE_CAP, V6ShapedDecoder, V6ShapedEncoder,
    V6UnshapedDecoder, V6UnshapedEncoder, decode_connect_request, decode_udp_request,
    decode_udp_response, decode_udp_setup_prefix, encode_connect_request, encode_reject,
    encode_tunnel_reply, encode_udp_request, encode_udp_response, encode_udp_setup,
};
use snell_testkit::{load_golden_dir, seal_records};

fn fixture(name: &str) -> Vec<u8> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden");
    load_golden_dir(dir)
        .unwrap()
        .into_iter()
        .find(|fixture| fixture.name == name)
        .map(|fixture| fixture.bytes)
        .unwrap_or_else(|| panic!("missing fixture {name}"))
}

fn psk() -> Psk {
    Psk::new(b"0123456789abcdef").unwrap()
}

/// Encode through `write`, and return the written prefix of a scratch buffer.
fn encoded(write: impl FnOnce(&mut [u8]) -> snell_protocol::Result<usize>) -> Vec<u8> {
    let mut out = [0u8; 64];
    let n = write(&mut out).unwrap();
    out[..n].to_vec()
}

#[test]
fn connect_fixtures_match_codec() {
    let example = Address::domain("example.com", 443).unwrap();
    for (name, reuse) in [
        ("connect-example-com-443", false),
        ("connect-v2-example-com-443", true),
    ] {
        let wire = fixture(name);
        assert_eq!(
            encoded(|dst| encode_connect_request(dst, example.as_view(), reuse)),
            wire,
            "{name}"
        );
        let request = decode_connect_request(&wire).unwrap();
        assert_eq!(
            (request.destination, request.reuse),
            (example.clone(), reuse)
        );
    }

    // Readers skip a client id; this encoder never writes one.
    let request = decode_connect_request(&fixture("connect-with-client-id")).unwrap();
    assert_eq!(request.destination, Address::domain("dns", 53).unwrap());
    assert!(!request.reuse);
}

#[test]
fn control_reply_fixtures_match_codec() {
    let setup = fixture("udp-setup");
    assert_eq!(encoded(encode_udp_setup), setup);
    assert_eq!(decode_udp_setup_prefix(&setup), Ok(setup.len()));
    assert_eq!(encoded(encode_tunnel_reply), fixture("server-tunnel"));
    assert_eq!(
        encoded(|dst| encode_reject(dst, "connect failed")),
        fixture("server-error-code-1")
    );
}

#[test]
fn udp_datagram_fixtures_round_trip() {
    for name in [
        "udp-request-ipv4-127-0-0-1-8080",
        "udp-request-domain-example-com-53",
    ] {
        let wire = fixture(name);
        let packet = decode_udp_request(&wire).unwrap();
        assert_eq!(
            encoded(|dst| encode_udp_request(dst, packet.address, packet.payload)),
            wire,
            "{name}"
        );
    }
    let wire = fixture("udp-response-ipv4-8-8-8-8-53");
    let packet = decode_udp_response(&wire).unwrap();
    assert_eq!(packet.address.to_string(), "8.8.8.8:53");
    assert_eq!(packet.payload, b"dns");
    assert_eq!(
        encoded(|dst| encode_udp_response(dst, packet.address, packet.payload)),
        wire
    );
}

/// Seal `hello` as the first record, compare it with the fixture `name`,
/// and decode it back. Returns the decoder for further checks.
fn assert_hello_record<D: RecordDecoder>(
    name: &str,
    mut encoder: impl RecordEncoder,
    mut decoder: D,
) -> D {
    let expected = fixture(name);
    assert_eq!(seal_records(&mut encoder, &[b"hello"]), expected, "{name}");

    let mut buf = Buffer::new(V6_WIRE_CAP);
    buf.extend_from_slice(&expected).unwrap();
    let DecodeStatus::Record(record) = decoder.decode(&mut buf).unwrap() else {
        panic!("{name}: record not decoded");
    };
    assert_eq!(record.plaintext(buf.filled()), b"hello", "{name}");
    decoder
}

#[test]
fn record_fixtures_match_codecs() {
    let clock = FixedClock::new(0);
    for (name, padding) in [
        ("v4-record-hello-salt-07-no-padding", 0),
        ("v4-record-hello-salt-07-padding-8", 8),
    ] {
        let encoder = V4Encoder::with_salt(
            &psk(),
            [7; SALT_LEN],
            padding,
            RepeatEntropy { byte: 0x3c },
            clock,
        )
        .unwrap();
        assert_hello_record(name, encoder, V4Decoder::new(psk()));
    }

    let decoder = assert_hello_record(
        "v6-unshaped-hello-salt-07",
        V6UnshapedEncoder::with_salt(&psk(), [7; SALT_LEN]).unwrap(),
        V6UnshapedDecoder::new(psk()),
    );
    assert_eq!(decoder.replay_identity(), Some([7u8; SALT_LEN]));

    let decoder = assert_hello_record(
        "v6-shaped-hello-salt-07",
        V6ShapedEncoder::with_salt(&psk(), [7; SALT_LEN], clock).unwrap(),
        V6ShapedDecoder::new(psk()),
    );
    assert_eq!(decoder.replay_identity(), Some([7u8; SALT_LEN]));
}

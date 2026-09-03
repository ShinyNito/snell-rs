use std::path::PathBuf;

use snell_protocol::{
    ATYP_IPV4, COMMAND_CONNECT, COMMAND_CONNECT_V2, COMMAND_ERROR, COMMAND_TUNNEL, COMMAND_UDP,
    COMMAND_UDP_FORWARD, DecodeStatus, ERROR_REJECT, EncodeBuffer, FixedClock, PROTOCOL_VERSION,
    Psk, RecvBuffer, RepeatEntropy, SALT_LEN, V4_WIRE_CAP, V4Decoder, V4Encoder, V6_WIRE_CAP,
    V6ShapedDecoder, V6ShapedEncoder, V6UnshapedDecoder, V6UnshapedEncoder,
};
use snell_testkit::load_golden_dir;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden")
}

#[test]
fn loads_phase1_plaintext_fixtures() {
    let fixtures = load_golden_dir(golden_dir()).unwrap();
    assert!(
        fixtures.len() >= 5,
        "expected plaintext control fixtures, got {}",
        fixtures.len()
    );

    let with_id = fixture(&fixtures, "connect-with-client-id");
    assert_eq!(with_id.bytes().unwrap()[0], PROTOCOL_VERSION);
    assert_eq!(with_id.bytes().unwrap()[1], COMMAND_CONNECT);
    assert_eq!(with_id.bytes().unwrap()[2], 3);

    let connect = fixture(&fixtures, "connect-example-com-443");
    assert_eq!(connect.kind, "plaintext-control");
    let bytes = connect.bytes().unwrap();
    assert_eq!(bytes[0], PROTOCOL_VERSION);
    assert_eq!(bytes[1], COMMAND_CONNECT);

    let reuse = fixture(&fixtures, "connect-v2-example-com-443");
    assert_eq!(reuse.bytes().unwrap()[1], COMMAND_CONNECT_V2);

    let udp = fixture(&fixtures, "udp-setup");
    assert_eq!(udp.bytes().unwrap(), [PROTOCOL_VERSION, COMMAND_UDP, 0]);

    let udp_req = fixture(&fixtures, "udp-request-ipv4-127-0-0-1-8080");
    assert_eq!(udp_req.bytes().unwrap()[0], COMMAND_UDP_FORWARD);

    let tunnel = fixture(&fixtures, "server-tunnel");
    assert_eq!(tunnel.bytes().unwrap(), [COMMAND_TUNNEL]);

    let error = fixture(&fixtures, "server-error-code-1");
    assert_eq!(error.bytes().unwrap()[0], COMMAND_ERROR);
    assert_eq!(error.bytes().unwrap()[1], ERROR_REJECT);

    let udp_req_domain = fixture(&fixtures, "udp-request-domain-example-com-53");
    assert_eq!(udp_req_domain.bytes().unwrap()[0], COMMAND_UDP_FORWARD);

    let udp_resp = fixture(&fixtures, "udp-response-ipv4-8-8-8-8-53");
    assert_eq!(udp_resp.bytes().unwrap()[0], ATYP_IPV4);
}

#[test]
fn connect_fixture_matches_empty_client_id_layout() {
    let bytes = fixture(
        &load_golden_dir(golden_dir()).unwrap(),
        "connect-example-com-443",
    )
    .bytes()
    .unwrap();
    assert_eq!(bytes[0], PROTOCOL_VERSION);
    assert_eq!(bytes[1], COMMAND_CONNECT);
    assert_eq!(bytes[2], 0);
    assert_eq!(bytes[3], 11);
    assert_eq!(&bytes[4..15], b"example.com");
    assert_eq!(&bytes[15..17], 443u16.to_be_bytes());
}

#[test]
fn v4_record_fixture_round_trips() {
    let expected = fixture(
        &load_golden_dir(golden_dir()).unwrap(),
        "v4-record-hello-salt-07-no-padding",
    )
    .bytes()
    .unwrap();
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
    let wire = out.pending().to_vec();
    assert_eq!(wire, expected);

    let mut decoder = V4Decoder::new(psk);
    let mut buf = RecvBuffer::new(4096);
    buf.extend_from_slice(&wire).unwrap();
    match decoder.decode(&mut buf).unwrap() {
        DecodeStatus::Record(record) => {
            assert_eq!(record.plaintext(buf.filled()), b"hello");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn v4_padded_record_fixture_matches_hex() {
    let expected = fixture(
        &load_golden_dir(golden_dir()).unwrap(),
        "v4-record-hello-salt-07-padding-8",
    )
    .bytes()
    .unwrap();
    let psk = Psk::new(b"0123456789abcdef").unwrap();
    let mut encoder = V4Encoder::with_salt(
        &psk,
        [7; SALT_LEN],
        8,
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
    let wire = out.pending().to_vec();
    assert_eq!(wire, expected);

    let mut decoder = V4Decoder::new(psk);
    let mut buf = RecvBuffer::new(4096);
    buf.extend_from_slice(&wire).unwrap();
    match decoder.decode(&mut buf).unwrap() {
        DecodeStatus::Record(record) => {
            assert_eq!(record.plaintext(buf.filled()), b"hello");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn v6_unshaped_record_matches_v4_no_padding_hex() {
    let expected = fixture(
        &load_golden_dir(golden_dir()).unwrap(),
        "v6-unshaped-hello-salt-07",
    )
    .bytes()
    .unwrap();
    let psk = Psk::new(b"0123456789abcdef").unwrap();
    let mut encoder = V6UnshapedEncoder::with_salt(
        &psk,
        [7; SALT_LEN],
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
    let wire = out.pending().to_vec();
    assert_eq!(wire, expected);

    let mut decoder = V6UnshapedDecoder::new(psk);
    let mut buf = RecvBuffer::new(4096);
    buf.extend_from_slice(&wire).unwrap();
    match decoder.decode(&mut buf).unwrap() {
        DecodeStatus::Record(record) => {
            assert_eq!(record.plaintext(buf.filled()), b"hello");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(decoder.replay_identity(), Some([7u8; SALT_LEN]));
}

#[test]
fn v6_shaped_record_fixture_matches_hex() {
    let expected = fixture(
        &load_golden_dir(golden_dir()).unwrap(),
        "v6-shaped-hello-salt-07",
    )
    .bytes()
    .unwrap();
    let psk = Psk::new(b"0123456789abcdef").unwrap();
    let mut encoder = V6ShapedEncoder::with_salt(
        &psk,
        [7; SALT_LEN],
        RepeatEntropy { byte: 0x3c },
        FixedClock::new(0),
    )
    .unwrap();
    let mut out = EncodeBuffer::new(V6_WIRE_CAP);
    {
        let mut rec = encoder.reserve(&mut out, &[], 5).unwrap();
        rec.payload_mut()[..5].copy_from_slice(b"hello");
        rec.seal(5).unwrap();
    }
    let wire = out.pending().to_vec();
    assert_eq!(wire, expected);

    let mut decoder = V6ShapedDecoder::new(psk).unwrap();
    let mut buf = RecvBuffer::new(V6_WIRE_CAP);
    buf.extend_from_slice(&wire).unwrap();
    match decoder.decode(&mut buf).unwrap() {
        DecodeStatus::Record(record) => {
            assert_eq!(record.plaintext(buf.filled()), b"hello");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(decoder.replay_identity(), Some([7u8; SALT_LEN]));
}

fn fixture<'a>(
    fixtures: &'a [snell_testkit::GoldenFixture],
    name: &str,
) -> &'a snell_testkit::GoldenFixture {
    fixtures
        .iter()
        .find(|fixture| fixture.name == name)
        .unwrap_or_else(|| panic!("missing fixture {name}"))
}

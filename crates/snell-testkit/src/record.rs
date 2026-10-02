//! Record helpers for codec tests.

use snell_protocol::{Buffer, RecordEncoder, V6_WIRE_CAP};

/// Seal each payload as one record and return the records in wire order.
///
/// # Panics
/// If the encoder rejects a payload.
pub fn seal_records(encoder: &mut impl RecordEncoder, payloads: &[&[u8]]) -> Vec<u8> {
    let mut out = Buffer::new(V6_WIRE_CAP);
    let mut wire = Vec::new();
    for payload in payloads {
        let mut record = encoder.reserve(&mut out, &[], payload.len()).unwrap();
        record.payload_mut()[..payload.len()].copy_from_slice(payload);
        let split = record.seal(payload.len()).unwrap();
        wire.extend_from_slice(&out.filled()[split..]);
        wire.extend_from_slice(&out.filled()[..split]);
        out.consume(out.len()).unwrap();
    }
    wire
}

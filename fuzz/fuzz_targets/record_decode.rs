#![no_main]
use libfuzzer_sys::fuzz_target;
use snell_protocol::{
    DecodeStatus, Psk, RecvBuffer, V4Decoder, V6_WIRE_CAP, V6ShapedDecoder, V6UnshapedDecoder,
};

macro_rules! decode {
    ($decoder:expr, $data:expr, $chunk:expr) => {{
        let mut decoder = $decoder;
        let mut recv = RecvBuffer::new(V6_WIRE_CAP);
        for chunk in $data.chunks($chunk) {
            if recv.extend_from_slice(chunk).is_err() {
                break;
            }
            loop {
                match decoder.decode(&mut recv) {
                    Ok(DecodeStatus::Record(record)) => {
                        let _ = record.plaintext(recv.filled());
                        decoder.consume(&mut recv, &record).unwrap();
                    }
                    Ok(DecodeStatus::NeedMore { .. }) => break,
                    Err(_) => return,
                }
            }
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 || data.len() > 2 * V6_WIRE_CAP {
        return;
    }
    let psk = Psk::new(b"0123456789abcdef").unwrap();
    let chunk = usize::from(data[1]) + 1;
    let wire = &data[2..];
    match data[0] % 3 {
        0 => decode!(V4Decoder::new(psk), wire, chunk),
        1 => decode!(V6ShapedDecoder::new(psk).unwrap(), wire, chunk),
        _ => decode!(V6UnshapedDecoder::new(psk), wire, chunk),
    }
});

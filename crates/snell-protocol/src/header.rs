use std::mem::size_of;

use zerocopy::byteorder::big_endian::U16;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    Error, HEADER_PLAIN_LEN, HEADER_VERSION_MARKER, MAX_PACKET_SIZE, MAX_PACKET_SIZE_V6, Result,
    TAG_LEN,
};

/// Snell 7-byte plaintext record header.
///
/// Layout: `marker(1) reserved(2) padding_len(2 BE) payload_len(2 BE)`.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
#[repr(C, packed)]
pub struct WirePlainHeader {
    pub marker: u8,
    pub reserved: [u8; 2],
    pub padding_len: U16,
    pub payload_len: U16,
}

const _: () = assert!(size_of::<WirePlainHeader>() == HEADER_PLAIN_LEN);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordHeader {
    pub padding_len: usize,
    pub payload_len: usize,
}

impl RecordHeader {
    pub fn body_len_v4(self) -> Result<usize> {
        if self.payload_len == 0 {
            if self.padding_len != 0 {
                return Err(Error::ZeroChunkWithPadding);
            }
            return Ok(0);
        }
        Ok(self.padding_len + self.payload_len + TAG_LEN)
    }

    pub fn body_len_v6_unshaped(self) -> Result<usize> {
        if self.padding_len != 0 {
            return Err(Error::InvalidHeader);
        }
        if self.payload_len == 0 {
            return Ok(0);
        }
        Ok(self.payload_len + TAG_LEN)
    }

    pub fn body_len_v6_shaped(self) -> Result<usize> {
        if self.padding_len > MAX_PACKET_SIZE_V6 || self.payload_len > MAX_PACKET_SIZE_V6 {
            return Err(Error::PayloadTooLarge);
        }
        Ok(self.padding_len
            + if self.payload_len == 0 {
                0
            } else {
                self.payload_len + TAG_LEN
            })
    }

    #[cfg(feature = "unsafe-raw")]
    pub fn body_len_v6_raw(self) -> Result<usize> {
        if self.padding_len != 0 {
            return Err(Error::InvalidHeader);
        }
        Ok(self.payload_len)
    }
}

pub fn parse_v4_plain_header(header: &[u8]) -> Result<RecordHeader> {
    let (wire, _) = WirePlainHeader::ref_from_prefix(header).map_err(|_| Error::Truncated)?;
    if wire.marker != HEADER_VERSION_MARKER {
        return Err(Error::InvalidHeader);
    }
    let padding_len = wire.padding_len.get() as usize;
    let payload_len = wire.payload_len.get() as usize;
    if padding_len > MAX_PACKET_SIZE || payload_len > MAX_PACKET_SIZE {
        return Err(Error::PayloadTooLarge);
    }
    Ok(RecordHeader {
        padding_len,
        payload_len,
    })
}

pub fn parse_v6_plain_header(header: &[u8]) -> Result<RecordHeader> {
    let (wire, _) = WirePlainHeader::ref_from_prefix(header).map_err(|_| Error::Truncated)?;
    if wire.marker != HEADER_VERSION_MARKER {
        return Err(Error::InvalidHeader);
    }
    let reserved = wire.reserved;
    if reserved != [0, 0] {
        return Err(Error::InvalidReserved(reserved[0] | reserved[1]));
    }
    Ok(RecordHeader {
        padding_len: wire.padding_len.get() as usize,
        payload_len: wire.payload_len.get() as usize,
    })
}

pub fn write_v4_plain_header(
    header: &mut [u8],
    padding_len: usize,
    payload_len: usize,
) -> Result<()> {
    write_plain_header(header, padding_len, payload_len, false)
}

pub fn write_v6_plain_header(
    header: &mut [u8],
    padding_len: usize,
    payload_len: usize,
) -> Result<()> {
    write_plain_header(header, padding_len, payload_len, true)
}

fn write_plain_header(
    header: &mut [u8],
    padding_len: usize,
    payload_len: usize,
    reserved_zero: bool,
) -> Result<()> {
    let available = header.len();
    let (wire, _) =
        WirePlainHeader::mut_from_prefix(header).map_err(|_| Error::BufferTooSmall {
            needed: HEADER_PLAIN_LEN,
            available,
        })?;
    let max = if reserved_zero {
        MAX_PACKET_SIZE_V6
    } else {
        MAX_PACKET_SIZE
    };
    if padding_len > max || payload_len > max {
        return Err(Error::PayloadTooLarge);
    }
    wire.marker = HEADER_VERSION_MARKER;
    wire.reserved = [0, 0];
    wire.padding_len.set(padding_len as u16);
    wire.payload_len.set(payload_len as u16);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_zero_chunk_rejects_padding() {
        let mut header = [0; HEADER_PLAIN_LEN];
        write_v4_plain_header(&mut header, 1, 0).unwrap();
        let parsed = parse_v4_plain_header(&header).unwrap();
        assert!(parsed.body_len_v4().is_err());
    }

    #[test]
    fn v6_requires_reserved_zero() {
        let mut header = [0; HEADER_PLAIN_LEN];
        write_v6_plain_header(&mut header, 0, 4).unwrap();
        header[1] = 1;
        assert!(parse_v6_plain_header(&header).is_err());
    }

    #[test]
    fn v4_round_trip() {
        let mut header = [0; HEADER_PLAIN_LEN];
        write_v4_plain_header(&mut header, 8, 16).unwrap();
        let parsed = parse_v4_plain_header(&header).unwrap();
        assert_eq!(parsed.padding_len, 8);
        assert_eq!(parsed.payload_len, 16);
        assert_eq!(parsed.body_len_v4().unwrap(), 8 + 16 + TAG_LEN);
    }

    #[test]
    fn truncated_header_is_truncated() {
        assert!(matches!(
            parse_v4_plain_header(&[4, 0, 0, 0, 0, 0]),
            Err(Error::Truncated)
        ));
        assert!(matches!(parse_v6_plain_header(&[]), Err(Error::Truncated)));
    }

    #[test]
    fn write_buffer_too_small() {
        let mut header = [0; 6];
        assert!(matches!(
            write_v4_plain_header(&mut header, 0, 1),
            Err(Error::BufferTooSmall {
                needed: HEADER_PLAIN_LEN,
                available: 6
            })
        ));
    }
}

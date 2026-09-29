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
        if self.payload_len == 0 && self.padding_len != 0 {
            return Err(Error::ZeroChunkWithPadding);
        }
        Ok(self.padding_len + self.payload_body_len())
    }

    pub fn body_len_v6_unshaped(self) -> Result<usize> {
        if self.padding_len != 0 {
            return Err(Error::InvalidHeader);
        }
        Ok(self.payload_body_len())
    }

    /// Both lengths come from `u16` wire fields, so no range check applies.
    pub fn body_len_v6_shaped(self) -> usize {
        self.padding_len + self.payload_body_len()
    }

    #[cfg(feature = "unsafe-raw")]
    pub fn body_len_v6_raw(self) -> Result<usize> {
        if self.padding_len != 0 {
            return Err(Error::InvalidHeader);
        }
        Ok(self.payload_len)
    }

    /// Payload plus its tag; a zero-length payload carries no tag.
    const fn payload_body_len(self) -> usize {
        if self.payload_len == 0 {
            0
        } else {
            self.payload_len + TAG_LEN
        }
    }
}

fn parse_plain_header(header: &[u8]) -> Result<&WirePlainHeader> {
    let (wire, _) = WirePlainHeader::ref_from_prefix(header).map_err(|_| Error::Truncated)?;
    if wire.marker != HEADER_VERSION_MARKER {
        return Err(Error::InvalidHeader);
    }
    Ok(wire)
}

impl From<&WirePlainHeader> for RecordHeader {
    fn from(wire: &WirePlainHeader) -> Self {
        Self {
            padding_len: usize::from(wire.padding_len.get()),
            payload_len: usize::from(wire.payload_len.get()),
        }
    }
}

pub fn parse_v4_plain_header(header: &[u8]) -> Result<RecordHeader> {
    let header = RecordHeader::from(parse_plain_header(header)?);
    if header.padding_len > MAX_PACKET_SIZE || header.payload_len > MAX_PACKET_SIZE {
        return Err(Error::PayloadTooLarge);
    }
    Ok(header)
}

pub fn parse_v6_plain_header(header: &[u8]) -> Result<RecordHeader> {
    let wire = parse_plain_header(header)?;
    let [a, b] = wire.reserved;
    if a | b != 0 {
        return Err(Error::InvalidReserved(a | b));
    }
    Ok(wire.into())
}

pub fn write_v4_plain_header(
    header: &mut [u8],
    padding_len: usize,
    payload_len: usize,
) -> Result<()> {
    write_plain_header(header, padding_len, payload_len, MAX_PACKET_SIZE)
}

pub fn write_v6_plain_header(
    header: &mut [u8],
    padding_len: usize,
    payload_len: usize,
) -> Result<()> {
    write_plain_header(header, padding_len, payload_len, MAX_PACKET_SIZE_V6)
}

fn write_plain_header(
    header: &mut [u8],
    padding_len: usize,
    payload_len: usize,
    max: usize,
) -> Result<()> {
    let available = header.len();
    let (wire, _) =
        WirePlainHeader::mut_from_prefix(header).map_err(|_| Error::BufferTooSmall {
            needed: HEADER_PLAIN_LEN,
            available,
        })?;
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

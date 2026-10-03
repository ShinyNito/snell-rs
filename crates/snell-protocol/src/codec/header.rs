use std::mem::size_of;

use zerocopy::byteorder::big_endian::U16;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    Error, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN, HEADER_VERSION_MARKER, MAX_PACKET_SIZE,
    MAX_PACKET_SIZE_V6, Result, TAG_LEN,
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
        if self.payload_len > MAX_PACKET_SIZE {
            return Err(Error::PayloadTooLarge);
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

fn parse_plain_header(header: &[u8; HEADER_PLAIN_LEN]) -> Result<&WirePlainHeader> {
    let wire: &WirePlainHeader = zerocopy::transmute_ref!(header);
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

pub fn parse_v4_plain_header(header: &[u8; HEADER_PLAIN_LEN]) -> Result<RecordHeader> {
    let header = RecordHeader::from(parse_plain_header(header)?);
    if header.padding_len > MAX_PACKET_SIZE || header.payload_len > MAX_PACKET_SIZE {
        return Err(Error::PayloadTooLarge);
    }
    Ok(header)
}

pub fn parse_v6_plain_header(header: &[u8; HEADER_PLAIN_LEN]) -> Result<RecordHeader> {
    let wire = parse_plain_header(header)?;
    let [a, b] = wire.reserved;
    if a | b != 0 {
        return Err(Error::InvalidReserved(a | b));
    }
    Ok(wire.into())
}

/// Plaintext half of an opened `header + tag` block.
pub fn opened_header(block: &[u8; HEADER_CIPHER_LEN]) -> &[u8; HEADER_PLAIN_LEN] {
    let (plain, _tag) = block.split_first_chunk().expect("the block holds a header");
    plain
}

/// Plaintext header for lengths the encoder has already bounded: the v4
/// codec by [`MAX_PACKET_SIZE`], the v6 codecs by the `u16` fields.
pub fn plain_header(padding_len: usize, payload_len: usize) -> [u8; HEADER_PLAIN_LEN] {
    debug_assert!(padding_len <= MAX_PACKET_SIZE_V6 && payload_len <= MAX_PACKET_SIZE_V6);
    zerocopy::transmute!(WirePlainHeader {
        marker: HEADER_VERSION_MARKER,
        reserved: [0, 0],
        padding_len: U16::new(padding_len as u16),
        payload_len: U16::new(payload_len as u16),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_round_trip_and_zero_chunk_padding() {
        let parsed = parse_v4_plain_header(&plain_header(8, 16)).unwrap();
        assert_eq!(parsed.padding_len, 8);
        assert_eq!(parsed.payload_len, 16);
        assert_eq!(parsed.body_len_v4().unwrap(), 8 + 16 + TAG_LEN);
        let zero = parse_v4_plain_header(&plain_header(1, 0)).unwrap();
        assert_eq!(zero.body_len_v4(), Err(Error::ZeroChunkWithPadding));
    }

    #[test]
    fn v4_rejects_oversized_lengths() {
        let header = plain_header(0, MAX_PACKET_SIZE + 1);
        assert_eq!(parse_v4_plain_header(&header), Err(Error::PayloadTooLarge));
    }

    #[test]
    fn v6_requires_marker_and_reserved_zero() {
        let mut header = plain_header(0, 4);
        header[1] = 1;
        assert_eq!(
            parse_v6_plain_header(&header),
            Err(Error::InvalidReserved(1))
        );
        header[0] = 0;
        assert_eq!(parse_v6_plain_header(&header), Err(Error::InvalidHeader));
    }
}

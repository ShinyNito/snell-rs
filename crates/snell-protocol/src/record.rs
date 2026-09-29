use std::ops::Range;

use crate::{Buffer, Error, Result};

/// Outcome of feeding ciphertext currently in a [`crate::Buffer`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeStatus {
    /// Need at least `minimum` bytes from the start of `Buffer::filled`
    /// (including any returned-but-unconsumed records). When outstanding
    /// records leave no room for the next one, `minimum` can exceed the
    /// buffer capacity: consume the outstanding records first.
    NeedMore { minimum: usize },
    /// One record is ready. Decoders support decode-ahead: further records
    /// may be decoded before consuming, and every returned record's ranges
    /// stay valid against the unmoved `filled()` view until any is consumed.
    /// Consume records in decode order.
    Record(DecodedRecord),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedRecord {
    /// Ciphertext byte length of this record.
    pub consumed: usize,
    /// Plaintext range inside `filled()` as of decode time, empty for a
    /// zero chunk. Invalidated by consuming any record.
    pub plaintext: Range<usize>,
    pub kind: RecordKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    Data,
    ZeroChunk,
}

impl DecodedRecord {
    pub fn plaintext<'a>(&self, filled: &'a [u8]) -> &'a [u8] {
        &filled[self.plaintext.clone()]
    }
}

/// Decode-ahead accounting shared by every record decoder: the byte length of
/// returned-but-unconsumed records at the front of `filled()`. The next record
/// is parsed at this offset; [`Self::consume`] drains records FIFO.
#[derive(Debug, Default)]
pub(crate) struct Pending(usize);

impl Pending {
    pub(crate) const fn offset(&self) -> usize {
        self.0
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// `minimum` is measured from the start of `filled()` and includes the
    /// pending records. A record must fit the buffer on its own; when
    /// outstanding records crowd it out, report `NeedMore` so the caller
    /// drains first.
    pub(crate) fn need(&self, buf: &Buffer, minimum: usize) -> Result<Option<DecodeStatus>> {
        if minimum - self.0 > buf.max() {
            Err(Error::PayloadTooLarge)
        } else if buf.len() < minimum {
            Ok(Some(DecodeStatus::NeedMore { minimum }))
        } else {
            Ok(None)
        }
    }

    /// Hand out the record ending at absolute offset `end` of `filled()`.
    pub(crate) fn data(&mut self, end: usize, plaintext: Range<usize>) -> DecodeStatus {
        self.emit(end, plaintext, RecordKind::Data)
    }

    pub(crate) fn zero_chunk(&mut self, end: usize) -> DecodeStatus {
        self.emit(end, 0..0, RecordKind::ZeroChunk)
    }

    fn emit(&mut self, end: usize, plaintext: Range<usize>, kind: RecordKind) -> DecodeStatus {
        let consumed = end - self.0;
        self.0 = end;
        DecodeStatus::Record(DecodedRecord {
            consumed,
            plaintext,
            kind,
        })
    }

    pub(crate) fn consume(&mut self, buf: &mut Buffer, record: &DecodedRecord) -> Result<()> {
        self.0 = self
            .0
            .checked_sub(record.consumed)
            .ok_or(Error::PlaintextNotDrained)?;
        buf.consume(record.consumed)
    }
}

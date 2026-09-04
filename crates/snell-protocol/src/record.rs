use std::ops::Range;

/// Outcome of feeding ciphertext currently in a [`crate::RecvBuffer`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeStatus {
    /// Need at least `minimum` bytes from the start of `RecvBuffer::filled`
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

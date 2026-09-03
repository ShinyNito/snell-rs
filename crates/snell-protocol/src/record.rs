use std::ops::Range;

/// Outcome of feeding ciphertext currently in a [`crate::RecvBuffer`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeStatus {
    /// Need at least `minimum` bytes from the start of `RecvBuffer::filled`.
    NeedMore { minimum: usize },
    /// One record is ready. Consume `record.consumed` before decoding again.
    Record(DecodedRecord),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedRecord {
    /// Ciphertext bytes of this record, from the start of `filled()`.
    pub consumed: usize,
    /// Plaintext range inside `filled()`, empty for a zero chunk.
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

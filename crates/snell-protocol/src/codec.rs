//! The record codec interface: what callers that drive any TCP record codec
//! generically rely on.

use crate::buffer::{Reservation, Slot};
use crate::record::{DecodeStatus, DecodedRecord, EncoderState};
use crate::{AES_128_KEY_LEN, Buffer, Result, SALT_LEN};

/// Seals payloads into records, in place in a [`Buffer`].
///
/// [`reserve`](Self::reserve) a record, write its payload through the
/// returned [`Reservation`], then seal it. Dropping the reservation unsealed
/// cancels the record and leaves the encoder ready for the next one.
pub trait RecordEncoder: Sized + sealed::Seal {
    /// Reserve a record in `buf` whose payload starts with `prefix` and has
    /// room for up to `hint` more bytes, within the encoder's record budget.
    fn reserve<'a>(
        &'a mut self,
        buf: &'a mut Buffer,
        prefix: &[u8],
        hint: usize,
    ) -> Result<Reservation<'a, Self>>;
}

/// Opens records in place in a [`Buffer`].
pub trait RecordDecoder {
    /// Open the next complete record at the front of `buf`, after any
    /// records already returned but not yet consumed.
    fn decode(&mut self, buf: &mut Buffer) -> Result<DecodeStatus>;

    /// Drop a decoded record from `buf`. Records are consumed in decode order.
    fn consume(&mut self, buf: &mut Buffer, record: &DecodedRecord) -> Result<()>;

    /// Whether decoded records are still waiting to be consumed.
    fn has_unconsumed_plaintext(&self) -> bool;

    /// The session salt once known, for codecs whose salts are replay-checked.
    fn replay_identity(&self) -> Option<[u8; SALT_LEN]>;

    /// Bytes needed at the front of `buf` before the session key can be
    /// derived; zero once a key is installed or derived.
    fn kdf_need(&self) -> usize;

    /// The session salt carried by the first [`kdf_need`](Self::kdf_need)
    /// bytes of `buf`.
    fn kdf_salt(&self, buf: &Buffer) -> Result<[u8; SALT_LEN]>;

    /// Install a session key derived elsewhere from
    /// [`kdf_salt`](Self::kdf_salt), so `decode` does not derive it inline.
    fn install_aead(&mut self, salt: [u8; SALT_LEN], key: [u8; AES_128_KEY_LEN]) -> Result<()>;
}

pub(crate) mod sealed {
    use super::*;

    /// The codec-specific half of a [`Reservation`]. Private to this crate,
    /// so [`RecordEncoder`] cannot be implemented elsewhere.
    pub trait Seal {
        /// Record layout decided by `reserve`, beyond the payload slot.
        type Record;

        fn state(&mut self) -> &mut EncoderState;

        /// Seal a record holding `payload_len` payload bytes. On success the
        /// encoder is ready again and the return value is the record's
        /// split: it goes on the wire as `[split..]`, then `[..split]`,
        /// relative to `slot.record_start`.
        fn finish(
            &mut self,
            buf: &mut Buffer,
            slot: &Slot,
            record: &Self::Record,
            payload_len: usize,
        ) -> Result<usize>;
    }
}

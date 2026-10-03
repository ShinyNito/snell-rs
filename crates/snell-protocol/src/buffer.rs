#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::mem::MaybeUninit;

use crate::codec::RecordEncoder;
use crate::codec::record::EncoderState;
use crate::{Error, Result};

/// Fixed backing allocation and a live byte range; never grows implicitly.
pub struct Buffer {
    storage: Vec<u8>,
    start: usize,
    max: usize,
}

impl Buffer {
    pub fn new(max: usize) -> Self {
        Self {
            storage: Vec::with_capacity(max),
            start: 0,
            max,
        }
    }

    /// No allocation; the runtime supplies backing storage on demand.
    pub fn empty(max: usize) -> Self {
        Self {
            storage: Vec::new(),
            start: 0,
            max,
        }
    }

    pub fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.storage[self.start..]
    }

    /// Replace the allocation, copying only live bytes. Invalidates absolute
    /// codec offsets: callers must first consume every decoded record.
    pub fn replace_storage(&mut self, mut storage: Vec<u8>) -> Result<Vec<u8>> {
        if storage.capacity() < self.len() {
            return Err(Error::BufferTooSmall {
                needed: self.len(),
                available: storage.capacity(),
            });
        }
        storage.clear();
        storage.extend_from_slice(self.filled());
        self.start = 0;
        let mut previous = std::mem::replace(&mut self.storage, storage);
        previous.clear();
        Ok(previous)
    }

    /// Release storage only when there are no live bytes.
    pub fn take_empty_storage(&mut self) -> Option<Vec<u8>> {
        if !self.is_empty() {
            return None;
        }
        self.start = 0;
        Some(std::mem::take(&mut self.storage))
    }

    pub fn into_storage(mut self) -> Vec<u8> {
        self.storage.clear();
        self.storage
    }

    pub fn filled(&self) -> &[u8] {
        &self.storage[self.start..]
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.storage.len()
    }

    pub fn len(&self) -> usize {
        self.storage.len() - self.start
    }

    pub fn capacity(&self) -> usize {
        self.storage.capacity()
    }

    pub fn max(&self) -> usize {
        self.max
    }

    #[cfg(test)]
    pub(crate) fn filled_len(&self) -> usize {
        self.storage.len()
    }

    /// Ensure at least `min` writable bytes, then return the entire uninitialized tail.
    pub fn spare_capacity_mut(&mut self, min: usize) -> Result<&mut [MaybeUninit<u8>]> {
        let live = self.len();
        if live.checked_add(min).is_none_or(|needed| needed > self.max) {
            return Err(Error::PayloadTooLarge);
        }
        // Preflight before compact: a failed reservation followed by growth
        // must not copy the live bytes twice or invalidate offsets on error.
        if self.capacity().min(self.max) - live < min {
            return Err(Error::BufferTooSmall {
                needed: self.len() + min,
                available: self.capacity(),
            });
        }
        if self.capacity().min(self.max) - self.storage.len() < min {
            self.compact();
        }
        let writable = self.capacity().min(self.max) - self.storage.len();
        let spare = self.storage.spare_capacity_mut();
        Ok(&mut spare[..writable])
    }

    /// Absolute end index of committed storage. Record bookkeeping only;
    /// indices are invalid across compact.
    pub(crate) fn end(&self) -> usize {
        self.storage.len()
    }

    /// Reserve capacity for a whole record of `total` bytes (may compact once),
    /// then zero-fill and commit only the first `fixed` bytes. Returns the
    /// record start index.
    ///
    /// Until `total - fixed` further bytes are committed, subsequent
    /// [`Self::reserve_zeroed`], [`Self::extend_from_slice`], and
    /// [`Self::commit`] calls within the record cannot compact or fail
    /// for capacity, so absolute indices stay valid.
    pub(crate) fn reserve_record(&mut self, total: usize, fixed: usize) -> Result<usize> {
        debug_assert!(fixed <= total);
        self.spare_capacity_mut(total)?;
        let start = self.storage.len();
        self.extend_zeroed(fixed);
        Ok(start)
    }

    /// Copy `bytes` into the uninitialized tail and commit them.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.spare_capacity_mut(bytes.len())?[..bytes.len()].write_copy_of_slice(bytes);
        // SAFETY: the bounds-checked write initialized `bytes.len()` spare bytes.
        unsafe { self.storage.set_len(self.storage.len() + bytes.len()) };
        Ok(())
    }

    /// Zero-fill and commit `n` spare bytes. The slice index bounds `n` by
    /// the allocation; callers have already checked it against `max`.
    fn extend_zeroed(&mut self, n: usize) {
        self.storage.spare_capacity_mut()[..n].fill(MaybeUninit::new(0));
        // SAFETY: the bounds-checked fill initialized `n` spare bytes.
        unsafe { self.storage.set_len(self.storage.len() + n) };
    }

    /// Zero-commit up to absolute index `end` inside capacity a record
    /// reservation holds. Committed bytes are never touched.
    pub(crate) fn zero_extend_to(&mut self, end: usize) {
        if let Some(n) = end.checked_sub(self.storage.len()) {
            self.extend_zeroed(n);
        }
    }

    /// Move the committed end of a reserved record to absolute `end`,
    /// zero-filling reserved capacity or dropping unused bytes.
    pub(crate) fn set_record_end(&mut self, end: usize) {
        debug_assert!(end >= self.start);
        if end > self.storage.len() {
            self.zero_extend_to(end);
        } else {
            self.storage.truncate(end);
        }
    }

    /// Entire uninitialized tail without compaction. The caller may initialize
    /// a prefix of it (for example through Tokio `ReadBuf::uninit`) and then
    /// commit with [`Self::commit`].
    pub(crate) fn spare_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        let writable = self.capacity().min(self.max) - self.storage.len();
        let spare = self.storage.spare_capacity_mut();
        &mut spare[..writable]
    }

    /// Zero-fill `n` bytes of spare and commit them. Returns the start index after compact.
    pub fn reserve_zeroed(&mut self, n: usize) -> Result<usize> {
        if n == 0 {
            return Ok(self.storage.len());
        }
        self.spare_capacity_mut(n)?;
        let start = self.storage.len();
        self.extend_zeroed(n);
        Ok(start)
    }

    /// # Safety
    ///
    /// `storage[old_len..old_len + n]` must already be initialized.
    ///
    /// A bare length is not an initialization proof:
    /// ```compile_fail
    /// let mut buffer = snell_protocol::Buffer::new(16);
    /// buffer.commit(16).unwrap();
    /// ```
    pub unsafe fn commit(&mut self, n: usize) -> Result<()> {
        let writable = self.capacity().min(self.max) - self.storage.len();
        if n > writable {
            return Err(Error::BufferTooSmall {
                needed: self.storage.len().saturating_add(n),
                available: self.storage.len() + writable,
            });
        }
        let new_len = self.storage.len() + n;
        unsafe {
            self.storage.set_len(new_len);
        }
        Ok(())
    }

    pub(crate) fn range_mut(&mut self, start: usize, end: usize) -> &mut [u8] {
        &mut self.storage[start..end]
    }

    /// Indices are absolute in `storage` and invalid across compact.
    pub(crate) fn truncate(&mut self, len: usize) -> Result<()> {
        if len < self.start || len > self.storage.len() {
            return Err(Error::BufferTooSmall {
                needed: len,
                available: self.storage.len(),
            });
        }
        self.storage.truncate(len);
        Ok(())
    }

    pub fn consume(&mut self, written: usize) -> Result<()> {
        let remaining = self.storage.len() - self.start;
        if written > remaining {
            return Err(Error::BufferTooSmall {
                needed: written,
                available: remaining,
            });
        }
        self.start += written;
        if self.start == self.storage.len() {
            self.storage.clear();
            self.start = 0;
        }
        Ok(())
    }

    fn compact(&mut self) {
        if self.start == 0 {
            return;
        }
        let live = self.storage.len() - self.start;
        let end = self.storage.len();
        self.storage.copy_within(self.start..end, 0);
        self.storage.truncate(live);
        self.start = 0;
    }
}

/// Payload slot of one reserved record.
///
/// Offsets are absolute in [`Buffer`] storage. [`Buffer::reserve_record`]
/// guarantees they stay valid until the record is sealed or cancelled.
#[derive(Clone, Copy, Debug)]
pub struct Slot {
    pub(crate) record_start: usize,
    pub(crate) payload_start: usize,
    /// Bytes copied in front of the caller's payload at reserve time.
    pub(crate) prefix_len: usize,
    /// Payload capacity, including the prefix.
    pub(crate) max_payload: usize,
}

/// A record reserved in a [`Buffer`] by a [`RecordEncoder`]: write the
/// payload, then seal it. Dropping it unsealed cancels the record.
///
/// The payload is written either through [`payload_mut`](Self::payload_mut)
/// and sealed with [`seal`](Self::seal), or read straight into
/// [`payload_uninit`](Self::payload_uninit) and sealed with
/// [`seal_init`](Self::seal_init), which skips zero-filling it first.
#[must_use = "unsealed reservations are cancelled on drop"]
pub struct Reservation<'a, E: RecordEncoder> {
    encoder: &'a mut E,
    buf: &'a mut Buffer,
    slot: Slot,
    record: E::Record,
}

impl<'a, E: RecordEncoder> Reservation<'a, E> {
    /// Hold `slot` for `encoder` once its prefix has been written. The
    /// encoder stays `Reserving` until the record is sealed or cancelled.
    pub(crate) fn new(
        encoder: &'a mut E,
        buf: &'a mut Buffer,
        slot: Slot,
        record: E::Record,
    ) -> Self {
        *encoder.state() = EncoderState::Reserving;
        Self {
            encoder,
            buf,
            slot,
            record,
        }
    }

    /// Payload bytes available after the prefix.
    pub fn capacity(&self) -> usize {
        self.slot.max_payload - self.slot.prefix_len
    }

    /// The zero-filled payload after the prefix.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let end = self.slot.payload_start + self.slot.max_payload;
        self.buf.zero_extend_to(end);
        self.buf.range_mut(self.unwritten_start(), end)
    }

    /// The uninitialized payload after the prefix, for example for Tokio's
    /// `ReadBuf::uninit`. Empty once [`payload_mut`](Self::payload_mut) has
    /// zero-filled it.
    pub fn payload_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        if self.buf.end() != self.unwritten_start() {
            return &mut [];
        }
        let capacity = self.capacity();
        &mut self.buf.spare_uninit()[..capacity]
    }

    /// Seal `written` bytes of [`payload_mut`](Self::payload_mut). Returns
    /// the record's split: send `[split..]` of the record, then `[..split]`.
    pub fn seal(mut self, written: usize) -> Result<usize> {
        let total = self.total(written)?;
        if self.buf.end() < self.slot.payload_start + total {
            return Err(Error::PendingWire);
        }
        self.finish(total)
    }

    /// Seal `written` bytes initialized in
    /// [`payload_uninit`](Self::payload_uninit). Returns the record's split,
    /// as [`seal`](Self::seal) does.
    ///
    /// # Safety
    /// The first `written` bytes of `payload_uninit()` must have been
    /// initialized since the reservation was created.
    pub unsafe fn seal_init(mut self, written: usize) -> Result<usize> {
        let total = self.total(written)?;
        if self.buf.end() != self.unwritten_start() {
            return Err(Error::PendingWire);
        }
        // SAFETY: the caller initialized these bytes of `payload_uninit`,
        // which starts at the committed end of `buf`.
        unsafe { self.buf.commit(written)? };
        self.finish(total)
    }

    /// Absolute index just past the prefix, where the caller's bytes go.
    fn unwritten_start(&self) -> usize {
        self.slot.payload_start + self.slot.prefix_len
    }

    /// Payload length for `written` bytes after the prefix.
    fn total(&self, written: usize) -> Result<usize> {
        self.slot
            .prefix_len
            .checked_add(written)
            .filter(|&total| total <= self.slot.max_payload)
            .ok_or(Error::PayloadTooLarge)
    }

    fn finish(&mut self, payload_len: usize) -> Result<usize> {
        self.encoder
            .finish(self.buf, &self.slot, &self.record, payload_len)
    }
}

impl<E: RecordEncoder> Drop for Reservation<'_, E> {
    fn drop(&mut self) {
        let state = self.encoder.state();
        if *state == EncoderState::Reserving {
            *state = EncoderState::Ready;
            let _ = self.buf.truncate(self.slot.record_start);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FixedClock, Psk, RepeatEntropy, SALT_LEN, V4Encoder, V6_WIRE_CAP, V6ShapedEncoder,
        V6UnshapedEncoder,
    };

    /// `seal_init` over `payload_uninit` is byte-identical to `seal` over
    /// `payload_mut` for first, prefixed, and short records. Mixing the two
    /// fails closed, cancels the record, and leaves the encoder usable.
    fn assert_seal_init_parity<E: RecordEncoder>(make: impl Fn(&Psk) -> E) {
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let (mut a_enc, mut b_enc) = (make(&psk), make(&psk));
        let mut a = Buffer::new(V6_WIRE_CAP);
        let mut b = Buffer::new(V6_WIRE_CAP);
        for (prefix, msg, hint) in [
            (&b""[..], &b"hello"[..], 5),
            (b"pfx", b"steady", 6),
            (b"", b"abc", 8),
        ] {
            let mut rec = a_enc.reserve(&mut a, prefix, hint).unwrap();
            rec.payload_mut()[..msg.len()].copy_from_slice(msg);
            rec.seal(msg.len()).unwrap();

            let mut rec = b_enc.reserve(&mut b, prefix, hint).unwrap();
            rec.payload_uninit()[..msg.len()].write_copy_of_slice(msg);
            // SAFETY: the preceding write initialized `msg.len()` bytes.
            unsafe { rec.seal_init(msg.len()) }.unwrap();
        }
        assert_eq!(a.filled(), b.filled());

        a.consume(a.len()).unwrap();
        let mut rec = a_enc.reserve(&mut a, &[], 5).unwrap();
        rec.payload_mut()[..5].copy_from_slice(b"hello");
        assert!(rec.payload_uninit().is_empty());
        // SAFETY: `payload_mut` initialized the payload.
        assert_eq!(unsafe { rec.seal_init(5) }, Err(Error::PendingWire));
        assert!(a.is_empty(), "a failed seal cancels the record");
        let mut rec = a_enc.reserve(&mut a, &[], 5).unwrap();
        rec.payload_mut()[..5].copy_from_slice(b"hello");
        rec.seal(5).unwrap();
        assert!(!a.is_empty());
    }

    #[test]
    #[cfg_attr(miri, ignore = "ring's AES-GCM is foreign code")]
    fn v4_seal_init_parity() {
        assert_seal_init_parity(|psk| {
            V4Encoder::with_salt(
                psk,
                [7; SALT_LEN],
                32,
                RepeatEntropy { byte: 0x3c },
                FixedClock::new(0),
            )
            .unwrap()
        });
    }

    #[test]
    #[cfg_attr(miri, ignore = "ring's AES-GCM is foreign code")]
    fn v6_unshaped_seal_init_parity() {
        assert_seal_init_parity(|psk| V6UnshapedEncoder::with_salt(psk, [7; SALT_LEN]).unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore = "ring's AES-GCM is foreign code")]
    fn v6_shaped_seal_init_parity() {
        assert_seal_init_parity(|psk| {
            V6ShapedEncoder::with_salt(psk, [7; SALT_LEN], FixedClock::new(0)).unwrap()
        });
    }

    /// The raw codec has no AEAD, so this runs under Miri as well.
    #[cfg(feature = "unsafe-raw")]
    #[test]
    fn v6_raw_seal_init_parity() {
        assert_seal_init_parity(|_| crate::V6UnsafeRawEncoder::new());
    }

    #[test]
    #[cfg_attr(miri, ignore = "ring's AES-GCM is foreign code")]
    fn seal_requires_a_written_payload() {
        let psk = Psk::new(b"0123456789abcdef").unwrap();
        let mut encoder = V6UnshapedEncoder::with_salt(&psk, [7; SALT_LEN]).unwrap();
        let mut out = Buffer::new(V6_WIRE_CAP);
        let rec = encoder.reserve(&mut out, &[], 5).unwrap();
        assert_eq!(rec.seal(5), Err(Error::PendingWire));
        assert!(out.is_empty(), "a failed seal cancels the record");
        encoder.reserve(&mut out, &[], 5).unwrap().seal(0).unwrap();
        assert!(!out.is_empty());
    }

    #[test]
    fn failed_reservation_does_not_move_live_bytes() {
        let mut buf = Buffer::empty(16);
        buf.replace_storage(Vec::with_capacity(8)).unwrap();
        buf.extend_from_slice(b"abcdefgh").unwrap();
        buf.consume(6).unwrap();
        let ptr = buf.filled().as_ptr();
        assert!(buf.spare_capacity_mut(7).is_err());
        assert_eq!(buf.filled().as_ptr(), ptr);
        assert_eq!(buf.filled(), b"gh");
    }

    #[test]
    fn recv_compact_only_when_needed() {
        let mut buf = Buffer::new(8);
        buf.extend_from_slice(b"abcd").unwrap();
        buf.consume(2).unwrap();
        buf.extend_from_slice(b"efghij").unwrap();
        assert_eq!(buf.filled(), b"cdefghij");
    }

    #[test]
    fn spare_returns_entire_tail_not_min() {
        let mut buf = Buffer::new(64);
        let spare = buf.spare_capacity_mut(2).unwrap();
        assert!(spare.len() >= 2);
        assert_eq!(spare.len(), 64);
    }

    #[test]
    fn does_not_compact_when_tail_already_fits() {
        let mut buf = Buffer::new(8);
        buf.extend_from_slice(b"abcd").unwrap();
        buf.consume(2).unwrap();
        let spare = buf.spare_capacity_mut(1).unwrap();
        assert_eq!(spare.len(), 4);
        assert_eq!(buf.filled(), b"cd");
    }

    #[test]
    fn commit_rejects_past_writable_tail() {
        let mut buf = Buffer::new(8);
        buf.extend_from_slice(b"ab").unwrap();
        assert_eq!(
            unsafe { buf.commit(7) },
            Err(Error::BufferTooSmall {
                needed: 9,
                available: 8,
            })
        );
        assert_eq!(buf.filled(), b"ab");
    }

    #[test]
    fn consume_rejects_past_filled() {
        let mut buf = Buffer::new(8);
        buf.extend_from_slice(b"ab").unwrap();
        assert_eq!(
            buf.consume(3),
            Err(Error::BufferTooSmall {
                needed: 3,
                available: 2,
            })
        );
        assert_eq!(buf.filled(), b"ab");
        buf.consume(2).unwrap();
        assert!(buf.is_empty());
        let spare = buf.spare_capacity_mut(1).unwrap();
        assert_eq!(spare.len(), 8);
    }

    #[test]
    fn encode_buffer_partial_advance_is_contiguous() {
        let mut buf = Buffer::new(64);
        buf.reserve_zeroed(5).unwrap();
        buf.range_mut(0, 5).copy_from_slice(b"hello");
        buf.reserve_zeroed(5).unwrap();
        buf.range_mut(5, 10).copy_from_slice(b"world");
        assert_eq!(buf.filled(), b"helloworld");
        buf.consume(3).unwrap();
        assert_eq!(buf.filled(), b"loworld");
        buf.consume(7).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn encode_buffer_compacts_unsent_when_tail_is_short() {
        let mut buf = Buffer::new(8);
        buf.reserve_zeroed(6).unwrap();
        buf.range_mut(0, 6).copy_from_slice(b"abcdef");
        buf.consume(4).unwrap();
        buf.reserve_zeroed(6).unwrap();
        buf.range_mut(buf.filled_len() - 6, buf.filled_len())
            .copy_from_slice(b"ghijkl");
        assert_eq!(buf.filled(), b"efghijkl");
    }

    #[test]
    fn commit_init_advances_filled() {
        let mut buf = Buffer::new(8);
        let spare = buf.spare_capacity_mut(2).unwrap();
        spare[..2].write_copy_of_slice(b"ab");
        // SAFETY: the preceding write initialized two spare bytes.
        unsafe {
            buf.commit(2).unwrap();
        }
        assert_eq!(buf.filled(), b"ab");
    }

    #[test]
    fn reserve_record_commits_only_fixed_part() {
        let mut buf = Buffer::new(64);
        let start = buf.reserve_record(16, 4).unwrap();
        assert_eq!(start, 0);
        assert_eq!(buf.end(), 4);
        assert_eq!(buf.range_mut(0, 4), &[0u8; 4]);
        // Remaining record bytes commit without compaction or capacity errors.
        buf.extend_from_slice(b"abcd").unwrap();
        let spare = buf.spare_uninit();
        spare[..4].write_copy_of_slice(b"efgh");
        // SAFETY: the preceding write initialized four spare bytes.
        unsafe {
            buf.commit(4).unwrap();
        }
        buf.reserve_zeroed(4).unwrap();
        assert_eq!(buf.end(), 16);
        assert_eq!(buf.filled(), b"\0\0\0\0abcdefgh\0\0\0\0");
    }

    #[test]
    fn reserve_record_compacts_once_and_rejects_oversize() {
        let mut buf = Buffer::new(8);
        buf.reserve_zeroed(6).unwrap();
        buf.range_mut(0, 6).copy_from_slice(b"abcdef");
        buf.consume(4).unwrap();
        let start = buf.reserve_record(6, 2).unwrap();
        assert_eq!(start, 2, "compacted so the record fits the tail");
        assert_eq!(buf.filled(), b"ef\0\0");
        assert_eq!(buf.reserve_record(64, 0), Err(Error::PayloadTooLarge));
    }

    #[test]
    fn truncate_rejects_below_sent_or_past_len() {
        let mut buf = Buffer::new(16);
        buf.reserve_zeroed(8).unwrap();
        buf.consume(3).unwrap();
        assert!(buf.truncate(2).is_err());
        assert!(buf.truncate(9).is_err());
        buf.truncate(6).unwrap();
        assert_eq!(buf.filled().len(), 3);
    }
}

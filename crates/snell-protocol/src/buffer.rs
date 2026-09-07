#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::mem::MaybeUninit;

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
        if self.capacity().min(self.max) - self.storage.len() < min {
            self.compact();
        }
        let writable = self.capacity().min(self.max) - self.storage.len();
        if writable < min {
            return Err(Error::BufferTooSmall {
                needed: self.len() + min,
                available: self.capacity(),
            });
        }
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
        let spare = self.spare_capacity_mut(total)?;
        spare[..fixed].fill(MaybeUninit::new(0));
        // SAFETY: `fill` initialized `fixed` bytes of the tail.
        unsafe {
            self.commit(fixed)?;
        }
        Ok(self.storage.len() - fixed)
    }

    /// Copy `bytes` into the uninitialized tail and commit them.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let spare = self.spare_capacity_mut(bytes.len())?;
        spare[..bytes.len()].write_copy_of_slice(bytes);
        // SAFETY: `write_copy_of_slice` initialized `bytes.len()` bytes of the tail.
        unsafe { self.commit(bytes.len()) }
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
        let spare = self.spare_capacity_mut(n)?;
        spare[..n].fill(MaybeUninit::new(0));
        // SAFETY: `fill` initialized `n` bytes of the tail.
        unsafe {
            self.commit(n)?;
        }
        Ok(self.storage.len() - n)
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

    pub(crate) fn copy_within(&mut self, src: usize, dest: usize, n: usize) {
        self.storage.copy_within(src..src + n, dest);
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

/// Shared reservation `seal_init` bookkeeping: validate the payload slot is
/// still uninitialized spare, then commit `written` caller-initialized bytes.
/// Returns the total payload length including the prefix.
pub(crate) fn commit_init_payload(
    buf: &mut Buffer,
    payload_start: usize,
    prefix_len: usize,
    max_payload: usize,
    written: usize,
) -> Result<usize> {
    let total = prefix_len
        .checked_add(written)
        .ok_or(Error::PayloadTooLarge)?;
    if total > max_payload {
        return Err(Error::PayloadTooLarge);
    }
    if buf.end() != payload_start + prefix_len {
        return Err(Error::PendingWire);
    }
    // SAFETY: the public reservation entry point is unsafe and requires these
    // exact payload bytes to have been initialized. This helper is crate-private.
    unsafe {
        buf.commit(written)?;
    }
    Ok(total)
}

// Unsafe entry points live here, alongside the storage initialization boundary.
impl<E: crate::Entropy, C: crate::Clock> crate::V4Reservation<'_, E, C> {
    /// Seal bytes initialized directly in the uninitialized payload slot.
    ///
    /// # Safety
    /// The first `written` bytes of this reservation's `payload_uninit()`
    /// must have been initialized since the reservation was created.
    pub unsafe fn seal_init(self, written: usize) -> Result<()> {
        self.seal_init_impl(written)
    }
}
impl<E: crate::Entropy, C: crate::Clock> crate::V6ShapedReservation<'_, E, C> {
    /// Seal bytes initialized directly in the uninitialized payload slot.
    ///
    /// # Safety
    /// The first `written` bytes of this reservation's `payload_uninit()`
    /// must have been initialized since the reservation was created.
    pub unsafe fn seal_init(self, written: usize) -> Result<()> {
        self.seal_init_impl(written)
    }
}
impl<E: crate::Entropy, C: crate::Clock> crate::V6UnshapedReservation<'_, E, C> {
    /// Seal bytes initialized directly in the uninitialized payload slot.
    ///
    /// # Safety
    /// The first `written` bytes of this reservation's `payload_uninit()`
    /// must have been initialized since the reservation was created.
    pub unsafe fn seal_init(self, written: usize) -> Result<()> {
        self.seal_init_impl(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::mem::MaybeUninit;

use bytes::{BufMut, buf::UninitSlice};

use crate::{Error, Result};

/// Contiguous receive allocation: `consumed | live | uninitialized cap`.
///
/// Allocation is lazy and grows geometrically up to the hard limit.
/// `storage.len()` is the initialized end. Front `start` is consumed. I/O writes
/// [`Self::spare_capacity_mut`], which is the whole tail, not `min` bytes.
pub struct RecvBuffer {
    storage: Vec<u8>,
    start: usize,
    max: usize,
}

impl RecvBuffer {
    pub fn new(max: usize) -> Self {
        Self {
            storage: Vec::new(),
            start: 0,
            max,
        }
    }

    pub fn len(&self) -> usize {
        self.storage.len() - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.storage.len()
    }

    pub fn filled(&self) -> &[u8] {
        &self.storage[self.start..]
    }

    pub fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.storage[self.start..]
    }

    pub fn max(&self) -> usize {
        self.max
    }

    /// Ensure at least `min` writable bytes, then return the entire uninitialized tail.
    ///
    /// Compacts or grows only when the allocated tail cannot fit `min`.
    /// Call only after outstanding decoded records have been consumed.
    pub fn spare_capacity_mut(&mut self, min: usize) -> Result<&mut [MaybeUninit<u8>]> {
        if self.len().checked_add(min).is_none_or(|n| n > self.max) {
            return Err(Error::PayloadTooLarge);
        }
        if self.storage.capacity().min(self.max) - self.storage.len() < min {
            self.compact();
            grow(&mut self.storage, self.max, min);
        }
        let writable = self.storage.capacity().min(self.max) - self.storage.len();
        Ok(&mut self.storage.spare_capacity_mut()[..writable])
    }

    pub fn capacity(&self) -> usize {
        self.storage.capacity()
    }

    /// Increase the protocol limit without copying buffered bytes.
    pub fn set_max(&mut self, max: usize) -> Result<()> {
        if max < self.max {
            return Err(Error::PayloadTooLarge);
        }
        self.max = max;
        Ok(())
    }

    /// Reclaim idle capacity while preserving any pipelined bytes.
    pub fn shrink_idle(&mut self) {
        self.compact();
        self.storage.shrink_to_fit();
    }

    /// Copy `bytes` into the uninitialized tail. Test and assembler helper.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let spare = self.spare_capacity_mut(bytes.len())?;
        spare[..bytes.len()].write_copy_of_slice(bytes);
        // SAFETY: `write_copy_of_slice` initialized `bytes.len()` bytes of the tail.
        unsafe { self.commit(bytes.len()) }
    }

    /// Advance `len` after the caller has initialized `n` bytes of the spare tail.
    ///
    /// # Safety
    ///
    /// `storage[old_len..old_len + n]` must already be initialized.
    pub unsafe fn commit(&mut self, n: usize) -> Result<()> {
        let writable = self.storage.capacity().min(self.max) - self.storage.len();
        if n > writable {
            return Err(Error::BufferTooSmall {
                needed: self.storage.len().saturating_add(n),
                available: self.storage.len() + writable,
            });
        }
        let new_len = self.storage.len() + n;
        // SAFETY: caller initialized `old_len..new_len`; `n <= writable`.
        unsafe {
            self.storage.set_len(new_len);
        }
        Ok(())
    }

    pub fn consume(&mut self, n: usize) -> Result<()> {
        if n > self.len() {
            return Err(Error::BufferTooSmall {
                needed: n,
                available: self.len(),
            });
        }
        self.start += n;
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

/// Contiguous encode allocation: `sent | unsent bytes | uninitialized spare`.
///
/// The codec writes Snell records directly into the spare and seals in place.
/// TCP is a byte stream: [`Self::pending`] is one slice for `write()`, not
/// one iovec per record.
pub struct EncodeBuffer {
    storage: Vec<u8>,
    sent: usize,
    max: usize,
}

impl EncodeBuffer {
    pub fn new(max: usize) -> Self {
        Self {
            storage: Vec::new(),
            sent: 0,
            max,
        }
    }

    pub fn pending(&self) -> &[u8] {
        &self.storage[self.sent..]
    }

    pub fn is_empty(&self) -> bool {
        self.sent == self.storage.len()
    }

    pub fn len(&self) -> usize {
        self.storage.len() - self.sent
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
        if self.len().checked_add(min).is_none_or(|n| n > self.max) {
            return Err(Error::PayloadTooLarge);
        }
        if self.storage.capacity().min(self.max) - self.storage.len() < min {
            self.compact();
            grow(&mut self.storage, self.max, min);
        }
        let writable = self.storage.capacity().min(self.max) - self.storage.len();
        Ok(&mut self.storage.spare_capacity_mut()[..writable])
    }

    /// An idle encoder must have no pending wire bytes.
    pub fn shrink_idle(&mut self) -> Result<()> {
        if !self.is_empty() {
            return Err(Error::PendingWire);
        }
        self.storage = Vec::new();
        self.sent = 0;
        Ok(())
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
    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<()> {
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
        let writable = self.storage.capacity().min(self.max) - self.storage.len();
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
    pub unsafe fn commit(&mut self, n: usize) -> Result<()> {
        let writable = self.storage.capacity().min(self.max) - self.storage.len();
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
        if len < self.sent || len > self.storage.len() {
            return Err(Error::BufferTooSmall {
                needed: len,
                available: self.storage.len(),
            });
        }
        self.storage.truncate(len);
        Ok(())
    }

    pub fn advance(&mut self, written: usize) -> Result<()> {
        let remaining = self.storage.len() - self.sent;
        if written > remaining {
            return Err(Error::BufferTooSmall {
                needed: written,
                available: remaining,
            });
        }
        self.sent += written;
        if self.sent == self.storage.len() {
            self.storage.clear();
            self.sent = 0;
        }
        Ok(())
    }

    fn compact(&mut self) {
        if self.sent == 0 {
            return;
        }
        let live = self.storage.len() - self.sent;
        let end = self.storage.len();
        self.storage.copy_within(self.sent..end, 0);
        self.storage.truncate(live);
        self.sent = 0;
    }
}

/// A bounded, append-only payload writer. Initialized length can advance only
/// through `BufMut`'s unsafe contract or its safe copying methods.
pub struct PayloadBuffer<'a> {
    buf: &'a mut EncodeBuffer,
    end: usize,
}

impl<'a> PayloadBuffer<'a> {
    pub(crate) fn new(buf: &'a mut EncodeBuffer, end: usize) -> Self {
        Self { buf, end }
    }
}

// SAFETY: chunks expose only reserved spare capacity, and advance_mut requires
// the caller to have initialized exactly the bytes being committed.
unsafe impl BufMut for PayloadBuffer<'_> {
    fn remaining_mut(&self) -> usize {
        self.end.saturating_sub(self.buf.end())
    }

    fn chunk_mut(&mut self) -> &mut UninitSlice {
        let n = self.remaining_mut();
        UninitSlice::uninit(&mut self.buf.spare_uninit()[..n])
    }

    unsafe fn advance_mut(&mut self, n: usize) {
        assert!(
            n <= self.remaining_mut(),
            "payload initialization exceeds reservation"
        );
        // SAFETY: BufMut caller initialized n bytes, and n is within the slot.
        unsafe { self.buf.commit(n).expect("reserved payload capacity") };
    }
}

// SAFETY: the I/O adapter prepares capacity first. No safe method exposes
// uninitialized bytes as u8; only an unsafe advance commits them.
unsafe impl BufMut for RecvBuffer {
    fn remaining_mut(&self) -> usize {
        self.storage.capacity().min(self.max) - self.storage.len()
    }

    fn chunk_mut(&mut self) -> &mut UninitSlice {
        let n = self.remaining_mut();
        UninitSlice::uninit(&mut self.storage.spare_capacity_mut()[..n])
    }

    unsafe fn advance_mut(&mut self, n: usize) {
        // SAFETY: BufMut caller initialized n bytes. commit checks the bound.
        unsafe { self.commit(n).expect("prepared receive capacity") };
    }
}

fn grow(storage: &mut Vec<u8>, max: usize, additional: usize) {
    let needed = storage.len() + additional;
    if needed > storage.capacity() {
        let target = needed
            .max(storage.capacity().saturating_mul(2))
            .max(4096)
            .min(max);
        storage.reserve_exact(target - storage.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recv_compact_only_when_needed() {
        let mut buf = RecvBuffer::new(8);
        buf.extend_from_slice(b"abcd").unwrap();
        buf.consume(2).unwrap();
        buf.extend_from_slice(b"efghij").unwrap();
        assert_eq!(buf.filled(), b"cdefghij");
    }

    #[test]
    fn spare_returns_entire_tail_not_min() {
        let mut buf = RecvBuffer::new(64);
        let spare = buf.spare_capacity_mut(2).unwrap();
        assert!(spare.len() >= 2);
        assert_eq!(spare.len(), 64);
    }

    #[test]
    fn does_not_compact_when_tail_already_fits() {
        let mut buf = RecvBuffer::new(8);
        buf.extend_from_slice(b"abcd").unwrap();
        buf.consume(2).unwrap();
        let spare = buf.spare_capacity_mut(1).unwrap();
        assert_eq!(spare.len(), 4);
        assert_eq!(buf.filled(), b"cd");
    }

    #[test]
    fn commit_rejects_past_writable_tail() {
        let mut buf = RecvBuffer::new(8);
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
        let mut buf = RecvBuffer::new(8);
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
        let mut buf = EncodeBuffer::new(64);
        buf.reserve_zeroed(5).unwrap();
        buf.range_mut(0, 5).copy_from_slice(b"hello");
        buf.reserve_zeroed(5).unwrap();
        buf.range_mut(5, 10).copy_from_slice(b"world");
        assert_eq!(buf.pending(), b"helloworld");
        buf.advance(3).unwrap();
        assert_eq!(buf.pending(), b"loworld");
        buf.advance(7).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn encode_buffer_compacts_unsent_when_tail_is_short() {
        let mut buf = EncodeBuffer::new(8);
        buf.reserve_zeroed(6).unwrap();
        buf.range_mut(0, 6).copy_from_slice(b"abcdef");
        buf.advance(4).unwrap();
        buf.reserve_zeroed(6).unwrap();
        buf.range_mut(buf.filled_len() - 6, buf.filled_len())
            .copy_from_slice(b"ghijkl");
        assert_eq!(buf.pending(), b"efghijkl");
    }

    #[test]
    fn initialized_commit_advances_filled() {
        let mut buf = RecvBuffer::new(8);
        let spare = buf.spare_capacity_mut(2).unwrap();
        spare[..2].write_copy_of_slice(b"ab");
        // SAFETY: the preceding write initialized both bytes.
        unsafe { buf.commit(2).unwrap() };
        assert_eq!(buf.filled(), b"ab");
    }

    #[test]
    fn reserve_record_commits_only_fixed_part() {
        let mut buf = EncodeBuffer::new(64);
        let start = buf.reserve_record(16, 4).unwrap();
        assert_eq!(start, 0);
        assert_eq!(buf.end(), 4);
        assert_eq!(buf.range_mut(0, 4), &[0u8; 4]);
        // Remaining record bytes commit without compaction or capacity errors.
        buf.extend_from_slice(b"abcd").unwrap();
        let spare = buf.spare_uninit();
        spare[..4].write_copy_of_slice(b"efgh");
        // SAFETY: the preceding write initialized all four bytes.
        unsafe { buf.commit(4).unwrap() };
        buf.reserve_zeroed(4).unwrap();
        assert_eq!(buf.end(), 16);
        assert_eq!(buf.pending(), b"\0\0\0\0abcdefgh\0\0\0\0");
    }

    #[test]
    fn reserve_record_compacts_once_and_rejects_oversize() {
        let mut buf = EncodeBuffer::new(8);
        buf.reserve_zeroed(6).unwrap();
        buf.range_mut(0, 6).copy_from_slice(b"abcdef");
        buf.advance(4).unwrap();
        let start = buf.reserve_record(6, 2).unwrap();
        assert_eq!(start, 2, "compacted so the record fits the tail");
        assert_eq!(buf.pending(), b"ef\0\0");
        assert_eq!(buf.reserve_record(64, 0), Err(Error::PayloadTooLarge));
    }

    #[test]
    fn truncate_rejects_below_sent_or_past_len() {
        let mut buf = EncodeBuffer::new(16);
        buf.reserve_zeroed(8).unwrap();
        buf.advance(3).unwrap();
        assert!(buf.truncate(2).is_err());
        assert!(buf.truncate(9).is_err());
        buf.truncate(6).unwrap();
        assert_eq!(buf.pending().len(), 3);
    }

    #[test]
    fn capacity_is_lazy_and_idle_buffers_release_backing_storage() {
        let mut recv = RecvBuffer::new(crate::V6_WIRE_CAP);
        let mut encode = EncodeBuffer::new(crate::V6_WIRE_CAP);
        assert_eq!(recv.capacity(), 0);
        assert_eq!(encode.capacity(), 0);
        recv.extend_from_slice(b"small").unwrap();
        assert!(recv.capacity() < crate::V6_WIRE_CAP);
        recv.extend_from_slice(&vec![0xA5; 60_000]).unwrap();
        recv.consume(recv.len()).unwrap();
        recv.shrink_idle();
        encode.reserve_zeroed(60_000).unwrap();
        assert!(encode.shrink_idle().is_err());
        encode.advance(encode.len()).unwrap();
        encode.shrink_idle().unwrap();
        assert_eq!(recv.capacity(), 0);
        assert_eq!(encode.capacity(), 0);
    }

    #[test]
    fn shrinking_preserves_pipelined_data_and_protocol_limit() {
        let mut recv = RecvBuffer::new(crate::V6_WIRE_CAP);
        let data = vec![0xA5; 50_000];
        recv.extend_from_slice(&data).unwrap();
        recv.consume(123).unwrap();
        recv.shrink_idle();
        assert_eq!(recv.filled(), &data[123..]);
        assert_eq!(recv.max(), crate::V6_WIRE_CAP);
        recv.consume(recv.len()).unwrap();
        recv.extend_from_slice(&vec![1; crate::V6_WIRE_CAP])
            .unwrap();
        assert_eq!(recv.len(), crate::V6_WIRE_CAP);
        assert!(recv.extend_from_slice(&[1]).is_err());
    }

    #[test]
    fn warmed_buffers_do_not_reallocate() {
        let mut recv = RecvBuffer::new(crate::V6_WIRE_CAP);
        recv.extend_from_slice(&vec![0; crate::V6_WIRE_CAP])
            .unwrap();
        let ptr = recv.filled().as_ptr();
        let capacity = recv.capacity();
        for _ in 0..100 {
            recv.consume(recv.len()).unwrap();
            recv.extend_from_slice(&[1; 16383]).unwrap();
            assert_eq!(recv.filled().as_ptr(), ptr);
            assert_eq!(recv.capacity(), capacity);
        }
    }

    #[test]
    fn payload_bufmut_commits_only_initialized_bytes() {
        let mut encode = EncodeBuffer::new(64);
        encode.reserve_record(32, 4).unwrap();
        {
            let mut slot = PayloadBuffer::new(&mut encode, 16);
            slot.put_slice(b"hello");
            slot.put_slice(b"world");
            assert_eq!(slot.remaining_mut(), 2);
        }
        assert_eq!(encode.pending(), b"\0\0\0\0helloworld");
    }
}

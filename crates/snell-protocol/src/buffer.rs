#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::mem::MaybeUninit;

use bytes::{BufMut, buf::UninitSlice};

use crate::{Error, Result};

/// Contiguous receive allocation: `consumed | live | uninitialized cap`.
///
/// Allocation is lazy and grows geometrically, bounded by the legal wire limit.
/// `storage.len()` is the initialized end; `start` is consumed. `BufMut` allows
/// an I/O adapter to append initialized bytes without zeroing or copying them.
///
/// Advancing uninitialized storage requires an explicit unsafe contract:
/// ```compile_fail
/// use bytes::BufMut;
/// let mut buf = snell_protocol::RecvBuffer::new(4096);
/// buf.advance_mut(1);
/// ```
pub struct RecvBuffer {
    storage: Vec<u8>,
    start: usize,
    max: usize,
    saturated: bool,
}

impl RecvBuffer {
    pub fn new(max: usize) -> Self {
        Self {
            storage: Vec::new(),
            start: 0,
            max,
            saturated: false,
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

    pub fn capacity(&self) -> usize {
        self.storage.capacity()
    }

    /// Enlarge a probe's legal limit without reallocating or moving live data.
    pub fn raise_limit(&mut self, max: usize) {
        self.max = self.max.max(max);
    }

    /// Keep only live bytes and a small receive window while idle.
    /// Call only when no decoded records still refer to the previous layout.
    pub fn shrink_idle(&mut self) {
        self.compact();
        self.saturated = false;
        let target = self.len().max(4096).min(self.max);
        if self.storage.capacity() > target {
            self.storage.shrink_to(target);
        }
    }

    /// Ensure at least `min` writable bytes, then return the entire uninitialized tail.
    ///
    /// Compacts only when the tail is too short. A full read allows the next
    /// read to grow its window, so bulk traffic is not stuck at the initial size.
    pub fn spare_capacity_mut(&mut self, min: usize) -> Result<&mut [MaybeUninit<u8>]> {
        if self.len().checked_add(min).is_none_or(|n| n > self.max) {
            return Err(Error::PayloadTooLarge);
        }
        if self.storage.capacity().min(self.max) - self.storage.len() < min {
            self.compact();
        }
        let demand = self.storage.len() + min;
        let target = if self.saturated && self.storage.capacity() < self.max {
            demand
                .max(self.storage.capacity().saturating_mul(2))
                .min(self.max)
        } else {
            demand
        };
        grow(&mut self.storage, target, self.max);
        self.saturated = false;
        let writable = self.storage.capacity().min(self.max) - self.storage.len();
        Ok(&mut self.storage.spare_capacity_mut()[..writable])
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
        self.saturated = n > 0 && n == writable;
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

    /// Release empty backing storage; pending wire is never discarded.
    pub fn shrink_idle(&mut self) {
        if self.is_empty() {
            self.storage = Vec::new();
            self.sent = 0;
        }
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
        }
        let demand = self.storage.len() + min;
        grow(&mut self.storage, demand, self.max);
        let writable = self.storage.capacity().min(self.max) - self.storage.len();
        Ok(&mut self.storage.spare_capacity_mut()[..writable])
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

/// Shared bounded growth; length remains the initialized prefix.
fn grow(storage: &mut Vec<u8>, needed: usize, max: usize) {
    if needed > storage.capacity() {
        let target = needed
            .checked_next_power_of_two()
            .unwrap_or(max)
            .max(4096)
            .min(max);
        storage.reserve_exact(target - storage.len());
    }
}

// SAFETY: chunk_mut exposes only writable tail storage. advance_mut's caller
// must initialize exactly the prefix being committed, as required by BufMut.
unsafe impl BufMut for RecvBuffer {
    fn remaining_mut(&self) -> usize {
        self.max - self.len()
    }

    fn chunk_mut(&mut self) -> &mut UninitSlice {
        if self.remaining_mut() == 0 {
            return UninitSlice::new(&mut []);
        }
        UninitSlice::uninit(
            self.spare_capacity_mut(1)
                .expect("remaining receive capacity"),
        )
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        // SAFETY: the BufMut caller initialized cnt bytes in chunk_mut().
        unsafe { self.commit(cnt).expect("initialized receive tail") }
    }
}

// Reservation fields are crate-private only so the unsafe BufMut implementation
// can stay in this module. No codec or runtime is trusted to commit a bare usize.
macro_rules! reservation_buf_mut {
    ($reservation:ident) => {
        // SAFETY: the slot was reserved before this implementation is exposed.
        // Remaining length excludes headers, padding, prefixes and the AEAD tag.
        unsafe impl<E: crate::Entropy, C: crate::Clock> BufMut for crate::$reservation<'_, E, C> {
            fn remaining_mut(&self) -> usize {
                (self.encoder.payload_start + self.encoder.max_payload)
                    .saturating_sub(self.buf.end())
            }

            fn chunk_mut(&mut self) -> &mut UninitSlice {
                let remaining = self.remaining_mut();
                UninitSlice::uninit(&mut self.buf.spare_uninit()[..remaining])
            }

            unsafe fn advance_mut(&mut self, cnt: usize) {
                assert!(
                    cnt <= self.remaining_mut(),
                    "initialized payload exceeds slot"
                );
                // SAFETY: BufMut requires the caller to initialize this prefix.
                unsafe { self.buf.commit(cnt).expect("reserved payload capacity") }
            }
        }
    };
}

reservation_buf_mut!(V4Reservation);
reservation_buf_mut!(V6ShapedReservation);
reservation_buf_mut!(V6UnshapedReservation);

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
    fn initialized_append_advances_filled() {
        let mut buf = RecvBuffer::new(8);
        let spare = buf.spare_capacity_mut(2).unwrap();
        spare[..2].write_copy_of_slice(b"ab");
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
    fn lazy_allocations_and_idle_shrink_preserve_limits_and_live_bytes() {
        let mut recv = RecvBuffer::new(crate::V6_WIRE_CAP);
        let mut encode = EncodeBuffer::new(crate::V6_WIRE_CAP);
        assert_eq!(recv.capacity(), 0);
        assert_eq!(encode.capacity(), 0);
        recv.extend_from_slice(&vec![7; 60_000]).unwrap();
        recv.consume(59_997).unwrap();
        recv.shrink_idle();
        assert_eq!(recv.filled(), &[7; 3]);
        assert!(recv.capacity() <= 4096);
        assert_eq!(recv.max(), crate::V6_WIRE_CAP);
        encode.reserve_zeroed(60_000).unwrap();
        encode.shrink_idle();
        assert_eq!(encode.len(), 60_000, "pending wire must survive idle trim");
        encode.advance(60_000).unwrap();
        encode.shrink_idle();
        assert_eq!(encode.capacity(), 0);
        recv.consume(3).unwrap();
        recv.extend_from_slice(&vec![9; crate::V6_WIRE_CAP])
            .unwrap();
        assert_eq!(recv.len(), crate::V6_WIRE_CAP);
        assert!(recv.extend_from_slice(&[0]).is_err());
    }

    #[test]
    fn probe_upgrade_preserves_live_prefix_without_copying() {
        let mut recv = RecvBuffer::new(4096);
        recv.put_slice(b"prefix");
        let ptr = recv.filled().as_ptr();
        recv.raise_limit(crate::V6_WIRE_CAP);
        assert_eq!(recv.filled().as_ptr(), ptr);
        assert_eq!(recv.filled(), b"prefix");
        recv.put_slice(&vec![1; 32_000]);
        assert_eq!(&recv.filled()[..6], b"prefix");
    }

    #[test]
    fn initialized_buf_mut_does_not_expose_unwritten_tail() {
        let mut recv = RecvBuffer::new(8192);
        recv.put_slice(b"hello");
        assert_eq!(recv.filled(), b"hello");
        recv.consume(5).unwrap();
        recv.put_slice(b"x");
        assert_eq!(recv.filled(), b"x");
    }
}

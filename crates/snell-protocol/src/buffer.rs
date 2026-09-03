#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::mem::MaybeUninit;

use crate::{Error, Result};

/// Default encode-buffer cap: several max v4 records, one allocation per connection.
pub const ENCODE_BUFFER_MAX: usize = 256 * 1024;

/// Contiguous receive allocation: `consumed | live | uninitialized cap`.
///
/// Fixed capacity: `new(max)` does `Vec::with_capacity(max)` and never reallocates.
/// `storage.len()` is the live end. Front `start` is consumed. The kernel writes
/// [`Self::spare_capacity_mut`], which is the whole tail, not `min` bytes.
pub struct RecvBuffer {
    storage: Vec<u8>,
    start: usize,
    max: usize,
}

impl RecvBuffer {
    pub fn new(max: usize) -> Self {
        Self {
            storage: Vec::with_capacity(max),
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
    /// Compacts only when `max - len < min`. Capacity is `>= max` for the lifetime
    /// of the buffer; this never grows.
    pub fn spare_capacity_mut(&mut self, min: usize) -> Result<&mut [MaybeUninit<u8>]> {
        let live = self.len();
        if live.checked_add(min).is_none_or(|needed| needed > self.max) {
            return Err(Error::PayloadTooLarge);
        }
        if self.max - self.storage.len() < min {
            self.compact();
        }
        let writable = self.max - self.storage.len();
        let spare = self.storage.spare_capacity_mut();
        Ok(&mut spare[..writable])
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
        let writable = self.max - self.storage.len();
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
            storage: Vec::with_capacity(max),
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
        let unsent = self.len();
        if unsent
            .checked_add(min)
            .is_none_or(|needed| needed > self.max)
        {
            return Err(Error::PayloadTooLarge);
        }
        if self.max - self.storage.len() < min {
            self.compact();
        }
        let writable = self.max - self.storage.len();
        let spare = self.storage.spare_capacity_mut();
        Ok(&mut spare[..writable])
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
        let writable = self.max - self.storage.len();
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
    fn truncate_rejects_below_sent_or_past_len() {
        let mut buf = EncodeBuffer::new(16);
        buf.reserve_zeroed(8).unwrap();
        buf.advance(3).unwrap();
        assert!(buf.truncate(2).is_err());
        assert!(buf.truncate(9).is_err());
        buf.truncate(6).unwrap();
        assert_eq!(buf.pending().len(), 3);
    }
}

use std::time::Duration;

use crate::protocol::snell::{HEADER_CIPHER_LEN, TAG_LEN};

use super::labels::{
    CHUNK_JITTER_VALUE, CHUNK_SIZE, PAYLOAD_PADDING, WRITE_JITTER_VALUE, WRITE_NEXT, WRITE_TARGET,
};
use super::{
    MAX_EXTRA_TARGET_PADDING, PROFILE_TARGET_DIRECT_LIMIT, PROFILE_TARGET_U16_LIMIT, ShapedProfile,
    isize_from_usize, u32_from_usize, usize_from_isize, usize_from_u32,
};

impl ShapedProfile {
    #[must_use]
    pub(crate) fn final_padding_len(
        &self,
        seq: u32,
        prefix_len: usize,
        payload_len: usize,
        first_frame: bool,
    ) -> usize {
        let mut base_pad = 0;
        if seq < self.pad_count
            || (payload_len != 0 && payload_len <= self.small_limit)
            || seq.is_multiple_of(self.pad_interval)
        {
            base_pad = self.pick(
                PAYLOAD_PADDING,
                seq,
                u32_from_usize(payload_len),
                self.pad_min,
                self.pad_max,
            );
        }

        let mut current_len = prefix_len
            + HEADER_CIPHER_LEN
            + base_pad
            + if payload_len > 0 {
                payload_len + TAG_LEN
            } else {
                0
            };
        if first_frame {
            current_len += self.salt_block_len;
        }

        let target = self.write_target_len(seq, current_len);
        if current_len < target {
            base_pad += MAX_EXTRA_TARGET_PADDING.min(target - current_len);
        }
        base_pad
    }

    #[must_use]
    pub fn chunk_limit(
        &self,
        seq: u32,
        current_chunk_size: usize,
        idle_for: Option<Duration>,
    ) -> usize {
        let current_chunk_size = if idle_for.is_some_and(|idle| idle > self.idle_reset) {
            self.chunk_initial
        } else {
            current_chunk_size
        };
        let mut cur = if current_chunk_size == 0 {
            self.chunk_initial
        } else {
            current_chunk_size
        };
        match self.chunk_policy {
            1 => {
                cur = self.chunk_buckets[usize_from_u32(self.prf32(CHUNK_SIZE, seq, cur as u32))
                    % self.chunk_buckets.len()];
            }
            2 => {
                let span = 2 * self.chunk_jitter + 1;
                let j = isize_from_usize(
                    usize_from_u32(self.prf32(CHUNK_JITTER_VALUE, seq, cur as u32)) % span,
                ) - isize_from_usize(self.chunk_jitter);
                cur = usize_from_isize((isize_from_usize(cur) + j).max(0x40));
            }
            _ => {}
        }
        cur.clamp(0x40, self.chunk_max)
    }

    #[must_use]
    pub(crate) fn advance_chunk_size(
        &self,
        current_chunk_size: usize,
        idle_for: Option<Duration>,
    ) -> usize {
        if current_chunk_size == 0 {
            return self.chunk_initial;
        }
        let current_chunk_size = if idle_for.is_some_and(|idle| idle > self.idle_reset) {
            self.chunk_initial
        } else {
            current_chunk_size
        };
        current_chunk_size
            .saturating_add(self.chunk_step)
            .min(self.chunk_max)
    }

    fn write_target_len(&self, seq: u32, current_len: usize) -> usize {
        if current_len > PROFILE_TARGET_DIRECT_LIMIT {
            return if current_len <= PROFILE_TARGET_U16_LIMIT {
                current_len
            } else {
                u32::MAX as usize
            };
        }

        let mut target = if seq < self.write_first {
            self.write_seq[usize_from_u32(seq)]
        } else {
            self.write_buckets[usize_from_u32(self.prf32(
                WRITE_TARGET,
                seq,
                u32_from_usize(current_len),
            )) % self.write_buckets.len()]
        };

        if self.write_policy == 2 {
            let span = 2 * self.write_jitter + 1;
            let j = isize_from_usize(usize_from_u32(self.prf32(WRITE_JITTER_VALUE, seq, 0)) % span)
                - isize_from_usize(self.write_jitter);
            target = usize_from_isize((isize_from_usize(target) + j).max(1));
        }

        let jitter_bound =
            MAX_EXTRA_TARGET_PADDING.min(self.write_jitter_percent * current_len / 100);
        if self.prf32(WRITE_TARGET, seq, u32_from_usize(jitter_bound)) & 1 == 0 {
            target = target.saturating_add(jitter_bound);
        } else if target > jitter_bound / 2 {
            target -= jitter_bound / 2;
        }

        while current_len > target {
            let cand = self.write_buckets[usize_from_u32(self.prf32(
                WRITE_NEXT,
                seq,
                u32_from_usize(target),
            )) % self.write_buckets.len()];
            if target < cand {
                target = cand;
            } else {
                target = target.saturating_add(self.pad_max);
                if target > u16::MAX as usize {
                    return u32::MAX as usize;
                }
            }
        }

        target
    }
}

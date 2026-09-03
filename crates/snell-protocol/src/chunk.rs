use crate::{
    MAX_PACKET_SIZE, V4_FIRST_RECORD_OVERHEAD, V4_IDLE_RESET_SECS, V4_MSS_BASE, V4_RESET_OVERHEAD,
};

/// Grow the v4 payload budget by one MSS minus reset overhead, capped at [`MAX_PACKET_SIZE`].
pub fn next_v4_chunk_limit(current_limit: usize) -> usize {
    if current_limit > MAX_PACKET_SIZE - 1 {
        current_limit.min(MAX_PACKET_SIZE)
    } else {
        current_limit
            .saturating_add(V4_MSS_BASE)
            .saturating_sub(V4_RESET_OVERHEAD)
            .min(MAX_PACKET_SIZE)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct V4ChunkState {
    salt_sent: bool,
    initial_padding_len: usize,
    chunk_limit: usize,
    last_write_secs: Option<u64>,
}

impl V4ChunkState {
    pub(crate) fn new(initial_padding_len: usize) -> Self {
        Self {
            salt_sent: false,
            initial_padding_len,
            chunk_limit: 0,
            last_write_secs: None,
        }
    }

    pub(crate) fn salt_sent(&self) -> bool {
        self.salt_sent
    }

    pub(crate) fn mark_salt_sent(&mut self) {
        self.salt_sent = true;
    }

    pub(crate) fn initial_padding_len(&self) -> usize {
        self.initial_padding_len
    }

    /// Payload bytes allowed for a record at `now`. Does not roll the window.
    pub(crate) fn payload_limit(&self, now: u64, hint: usize) -> usize {
        hint.min(self.record_budget(now))
    }

    pub(crate) fn record_budget(&self, now: u64) -> usize {
        self.budget(now).min(MAX_PACKET_SIZE)
    }

    /// Roll the congestion window after a record is successfully sealed.
    pub(crate) fn commit_write(&mut self, now: u64, budget: usize) {
        self.chunk_limit = next_v4_chunk_limit(budget.min(MAX_PACKET_SIZE));
        self.last_write_secs = Some(now);
    }

    fn budget(&self, now: u64) -> usize {
        if !self.salt_sent {
            V4_MSS_BASE.saturating_sub(V4_FIRST_RECORD_OVERHEAD + self.initial_padding_len)
        } else if self
            .last_write_secs
            .is_some_and(|last| now.saturating_sub(last) > V4_IDLE_RESET_SECS)
        {
            V4_MSS_BASE.saturating_sub(V4_RESET_OVERHEAD)
        } else if self.chunk_limit != 0 {
            self.chunk_limit
        } else {
            V4_MSS_BASE.saturating_sub(V4_RESET_OVERHEAD)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_record_budget_subtracts_overhead_and_padding() {
        let state = V4ChunkState::new(8);
        assert_eq!(state.budget(0), V4_MSS_BASE - V4_FIRST_RECORD_OVERHEAD - 8);
    }

    #[test]
    fn idle_reset_is_strictly_after_30s() {
        let mut state = V4ChunkState::new(8);
        let first = state.payload_limit(10, MAX_PACKET_SIZE);
        state.commit_write(10, first);
        state.mark_salt_sent();
        assert_eq!(state.budget(40), next_v4_chunk_limit(first));
        assert_eq!(state.budget(41), V4_MSS_BASE - V4_RESET_OVERHEAD);
    }

    #[test]
    fn budget_is_stable_until_commit() {
        let mut state = V4ChunkState::new(8);
        let first = state.payload_limit(0, MAX_PACKET_SIZE);
        assert_eq!(state.payload_limit(0, MAX_PACKET_SIZE), first);
        state.commit_write(0, first);
        state.mark_salt_sent();
        assert_eq!(
            state.payload_limit(0, MAX_PACKET_SIZE),
            next_v4_chunk_limit(first)
        );
    }

    #[test]
    fn chunk_limit_grows_to_max() {
        let mut limit = 64;
        for _ in 0..32 {
            limit = next_v4_chunk_limit(limit);
        }
        assert_eq!(limit, MAX_PACKET_SIZE);
    }
}

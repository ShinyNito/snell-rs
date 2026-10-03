use crate::{
    MAX_PACKET_SIZE, V4_FIRST_RECORD_OVERHEAD, V4_IDLE_RESET_SECS, V4_MSS_BASE, V4_RESET_OVERHEAD,
};

/// Grow the v4 payload budget by one MSS minus reset overhead, capped at [`MAX_PACKET_SIZE`].
pub fn next_v4_chunk_limit(current_limit: usize) -> usize {
    current_limit
        .saturating_add(V4_MSS_BASE)
        .saturating_sub(V4_RESET_OVERHEAD)
        .min(MAX_PACKET_SIZE)
}

/// The last sealed record: when it was sealed and the limit it grew to.
#[derive(Clone, Copy, Debug)]
struct Window {
    sealed_at: u64,
    limit: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct V4ChunkState {
    initial_padding_len: usize,
    /// `None` until the first record, which carries the salt, is sealed.
    last: Option<Window>,
}

impl V4ChunkState {
    pub(crate) fn new(initial_padding_len: usize) -> Self {
        Self {
            initial_padding_len,
            last: None,
        }
    }

    pub(crate) fn salt_sent(&self) -> bool {
        self.last.is_some()
    }

    pub(crate) fn initial_padding_len(&self) -> usize {
        self.initial_padding_len
    }

    /// Payload bytes allowed for a record sealed at `now`, at most
    /// [`MAX_PACKET_SIZE`].
    pub(crate) fn record_budget(&self, now: u64) -> usize {
        match self.last {
            None => V4_MSS_BASE.saturating_sub(V4_FIRST_RECORD_OVERHEAD + self.initial_padding_len),
            Some(last) if now.saturating_sub(last.sealed_at) > V4_IDLE_RESET_SECS => {
                V4_MSS_BASE - V4_RESET_OVERHEAD
            }
            Some(last) => last.limit,
        }
    }

    /// Grow the window from `budget` after a record is sealed at `now`.
    pub(crate) fn commit_write(&mut self, now: u64, budget: usize) {
        self.last = Some(Window {
            sealed_at: now,
            limit: next_v4_chunk_limit(budget),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_record_budget_subtracts_overhead_and_padding() {
        let state = V4ChunkState::new(8);
        assert_eq!(
            state.record_budget(0),
            V4_MSS_BASE - V4_FIRST_RECORD_OVERHEAD - 8
        );
    }

    #[test]
    fn idle_reset_is_strictly_after_30s() {
        let mut state = V4ChunkState::new(8);
        let first = state.record_budget(10);
        assert_eq!(state.record_budget(10), first, "no roll");
        state.commit_write(10, first);
        assert!(state.salt_sent());
        assert_eq!(state.record_budget(40), next_v4_chunk_limit(first));
        assert_eq!(state.record_budget(41), V4_MSS_BASE - V4_RESET_OVERHEAD);
    }

    #[test]
    fn chunk_limit_grows_to_max() {
        let mut limit = 64;
        for _ in 0..32 {
            limit = next_v4_chunk_limit(limit);
        }
        assert_eq!(limit, MAX_PACKET_SIZE);
        assert_eq!(next_v4_chunk_limit(usize::MAX), MAX_PACKET_SIZE);
    }
}

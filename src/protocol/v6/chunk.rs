use super::*;

#[derive(Clone, Debug)]
pub struct V6ChunkSizer {
    profile: V6Profile,
    current_chunk_size: usize,
    last_record_at: Option<Instant>,
}

impl V6ChunkSizer {
    #[must_use]
    pub fn new(profile: V6Profile) -> Self {
        Self {
            profile,
            current_chunk_size: 0,
            last_record_at: None,
        }
    }

    #[must_use]
    pub fn peek_limit(&self, seq: u32, now: Instant) -> usize {
        let current = if self
            .last_record_at
            .is_some_and(|last| now.duration_since(last) > self.profile.idle_reset)
        {
            self.profile.chunk_initial
        } else {
            self.current_chunk_size
        };
        self.profile.chunk_limit(seq, current)
    }

    pub fn commit_record(&mut self, now: Instant) {
        if self
            .last_record_at
            .is_some_and(|last| now.duration_since(last) > self.profile.idle_reset)
        {
            self.current_chunk_size = self.profile.chunk_initial;
        }
        self.current_chunk_size = self.profile.next_chunk_size(self.current_chunk_size);
        self.last_record_at = Some(now);
    }

    #[cfg(test)]
    pub(crate) const fn has_committed_record(&self) -> bool {
        self.last_record_at.is_some()
    }
}

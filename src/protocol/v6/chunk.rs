use super::*;

#[derive(Clone, Debug)]
pub struct V6ChunkSizer {
    current_chunk_size: usize,
    last_record_at: Option<Instant>,
}

impl V6ChunkSizer {
    pub const fn new() -> Self {
        Self {
            current_chunk_size: 0,
            last_record_at: None,
        }
    }

    pub fn peek_limit(&self, profile: &V6Profile, seq: u32, now: Instant) -> usize {
        let current = if self
            .last_record_at
            .is_some_and(|last| now.duration_since(last) > profile.idle_reset)
        {
            profile.chunk_initial
        } else {
            self.current_chunk_size
        };
        profile.chunk_limit(seq, current)
    }

    pub fn commit_record(&mut self, profile: &V6Profile, now: Instant) {
        if self
            .last_record_at
            .is_some_and(|last| now.duration_since(last) > profile.idle_reset)
        {
            self.current_chunk_size = profile.chunk_initial;
        }
        self.current_chunk_size = profile.next_chunk_size(self.current_chunk_size);
        self.last_record_at = Some(now);
    }

    #[cfg(test)]
    pub(crate) const fn has_committed_record(&self) -> bool {
        self.last_record_at.is_some()
    }
}

impl Default for V6ChunkSizer {
    fn default() -> Self {
        Self::new()
    }
}

use std::time::Instant;

/// Monotonic seconds for record sizing windows and idle resets.
pub trait Clock {
    fn monotonic_secs(&self) -> u64;
}

#[derive(Clone, Copy, Debug)]
pub struct FixedClock {
    pub monotonic_secs: u64,
}

impl FixedClock {
    pub const fn new(secs: u64) -> Self {
        Self {
            monotonic_secs: secs,
        }
    }
}

impl Clock for FixedClock {
    fn monotonic_secs(&self) -> u64 {
        self.monotonic_secs
    }
}

/// Seconds elapsed since the clock was created.
#[derive(Clone, Debug)]
pub struct MonotonicClock {
    origin: Instant,
}

impl MonotonicClock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MonotonicClock {
    fn monotonic_secs(&self) -> u64 {
        self.origin.elapsed().as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clocks_report_monotonic_seconds() {
        assert_eq!(FixedClock::new(9).monotonic_secs(), 9);
        assert_eq!(MonotonicClock::new().monotonic_secs(), 0);
    }
}

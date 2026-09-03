use std::time::Instant;

pub trait Clock {
    fn unix_secs(&self) -> u64;
    fn monotonic_secs(&self) -> u64;
}

#[derive(Clone, Copy, Debug)]
pub struct FixedClock {
    pub unix_secs: u64,
    pub monotonic_secs: u64,
}

impl FixedClock {
    pub const fn new(secs: u64) -> Self {
        Self {
            unix_secs: secs,
            monotonic_secs: secs,
        }
    }
}

impl Clock for FixedClock {
    fn unix_secs(&self) -> u64 {
        self.unix_secs
    }

    fn monotonic_secs(&self) -> u64 {
        self.monotonic_secs
    }
}

/// Wall-clock Unix seconds plus process-elapsed monotonic seconds.
#[derive(Clone, Debug)]
pub struct UnixClock {
    origin: Instant,
}

impl UnixClock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for UnixClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for UnixClock {
    fn unix_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }

    fn monotonic_secs(&self) -> u64 {
        self.origin.elapsed().as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock_returns_value() {
        let clock = FixedClock::new(9);
        assert_eq!(clock.unix_secs(), 9);
        assert_eq!(clock.monotonic_secs(), 9);
        let split = FixedClock {
            unix_secs: 100,
            monotonic_secs: 3,
        };
        assert_eq!(split.unix_secs(), 100);
        assert_eq!(split.monotonic_secs(), 3);
    }

    #[test]
    fn unix_clock_monotonic_is_elapsed() {
        let clock = UnixClock::new();
        assert_eq!(clock.monotonic_secs(), 0);
        assert!(clock.unix_secs() > 0);
    }
}

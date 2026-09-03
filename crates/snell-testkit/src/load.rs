//! Repeatable SOCKS5 load helpers. They do not implement Snell.

use std::time::{Duration, Instant};

use crate::oracle::{self, OracleError, ProcessPair};

#[derive(Clone, Copy, Debug)]
pub struct LoadReport {
    pub bytes: u64,
    pub elapsed: Duration,
}

impl LoadReport {
    pub fn bits_per_second(&self) -> f64 {
        if self.elapsed.is_zero() {
            return 0.0;
        }
        (self.bytes as f64) * 8.0 / self.elapsed.as_secs_f64()
    }
}

pub async fn tcp_echo_once(pair: &ProcessPair, payload: &[u8]) -> Result<Vec<u8>, OracleError> {
    oracle::socks5_echo_roundtrip(pair.socks, payload).await
}

pub async fn tcp_echo_throughput(
    pair: &ProcessPair,
    payload: &[u8],
    rounds: usize,
) -> Result<LoadReport, OracleError> {
    let started = Instant::now();
    let mut bytes = 0u64;
    for _ in 0..rounds {
        let echoed = tcp_echo_once(pair, payload).await?;
        if echoed != payload {
            return Err(std::io::Error::other("echo mismatch").into());
        }
        bytes += payload.len() as u64;
    }
    Ok(LoadReport {
        bytes,
        elapsed: started.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_per_second_is_zero_for_empty_elapsed() {
        let report = LoadReport {
            bytes: 8,
            elapsed: Duration::ZERO,
        };
        assert_eq!(report.bits_per_second(), 0.0);
    }
}

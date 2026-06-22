//! SplitMix64 finalizer.
//!
//! This is the canonical Stafford variant 13 SplitMix64 mixer. Every PRF in the
//! Profile derivation (`prf32`, `expand_stream`, namespace derivation) routes
//! its intermediate state through this function, so it must be byte-exact.

/// SplitMix64 mixing constants (Stafford variant 13).
const MUL1: u64 = 0xBF58476D1CE4E5B9;
const MUL2: u64 = 0x94D049BB133111EB;

/// Apply the SplitMix64 finalizer to a 64-bit value.
///
/// ```text
/// x ^= x >> 30
/// x *= 0xBF58476D1CE4E5B9
/// x ^= x >> 27
/// x *= 0x94D049BB133111EB
/// x ^= x >> 31
/// ```
#[inline]
#[must_use]
pub fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(MUL1);
    x ^= x >> 27;
    x = x.wrapping_mul(MUL2);
    x ^= x >> 31;
    x
}

#[cfg(test)]
mod tests {
    use super::super::GOLDEN_GAMMA;
    use super::*;

    /// SplitMix64 with the golden-gamma increment has a well-known reference
    /// sequence (Stafford 2013). `mix(1)` and `mix(2)` are widely cited golden
    /// values; they pin down the finalizer end-to-end.
    #[test]
    fn splitmix64_known_values() {
        // mix(n) = splitmix64(n * GOLDEN_GAMMA), i.e. the classic SplitMix64 stream.
        // Multiplications wrap mod 2^64 — that's the whole point of SplitMix64.
        // Verified against the public reference outputs.
        let s1 = splitmix64(GOLDEN_GAMMA.wrapping_mul(1));
        let s2 = splitmix64(GOLDEN_GAMMA.wrapping_mul(2));
        let s3 = splitmix64(GOLDEN_GAMMA.wrapping_mul(3));

        // Classic SplitMix64(RNG state=0) stream — first three outputs.
        assert_eq!(s1, 0xE220A8397B1DCDAF, "splitmix64(gamma*1)");
        assert_eq!(s2, 0x6E789E6AA1B965F4, "splitmix64(gamma*2)");
        assert_eq!(s3, 0x06C45D188009454F, "splitmix64(gamma*3)");
    }

    /// `splitmix64(0)` is a fixed, easily reproduced value. Guards against
    /// accidental sign-extension or shift mistakes.
    #[test]
    fn splitmix64_zero() {
        // Computed by hand from the formula: all wrapping-mul inputs are 0,
        // only the final shifts touch zero → result is 0.
        assert_eq!(splitmix64(0), 0);
    }

    /// Diffusion sanity check: a single-bit input change must avalanche to a
    /// completely different output. SplitMix64 is designed for this.
    #[test]
    fn splitmix64_avalanche() {
        let a = splitmix64(0xDEADBEEFCAFEBABE);
        let b = splitmix64(0xDEADBEEFCAFEBABF); // flip lowest bit
        // For a proper avalanche mixer, the outputs should differ in ~32 bits
        // on average. A diff of < 8 bits would indicate a broken implementation.
        let diff = (a ^ b).count_ones();
        assert!(
            diff >= 16,
            "avalanche too weak: hamming distance {diff} (a={a:#018x}, b={b:#018x})"
        );
    }
}

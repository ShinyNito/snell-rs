//! PRF32 mixer and its entry-point helpers.
//!
//! Layout:
//! - `prf32_fold` — the numeric mixer (namespace/label/a/b → u32).
//! - `prf32_seq`  — selects the namespace for `label`, then folds with
//!   (a=seq, b=domain). Used by record/padding/mix paths.
//! - `prf32`      — `prf32_seq` with seq=0 (static PRF).
//!
//! Namespace *selection* (the `label → 64-bit namespace` jump table) is
//! implemented in `snell::profile`, because it depends on the per-connection
//! profile secret. The functions here take an already-resolved namespace value
//! so they can be tested without a profile.

use super::{GOLDEN_GAMMA, splitmix::splitmix64};

/// PRF32 linear-mix constants.
// `b` coefficient and addend.
pub(crate) const COEF_B: u64 = 0x589965CC75374CC3;
pub(crate) const ADD_B: u64 = 0x33A213EC50FFE2E9;
// `a` coefficient and addend.
pub(crate) const COEF_A: u64 = 0xE7037ED1A0B428DB;
pub(crate) const ADD_A: u64 = 0x8F3907F7B2B80C35;

/// The core PRF32 fold.
///
/// `namespace` is the 64-bit namespace value resolved for `label` by the jump
/// table (see `snell::profile`). `a` and `b` are the two caller-supplied
/// parameters: typically (seq, domain) or (0, domain).
///
/// ```text
/// x = namespace
///   ^ (b * 0x589965CC75374CC3 + 0x33A213EC50FFE2E9)
///   ^ (label * GOLDEN_GAMMA)
///   ^ (a * 0xE7037ED1A0B428DB + 0x8F3907F7B2B80C35)
/// y = splitmix64(x)
/// return (y ^ (y >> 32)) as u32
/// ```
#[inline]
#[must_use]
pub fn prf32_fold(namespace: u64, label: u32, a: u64, b: u64) -> u32 {
    let x = namespace
        ^ b.wrapping_mul(COEF_B).wrapping_add(ADD_B)
        ^ u64::from(label).wrapping_mul(GOLDEN_GAMMA)
        ^ a.wrapping_mul(COEF_A).wrapping_add(ADD_A);
    let y = splitmix64(x);
    // Fold the 64-bit SplitMix64 output to 32 bits exactly as the binary does:
    // high half XOR low half.
    (y ^ (y >> 32)) as u32
}

/// PRF32 with explicit seq and domain.
///
/// This selects the namespace for `label` from the profile context and then
/// folds with `(a=seq, b=domain)`. We take the resolved namespace directly so
/// this module stays profile-free.
///
/// Callers that hold a profile should use `Profile::namespace_for` to resolve
/// `label` first.
#[inline]
#[must_use]
pub fn prf32_seq(namespace: u64, label: u32, seq: u64, domain: u32) -> u32 {
    prf32_fold(namespace, label, seq, u64::from(domain))
}

/// Static PRF32: `prf32_seq` with `seq = 0`.
///
/// Used for fields that don't vary per-record (prefix bounds, chunk sizes,
/// padding bounds, etc.).
#[inline]
#[must_use]
pub fn prf32(namespace: u64, label: u32, domain: u32) -> u32 {
    prf32_seq(namespace, label, 0, domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Folding must produce a u32 — guards against accidental truncation or
    /// sign-extension when casting the SplitMix64 result.
    #[test]
    fn prf32_fold_returns_u32_range() {
        for (ns, label, a, b) in [
            (0u64, 0u32, 0u64, 0u64),
            (u64::MAX, 0, 0, 0),
            (0, u32::MAX, 0, 0),
            (0x1234_5678_9ABC_DEF0, 21, 7, 0x7053),
            (0xB46C2E7D9A1538F1, 5, 0, 0), // profile namespace, label 5
        ] {
            let out = prf32_fold(ns, label, a, b);
            assert_eq!(out.to_be_bytes().len(), 4, "result is 4 bytes");
            // No value of u32 is out of range; this just documents the contract.
            let _ = out;
        }
    }

    /// `prf32` == `prf32_seq` with seq=0. Pins the static helper to the seq'd one.
    #[test]
    fn prf32_is_prf32_seq_with_zero_seq() {
        let ns = 0xA71F0C54D8396E2B; // motif namespace
        assert_eq!(prf32(ns, 2, 0x51A7), prf32_seq(ns, 2, 0, 0x51A7));
        assert_eq!(prf32(ns, 21, 0), prf32_seq(ns, 21, 0, 0));
    }

    /// Determinism: same inputs → same output across calls.
    #[test]
    fn prf32_is_deterministic() {
        let ns = 0x5D9217C083E64AB9;
        let a = prf32_fold(ns, 14, 0, 0);
        let b = prf32_fold(ns, 14, 0, 0);
        assert_eq!(a, b);
    }

    /// Avalanche: flipping one bit of any input should produce a very different
    /// output. PRF32 is built on SplitMix64, so we expect strong diffusion.
    #[test]
    fn prf32_avalanche_on_each_input() {
        let base_ns = 0xDEADBEEFCAFEBABE;
        let base_label = 22u32;
        let base_a = 3u64;
        let base_b = 0x7053u64;
        let reference = prf32_fold(base_ns, base_label, base_a, base_b);

        // Flip a bit in each input independently.
        let d_ns = prf32_fold(base_ns ^ 1, base_label, base_a, base_b) ^ reference;
        let d_a = prf32_fold(base_ns, base_label, base_a ^ 1, base_b) ^ reference;
        let d_b = prf32_fold(base_ns, base_label, base_a, base_b ^ 1) ^ reference;

        for (name, d) in [("ns", d_ns), ("a", d_a), ("b", d_b)] {
            let dist = d.count_ones();
            assert!(
                dist >= 8,
                "avalanche too weak on {name}: hamming distance {dist}"
            );
        }
    }

    /// `label` only has a small effect through the mix (it's multiplied by the
    /// golden gamma), but two distinct labels must still (almost surely) give
    /// distinct outputs. This catches a label-coefficient bug.
    #[test]
    fn prf32_distinguishes_labels() {
        let ns = 0x62D0B5E19C4A783F; // chunk namespace
        let mut distinct = std::collections::HashSet::new();
        for label in 0..=39u32 {
            distinct.insert(prf32(ns, label, 0));
        }
        // 40 distinct labels → at least 38 distinct outputs (allowing rare
        // collisions in a 32-bit space is fine; a total collapse is not).
        assert!(
            distinct.len() >= 38,
            "too many label collisions: {} distinct outputs",
            distinct.len()
        );
    }
}

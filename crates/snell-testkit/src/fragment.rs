//! Fragmentation cases that later codec tests must cover.
//!
//! Phase 1 records the required cuts. It does not implement a decoder.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentCase {
    pub id: &'static str,
    pub description: &'static str,
}

pub const FRAGMENTATION_CASES: &[FragmentCase] = &[
    FragmentCase {
        id: "byte-at-a-time",
        description: "feed the same wire one byte per commit",
    },
    FragmentCase {
        id: "all-single-cuts",
        description: "split the wire at every offset",
    },
    FragmentCase {
        id: "random-multi-cut",
        description: "split the wire at several random offsets",
    },
    FragmentCase {
        id: "header-body-boundary",
        description: "cut between AEAD header and body",
    },
    FragmentCase {
        id: "multi-record-read",
        description: "one read contains more than one record",
    },
    FragmentCase {
        id: "partial-write",
        description: "flush pending wire with short writes",
    },
    FragmentCase {
        id: "vectored-partial-write",
        description: "flush pending wire with short vectored writes",
    },
    FragmentCase {
        id: "cancellation",
        description: "cancel during reservation read and require rollback",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase1_lists_the_required_fragmentation_matrix() {
        let ids: Vec<_> = FRAGMENTATION_CASES.iter().map(|case| case.id).collect();
        assert!(ids.contains(&"byte-at-a-time"));
        assert!(ids.contains(&"all-single-cuts"));
        assert!(ids.contains(&"random-multi-cut"));
        assert!(ids.contains(&"header-body-boundary"));
        assert!(ids.contains(&"multi-record-read"));
        assert!(ids.contains(&"partial-write"));
        assert!(ids.contains(&"vectored-partial-write"));
        assert!(ids.contains(&"cancellation"));
    }
}

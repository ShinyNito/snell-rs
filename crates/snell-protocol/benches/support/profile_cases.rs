// Public benchmark inputs, ordered by the generator selected by Profile::derive.
// profile::bench::profile_cases_match_baseline verifies this mapping.
pub const CASES: [(u32, &[u8]); 4] = [
    (0, b"profile-bench-000"),
    (1, b"profile-bench-003"),
    (2, b"profile-bench-004"),
    (3, b"profile-bench-001"),
];

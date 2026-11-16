Inputs that made a fuzz target abort (fuzz/artifacts of the differential
target, rounds 1 and 2, and one artifact of an earlier run). They are replayed
by `tests/fuzz_artifacts.rs`. Most of them exposed finding R-2 of
fuzz/KNOWN_DIVERGENCES.md (duplicate symbol tables skipped by the audit) or
gaps in the target's own allowlist; all pass both targets now.

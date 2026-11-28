//! A stand-in for a crates.io dependency: `build.sh` compiles it with its
//! source directory remapped to where cargo would have unpacked it on a
//! Windows machine (`C:\Users\...\.cargo\registry\src\index.crates.io-...\fakedep-1.2.3\`),
//! so its panic locations carry the registry path that unforge reads
//! dependencies and versions from.

use std::collections::HashMap;

/// Counts words; panics on an empty input (a panic location in this crate).
#[inline(never)]
pub fn word_counts(text: &str) -> HashMap<String, usize> {
    assert!(!text.is_empty(), "fakedep: empty input");
    let mut m = HashMap::new();
    for w in text.split_whitespace() {
        *m.entry(w.to_owned()).or_insert(0) += 1;
    }
    m
}

/// Index into a slice (a bounds check with this crate's location).
#[inline(never)]
pub fn nth(v: &[u32], i: usize) -> u32 {
    v[i]
}

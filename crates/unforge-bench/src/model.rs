//! The files of a corpus item and their JSON schemas.
//!
//! A corpus directory holds, for every built binary `<id>`:
//!
//! | file | written by | content |
//! |---|---|---|
//! | `<id>.debug` | the build | the binary with DWARF (`debug = 2`) |
//! | `<id>.stripped` | the build | the same file after `objcopy --strip-all` |
//! | `<id>.meta.json` | the build | [`Meta`] |
//! | `<id>.truth.json` | `unforge-bench truth` | [`Truth`] |

use serde::{Deserialize, Serialize};

pub const TRUTH_SCHEMA: &str = "unforge-bench-truth/1";
pub const RESULTS_SCHEMA: &str = "unforge-bench-results/1";

/// How one binary was built (`<id>.meta.json`). Written by
/// `.github/workflows/bench-corpus.yml` and `bench/build-testdata.sh`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Meta {
    #[serde(default)]
    pub schema: String,
    #[serde(default)]
    pub id: String,
    /// Package name (`ripgrep`), or the program name for `testdata/src`.
    #[serde(rename = "crate")]
    pub krate: String,
    #[serde(default)]
    pub version: String,
    /// Name of the installed binary (`rg`).
    #[serde(default)]
    pub bin: String,
    /// `crates.io` or `testdata`.
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub variant: Variant,
    /// `rustc -vV` output.
    #[serde(default)]
    pub rustc: String,
    #[serde(default)]
    pub sha256: Hashes,
    /// The `Cargo.lock` the binary was built with (`null` without one).
    #[serde(default)]
    pub cargo_lock: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Variant {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub opt_level: String,
    #[serde(default)]
    pub lto: String,
    #[serde(default)]
    pub panic: String,
    #[serde(default)]
    pub codegen_units: u32,
    #[serde(default)]
    pub debug: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Hashes {
    #[serde(default)]
    pub debug: String,
    #[serde(default)]
    pub stripped: String,
}

impl Meta {
    /// `commit-hash:` from the recorded `rustc -vV`.
    pub fn rustc_commit(&self) -> Option<&str> {
        self.rustc
            .lines()
            .find_map(|l| l.strip_prefix("commit-hash: "))
            .map(str::trim)
            .filter(|h| h.len() == 40)
    }
}

/// A package name and version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
}

/// Ground truth for one binary (`<id>.truth.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Truth {
    pub schema: String,
    /// File name of the binary the truth was read from.
    pub binary: String,
    /// The package that was built (its code is the "user" group).
    pub package: Option<Package>,
    /// Commit of the rustc that built it (from `/rustc/<commit>` paths in
    /// the debug info, else from the meta file).
    pub rustc_commit: Option<String>,
    /// Every function, sorted by start address, one per address.
    pub functions: Vec<TruthFunction>,
    /// Packages whose code is in the binary (see `truth::linked_dependencies`),
    /// plus `rustc` with the commit as its version. This is what M3 scores.
    pub dependencies: Vec<Package>,
    /// Every registry package of the `Cargo.lock` (for reference; most
    /// lock files list platform-specific packages that are never built).
    pub lock_packages: Vec<Package>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthFunction {
    pub start: u64,
    pub size: u64,
    /// Demangled name without the hash (or the plain name).
    pub name: Option<String>,
    /// The crate the code was defined in (`_` spelling), if known.
    #[serde(rename = "crate")]
    pub krate: Option<String>,
    /// `user`, `std`, `dep:<crate>` ([`unforge_analysis::Group::label`]).
    pub group: String,
    /// `dwarf` (a `DW_TAG_subprogram` with an address) or `symtab` (a
    /// function symbol with no DWARF entry, e.g. C runtime or assembly), or
    /// `entry` (the ELF entry point when neither describes it; size 0).
    pub origin: String,
}

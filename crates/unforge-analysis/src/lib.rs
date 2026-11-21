//! What unforge recovers from a Rust binary, as stable output types.
//!
//! [`Analysis`] runs on an ELF file (usually a stripped one) and answers two
//! questions a malware analyst asks first:
//!
//! - [`Analysis::functions`]: where are the functions, what are they called
//!   (when that is known) and whose code are they (the program's own code,
//!   a dependency crate, or the standard library)?
//! - [`Analysis::dependencies`]: which crates (and versions) were compiled
//!   into it, and with which toolchain?
//!
//! The benchmark (`crates/unforge-bench`, `bench/README.md`) scores exactly
//! these results against ground truth taken from DWARF. The types here are
//! the interface between the two, so they change only together with
//! [`API_VERSION`].
//!
//! # Baseline (v0)
//!
//! No code is disassembled yet:
//! - functions come from the symbols that remain (`.symtab`, `.dynsym`, the
//!   dynamic symbol table found through `PT_DYNAMIC`) plus the entry point;
//! - dependencies come from source paths in the loaded bytes
//!   (`.../registry/src/<index>/<crate>-<version>/...` and
//!   `/rustc/<commit>/...`, see [`paths`]).
//!
//! # Bounds
//!
//! Like `unforge-elf`, nothing here panics on any input. Work is linear in
//! the file size plus the number of symbols, and the output is capped
//! ([`MAX_FUNCTIONS`], [`MAX_DEPENDENCIES`], [`MAX_NAME_LEN`]).

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod names;
pub mod paths;

use std::collections::{BTreeMap, BTreeSet};

use unforge_elf::consts::{ET_DYN, ET_EXEC, PT_LOAD, STT_FUNC};
use unforge_elf::{ElfFile, Symbol, SymbolSection};

/// Version of the output types. Bumped whenever [`FunctionGuess`],
/// [`Group`] or [`DependencyGuess`] change meaning.
pub const API_VERSION: u32 = 1;

/// At most this many functions are reported.
pub const MAX_FUNCTIONS: usize = 1 << 22;
/// At most this many dependencies are reported.
pub const MAX_DEPENDENCIES: usize = 1 << 14;
/// Symbol names longer than this are not read (the function is still
/// reported, without a name).
pub const MAX_NAME_LEN: usize = 4096;

/// `STT_GNU_IFUNC` (GNU extension; glibc `elf.h`).
const STT_GNU_IFUNC: u8 = 10;

/// Whose code a function is.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Group {
    /// The program's own code (the package that was built).
    User,
    /// A dependency crate, by crate name (`_` spelling, e.g. `regex_automata`).
    Dependency(String),
    /// The standard library and the toolchain's runtime (`std`, `core`,
    /// `alloc`, the crates `std` vendors, C runtime start files).
    Std,
}

impl Group {
    /// Stable text form: `user`, `std`, `dep:<crate>`.
    pub fn label(&self) -> String {
        match self {
            Group::User => "user".to_owned(),
            Group::Std => "std".to_owned(),
            Group::Dependency(c) => format!("dep:{}", names::normalize_crate(c)),
        }
    }

    /// Parses [`Group::label`].
    pub fn from_label(s: &str) -> Option<Group> {
        match s {
            "user" => Some(Group::User),
            "std" => Some(Group::Std),
            _ => s
                .strip_prefix("dep:")
                .filter(|c| !c.is_empty())
                .map(|c| Group::Dependency(names::normalize_crate(c))),
        }
    }

    pub fn is_user(&self) -> bool {
        matches!(self, Group::User)
    }
}

/// One recovered function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionGuess {
    /// Virtual address of the first instruction (as linked; PIE files are
    /// not relocated).
    pub start: u64,
    /// Size in bytes; 0 when unknown.
    pub size: u64,
    /// Demangled name without the hash, or the raw name for non-Rust
    /// symbols. `None` when unknown.
    pub name: Option<String>,
    /// Whose code it is. `None` when unknown.
    pub group: Option<Group>,
}

/// One recovered dependency (or the toolchain, as `rustc` with the commit
/// hash as its version).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DependencyGuess {
    /// Package name as cargo spells it (`regex-automata`), or `rustc`.
    pub name: String,
    /// Exact version (`0.4.9`; for `rustc`, the 40-hex commit), if known.
    pub version: Option<String>,
}

/// Errors that stop the analysis altogether.
#[derive(Debug)]
pub enum Error {
    /// The input is not an ELF file `unforge-elf` can read at all.
    Elf(unforge_elf::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Elf(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

/// An analysis of one ELF file.
pub struct Analysis<'data> {
    file: ElfFile<'data>,
}

impl<'data> Analysis<'data> {
    /// Parses `data`. Fails only when not even an ELF header can be read.
    pub fn new(data: &'data [u8]) -> Result<Self, Error> {
        let file = ElfFile::parse(data).map_err(Error::Elf)?;
        Ok(Analysis { file })
    }

    pub fn elf(&self) -> &ElfFile<'data> {
        &self.file
    }

    /// Recovered functions, sorted by start address, one per address.
    pub fn functions(&self) -> Vec<FunctionGuess> {
        let mut by_start: BTreeMap<u64, FunctionGuess> = BTreeMap::new();
        let mut add = |sym: &Symbol, name: Option<&[u8]>| {
            if by_start.len() >= MAX_FUNCTIONS {
                return;
            }
            if !is_function(sym) {
                return;
            }
            let name = name
                .and_then(|n| std::str::from_utf8(n).ok())
                .filter(|n| !n.is_empty());
            let guess = FunctionGuess {
                start: sym.value,
                size: sym.size,
                name: name.map(|n| names::demangle_rust(n).unwrap_or_else(|| n.to_owned())),
                group: None,
            };
            let e = by_start.entry(sym.value).or_insert_with(|| guess.clone());
            if e.name.is_none() {
                e.name = guess.name;
            }
            if e.size == 0 {
                e.size = guess.size;
            }
        };

        if let Ok(tables) = self.file.symbol_tables() {
            for table in tables {
                for sym in table.iter() {
                    let name = table
                        .name_bounded(&sym, MAX_NAME_LEN)
                        .ok()
                        .filter(|n| !n.truncated)
                        .map(|n| n.bytes);
                    add(&sym, name);
                }
            }
        }
        if let Ok(dynsyms) = self.file.dynamic_symbols() {
            for i in 0..dynsyms.len() {
                let Some(sym) = dynsyms.get(i) else { break };
                let name = dynsyms
                    .name_bounded(&sym, MAX_NAME_LEN)
                    .ok()
                    .filter(|n| !n.truncated)
                    .map(|n| n.bytes);
                add(&sym, name);
            }
        }

        let header = self.file.header();
        if matches!(header.e_type, ET_EXEC | ET_DYN)
            && header.entry != 0
            && by_start.len() < MAX_FUNCTIONS
        {
            by_start.entry(header.entry).or_insert(FunctionGuess {
                start: header.entry,
                size: 0,
                name: None,
                group: None,
            });
        }

        let mut out: Vec<FunctionGuess> = by_start.into_values().collect();
        assign_groups(&mut out);
        out
    }

    /// Recovered dependencies, sorted, without duplicates.
    pub fn dependencies(&self) -> Vec<DependencyGuess> {
        let mut found: BTreeSet<DependencyGuess> = BTreeSet::new();
        for (start, end) in self.loaded_file_ranges() {
            let Some(bytes) = self.file.data().get(start..end) else {
                continue;
            };
            paths::scan_path_clues(bytes, |clue| {
                if found.len() >= MAX_DEPENDENCIES {
                    return;
                }
                let d = match clue {
                    paths::PathClue::Rustc { commit } => DependencyGuess {
                        name: "rustc".to_owned(),
                        version: Some(commit),
                    },
                    paths::PathClue::Registry { name, version } => DependencyGuess {
                        name,
                        version: Some(version),
                    },
                };
                found.insert(d);
            });
        }
        found.into_iter().collect()
    }

    /// The file ranges of `PT_LOAD` segments, merged (so overlapping
    /// segments are scanned once). The whole file when there is none.
    fn loaded_file_ranges(&self) -> Vec<(usize, usize)> {
        let len = self.file.data().len();
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        if let Ok(phdrs) = self.file.program_headers() {
            for ph in phdrs.iter().filter(|p| p.p_type == PT_LOAD) {
                let s = usize::try_from(ph.offset).unwrap_or(usize::MAX).min(len);
                let e = usize::try_from(ph.offset.saturating_add(ph.filesz))
                    .unwrap_or(usize::MAX)
                    .min(len);
                if s < e {
                    ranges.push((s, e));
                }
            }
        }
        if ranges.is_empty() {
            return vec![(0, len)];
        }
        ranges.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
        for (s, e) in ranges {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        merged
    }
}

fn is_function(sym: &Symbol) -> bool {
    (sym.kind() == STT_FUNC || sym.kind() == STT_GNU_IFUNC)
        && sym.value != 0
        && matches!(sym.section, SymbolSection::Index(i) if i != 0)
}

/// Fills in [`FunctionGuess::group`] from the names.
///
/// The crate of a Rust name is its first path segment
/// ([`names::crate_of_demangled`]). Standard library crates are
/// [`Group::Std`]. The program's own crate is guessed as the crate of
/// `<crate>::main` (the function `std::rt::lang_start` is handed); every
/// other crate is a [`Group::Dependency`]. Non-Rust names stay `None`.
fn assign_groups(funcs: &mut [FunctionGuess]) {
    let mut mains: BTreeSet<String> = BTreeSet::new();
    for f in funcs.iter() {
        if let Some(n) = &f.name
            && let Some(c) = n.strip_suffix("::main")
            && !c.contains("::")
            && !names::is_std_crate(c)
            && !c.is_empty()
        {
            mains.insert(names::normalize_crate(c));
        }
    }
    let user = if mains.len() == 1 {
        mains.into_iter().next()
    } else {
        None
    };
    for f in funcs.iter_mut() {
        let Some(n) = &f.name else { continue };
        let Some(c) = names::crate_of_demangled(n) else {
            continue;
        };
        let c = names::normalize_crate(c);
        f.group = Some(if names::is_std_crate(&c) {
            Group::Std
        } else if user.as_deref() == Some(c.as_str()) {
            Group::User
        } else {
            Group::Dependency(c)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(start: u64, name: &str) -> FunctionGuess {
        FunctionGuess {
            start,
            size: 1,
            name: Some(name.to_owned()),
            group: None,
        }
    }

    #[test]
    fn groups_from_names() {
        let mut v = vec![
            f(1, "mytool::main"),
            f(2, "mytool::run"),
            f(3, "core::fmt::write"),
            f(4, "serde_json::de::from_str"),
            f(5, "memcpy"),
        ];
        assign_groups(&mut v);
        let g: Vec<_> = v.iter().map(|f| f.group.clone()).collect();
        assert_eq!(
            g,
            vec![
                Some(Group::User),
                Some(Group::User),
                Some(Group::Std),
                Some(Group::Dependency("serde_json".into())),
                None
            ]
        );
    }

    #[test]
    fn labels_round_trip() {
        for g in [
            Group::User,
            Group::Std,
            Group::Dependency("regex_automata".into()),
        ] {
            assert_eq!(Group::from_label(&g.label()), Some(g));
        }
        assert_eq!(
            Group::from_label("dep:regex-automata"),
            Some(Group::Dependency("regex_automata".into()))
        );
        assert_eq!(Group::from_label("dep:"), None);
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        assert!(Analysis::new(b"not an elf").is_err());
        assert!(Analysis::new(&[]).is_err());
    }
}

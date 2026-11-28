//! Function fingerprints: names for the functions of stripped Rust binaries.
//!
//! Malware is usually stripped, but `unforge-analysis` can still tell which
//! crates (and versions) and which toolchain went into it. The code of
//! those crates is public: build a database of fingerprints from binaries
//! that still have symbols and contain the same code, and the functions of
//! the stripped binary can be named by looking their fingerprints up. This
//! is what IDA's FLIRT and Ghidra's Function ID do.
//!
//! - [`Fingerprinter`] computes the [`Fingerprint`] of a function.
//! - [`Db`] holds fingerprints and names; [`Db::add_elf`] adds the named
//!   functions of an ELF file, [`Db::merge`] joins databases,
//!   [`Db::to_bytes`] / [`Db::from_bytes`] store them (format in [`db`]).
//! - [`match_elf`] looks up every function of a (stripped) file.
//!
//! # Fingerprint
//!
//! A function is disassembled over its whole size with `unforge-disasm`,
//! trailing alignment padding (`nop`, `int3`) is dropped, and every
//! instruction becomes one line of text: its mnemonic and its operands in
//! Intel syntax, with the numbers that depend on the layout of the binary
//! masked (see [`normalize`]):
//!
//! - **Branch and call targets** (`call 0x401020`) become `T`: the callee
//!   is somewhere else in another binary. A target inside the function
//!   itself becomes `L<offset>` instead: that offset depends only on the
//!   function's own code, and keeping it tells apart functions that differ
//!   only in their control flow.
//! - **RIP-relative addresses** (`lea rdi, [0x404010]`, which
//!   `unforge-disasm` prints as absolute) become `T`: the data or the GOT
//!   slot moves with the layout.
//! - **Absolute addresses** in 64-bit code (any other number `>= 0x1000`
//!   that falls in a `PT_LOAD` segment of the same file, e.g. `mov edi,
//!   0x4a3000` in a non-PIE file) become `A`.
//! - **TLS offsets** (non-zero numbers inside `fs:[..]` / `gs:[..]`) become
//!   `F`: they depend on all the thread-locals linked into the binary.
//! - **i386 PIC offsets**: 32-bit position-independent code reaches its
//!   data relative to the GOT, whose address it computes at run time
//!   (`call __x86.get_pc_thunk.bx; add ebx, 0x6dde6; lea eax,
//!   [ebx-0x10e0]`). In 32-bit code every number from `0x1000` up to
//!   `0xffff_0000` becomes `A` (such offsets cannot be told apart from
//!   constants), and every displacement from `ebx`, the register the
//!   i386 ABI uses for the GOT, becomes `G`. GOT offsets in other
//!   registers below `0x1000` are not recognized (that would need data
//!   flow).
//!
//! Everything else stays: mnemonics with their prefixes (`lock cmpxchg`),
//! register names, memory operand sizes and shapes (`qword ptr
//! [rax+rcx*8+0x10]`), immediates, and stack and field displacements. These
//! come from the source and the compiler, not from where the code was
//! placed, so they carry the identity of the function.
//!
//! The hash is FNV-1a 64 ([`fnv`]) of the lines (each followed by `\n`)
//! and then of the instruction count. It is defined byte by byte and is
//! stable across platforms, Rust versions and releases of this crate. The
//! instruction and byte counts are kept next to the hash ([`Fingerprint`]).
//!
//! # Small functions
//!
//! Short functions (`mov eax, 1; ret`, forwarding shims, tiny drop glue)
//! are shared by many unrelated names and match by accident. [`Options`]
//! sets a threshold; the default ([`Options::default`]) skips functions of
//! fewer than 6 instructions or 16 bytes, both when building and when
//! matching. See "Evaluation" for what it buys.
//!
//! # Collisions
//!
//! One fingerprint can belong to many names: generic functions instantiated
//! for different types often compile to identical code, and so do
//! unrelated functions with the same body. A database keeps every name (up
//! to [`db::MAX_NAMES`]), and a match says how far the names agree
//! ([`MatchStatus`]): one name, several instantiations of one generic
//! function ([`generic_base`]), or unrelated names.
//!
//! # Function starts
//!
//! [`match_elf`] fingerprints every function [`function_starts`] finds:
//! those of `unforge_analysis::Analysis::functions` (symbols, dynamic
//! symbols, entry point) plus the starts in the `.eh_frame_hdr` search
//! table ([`starts`]), because on this branch `Analysis::functions` does
//! not read the unwind tables yet. A function without a known size ends
//! where the next one starts (trailing padding is dropped anyway).
//!
//! # Evaluation
//!
//! Measured with `examples/score.rs` (rustc 1.99.0 `b940084d7`, x86-64):
//! build a database from file(s) A with symbols, match a copy of file B
//! stripped with `strip --strip-all`, and compare with B's own symbols at
//! the same addresses. Per match: one name ("unique") is correct when it is
//! B's name; several instantiations of one generic function ("generic")
//! are correct when B's name is an instantiation of the same function;
//! unrelated names ("ambiguous") are not counted as a name given.
//! *Precision* = correct / (unique + generic); *recall* = correct /
//! functions of B whose name A also has (and that pass the threshold, when
//! one is used).
//!
//! The programs are `testdata/src/*.rs` built for
//! `x86_64-unknown-linux-musl` (static PIE, std and musl inside) and, in
//! the "i686" rows, `i686-unknown-linux-musl` (PIC, see above), and two
//! debug binaries of this workspace (`unforge-bench` and its unit-test
//! executable, which share std, serde, serde_json and gimli; `unforge` and
//! its unit-test executable).
//!
//! | A → B | default (6 insns / 16 bytes) | no threshold |
//! |---|---|---|
//! | collections → collections (same file) | P 100.0 %, R 87.0 %, 35 ambiguous | P 100.0 %, R 78.9 %, 101 ambiguous |
//! | collections → enums (opt 3) | P 100.0 %, R 86.0 %, 39 ambiguous | P 100.0 %, R 77.7 %, 108 ambiguous |
//! | collections → ffi_statics (opt 3) | P 99.5 %, R 86.2 % | P 99.1 %, R 77.9 % |
//! | collections → enums (both opt 0) | P 99.0 %, R 86.5 % | P 98.9 %, R 78.0 % |
//! | collections opt 3 → enums opt 0 | P 100.0 %, R 85.4 % | P 99.7 %, R 76.9 % |
//! | 4 programs → traits (opt 3) | P 99.5 %, R 86.7 % | P 99.5 %, R 77.9 % |
//! | unforge-bench → its test exe (debug) | P 95.7 %, R 78.4 % | P 95.8 %, R 68.0 % |
//! | unforge → its test exe (debug) | P 94.6 %, R 82.6 % | P 94.3 %, R 73.5 % |
//! | unforge-bench → unforge (debug) | P 88.8 %, R 85.5 % | P 88.8 %, R 72.0 % |
//! | i686: collections → collections | P 100.0 %, R 88.8 % | P 100.0 %, R 85.7 % |
//! | i686: collections → enums (opt 3) | P 100.0 %, R 81.1 % | P 100.0 %, R 78.2 % |
//!
//! What the numbers say:
//!
//! - Normalization is not what limits recall: across files, functions
//!   both name with the same code almost always get the same fingerprint
//!   (`--diff` of the example finds one or two exceptions per pair, code
//!   that was inlined differently). Misses are functions with identical
//!   code under other names (counted ambiguous), and, in stripped musl
//!   files, C library functions that have no unwind entry and are only
//!   reached through pointers, so no start is found for them.
//! - Wrong names are code shared by different names: `<u32 as Debug>::fmt`
//!   and `<usize as Debug>::fmt`, or a generic function instantiated for
//!   types the database never saw. Debug builds have much more of that
//!   (every tiny generic helper is a separate function), hence the lower
//!   precision there; malware is normally built in release mode.
//! - The threshold barely changes precision but removes two thirds of the
//!   ambiguous matches; without it about 6 % more functions get a correct
//!   name in absolute numbers, at the price of 3× the ambiguous noise.
//!
//! Database size: about 1.0 MB per 10 000 fingerprints (≈ 95 bytes per
//! name) for release code, 1.7 MB per 10 000 named debug functions
//! (debug names, full of generic arguments, are longer). The name text is
//! 84 to 95 % of it.
//!
//! # Bounds
//!
//! Nothing here panics on any input. Work is linear in the code size,
//! names are capped at `unforge_analysis::MAX_NAME_LEN`, names per
//! fingerprint at [`db::MAX_NAMES`], instructions per function at
//! [`normalize::MAX_INSNS`].

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

pub mod db;
pub mod fnv;
pub mod normalize;
pub mod starts;

use std::collections::BTreeMap;

use unforge_analysis::{Analysis, names};
use unforge_disasm::Bitness;
use unforge_elf::consts::PF_X;
use unforge_elf::{ElfFile, MemoryMap};

pub use db::{Db, DbError, Entry, SigName};
pub use normalize::Fingerprint;

/// Which functions get a fingerprint at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Options {
    /// Fewer instructions than this (after trailing padding) are skipped.
    pub min_insns: u32,
    /// Fewer bytes than this are skipped.
    pub min_bytes: u32,
}

impl Options {
    /// No threshold: every function with at least one instruction.
    pub const NONE: Options = Options {
        min_insns: 1,
        min_bytes: 1,
    };

    /// Whether a function with this fingerprint passes the threshold.
    pub fn keeps(&self, fp: Fingerprint) -> bool {
        fp.insns >= self.min_insns && fp.bytes >= self.min_bytes
    }
}

impl Default for Options {
    /// At least 6 instructions and 16 bytes.
    fn default() -> Self {
        Options {
            min_insns: 6,
            min_bytes: 16,
        }
    }
}

/// Errors that stop building or matching for one file.
#[derive(Debug)]
pub enum Error {
    /// Not an ELF file `unforge-elf` can read.
    Analysis(unforge_analysis::Error),
    /// The code is not x86 / x86-64 (the `e_machine` value).
    UnsupportedMachine(u16),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Analysis(e) => write!(f, "{e}"),
            Error::UnsupportedMachine(m) => write!(
                f,
                "cannot fingerprint code for machine {m}: only x86 and x86-64 are supported"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Fingerprints the functions of one ELF file.
pub struct Fingerprinter<'a, 'data> {
    elf: &'a ElfFile<'data>,
    map: MemoryMap,
    bitness: Bitness,
    /// Mapped address ranges `[start, end)`, sorted.
    mapped: Vec<(u64, u64)>,
}

impl<'a, 'data> Fingerprinter<'a, 'data> {
    /// `Err` when the file is not for x86 / x86-64.
    pub fn new(elf: &'a ElfFile<'data>) -> Result<Self, Error> {
        let header = elf.header();
        let bitness = unforge_disasm::bitness_for(header.machine, header.class)
            .ok_or(Error::UnsupportedMachine(header.machine))?;
        let map = elf.memory_map();
        let mut mapped: Vec<(u64, u64)> = map.regions().map(|r| (r.start, r.end)).collect();
        mapped.sort_unstable();
        Ok(Fingerprinter {
            elf,
            map,
            bitness,
            mapped,
        })
    }

    /// Whether `addr` is mapped by the file.
    pub fn is_mapped(&self, addr: u64) -> bool {
        let i = self.mapped.partition_point(|&(s, _)| s <= addr);
        i > 0
            && self
                .mapped
                .get(i - 1)
                .is_some_and(|&(s, e)| s <= addr && addr < e)
    }

    /// Whether a number in an operand (that is not the instruction's
    /// target) may depend on the layout and is masked as `A`
    /// ([`normalize`]): in 64-bit code, when it is a mapped address; in
    /// 32-bit code, every number from [`normalize::MIN_ADDRESS`] up to
    /// `0xffff_0000` (small negative immediates stay), because i386 PIC
    /// code addresses everything relative to the GOT pointer in a register
    /// (`call __x86.get_pc_thunk.bx; add ebx, 0x6dde6; lea eax,
    /// [ebx-0x10e0]`), and such offsets cannot be told apart from
    /// constants.
    pub fn is_layout_dependent(&self, v: u64) -> bool {
        match self.bitness {
            Bitness::B32 => (normalize::MIN_ADDRESS..0xffff_0000).contains(&v),
            Bitness::B64 => self.is_mapped(v),
        }
    }

    /// Whether `addr` is in executable memory.
    pub fn is_executable(&self, addr: u64) -> bool {
        self.map
            .backing_ref(addr)
            .is_some_and(|b| b.flags & PF_X != 0)
    }

    /// The end (exclusive) of the executable region holding `addr`.
    fn executable_end(&self, addr: u64) -> Option<u64> {
        self.map
            .regions()
            .find(|r| r.start <= addr && addr < r.end && r.flags & PF_X != 0)
            .map(|r| r.end)
    }

    fn insns(&self, start: u64, size: u64) -> Option<Vec<unforge_disasm::Insn>> {
        if size == 0 {
            return None;
        }
        let bytes = unforge_disasm::function_bytes_in(&self.map, self.elf.data(), start, size)?;
        Some(unforge_disasm::disassemble(
            bytes,
            start,
            self.bitness,
            normalize::MAX_INSNS,
        ))
    }

    /// The fingerprint of the function at `start` with `size` bytes. `None`
    /// when the size is 0 (unknown), the bytes are not in the file, or only
    /// padding is there. Thresholds are not applied here ([`Options::keeps`]).
    pub fn fingerprint(&self, start: u64, size: u64) -> Option<Fingerprint> {
        let insns = self.insns(start, size)?;
        normalize::fingerprint_insns(&insns, start, &|a| self.is_layout_dependent(a))
    }

    /// The normalized lines [`Fingerprinter::fingerprint`] hashes, for
    /// showing why two functions do or do not match.
    pub fn normalized_lines(&self, start: u64, size: u64) -> Vec<String> {
        self.insns(start, size)
            .map(|v| normalize::normalized_lines(&v, start, &|a| self.is_layout_dependent(a)))
            .unwrap_or_default()
    }
}

/// A function start to fingerprint, as [`function_starts`] finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionStart {
    pub start: u64,
    /// Size in bytes: from a symbol, or else up to the next known start
    /// (within the same executable region). 0 when unknown.
    pub size: u64,
    /// The name the file itself gives (a symbol), if any.
    pub symbol: Option<String>,
}

/// Functions without a size are not cut longer than this from the gap to
/// the next start.
pub const MAX_GAP: u64 = 1 << 20;

/// Rounds of call-target discovery in [`function_starts`].
const CALL_TARGET_ROUNDS: usize = 4;

/// Function starts of `analysis`, sorted, one per address, executable ones
/// only: `Analysis::functions`, the `.eh_frame_hdr` table ([`starts`]), and
/// the targets of direct calls in the code of those functions (code without
/// unwind information, such as a statically linked C library, is found
/// only that way). A call target inside a function whose size came from a
/// symbol is not taken as a start.
pub fn function_starts(analysis: &Analysis<'_>, fp: &Fingerprinter<'_, '_>) -> Vec<FunctionStart> {
    // start -> (size from a symbol, or 0; symbol name)
    let mut known: BTreeMap<u64, (u64, Option<String>)> = BTreeMap::new();
    for f in analysis.functions() {
        if fp.is_executable(f.start) {
            known.insert(f.start, (f.size, f.name));
        }
    }
    for s in starts::eh_frame_hdr_starts(analysis.elf(), &fp.map) {
        if known.len() >= unforge_analysis::MAX_FUNCTIONS {
            break;
        }
        known.entry(s).or_insert((0, None));
    }
    // Symbol-sized ranges, sorted by start, for "inside a known function".
    let sized: Vec<(u64, u64)> = known
        .iter()
        .filter(|(_, (size, _))| *size > 0)
        .map(|(&s, (size, _))| (s, s.saturating_add(*size)))
        .collect();
    let inside_sized = |a: u64| {
        let i = sized.partition_point(|&(s, _)| s <= a);
        i > 0 && sized.get(i - 1).is_some_and(|&(s, e)| s < a && a < e)
    };
    // Code first scanned as part of a longer gap is not scanned again: only
    // the starts new in a round are.
    let mut todo: Vec<u64> = known.keys().copied().collect();
    for _ in 0..CALL_TARGET_ROUNDS {
        if todo.is_empty() {
            break;
        }
        let mut found: Vec<u64> = Vec::new();
        for f in fill_gaps(&known, fp) {
            if todo.binary_search(&f.start).is_err() {
                continue;
            }
            let Some(insns) = fp.insns(f.start, f.size) else {
                continue;
            };
            let end = f.start.saturating_add(f.size);
            for i in &insns {
                // Direct calls, and direct jumps out of the function (tail
                // calls). Not `call <next instruction>`: that is how i386
                // code reads its own address (`call 1f; 1: pop ebx`).
                let leaves = |t: u64| t < f.start || t >= end;
                let next = i.addr.wrapping_add(u64::from(i.len));
                let direct = match i.flow {
                    unforge_disasm::Flow::Call => i.target != Some(next),
                    unforge_disasm::Flow::Jump => i.target.is_some_and(leaves),
                    _ => false,
                };
                if direct
                    && !i.operands.contains('[')
                    && let Some(t) = i.target
                    && !known.contains_key(&t)
                    && fp.is_executable(t)
                    && !inside_sized(t)
                {
                    found.push(t);
                }
            }
        }
        found.sort_unstable();
        found.dedup();
        for &t in &found {
            if known.len() >= unforge_analysis::MAX_FUNCTIONS {
                break;
            }
            known.insert(t, (0, None));
        }
        todo = found;
    }
    fill_gaps(&known, fp)
}

/// `known` as [`FunctionStart`]s, with every size of 0 replaced by the gap
/// to the next start (within the same executable region, at most
/// [`MAX_GAP`]).
fn fill_gaps(
    known: &BTreeMap<u64, (u64, Option<String>)>,
    fp: &Fingerprinter<'_, '_>,
) -> Vec<FunctionStart> {
    let mut out: Vec<FunctionStart> = Vec::with_capacity(known.len());
    let mut it = known.iter().peekable();
    while let Some((&start, (size, symbol))) = it.next() {
        let mut size = *size;
        if size == 0 {
            let next = it.peek().map(|(n, _)| **n);
            let end = fp.executable_end(start);
            let stop = match (next, end) {
                (Some(n), Some(e)) => Some(n.min(e)),
                (n, e) => n.or(e),
            };
            if let Some(stop) = stop {
                let gap = stop.saturating_sub(start);
                if gap <= MAX_GAP {
                    size = gap;
                }
            }
        }
        out.push(FunctionStart {
            start,
            size,
            symbol: symbol.clone(),
        });
    }
    out
}

/// The crate of a name, for [`SigName::krate`].
fn crate_of(name: &str) -> Option<String> {
    names::crate_of_demangled(name).map(names::normalize_crate)
}

/// What [`Db::add_elf`] did with one file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AddStats {
    /// Functions with a name and a size.
    pub named: usize,
    /// Of those, fingerprinted and added.
    pub added: usize,
    /// Below the database's threshold.
    pub too_small: usize,
    /// Bytes not in the file, or only padding.
    pub unreadable: usize,
}

impl Db {
    /// Adds every function of the ELF file `data` that has a name and a
    /// size (from its symbols), and the file's dependencies as sources.
    pub fn add_elf(&mut self, data: &[u8]) -> Result<AddStats, Error> {
        let analysis = Analysis::new(data).map_err(Error::Analysis)?;
        let fpr = Fingerprinter::new(analysis.elf())?;
        let mut stats = AddStats::default();
        for f in analysis.functions() {
            let Some(name) = f.name else { continue };
            if f.size == 0 || !fpr.is_executable(f.start) {
                continue;
            }
            stats.named += 1;
            let Some(fp) = fpr.fingerprint(f.start, f.size) else {
                stats.unreadable += 1;
                continue;
            };
            if !self.options.keeps(fp) {
                stats.too_small += 1;
                continue;
            }
            stats.added += 1;
            let krate = crate_of(&name);
            self.insert(fp, SigName { name, krate });
        }
        for d in analysis.dependencies() {
            self.add_source(match d.version {
                Some(v) => format!("{} {v}", d.name),
                None => d.name,
            });
        }
        Ok(stats)
    }
}

/// Builds a database from ELF files with symbols. Fails on the first file
/// that cannot be read.
pub fn build_db(files: &[&[u8]], options: Options) -> Result<Db, Error> {
    let mut db = Db::new(options);
    for f in files {
        db.add_elf(f)?;
    }
    Ok(db)
}

/// A name with the generic arguments of every path segment removed:
/// `core::ptr::drop_in_place<alloc::string::String>` and
/// `core::ptr::drop_in_place::<u8>` both give `core::ptr::drop_in_place`.
/// Qualified paths keep their `<T as Trait>` part, generic arguments
/// inside it are removed too.
pub fn generic_base(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut skip = 0usize;
    let mut chars = name.chars().peekable();
    // Depth of '<' kept (qualified paths), so their '>' stays too.
    while let Some(c) = chars.next() {
        if skip > 0 {
            match c {
                '-' if chars.peek() == Some(&'>') => {
                    chars.next();
                }
                '<' => skip += 1,
                '>' => skip -= 1,
                _ => {}
            }
            continue;
        }
        if c == '<' {
            let generic = out
                .chars()
                .last()
                .is_some_and(|p| p.is_alphanumeric() || p == '_' || p == ':');
            if generic {
                while out.ends_with(':') {
                    out.pop();
                }
                skip = 1;
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// How a function's fingerprint matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MatchStatus {
    /// One name.
    Unique,
    /// Several names, all instantiations of the same generic function
    /// (equal [`generic_base`]).
    SameGeneric,
    /// Several unrelated names: identical code, the name is a guess.
    Ambiguous,
    /// The fingerprint is not in the database.
    NoMatch,
    /// Below the database's threshold ([`Options`]); not looked up.
    TooSmall,
    /// No size, bytes not in the file, or only padding.
    Unreadable,
}

impl MatchStatus {
    /// Whether the function got names.
    pub fn is_match(self) -> bool {
        matches!(
            self,
            MatchStatus::Unique | MatchStatus::SameGeneric | MatchStatus::Ambiguous
        )
    }
}

/// The result for one function start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionMatch {
    pub start: u64,
    pub size: u64,
    pub fingerprint: Option<Fingerprint>,
    pub status: MatchStatus,
    /// The database's names, sorted; empty unless [`MatchStatus::is_match`].
    pub names: Vec<SigName>,
    /// The database saw more names than it kept ([`Entry::truncated`]).
    pub names_truncated: bool,
    /// The name the file itself gives, if any (unstripped files).
    pub symbol: Option<String>,
}

impl FunctionMatch {
    /// The name to show: the name, or for [`MatchStatus::SameGeneric`] the
    /// generic function followed by `<..>`, or for an ambiguous match the
    /// first name in sort order. `None` when nothing matched.
    pub fn display_name(&self) -> Option<String> {
        let first = self.names.first()?;
        Some(match self.status {
            MatchStatus::SameGeneric => format!("{}<..>", generic_base(&first.name)),
            _ => first.name.clone(),
        })
    }

    /// Number of distinct names (at least, when truncated).
    pub fn candidates(&self) -> usize {
        self.names.len()
    }
}

fn status_of(entry: &Entry) -> MatchStatus {
    let mut names = entry.names.iter();
    let Some(first) = names.next() else {
        return MatchStatus::NoMatch;
    };
    if entry.names.len() == 1 && !entry.truncated {
        return MatchStatus::Unique;
    }
    let base = generic_base(&first.name);
    if names.all(|n| generic_base(&n.name) == base) {
        MatchStatus::SameGeneric
    } else {
        MatchStatus::Ambiguous
    }
}

/// Fingerprints every function start of the ELF file `data`
/// ([`function_starts`]) and looks it up in `db`, with the database's
/// threshold. One result per start, sorted by address.
pub fn match_elf(db: &Db, data: &[u8]) -> Result<Vec<FunctionMatch>, Error> {
    let analysis = Analysis::new(data).map_err(Error::Analysis)?;
    let fpr = Fingerprinter::new(analysis.elf())?;
    let options = db.options();
    let mut out = Vec::new();
    for f in function_starts(&analysis, &fpr) {
        let fp = fpr.fingerprint(f.start, f.size);
        let mut m = FunctionMatch {
            start: f.start,
            size: f.size,
            fingerprint: fp,
            status: MatchStatus::Unreadable,
            names: Vec::new(),
            names_truncated: false,
            symbol: f.symbol,
        };
        if let Some(fp) = fp {
            if !options.keeps(fp) {
                m.status = MatchStatus::TooSmall;
            } else if let Some(e) = db.get(&fp) {
                m.status = status_of(e);
                m.names = e.names.clone();
                m.names_truncated = e.truncated;
            } else {
                m.status = MatchStatus::NoMatch;
            }
        }
        out.push(m);
    }
    Ok(out)
}

/// Dependencies of the ELF file `data` (`name version`, as in
/// [`Db::sources`]) that none of the database's files had. Signatures for
/// their code cannot match; a different `rustc` commit in particular means
/// that most of the standard library will not match either.
pub fn uncovered_dependencies(db: &Db, data: &[u8]) -> Result<Vec<String>, Error> {
    let analysis = Analysis::new(data).map_err(Error::Analysis)?;
    Ok(analysis
        .dependencies()
        .into_iter()
        .map(|d| match d.version {
            Some(v) => format!("{} {v}", d.name),
            None => d.name,
        })
        .filter(|s| !db.sources.contains(s))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_bases() {
        for (name, base) in [
            (
                "core::ptr::drop_in_place<alloc::string::String>",
                "core::ptr::drop_in_place",
            ),
            ("core::ptr::drop_in_place::<u8>", "core::ptr::drop_in_place"),
            (
                "<alloc::vec::Vec<T> as core::ops::Drop>::drop",
                "<alloc::vec::Vec as core::ops::Drop>::drop",
            ),
            ("a::b<fn() -> u8>::c", "a::b::c"),
            ("memcpy", "memcpy"),
            ("x<<", "x"),
            ("<", "<"),
            ("", ""),
        ] {
            assert_eq!(generic_base(name), base, "{name}");
        }
    }

    fn entry(names: &[&str], truncated: bool) -> Entry {
        Entry {
            insns: 10,
            bytes: 30,
            names: names
                .iter()
                .map(|n| SigName {
                    name: (*n).into(),
                    krate: None,
                })
                .collect(),
            truncated,
        }
    }

    #[test]
    fn collisions_are_classified() {
        assert_eq!(status_of(&entry(&["a::f"], false)), MatchStatus::Unique);
        assert_eq!(
            status_of(&entry(&["a::f<u8>", "a::f<u16>"], false)),
            MatchStatus::SameGeneric
        );
        assert_eq!(
            status_of(&entry(&["a::f<u8>", "b::g"], false)),
            MatchStatus::Ambiguous
        );
        assert_eq!(status_of(&entry(&[], false)), MatchStatus::NoMatch);
    }

    #[test]
    fn display_names() {
        let m = FunctionMatch {
            start: 0,
            size: 1,
            fingerprint: None,
            status: MatchStatus::SameGeneric,
            names: entry(&["a::f<u16>", "a::f<u8>"], false).names,
            names_truncated: false,
            symbol: None,
        };
        assert_eq!(m.display_name().as_deref(), Some("a::f<..>"));
        assert_eq!(m.candidates(), 2);
    }

    #[test]
    fn garbage_is_an_error() {
        assert!(match_elf(&Db::new(Options::default()), b"nope").is_err());
        assert!(Db::new(Options::default()).add_elf(&[]).is_err());
        assert!(build_db(&[b"\x7fELF"], Options::default()).is_err());
    }
}

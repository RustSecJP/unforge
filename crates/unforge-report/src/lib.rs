//! What Mekiki (the desktop UI in `mekiki/`) shows about one file.
//!
//! [`report`] runs [`unforge_analysis::Analysis`] and the `unforge-elf` audit
//! (or the `unforge-pe` diagnostics for a Windows PE image) on the bytes of
//! a file and turns the results into a [`Report`], plain data
//! that serializes to JSON for the UI. The Tauri app calls it in-process; the
//! `report` example prints the same JSON for a file on the command line.
//!
//! Like the crates it builds on, nothing here panics on any input, and every
//! list is capped.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::collections::BTreeMap;

pub mod code;
pub mod setup;
pub mod signatures;

use serde::Serialize;
use unforge_analysis::{Analysis, Group, names};
use unforge_elf::{Class, ElfFile, Endian};
use unforge_pe::PeFile;

/// Bumped when the shape of [`Report`] changes (the UI checks it).
///
/// 4: PE images; [`FileSummary::format`], [`FileSummary::pdb_path`] and
/// [`Report::imports`] were added.
pub const REPORT_VERSION: u32 = 4;
/// At most this many imports are listed.
pub const MAX_IMPORT_ROWS: usize = 65_536;

/// At most this many diagnostics are put in a report.
pub const MAX_WARNINGS: usize = 1000;
/// At most this many functions are listed (all are still counted).
pub const MAX_FUNCTION_ROWS: usize = 500_000;
/// At most this many sections / segments are listed.
pub const MAX_TABLE_ROWS: usize = 65_536;
/// Section names longer than this are cut.
pub const MAX_SECTION_NAME: usize = 256;

#[derive(Debug, Serialize)]
pub struct Report {
    pub version: u32,
    pub file: FileSummary,
    /// The `rustc` commit hash found in the file, if any.
    pub rustc_commit: Option<String>,
    pub functions: FunctionCounts,
    /// Recovered functions, sorted by address.
    pub function_rows: Vec<FunctionRow>,
    /// Functions left out because of [`MAX_FUNCTION_ROWS`].
    pub functions_omitted: usize,
    pub sections: Vec<SectionRow>,
    pub segments: Vec<SegmentRow>,
    /// Dependency crates, sorted by name.
    pub crates: Vec<CrateRow>,
    /// Audit findings, most severe first.
    pub warnings: Vec<Warning>,
    /// Findings left out because of [`MAX_WARNINGS`].
    pub warnings_omitted: usize,
    /// Imported functions with the address of their pointer slot (PE: the
    /// IAT), so that calls through a slot can be labelled. Empty for ELF.
    pub imports: Vec<ImportRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportRow {
    /// Virtual address of the slot the loader fills in.
    pub slot: u64,
    /// The DLL as written in the file (`KERNEL32.dll`).
    pub dll: String,
    /// The function name, or `#<ordinal>`.
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct FileSummary {
    /// `ELF` or `PE`.
    pub format: &'static str,
    pub size: u64,
    /// `ELF32` / `ELF64`, or `PE32` / `PE32+`.
    pub class: &'static str,
    /// `little` / `big`.
    pub endian: &'static str,
    /// CPU name, or `machine 0x..` when unknown.
    pub machine: String,
    /// `executable`, `PIE executable`, `shared object`, ..., or for PE
    /// `PE executable` / `PE DLL`.
    pub kind: String,
    pub entry: u64,
    /// No `.symtab` left (PE: no COFF symbol table, as with every
    /// MSVC-linked image).
    pub stripped: bool,
    pub sections: u64,
    /// Program headers; for PE the sections again (each is mapped).
    pub segments: u64,
    /// PE: the PDB path of the CodeView record (often the build
    /// directory on the author's machine).
    pub pdb_path: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct FunctionCounts {
    pub total: usize,
    /// The program's own code.
    pub user: usize,
    pub dependency: usize,
    pub std: usize,
    /// No name, or not a Rust name.
    pub unknown: usize,
}

#[derive(Debug, Serialize)]
pub struct FunctionRow {
    pub start: u64,
    /// 0 when unknown.
    pub size: u64,
    pub name: Option<String>,
    /// `user`, `std`, `dep:<crate>` (normalized), or `None` when unknown.
    pub owner: Option<String>,
    /// Where `name` comes from: `symbols` (the file's own symbol tables) or
    /// `signature` (a fingerprint matched a known function); `None` when unnamed.
    pub named_by: Option<&'static str>,
    /// What the fingerprint database said about this function, if one was used.
    pub signature: Option<signatures::SignatureInfo>,
}

#[derive(Debug, Serialize)]
pub struct SectionRow {
    pub index: usize,
    pub name: String,
    /// `PROGBITS`, `NOBITS`, ... or `0x..`.
    pub kind: String,
    /// `W` `A` `X` `M` `S` `I` `L` `G` `T` letters, readelf style.
    pub flags: String,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    /// The section has no bytes in the file (`SHT_NOBITS`).
    pub nobits: bool,
}

#[derive(Debug, Serialize)]
pub struct SegmentRow {
    pub index: usize,
    /// `LOAD`, `DYNAMIC`, `GNU_STACK`, ... or `0x..`.
    pub kind: String,
    /// `R` `W` `E` or `-`, e.g. `R-E`.
    pub flags: String,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

#[derive(Debug, Serialize)]
pub struct CrateRow {
    /// Package name as cargo spells it (`regex-automata`) when the version
    /// was found in a source path, else the crate name from symbols.
    pub name: String,
    pub version: Option<String>,
    /// Functions attributed to this crate (from symbol names).
    pub functions: usize,
    /// Their total size in bytes (sizes that are known).
    pub bytes: u64,
    /// How the crate was found.
    pub found_in: FoundIn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FoundIn {
    /// A `registry/src/.../<crate>-<version>/` source path.
    Path,
    /// Only symbol names (so no version).
    Symbols,
    /// Both.
    Both,
    /// Only function names put back by fingerprints.
    Signatures,
}

#[derive(Debug, Serialize)]
pub struct Warning {
    /// `note`, `warning` or `would not load`.
    pub severity: String,
    /// `format`, `inference`, `consistency`, `loader` or `audit`.
    pub category: &'static str,
    /// Stable short name of the kind of finding.
    pub kind: &'static str,
    pub message: String,
    /// File offset of the bytes involved, when there is one range.
    pub offset: Option<u64>,
}

/// The input is not an ELF file or a PE image at all.
#[derive(Debug, Serialize)]
pub struct Failure {
    pub version: u32,
    pub error: String,
}

/// Analyzes `data`.
pub fn report(data: &[u8]) -> Result<Report, Failure> {
    let analysis = Analysis::new(data).map_err(|e| Failure {
        version: REPORT_VERSION,
        error: e.to_string(),
    })?;

    let mut functions = FunctionCounts::default();
    let mut function_rows = Vec::new();
    let mut functions_omitted = 0;
    // normalized crate name -> (functions, bytes)
    let mut by_crate: BTreeMap<String, (usize, u64)> = BTreeMap::new();
    for f in analysis.functions() {
        functions.total += 1;
        if function_rows.len() < MAX_FUNCTION_ROWS {
            let owner = match &f.group {
                Some(Group::Dependency(c)) if !is_crate_name(c) => None,
                g => g.as_ref().map(Group::label),
            };
            function_rows.push(FunctionRow {
                start: f.start,
                size: f.size,
                named_by: f.name.as_ref().map(|_| "symbols"),
                name: f.name.clone(),
                owner,
                signature: None,
            });
        } else {
            functions_omitted += 1;
        }
        match &f.group {
            Some(Group::User) => functions.user += 1,
            Some(Group::Std) => functions.std += 1,
            // `_` is not a crate: it is the anonymous `const _: () = { .. }`
            // block derive macros emit, whose real crate is unknown.
            Some(Group::Dependency(c)) if !is_crate_name(c) => functions.unknown += 1,
            Some(Group::Dependency(c)) => {
                functions.dependency += 1;
                let e = by_crate.entry(names::normalize_crate(c)).or_default();
                e.0 += 1;
                e.1 = e.1.saturating_add(f.size);
            }
            None => functions.unknown += 1,
        }
    }

    let mut rustc_commit = None;
    let mut crates = Vec::new();
    for d in analysis.dependencies() {
        if d.name == "rustc" {
            rustc_commit = rustc_commit.or(d.version);
            continue;
        }
        let (count, bytes, found_in) = match by_crate.remove(&names::normalize_crate(&d.name)) {
            Some((n, b)) => (n, b, FoundIn::Both),
            None => (0, 0, FoundIn::Path),
        };
        crates.push(CrateRow {
            name: d.name,
            version: d.version,
            functions: count,
            bytes,
            found_in,
        });
    }
    // A crate seen in several versions shares one symbol count; the rows
    // after the first one of each name get nothing extra from `by_crate`
    // because it was removed above. Crates only seen in symbols come last.
    for (name, (count, bytes)) in by_crate {
        crates.push(CrateRow {
            name,
            version: None,
            functions: count,
            bytes,
            found_in: FoundIn::Symbols,
        });
    }
    crates.sort_by(|a, b| {
        names::normalize_crate(&a.name)
            .cmp(&names::normalize_crate(&b.name))
            .then_with(|| a.version.cmp(&b.version))
    });

    let (file, sections, segments, (warnings, warnings_omitted), imports) =
        match (analysis.elf(), analysis.pe()) {
            (Some(elf), _) => (
                summary(elf),
                sections(elf),
                segments(elf),
                elf_warnings(elf),
                Vec::new(),
            ),
            (_, Some(pe)) => (
                pe_summary(pe),
                pe_sections(pe),
                pe_segments(pe),
                pe_warnings(pe),
                pe_imports(pe),
            ),
            _ => {
                return Err(Failure {
                    version: REPORT_VERSION,
                    error: "unknown file format".to_owned(),
                });
            }
        };

    Ok(Report {
        version: REPORT_VERSION,
        file,
        rustc_commit,
        functions,
        function_rows,
        functions_omitted,
        sections,
        segments,
        crates,
        warnings,
        warnings_omitted,
        imports,
    })
}

fn elf_warnings(elf: &ElfFile<'_>) -> (Vec<Warning>, usize) {
    let mut diagnostics = elf.diagnostics();
    diagnostics.sort_by_key(|d| std::cmp::Reverse(d.severity));
    let warnings_omitted = diagnostics.len().saturating_sub(MAX_WARNINGS);
    let warnings = diagnostics
        .into_iter()
        .take(MAX_WARNINGS)
        .map(|d| Warning {
            severity: d.severity.to_string(),
            category: category_name(d.category()),
            kind: d.kind.name(),
            message: d.to_string(),
            offset: d.location.range.map(|r| r.offset),
        })
        .collect();
    (warnings, warnings_omitted)
}

fn pe_warnings(pe: &PeFile<'_>) -> (Vec<Warning>, usize) {
    let mut diagnostics = pe.diagnostics();
    diagnostics.sort_by_key(|d| std::cmp::Reverse(d.severity));
    let omitted = diagnostics.len().saturating_sub(MAX_WARNINGS);
    let warnings = diagnostics
        .into_iter()
        .take(MAX_WARNINGS)
        .map(|d| Warning {
            severity: d.severity.to_string(),
            category: match d.category() {
                unforge_pe::Category::Format => "format",
                unforge_pe::Category::Consistency => "consistency",
                unforge_pe::Category::Loader => "loader",
                _ => "other",
            },
            kind: d.kind.name(),
            message: d.to_string(),
            offset: d.offset,
        })
        .collect();
    (warnings, omitted)
}

fn pe_summary(pe: &PeFile<'_>) -> FileSummary {
    let n = pe.sections().len() as u64;
    FileSummary {
        format: "PE",
        size: pe.data().len() as u64,
        class: match pe.kind() {
            unforge_pe::PeKind::Pe32 => "PE32",
            _ => "PE32+",
        },
        endian: "little",
        machine: pe_machine_name(pe.machine()),
        kind: if pe.is_dll() {
            "PE DLL".to_owned()
        } else {
            "PE executable".to_owned()
        },
        entry: pe
            .entry_rva()
            .and_then(|e| pe.rva_to_va(u64::from(e)))
            .unwrap_or(0),
        stripped: pe.coff_symbols().is_empty(),
        sections: n,
        segments: n,
        pdb_path: pe.codeview().map(|c| {
            String::from_utf8_lossy(c.path)
                .chars()
                .filter(|c| !c.is_control())
                .take(MAX_SECTION_NAME * 4)
                .collect()
        }),
    }
}

fn pe_machine_name(m: u16) -> String {
    match m {
        unforge_pe::MACHINE_AMD64 => "x86-64".to_owned(),
        unforge_pe::MACHINE_I386 => "x86".to_owned(),
        unforge_pe::MACHINE_ARM64 => "AArch64".to_owned(),
        unforge_pe::MACHINE_ARMNT => "ARM".to_owned(),
        _ => format!("machine 0x{m:x}"),
    }
}

/// `A` (every section is mapped), `W`, `X`, readelf style, so the UI
/// treats PE sections like ELF ones.
fn pe_section_flags(c: u32) -> String {
    let mut f = String::from("A");
    if c & unforge_pe::SCN_MEM_WRITE != 0 {
        f.push('W');
    }
    if c & (unforge_pe::SCN_MEM_EXECUTE | unforge_pe::SCN_CNT_CODE) != 0 {
        f.push('X');
    }
    f
}

fn pe_section_kind(c: u32) -> String {
    if c & unforge_pe::SCN_CNT_CODE != 0 {
        "CODE".to_owned()
    } else if c & unforge_pe::SCN_CNT_INITIALIZED_DATA != 0 {
        "DATA".to_owned()
    } else if c & unforge_pe::SCN_CNT_UNINITIALIZED_DATA != 0 {
        "BSS".to_owned()
    } else {
        format!("0x{c:x}")
    }
}

/// Sections as the loader maps them: `addr` is the virtual address, and
/// `offset` / `size` are the file bytes behind it (after the loader's
/// alignment rules), so `offset + (a - addr)` is the file offset of `a`.
/// A section with no file bytes is `nobits`, with its memory size.
fn pe_sections(pe: &PeFile<'_>) -> Vec<SectionRow> {
    let base = pe.image_base();
    let mut rows: Vec<SectionRow> = Vec::new();
    for s in pe.sections().iter().take(MAX_TABLE_ROWS) {
        let region = pe
            .regions()
            .iter()
            .find(|r| r.section == Some(s.index))
            .copied();
        let mut name = pe.section_name(s);
        name.truncate(name.floor_char_boundary(MAX_SECTION_NAME));
        let (addr, offset, size, nobits) = match region {
            Some(r) if r.file_len > 0 => (
                base.saturating_add(r.start),
                r.file_offset,
                r.file_len.min(r.end - r.start),
                false,
            ),
            Some(r) => (base.saturating_add(r.start), 0, r.end - r.start, true),
            None => (
                base.saturating_add(u64::from(s.virtual_address)),
                u64::from(s.pointer_to_raw_data),
                0,
                true,
            ),
        };
        rows.push(SectionRow {
            index: s.index,
            name,
            kind: pe_section_kind(s.characteristics),
            flags: pe_section_flags(s.characteristics),
            addr,
            offset,
            size,
            nobits,
        });
    }
    rows
}

/// For PE, every section is a mapping: the segments mirror the sections
/// (`LOAD`, `R` `W` `E` flags, file bytes and memory size).
fn pe_segments(pe: &PeFile<'_>) -> Vec<SegmentRow> {
    let base = pe.image_base();
    pe.regions()
        .iter()
        .filter_map(|r| Some((r.section?, r)))
        .take(MAX_TABLE_ROWS)
        .map(|(index, r)| SegmentRow {
            index,
            kind: "LOAD".to_owned(),
            flags: [
                (unforge_pe::SCN_MEM_READ, 'R'),
                (unforge_pe::SCN_MEM_WRITE, 'W'),
                (unforge_pe::SCN_MEM_EXECUTE | unforge_pe::SCN_CNT_CODE, 'E'),
            ]
            .iter()
            .map(|&(bit, c)| if r.characteristics & bit != 0 { c } else { '-' })
            .collect(),
            offset: r.file_offset,
            vaddr: base.saturating_add(r.start),
            filesz: r.file_len,
            memsz: r.end - r.start,
        })
        .collect()
}

fn pe_imports(pe: &PeFile<'_>) -> Vec<ImportRow> {
    let base = pe.image_base();
    let mut out = Vec::new();
    for dll in pe.imports() {
        let d: String = String::from_utf8_lossy(dll.name)
            .chars()
            .filter(|c| !c.is_control())
            .collect();
        for e in &dll.entries {
            if out.len() >= MAX_IMPORT_ROWS {
                return out;
            }
            let name = match &e.kind {
                unforge_pe::ImportKind::Name { name, .. } => String::from_utf8_lossy(name)
                    .chars()
                    .filter(|c| !c.is_control())
                    .collect(),
                unforge_pe::ImportKind::Ordinal(o) => format!("#{o}"),
                unforge_pe::ImportKind::Unreadable(_) => continue,
            };
            out.push(ImportRow {
                slot: base.saturating_add(u64::from(e.slot_rva)),
                dll: d.clone(),
                name,
            });
        }
    }
    out
}

/// [`report`], then the function starts the fingerprint matcher finds and,
/// with `db`, names for functions without symbols ([`signatures::apply`]).
pub fn report_with_signatures(
    data: &[u8],
    db: Option<&unforge_sigs::Db>,
) -> Result<(Report, signatures::Applied), Failure> {
    let mut r = report(data)?;
    let applied = signatures::apply(&mut r, data, db);
    Ok((r, applied))
}

impl Report {
    /// The functions as (`start`, `size`), for [`code::code_map_for`].
    pub fn function_spans(&self) -> Vec<(u64, u64)> {
        self.function_rows
            .iter()
            .map(|f| (f.start, f.size))
            .collect()
    }

    /// The functions as (`start`, name), for [`setup::decompiler_setup_for`].
    pub fn function_names(&self) -> Vec<(u64, Option<String>)> {
        self.function_rows
            .iter()
            .map(|f| (f.start, f.name.clone()))
            .collect()
    }
}

/// [`report`] as JSON: a [`Report`], or a [`Failure`] (which has `error`).
pub fn report_json(data: &[u8]) -> String {
    let out = match report(data) {
        Ok(r) => serde_json::to_string(&r),
        Err(f) => serde_json::to_string(&f),
    };
    out.unwrap_or_else(|e| {
        format!(
            "{{\"version\":{REPORT_VERSION},\"error\":{:?}}}",
            e.to_string()
        )
    })
}

fn summary(elf: &ElfFile<'_>) -> FileSummary {
    let h = elf.header();
    let segments = elf.program_headers().ok();
    let has_interp = segments.as_ref().is_some_and(|t| {
        (0..t.len())
            .filter_map(|i| t.get(i))
            .any(|p| p.p_type == PT_INTERP)
    });
    FileSummary {
        format: "ELF",
        size: elf.data().len() as u64,
        class: match h.class {
            Class::Elf32 => "ELF32",
            Class::Elf64 => "ELF64",
            _ => "ELF",
        },
        endian: match h.endian {
            Endian::Little => "little",
            Endian::Big => "big",
            _ => "unknown",
        },
        machine: machine_name(h.machine),
        kind: match h.e_type {
            1 => "relocatable".to_owned(),
            2 => "executable".to_owned(),
            3 if has_interp => "PIE executable".to_owned(),
            3 => "shared object".to_owned(),
            4 => "core dump".to_owned(),
            t => format!("type 0x{t:x}"),
        },
        entry: h.entry,
        stripped: elf.section_by_name(b".symtab").is_none(),
        sections: h.shnum,
        segments: h.phnum,
        pdb_path: None,
    }
}

const PT_INTERP: u32 = 3;

fn sections(elf: &ElfFile<'_>) -> Vec<SectionRow> {
    let Ok(table) = elf.section_headers() else {
        return Vec::new();
    };
    (0..table.len().min(MAX_TABLE_ROWS))
        .filter_map(|i| table.get(i).map(|sh| (i, sh)))
        .map(|(index, sh)| SectionRow {
            index,
            name: elf
                .section_name_bounded(&sh, MAX_SECTION_NAME)
                .map(|n| String::from_utf8_lossy(n.bytes).into_owned())
                .unwrap_or_default(),
            kind: section_kind(sh.sh_type),
            flags: section_flags(sh.flags),
            addr: sh.addr,
            offset: sh.offset,
            size: sh.size,
            nobits: sh.sh_type == 8,
        })
        .collect()
}

fn segments(elf: &ElfFile<'_>) -> Vec<SegmentRow> {
    let Ok(table) = elf.program_headers() else {
        return Vec::new();
    };
    (0..table.len().min(MAX_TABLE_ROWS))
        .filter_map(|i| table.get(i).map(|ph| (i, ph)))
        .map(|(index, ph)| SegmentRow {
            index,
            kind: segment_kind(ph.p_type),
            flags: [(4, 'R'), (2, 'W'), (1, 'E')]
                .iter()
                .map(|&(bit, c)| if ph.flags & bit != 0 { c } else { '-' })
                .collect(),
            offset: ph.offset,
            vaddr: ph.vaddr,
            filesz: ph.filesz,
            memsz: ph.memsz,
        })
        .collect()
}

fn section_kind(t: u32) -> String {
    let name = match t {
        0 => "NULL",
        1 => "PROGBITS",
        2 => "SYMTAB",
        3 => "STRTAB",
        4 => "RELA",
        5 => "HASH",
        6 => "DYNAMIC",
        7 => "NOTE",
        8 => "NOBITS",
        9 => "REL",
        11 => "DYNSYM",
        14 => "INIT_ARRAY",
        15 => "FINI_ARRAY",
        16 => "PREINIT_ARRAY",
        17 => "GROUP",
        18 => "SYMTAB_SHNDX",
        0x6fff_fff6 => "GNU_HASH",
        0x6fff_fffd => "VERDEF",
        0x6fff_fffe => "VERNEED",
        0x6fff_ffff => "VERSYM",
        _ => return format!("0x{t:x}"),
    };
    name.to_owned()
}

fn segment_kind(t: u32) -> String {
    let name = match t {
        0 => "NULL",
        1 => "LOAD",
        2 => "DYNAMIC",
        3 => "INTERP",
        4 => "NOTE",
        5 => "SHLIB",
        6 => "PHDR",
        7 => "TLS",
        0x6474_e550 => "GNU_EH_FRAME",
        0x6474_e551 => "GNU_STACK",
        0x6474_e552 => "GNU_RELRO",
        0x6474_e553 => "GNU_PROPERTY",
        _ => return format!("0x{t:x}"),
    };
    name.to_owned()
}

fn section_flags(f: u64) -> String {
    [
        (0x1, 'W'),
        (0x2, 'A'),
        (0x4, 'X'),
        (0x10, 'M'),
        (0x20, 'S'),
        (0x40, 'I'),
        (0x80, 'L'),
        (0x200, 'G'),
        (0x400, 'T'),
    ]
    .iter()
    .filter(|&&(bit, _)| f & bit != 0)
    .map(|&(_, c)| c)
    .collect()
}

/// A name cargo accepts for a crate: ASCII letters, digits, `_` and `-`,
/// starting with a letter or `_`, and not `_` alone.
pub fn is_crate_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    name != "_"
        && (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn machine_name(m: u16) -> String {
    let name = match m {
        2 => "SPARC",
        3 => "x86",
        8 => "MIPS",
        20 => "PowerPC",
        21 => "PowerPC64",
        22 => "s390x",
        40 => "ARM",
        43 => "SPARC V9",
        62 => "x86-64",
        183 => "AArch64",
        243 => "RISC-V",
        258 => "LoongArch",
        _ => return format!("machine 0x{m:x}"),
    };
    name.to_owned()
}

fn category_name(c: unforge_elf::Category) -> &'static str {
    use unforge_elf::Category::*;
    match c {
        Format => "format",
        Inference => "inference",
        Consistency => "consistency",
        Loader => "loader",
        Audit => "audit",
        _ => "other",
    }
}

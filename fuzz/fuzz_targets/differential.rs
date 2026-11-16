//! Differential fuzzing: parse the same bytes with `unforge-elf`, `object`
//! (low-level `read::elf` API) and `goblin` (`elf::Elf::parse`, strict mode)
//! and compare the ELF header, program headers, section headers, section
//! names and symbols wherever an oracle succeeds.
//!
//! Rules:
//! - An oracle that fails is not a divergence: `unforge-elf` is meant to be
//!   more tolerant than both oracles.
//! - `unforge-elf` failing where an oracle succeeds, or the two disagreeing on
//!   a value, is a divergence. It aborts the run unless it matches an entry of
//!   `fuzz/KNOWN_DIVERGENCES.md` (the `KD-*` constants below).
//! - An allowlisted divergence must come with the diagnostic(s) the entry
//!   names in `ElfFile::audit()`: a tolerant reading is only acceptable when
//!   it is reported. A missing diagnostic aborts the run as "silent".
//! - Oracle panics are caught (they are oracle bugs, recorded as `ORACLE-*`
//!   events); a panic inside `unforge-elf` is never caught.
//!
//! Set `UNFORGE_DIFF_REPORT=1` to print new divergences instead of aborting
//! (triage of a whole corpus in one replay).
//!
//! Set `UNFORGE_DIFF_LOG=1` to print, for every input, one `DIFF` line with
//! the comparisons that ran and the known divergences that were hit (used to
//! produce the counts in KNOWN_DIVERGENCES.md).
#![no_main]

use std::collections::BTreeSet;
use std::fmt::{Debug, Display};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use object::elf::{FileHeader32, FileHeader64};
use object::read::elf::{FileHeader, ProgramHeader as _, SectionHeader as _, Sym as _};
use object::{Endianness, SectionIndex, SymbolIndex};
use unforge_elf::{Audit, Class, DiagnosticKind, ElfFile, Endian, SectionHeader, SymbolSection};

// gABI ch4 values, spelled out rather than taken from the code under test.
const SHT_NULL: u32 = 0;
const SHT_SYMTAB: u32 = 2;
const SHT_NOBITS: u32 = 8;
const SHT_DYNSYM: u32 = 11;
const SHT_SYMTAB_SHNDX: u32 = 18;
const SHN_XINDEX: u16 = 0xffff;
const PN_XNUM: u16 = 0xffff;

/// Work bounds per input, so that hostile counts keep each run short.
const MAX_SECTIONS: usize = 4096;
const MAX_SYMBOLS: usize = 1 << 16;

/// One allowlisted divergence (see fuzz/KNOWN_DIVERGENCES.md).
#[derive(Clone, Copy)]
struct Kd {
    id: &'static str,
    /// At least one of these diagnostic kind names must be in the audit.
    /// Empty: no diagnostic is required (the entry explains why).
    needs: &'static [&'static str],
}

const KD_LAYOUT: Kd = Kd {
    id: "KD-01-layout-inferred",
    needs: &["class-mismatch", "data-mismatch"],
};
const KD_PHOFF_ZERO: Kd = Kd {
    id: "KD-02-phoff-zero",
    needs: &[],
};
const KD_PHENTSIZE: Kd = Kd {
    id: "KD-03a-phentsize-not-struct-size",
    needs: &["bad-phentsize"],
};
const KD_SHENTSIZE: Kd = Kd {
    id: "KD-03b-shentsize-not-struct-size",
    needs: &["bad-shentsize"],
};
const KD_SYMENTSIZE: Kd = Kd {
    id: "KD-03c-sym-entsize-not-struct-size",
    needs: &["symbol-entry-size"],
};
const KD_PN_XNUM: Kd = Kd {
    id: "KD-04-pn-xnum",
    needs: &[],
};
const KD_SHNUM_NO_TABLE: Kd = Kd {
    id: "KD-05-shnum-without-table",
    needs: &["shnum-without-table"],
};
const KD_NODATA_STRTAB: Kd = Kd {
    id: "KD-06-strtab-is-null-or-nobits",
    needs: &["shstrndx-not-strtab", "symbol-link-not-strtab"],
};
const KD_GOBLIN_SH0_ONLY: Kd = Kd {
    id: "KD-07-goblin-extended-shnum-zero",
    needs: &[],
};
const KD_GOBLIN_INDEX0_STRTAB: Kd = Kd {
    id: "KD-08-goblin-section0-as-strtab",
    needs: &[],
};
const KD_SHNDX_MULTI: Kd = Kd {
    id: "KD-09-several-symtab-shndx",
    needs: &["inferred-extended-index-table"],
};
const KD_XINDEX_LINK0: Kd = Kd {
    id: "KD-10-shstrndx-xindex-link-0",
    needs: &[],
};
// R-1 (KNOWN_DIVERGENCES.md) added these diagnostics.
const KD_UNTERMINATED: Kd = Kd {
    id: "KD-11-unterminated-last-string",
    needs: &[
        "string-table-unterminated",
        "section-names-unterminated",
        "symbol-names-unterminated",
    ],
};

/// `theirs` is exactly the bytes from `offset` to the end of `table`, and
/// those bytes hold no NUL: the oracle took an unterminated string to end at
/// the end of the string table.
fn unterminated_tail(table: Option<&[u8]>, offset: u32, theirs: &[u8]) -> bool {
    let Some(rest) = table.and_then(|t| t.get(offset as usize..)) else {
        return false;
    };
    !rest.contains(&0) && rest == theirs
}

fn log_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("UNFORGE_DIFF_LOG").is_some())
}

/// Triage mode (`UNFORGE_DIFF_REPORT=1`): print new divergences instead of
/// aborting, so that one replay of a corpus lists all of them.
fn report_only() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("UNFORGE_DIFF_REPORT").is_some())
}

/// Run an oracle, turning its panics into `None` without printing them.
/// libfuzzer-sys installs a hook that aborts on any panic, so the hook is
/// swapped out for the duration of the call (the target is single-threaded).
fn oracle<T>(f: impl FnOnce() -> T) -> Option<T> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = catch_unwind(AssertUnwindSafe(f));
    std::panic::set_hook(prev);
    r.ok()
}

struct Run<'a, 'data> {
    data: &'data [u8],
    ours: &'a ElfFile<'data>,
    audit: Audit,
    /// Comparisons that ran (`obj-phdrs`, ...).
    ran: BTreeSet<&'static str>,
    /// Known divergences that were hit.
    hits: BTreeSet<&'static str>,
    /// Oracle events (`ORACLE-goblin-panic`, ...).
    events: BTreeSet<&'static str>,
}

impl Run<'_, '_> {
    fn has(&self, name: &str) -> bool {
        self.audit.diagnostics.iter().any(|d| match &d.kind {
            DiagnosticKind::Suppressed { kind, .. } => *kind == name,
            k => k.name() == name,
        })
    }

    /// Record a divergence. Aborts unless `known` applies and its diagnostic
    /// is present.
    fn diverge(&mut self, what: impl Display, known: Option<Kd>) {
        match known {
            Some(kd) => {
                if !kd.needs.is_empty() && !kd.needs.iter().any(|n| self.has(n)) {
                    if report_only() {
                        eprintln!("SILENT known divergence {}: {what}", kd.id);
                        self.events.insert("SILENT");
                        return;
                    }
                    panic!(
                        "SILENT known divergence {}: {what}; none of the diagnostics {:?} \
                         is in the audit ({} diagnostics)",
                        kd.id,
                        kd.needs,
                        self.audit.diagnostics.len()
                    );
                }
                self.hits.insert(kd.id);
            }
            None => {
                let msg = format!(
                    "NEW DIVERGENCE: {what} (input {} bytes, layout {:?}/{:?})",
                    self.data.len(),
                    self.ours.header().class,
                    self.ours.header().endian
                );
                if report_only() {
                    eprintln!("{msg}");
                    self.events.insert("NEW");
                } else {
                    panic!("{msg}");
                }
            }
        }
    }

    fn eq<T: PartialEq + Debug>(&mut self, what: &str, ours: T, theirs: T, known: Option<Kd>) {
        if ours != theirs {
            self.diverge(
                format_args!("{what}: unforge={ours:?} oracle={theirs:?}"),
                known,
            );
        }
    }

    /// The section types that make a section's file bytes empty for
    /// `unforge-elf` (gABI: `SHT_NULL` has no section, `SHT_NOBITS`
    /// occupies no file space).
    fn no_data(sh: &SectionHeader) -> bool {
        sh.sh_type == SHT_NULL || sh.sh_type == SHT_NOBITS
    }
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

// ---------------------------------------------------------------------------
// object
// ---------------------------------------------------------------------------

fn compare_object<Elf: FileHeader<Endian = Endianness>>(r: &mut Run<'_, '_>) {
    let data = r.data;
    let Some(Ok(h)) = oracle(|| Elf::parse(data)) else {
        return;
    };
    let Ok(e) = h.endian() else { return };
    r.ran.insert("obj-header");
    let oh = r.ours.header().clone();

    let id = h.e_ident();
    r.eq("EI_VERSION", oh.ident_version, id.version.0, None);
    r.eq("EI_OSABI", oh.os_abi, id.os_abi.0, None);
    r.eq("EI_ABIVERSION", oh.abi_version, id.abi_version, None);
    r.eq("e_type", oh.e_type, h.e_type(e).0, None);
    r.eq("e_machine", oh.machine, h.e_machine(e).0, None);
    r.eq("e_version", oh.version, h.e_version(e), None);
    r.eq("e_entry", oh.entry, h.e_entry(e).into(), None);
    r.eq("e_phoff", oh.phoff, h.e_phoff(e).into(), None);
    r.eq("e_shoff", oh.shoff, h.e_shoff(e).into(), None);
    r.eq("e_flags", oh.flags, h.e_flags(e).0, None);
    r.eq("e_ehsize", oh.ehsize, h.e_ehsize(e), None);
    r.eq("e_phentsize", oh.phentsize, h.e_phentsize(e), None);
    r.eq("e_shentsize", oh.shentsize, h.e_shentsize(e), None);
    r.eq("raw e_phnum", oh.raw_phnum, h.e_phnum(e), None);
    r.eq("raw e_shnum", oh.raw_shnum, h.e_shnum(e), None);
    r.eq("raw e_shstrndx", oh.raw_shstrndx, h.e_shstrndx(e).0, None);

    if let Ok(n) = h.phnum(e, data) {
        r.ran.insert("obj-phnum");
        r.eq("resolved phnum", oh.phnum, u64::from(n), None);
    }
    if let Ok(n) = h.shnum(e, data) {
        r.ran.insert("obj-shnum");
        let known = (oh.shoff == 0 && oh.raw_shnum != 0).then_some(KD_SHNUM_NO_TABLE);
        r.eq("resolved shnum", oh.shnum, u64::from(n), known);
    }
    if let Ok(n) = h.shstrndx(e, data) {
        r.ran.insert("obj-shstrndx");
        let known = (oh.raw_shstrndx == SHN_XINDEX && n == 0).then_some(KD_XINDEX_LINK0);
        r.eq("resolved shstrndx", oh.shstrndx, Some(n), known);
    }

    // --- program headers ---------------------------------------------------
    if let Ok(tp) = h.program_headers(e, data) {
        r.ran.insert("obj-phdrs");
        match r.ours.program_headers() {
            // object returns an empty table for e_phoff == 0 before looking
            // at e_phnum; unforge reads e_phnum and may fail (e.g. PN_XNUM
            // without a readable section 0).
            Err(err) => r.diverge(
                format_args!(
                    "program headers: unforge failed ({err}), object read {}",
                    tp.len()
                ),
                (oh.phoff == 0 && tp.is_empty()).then_some(KD_PHOFF_ZERO),
            ),
            Ok(op) => {
                let known = (oh.phoff == 0 && tp.is_empty()).then_some(KD_PHOFF_ZERO);
                r.eq("program header count", op.len(), tp.len(), known);
                for (i, (o, t)) in op.iter().zip(tp).enumerate() {
                    let ours = (
                        o.p_type, o.flags, o.offset, o.vaddr, o.paddr, o.filesz, o.memsz, o.align,
                    );
                    let theirs = (
                        t.p_type(e).0,
                        t.p_flags(e).0,
                        t.p_offset(e).into(),
                        t.p_vaddr(e).into(),
                        t.p_paddr(e).into(),
                        t.p_filesz(e).into(),
                        t.p_memsz(e).into(),
                        t.p_align(e).into(),
                    );
                    r.eq(&format!("phdr[{i}]"), ours, theirs, None);
                }
            }
        }
    }

    // --- section headers ---------------------------------------------------
    let Ok(tsh) = h.section_headers(e, data) else {
        return;
    };
    r.ran.insert("obj-shdrs");
    let osh = match r.ours.section_headers() {
        Ok(s) => s,
        Err(err) => {
            r.diverge(
                format_args!(
                    "section headers: unforge failed ({err}), object read {}",
                    tsh.len()
                ),
                None,
            );
            return;
        }
    };
    r.eq("section header count", osh.len(), tsh.len(), None);
    let n = osh.len().min(tsh.len()).min(MAX_SECTIONS);
    for (i, (o, t)) in osh.iter().zip(tsh).take(n).enumerate() {
        let ours = (
            o.name,
            o.sh_type,
            o.flags,
            o.addr,
            o.offset,
            o.size,
            o.link,
            o.info,
            o.addralign,
            o.entsize,
        );
        let theirs = (
            t.sh_name(e),
            t.sh_type(e).0,
            t.sh_flags(e).0,
            t.sh_addr(e).into(),
            t.sh_offset(e).into(),
            t.sh_size(e).into(),
            t.sh_link(e),
            t.sh_info(e),
            t.sh_addralign(e).into(),
            t.sh_entsize(e).into(),
        );
        r.eq(&format!("shdr[{i}]"), ours, theirs, None);
    }
    if osh.len() != tsh.len() {
        return;
    }

    // --- section names -----------------------------------------------------
    if let Ok(table) = h.sections(e, data) {
        r.ran.insert("obj-names");
        // object reads SHT_NULL sections' file bytes; unforge does not.
        let shstrtab_nodata = r
            .ours
            .header()
            .shstrndx
            .and_then(|i| osh.get(i as usize))
            .is_some_and(|s| Run::no_data(&s));
        // e_shstrndx == SHN_XINDEX and sh0.sh_link == 0: object uses
        // section 0 as the name table, unforge has none (SHN_UNDEF).
        let xindex_link0 = oh.raw_shstrndx == SHN_XINDEX && osh.get(0).is_some_and(|s| s.link == 0);
        let names_known = if xindex_link0 {
            Some(KD_XINDEX_LINK0)
        } else {
            shstrtab_nodata.then_some(KD_NODATA_STRTAB)
        };
        for (i, (o, t)) in osh.iter().zip(tsh).take(n).enumerate() {
            let Ok(theirs) = table.section_name(e, t) else {
                continue;
            };
            match r.ours.section_name(&o) {
                Ok(ours) => r.eq(
                    &format!("shdr[{i}] name"),
                    lossy(ours),
                    lossy(theirs),
                    names_known,
                ),
                Err(err) => r.diverge(
                    format_args!(
                        "shdr[{i}] name: unforge failed ({err}), object read {:?}",
                        lossy(theirs)
                    ),
                    names_known,
                ),
            }
        }
    }

    // --- symbol tables -----------------------------------------------------
    // Symbols do not need section names: without them, build the table alone.
    let table = h
        .sections(e, data)
        .unwrap_or_else(|_| object::read::elf::SectionTable::new(tsh, Default::default()));
    let mut budget = MAX_SYMBOLS;
    for (si, osec) in osh.iter().enumerate().take(n) {
        if osec.sh_type != SHT_SYMTAB && osec.sh_type != SHT_DYNSYM {
            continue;
        }
        let Ok(tt) = table.symbol_table_by_index(e, data, SectionIndex(si)) else {
            continue;
        };
        r.ran.insert("obj-symtab");
        let ot = match r.ours.symbol_table(si) {
            Ok(t) => t,
            Err(err) => {
                r.diverge(
                    format_args!(
                        "symtab[{si}]: unforge failed ({err}), object read {}",
                        tt.len()
                    ),
                    None,
                );
                continue;
            }
        };
        let size = match r.ours.header().class {
            Class::Elf32 => 16,
            _ => 24,
        };
        // object ignores sh_entsize and reads packed `sizeof(Sym)` entries.
        let entsize_known = (osec.entsize > size).then_some(KD_SYMENTSIZE);
        r.eq(
            &format!("symtab[{si}] count"),
            ot.len(),
            tt.len(),
            entsize_known,
        );
        let shndx_tables = osh
            .iter()
            .filter(|s| s.sh_type == SHT_SYMTAB_SHNDX && s.link as usize == si)
            .count();
        for (j, (o, t)) in ot.iter().zip(tt.symbols()).enumerate() {
            if budget == 0 {
                return;
            }
            budget -= 1;
            let at = format!("symtab[{si}][{j}]");
            let ours = (o.name, o.value, o.size, o.info, o.other, o.raw_shndx);
            let theirs = (
                t.st_name(e),
                t.st_value(e).into(),
                t.st_size(e).into(),
                t.st_info().0,
                t.st_other().0,
                t.st_shndx(e).0,
            );
            r.eq(&at, ours, theirs, entsize_known);
            if ours != theirs {
                continue;
            }
            if let Ok(theirs) = tt.symbol_name(e, t) {
                match ot.name(&o) {
                    Ok(ours) => r.eq(&format!("{at} name"), lossy(ours), lossy(theirs), None),
                    Err(err) => r.diverge(
                        format_args!(
                            "{at} name: unforge failed ({err}), object read {:?}",
                            lossy(theirs)
                        ),
                        None,
                    ),
                }
            }
            if let Ok(theirs) = tt.symbol_section(e, t, SymbolIndex(j)) {
                let mine = match o.section {
                    SymbolSection::Index(n) if n != 0 => Some(n as usize),
                    _ => None,
                };
                let known =
                    (o.raw_shndx == SHN_XINDEX && shndx_tables > 1).then_some(KD_SHNDX_MULTI);
                r.eq(
                    &format!("{at} resolved section"),
                    mine,
                    theirs.map(|s| s.0),
                    known,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// goblin
// ---------------------------------------------------------------------------

fn compare_goblin(r: &mut Run<'_, '_>) {
    let data = r.data;
    let g = match oracle(|| goblin::elf::Elf::parse(data)) {
        None => {
            r.events.insert("ORACLE-goblin-panic");
            return;
        }
        Some(Err(_)) => return,
        Some(Ok(g)) => g,
    };
    r.ran.insert("gob-elf");
    let oh = r.ours.header().clone();
    let gh = &g.header;
    r.eq("goblin e_type", oh.e_type, gh.e_type, None);
    r.eq("goblin e_machine", oh.machine, gh.e_machine, None);
    r.eq("goblin e_version", oh.version, gh.e_version, None);
    r.eq("goblin e_entry", oh.entry, gh.e_entry, None);
    r.eq("goblin e_phoff", oh.phoff, gh.e_phoff, None);
    r.eq("goblin e_shoff", oh.shoff, gh.e_shoff, None);
    r.eq("goblin e_flags", oh.flags, gh.e_flags, None);
    r.eq("goblin e_ehsize", oh.ehsize, gh.e_ehsize, None);
    r.eq("goblin e_phentsize", oh.phentsize, gh.e_phentsize, None);
    r.eq("goblin e_shentsize", oh.shentsize, gh.e_shentsize, None);
    r.eq("goblin raw e_phnum", oh.raw_phnum, gh.e_phnum, None);
    r.eq("goblin raw e_shnum", oh.raw_shnum, gh.e_shnum, None);
    r.eq(
        "goblin raw e_shstrndx",
        oh.raw_shstrndx,
        gh.e_shstrndx,
        None,
    );
    r.eq("goblin is_64", oh.class == Class::Elf64, g.is_64, None);
    r.eq(
        "goblin little_endian",
        oh.endian == Endian::Little,
        g.little_endian,
        None,
    );

    // --- program headers ---------------------------------------------------
    // goblin reads raw e_phnum entries at sizeof(Phdr) strides, ignoring
    // e_phentsize and PN_XNUM.
    let ph_size: u16 = if g.is_64 { 56 } else { 32 };
    let ph_known = if oh.raw_phnum == PN_XNUM {
        Some(KD_PN_XNUM)
    } else if oh.phentsize > ph_size {
        Some(KD_PHENTSIZE)
    } else {
        None
    };
    match r.ours.program_headers() {
        Err(err) if !g.program_headers.is_empty() => r.diverge(
            format_args!(
                "goblin program headers: unforge failed ({err}), goblin read {}",
                g.program_headers.len()
            ),
            ph_known,
        ),
        Err(_) => {}
        Ok(op) => {
            r.ran.insert("gob-phdrs");
            r.eq(
                "goblin phdr count",
                op.len(),
                g.program_headers.len(),
                ph_known,
            );
            for (i, (o, t)) in op.iter().zip(&g.program_headers).enumerate() {
                r.eq(
                    &format!("goblin phdr[{i}]"),
                    (
                        o.p_type, o.flags, o.offset, o.vaddr, o.paddr, o.filesz, o.memsz, o.align,
                    ),
                    (
                        t.p_type, t.p_flags, t.p_offset, t.p_vaddr, t.p_paddr, t.p_filesz,
                        t.p_memsz, t.p_align,
                    ),
                    ph_known,
                );
            }
        }
    }

    // --- section headers ---------------------------------------------------
    let osh = match r.ours.section_headers() {
        Ok(s) => s,
        Err(err) => {
            if !g.section_headers.is_empty() {
                r.diverge(
                    format_args!(
                        "goblin section headers: unforge failed ({err}), goblin read {}",
                        g.section_headers.len()
                    ),
                    None,
                );
            }
            return;
        }
    };
    r.ran.insert("gob-shdrs");
    let sh_size: u16 = if g.is_64 { 64 } else { 40 };
    let sh0_size = g.section_headers.first().map(|s| s.sh_size);
    let sh_known = if oh.shentsize > sh_size && g.section_headers.len() > 1 {
        Some(KD_SHENTSIZE)
    } else if oh.raw_shnum == 0 && oh.shoff != 0 && sh0_size == Some(0) {
        // e_shnum == 0 escape with sh0.sh_size == 0: goblin keeps sh0.
        Some(KD_GOBLIN_SH0_ONLY)
    } else {
        None
    };
    let sh0_only = sh_known.is_some_and(|k| k.id == KD_GOBLIN_SH0_ONLY.id);
    if sh0_only {
        // goblin's table is [sh0]; unforge's is empty.
        r.eq(
            "goblin shdr count",
            osh.len(),
            g.section_headers.len(),
            sh_known,
        );
        return;
    }
    r.eq(
        "goblin shdr count",
        osh.len(),
        g.section_headers.len(),
        sh_known,
    );
    let n = osh.len().min(g.section_headers.len()).min(MAX_SECTIONS);
    let mut shdrs_agree = osh.len() == g.section_headers.len();
    for (i, (o, t)) in osh.iter().zip(&g.section_headers).take(n).enumerate() {
        let ours = (
            o.name as usize,
            o.sh_type,
            o.flags,
            o.addr,
            o.offset,
            o.size,
            o.link,
            o.info,
            o.addralign,
            o.entsize,
        );
        let theirs = (
            t.sh_name,
            t.sh_type,
            t.sh_flags,
            t.sh_addr,
            t.sh_offset,
            t.sh_size,
            t.sh_link,
            t.sh_info,
            t.sh_addralign,
            t.sh_entsize,
        );
        if ours != theirs {
            shdrs_agree = false;
        }
        r.eq(&format!("goblin shdr[{i}]"), ours, theirs, sh_known);
    }
    if !shdrs_agree {
        return;
    }

    // --- section names -----------------------------------------------------
    // goblin: e_shstrndx (SHN_XINDEX via sh0.sh_link) names the table,
    // whatever its type and including index 0.
    let gob_strndx = if oh.raw_shstrndx == SHN_XINDEX {
        osh.get(0).map(|s| s.link as usize)
    } else {
        Some(usize::from(oh.raw_shstrndx))
    };
    let name_known = match gob_strndx.and_then(|i| osh.get(i).map(|s| (i, s))) {
        Some((0, _)) => Some(KD_GOBLIN_INDEX0_STRTAB),
        Some((_, s)) if Run::no_data(&s) => Some(KD_NODATA_STRTAB),
        _ => None,
    };
    r.ran.insert("gob-names");
    for (i, o) in osh.iter().take(n).enumerate() {
        let Some(theirs) = g.shdr_strtab.get_at(o.name as usize) else {
            continue;
        };
        match r.ours.section_name(&o) {
            Ok(ours) => r.eq(
                &format!("goblin shdr[{i}] name"),
                lossy(ours),
                theirs.to_owned(),
                name_known,
            ),
            Err(err) => {
                let known = name_known.or_else(|| {
                    let table = r.ours.section_name_table().ok();
                    unterminated_tail(table, o.name, theirs.as_bytes()).then_some(KD_UNTERMINATED)
                });
                r.diverge(
                    format_args!(
                        "goblin shdr[{i}] name: unforge failed ({err}), goblin read {theirs:?}"
                    ),
                    known,
                )
            }
        }
    }

    // --- .symtab (goblin: the last SHT_SYMTAB) -----------------------------
    let Some(si) = osh
        .iter()
        .enumerate()
        .filter(|(_, s)| s.sh_type == SHT_SYMTAB)
        .map(|(i, _)| i)
        .next_back()
    else {
        return;
    };
    let Ok(sec) = r.ours.section_header(si) else {
        return;
    };
    let ot = match r.ours.symbol_table(si) {
        Ok(t) => t,
        Err(err) => {
            if !g.syms.is_empty() {
                r.diverge(
                    format_args!("goblin symtab[{si}]: unforge failed ({err})"),
                    None,
                );
            }
            return;
        }
    };
    r.ran.insert("gob-symtab");
    let sym_size: u64 = if g.is_64 { 24 } else { 16 };
    // goblin: count = sh_size / sh_entsize, stride sizeof(Sym).
    let sym_known = (sec.entsize != sym_size).then_some(KD_SYMENTSIZE);
    let strtab_known = match sec.link {
        0 => Some(KD_GOBLIN_INDEX0_STRTAB),
        l => osh
            .get(l as usize)
            .filter(Run::no_data)
            .map(|_| KD_NODATA_STRTAB),
    };
    r.eq(
        &format!("goblin symtab[{si}] count"),
        ot.len(),
        g.syms.len(),
        sym_known,
    );
    for (j, (o, t)) in ot.iter().zip(g.syms.iter()).enumerate().take(MAX_SYMBOLS) {
        let at = format!("goblin symtab[{si}][{j}]");
        let ours = (
            o.name as usize,
            o.info,
            o.other,
            o.raw_shndx as usize,
            o.value,
            o.size,
        );
        let theirs = (
            t.st_name, t.st_info, t.st_other, t.st_shndx, t.st_value, t.st_size,
        );
        r.eq(&at, ours, theirs, sym_known);
        if ours != theirs {
            continue;
        }
        let Some(theirs) = g.strtab.get_at(t.st_name) else {
            continue;
        };
        match ot.name(&o) {
            Ok(ours) => r.eq(
                &format!("{at} name"),
                lossy(ours),
                theirs.to_owned(),
                strtab_known,
            ),
            Err(err) => {
                let known = strtab_known.or_else(|| {
                    unterminated_tail(ot.strtab(), o.name, theirs.as_bytes())
                        .then_some(KD_UNTERMINATED)
                });
                r.diverge(
                    format_args!("{at} name: unforge failed ({err}), goblin read {theirs:?}"),
                    known,
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------

fuzz_target!(|data: &[u8]| {
    let ident = (data.get(4).copied(), data.get(5).copied());
    let ours = match ElfFile::parse(data) {
        Ok(f) => f,
        Err(err) => {
            // unforge fails only without an ELF header; the oracles must
            // fail too.
            let obj = match ident.0 {
                Some(1) => oracle(|| FileHeader32::<Endianness>::parse(data).is_ok()),
                Some(2) => oracle(|| FileHeader64::<Endianness>::parse(data).is_ok()),
                _ => Some(false),
            };
            if obj == Some(true) {
                panic!("NEW DIVERGENCE: unforge parse failed ({err}), object read the header");
            }
            if oracle(|| goblin::elf::Elf::parse(data).is_ok()) == Some(true) {
                panic!("NEW DIVERGENCE: unforge parse failed ({err}), goblin parsed the file");
            }
            return;
        }
    };
    let mut r = Run {
        data,
        ours: &ours,
        audit: ours.audit(),
        ran: BTreeSet::new(),
        hits: BTreeSet::new(),
        events: BTreeSet::new(),
    };

    let h = ours.header();
    let claimed = (
        match ident.0 {
            Some(1) => Some(Class::Elf32),
            Some(2) => Some(Class::Elf64),
            _ => None,
        },
        match ident.1 {
            Some(1) => Some(Endian::Little),
            Some(2) => Some(Endian::Big),
            _ => None,
        },
    );
    if claimed == (Some(h.class), Some(h.endian)) {
        match h.class {
            Class::Elf32 => compare_object::<FileHeader32<Endianness>>(&mut r),
            _ => compare_object::<FileHeader64<Endianness>>(&mut r),
        }
        compare_goblin(&mut r);
    } else if let (Some(c), Some(_)) = claimed {
        // The oracles read the layout EI_CLASS/EI_DATA claim; unforge chose
        // another one from stronger clues. Whether an oracle accepts the
        // header is all that can be compared.
        let obj = match c {
            Class::Elf32 => oracle(|| FileHeader32::<Endianness>::parse(data).is_ok()),
            _ => oracle(|| FileHeader64::<Endianness>::parse(data).is_ok()),
        };
        if obj == Some(true) {
            r.diverge(
                "layout: unforge did not use EI_CLASS/EI_DATA",
                Some(KD_LAYOUT),
            );
        }
    }

    if log_enabled() {
        let join = |s: &BTreeSet<&str>| s.iter().copied().collect::<Vec<_>>().join(",");
        eprintln!(
            "DIFF ran={} hits={} events={}",
            join(&r.ran),
            join(&r.hits),
            join(&r.events)
        );
    }
});

//! Differential test: every ELF file in `testdata/bin` (built by
//! `testdata/build.sh`) is parsed by `unforge_elf::ElfFile` and by the `object`
//! crate's low-level ELF reader (plus `goblin` for a second opinion on headers
//! and `.symtab`). Every field must agree.
//!
//! `object` and `goblin` are used only as oracles here; see the workspace
//! `Cargo.toml`.
//!
//! Notes on where the oracles are *stricter* than the gABI (and therefore may
//! legitimately reject a file we accept): `object` requires `e_shentsize` /
//! `e_phentsize` to equal the structure size and its slices to be aligned in
//! memory. Such oracle errors are reported as notes, not mismatches, unless we
//! fail where the oracle succeeds.

use std::fmt::Debug;
use std::path::{Path, PathBuf};

use object::elf::{FileHeader32, FileHeader64};
use object::read::elf::{FileHeader, ProgramHeader as _, SectionHeader as _, Sym as _};
use object::{Endianness, SectionIndex, SymbolIndex};
use unforge_elf::{Category, Class, ElfFile, Endian, LayoutSource, Severity, SymbolSection};

const ELFMAG: &[u8; 4] = b"\x7fELF";

// gABI ch4 values, spelled out here rather than taken from the code under test.
const SHN_XINDEX: u16 = 0xffff;
const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/bin")
}

/// Every regular file under `dir`, recursively, skipping dot-directories
/// (`bin/.gen` holds generated sources and logs) and symlinks.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.path());
    for e in entries {
        let path = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() {
            if !e.file_name().to_string_lossy().starts_with('.') {
                walk(&path, out);
            }
        } else if ft.is_file() {
            out.push(path);
        }
    }
}

/// Collects mismatches for one file so they can all be reported at once.
struct Diff {
    errors: Vec<String>,
    notes: Vec<String>,
}

impl Diff {
    fn eq<T: PartialEq + Debug>(&mut self, what: impl FnOnce() -> String, ours: T, theirs: T) {
        if ours != theirs {
            self.errors
                .push(format!("{}: ours={ours:?} oracle={theirs:?}", what()));
        }
    }
}

/// Which interesting properties the corpus as a whole has.
#[derive(Default, Debug)]
struct Coverage {
    elf32: usize,
    elf64: usize,
    big_endian: usize,
    little_endian: usize,
    et_rel: usize,
    et_exec: usize,
    et_dyn: usize,
    shnum_escape: usize,
    shstrndx_escape: usize,
    sym_xindex: usize,
    symbols: usize,
    sections: usize,
    segments: usize,
}

fn compare_object<Elf: FileHeader<Endian = Endianness>>(
    data: &[u8],
    ours: &ElfFile<'_>,
    d: &mut Diff,
    cov: &mut Coverage,
) {
    let h = match Elf::parse(data) {
        Ok(h) => h,
        Err(e) => {
            d.errors.push(format!("object: cannot parse header: {e}"));
            return;
        }
    };
    let endian = match h.endian() {
        Ok(e) => e,
        Err(e) => {
            d.errors.push(format!("object: bad endian: {e}"));
            return;
        }
    };
    let oh = ours.header();

    // --- ELF header -------------------------------------------------------
    let id = h.e_ident();
    d.eq(
        || "e_ident[EI_VERSION]".into(),
        oh.ident_version,
        id.version.0,
    );
    d.eq(|| "e_ident[EI_OSABI]".into(), oh.os_abi, id.os_abi.0);
    d.eq(
        || "e_ident[EI_ABIVERSION]".into(),
        oh.abi_version,
        id.abi_version,
    );
    d.eq(|| "e_type".into(), oh.e_type, h.e_type(endian).0);
    d.eq(|| "e_machine".into(), oh.machine, h.e_machine(endian).0);
    d.eq(|| "e_version".into(), oh.version, h.e_version(endian));
    d.eq(|| "e_entry".into(), oh.entry, h.e_entry(endian).into());
    d.eq(|| "e_phoff".into(), oh.phoff, h.e_phoff(endian).into());
    d.eq(|| "e_shoff".into(), oh.shoff, h.e_shoff(endian).into());
    d.eq(|| "e_flags".into(), oh.flags, h.e_flags(endian).0);
    d.eq(|| "e_ehsize".into(), oh.ehsize, h.e_ehsize(endian));
    d.eq(|| "e_phentsize".into(), oh.phentsize, h.e_phentsize(endian));
    d.eq(|| "e_shentsize".into(), oh.shentsize, h.e_shentsize(endian));
    d.eq(|| "raw e_phnum".into(), oh.raw_phnum, h.e_phnum(endian));
    d.eq(|| "raw e_shnum".into(), oh.raw_shnum, h.e_shnum(endian));
    d.eq(
        || "raw e_shstrndx".into(),
        oh.raw_shstrndx,
        h.e_shstrndx(endian).0,
    );

    match h.phnum(endian, data) {
        Ok(n) => d.eq(|| "resolved phnum".into(), oh.phnum, u64::from(n)),
        Err(e) => d.notes.push(format!("object phnum: {e}")),
    }
    match h.shnum(endian, data) {
        Ok(n) => d.eq(|| "resolved shnum".into(), oh.shnum, u64::from(n)),
        Err(e) => d.notes.push(format!("object shnum: {e}")),
    }
    // object reports SHN_UNDEF as an error ("Missing ELF e_shstrndx"); we
    // report it as `None`.
    match h.shstrndx(endian, data) {
        Ok(n) => d.eq(|| "resolved shstrndx".into(), oh.shstrndx, Some(n)),
        Err(e) => {
            if oh.raw_shstrndx == 0 {
                d.eq(|| "resolved shstrndx (SHN_UNDEF)".into(), oh.shstrndx, None);
            } else {
                d.notes.push(format!("object shstrndx: {e}"));
            }
        }
    }
    if oh.shoff != 0 && oh.raw_shnum == 0 {
        cov.shnum_escape += 1;
    }
    if oh.shoff != 0 && oh.raw_shstrndx == SHN_XINDEX {
        cov.shstrndx_escape += 1;
    }

    // --- program headers --------------------------------------------------
    match (ours.program_headers(), h.program_headers(endian, data)) {
        (Ok(op), Ok(tp)) => {
            d.eq(|| "program header count".into(), op.len(), tp.len());
            cov.segments += op.len();
            for (i, (o, t)) in op.iter().zip(tp).enumerate() {
                d.eq(|| format!("phdr[{i}].p_type"), o.p_type, t.p_type(endian).0);
                d.eq(
                    || format!("phdr[{i}].p_flags"),
                    o.flags,
                    t.p_flags(endian).0,
                );
                d.eq(
                    || format!("phdr[{i}].p_offset"),
                    o.offset,
                    t.p_offset(endian).into(),
                );
                d.eq(
                    || format!("phdr[{i}].p_vaddr"),
                    o.vaddr,
                    t.p_vaddr(endian).into(),
                );
                d.eq(
                    || format!("phdr[{i}].p_paddr"),
                    o.paddr,
                    t.p_paddr(endian).into(),
                );
                d.eq(
                    || format!("phdr[{i}].p_filesz"),
                    o.filesz,
                    t.p_filesz(endian).into(),
                );
                d.eq(
                    || format!("phdr[{i}].p_memsz"),
                    o.memsz,
                    t.p_memsz(endian).into(),
                );
                d.eq(
                    || format!("phdr[{i}].p_align"),
                    o.align,
                    t.p_align(endian).into(),
                );
            }
        }
        (Err(e), Ok(_)) => d
            .errors
            .push(format!("ours failed on program headers: {e}")),
        (Ok(_), Err(e)) => d.notes.push(format!("object program headers: {e}")),
        (Err(a), Err(b)) => d.notes.push(format!("both failed on phdrs: {a} / {b}")),
    }

    // --- section headers and names ----------------------------------------
    let tsections = match h.sections(endian, data) {
        Ok(s) => s,
        Err(e) => {
            if let Err(o) = ours.section_headers() {
                d.notes.push(format!("both failed on sections: {o} / {e}"));
            } else {
                d.notes.push(format!("object sections: {e}"));
            }
            return;
        }
    };
    let osections = match ours.section_headers() {
        Ok(s) => s,
        Err(e) => {
            d.errors
                .push(format!("ours failed on section headers: {e}"));
            return;
        }
    };
    d.eq(
        || "section header count".into(),
        osections.len(),
        tsections.len(),
    );
    cov.sections += osections.len();
    for (i, (o, t)) in osections.iter().zip(tsections.iter()).enumerate() {
        d.eq(|| format!("shdr[{i}].sh_name"), o.name, t.sh_name(endian));
        d.eq(
            || format!("shdr[{i}].sh_type"),
            o.sh_type,
            t.sh_type(endian).0,
        );
        d.eq(
            || format!("shdr[{i}].sh_flags"),
            o.flags,
            t.sh_flags(endian).0,
        );
        d.eq(
            || format!("shdr[{i}].sh_addr"),
            o.addr,
            t.sh_addr(endian).into(),
        );
        d.eq(
            || format!("shdr[{i}].sh_offset"),
            o.offset,
            t.sh_offset(endian).into(),
        );
        d.eq(
            || format!("shdr[{i}].sh_size"),
            o.size,
            t.sh_size(endian).into(),
        );
        d.eq(|| format!("shdr[{i}].sh_link"), o.link, t.sh_link(endian));
        d.eq(|| format!("shdr[{i}].sh_info"), o.info, t.sh_info(endian));
        d.eq(
            || format!("shdr[{i}].sh_addralign"),
            o.addralign,
            t.sh_addralign(endian).into(),
        );
        d.eq(
            || format!("shdr[{i}].sh_entsize"),
            o.entsize,
            t.sh_entsize(endian).into(),
        );
        match (ours.section_name(&o), tsections.section_name(endian, t)) {
            (Ok(a), Ok(b)) => {
                if a != b {
                    d.errors.push(format!(
                        "shdr[{i}] name: ours={:?} oracle={:?}",
                        String::from_utf8_lossy(a),
                        String::from_utf8_lossy(b)
                    ));
                }
            }
            (Err(e), Ok(_)) => d.errors.push(format!("shdr[{i}] name: ours failed: {e}")),
            (Ok(_), Err(e)) => d.notes.push(format!("shdr[{i}] name: object failed: {e}")),
            (Err(_), Err(_)) => {}
        }
    }

    // `section_by_name` must find the first section with each name.
    for t in tsections.iter().take(64) {
        if let Ok(name) = tsections.section_name(endian, t) {
            let first = tsections
                .iter()
                .position(|s| tsections.section_name(endian, s).is_ok_and(|n| n == name));
            d.eq(
                || format!("section_by_name({:?})", String::from_utf8_lossy(name)),
                ours.section_by_name(name).map(|(idx, _)| idx),
                first,
            );
        }
    }

    // --- symbol tables ----------------------------------------------------
    let symtab_indices: Vec<usize> = osections
        .iter()
        .enumerate()
        .filter(|(_, s)| s.sh_type == SHT_SYMTAB || s.sh_type == SHT_DYNSYM)
        .map(|(i, _)| i)
        .collect();
    match ours.symbol_tables() {
        Ok(tables) => d.eq(
            || "symbol_tables() section indices".into(),
            tables.map(|t| t.section_index).collect::<Vec<_>>(),
            symtab_indices.clone(),
        ),
        Err(e) => d.errors.push(format!("ours symbol_tables(): {e}")),
    }
    for &si in &symtab_indices {
        let tt = match tsections.symbol_table_by_index(endian, data, SectionIndex(si)) {
            Ok(t) => t,
            Err(e) => {
                d.notes.push(format!("object symtab[{si}]: {e}"));
                continue;
            }
        };
        let ot = match ours.symbol_table(si) {
            Ok(t) => t,
            Err(e) => {
                d.errors.push(format!("ours symbol_table({si}): {e}"));
                continue;
            }
        };
        d.eq(|| format!("symtab[{si}] count"), ot.len(), tt.len());
        cov.symbols += ot.len();
        for (j, (o, t)) in ot.iter().zip(tt.symbols()).enumerate() {
            let at = || format!("symtab[{si}][{j}]");
            d.eq(|| format!("{}.st_name", at()), o.name, t.st_name(endian));
            d.eq(
                || format!("{}.st_value", at()),
                o.value,
                t.st_value(endian).into(),
            );
            d.eq(
                || format!("{}.st_size", at()),
                o.size,
                t.st_size(endian).into(),
            );
            d.eq(|| format!("{}.st_info", at()), o.info, t.st_info().0);
            d.eq(|| format!("{}.st_other", at()), o.other, t.st_other().0);
            d.eq(
                || format!("{}.st_shndx raw", at()),
                o.raw_shndx,
                t.st_shndx(endian).0,
            );
            if o.raw_shndx == SHN_XINDEX {
                cov.sym_xindex += 1;
            }
            match (ot.name(&o), tt.symbol_name(endian, t)) {
                (Ok(a), Ok(b)) => {
                    if a != b {
                        d.errors.push(format!(
                            "{} name: ours={:?} oracle={:?}",
                            at(),
                            String::from_utf8_lossy(a),
                            String::from_utf8_lossy(b)
                        ));
                    }
                }
                (Err(e), Ok(_)) => d.errors.push(format!("{} name: ours failed: {e}", at())),
                (Ok(_), Err(e)) => d.notes.push(format!("{} name: object failed: {e}", at())),
                (Err(_), Err(_)) => {}
            }
            // object: Some(index) for a real section (incl. resolved
            // SHN_XINDEX), None for UNDEF / ABS / COMMON / other reserved.
            let theirs = tt
                .symbol_section(endian, t, SymbolIndex(j))
                .map(|s| s.map(|s| s.0));
            let mine = match o.section {
                SymbolSection::Index(n) if n != 0 => Some(n as usize),
                SymbolSection::Index(_) => None,
                SymbolSection::Undefined
                | SymbolSection::Absolute
                | SymbolSection::Common
                | SymbolSection::Reserved(_)
                | SymbolSection::Unresolved => None,
                _ => None,
            };
            match theirs {
                Ok(t) => d.eq(|| format!("{} resolved section", at()), mine, t),
                Err(e) => d.notes.push(format!("{} object symbol_section: {e}", at())),
            }
            // And the classification of the reserved values themselves.
            let expected_kind = match o.raw_shndx {
                0 => Some(SymbolSection::Undefined),
                0xfff1 => Some(SymbolSection::Absolute),
                0xfff2 => Some(SymbolSection::Common),
                SHN_XINDEX => None, // checked above via the oracle
                n if n >= 0xff00 => Some(SymbolSection::Reserved(n)),
                n => Some(SymbolSection::Index(n.into())),
            };
            if let Some(k) = expected_kind {
                d.eq(|| format!("{} section kind", at()), o.section, k);
            }
        }
    }
}

fn compare_goblin(data: &[u8], ours: &ElfFile<'_>, d: &mut Diff) {
    let g = match goblin::elf::Elf::parse(data) {
        Ok(g) => g,
        Err(e) => {
            d.notes.push(format!("goblin: {e}"));
            return;
        }
    };
    let oh = ours.header();
    d.eq(|| "goblin e_type".into(), oh.e_type, g.header.e_type);
    d.eq(|| "goblin e_machine".into(), oh.machine, g.header.e_machine);
    d.eq(|| "goblin e_entry".into(), oh.entry, g.header.e_entry);
    d.eq(|| "goblin e_phoff".into(), oh.phoff, g.header.e_phoff);
    d.eq(|| "goblin e_shoff".into(), oh.shoff, g.header.e_shoff);
    d.eq(|| "goblin e_flags".into(), oh.flags, g.header.e_flags);
    d.eq(|| "goblin is_64".into(), oh.class == Class::Elf64, g.is_64);
    d.eq(
        || "goblin little_endian".into(),
        oh.endian == Endian::Little,
        g.little_endian,
    );

    if let Ok(op) = ours.program_headers() {
        d.eq(
            || "goblin phdr count".into(),
            op.len(),
            g.program_headers.len(),
        );
        for (i, (o, t)) in op.iter().zip(&g.program_headers).enumerate() {
            d.eq(
                || format!("goblin phdr[{i}]"),
                (
                    o.p_type, o.flags, o.offset, o.vaddr, o.paddr, o.filesz, o.memsz, o.align,
                ),
                (
                    t.p_type, t.p_flags, t.p_offset, t.p_vaddr, t.p_paddr, t.p_filesz, t.p_memsz,
                    t.p_align,
                ),
            );
        }
    }
    if let Ok(os) = ours.section_headers() {
        d.eq(
            || "goblin shdr count".into(),
            os.len(),
            g.section_headers.len(),
        );
        for (i, (o, t)) in os.iter().zip(&g.section_headers).enumerate() {
            d.eq(
                || format!("goblin shdr[{i}]"),
                (
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
                ),
                (
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
                ),
            );
        }
        // goblin's `syms` is the *last* SHT_SYMTAB section.
        if let Some(si) = os.iter().rposition(|s| s.sh_type == SHT_SYMTAB)
            && let Ok(ot) = ours.symbol_table(si)
        {
            d.eq(|| "goblin .symtab count".into(), ot.len(), g.syms.len());
            for (j, (o, t)) in ot.iter().zip(g.syms.iter()).enumerate() {
                d.eq(
                    || format!("goblin symtab[{j}]"),
                    (
                        o.name as usize,
                        o.info,
                        o.other,
                        o.raw_shndx as usize,
                        o.value,
                        o.size,
                    ),
                    (
                        t.st_name, t.st_info, t.st_other, t.st_shndx, t.st_value, t.st_size,
                    ),
                );
            }
        }
    }
}

#[test]
fn corpus_matches_oracles() {
    let dir = corpus_dir();
    if !dir.is_dir() {
        eprintln!(
            "SKIP corpus_matches_oracles: {} does not exist.\n\
             Build the corpus first with:  testdata/build.sh   (see testdata/README.md)",
            dir.display()
        );
        return;
    }
    let mut files = Vec::new();
    walk(&dir, &mut files);

    let mut cov = Coverage::default();
    let mut checked = 0usize;
    let mut failures: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    for path in &files {
        let Ok(data) = std::fs::read(path) else {
            continue;
        };
        if data.len() < 4 || &data[..4] != ELFMAG {
            continue;
        }
        // `ar` archives etc. are not ELF; everything else with the magic is.
        let rel = path
            .strip_prefix(&dir)
            .unwrap_or(path)
            .display()
            .to_string();
        let ours = match ElfFile::parse(&data) {
            Ok(f) => f,
            Err(e) => {
                failures.push(format!("{rel}: ElfFile::parse failed: {e}"));
                continue;
            }
        };
        checked += 1;
        let h = ours.header();
        match h.class {
            Class::Elf32 => cov.elf32 += 1,
            _ => cov.elf64 += 1,
        }
        match h.endian {
            Endian::Big => cov.big_endian += 1,
            _ => cov.little_endian += 1,
        }
        match h.e_type {
            1 => cov.et_rel += 1,
            2 => cov.et_exec += 1,
            3 => cov.et_dyn += 1,
            _ => {}
        }

        let mut d = Diff {
            errors: Vec::new(),
            notes: Vec::new(),
        };
        // EI_CLASS / EI_DATA cross-check against the raw ident bytes.
        d.eq(|| "EI_CLASS".into(), h.class == Class::Elf64, data[4] == 2);
        d.eq(|| "EI_DATA".into(), h.endian == Endian::Big, data[5] == 2);
        match h.class {
            Class::Elf32 => {
                compare_object::<FileHeader32<Endianness>>(&data, &ours, &mut d, &mut cov)
            }
            _ => compare_object::<FileHeader64<Endianness>>(&data, &ours, &mut d, &mut cov),
        }
        compare_goblin(&data, &ours, &mut d);

        // Real, well-formed binaries need no inference and produce no
        // warning about their format (loader predictions are host-dependent
        // and not checked here).
        d.eq(
            || "layout read from EI_CLASS/EI_DATA".into(),
            ours.layout().source,
            LayoutSource::Ident,
        );
        let audit = ours.audit();
        d.eq(|| "is_ambiguous".into(), audit.ambiguous, false);
        d.eq(|| "inferred anything".into(), audit.inferred, false);
        for diag in &audit.diagnostics {
            if diag.severity >= Severity::Warning && diag.category() != Category::Loader {
                d.errors.push(format!("unexpected diagnostic: {diag}"));
            }
        }

        if !d.errors.is_empty() {
            let shown = d.errors.len().min(40);
            failures.push(format!(
                "{rel}: {} mismatch(es):\n    {}{}",
                d.errors.len(),
                d.errors[..shown].join("\n    "),
                if d.errors.len() > shown {
                    "\n    ..."
                } else {
                    ""
                }
            ));
        }
        for n in d.notes.iter().take(5) {
            notes.push(format!("{rel}: {n}"));
        }
    }

    eprintln!(
        "corpus: {} files, {checked} ELF files checked; {cov:?}",
        files.len()
    );
    for n in &notes {
        eprintln!("note: {n}");
    }
    assert!(
        failures.is_empty(),
        "{} file(s) disagree with the oracles:\n{}",
        failures.len(),
        failures.join("\n")
    );

    // The corpus must actually exercise every case the loader distinguishes.
    let missing: Vec<&str> = [
        ("ELF32", cov.elf32),
        ("ELF64", cov.elf64),
        ("big-endian", cov.big_endian),
        ("little-endian", cov.little_endian),
        ("ET_REL", cov.et_rel),
        ("ET_EXEC", cov.et_exec),
        ("ET_DYN", cov.et_dyn),
        ("e_shnum == 0 (extended section count)", cov.shnum_escape),
        ("e_shstrndx == SHN_XINDEX", cov.shstrndx_escape),
        ("st_shndx == SHN_XINDEX", cov.sym_xindex),
    ]
    .into_iter()
    .filter(|(_, n)| *n == 0)
    .map(|(what, _)| what)
    .collect();
    assert!(
        missing.is_empty(),
        "corpus in {} lacks: {missing:?} (re-run testdata/build.sh)",
        dir.display()
    );
}

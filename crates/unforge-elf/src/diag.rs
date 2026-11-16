//! Diagnostics: what the reader found odd, and what it had to infer.
//!
//! The reader is tolerant: it reads everything it can and describes every
//! anomaly as a [`Diagnostic`] instead of refusing the file. Plain accessors
//! never compute diagnostics (they stay cheap); [`crate::ElfFile::audit`]
//! walks the file once and returns all of them.
//!
//! Whenever the reader has to *choose* an interpretation (the layout when
//! `EI_CLASS` lies, a count clipped to the file, an entry size when
//! `sh_entsize` is unusable, the string table of a symbol table whose
//! `sh_link` is odd, ...) it records an [`Inference`]: what it chose, which
//! clues it used, and the alternatives. If any alternative is also consistent
//! with the file ([`Alternative::viable`]), the file has no unique reading;
//! [`crate::ElfFile::is_ambiguous`] reports that.

use core::fmt;

use crate::kernel::KernelPrediction;
use crate::{Class, Endian, Error};

/// How bad a finding is. Ordered: `Info < Warning < WouldNotLoad`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Severity {
    /// Unusual but harmless to every consumer, or a note about the reading.
    Info,
    /// The file departs from the gABI, the views disagree, or a value had to
    /// be clipped or inferred: analysis results may mislead.
    Warning,
    /// A Linux loader (the kernel or `ld.so`) would refuse or crash on this.
    WouldNotLoad,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "note",
            Severity::Warning => "warning",
            Severity::WouldNotLoad => "would not load",
        })
    }
}

/// What a diagnostic is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Category {
    /// The bytes themselves: header fields, table bounds, entry sizes.
    Format,
    /// An interpretation the reader chose ([`DiagnosticKind::Inferred`]).
    Inference,
    /// Two views of the file disagree (sections vs segments, ...).
    Consistency,
    /// What a Linux loader would do with the file (kernel, `ld.so`). These
    /// depend on the platform the file is run on.
    Loader,
    /// About the audit itself (suppressed or skipped checks).
    Audit,
}

/// A byte range of the input file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileRange {
    pub offset: u64,
    pub size: u64,
}

/// The table a diagnostic refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TableRef {
    ElfHeader,
    ProgramHeaders,
    SectionHeaders,
    /// The section with this index (its header or its data).
    Section(usize),
    /// The symbol table stored in this section.
    SymbolTable(usize),
    /// The dynamic table (`PT_DYNAMIC`).
    Dynamic,
}

/// Where a diagnostic points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Location {
    /// The bytes involved, when there is one range to point at.
    pub range: Option<FileRange>,
    pub table: Option<TableRef>,
    /// Entry index within `table`.
    pub index: Option<u64>,
}

impl Location {
    pub(crate) fn table(table: TableRef) -> Self {
        Location {
            table: Some(table),
            ..Location::default()
        }
    }
    pub(crate) fn entry(table: TableRef, index: usize) -> Self {
        Location {
            table: Some(table),
            index: Some(index as u64),
            ..Location::default()
        }
    }
    pub(crate) fn at(mut self, offset: u64, size: u64) -> Self {
        self.range = Some(FileRange { offset, size });
        self
    }
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub kind: DiagnosticKind,
    pub location: Location,
}

impl Diagnostic {
    pub fn new(kind: DiagnosticKind, location: Location) -> Self {
        Diagnostic {
            severity: kind.default_severity(),
            kind,
            location,
        }
    }

    pub fn category(&self) -> Category {
        self.kind.category()
    }

    /// The inference record, for [`DiagnosticKind::Inferred`].
    pub fn inference(&self) -> Option<&Inference> {
        match &self.kind {
            DiagnosticKind::Inferred(i) => Some(i),
            _ => None,
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)
    }
}

/// At most this many diagnostics of one kind are returned by an audit; the
/// rest are counted in one [`DiagnosticKind::Suppressed`].
pub const MAX_DIAGNOSTICS_PER_KIND: usize = 16;

/// Every kind of finding. Table indices (`index`, `table`, `segment`, ...) are
/// indices into the section or program header table.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiagnosticKind {
    // --- ELF header / e_ident -------------------------------------------
    /// `EI_CLASS` disagrees with the class used to read the file.
    ClassMismatch { claimed: u8, used: Class },
    /// `EI_DATA` disagrees with the byte order used to read the file.
    DataMismatch { claimed: u8, used: Endian },
    /// `e_ident[EI_VERSION] != EV_CURRENT` (gABI ch4 "ELF Identification").
    IdentVersion(u8),
    /// `e_version != EV_CURRENT` (gABI ch4 "ELF Header").
    Version(u32),
    /// `EI_OSABI` is neither `ELFOSABI_NONE` (0) nor `ELFOSABI_GNU` (3).
    OsAbi(u8),
    /// `EI_ABIVERSION != 0`.
    AbiVersion(u8),
    /// `e_ident[EI_PAD..16]` is not all zero (gABI: "set to zero").
    NonZeroPadding,
    /// `e_ehsize` differs from `sizeof(Ehdr)` of the class used.
    HeaderSize { found: u16, expected: u16 },
    /// The header is not consistent in the layout used to read the file
    /// (see [`crate::LayoutCandidate::consistent`]); no consistent layout
    /// scored higher.
    LayoutInconsistent { class: Class, endian: Endian },

    // --- program header table --------------------------------------------
    /// `e_phentsize` differs from `sizeof(Phdr)`. Larger: each entry is read
    /// from the first `sizeof(Phdr)` bytes; smaller: see the inference.
    BadProgramHeaderEntrySize { found: u16, expected: u16 },
    /// The program header table could not be read at all.
    ProgramHeaderTableUnreadable { error: Error },
    /// Only `usable` of the `declared` program headers are inside the file.
    ProgramHeaderCountClipped { declared: u64, usable: u64 },
    /// The program header table shares bytes with the ELF header (tiny ELF).
    PhdrsOverlapHeader,
    /// `p_offset + p_filesz` is past the end of the file; the segment's
    /// bytes are clipped.
    SegmentPastEof {
        index: usize,
        end: u64,
        file_len: u64,
    },
    /// Two `PT_LOAD`s cover the same addresses; `later` replaces `earlier`
    /// in `[start, end)` (the kernel maps later segments with `MAP_FIXED`).
    LoadsOverlap {
        earlier: usize,
        later: usize,
        start: u64,
        end: u64,
    },
    /// `p_filesz > p_memsz` in a `PT_LOAD` (gABI ch5 "Program Header": "The
    /// file size may not be larger than the memory size"). The kernel kills
    /// the process; the memory map uses only `p_memsz` file bytes.
    FileszExceedsMemsz {
        index: usize,
        filesz: u64,
        memsz: u64,
    },
    /// `p_offset` and `p_vaddr` of a `PT_LOAD` with file bytes differ modulo
    /// the page size the audit assumed: the kernel's `vm_mmap` of the segment
    /// fails and the process is killed (LOADER_RULES.md §2). The page size is
    /// the memory map's ([`crate::MemoryMap::page_size`]); larger pages fail
    /// too.
    OffsetNotPageCongruent {
        index: usize,
        offset: u64,
        vaddr: u64,
        page_size: u64,
    },
    /// `PT_LOAD` `index` has a lower `p_vaddr` than the one before it (gABI
    /// ch5: "sorted on the p_vaddr member").
    LoadsNotSorted { index: usize },
    /// `p_align` of a `PT_LOAD` is not 0, 1 or a power of two.
    AlignNotPowerOfTwo { index: usize, align: u64 },
    /// `p_offset % p_align != p_vaddr % p_align` (gABI ch5; the kernel only
    /// needs congruence modulo the page size).
    AlignCongruence {
        index: usize,
        offset: u64,
        vaddr: u64,
        align: u64,
    },
    /// `p_type` is neither defined by the gABI nor in the OS/processor ranges.
    UnknownSegmentType { index: usize, p_type: u32 },
    /// A segment type that is used once appears again (`PT_INTERP`,
    /// `PT_PHDR`: gABI "may not occur more than once"; the kernel uses the
    /// first `PT_INTERP` and the last `PT_GNU_STACK`).
    DuplicateSegment {
        p_type: u32,
        used: usize,
        ignored: usize,
    },
    /// The memory map was built from the first `used` of `total` `PT_LOAD`s.
    MemoryMapTruncated { used: usize, total: usize },

    // --- section header table --------------------------------------------
    /// `e_shoff == 0`: no section header table (Info: loaders never read it).
    NoSectionHeaderTable,
    /// `e_shoff == 0` but `e_shnum != 0`; the count is ignored.
    SectionCountWithoutTable { shnum: u16 },
    /// The section header table starts outside the file; no section read.
    SectionTableOutsideFile {
        offset: u64,
        size: u64,
        file_len: u64,
    },
    /// The section header table could not be read (e.g. an unresolvable
    /// extended section count).
    SectionHeaderTableUnreadable { error: Error },
    /// Only `usable` of the `declared` section headers are inside the file.
    SectionCountClipped { declared: u64, usable: u64 },
    /// `e_shentsize` differs from `sizeof(Shdr)`.
    BadSectionEntrySize { found: u16, expected: u16 },
    /// `e_shstrndx` is not the index of a section in the table.
    ShstrndxOutOfRange { index: u32, shnum: u64 },
    /// `e_shstrndx` is in `SHN_LORESERVE..SHN_XINDEX`; gABI requires
    /// `SHN_XINDEX` for such indices. It is used as an index anyway.
    ShstrndxReserved(u16),
    /// The section name table is not `SHT_STRTAB`; names are read from it
    /// anyway.
    ShstrndxNotStrtab { index: u32, sh_type: u32 },
    /// The last byte of string table `section` is not NUL (gABI ch4 "String
    /// Table": "the last byte is defined to hold a null character"). Names
    /// that start after its last NUL cannot be read.
    StringTableUnterminated { section: u32 },
    /// `count` section names start after the last NUL of the section name
    /// table and cannot be read.
    SectionNamesUnterminated { count: usize },
    /// A section's range runs past the end of the file and is clipped
    /// (`available` may be 0).
    SectionClipped {
        index: usize,
        declared: u64,
        available: u64,
    },
    /// A section's name contradicts its flags or the segment holding it.
    SectionNameMismatch { index: usize, reason: &'static str },
    /// An `SHT_NOBITS` section (not TLS) whose address lies in the file-backed
    /// part of a `PT_LOAD`: the bytes there do exist in the file.
    NobitsInFileBytes { index: usize, segment: usize },
    /// Section `second` starts inside section `first` (gABI ch4: "Sections
    /// in a file may not overlap").
    SectionsOverlap {
        first: usize,
        second: usize,
        start: u64,
        end: u64,
    },
    /// Section `index` covers exactly the same bytes as the earlier symbol
    /// table `same_as` (overlapping tables).
    DuplicateTable { index: usize, same_as: usize },
    /// `sh_addr` disagrees with the address the `PT_LOAD` holding the
    /// section's bytes maps them to.
    SectionAddressMismatch {
        index: usize,
        segment: usize,
        expected: u64,
        found: u64,
    },
    /// The `SHT_DYNAMIC` section disagrees with `PT_DYNAMIC`.
    DynamicSectionMismatch {
        section: usize,
        dynamic_offset: Option<u64>,
    },

    // --- symbol tables (one per table) -----------------------------------
    /// `sh_entsize` of a symbol table differs from `sizeof(Sym)`.
    SymbolEntrySize { table: usize, found: u64 },
    /// `sh_size % stride` bytes at the end of the table were ignored.
    SymbolTableTrailingBytes { table: usize, bytes: u64 },
    /// `sh_link` names a section that is not `SHT_STRTAB`; names were read
    /// from it anyway.
    SymbolTableLinkNotStrtab {
        table: usize,
        link: u32,
        sh_type: u32,
    },
    /// `sh_link` does not name a section; symbol names are unavailable.
    SymbolTableLinkInvalid { table: usize, link: u32 },
    /// `count` symbols have an `st_name` past the end of the string table.
    SymbolNamesOutOfRange { table: usize, count: usize },
    /// `count` symbols have an `st_name` after the last NUL of the string
    /// table: the name has no terminator, so it cannot be read.
    SymbolNamesUnterminated { table: usize, count: usize },
    /// Symbol 0 is not the all-zero undefined symbol (gABI ch4 "Symbol
    /// Table", "Symbol Table Entry: Index 0").
    FirstSymbolNotNull { table: usize },
    /// `count` symbols have an `st_shndx` in the reserved range that is not
    /// `SHN_ABS`, `SHN_COMMON` or `SHN_XINDEX`.
    ReservedSymbolSection { table: usize, count: usize },
    /// `count` symbols have an `st_shndx` below `SHN_LORESERVE` that is not
    /// the index of a section in the table.
    SymbolSectionOutOfRange { table: usize, count: usize },
    /// `count` symbols use `SHN_XINDEX` without a usable `SHT_SYMTAB_SHNDX`
    /// entry (gABI ch4: that section is required then).
    UnresolvedExtendedIndex { table: usize, count: usize },
    /// `count` defined `STT_FUNC` symbols with a size whose range is not
    /// inside one executable `PT_LOAD`.
    FunctionsOutsideCode { table: usize, count: usize },

    // --- dynamic -----------------------------------------------------------
    /// `PT_DYNAMIC` `p_offset` differs from the file offset its `p_vaddr` is
    /// mapped from (ld.so uses `p_vaddr` only).
    DynamicOffsetMismatch {
        p_offset: u64,
        mapped_offset: Option<u64>,
    },
    /// `SHT_DYNSYM` section `section` disagrees with the dynamic symbol table
    /// `ld.so` uses (found through `PT_DYNAMIC`; see
    /// [`crate::ElfFile::dynamic_symbols`]). `ld.so` never reads section
    /// headers, so the `PT_DYNAMIC` value is the one that is used.
    DynamicSymbolsMismatch {
        section: usize,
        what: &'static str,
        dynamic: u64,
        section_value: u64,
    },
    /// Symbol 0 of the dynamic symbol table (`DT_SYMTAB`) is not all zero.
    DynamicFirstSymbolNotNull,
    /// `DT_SYMENT` differs from `sizeof(Sym)` (loaders ignore it).
    DynamicSymbolEntrySize { found: u64 },
    /// `PT_DYNAMIC` `p_vaddr` is not backed by file bytes of any `PT_LOAD`.
    DynamicNotMapped { vaddr: u64 },
    /// No `DT_NULL` ends the dynamic table before the end of the file bytes
    /// that back it; `entries` were read (glibc and musl read until a
    /// `DT_NULL`, with no other bound).
    DynamicUnterminated { entries: usize },

    // --- loader expectations (Category::Loader) ----------------------------
    /// No `PT_LOAD` holds `e_phoff`, so the kernel's `AT_PHDR` is bogus
    /// (fs/binfmt_elf.c `load_elf_binary`, v7.0.12 lines 1210-1214).
    PhdrsNotInLoad,
    /// `PT_PHDR` disagrees with where the program header table is mapped.
    PtPhdrMismatch {
        pt_phdr_vaddr: u64,
        mapped_vaddr: Option<u64>,
    },
    /// `e_entry` is not in an executable `PT_LOAD` (after later-wins overlay).
    /// `backing` is the `PT_LOAD` that maps it, if any.
    EntryNotExecutable { entry: u64, backing: Option<usize> },
    /// `e_entry` is outside every `PT_LOAD`'s `[p_vaddr, p_vaddr + p_memsz)`
    /// but inside a page the kernel maps for `segment` (page slack), for the
    /// assumed page size.
    EntryInPageSlack {
        entry: u64,
        segment: usize,
        page_size: u64,
    },
    /// `PT_INTERP` without `PT_DYNAMIC`: glibc and musl `ld.so` read the
    /// program's dynamic section through `PT_DYNAMIC`.
    InterpWithoutDynamic,
    /// What [`crate::ElfFile::kernel_prediction_for`] predicts, when it is
    /// not `Loads`. Never produced by [`crate::ElfFile::audit`] itself (the
    /// prediction depends on the host); callers add it.
    Kernel(KernelPrediction),

    // --- inferences and the audit itself -----------------------------------
    /// The reader chose an interpretation. See [`Inference`].
    Inferred(Box<Inference>),
    /// `count` more diagnostics of `kind` were dropped.
    Suppressed { kind: &'static str, count: u64 },
    /// `what` was not checked for `skipped` items, to bound the work.
    AuditIncomplete { what: &'static str, skipped: u64 },
}

impl DiagnosticKind {
    /// A stable short name, used for [`MAX_DIAGNOSTICS_PER_KIND`].
    pub fn name(&self) -> &'static str {
        use DiagnosticKind as K;
        match self {
            K::ClassMismatch { .. } => "class-mismatch",
            K::DataMismatch { .. } => "data-mismatch",
            K::IdentVersion(_) => "ident-version",
            K::Version(_) => "version",
            K::OsAbi(_) => "os-abi",
            K::AbiVersion(_) => "abi-version",
            K::NonZeroPadding => "non-zero-padding",
            K::HeaderSize { .. } => "header-size",
            K::LayoutInconsistent { .. } => "layout-inconsistent",
            K::BadProgramHeaderEntrySize { .. } => "bad-phentsize",
            K::ProgramHeaderTableUnreadable { .. } => "phdrs-unreadable",
            K::ProgramHeaderCountClipped { .. } => "phnum-clipped",
            K::PhdrsOverlapHeader => "phdrs-overlap-header",
            K::SegmentPastEof { .. } => "segment-past-eof",
            K::LoadsOverlap { .. } => "loads-overlap",
            K::LoadsNotSorted { .. } => "loads-not-sorted",
            K::FileszExceedsMemsz { .. } => "filesz-exceeds-memsz",
            K::OffsetNotPageCongruent { .. } => "offset-not-page-congruent",
            K::EntryInPageSlack { .. } => "entry-in-page-slack",
            K::AlignNotPowerOfTwo { .. } => "align-not-power-of-two",
            K::AlignCongruence { .. } => "align-congruence",
            K::UnknownSegmentType { .. } => "unknown-segment-type",
            K::DuplicateSegment { .. } => "duplicate-segment",
            K::MemoryMapTruncated { .. } => "memory-map-truncated",
            K::NoSectionHeaderTable => "no-section-header-table",
            K::SectionCountWithoutTable { .. } => "shnum-without-table",
            K::SectionTableOutsideFile { .. } => "section-table-outside-file",
            K::SectionHeaderTableUnreadable { .. } => "shdrs-unreadable",
            K::SectionCountClipped { .. } => "shnum-clipped",
            K::BadSectionEntrySize { .. } => "bad-shentsize",
            K::ShstrndxOutOfRange { .. } => "shstrndx-out-of-range",
            K::ShstrndxReserved(_) => "shstrndx-reserved",
            K::ShstrndxNotStrtab { .. } => "shstrndx-not-strtab",
            K::SectionClipped { .. } => "section-clipped",
            K::SectionNameMismatch { .. } => "section-name-mismatch",
            K::NobitsInFileBytes { .. } => "nobits-in-file-bytes",
            K::SectionsOverlap { .. } => "sections-overlap",
            K::DuplicateTable { .. } => "duplicate-table",
            K::SectionAddressMismatch { .. } => "section-address-mismatch",
            K::DynamicSectionMismatch { .. } => "dynamic-section-mismatch",
            K::SymbolEntrySize { .. } => "symbol-entry-size",
            K::SymbolTableTrailingBytes { .. } => "symbol-table-trailing-bytes",
            K::SymbolTableLinkNotStrtab { .. } => "symbol-link-not-strtab",
            K::SymbolTableLinkInvalid { .. } => "symbol-link-invalid",
            K::SymbolNamesOutOfRange { .. } => "symbol-names-out-of-range",
            K::SymbolNamesUnterminated { .. } => "symbol-names-unterminated",
            K::FirstSymbolNotNull { .. } => "first-symbol-not-null",
            K::StringTableUnterminated { .. } => "string-table-unterminated",
            K::SectionNamesUnterminated { .. } => "section-names-unterminated",
            K::ReservedSymbolSection { .. } => "reserved-symbol-section",
            K::SymbolSectionOutOfRange { .. } => "symbol-section-out-of-range",
            K::UnresolvedExtendedIndex { .. } => "unresolved-extended-index",
            K::FunctionsOutsideCode { .. } => "functions-outside-code",
            K::DynamicOffsetMismatch { .. } => "dynamic-offset-mismatch",
            K::DynamicNotMapped { .. } => "dynamic-not-mapped",
            K::DynamicSymbolsMismatch { .. } => "dynamic-symbols-mismatch",
            K::DynamicFirstSymbolNotNull => "dynamic-first-symbol-not-null",
            K::DynamicSymbolEntrySize { .. } => "dynamic-symbol-entry-size",
            K::DynamicUnterminated { .. } => "dynamic-unterminated",
            K::PhdrsNotInLoad => "phdrs-not-in-load",
            K::PtPhdrMismatch { .. } => "pt-phdr-mismatch",
            K::EntryNotExecutable { .. } => "entry-not-executable",
            K::InterpWithoutDynamic => "interp-without-dynamic",
            K::Kernel(_) => "kernel",
            K::Inferred(i) => i.subject.name(),
            K::Suppressed { .. } => "suppressed",
            K::AuditIncomplete { .. } => "audit-incomplete",
        }
    }

    pub fn category(&self) -> Category {
        use DiagnosticKind as K;
        match self {
            K::SectionNameMismatch { .. }
            | K::NobitsInFileBytes { .. }
            | K::SectionAddressMismatch { .. }
            | K::DynamicSectionMismatch { .. }
            | K::FunctionsOutsideCode { .. }
            | K::DynamicOffsetMismatch { .. }
            | K::DynamicSymbolsMismatch { .. } => Category::Consistency,
            K::PhdrsNotInLoad
            | K::PtPhdrMismatch { .. }
            | K::EntryNotExecutable { .. }
            | K::EntryInPageSlack { .. }
            | K::OffsetNotPageCongruent { .. }
            | K::InterpWithoutDynamic
            | K::DynamicNotMapped { .. }
            | K::Kernel(_) => Category::Loader,
            K::Inferred(_) => Category::Inference,
            K::Suppressed { .. } | K::AuditIncomplete { .. } => Category::Audit,
            _ => Category::Format,
        }
    }

    pub fn default_severity(&self) -> Severity {
        use DiagnosticKind as K;
        match self {
            K::OsAbi(_)
            | K::AbiVersion(_)
            | K::NonZeroPadding
            | K::PhdrsOverlapHeader
            | K::LoadsNotSorted { .. }
            | K::AlignNotPowerOfTwo { .. }
            | K::AlignCongruence { .. }
            | K::UnknownSegmentType { .. }
            | K::NoSectionHeaderTable
            | K::Suppressed { .. }
            | K::AuditIncomplete { .. } => Severity::Info,
            K::InterpWithoutDynamic
            | K::Kernel(_)
            | K::FileszExceedsMemsz { .. }
            | K::OffsetNotPageCongruent { .. } => Severity::WouldNotLoad,
            K::Inferred(i) if !i.is_ambiguous() => Severity::Info,
            _ => Severity::Warning,
        }
    }
}

impl fmt::Display for DiagnosticKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DiagnosticKind as K;
        match self {
            K::ClassMismatch { claimed, used } => write!(
                f,
                "EI_CLASS is {claimed:#x} but the header was read as {used:?} (the kernel ignores EI_CLASS)"
            ),
            K::DataMismatch { claimed, used } => write!(
                f,
                "EI_DATA is {claimed:#x} but the header was read as {used:?}-endian (the kernel ignores EI_DATA)"
            ),
            K::IdentVersion(v) => {
                write!(f, "e_ident[EI_VERSION] is {v}, expected EV_CURRENT (1)")
            }
            K::Version(v) => write!(f, "e_version is {v}, expected EV_CURRENT (1)"),
            K::OsAbi(v) => write!(f, "EI_OSABI is {v} (not SYSV or GNU)"),
            K::AbiVersion(v) => write!(f, "EI_ABIVERSION is {v}"),
            K::NonZeroPadding => write!(f, "e_ident padding (bytes 9..16) is not zero"),
            K::HeaderSize { found, expected } => {
                write!(f, "e_ehsize is {found}, expected {expected}")
            }
            K::LayoutInconsistent { class, endian } => write!(
                f,
                "the header is read as {class:?} {endian:?}-endian, but it is not consistent in that layout (machine class or header size fields disagree)"
            ),
            K::BadProgramHeaderEntrySize { found, expected } => {
                write!(f, "e_phentsize is {found}, expected {expected}")
            }
            K::ProgramHeaderTableUnreadable { error } => {
                write!(f, "program header table unreadable: {error}")
            }
            K::ProgramHeaderCountClipped { declared, usable } => write!(
                f,
                "program header table: {declared} entries declared, only {usable} inside the file"
            ),
            K::PhdrsOverlapHeader => {
                write!(f, "program header table overlaps the ELF header")
            }
            K::SegmentPastEof {
                index,
                end,
                file_len,
            } => write!(
                f,
                "segment [{index}]: file range ends at {end:#x}, past the end of the file ({file_len:#x}); clipped"
            ),
            K::LoadsOverlap {
                earlier,
                later,
                start,
                end,
            } => write!(
                f,
                "PT_LOAD [{later}] replaces PT_LOAD [{earlier}] at {start:#x}..{end:#x}"
            ),
            K::LoadsNotSorted { index } => {
                write!(f, "PT_LOAD [{index}] is not sorted by p_vaddr")
            }
            K::FileszExceedsMemsz {
                index,
                filesz,
                memsz,
            } => write!(
                f,
                "segment [{index}]: p_filesz {filesz:#x} is larger than p_memsz {memsz:#x} (the kernel kills the process); the memory map shows only p_memsz bytes"
            ),
            K::OffsetNotPageCongruent {
                index,
                offset,
                vaddr,
                page_size,
            } => write!(
                f,
                "segment [{index}]: p_offset {offset:#x} and p_vaddr {vaddr:#x} differ modulo the page size {page_size:#x} (assumed); the kernel cannot map it and kills the process"
            ),
            K::EntryInPageSlack {
                entry,
                segment,
                page_size,
            } => write!(
                f,
                "e_entry {entry:#x} is outside every PT_LOAD, but inside a page the kernel maps for segment [{segment}] (page size {page_size:#x} assumed)"
            ),
            K::AlignNotPowerOfTwo { index, align } => write!(
                f,
                "segment [{index}]: p_align {align:#x} is not a power of two"
            ),
            K::AlignCongruence {
                index,
                offset,
                vaddr,
                align,
            } => write!(
                f,
                "segment [{index}]: p_offset {offset:#x} and p_vaddr {vaddr:#x} differ modulo p_align {align:#x}"
            ),
            K::UnknownSegmentType { index, p_type } => {
                write!(f, "segment [{index}]: unknown p_type {p_type:#x}")
            }
            K::DuplicateSegment {
                p_type,
                used,
                ignored,
            } => write!(
                f,
                "segment type {p_type:#x} appears more than once: [{used}] is used, [{ignored}] is not"
            ),
            K::MemoryMapTruncated { used, total } => write!(
                f,
                "memory map built from the first {used} of {total} PT_LOAD segments"
            ),
            K::NoSectionHeaderTable => write!(f, "no section header table (e_shoff = 0)"),
            K::SectionCountWithoutTable { shnum } => write!(
                f,
                "e_shnum is {shnum} but e_shoff is 0; there is no section header table"
            ),
            K::SectionTableOutsideFile {
                offset,
                size,
                file_len,
            } => write!(
                f,
                "section header table at {offset:#x} ({size:#x} bytes) is outside the file ({file_len:#x} bytes); no section headers read"
            ),
            K::SectionHeaderTableUnreadable { error } => {
                write!(f, "section header table unreadable: {error}")
            }
            K::SectionCountClipped { declared, usable } => write!(
                f,
                "section header table: {declared} entries declared, only {usable} inside the file"
            ),
            K::BadSectionEntrySize { found, expected } => {
                write!(f, "e_shentsize is {found}, expected {expected}")
            }
            K::ShstrndxOutOfRange { index, shnum } => write!(
                f,
                "e_shstrndx {index} is not a section index (there are {shnum} sections); section names unavailable"
            ),
            K::ShstrndxReserved(raw) => write!(
                f,
                "e_shstrndx {raw:#x} is in the reserved range (gABI requires SHN_XINDEX); used as an index anyway"
            ),
            K::ShstrndxNotStrtab { index, sh_type } => write!(
                f,
                "section name table [{index}] has type {sh_type:#x}, not SHT_STRTAB; names read from it anyway"
            ),
            K::SectionClipped {
                index,
                declared,
                available,
            } => write!(
                f,
                "section [{index}]: {declared:#x} bytes declared, {available:#x} inside the file; clipped"
            ),
            K::SectionNameMismatch { index, reason } => {
                write!(f, "section [{index}]: {reason}")
            }
            K::NobitsInFileBytes { index, segment } => write!(
                f,
                "section [{index}] is SHT_NOBITS but its address is in the file-backed part of segment [{segment}]"
            ),
            K::SectionsOverlap {
                first,
                second,
                start,
                end,
            } => write!(
                f,
                "sections [{first}] and [{second}] overlap at {start:#x}..{end:#x}"
            ),
            K::DuplicateTable { index, same_as } => write!(
                f,
                "section [{index}] covers the same bytes as symbol table [{same_as}] (overlapping tables)"
            ),
            K::SectionAddressMismatch {
                index,
                segment,
                expected,
                found,
            } => write!(
                f,
                "section [{index}]: sh_addr {found:#x}, but segment [{segment}] maps its bytes at {expected:#x}"
            ),
            K::DynamicSectionMismatch {
                section,
                dynamic_offset: Some(o),
            } => write!(
                f,
                "section [{section}] (SHT_DYNAMIC) disagrees with PT_DYNAMIC (p_offset {o:#x})"
            ),
            K::DynamicSectionMismatch {
                section,
                dynamic_offset: None,
            } => write!(
                f,
                "section [{section}] is SHT_DYNAMIC but there is no PT_DYNAMIC"
            ),
            K::SymbolEntrySize { table, found } => {
                write!(f, "symbol table [{table}]: sh_entsize is {found}")
            }
            K::SymbolTableTrailingBytes { table, bytes } => write!(
                f,
                "symbol table [{table}]: sh_size is not a multiple of the entry size; {bytes} trailing bytes ignored"
            ),
            K::SymbolTableLinkNotStrtab {
                table,
                link,
                sh_type,
            } => write!(
                f,
                "symbol table [{table}]: sh_link {link} names a section of type {sh_type:#x}, not SHT_STRTAB; names read from it anyway"
            ),
            K::SymbolTableLinkInvalid { table, link } => write!(
                f,
                "symbol table [{table}]: sh_link {link} does not name a section; symbol names unavailable"
            ),
            K::SymbolNamesOutOfRange { table, count } => write!(
                f,
                "symbol table [{table}]: {count} symbols have a name offset past the string table"
            ),
            K::SymbolNamesUnterminated { table, count } => write!(
                f,
                "symbol table [{table}]: {count} symbol names start after the last NUL of the string table and cannot be read"
            ),
            K::FirstSymbolNotNull { table } => write!(
                f,
                "symbol table [{table}]: symbol 0 is not the all-zero undefined symbol (gABI); symbol indices may be shifted"
            ),
            K::StringTableUnterminated { section } => write!(
                f,
                "string table [{section}]: the last byte is not NUL; a name that runs to the end cannot be read"
            ),
            K::SectionNamesUnterminated { count } => write!(
                f,
                "{count} section names start after the last NUL of the section name table and cannot be read"
            ),
            K::ReservedSymbolSection { table, count } => write!(
                f,
                "symbol table [{table}]: {count} symbols have a reserved st_shndx"
            ),
            K::SymbolSectionOutOfRange { table, count } => write!(
                f,
                "symbol table [{table}]: {count} symbols have an st_shndx past the section header table"
            ),
            K::UnresolvedExtendedIndex { table, count } => write!(
                f,
                "symbol table [{table}]: {count} symbols use SHN_XINDEX but have no usable SHT_SYMTAB_SHNDX entry (shown as XINDEX?)"
            ),
            K::FunctionsOutsideCode { table, count } => write!(
                f,
                "symbol table [{table}]: {count} functions extend outside every executable PT_LOAD"
            ),
            K::DynamicOffsetMismatch {
                p_offset,
                mapped_offset: Some(m),
            } => write!(
                f,
                "PT_DYNAMIC p_offset is {p_offset:#x} but its p_vaddr is mapped from {m:#x} (ld.so uses p_vaddr)"
            ),
            K::DynamicOffsetMismatch {
                p_offset,
                mapped_offset: None,
            } => write!(
                f,
                "PT_DYNAMIC p_offset is {p_offset:#x} and its p_vaddr is not file-backed"
            ),
            K::DynamicSymbolsMismatch {
                section,
                what,
                dynamic,
                section_value,
            } => write!(
                f,
                "SHT_DYNSYM [{section}] disagrees with PT_DYNAMIC on the {what}: section {section_value:#x}, dynamic {dynamic:#x}; ld.so uses the PT_DYNAMIC value"
            ),
            K::DynamicFirstSymbolNotNull => write!(
                f,
                "dynamic symbol 0 (at DT_SYMTAB) is not the all-zero undefined symbol"
            ),
            K::DynamicSymbolEntrySize { found } => write!(
                f,
                "DT_SYMENT is {found}, not sizeof(Sym) (ld.so ignores DT_SYMENT)"
            ),
            K::DynamicNotMapped { vaddr } => write!(
                f,
                "PT_DYNAMIC p_vaddr {vaddr:#x} is not backed by file bytes of any PT_LOAD"
            ),
            K::DynamicUnterminated { entries } => write!(
                f,
                "dynamic table: no DT_NULL before the end of its file bytes; {entries} entries read"
            ),
            K::PhdrsNotInLoad => write!(
                f,
                "no PT_LOAD contains the program header table; AT_PHDR will be bogus"
            ),
            K::PtPhdrMismatch {
                pt_phdr_vaddr,
                mapped_vaddr: Some(m),
            } => write!(
                f,
                "PT_PHDR says {pt_phdr_vaddr:#x} but the program header table is mapped at {m:#x}"
            ),
            K::PtPhdrMismatch {
                pt_phdr_vaddr,
                mapped_vaddr: None,
            } => write!(
                f,
                "PT_PHDR says {pt_phdr_vaddr:#x} but the program header table is not mapped"
            ),
            K::EntryNotExecutable {
                entry,
                backing: Some(s),
            } => write!(f, "e_entry {entry:#x} is in non-executable segment [{s}]"),
            K::EntryNotExecutable {
                entry,
                backing: None,
            } => write!(f, "e_entry {entry:#x} is not inside any PT_LOAD"),
            K::InterpWithoutDynamic => write!(
                f,
                "PT_INTERP without PT_DYNAMIC: the dynamic loader cannot find the dynamic section"
            ),
            K::Kernel(p) => write!(f, "kernel: {p}"),
            K::Inferred(i) => i.fmt(f),
            K::Suppressed { kind, count } => {
                write!(f, "{count} more '{kind}' diagnostics suppressed")
            }
            K::AuditIncomplete { what, skipped } => {
                write!(f, "{what}: {skipped} items not checked (work bound)")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Inferences
// ---------------------------------------------------------------------------

/// What was inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InferenceSubject {
    /// Class and byte order of the whole file.
    Layout,
    /// Number of program headers read.
    ProgramHeaderCount,
    /// Distance between program headers.
    ProgramHeaderEntrySize,
    /// Number of section headers read.
    SectionHeaderCount,
    /// Distance between section headers.
    SectionHeaderEntrySize,
    /// Distance between symbols of the symbol table in this section.
    SymbolEntrySize { table: usize },
    /// Number of symbols read from the table in this section.
    SymbolCount { table: usize },
    /// The string table of the symbol table in this section.
    StringTable { table: usize },
    /// The section name string table.
    SectionNameTable,
    /// Where the dynamic table was read from.
    DynamicTableLocation,
    /// Number of dynamic entries, when no `DT_NULL` ends the table.
    DynamicEntryCount,
    /// The page size the memory map assumed, when a result depends on it.
    PageSize,
    /// Number of dynamic symbols (`DT_SYMTAB`), when `DT_HASH` does not give
    /// it and no `SHT_DYNSYM` confirms it.
    DynamicSymbolCount,
    /// The `SHT_SYMTAB_SHNDX` section used for the symbol table in this
    /// section, when several claim it.
    ExtendedIndexTable { table: usize },
}

impl InferenceSubject {
    pub fn name(&self) -> &'static str {
        match self {
            InferenceSubject::Layout => "inferred-layout",
            InferenceSubject::ProgramHeaderCount => "inferred-phnum",
            InferenceSubject::ProgramHeaderEntrySize => "inferred-phentsize",
            InferenceSubject::SectionHeaderCount => "inferred-shnum",
            InferenceSubject::SectionHeaderEntrySize => "inferred-shentsize",
            InferenceSubject::SymbolEntrySize { .. } => "inferred-symbol-entry-size",
            InferenceSubject::SymbolCount { .. } => "inferred-symbol-count",
            InferenceSubject::StringTable { .. } => "inferred-string-table",
            InferenceSubject::SectionNameTable => "inferred-section-name-table",
            InferenceSubject::DynamicTableLocation => "inferred-dynamic-location",
            InferenceSubject::DynamicEntryCount => "inferred-dynamic-count",
            InferenceSubject::PageSize => "inferred-page-size",
            InferenceSubject::DynamicSymbolCount => "inferred-dynamic-symbol-count",
            InferenceSubject::ExtendedIndexTable { .. } => "inferred-extended-index-table",
        }
    }
}

impl fmt::Display for InferenceSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InferenceSubject::Layout => write!(f, "layout"),
            InferenceSubject::ProgramHeaderCount => write!(f, "program header count"),
            InferenceSubject::ProgramHeaderEntrySize => write!(f, "program header entry size"),
            InferenceSubject::SectionHeaderCount => write!(f, "section header count"),
            InferenceSubject::SectionHeaderEntrySize => write!(f, "section header entry size"),
            InferenceSubject::SymbolEntrySize { table } => {
                write!(f, "entry size of symbol table [{table}]")
            }
            InferenceSubject::SymbolCount { table } => {
                write!(f, "symbol count of symbol table [{table}]")
            }
            InferenceSubject::StringTable { table } => {
                write!(f, "string table of symbol table [{table}]")
            }
            InferenceSubject::SectionNameTable => write!(f, "section name table"),
            InferenceSubject::DynamicTableLocation => write!(f, "dynamic table location"),
            InferenceSubject::DynamicEntryCount => write!(f, "dynamic entry count"),
            InferenceSubject::PageSize => write!(f, "page size"),
            InferenceSubject::DynamicSymbolCount => write!(f, "dynamic symbol count"),
            InferenceSubject::ExtendedIndexTable { table } => {
                write!(f, "SHT_SYMTAB_SHNDX section of symbol table [{table}]")
            }
        }
    }
}

/// A value the reader chose (or could have chosen).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Choice {
    Layout {
        class: Class,
        endian: Endian,
    },
    Count(u64),
    EntrySize(u64),
    /// A section, by index.
    Section(u32),
    /// A file offset.
    FileOffset(u64),
    /// A page size in bytes.
    PageSize(u64),
    /// Nothing usable.
    Nothing,
}

impl fmt::Display for Choice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Choice::Layout { class, endian } => write!(f, "{class:?} {endian:?}-endian"),
            Choice::Count(n) => write!(f, "{n} entries"),
            Choice::EntrySize(n) => write!(f, "{n} bytes"),
            Choice::Section(i) => write!(f, "section [{i}]"),
            Choice::FileOffset(o) => write!(f, "file offset {o:#x}"),
            Choice::PageSize(n) => write!(f, "{n:#x}-byte pages"),
            Choice::Nothing => write!(f, "nothing"),
        }
    }
}

/// One piece of evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Clue {
    /// `e_machine` read in this byte order is a machine the reader knows.
    MachineReadsAs { machine: u16, endian: Endian },
    /// Linux uses this class for that machine.
    MachineUsesClass { machine: u16, class: Class },
    /// A header size field equals the structure size of the class.
    EntrySizeMatches { field: &'static str, value: u16 },
    /// `EI_CLASS` / `EI_DATA` claim this.
    IdentClaims { field: &'static str, value: u8 },
    /// `EI_CLASS` / `EI_DATA` hold no valid value.
    InvalidIdent { field: &'static str, value: u8 },
    /// `e_version` reads as `EV_CURRENT` in this byte order.
    VersionIsCurrent,
    /// The header read in this layout passes the Linux kernel's ELF header
    /// checks (see [`crate::Layout`]).
    KernelAccepts { class: Class, endian: Endian },
    /// The claimed layout was chosen but the file does not confirm it:
    /// `tie` = another consistent layout is supported as much by the rest of
    /// the header, and only the claim decided;
    /// `consistent` = whether the header is consistent in the claimed layout.
    ClaimUnconfirmed { tie: bool, consistent: bool },
    /// The file is this long.
    FileLength(u64),
    /// A field holds this value.
    Field { field: &'static str, value: u64 },
    /// The structure size for the class used.
    StructureSize(u64),
    /// Section `index` has type `sh_type`.
    SectionType { index: u32, sh_type: u32 },
}

impl fmt::Display for Clue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Clue::MachineReadsAs { machine, endian } => {
                write!(f, "e_machine reads as {machine} in {endian:?}-endian")
            }
            Clue::MachineUsesClass { machine, class } => {
                write!(f, "Linux uses {class:?} for machine {machine}")
            }
            Clue::EntrySizeMatches { field, value } => write!(f, "{field} = {value}"),
            Clue::IdentClaims { field, value } => write!(f, "{field} = {value}"),
            Clue::InvalidIdent { field, value } => write!(f, "{field} = {value:#x} is invalid"),
            Clue::VersionIsCurrent => write!(f, "e_version = 1"),
            Clue::KernelAccepts { class, endian } => write!(
                f,
                "the Linux kernel accepts the header as {class:?} {endian:?}-endian"
            ),
            Clue::ClaimUnconfirmed { tie, consistent } => {
                f.write_str("EI_CLASS/EI_DATA chosen without confirmation")?;
                if *tie {
                    f.write_str(" (only they decided between equally supported layouts)")?;
                }
                if !*consistent {
                    f.write_str(" (the header is inconsistent in that layout)")?;
                }
                Ok(())
            }
            Clue::FileLength(n) => write!(f, "file length {n:#x}"),
            Clue::Field { field, value } => write!(f, "{field} = {value:#x}"),
            Clue::StructureSize(n) => write!(f, "structure size {n}"),
            Clue::SectionType { index, sh_type } => {
                write!(f, "section [{index}] has type {sh_type:#x}")
            }
        }
    }
}

/// An interpretation the reader did not choose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alternative {
    pub choice: Choice,
    /// The file is also consistent with this choice.
    pub viable: bool,
    /// The alternative's score, for scored inferences (the layout).
    pub score: Option<u32>,
    pub clues: Vec<Clue>,
}

/// An interpretation the reader chose, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inference {
    pub subject: InferenceSubject,
    pub chosen: Choice,
    /// The chosen value's score, for scored inferences (the layout).
    pub score: Option<u32>,
    pub clues: Vec<Clue>,
    pub alternatives: Vec<Alternative>,
}

impl Inference {
    /// Some other choice is also consistent with the file.
    pub fn is_ambiguous(&self) -> bool {
        self.alternatives.iter().any(|a| a.viable)
    }
}

fn list<T: fmt::Display>(f: &mut fmt::Formatter<'_>, items: &[T]) -> fmt::Result {
    for (i, c) in items.iter().enumerate() {
        if i > 0 {
            f.write_str(", ")?;
        }
        c.fmt(f)?;
    }
    Ok(())
}

impl fmt::Display for Inference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "inferred {}: chose {}", self.subject, self.chosen)?;
        if let Some(s) = self.score {
            write!(f, " (score {s})")?;
        }
        if !self.clues.is_empty() {
            f.write_str(" from ")?;
            list(f, &self.clues)?;
        }
        if self.alternatives.is_empty() {
            f.write_str("; no alternative")?;
        } else {
            f.write_str("; alternatives: ")?;
            for (i, a) in self.alternatives.iter().enumerate() {
                if i > 0 {
                    f.write_str("; ")?;
                }
                write!(f, "{}", a.choice)?;
                if let Some(s) = a.score {
                    write!(f, " (score {s})")?;
                }
                if !a.clues.is_empty() {
                    f.write_str(" from ")?;
                    list(f, &a.clues)?;
                }
                f.write_str(if a.viable {
                    " [also consistent]"
                } else {
                    " [inconsistent]"
                })?;
            }
        }
        if self.is_ambiguous() {
            f.write_str("; the file has no unique interpretation")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The audit result and its bounded collector.
// ---------------------------------------------------------------------------

/// Result of [`crate::ElfFile::audit`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Audit {
    /// The diagnostics, at most [`MAX_DIAGNOSTICS_PER_KIND`] per kind, then
    /// one [`DiagnosticKind::Suppressed`] per kind that overflowed.
    pub diagnostics: Vec<Diagnostic>,
    /// Some inference (including suppressed ones) has a viable alternative.
    pub ambiguous: bool,
    /// Some value was inferred (including suppressed ones).
    pub inferred: bool,
}

impl Audit {
    pub fn inferences(&self) -> impl Iterator<Item = &Inference> {
        self.diagnostics.iter().filter_map(Diagnostic::inference)
    }

    /// The highest severity, if any.
    pub fn max_severity(&self) -> Option<Severity> {
        self.diagnostics.iter().map(|d| d.severity).max()
    }
}

/// Collects diagnostics with a per-kind cap.
pub(crate) struct Collector {
    audit: Audit,
    counts: Vec<(&'static str, u64)>,
}

impl Collector {
    pub(crate) fn new() -> Self {
        Collector {
            audit: Audit::default(),
            counts: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, kind: DiagnosticKind, location: Location) {
        if let DiagnosticKind::Inferred(i) = &kind {
            self.audit.inferred = true;
            self.audit.ambiguous |= i.is_ambiguous();
        }
        let name = kind.name();
        let n = match self.counts.iter_mut().find(|(k, _)| *k == name) {
            Some((_, n)) => {
                *n += 1;
                *n
            }
            None => {
                self.counts.push((name, 1));
                1
            }
        };
        if n <= MAX_DIAGNOSTICS_PER_KIND as u64 {
            self.audit.diagnostics.push(Diagnostic::new(kind, location));
        }
    }

    pub(crate) fn infer(&mut self, inference: Inference, location: Location) {
        self.push(DiagnosticKind::Inferred(Box::new(inference)), location);
    }

    pub(crate) fn finish(mut self) -> Audit {
        for (kind, n) in self.counts {
            if n > MAX_DIAGNOSTICS_PER_KIND as u64 {
                self.audit.diagnostics.push(Diagnostic::new(
                    DiagnosticKind::Suppressed {
                        kind,
                        count: n - MAX_DIAGNOSTICS_PER_KIND as u64,
                    },
                    Location::default(),
                ));
            }
        }
        self.audit
    }
}

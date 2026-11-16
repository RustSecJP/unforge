//! A tolerant, zero-copy, panic-free ELF reader built on `zerocopy`.
//!
//! Layers:
//! - [`raw`]: the on-disk structures, read with `zerocopy` (no `unsafe`).
//! - [`table`]: borrowed views of tables of those structures. Nothing is
//!   copied or collected: a table is a `&[R]` (or a stride over the input when
//!   the entry size is larger than the structure), and the class-independent
//!   types ([`ProgramHeader`], [`SectionHeader`], [`Symbol`]) are produced
//!   when an entry is accessed. The four (class, byte order) layouts are one
//!   enum behind one API ([`table::LayoutTable`]).
//! - [`ElfFile`]: ties the views to the input bytes.
//!
//! # Tolerance
//!
//! This is an analysis tool, so it reads what a loader would run: `parse`
//! fails only when not even an ELF header can be read (bad magic, a file
//! shorter than the header, or no clue at all about the layout). Everything
//! else is read as far as the bytes allow, and every anomaly is reported by
//! [`ElfFile::audit`] as a [`Diagnostic`]. Fields the Linux kernel ignores
//! (`EI_CLASS`, `EI_DATA`, `EI_VERSION`, `e_version`, `e_ehsize`, all `e_sh*`
//! fields; testdata/anomalous/LOADER_RULES.md §1) never make reading fail.
//!
//! Whenever the reader has to choose an interpretation, the audit records an
//! [`Inference`] with the choice, the clues and the alternatives;
//! [`ElfFile::is_ambiguous`] says whether some alternative is equally
//! consistent with the file.
//!
//! # Bounds
//!
//! Every offset and size from the file is checked with checked arithmetic.
//! Plain accessors do not allocate: listing every symbol of every symbol
//! table needs O(1) memory beyond the input, however many tables overlap.
//! [`ElfFile::audit`] allocates O(number of sections + number of segments)
//! and caps its output at [`MAX_DIAGNOSTICS_PER_KIND`] per kind.

#![forbid(unsafe_code)]

mod audit;
pub mod consts;
mod diag;
mod dynsym;
mod error;
mod kernel;
mod layout;
mod memmap;
mod parse;
pub mod raw;
mod symbols;
pub mod table;
mod widen;

pub use diag::{
    Alternative, Audit, Category, Choice, Clue, Diagnostic, DiagnosticKind, FileRange, Inference,
    InferenceSubject, Location, MAX_DIAGNOSTICS_PER_KIND, Severity, TableRef,
};
pub use dynsym::{DynamicSymbolCount, DynamicSymbols};
pub use error::{Error, Result};
pub use kernel::{KernelHost, KernelPrediction, KernelRule};
pub use layout::{Layout, LayoutCandidate, LayoutSource};
pub use memmap::{
    Backing, BackingRef, DEFAULT_PAGE_SIZE, DynamicSource, DynamicTable, MemoryMap, Region,
};
pub use parse::{BoundedName, ClippedBytes, ElfFile};
pub use symbols::{SymbolIter, SymbolTable, SymbolTables};
pub use table::{ProgramHeaders, SectionHeaders};

/// `EI_CLASS`: the width of addresses and offsets, as used to read the file
/// (see [`Layout`] for how it is decided).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Class {
    Elf32,
    Elf64,
}

/// `EI_DATA`: the byte order of multi-byte fields, as used to read the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Endian {
    Little,
    Big,
}

/// The ELF header (`Elf32_Ehdr` / `Elf64_Ehdr`), widened.
///
/// `class` and `endian` are the layout the file was read in ([`Layout`]),
/// which may differ from `ident_class` / `ident_data` (the raw `EI_CLASS` /
/// `EI_DATA` bytes) when those lie.
///
/// `phnum`, `shnum` and `shstrndx` are the *resolved* values: when the header
/// uses the escape values (`PN_XNUM`, `e_shnum == 0`, `SHN_XINDEX`) the real
/// numbers are taken from section header 0, as specified in gABI ch4
/// "ELF Header" / "Sections". The raw values are kept in `raw_*`. These are
/// the declared counts; the tables may hold fewer entries when the file is
/// too short ([`ElfFile::program_headers`], [`ElfFile::section_headers`]).
///
/// If an escape is used but section header 0 cannot be read, the real value
/// is unknown: the count is reported as 0 / `shstrndx` as `None`, and the
/// table accessor returns the error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub class: Class,
    pub endian: Endian,
    pub ident_class: u8,
    pub ident_data: u8,
    pub ident_version: u8,
    pub os_abi: u8,
    pub abi_version: u8,
    pub e_type: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub shentsize: u16,
    pub phnum: u64,
    pub shnum: u64,
    /// The section name table index. `None` when the file has none
    /// (`SHN_UNDEF`), or when `e_shstrndx == SHN_XINDEX` and section header 0
    /// is unavailable. A raw value in the reserved range
    /// `SHN_LORESERVE..SHN_XINDEX` is kept as an index (the audit reports it,
    /// gABI ch4 "ELF Header" says such indices are stored as `SHN_XINDEX`).
    pub shstrndx: Option<u32>,
    pub raw_phnum: u16,
    pub raw_shnum: u16,
    pub raw_shstrndx: u16,
}

/// A program header (`Elf32_Phdr` / `Elf64_Phdr`), widened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

/// A section header (`Elf32_Shdr` / `Elf64_Shdr`), widened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionHeader {
    pub name: u32,
    pub sh_type: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entsize: u64,
}

/// Where a symbol is defined (`st_shndx`, after resolving `SHN_XINDEX`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SymbolSection {
    /// `SHN_UNDEF`
    Undefined,
    /// `SHN_ABS`
    Absolute,
    /// `SHN_COMMON`
    Common,
    /// A real section index.
    Index(u32),
    /// Some other value in the reserved range `SHN_LORESERVE..=SHN_HIRESERVE`
    /// (processor/OS specific), kept as-is. Never `SHN_XINDEX`.
    Reserved(u16),
    /// `st_shndx == SHN_XINDEX`, but the real index could not be determined:
    /// the symbol table has no usable `SHT_SYMTAB_SHNDX` section, that section
    /// is too short, or its entry for this symbol is 0.
    ///
    /// gABI ch4 "Special Section Indexes": `SHN_XINDEX` "is an escape value. It
    /// indicates that the actual section header index is too large to fit in
    /// the containing field and is to be found in another location", so it is
    /// not a reserved index of its own. An entry of 0 is treated as unresolved
    /// because the gABI ("Sections", `SHT_SYMTAB_SHNDX`) says entries for
    /// symbols that do *not* use the escape "must be SHN_UNDEF (0)", so 0 does
    /// not carry an index.
    Unresolved,
}

/// A symbol table entry (`Elf32_Sym` / `Elf64_Sym`), widened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Symbol {
    pub name: u32,
    pub value: u64,
    pub size: u64,
    pub info: u8,
    pub other: u8,
    pub raw_shndx: u16,
    pub section: SymbolSection,
}

impl Symbol {
    /// `ELF_ST_BIND(st_info)`
    pub fn bind(&self) -> u8 {
        self.info >> 4
    }
    /// `ELF_ST_TYPE(st_info)`
    pub fn kind(&self) -> u8 {
        self.info & 0xf
    }
    /// `ELF_ST_VISIBILITY(st_other)`
    pub fn visibility(&self) -> u8 {
        self.other & 0x3
    }
}

/// A dynamic table entry (`Elf32_Dyn` / `Elf64_Dyn`), widened. `d_tag` is
/// signed in both classes (gABI ch5 "Dynamic Section").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DynamicEntry {
    pub tag: i64,
    pub value: u64,
}

# Proposed tolerant-reader API for `unforge-elf`

Status: **realized** in `unforge-elf` (2026-11-16); the `tolerant-api`
feature gate is gone and `cargo test -p unforge-elf --test tolerant_api`
runs. The text below is the original proposal. Where the implementation
differs:

- `validate()` is `ElfFile::audit()` (returns `Audit`: diagnostics, plus
  `ambiguous` / `inferred` flags) and `ElfFile::diagnostics()`. Kernel
  predictions are not part of the audit (they depend on the host); callers
  add `DiagnosticKind::Kernel` themselves, as the CLI does with
  `--loader-checks`.
- Every interpretation the reader chooses is a `DiagnosticKind::Inferred`
  with an `Inference` (subject, chosen value, clues, alternatives with a
  `viable` flag); `ElfFile::is_ambiguous()` is true when some alternative is
  viable. The layout decision is a scored choice (`Layout::candidates`), not
  the step list in §4.
- Tables are lazy views (`table::LayoutTable`; `SymbolTable` and
  `DynamicTable` wrap them), and `symbol_tables()` is an iterator. No `Vec`
  of entries is ever built.
- `SegmentBytes` is `ClippedBytes` (used for sections too); `section_data`
  clips like `segment_data`.
- `OverlappingFunctions` is `FunctionsOutsideCode` (a function range outside
  every executable `PT_LOAD`); `y54`'s `st_shndx` 0xfeee is reported as
  `SymbolSectionOutOfRange` (it is below `SHN_LORESERVE`, so not reserved).
- `kernel_prediction_for(data, host_machine)` models aarch64 and x86-64 only
  (`KernelHost`, 4 KiB pages); other hosts give `NotModelled`.

The behaviour the API must have comes from `LOADER_RULES.md` (what
`fs/binfmt_elf.c`, glibc `ld.so` and musl check) and `TECHNIQUES.md` §2 ("A
tolerant reader in one page"). The oracle for it is `verdicts.tsv`
(`run_oracle.sh`): a file the kernel loaded must be readable.

## 1. Principles the signatures encode

1. `ElfFile::parse` fails only when the loader view cannot be built at all:
   bad magic, or a file shorter than the ELF header. Everything the kernel
   ignores (`EI_CLASS`, `EI_DATA`, `EI_VERSION`, `EI_OSABI`, `EI_PAD`,
   `e_version`, `e_ehsize`, `e_flags`, every `e_sh*` field) is a diagnostic,
   never an error.
2. The layout (class and byte order) is chosen as the loader chooses it: from
   `e_machine`, decoded in both byte orders (§4 below). `EI_CLASS`/`EI_DATA`
   are used only when `e_machine` is not one the reader knows.
3. Ranges are clipped to the file and reported, not refused.
4. Tables are views. No accessor allocates more than O(file size), and no
   accessor does more than O(file size) work per call.
5. Diagnostics are bounded: at most `MAX_DIAGNOSTICS_PER_KIND` of each kind,
   then one `Suppressed` entry with the count.

## 2. New public items

```rust
// crates/unforge-elf/src/diag.rs (new), re-exported from lib.rs

/// How bad a finding is. Ordered: Info < Warning < WouldNotLoad.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Unusual but harmless to every loader (e.g. no section header table).
    Info,
    /// The linker view disagrees with the loader view, or a field is out of
    /// range; analysis results may mislead.
    Warning,
    /// The kernel (or ld.so) would refuse or abort this file.
    WouldNotLoad,
}

/// A byte range of the input file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileRange {
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub kind: DiagnosticKind,
    /// The bytes involved, when there is one range to point at.
    pub range: Option<FileRange>,
}

impl core::fmt::Display for Diagnostic { /* "warning: section [5] .text: ..." */ }

/// At most this many diagnostics of one kind; the rest are counted in one
/// `DiagnosticKind::Suppressed`.
pub const MAX_DIAGNOSTICS_PER_KIND: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiagnosticKind {
    // --- ELF header / e_ident (T10, T12, T13) --- default severity
    /// EI_CLASS disagrees with the layout chosen from e_machine.        Warning
    ClassMismatch { claimed: u8, used: Class },
    /// EI_DATA disagrees with the byte order chosen from e_machine.     Warning
    DataMismatch { claimed: u8, used: Endian },
    /// e_machine unknown and EI_CLASS/EI_DATA invalid.                   Warning
    LayoutUndetermined,
    IdentVersion(u8),                                                 // Info
    Version(u32),                                                     // Info
    OsAbi(u8),                                                        // Info
    AbiVersion(u8),                                                   // Info
    /// e_ident[9..16] not all zero.                                      Info
    NonZeroPadding,
    HeaderSize { found: u16, expected: u16 },                         // Info

    // --- section header table (T01-T05) ---
    /// e_shoff == 0.                                                     Info
    NoSectionHeaderTable,
    SectionTableOutsideFile { offset: u64, size: u64, file_len: u64 },// Warning
    /// Only `usable` entries fit before EOF; those are decoded.          Warning
    SectionCountClipped { declared: u64, usable: u64 },
    /// e_shoff == 0 but e_shnum != 0 (e.g. the tiny ELF, T10).           Warning
    SectionCountWithoutTable { shnum: u16 },
    /// e_shentsize < sizeof(Shdr): no sections; > : decoded by prefix.  Warning
    BadSectionEntrySize { found: u16, expected: u16 },
    ShstrndxOutOfRange { index: u32, shnum: u64 },                    // Warning
    ShstrndxNotStrtab { index: u32, sh_type: u32 },                   // Warning

    // --- sections vs file and vs segments (T06-T09) ---
    /// The section's range is clipped to the file (available may be 0). Warning
    SectionClipped { index: usize, declared: u64, available: u64 },
    /// An executable section has a data name or vice versa, judged by the
    /// PF_X of the segment containing it, not by the name.               Warning
    SectionNameMismatch { index: usize, reason: &'static str },
    /// SHT_NOBITS section whose sh_addr lies in a PT_LOAD's file part.    Warning
    NobitsInFileBytes { index: usize, segment: usize },
    SectionsOverlap { first: usize, second: usize, start: u64, end: u64 }, // Warning
    /// sh_addr - sh_offset != p_vaddr - p_offset of the containing PT_LOAD. Warning
    SectionAddressMismatch { index: usize, segment: usize, expected: u64, found: u64 },
    /// The .dynamic section header disagrees with PT_DYNAMIC.           Warning
    DynamicSectionMismatch { section: usize, dynamic_offset: Option<u64> },

    // --- program headers (T10, T11, T14, T15) ---
    /// The program header table shares bytes with the ELF header.       Info
    PhdrsOverlapHeader,
    /// No PT_LOAD covers e_phoff, so AT_PHDR is bogus at run time.      Warning
    PhdrsNotInLoad,
    PtPhdrMismatch { pt_phdr_vaddr: u64, mapped_vaddr: Option<u64> }, // Warning
    /// p_offset + p_filesz > file length; the view is clipped.          Warning
    SegmentPastEof { index: usize, end: u64, file_len: u64 },
    /// `later` replaces `earlier` in [start, end) (MAP_FIXED).          Warning
    LoadsOverlap { earlier: usize, later: usize, start: u64, end: u64 },
    LoadsNotSorted { index: usize },                                  // Info
    AlignNotPowerOfTwo { index: usize, align: u64 },                  // Info
    /// gABI p_offset % p_align == p_vaddr % p_align fails (kernel ignores). Info
    AlignCongruence { index: usize, offset: u64, vaddr: u64, align: u64 },
    UnknownSegmentType { index: usize, p_type: u32 },                 // Info
    /// Same p_type twice where one copy is used (PT_INTERP: the first;
    /// PT_GNU_STACK: the last).                                          Warning
    DuplicateSegment { p_type: u32, used: usize, ignored: usize },
    /// e_entry not in an executable PT_LOAD (after later-wins overlay).  Warning
    EntryNotExecutable { entry: u64, backing: Option<usize> },

    // --- dynamic (T16) ---
    /// PT_DYNAMIC p_offset != the offset PT_LOAD maps p_vaddr to.        Warning
    DynamicOffsetMismatch { p_offset: u64, mapped_offset: Option<u64> },
    /// PT_DYNAMIC p_vaddr is not file-backed by any PT_LOAD.            Warning
    DynamicNotMapped { vaddr: u64 },
    /// PT_INTERP present but no PT_DYNAMIC: ld.so will fail.             WouldNotLoad
    InterpWithoutDynamic,

    // --- symbols (T17) --- (aggregated: one per table)
    SymbolNamesOutOfRange { table: usize, count: usize },             // Warning
    SymbolTableLinkNotStrtab { table: usize, link: u32 },             // Warning
    /// sh_entsize 0 or not sizeof(Sym); sizeof(Sym) is used.           Warning
    SymbolEntrySize { table: usize, found: u64 },
    SymbolTableTrailingBytes { table: usize, bytes: u64 },            // Warning
    ReservedSymbolSection { table: usize, count: usize },             // Warning
    OverlappingFunctions { table: usize, count: usize },              // Warning

    // --- the kernel's verdict (T19) ---
    /// What `kernel_prediction` says, when it is not `Loads`.           WouldNotLoad
    Kernel(KernelPrediction),

    // --- output bounding ---
    /// `count` more diagnostics of `kind` were dropped.                 Info
    Suppressed { kind: &'static str, count: u64 },
}

/// One rule the kernel enforces (LOADER_RULES.md §5 "Fields the kernel does
/// enforce"), with the values that broke it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KernelRule {
    BadMagic,
    BadType(u16),
    BadMachine(u16),
    PhentsizeMismatch { found: u16, expected: u16 },
    /// e_phnum * sizeof(Phdr) not in 1..=65536 (PN_XNUM is not honoured).
    PhnumOutOfRange(u16),
    /// The program header table is not entirely inside the file.
    PhdrsOutsideFile,
    InterpSize(u64),
    InterpNotTerminated,
    FileszExceedsMemsz { index: usize },
    /// p_offset not congruent to p_vaddr modulo the page size (p_filesz > 0).
    OffsetVaddrNotCongruent { index: usize },
    /// Writable PT_LOAD with p_memsz > p_filesz whose last file page is
    /// past EOF: padzero() fails with -EFAULT.
    PaddingFault { index: usize },
    /// p_vaddr / p_memsz / e_entry at or above TASK_SIZE.
    AddressAboveTaskSize { index: Option<usize> },
    /// arm64 only: a malformed NT_GNU_PROPERTY_TYPE_0 note.
    GnuPropertyMalformed,
}

/// The kernel's verdict on a file, predicted from the bytes alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelPrediction {
    /// execve maps the file and starts user space (or ld.so). Says nothing
    /// about whether the program then works.
    Loads,
    /// execve returns an errno: the rule failed before begin_new_exec().
    RejectedAtExec(KernelRule),
    /// The rule fails after the point of no return: the process is killed
    /// with SIGSEGV (fs/exec.c bprm_execve, force_fatal_sig).
    AbortedAfterPointOfNoReturn(KernelRule),
}

/// How the file's layout was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutSource {
    /// From e_machine (the loader's way); EI_CLASS/EI_DATA may disagree.
    Machine,
    /// e_machine unknown: from EI_CLASS/EI_DATA.
    Ident,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub class: Class,
    pub endian: Endian,
    pub source: LayoutSource,
}

/// A segment's file bytes, clipped to the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentBytes<'data> {
    /// The part of [p_offset, p_offset + p_filesz) inside the file.
    pub bytes: &'data [u8],
    /// p_filesz - bytes.len(): claimed bytes that do not exist. Their run-time
    /// content is not known (SIGBUS on touch for whole pages past EOF).
    pub missing: u64,
}

/// The address space as the kernel builds it: PT_LOADs applied in table
/// order, each later one replacing earlier ones where they overlap.
#[derive(Debug, Clone)]
pub struct MemoryMap { /* private: sorted, non-overlapping intervals */ }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backing {
    /// Index (in the program header table) of the PT_LOAD that wins here.
    pub segment: usize,
    /// Earlier PT_LOADs that also covered this address and were replaced.
    pub overrides: Vec<usize>,
    /// File offset of the byte, or None for zero-fill (p_filesz..p_memsz)
    /// and for bytes past EOF.
    pub file_offset: Option<u64>,
    pub flags: u32,
}

impl MemoryMap {
    pub fn backing(&self, vaddr: u64) -> Option<Backing>;
    /// Shorthand for `backing(vaddr)?.file_offset`.
    pub fn file_offset(&self, vaddr: u64) -> Option<u64>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DynamicEntry {
    pub tag: u64,
    pub value: u64,
}

/// The dynamic table as ld.so sees it: found at PT_DYNAMIC's p_vaddr through
/// the memory map (glibc elf/rtld.c rtld_setup_main_map), read up to DT_NULL
/// or the end of file-backed bytes, at most file_len / entry_size entries.
#[derive(Debug, Clone)]
pub struct DynamicTable<'data> {
    pub entries: Vec<DynamicEntry>,
    /// Where the table was read from.
    pub file_offset: u64,
    raw: &'data [u8],
}
```

## 3. New and changed methods on existing types

```rust
impl<'data> ElfFile<'data> {
    // New.
    /// Diagnostics found while parsing (layout, header, table bounds).
    /// Cheap; computed once in `parse`.
    pub fn diagnostics(&self) -> &[Diagnostic];
    /// `diagnostics()` plus every cross-check (sections vs segments, memory
    /// map overlaps, dynamic table, symbol tables, kernel prediction for the
    /// file's own e_machine). Sorted by severity, then file offset. Bounded
    /// by MAX_DIAGNOSTICS_PER_KIND per kind.
    pub fn validate(&self) -> Vec<Diagnostic>;
    pub fn layout(&self) -> Layout;
    pub fn segment_bytes(&self, segment: &ProgramHeader) -> SegmentBytes<'data>;
    pub fn memory_map(&self) -> MemoryMap;
    pub fn dynamic(&self) -> Result<DynamicTable<'data>>;
    /// The kernel's verdict for a host whose native machine is
    /// `host_machine` (EM_AARCH64, EM_X86_64, ...). Works on any bytes,
    /// including files `parse` refuses (bad magic, unreadable phdrs).
    /// Does not model the file system (a missing PT_INTERP target gives
    /// ENOENT at run time but is predicted `Loads`) or binfmt_misc.
    pub fn kernel_prediction_for(data: &[u8], host_machine: u16) -> KernelPrediction;

    // Changed behaviour (same signatures).
    /// Err only when the table cannot be located at all. Entries past EOF are
    /// dropped and reported (SectionCountClipped).
    pub fn section_headers(&self) -> Result<&[SectionHeader]>;
    /// The clipped segment bytes (same as `segment_bytes(..).bytes`) instead
    /// of Err(OutOfBounds) when p_filesz runs past EOF. Still Err for an
    /// offset/size overflow.
    pub fn segment_data(&self, segment: &ProgramHeader) -> Result<&'data [u8]>;
    /// Lazy views: no longer Err(OverlappingTables); each table costs O(1)
    /// until its symbols are iterated.
    pub fn symbol_tables(&self) -> Result<Vec<SymbolTable<'data>>>;
}

impl<'data> SymbolTable<'data> {
    // `symbols: Vec<Symbol>` becomes a lazy view; the field is replaced by:
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn get(&self, index: usize) -> Option<Symbol>;
    pub fn iter(&self) -> impl Iterator<Item = Symbol> + 'data;
    /// None when sh_link does not name an SHT_STRTAB (names unknown).
    pub fn strtab(&self) -> Option<&'data [u8]>;
}
```

`Header::deviations()` and `Deviation` become redundant with
`DiagnosticKind::{IdentVersion, Version, HeaderSize}`; keep them as a thin
wrapper or remove them together with their tests in `spec.rs`.

## 4. Layout selection (rule for `layout()`)

1. Read the 2 bytes at offset 0x12 (`e_machine`; same offset in both
   classes) as little-endian and as big-endian.
2. If exactly one reading is a machine the reader knows, use that byte order
   and that machine's Linux class: `EM_AARCH64`, `EM_X86_64`, `EM_PPC64`,
   `EM_S390`, `EM_RISCV` (with `EI_CLASS` 2) → ELF64; `EM_386`, `EM_ARM` →
   ELF32. `source = Machine`.
3. Machines used by both classes (`EM_X86_64` x32, `EM_MIPS`, `EM_PPC`,
   `EM_RISCV`): try both classes and keep the one whose program header
   table decodes inside the file with `e_phentsize` equal to the class's
   `sizeof(Phdr)`; if both or neither do, fall back to `EI_CLASS` when valid.
   This is a heuristic; TECHNIQUES.md T12 lists where it is NOT VERIFIED.
4. Otherwise use `EI_CLASS`/`EI_DATA`, `source = Ident`; if they are invalid
   too, report `LayoutUndetermined` and make `program_headers()` an error
   (the loader view cannot be built).

Note: the kernel itself never decides a layout; its native handler always uses
the host's (LOADER_RULES.md §1). Step 2 reproduces that for every host whose
machine is in the list.

## 5. Test map

| test in `tolerant_api.rs` | files | API used |
|---|---|---|
| `controls_have_no_warnings` | s00, y00, t65, t83, t84, d00 | `validate`, `Severity` |
| `t01_..` - `t09_..` | s01-s15, d42, t60 | `validate`, `section_headers`, `symbol_tables` |
| `t10_..` - `t13_..` | t60, t61, s16-s24, t90, d16 | `layout`, `validate` |
| `t14_..` | s25, s26, t62-t64 | `segment_bytes`, `SegmentPastEof` |
| `t15_..` | s27-s30, s34, s35 | `memory_map().backing`, `LoadsOverlap` ... |
| `t16_..` | d00, d01, d40, t85, t86 | `dynamic`, `DynamicOffsetMismatch`, `InterpWithoutDynamic` |
| `t17_..` | y50-y54 | `SymbolTable::len`, symbol diagnostics |
| `t19_kernel_rules_are_named` | s31, s32, t62, t70-t89 | `kernel_prediction_for`, `KernelRule` |
| `kernel_prediction_agrees_with_the_oracle` | every `source = kernel` row of verdicts.tsv | `kernel_prediction_for` |

`crates/unforge-elf/tests/kernel_oracle.rs` needs no new API. It failed
on the files listed in README.md ("Current status") before, and passes once
`parse`/`layout` follow §4 and `segment_data` clips.

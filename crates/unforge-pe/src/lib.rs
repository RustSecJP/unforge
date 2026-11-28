//! A tolerant, panic-free reader of PE/COFF images (Windows `.exe` and
//! `.dll` files), in the style of `unforge-elf`.
//!
//! [`PeFile::parse`] fails only when there is no image at all: no `MZ`
//! signature, an `e_lfanew` outside the file, no `PE\0\0` signature, or a
//! COFF file header cut short. Everything else is read as far as the bytes
//! allow, and each anomaly is reported by [`PeFile::diagnostics`].
//!
//! What is read:
//!
//! - the DOS header (`e_lfanew` only), the COFF file header, the optional
//!   header (PE32 and PE32+), the data directories and the section table;
//! - the image's memory layout: which RVA is backed by which file bytes
//!   ([`PeFile::regions`], [`PeFile::rva_to_offset`],
//!   [`PeFile::bytes_at_rva`]), with the Windows loader's alignment rules
//!   (see "Mapping");
//! - the import directory ([`PeFile::imports`]): DLL names, imports by name
//!   (with hint) or by ordinal, and the IAT slot of each;
//! - the export directory ([`PeFile::exports`]), with forwarders;
//! - base relocations ([`PeFile::relocations`]);
//! - the x64 exception directory ([`PeFile::runtime_functions`]): the
//!   `RUNTIME_FUNCTION` entries of `.pdata`, which give the start and end of
//!   every function that has unwind data. In a stripped image this is the
//!   main source of function boundaries;
//! - TLS callbacks ([`PeFile::tls`]);
//! - the debug directory and the CodeView record with the PDB path
//!   ([`PeFile::debug_entries`], [`PeFile::codeview`]);
//! - the COFF symbol table, which MinGW-built (`*-windows-gnu`) images keep
//!   unless stripped ([`PeFile::coff_symbols`]), and long section names
//!   (`/123`) from its string table.
//!
//! # Mapping
//!
//! The Windows loader maps an image section by section. With the usual
//! `SectionAlignment >= 4096`:
//!
//! - the headers (`SizeOfHeaders` bytes from offset 0) are mapped at RVA 0;
//! - a section's memory is `[VirtualAddress, VirtualAddress +
//!   align_up(VirtualSize, SectionAlignment))`; a `VirtualSize` of 0 means
//!   `SizeOfRawData`;
//! - the file bytes come from `PointerToRawData` rounded *down* to 512 (the
//!   loader ignores the low 9 bits when `FileAlignment >= 512`), and there
//!   are `min(align_up(SizeOfRawData, FileAlignment), virtual size)` of
//!   them; the rest of the section is zero.
//!
//! With `SectionAlignment < 4096` ("low alignment", used by tiny
//! hand-crafted files and some drivers) the loader maps the file as it is:
//! RVA and file offset are the same. Where sections overlap in memory (the
//! loader refuses such images; the diagnostics say so), the one with the
//! lower start keeps the overlap, and the other is cut where it ends.
//!
//! # Bounds
//!
//! Every offset and size from the file is checked. Lists are capped
//! ([`MAX_SECTIONS`], [`MAX_IMPORTS`], [`MAX_EXPORTS`],
//! [`MAX_RUNTIME_FUNCTIONS`], [`MAX_TLS_CALLBACKS`], [`MAX_SYMBOLS`],
//! [`MAX_NAME_LEN`]); plain accessors allocate at most in proportion to
//! what they return.

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

mod diag;
mod dirs;
mod read;
mod symbols;
pub mod synth;

use core::fmt;

pub use diag::{Category, Diagnostic, DiagnosticKind, MAX_DIAGNOSTICS_PER_KIND, Severity};
pub use dirs::{
    CodeView, DebugEntry, Export, Exports, Import, ImportDll, ImportKind, Relocation, Relocations,
    RuntimeFunction, Tls,
};
pub use symbols::CoffSymbol;

use diag::Sink;
use read::{align_up, u16_at, u32_at, u64_at, usize_of};

/// `IMAGE_FILE_MACHINE_I386`
pub const MACHINE_I386: u16 = 0x14c;
/// `IMAGE_FILE_MACHINE_AMD64`
pub const MACHINE_AMD64: u16 = 0x8664;
/// `IMAGE_FILE_MACHINE_ARM64`
pub const MACHINE_ARM64: u16 = 0xaa64;
/// `IMAGE_FILE_MACHINE_ARMNT`
pub const MACHINE_ARMNT: u16 = 0x1c4;

/// `IMAGE_FILE_EXECUTABLE_IMAGE`
pub const FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
/// `IMAGE_FILE_DLL`
pub const FILE_DLL: u16 = 0x2000;

/// `IMAGE_SCN_CNT_CODE`
pub const SCN_CNT_CODE: u32 = 0x0000_0020;
/// `IMAGE_SCN_CNT_INITIALIZED_DATA`
pub const SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
/// `IMAGE_SCN_CNT_UNINITIALIZED_DATA`
pub const SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
/// `IMAGE_SCN_MEM_DISCARDABLE`
pub const SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
/// `IMAGE_SCN_MEM_EXECUTE`
pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// `IMAGE_SCN_MEM_READ`
pub const SCN_MEM_READ: u32 = 0x4000_0000;
/// `IMAGE_SCN_MEM_WRITE`
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Data directory indices (`IMAGE_DIRECTORY_ENTRY_*`).
pub mod dir {
    pub const EXPORT: usize = 0;
    pub const IMPORT: usize = 1;
    pub const RESOURCE: usize = 2;
    pub const EXCEPTION: usize = 3;
    pub const SECURITY: usize = 4;
    pub const BASERELOC: usize = 5;
    pub const DEBUG: usize = 6;
    pub const ARCHITECTURE: usize = 7;
    pub const GLOBALPTR: usize = 8;
    pub const TLS: usize = 9;
    pub const LOAD_CONFIG: usize = 10;
    pub const BOUND_IMPORT: usize = 11;
    pub const IAT: usize = 12;
    pub const DELAY_IMPORT: usize = 13;
    pub const CLR_RUNTIME: usize = 14;
    /// Short names, by index.
    pub const NAMES: [&str; 16] = [
        "export",
        "import",
        "resource",
        "exception",
        "security",
        "basereloc",
        "debug",
        "architecture",
        "globalptr",
        "tls",
        "load_config",
        "bound_import",
        "iat",
        "delay_import",
        "clr_runtime",
        "reserved",
    ];
}

/// At most this many section headers are read (the COFF field is 16 bits).
pub const MAX_SECTIONS: usize = 65_535;
/// At most this many imports are read (all DLLs together).
pub const MAX_IMPORTS: usize = 1 << 20;
/// At most this many imported DLLs are read.
pub const MAX_IMPORT_DLLS: usize = 1 << 14;
/// At most this many exports are read.
pub const MAX_EXPORTS: usize = 1 << 20;
/// At most this many `RUNTIME_FUNCTION` entries are read.
pub const MAX_RUNTIME_FUNCTIONS: usize = 1 << 22;
/// At most this many TLS callbacks are read.
pub const MAX_TLS_CALLBACKS: usize = 1024;
/// At most this many debug directory entries are read.
pub const MAX_DEBUG_ENTRIES: usize = 1024;
/// At most this many COFF symbols are read.
pub const MAX_SYMBOLS: usize = 1 << 22;
/// Names (DLLs, imports, exports, symbols, PDB path) longer than this are
/// cut.
pub const MAX_NAME_LEN: usize = 4096;

/// Page size of the Windows loader: below this `SectionAlignment` the file
/// is mapped as it is.
pub const PAGE_SIZE: u64 = 0x1000;

/// The file cannot be read as a PE image at all.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The first two bytes are not `MZ`.
    BadMagic([u8; 2]),
    /// `e_lfanew` (or the file header after it) is outside the file.
    BadPeOffset { offset: u64, file_len: u64 },
    /// The four bytes at `e_lfanew` are not `PE\0\0`.
    BadSignature([u8; 4]),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadMagic(m) => write!(f, "not a PE file (magic {m:02x?})"),
            Error::BadPeOffset { offset, file_len } => write!(
                f,
                "PE header offset {offset:#x} is outside the file ({file_len:#x} bytes)"
            ),
            Error::BadSignature(s) => write!(f, "no PE signature (found {s:02x?})"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

/// Whether `data` starts like a PE image (`MZ`). [`PeFile::parse`] decides.
pub fn looks_like_pe(data: &[u8]) -> bool {
    data.starts_with(b"MZ")
}

/// The COFF file header (`IMAGE_FILE_HEADER`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// PE32 or PE32+.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeKind {
    /// `0x10b`: 32-bit addresses.
    Pe32,
    /// `0x20b`: 64-bit addresses.
    Pe32Plus,
}

impl PeKind {
    /// Size of an address (thunks, TLS fields, pointers): 4 or 8.
    pub fn pointer_size(self) -> usize {
        match self {
            PeKind::Pe32 => 4,
            PeKind::Pe32Plus => 8,
        }
    }
}

/// One data directory (`IMAGE_DATA_DIRECTORY`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DataDirectory {
    pub rva: u32,
    pub size: u32,
}

/// The optional header (`IMAGE_OPTIONAL_HEADER32` / `64`), widened.
///
/// Fields beyond the end of a short optional header are 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalHeader {
    /// The raw magic (`0x10b`, `0x20b`, or anything else).
    pub magic: u16,
    /// The layout the header was read in. When `magic` is invalid it is
    /// guessed from the machine (the diagnostics say so).
    pub kind: PeKind,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub major_subsystem_version: u16,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub number_of_rva_and_sizes: u32,
    /// The 16 directories; the ones past `number_of_rva_and_sizes` (or past
    /// the end of the optional header) are zero.
    pub data_directories: [DataDirectory; 16],
}

/// A section header (`IMAGE_SECTION_HEADER`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub index: usize,
    /// The 8 raw name bytes.
    pub raw_name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub number_of_relocations: u16,
    pub characteristics: u32,
}

impl Section {
    /// Code is run from it (`MEM_EXECUTE`, or `CNT_CODE`: the loader maps
    /// code sections executable whatever the flags say on old systems, and
    /// linkers always set both).
    pub fn is_executable(&self) -> bool {
        self.characteristics & (SCN_MEM_EXECUTE | SCN_CNT_CODE) != 0
    }

    pub fn is_writable(&self) -> bool {
        self.characteristics & SCN_MEM_WRITE != 0
    }

    pub fn is_readable(&self) -> bool {
        self.characteristics & SCN_MEM_READ != 0
    }

    /// The name bytes before the first NUL (at most 8; see
    /// [`PeFile::section_name`] for long names).
    pub fn short_name(&self) -> &[u8] {
        read::cstr(&self.raw_name, 8).0
    }
}

/// One interval of the image's memory, and the file bytes behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    /// First RVA.
    pub start: u64,
    /// Exclusive end RVA (the virtual size, aligned).
    pub end: u64,
    /// File offset of the byte at `start`.
    pub file_offset: u64,
    /// How many bytes from `start` are file bytes (inside the file); the
    /// rest of the region is zero.
    pub file_len: u64,
    /// The section, or `None` for the headers.
    pub section: Option<usize>,
    /// The section's characteristics (`MEM_READ` for the headers).
    pub characteristics: u32,
}

impl Region {
    pub fn is_executable(&self) -> bool {
        self.characteristics & (SCN_MEM_EXECUTE | SCN_CNT_CODE) != 0
    }

    pub fn is_writable(&self) -> bool {
        self.characteristics & SCN_MEM_WRITE != 0
    }
}

/// A parsed PE image, borrowing the file's bytes.
#[derive(Debug, Clone)]
pub struct PeFile<'data> {
    data: &'data [u8],
    pe_offset: u64,
    coff: CoffHeader,
    optional: Option<OptionalHeader>,
    kind: PeKind,
    sections: Vec<Section>,
    regions: Vec<Region>,
    section_alignment: u64,
    file_alignment: u64,
    /// Findings made while parsing the headers.
    header_diags: Vec<Diagnostic>,
}

impl<'data> PeFile<'data> {
    /// Parses the headers and the section table of `data`.
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        let file_len = data.len() as u64;
        let magic = [
            data.first().copied().unwrap_or(0),
            data.get(1).copied().unwrap_or(0),
        ];
        if &magic != b"MZ" {
            return Err(Error::BadMagic(magic));
        }
        let lfanew = u32_at(data, 0x3c).ok_or(Error::BadPeOffset {
            offset: 0x3c,
            file_len,
        })?;
        let pe = usize_of(u64::from(lfanew));
        let sig = data
            .get(pe..pe.saturating_add(4))
            .filter(|s| s.len() == 4)
            .ok_or(Error::BadPeOffset {
                offset: u64::from(lfanew),
                file_len,
            })?;
        if sig != b"PE\0\0" {
            let mut s = [0u8; 4];
            s.copy_from_slice(sig);
            return Err(Error::BadSignature(s));
        }
        let fh = pe + 4;
        let bad = Error::BadPeOffset {
            offset: u64::from(lfanew),
            file_len,
        };
        let coff = CoffHeader {
            machine: u16_at(data, fh).ok_or_else(|| bad.clone())?,
            number_of_sections: u16_at(data, fh + 2).ok_or_else(|| bad.clone())?,
            time_date_stamp: u32_at(data, fh + 4).ok_or_else(|| bad.clone())?,
            pointer_to_symbol_table: u32_at(data, fh + 8).ok_or_else(|| bad.clone())?,
            number_of_symbols: u32_at(data, fh + 12).ok_or_else(|| bad.clone())?,
            size_of_optional_header: u16_at(data, fh + 16).ok_or_else(|| bad.clone())?,
            characteristics: u16_at(data, fh + 18).ok_or(bad)?,
        };
        let mut sink = Sink::recording();
        let opt_at = fh + 20;
        let optional = read_optional(data, opt_at, &coff, &mut sink);
        let kind = optional
            .as_ref()
            .map_or_else(|| guess_kind(coff.machine), |o: &OptionalHeader| o.kind);
        let sections = read_sections(data, opt_at, &coff, &mut sink);
        let mut file = PeFile {
            data,
            pe_offset: u64::from(lfanew),
            coff,
            optional,
            kind,
            sections,
            regions: Vec::new(),
            section_alignment: PAGE_SIZE,
            file_alignment: 0x200,
            header_diags: Vec::new(),
        };
        file.build_regions(&mut sink);
        file.check_headers(&mut sink);
        file.header_diags = sink.out;
        Ok(file)
    }

    pub fn data(&self) -> &'data [u8] {
        self.data
    }

    /// File offset of the `PE\0\0` signature (`e_lfanew`).
    pub fn pe_offset(&self) -> u64 {
        self.pe_offset
    }

    pub fn coff(&self) -> &CoffHeader {
        &self.coff
    }

    pub fn machine(&self) -> u16 {
        self.coff.machine
    }

    /// The optional header, `None` when `SizeOfOptionalHeader` is too small
    /// to hold even its magic.
    pub fn optional(&self) -> Option<&OptionalHeader> {
        self.optional.as_ref()
    }

    /// The layout used for addresses (see [`OptionalHeader::kind`]).
    pub fn kind(&self) -> PeKind {
        self.kind
    }

    /// `IMAGE_FILE_DLL` is set.
    pub fn is_dll(&self) -> bool {
        self.coff.characteristics & FILE_DLL != 0
    }

    /// The preferred load address (0 without an optional header).
    pub fn image_base(&self) -> u64 {
        self.optional.as_ref().map_or(0, |o| o.image_base)
    }

    /// The entry point RVA, `None` when it is 0 (DLLs may have none).
    pub fn entry_rva(&self) -> Option<u32> {
        self.optional
            .as_ref()
            .map(|o| o.address_of_entry_point)
            .filter(|&e| e != 0)
    }

    /// `rva` as a virtual address at the preferred base.
    pub fn rva_to_va(&self, rva: u64) -> Option<u64> {
        self.image_base().checked_add(rva)
    }

    /// `va` (at the preferred base) as an RVA.
    pub fn va_to_rva(&self, va: u64) -> Option<u64> {
        va.checked_sub(self.image_base())
    }

    /// The data directory `index` ([`dir`]), `None` when absent or empty.
    pub fn directory(&self, index: usize) -> Option<DataDirectory> {
        let d = *self.optional.as_ref()?.data_directories.get(index)?;
        (d.rva != 0).then_some(d)
    }

    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// The section's name: the short name, or for `/<decimal>` the long
    /// name from the COFF string table (MinGW images), lossily as UTF-8.
    pub fn section_name(&self, s: &Section) -> String {
        let short = s.short_name();
        if let Some(digits) = short.strip_prefix(b"/")
            && let Ok(text) = std::str::from_utf8(digits)
            && let Ok(off) = text.parse::<u32>()
            && let Some(long) = symbols::string_at(self, off)
        {
            return String::from_utf8_lossy(long).into_owned();
        }
        String::from_utf8_lossy(short).into_owned()
    }

    /// The section that maps `rva` (by its memory extent).
    pub fn section_at_rva(&self, rva: u64) -> Option<&Section> {
        let r = self.region_at(rva)?;
        self.sections.get(r.section?)
    }

    /// The image's memory, sorted by RVA, without overlaps: the headers
    /// first, then one region per section that has memory.
    pub fn regions(&self) -> &[Region] {
        &self.regions
    }

    /// The region containing `rva`.
    pub fn region_at(&self, rva: u64) -> Option<&Region> {
        let i = self.regions.partition_point(|r| r.start <= rva);
        let r = self.regions.get(i.checked_sub(1)?)?;
        (rva < r.end).then_some(r)
    }

    /// The file offset of the byte at `rva`, `None` when that byte is not
    /// backed by the file (zero fill, outside every section, or past the
    /// end of the file).
    pub fn rva_to_offset(&self, rva: u64) -> Option<u64> {
        let r = self.region_at(rva)?;
        let d = rva - r.start;
        (d < r.file_len).then(|| r.file_offset + d)
    }

    /// The file bytes from `rva` to the end of what its region maps from
    /// the file. Empty slices are never returned.
    pub fn bytes_at_rva(&self, rva: u64) -> Option<&'data [u8]> {
        let r = self.region_at(rva)?;
        let d = rva - r.start;
        if d >= r.file_len {
            return None;
        }
        let s = usize_of(r.file_offset.checked_add(d)?);
        let e = usize_of(r.file_offset.checked_add(r.file_len)?);
        self.data.get(s..e).filter(|b| !b.is_empty())
    }

    /// [`PeFile::bytes_at_rva`] at the virtual address `va`.
    pub fn bytes_at_va(&self, va: u64) -> Option<&'data [u8]> {
        self.bytes_at_rva(self.va_to_rva(va)?)
    }

    /// `rva` lies in an executable region.
    pub fn is_executable_rva(&self, rva: u64) -> bool {
        self.region_at(rva).is_some_and(Region::is_executable)
    }

    /// Up to `len` bytes at `rva` (fewer where the file bytes end).
    pub(crate) fn slice_at_rva(&self, rva: u64, len: u64) -> Option<&'data [u8]> {
        let b = self.bytes_at_rva(rva)?;
        b.get(..usize_of(len).min(b.len()))
    }

    /// The end of the last section's file bytes, and how many bytes follow
    /// it (an overlay: installers, appended payloads, certificates).
    pub fn overlay(&self) -> Option<(u64, u64)> {
        let end = self
            .regions
            .iter()
            .filter(|r| r.section.is_some())
            .map(|r| r.file_offset.saturating_add(r.file_len))
            .max()?;
        let len = (self.data.len() as u64).checked_sub(end)?;
        (len > 0).then_some((end, len))
    }

    /// Every finding: the headers' and those of every directory.
    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        let mut sink = Sink::recording();
        sink.out = self.header_diags.clone();
        dirs::audit(self, &mut sink);
        symbols::audit(self, &mut sink);
        sink.finish()
    }

    fn build_regions(&mut self, sink: &mut Sink) {
        let (sa, fa, size_of_headers) = match &self.optional {
            Some(o) => (
                u64::from(o.section_alignment),
                u64::from(o.file_alignment),
                u64::from(o.size_of_headers),
            ),
            None => (PAGE_SIZE, 0x200, 0),
        };
        let file_len = self.data.len() as u64;
        let (sa, fa) = effective_alignment(sa, fa, sink);
        self.section_alignment = sa;
        self.file_alignment = fa;
        let low = sa < PAGE_SIZE;
        if low {
            sink.push(Severity::Info, DiagnosticKind::LowAlignment, None, || {
                format!(
                    "SectionAlignment {sa:#x} is below the page size: the loader maps the file as it is (RVA = file offset)"
                )
            });
        }
        let mut regions: Vec<Region> = Vec::with_capacity(self.sections.len() + 1);
        let first_section = self
            .sections
            .iter()
            .map(|s| u64::from(s.virtual_address))
            .filter(|&v| v > 0)
            .min()
            .unwrap_or(u64::MAX);
        let hdr_mem = if low {
            first_section.min(file_len.max(size_of_headers))
        } else {
            align_up(size_of_headers.max(1), sa).min(first_section)
        };
        if hdr_mem > 0 && hdr_mem != u64::MAX {
            regions.push(Region {
                start: 0,
                end: hdr_mem,
                file_offset: 0,
                file_len: if low { hdr_mem } else { size_of_headers }
                    .min(file_len)
                    .min(hdr_mem),
                section: None,
                characteristics: SCN_MEM_READ,
            });
        }
        let mut prev_va = 0u64;
        for s in &self.sections {
            let start = u64::from(s.virtual_address);
            if start < prev_va {
                sink.push(
                    Severity::Warning,
                    DiagnosticKind::SectionMisordered,
                    None,
                    || {
                        format!(
                            "section {} starts at RVA {start:#x}, below the previous section ({prev_va:#x})",
                            s.index
                        )
                    },
                );
            }
            prev_va = start;
            let vs = section_virtual_size(s);
            let mem = align_up(vs, sa);
            let end = start.saturating_add(mem);
            if mem == 0 {
                continue;
            }
            let (raw_off, mut raw_len) = if low {
                (start, mem)
            } else {
                let off = if fa >= 0x200 {
                    u64::from(s.pointer_to_raw_data) & !0x1ff
                } else {
                    u64::from(s.pointer_to_raw_data)
                };
                let len = if s.pointer_to_raw_data == 0 {
                    0
                } else {
                    align_up(u64::from(s.size_of_raw_data), fa).min(mem)
                };
                (off, len)
            };
            let avail = file_len.saturating_sub(raw_off);
            if raw_len > avail {
                if !low {
                    sink.push(
                        Severity::Warning,
                        DiagnosticKind::SectionPastEndOfFile,
                        Some(raw_off),
                        || {
                            format!(
                                "section {} wants {raw_len:#x} file bytes from offset {raw_off:#x}, the file has {avail:#x}: the rest reads as zero",
                                s.index
                            )
                        },
                    );
                }
                raw_len = avail;
            }
            regions.push(Region {
                start,
                end,
                file_offset: raw_off,
                file_len: raw_len,
                section: Some(s.index),
                characteristics: s.characteristics,
            });
        }
        let (regions, overlapped) = sweep(regions);
        for (idx, start, end) in overlapped {
            sink.push(Severity::WouldNotLoad, DiagnosticKind::SectionsOverlap, None, || {
                format!(
                    "section {idx} (RVA {start:#x}..{end:#x}) overlaps the memory of a section (or the headers) below it; that one is kept"
                )
            });
        }
        self.regions = regions;
    }

    fn check_headers(&self, sink: &mut Sink) {
        let Some(o) = &self.optional else { return };
        let file_len = self.data.len() as u64;
        if o.size_of_image != 0 {
            let last = self.regions.iter().map(|r| r.end).max().unwrap_or(0);
            let want = align_up(last, self.section_alignment);
            if u64::from(o.size_of_image) < last {
                sink.push(
                    Severity::WouldNotLoad,
                    DiagnosticKind::SizeOfImageMismatch,
                    None,
                    || {
                        format!(
                            "SizeOfImage {:#x} is smaller than the sections' extent {want:#x}",
                            o.size_of_image
                        )
                    },
                );
            }
        }
        if u64::from(o.size_of_headers) > file_len {
            sink.push(
                Severity::Warning,
                DiagnosticKind::SizeOfHeadersMismatch,
                None,
                || {
                    format!(
                        "SizeOfHeaders {:#x} is past the end of the file ({file_len:#x})",
                        o.size_of_headers
                    )
                },
            );
        }
        if self.coff.characteristics & FILE_EXECUTABLE_IMAGE == 0 {
            sink.push(
                Severity::WouldNotLoad,
                DiagnosticKind::NotExecutableImage,
                None,
                || "IMAGE_FILE_EXECUTABLE_IMAGE is not set".to_owned(),
            );
        }
        if !matches!(
            self.coff.machine,
            MACHINE_I386 | MACHINE_AMD64 | MACHINE_ARM64 | MACHINE_ARMNT
        ) {
            let m = self.coff.machine;
            sink.push(Severity::Info, DiagnosticKind::UnknownMachine, None, || {
                format!("machine {m:#x} is not x86, x86-64 or ARM")
            });
        }
        if let Some(e) = self.entry_rva() {
            let e = u64::from(e);
            match self.region_at(e) {
                None => sink.push(
                    Severity::Warning,
                    DiagnosticKind::EntryOutsideImage,
                    None,
                    || format!("the entry point RVA {e:#x} is outside every section"),
                ),
                Some(r) if !r.is_executable() => sink.push(
                    Severity::Warning,
                    DiagnosticKind::EntryNotExecutable,
                    None,
                    || format!("the entry point RVA {e:#x} is in a section that is not executable"),
                ),
                Some(_) => {}
            }
        }
        if let Some((at, len)) = self.overlay() {
            sink.push(Severity::Info, DiagnosticKind::Overlay, Some(at), || {
                format!("{len:#x} bytes after the last section (an overlay)")
            });
        }
        for (i, d) in o.data_directories.iter().enumerate() {
            // The security directory holds a file offset, not an RVA.
            if d.rva == 0 || i == dir::SECURITY {
                continue;
            }
            if self.rva_to_offset(u64::from(d.rva)).is_none() {
                let name = dir::NAMES.get(i).copied().unwrap_or("?");
                sink.push(
                    Severity::Warning,
                    DiagnosticKind::DirectoryUnmapped,
                    None,
                    || {
                        format!(
                            "the {name} directory at RVA {:#x} is not backed by file bytes",
                            d.rva
                        )
                    },
                );
            }
        }
    }
}

fn guess_kind(machine: u16) -> PeKind {
    match machine {
        MACHINE_AMD64 | MACHINE_ARM64 => PeKind::Pe32Plus,
        _ => PeKind::Pe32,
    }
}

fn section_virtual_size(s: &Section) -> u64 {
    if s.virtual_size == 0 {
        u64::from(s.size_of_raw_data)
    } else {
        u64::from(s.virtual_size)
    }
}

/// The alignments the mapping uses: the file's when they are powers of two
/// with `FileAlignment <= SectionAlignment`, else the usual 4096 / 512.
fn effective_alignment(sa: u64, fa: u64, sink: &mut Sink) -> (u64, u64) {
    let sa_ok = sa.is_power_of_two();
    let fa_ok = fa.is_power_of_two() && fa <= sa.max(1);
    if !sa_ok || !fa_ok {
        sink.push(Severity::WouldNotLoad, DiagnosticKind::BadAlignment, None, || {
            format!(
                "SectionAlignment {sa:#x} / FileAlignment {fa:#x} are not valid (powers of two, file <= section); read as 0x1000 / 0x200"
            )
        });
    }
    let sa = if sa_ok { sa } else { PAGE_SIZE };
    let fa = if fa_ok && fa <= sa { fa } else { 0x200.min(sa) };
    (sa, fa)
}

/// Sorts `regions` by start (the headers first at equal starts, then table
/// order) and cuts the front of every region that overlaps the ones before
/// it. Returns the regions and the (section, start, end) of every section
/// that was cut.
fn sweep(mut regions: Vec<Region>) -> (Vec<Region>, Vec<(usize, u64, u64)>) {
    regions.sort_by_key(|r| (r.start, r.section.map_or(0, |i| i + 1)));
    let mut out: Vec<Region> = Vec::with_capacity(regions.len());
    let mut cut = Vec::new();
    let mut covered = 0u64;
    for r in regions {
        if r.start < covered {
            if let Some(i) = r.section {
                cut.push((i, r.start, r.end));
            }
            if r.end <= covered {
                continue;
            }
            let d = covered - r.start;
            out.push(Region {
                start: covered,
                file_offset: r.file_offset.saturating_add(d),
                file_len: r.file_len.saturating_sub(d),
                ..r
            });
        } else {
            out.push(r);
        }
        covered = covered.max(r.end);
    }
    (out, cut)
}

fn read_optional(
    data: &[u8],
    at: usize,
    coff: &CoffHeader,
    sink: &mut Sink,
) -> Option<OptionalHeader> {
    let declared = usize::from(coff.size_of_optional_header);
    let avail = data.len().saturating_sub(at);
    let size = declared.min(avail);
    if size < 2 {
        sink.push(
            Severity::WouldNotLoad,
            DiagnosticKind::OptionalHeaderMissing,
            Some(at as u64),
            || {
                format!(
                    "no optional header (SizeOfOptionalHeader {declared}, {avail} bytes left in the file)"
                )
            },
        );
        return None;
    }
    if size < declared {
        sink.push(
            Severity::Warning,
            DiagnosticKind::OptionalHeaderTruncated,
            Some(at as u64),
            || format!("the optional header ({declared} bytes) is cut by the end of the file"),
        );
    }
    let h = data.get(at..at + size)?;
    let magic = u16_at(h, 0)?;
    let kind = match magic {
        0x10b => PeKind::Pe32,
        0x20b => PeKind::Pe32Plus,
        _ => {
            let k = guess_kind(coff.machine);
            sink.push(
                Severity::WouldNotLoad,
                DiagnosticKind::BadOptionalMagic,
                Some(at as u64),
                || format!("optional header magic {magic:#x} is neither PE32 nor PE32+; read as {k:?} from the machine"),
            );
            k
        }
    };
    let r16 = |o: usize| u16_at(h, o).unwrap_or(0);
    let r32 = |o: usize| u32_at(h, o).unwrap_or(0);
    let r8 = |o: usize| h.get(o).copied().unwrap_or(0);
    let (image_base, nrva_at, dirs_at) = match kind {
        PeKind::Pe32 => (u64::from(r32(28)), 92, 96),
        PeKind::Pe32Plus => (u64_at(h, 24).unwrap_or(0), 108, 112),
    };
    let needed = dirs_at;
    if size < needed && size == declared {
        sink.push(
            Severity::Warning,
            DiagnosticKind::OptionalHeaderTruncated,
            Some(at as u64),
            || format!("SizeOfOptionalHeader {declared} is smaller than the fixed part ({needed} bytes)"),
        );
    }
    let nrva = r32(nrva_at);
    if nrva < 16 {
        sink.push(
            Severity::Info,
            DiagnosticKind::FewDataDirectories,
            None,
            || format!("NumberOfRvaAndSizes is {nrva}: the other directories are absent"),
        );
    } else if nrva > 16 {
        sink.push(
            Severity::Info,
            DiagnosticKind::ManyDataDirectories,
            None,
            || format!("NumberOfRvaAndSizes is {nrva}: the loader uses the first 16"),
        );
    }
    let mut data_directories = [DataDirectory::default(); 16];
    for (i, d) in data_directories.iter_mut().enumerate() {
        if i as u64 >= u64::from(nrva) {
            break;
        }
        let o = dirs_at + i * 8;
        if let (Some(rva), Some(size)) = (u32_at(h, o), u32_at(h, o + 4)) {
            *d = DataDirectory { rva, size };
        }
    }
    Some(OptionalHeader {
        magic,
        kind,
        major_linker_version: r8(2),
        minor_linker_version: r8(3),
        size_of_code: r32(4),
        address_of_entry_point: r32(16),
        base_of_code: r32(20),
        image_base,
        section_alignment: r32(32),
        file_alignment: r32(36),
        major_operating_system_version: r16(40),
        major_subsystem_version: r16(48),
        size_of_image: r32(56),
        size_of_headers: r32(60),
        checksum: r32(64),
        subsystem: r16(68),
        dll_characteristics: r16(70),
        number_of_rva_and_sizes: nrva,
        data_directories,
    })
}

fn read_sections(data: &[u8], opt_at: usize, coff: &CoffHeader, sink: &mut Sink) -> Vec<Section> {
    let at = opt_at.saturating_add(usize::from(coff.size_of_optional_header));
    let declared = usize::from(coff.number_of_sections).min(MAX_SECTIONS);
    let fit = data.len().saturating_sub(at) / 40;
    let n = declared.min(fit);
    if n < declared {
        sink.push(
            Severity::Warning,
            DiagnosticKind::SectionTableTruncated,
            Some(at as u64),
            || format!("the section table declares {declared} sections, {n} fit in the file"),
        );
    }
    if declared > 96 {
        sink.push(Severity::Info, DiagnosticKind::ManySections, None, || {
            format!("{declared} sections (more than the 96 older Windows loaders accept)")
        });
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let o = at + i * 40;
        let Some(h) = data.get(o..o + 40) else { break };
        let mut raw_name = [0u8; 8];
        if let Some(name) = h.get(..8) {
            raw_name.copy_from_slice(name);
        }
        out.push(Section {
            index: i,
            raw_name,
            virtual_size: u32_at(h, 8).unwrap_or(0),
            virtual_address: u32_at(h, 12).unwrap_or(0),
            size_of_raw_data: u32_at(h, 16).unwrap_or(0),
            pointer_to_raw_data: u32_at(h, 20).unwrap_or(0),
            pointer_to_relocations: u32_at(h, 24).unwrap_or(0),
            number_of_relocations: u16_at(h, 32).unwrap_or(0),
            characteristics: u32_at(h, 36).unwrap_or(0),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_pe() {
        assert_eq!(PeFile::parse(b"").unwrap_err(), Error::BadMagic([0, 0]));
        assert_eq!(
            PeFile::parse(b"\x7fELF").unwrap_err(),
            Error::BadMagic([0x7f, b'E'])
        );
        assert!(matches!(
            PeFile::parse(b"MZ").unwrap_err(),
            Error::BadPeOffset { .. }
        ));
        let mut b = vec![0u8; 0x80];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3c] = 0x40;
        assert!(matches!(
            PeFile::parse(&b).unwrap_err(),
            Error::BadSignature(_)
        ));
        b[0x40..0x44].copy_from_slice(b"PE\0\0");
        // File header cut short.
        assert!(matches!(
            PeFile::parse(&b[..0x50]).unwrap_err(),
            Error::BadPeOffset { .. }
        ));
        // A bare file header: no optional header, no sections, still parsed.
        let pe = PeFile::parse(&b).unwrap();
        assert!(pe.optional().is_none());
        assert!(
            pe.diagnostics()
                .iter()
                .any(|d| d.kind == DiagnosticKind::OptionalHeaderMissing)
        );
    }

    #[test]
    fn overlap_removal() {
        let r = |s, e, sec| Region {
            start: s,
            end: e,
            file_offset: s,
            file_len: e - s,
            section: Some(sec),
            characteristics: 0,
        };
        let (out, cut) = sweep(vec![
            r(0x1000, 0x2000, 0),
            r(0x800, 0x3000, 1),
            r(0x1100, 0x1200, 2),
        ]);
        assert_eq!(
            out.iter()
                .map(|x| (x.start, x.end, x.section))
                .collect::<Vec<_>>(),
            vec![(0x800, 0x3000, Some(1))]
        );
        assert_eq!(cut.len(), 2);
        let (out, _) = sweep(vec![r(0x1000, 0x2000, 0), r(0x1800, 0x3000, 1)]);
        assert_eq!(out[1].start, 0x2000);
        assert_eq!(out[1].file_offset, 0x2000);
    }
}

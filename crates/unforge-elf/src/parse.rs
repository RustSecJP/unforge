use crate::consts::*;
use crate::layout::{self, HeaderFields, Layout};
use crate::table::{LayoutTable, PhdrKind, ProgramHeaders, SectionHeaders, ShdrKind};
use crate::{Class, Endian, Error, Header, ProgramHeader, Result, SectionHeader};

// ---------------------------------------------------------------------------
// Bounds-checked primitive reads.
// ---------------------------------------------------------------------------

pub(crate) fn file_len(data: &[u8]) -> u64 {
    data.len() as u64
}

/// The part of `[offset, offset + size)` that lies inside the file.
///
/// Returned by [`ElfFile::segment_bytes`] and [`ElfFile::section_bytes`]:
/// a range that runs past the end of the file is clipped, not refused, and
/// `missing` says how many declared bytes do not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClippedBytes<'data> {
    /// The declared bytes that are inside the file.
    pub bytes: &'data [u8],
    /// Declared bytes past the end of the file (0 when nothing was clipped).
    pub missing: u64,
}

impl ClippedBytes<'_> {
    pub fn is_clipped(&self) -> bool {
        self.missing != 0
    }
}

pub(crate) fn clip(data: &[u8], offset: u64, size: u64) -> ClippedBytes<'_> {
    let len = file_len(data);
    let start = offset.min(len);
    let end = offset.saturating_add(size).min(len);
    // Both bounds are <= data.len(), so the conversions and the slice cannot fail.
    let bytes = usize::try_from(start)
        .ok()
        .zip(usize::try_from(end).ok())
        .and_then(|(s, e)| data.get(s..e))
        .unwrap_or(&[]);
    ClippedBytes {
        bytes,
        missing: size - bytes.len() as u64,
    }
}

/// `data[offset..]`, or `None` past the end.
pub(crate) fn tail(data: &[u8], offset: u64) -> Option<&[u8]> {
    data.get(usize::try_from(offset).ok()?..)
}

/// The NUL-terminated string starting at `offset` in `table` (without the NUL).
pub(crate) fn cstr_at(table: &[u8], offset: u32) -> Result<&[u8]> {
    cstr_at_bounded(table, offset, usize::MAX).map(|n| n.bytes)
}

/// Like [`cstr_at`], but looks at no more than `max` bytes.
///
/// gABI ch4 "String Table" lets many entries share one string and puts no
/// limit on its length, so an unbounded lookup per entry costs
/// O(entries * string length) on a file of size O(entries + string length).
/// This bounds the cost of one lookup by `max`.
pub(crate) fn cstr_at_bounded(table: &[u8], offset: u32, max: usize) -> Result<BoundedName<'_>> {
    let bad = || Error::BadString {
        offset: offset.into(),
    };
    let start = usize::try_from(offset).map_err(|_| bad())?;
    let rest = table.get(start..).ok_or_else(bad)?;
    // Look one byte past `max` so that a name of exactly `max` bytes is found
    // together with its NUL and is not reported as truncated.
    let window = rest.get(..max.saturating_add(1)).unwrap_or(rest);
    match window.iter().position(|&b| b == 0) {
        Some(len) => Ok(BoundedName {
            bytes: window.get(..len).unwrap_or(window),
            truncated: false,
        }),
        // No NUL within `max + 1` bytes, but the table goes on: whether the
        // string is terminated at all is not checked.
        None if window.len() < rest.len() => Ok(BoundedName {
            bytes: window.get(..max).unwrap_or(window),
            truncated: true,
        }),
        None => Err(bad()),
    }
}

/// A name read with a length limit (see [`crate::SymbolTable::name_bounded`]
/// and [`ElfFile::section_name_bounded`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedName<'data> {
    /// The name, or its first `max` bytes when `truncated`.
    pub bytes: &'data [u8],
    /// No NUL was found within the limit. The string may still be
    /// unterminated further on; that was not checked.
    pub truncated: bool,
}

// ---------------------------------------------------------------------------
// ElfFile
// ---------------------------------------------------------------------------

/// A parsed ELF file borrowing its input bytes.
///
/// `parse` does O(1) work and allocates nothing: it decides the layout,
/// decodes the ELF header and sets up views of the program and section header
/// tables. A broken table does not make the whole file unreadable: the
/// corresponding accessor returns the error instead, so e.g. a file with a
/// garbage `e_shoff` still exposes its segments.
#[derive(Debug, Clone)]
pub struct ElfFile<'data> {
    pub(crate) data: &'data [u8],
    pub(crate) header: Header,
    pub(crate) layout: Layout,
    pub(crate) phdrs: Result<ProgramHeaders<'data>>,
    pub(crate) shdrs: Result<SectionHeaders<'data>>,
}

impl<'data> ElfFile<'data> {
    /// Read the ELF header and locate the tables.
    ///
    /// Fails only when there is no ELF header to read: the magic is wrong,
    /// the file is shorter than `e_ident` or than the header of every class,
    /// or no clue at all supports any layout ([`Error::UndeterminedLayout`]).
    /// `EI_CLASS`/`EI_DATA` are not trusted on their own; see [`Layout`].
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        let magic: Option<[u8; 4]> = data.get(..4).and_then(|m| m.try_into().ok());
        match magic {
            Some(m) if m != ELFMAG => return Err(Error::BadMagic(m)),
            _ => {}
        }
        if data.len() < 16 {
            return Err(Error::OutOfBounds {
                what: "e_ident",
                offset: 0,
                size: 16,
                file_len: file_len(data),
            });
        }
        let (layout, fields) = match layout::detect(data) {
            Ok(x) => x,
            Err(layout::DetectError::TooShort { needed }) => {
                return Err(Error::OutOfBounds {
                    what: "ELF header",
                    offset: 0,
                    size: needed,
                    file_len: file_len(data),
                });
            }
            Err(layout::DetectError::Undetermined) => {
                return Err(Error::UndeterminedLayout {
                    ident_class: data.get(4).copied().unwrap_or(0),
                    ident_data: data.get(5).copied().unwrap_or(0),
                });
            }
        };
        let mut header = header_from(data, &layout, &fields);
        let escapes = resolve_extended_numbering(data, &mut header);
        let (class, endian) = (header.class, header.endian);

        let phdrs = match escapes.program_headers {
            Some(e) => Err(e),
            None => table::<PhdrKind>(
                data,
                class,
                endian,
                "program header table",
                header.phoff,
                header.phnum,
                header.phentsize,
            ),
        };
        let shdrs = match escapes.section_headers {
            Some(e) => Err(e),
            None if header.shoff == 0 => Ok(LayoutTable::empty(class, endian)),
            None => table::<ShdrKind>(
                data,
                class,
                endian,
                "section header table",
                header.shoff,
                header.shnum,
                header.shentsize,
            ),
        };

        Ok(ElfFile {
            data,
            header,
            layout,
            phdrs,
            shdrs,
        })
    }

    pub fn data(&self) -> &'data [u8] {
        self.data
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The layout the file is read in, and the evidence for it.
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// The program header table: the declared entries that are inside the
    /// file. Fails only when not even one entry can be read (or when
    /// `PN_XNUM` cannot be resolved). An `e_phentsize` larger than
    /// `sizeof(Phdr)` is used as the stride; a smaller one is replaced by
    /// `sizeof(Phdr)` (an inference the audit reports).
    pub fn program_headers(&self) -> Result<ProgramHeaders<'data>> {
        self.phdrs.clone()
    }

    /// The section header table, with the same rules as
    /// [`ElfFile::program_headers`]. Empty when `e_shoff == 0`.
    pub fn section_headers(&self) -> Result<SectionHeaders<'data>> {
        self.shdrs.clone()
    }

    pub fn section_header(&self, index: usize) -> Result<SectionHeader> {
        let sections = self.section_headers()?;
        sections.get(index).ok_or(Error::BadIndex {
            what: "section index",
            index: index as u64,
            len: sections.len() as u64,
        })
    }

    /// The part of a segment's file bytes (`p_offset`, `p_filesz`) that is
    /// inside the file.
    pub fn segment_bytes(&self, segment: &ProgramHeader) -> ClippedBytes<'data> {
        clip(self.data, segment.offset, segment.filesz)
    }

    /// The bytes a segment occupies in the file (`p_filesz`, not `p_memsz`),
    /// clipped to the end of the file (the kernel maps such segments; see
    /// [`ElfFile::segment_bytes`] for how much is missing). Fails only when
    /// `p_offset + p_filesz` overflows.
    pub fn segment_data(&self, segment: &ProgramHeader) -> Result<&'data [u8]> {
        segment
            .offset
            .checked_add(segment.filesz)
            .ok_or(Error::Overflow {
                what: "segment data",
            })?;
        Ok(self.segment_bytes(segment).bytes)
    }

    /// The part of a section's bytes that is inside the file. `SHT_NOBITS`
    /// (e.g. `.bss`) and `SHT_NULL` sections occupy no file bytes.
    ///
    /// gABI ch4 "Sections", `SHT_NULL`: "it does not have an associated
    /// section. Other members of the section header have undefined values."
    /// In particular section 0's `sh_size` may hold the extended section
    /// count, not a data size.
    pub fn section_bytes(&self, section: &SectionHeader) -> ClippedBytes<'data> {
        if section.sh_type == SHT_NOBITS || section.sh_type == SHT_NULL {
            return ClippedBytes {
                bytes: &[],
                missing: 0,
            };
        }
        clip(self.data, section.offset, section.size)
    }

    /// The bytes a section occupies in the file, clipped to the end of the
    /// file ([`ElfFile::section_bytes`] says how much is missing). Fails only
    /// when `sh_offset + sh_size` overflows.
    pub fn section_data(&self, section: &SectionHeader) -> Result<&'data [u8]> {
        let b = self.section_bytes(section);
        if section.sh_type != SHT_NOBITS && section.sh_type != SHT_NULL {
            section
                .offset
                .checked_add(section.size)
                .ok_or(Error::Overflow {
                    what: "section data",
                })?;
        }
        Ok(b.bytes)
    }

    /// The section name string table (`e_shstrndx`), whatever its type (the
    /// audit reports a non-`SHT_STRTAB` one).
    ///
    /// Fails when the file has none (`SHN_UNDEF`), when `SHN_XINDEX` could
    /// not be resolved through section 0, or when the index is past the
    /// section header table.
    pub fn section_name_table(&self) -> Result<&'data [u8]> {
        let index = self.header.shstrndx.ok_or(Error::BadIndex {
            what: match self.header.raw_shstrndx {
                SHN_UNDEF => "e_shstrndx (SHN_UNDEF: no section name table)",
                _ => "e_shstrndx (SHN_XINDEX not resolvable through section 0)",
            },
            index: self.header.raw_shstrndx.into(),
            len: self.header.shnum,
        })?;
        let sh = self.section_header(index as usize).map_err(|e| match e {
            Error::BadIndex { len, .. } => Error::BadIndex {
                what: "e_shstrndx",
                index: index.into(),
                len,
            },
            e => e,
        })?;
        Ok(self.section_bytes(&sh).bytes)
    }

    /// The raw bytes of a section's name. ELF does not require names to be UTF-8.
    ///
    /// Cost: O(length of the name), which the file controls (all sections
    /// may share one long string); use [`ElfFile::section_name_bounded`] when
    /// naming every section.
    pub fn section_name(&self, section: &SectionHeader) -> Result<&'data [u8]> {
        cstr_at(self.section_name_table()?, section.name)
    }

    /// Like [`ElfFile::section_name`], but reads at most `max` bytes of the
    /// name, so the cost does not depend on the string table's contents.
    pub fn section_name_bounded(
        &self,
        section: &SectionHeader,
        max: usize,
    ) -> Result<BoundedName<'data>> {
        cstr_at_bounded(self.section_name_table()?, section.name, max)
    }

    /// The first section whose name is exactly `name`.
    ///
    /// Cost: O(sections * (`name.len()` + 1)): only `name.len() + 1` bytes of
    /// each section's name are compared, however long the names in the file
    /// are. No allocation.
    pub fn section_by_name(&self, name: &[u8]) -> Option<(usize, SectionHeader)> {
        let table = self.section_name_table().ok()?;
        self.section_headers()
            .ok()?
            .iter()
            .enumerate()
            .find(|(_, sh)| name_is(table, sh.name, name))
    }
}

/// `table[offset..]` starts with `name` followed by a NUL.
fn name_is(table: &[u8], offset: u32, name: &[u8]) -> bool {
    let Ok(start) = usize::try_from(offset) else {
        return false;
    };
    let Some(rest) = table.get(start..) else {
        return false;
    };
    rest.get(..name.len()) == Some(name) && rest.get(name.len()) == Some(&0)
}

/// A table view of at most `count` entries at `offset`.
fn table<'data, K: crate::table::EntryKind>(
    data: &'data [u8],
    class: Class,
    endian: Endian,
    what: &'static str,
    offset: u64,
    count: u64,
    entsize: u16,
) -> Result<LayoutTable<'data, K>> {
    if count == 0 {
        return Ok(LayoutTable::empty(class, endian));
    }
    let size = LayoutTable::<K>::entry_size(class);
    let stride = usize::from(entsize).max(size);
    let oob = || Error::OutOfBounds {
        what,
        offset,
        size: count.saturating_mul(stride as u64),
        file_len: file_len(data),
    };
    let bytes = tail(data, offset).ok_or_else(oob)?;
    let t = LayoutTable::new(class, endian, bytes, stride, count).ok_or_else(oob)?;
    if t.is_empty() {
        return Err(oob());
    }
    Ok(t)
}

fn header_from(data: &[u8], layout: &Layout, f: &HeaderFields) -> Header {
    let byte = |i: usize| data.get(i).copied().unwrap_or(0);
    Header {
        class: layout.class,
        endian: layout.endian,
        ident_class: byte(4),
        ident_data: byte(5),
        ident_version: byte(6),
        os_abi: byte(7),
        abi_version: byte(8),
        e_type: f.e_type,
        machine: f.e_machine,
        version: f.e_version,
        entry: f.e_entry,
        phoff: f.e_phoff,
        shoff: f.e_shoff,
        flags: f.e_flags,
        ehsize: f.e_ehsize,
        phentsize: f.e_phentsize,
        shentsize: f.e_shentsize,
        phnum: f.e_phnum.into(),
        shnum: f.e_shnum.into(),
        shstrndx: None, // resolved later
        raw_phnum: f.e_phnum,
        raw_shnum: f.e_shnum,
        raw_shstrndx: f.e_shstrndx,
    }
}

/// Errors produced while resolving the extended-numbering escapes. They are
/// not fatal for `parse`: each one is reported by the accessor of the table
/// whose size could not be determined.
struct EscapeErrors {
    program_headers: Option<Error>,
    section_headers: Option<Error>,
}

/// Read section header 0, which holds the real values behind the escapes.
pub(crate) fn read_section0(data: &[u8], h: &Header) -> Result<SectionHeader> {
    if h.shoff == 0 {
        // gABI ch4 "ELF Header", e_shoff: "If the file has no section header
        // table, this member holds zero." Then there is no section 0 either.
        return Err(Error::BadIndex {
            what: "section header 0 (no section header table)",
            index: 0,
            len: 0,
        });
    }
    let size = LayoutTable::<ShdrKind>::entry_size(h.class);
    let oob = || Error::OutOfBounds {
        what: "section header 0",
        offset: h.shoff,
        size: size as u64,
        file_len: file_len(data),
    };
    let bytes = tail(data, h.shoff).ok_or_else(oob)?;
    LayoutTable::<ShdrKind>::new(h.class, h.endian, bytes, size, 1)
        .and_then(|t| t.get(0))
        .ok_or_else(oob)
}

/// Apply the gABI escape hatches for counts that do not fit in 16 bits.
///
/// - `e_shnum == 0` while `e_shoff != 0`: the count is in section 0's `sh_size`.
/// - `e_phnum == PN_XNUM`: the count is in section 0's `sh_info`.
/// - `e_shstrndx == SHN_XINDEX`: the index is in section 0's `sh_link`.
///
/// Source: gABI ch4 "ELF Header" and "Sections", table "Section Header Table
/// Entry: Index 0". <https://www.sco.com/developers/gabi/latest/ch4.sheader.html>
///
/// The escape values are not counts themselves ("This value is an escape
/// value", gABI ch4 "Special Section Indexes"), so when section 0 cannot be
/// read the affected value is unknown: the count is set to 0, `shstrndx` to
/// `None`, and the reason is returned so the table accessor can report it.
/// `parse` itself does not fail.
///
/// Note that the Linux kernel does not implement `PN_XNUM` when loading
/// (`load_elf_phdrs` uses `e_phnum` literally; LOADER_RULES.md §1); this is
/// the gABI reading, which tools such as readelf also apply.
fn resolve_extended_numbering(data: &[u8], h: &mut Header) -> EscapeErrors {
    let mut errors = EscapeErrors {
        program_headers: None,
        section_headers: None,
    };
    let needs_sh0 = (h.raw_shnum == 0 && h.shoff != 0)
        || h.raw_phnum == PN_XNUM
        || h.raw_shstrndx == SHN_XINDEX;
    let sh0 = if needs_sh0 {
        Some(read_section0(data, h))
    } else {
        None
    };

    if h.shoff == 0 {
        // No section header table. gABI e_shoff vs e_shnum disagree when
        // e_shoff == 0 but e_shnum != 0; offset 0 holds the ELF header, so
        // no table can live there and the file is treated as having none
        // (the audit reports the stray count).
        h.shnum = 0;
    } else if h.raw_shnum == 0 {
        match &sh0 {
            Some(Ok(s)) => h.shnum = s.size,
            Some(Err(e)) => {
                h.shnum = 0;
                errors.section_headers = Some(e.clone());
            }
            None => {}
        }
    }

    if h.raw_phnum == PN_XNUM {
        match &sh0 {
            Some(Ok(s)) => h.phnum = s.info.into(),
            Some(Err(e)) => {
                h.phnum = 0;
                errors.program_headers = Some(e.clone());
            }
            None => {}
        }
    }

    h.shstrndx = if h.raw_shstrndx == SHN_XINDEX {
        match &sh0 {
            Some(Ok(s)) => Some(s.link),
            _ => None,
        }
    } else {
        match h.raw_shstrndx {
            SHN_UNDEF => None,
            // gABI ch4 "ELF Header", e_shstrndx: "If the section name string
            // table section index is greater than or equal to SHN_LORESERVE
            // (0xff00), this member has the value SHN_XINDEX (0xffff)". A raw
            // value in 0xff00..=0xfffe breaks that rule, but it is still the
            // only index the file gives; it is kept and the audit reports it.
            n => Some(n.into()),
        }
    };
    if h.shstrndx == Some(0) {
        h.shstrndx = None;
    }
    errors
}

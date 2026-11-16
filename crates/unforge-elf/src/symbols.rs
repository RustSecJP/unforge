//! Symbol tables as lazy views.

use zerocopy::FromBytes;
use zerocopy::byteorder::{BigEndian, LittleEndian, U32};

use crate::consts::*;
use crate::parse::{BoundedName, cstr_at, cstr_at_bounded};
use crate::table::{LayoutIter, LayoutTable, SymKind};
use crate::{ElfFile, Endian, Error, Result, SectionHeader, Symbol, SymbolSection};

/// One symbol table (`SHT_SYMTAB` / `SHT_DYNSYM`) together with its string
/// table, as a view of the input. Creating it does not read any symbol.
#[derive(Debug, Clone, Copy)]
pub struct SymbolTable<'data> {
    /// Index of the `SHT_SYMTAB` / `SHT_DYNSYM` section this came from.
    pub section_index: usize,
    header: SectionHeader,
    symbols: LayoutTable<'data, SymKind>,
    declared: u64,
    trailing_bytes: u64,
    stride_inferred: bool,
    strtab: Option<&'data [u8]>,
    strtab_index: Option<u32>,
    xindex: Option<&'data [u8]>,
    endian: Endian,
}

impl<'data> SymbolTable<'data> {
    /// Number of symbols that can be read (those inside the file).
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// `sh_size / stride`: the number of symbols the section declares. More
    /// than [`SymbolTable::len`] when the section runs past the end of the file.
    pub fn declared_len(&self) -> u64 {
        self.declared
    }

    /// Symbol `index`, with `SHN_XINDEX` resolved.
    pub fn get(&self, index: usize) -> Option<Symbol> {
        self.symbols.get(index).map(|s| self.resolve(index, s))
    }

    pub fn iter(&self) -> SymbolIter<'data> {
        SymbolIter {
            inner: self.symbols.iter(),
            index: 0,
            xindex: self.xindex,
            endian: self.endian,
        }
    }

    /// The raw (unresolved) symbol view.
    pub fn raw(&self) -> LayoutTable<'data, SymKind> {
        self.symbols
    }

    /// The section header of the table.
    pub fn section_header(&self) -> &SectionHeader {
        &self.header
    }

    /// Distance between entries: `sh_entsize`, or `sizeof(Sym)` when
    /// `sh_entsize` is smaller than the structure (see
    /// [`SymbolTable::entry_size_inferred`]).
    pub fn entry_size(&self) -> usize {
        self.symbols.stride()
    }

    /// `sh_entsize` was 0 or smaller than `sizeof(Sym)` and was replaced by
    /// `sizeof(Sym)`.
    pub fn entry_size_inferred(&self) -> bool {
        self.stride_inferred
    }

    /// The string table bytes, when `sh_link` names a section. Its type is
    /// not checked here (the audit reports a non-`SHT_STRTAB` one).
    pub fn strtab(&self) -> Option<&'data [u8]> {
        self.strtab
    }

    /// `sh_link`, when it names a section.
    pub fn strtab_index(&self) -> Option<u32> {
        self.strtab_index
    }

    /// The raw bytes of a symbol's name (not necessarily UTF-8; Rust symbols are
    /// mangled ASCII, but the format does not guarantee it).
    ///
    /// Cost: O(length of the name), which the file controls: many symbols
    /// may share one string of any length (gABI ch4 "String Table"), so
    /// calling this for every symbol can cost O(symbols * string length).
    /// Use [`SymbolTable::name_bounded`] when walking a whole table.
    pub fn name(&self, sym: &Symbol) -> Result<&'data [u8]> {
        cstr_at(self.strtab.ok_or(NO_STRTAB)?, sym.name)
    }

    /// Like [`SymbolTable::name`], but reads at most `max` bytes of the name,
    /// so the cost does not depend on the string table's contents.
    pub fn name_bounded(&self, sym: &Symbol, max: usize) -> Result<BoundedName<'data>> {
        cstr_at_bounded(self.strtab.ok_or(NO_STRTAB)?, sym.name, max)
    }

    /// `sh_size % stride`: bytes at the end of the section that do not form
    /// a whole entry and were ignored. 0 for a well-formed table.
    pub fn trailing_bytes(&self) -> u64 {
        self.trailing_bytes
    }

    /// How many symbols are [`SymbolSection::Unresolved`]. O(len).
    pub fn unresolved_count(&self) -> usize {
        self.iter()
            .filter(|s| s.section == SymbolSection::Unresolved)
            .count()
    }

    fn resolve(&self, index: usize, s: Symbol) -> Symbol {
        resolve(self.xindex, self.endian, index, s)
    }
}

const NO_STRTAB: Error = Error::Missing {
    what: "symbol table string table (sh_link names no section)",
};

/// `SHN_XINDEX`: the real index lives in the `SHT_SYMTAB_SHNDX` section
/// whose `sh_link` points back at the table (gABI ch4 "Symbol Table"). Every
/// way of failing to read it (no such section, too few entries, entry 0)
/// leaves the symbol `Unresolved`.
fn resolve(xindex: Option<&[u8]>, endian: Endian, index: usize, mut s: Symbol) -> Symbol {
    if s.raw_shndx == SHN_XINDEX {
        s.section = match xindex.and_then(|t| u32_at(t, endian, index)) {
            Some(0) | None => SymbolSection::Unresolved,
            Some(real) => SymbolSection::Index(real),
        };
    }
    s
}

fn u32_at(table: &[u8], endian: Endian, i: usize) -> Option<u32> {
    let bytes = table.get(i.checked_mul(4)?..)?;
    Some(match endian {
        Endian::Big => U32::<BigEndian>::read_from_prefix(bytes).ok()?.0.get(),
        _ => U32::<LittleEndian>::read_from_prefix(bytes).ok()?.0.get(),
    })
}

/// Iterator over the symbols of a [`SymbolTable`], `SHN_XINDEX` resolved.
#[derive(Debug, Clone)]
pub struct SymbolIter<'data> {
    inner: LayoutIter<'data, SymKind>,
    index: usize,
    xindex: Option<&'data [u8]>,
    endian: Endian,
}

impl Iterator for SymbolIter<'_> {
    type Item = Symbol;
    fn next(&mut self) -> Option<Symbol> {
        let s = self.inner.next()?;
        let i = self.index;
        self.index += 1;
        Some(resolve(self.xindex, self.endian, i, s))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for SymbolIter<'_> {}

impl<'data> IntoIterator for &SymbolTable<'data> {
    type Item = Symbol;
    type IntoIter = SymbolIter<'data>;
    fn into_iter(self) -> SymbolIter<'data> {
        self.iter()
    }
}

pub(crate) fn is_symtab(sh: &SectionHeader) -> bool {
    sh.sh_type == SHT_SYMTAB || sh.sh_type == SHT_DYNSYM
}

impl<'data> ElfFile<'data> {
    /// The symbol table stored in section `index`, which must be
    /// `SHT_SYMTAB` or `SHT_DYNSYM`.
    ///
    /// Tolerant: the table is read as far as the file allows.
    /// - The count is `sh_size / stride`, clipped to the entries inside the
    ///   file. A remainder is not an error (the gABI describes the section as
    ///   "a table of fixed-size entries" but does not state that `sh_size`
    ///   must be a multiple); [`SymbolTable::trailing_bytes`] reports it.
    /// - The stride is `sh_entsize`, or `sizeof(Sym)` when `sh_entsize` is
    ///   smaller than that (including 0); the audit records that inference.
    /// - The string table is the section `sh_link` names, whatever its type
    ///   (gABI ch4 Figure 4-14 says it is "the section header index of the
    ///   associated string table"; the audit reports a non-`SHT_STRTAB` one).
    ///   When `sh_link` names no section, names are unavailable and
    ///   [`SymbolTable::name`] fails for every symbol.
    ///
    /// Errors: `index` is not a section, or the section is not a symbol table.
    ///
    /// Cost: O(e_shnum) to find a `SHT_SYMTAB_SHNDX` section for this table;
    /// no allocation. Use [`ElfFile::symbol_tables`] to walk all tables.
    pub fn symbol_table(&self, index: usize) -> Result<SymbolTable<'data>> {
        let sh = self.section_header(index)?;
        let xindex = self.find_extended_index_table(index);
        self.symbol_table_with(index, sh, xindex)
    }

    fn symbol_table_with(
        &self,
        index: usize,
        sh: SectionHeader,
        xindex: Option<&'data [u8]>,
    ) -> Result<SymbolTable<'data>> {
        if !is_symtab(&sh) {
            return Err(Error::WrongSectionType {
                what: "symbol table",
                sh_type: sh.sh_type,
            });
        }
        let (class, endian) = (self.header.class, self.header.endian);
        let size = LayoutTable::<SymKind>::entry_size(class) as u64;
        let stride_inferred = sh.entsize < size;
        let stride = sh.entsize.max(size);
        let declared = sh.size / stride;
        let trailing_bytes = sh.size % stride;
        let bytes = self.section_bytes(&sh).bytes;
        let symbols = usize::try_from(stride)
            .ok()
            .and_then(|s| LayoutTable::new(class, endian, bytes, s, declared))
            .unwrap_or_else(|| LayoutTable::empty(class, endian));

        // sh_link of a symbol table is the index of its string table. Index 0
        // is SHN_UNDEF / the SHT_NULL entry, whose fields may hold the
        // extended numbering values instead of a data range.
        let (strtab, strtab_index) = match sh.link {
            0 => (None, None),
            link => match self.section_header(link as usize) {
                Ok(s) => (Some(self.section_bytes(&s).bytes), Some(link)),
                Err(_) => (None, None),
            },
        };
        Ok(SymbolTable {
            section_index: index,
            header: sh,
            symbols,
            declared,
            trailing_bytes,
            stride_inferred,
            strtab,
            strtab_index,
            xindex,
            endian,
        })
    }

    /// The data of the first `SHT_SYMTAB_SHNDX` section whose `sh_link` is
    /// `symtab_index`.
    fn find_extended_index_table(&self, symtab_index: usize) -> Option<&'data [u8]> {
        let sh = self
            .section_headers()
            .ok()?
            .iter()
            .find(|sh| sh.sh_type == SHT_SYMTAB_SHNDX && sh.link as usize == symtab_index)?;
        Some(self.section_bytes(&sh).bytes)
    }

    /// Every `SHT_SYMTAB` and `SHT_DYNSYM` table, in section order, as a lazy
    /// iterator of views.
    ///
    /// Time: O(number of sections) for the whole walk, plus O(log k) per
    /// table when there are k > 1 `SHT_SYMTAB_SHNDX` sections.
    ///
    /// Memory: O(1) beyond the input (O(k) when there are k > 1
    /// `SHT_SYMTAB_SHNDX` sections), whatever the tables contain, including
    /// many section headers that describe the same bytes (gABI ch4
    /// "Sections": "Sections in a file may not overlap", but nothing stops a
    /// file from declaring that; the audit reports it). Fails only when the
    /// section header table itself is unreadable.
    pub fn symbol_tables(&self) -> Result<SymbolTables<'_, 'data>> {
        let sections = self.section_headers()?;
        Ok(SymbolTables {
            file: self,
            next: 0,
            len: sections.len(),
            xindex: XIndexState::Unknown,
        })
    }
}

/// How the `SHT_SYMTAB_SHNDX` sections of the file are found, decided once
/// per [`SymbolTables`] walk.
#[derive(Debug, Clone)]
enum XIndexState {
    /// Not scanned yet.
    Unknown,
    /// The file has none.
    None,
    /// Exactly one, linked to this section.
    One { link: u32, index: usize },
    /// Several: `(sh_link, section index)`, sorted, so that each table finds
    /// its own (the first in section order) by binary search.
    Many(Vec<(u32, usize)>),
}

/// Iterator over the symbol tables of a file (see [`ElfFile::symbol_tables`]).
#[derive(Debug, Clone)]
pub struct SymbolTables<'f, 'data> {
    file: &'f ElfFile<'data>,
    next: usize,
    len: usize,
    xindex: XIndexState,
}

impl<'data> SymbolTables<'_, 'data> {
    fn xindex_for(&mut self, table: usize) -> Option<&'data [u8]> {
        if let XIndexState::Unknown = self.xindex {
            let mut state = XIndexState::None;
            if let Ok(sections) = self.file.section_headers() {
                for (i, sh) in sections.iter().enumerate() {
                    if sh.sh_type != SHT_SYMTAB_SHNDX {
                        continue;
                    }
                    state = match state {
                        XIndexState::None => XIndexState::One {
                            link: sh.link,
                            index: i,
                        },
                        XIndexState::One { link, index } => {
                            XIndexState::Many(vec![(link, index), (sh.link, i)])
                        }
                        XIndexState::Many(mut v) => {
                            v.push((sh.link, i));
                            XIndexState::Many(v)
                        }
                        XIndexState::Unknown => XIndexState::Unknown,
                    };
                }
            }
            if let XIndexState::Many(v) = &mut state {
                v.sort_unstable();
            }
            self.xindex = state;
        }
        let index = match &self.xindex {
            XIndexState::One { link, index } if *link as usize == table => *index,
            XIndexState::Many(v) => {
                let at = v.partition_point(|&(l, _)| (l as usize) < table);
                match v.get(at) {
                    Some(&(l, i)) if l as usize == table => i,
                    _ => return None,
                }
            }
            _ => return None,
        };
        let sh = self.file.section_header(index).ok()?;
        Some(self.file.section_bytes(&sh).bytes)
    }
}

impl<'data> Iterator for SymbolTables<'_, 'data> {
    type Item = SymbolTable<'data>;
    fn next(&mut self) -> Option<SymbolTable<'data>> {
        let sections = self.file.section_headers().ok()?;
        while self.next < self.len {
            let i = self.next;
            self.next += 1;
            let Some(sh) = sections.get(i) else {
                continue;
            };
            if !is_symtab(&sh) {
                continue;
            }
            let xindex = self.xindex_for(i);
            if let Ok(t) = self.file.symbol_table_with(i, sh, xindex) {
                return Some(t);
            }
        }
        None
    }
}

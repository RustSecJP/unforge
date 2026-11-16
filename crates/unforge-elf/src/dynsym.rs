//! The dynamic symbol table as the dynamic loader finds it: through
//! `PT_DYNAMIC` (`DT_SYMTAB`, `DT_STRTAB`, `DT_HASH` / `DT_GNU_HASH`), never
//! through section headers.
//!
//! glibc (elf/get-dynamic-info.h, elf/dl-setup_hash.c, glibc 2.44) and musl
//! (ldso/dynlink.c `decode_dyn`, musl 1.2.6) take the symbol table from
//! `DT_SYMTAB` and the string table from `DT_STRTAB` in memory, and step
//! through it in units of `sizeof(Sym)`: neither reads `DT_SYMENT` (grep of
//! those files). When a tag appears more than once, the last one wins in both
//! (`info[tag] = dyn` / `a[v[0]] = v[1]`).
//!
//! The table's length is not stored anywhere the loader reads. This view
//! takes it from:
//! 1. `DT_HASH` `nchain`: gABI ch5 "Hash Table": "the number of symbol table
//!    entries should equal nchain";
//! 2. otherwise `DT_GNU_HASH` (GNU extension, no gABI text): one past the
//!    highest symbol index reachable from a bucket, found by walking the
//!    chains to their end marker (bit 0 set), or `symoffset` when every
//!    bucket is empty. Symbols after the last hashed one are not counted;
//!    this is the usual reading of that table, not a rule of any loader;
//! 3. otherwise nothing: the count is 0 ([`DynamicSymbolCount::Unknown`]).
//!
//! The audit compares this view with `SHT_DYNSYM` and records an inference
//! when the count is not given by `DT_HASH` and no section header confirms it.

use zerocopy::FromBytes;
use zerocopy::byteorder::{BigEndian, LittleEndian, U32, U64};

use crate::consts::*;
use crate::memmap::{DynamicTable, MemoryMap};
use crate::parse::{BoundedName, cstr_at_bounded};
use crate::table::{LayoutIter, LayoutTable, SymKind};
use crate::{Class, ElfFile, Endian, Error, Result, Symbol};

/// Where [`DynamicSymbols::len`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DynamicSymbolCount {
    /// `nchain` of the `DT_HASH` table.
    Hash { nchain: u64 },
    /// Walking the `DT_GNU_HASH` chains.
    GnuHash { count: u64 },
    /// Neither hash table could be read; no symbols are listed.
    Unknown,
}

impl DynamicSymbolCount {
    pub fn count(&self) -> u64 {
        match *self {
            DynamicSymbolCount::Hash { nchain } => nchain,
            DynamicSymbolCount::GnuHash { count } => count,
            DynamicSymbolCount::Unknown => 0,
        }
    }
}

/// The dynamic symbol table found through `PT_DYNAMIC`. A view; no copy.
#[derive(Debug, Clone, Copy)]
pub struct DynamicSymbols<'data> {
    symbols: LayoutTable<'data, SymKind>,
    /// `DT_SYMTAB` (an address, unbiased).
    pub symtab_vaddr: u64,
    /// File offset `DT_SYMTAB` is mapped from.
    pub file_offset: u64,
    /// `DT_STRTAB`, when present.
    pub strtab_vaddr: Option<u64>,
    /// `DT_STRSZ`, when present.
    pub strtab_size: Option<u64>,
    /// `DT_SYMENT`, when present (not used: loaders step by `sizeof(Sym)`).
    pub syment: Option<u64>,
    /// How the count was found.
    pub count: DynamicSymbolCount,
    strtab: Option<&'data [u8]>,
}

impl<'data> DynamicSymbols<'data> {
    /// Symbols readable from the file (at most the count, clipped to the file
    /// bytes mapped contiguously at `DT_SYMTAB`).
    pub fn len(&self) -> usize {
        self.symbols.len()
    }
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
    /// Symbol `i`. `SHN_XINDEX` is not resolved: the loaders have no
    /// extended index table for dynamic symbols.
    pub fn get(&self, i: usize) -> Option<Symbol> {
        self.symbols.get(i)
    }
    pub fn iter(&self) -> LayoutIter<'data, SymKind> {
        self.symbols.iter()
    }
    /// The string table bytes (`DT_STRTAB`, at most `DT_STRSZ` bytes).
    pub fn strtab(&self) -> Option<&'data [u8]> {
        self.strtab
    }
    /// A symbol's name, at most `max` bytes.
    pub fn name_bounded(&self, sym: &Symbol, max: usize) -> Result<BoundedName<'data>> {
        let t = self.strtab.ok_or(Error::Missing {
            what: "DT_STRTAB (not present or not file-backed)",
        })?;
        cstr_at_bounded(t, sym.name, max)
    }
}

/// The value of the last `tag` entry.
fn last(d: &DynamicTable<'_>, tag: i64) -> Option<u64> {
    d.iter().rfind(|e| e.tag == tag).map(|e| e.value)
}

fn word(bytes: &[u8], endian: Endian, index: u64, size: usize) -> Option<u64> {
    let at = usize::try_from(index).ok()?.checked_mul(size)?;
    let b = bytes.get(at..)?;
    Some(match (size, endian) {
        (8, Endian::Big) => U64::<BigEndian>::read_from_prefix(b).ok()?.0.get(),
        (8, _) => U64::<LittleEndian>::read_from_prefix(b).ok()?.0.get(),
        (_, Endian::Big) => U32::<BigEndian>::read_from_prefix(b).ok()?.0.get().into(),
        (_, _) => U32::<LittleEndian>::read_from_prefix(b)
            .ok()?
            .0
            .get()
            .into(),
    })
}

/// `nchain` of a `DT_HASH` table. Its words are 32-bit, except on 64-bit
/// s390 where binutils writes 64-bit entries (`Elf_Symndx`); that exception
/// is the toolchain's convention and was not checked in loader source here.
fn hash_nchain(bytes: &[u8], endian: Endian, class: Class, machine: u16) -> Option<u64> {
    let size = if class == Class::Elf64 && machine == EM_S390 {
        8
    } else {
        4
    };
    word(bytes, endian, 1, size)
}

/// The symbol count implied by a `DT_GNU_HASH` table (see the module
/// documentation). Work: O(buckets + chain length), both bounded by the
/// file bytes mapped at the table.
fn gnu_hash_count(bytes: &[u8], endian: Endian, class: Class) -> Option<u64> {
    let w = |i: u64| word(bytes, endian, i, 4);
    let nbuckets = w(0)?;
    let symoffset = w(1)?;
    let bloom = w(2)?;
    let bloom_words = match class {
        Class::Elf32 => bloom,
        Class::Elf64 => bloom.checked_mul(2)?,
    };
    let buckets_at = 4u64.checked_add(bloom_words)?;
    let chains_at = buckets_at.checked_add(nbuckets)?;
    // Every bucket word must be inside the mapped bytes.
    if nbuckets > 0 {
        w(chains_at - 1)?;
    }
    let mut max = None::<u64>;
    for b in 0..nbuckets {
        let s = w(buckets_at + b)?;
        if s >= symoffset {
            max = Some(max.map_or(s, |m: u64| m.max(s)));
        }
    }
    let Some(mut i) = max else {
        return Some(symoffset);
    };
    loop {
        let h = w(chains_at.checked_add(i - symoffset)?)?;
        if h & 1 != 0 {
            return i.checked_add(1);
        }
        i = i.checked_add(1)?;
    }
}

impl<'data> ElfFile<'data> {
    /// The dynamic symbol table as `ld.so` finds it (see the module
    /// documentation of `dynsym`). Works without section headers.
    ///
    /// Errors: no `PT_DYNAMIC`, no `DT_SYMTAB`, or `DT_SYMTAB` not backed by
    /// file bytes.
    pub fn dynamic_symbols(&self) -> Result<DynamicSymbols<'data>> {
        let map = self.memory_map();
        let d = self.dynamic_with(&map)?;
        self.dynamic_symbols_with(&map, &d)
    }

    /// [`ElfFile::dynamic_symbols`] with an existing memory map and dynamic
    /// table of this file.
    pub fn dynamic_symbols_with(
        &self,
        map: &MemoryMap,
        d: &DynamicTable<'data>,
    ) -> Result<DynamicSymbols<'data>> {
        let (class, endian) = (self.header.class, self.header.endian);
        let symtab_vaddr = last(d, DT_SYMTAB).ok_or(Error::Missing { what: "DT_SYMTAB" })?;
        let (file_offset, _) = map.file_extent(symtab_vaddr).ok_or(Error::Missing {
            what: "DT_SYMTAB (not backed by file bytes)",
        })?;
        let bytes = map.bytes_at(self.data, symtab_vaddr).unwrap_or(&[]);
        let count = if let Some(n) = last(d, DT_HASH)
            .and_then(|a| map.bytes_at(self.data, a))
            .and_then(|b| hash_nchain(b, endian, class, self.header.machine))
        {
            DynamicSymbolCount::Hash { nchain: n }
        } else if let Some(n) = last(d, DT_GNU_HASH)
            .and_then(|a| map.bytes_at(self.data, a))
            .and_then(|b| gnu_hash_count(b, endian, class))
        {
            DynamicSymbolCount::GnuHash { count: n }
        } else {
            DynamicSymbolCount::Unknown
        };
        let size = LayoutTable::<SymKind>::entry_size(class);
        let symbols = LayoutTable::new(class, endian, bytes, size, count.count())
            .unwrap_or_else(|| LayoutTable::empty(class, endian));
        let strtab_vaddr = last(d, DT_STRTAB);
        let strtab_size = last(d, DT_STRSZ);
        let strtab =
            strtab_vaddr
                .and_then(|a| map.bytes_at(self.data, a))
                .map(
                    |b| match strtab_size.and_then(|n| usize::try_from(n).ok()) {
                        Some(n) => b.get(..n).unwrap_or(b),
                        None => b,
                    },
                );
        Ok(DynamicSymbols {
            symbols,
            symtab_vaddr,
            file_offset,
            strtab_vaddr,
            strtab_size,
            syment: last(d, DT_SYMENT),
            count,
            strtab,
        })
    }
}

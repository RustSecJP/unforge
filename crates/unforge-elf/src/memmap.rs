//! The address space as the kernel builds it, and the dynamic table as the
//! dynamic loader finds it.

use crate::consts::*;
use crate::parse::{file_len, tail};
use crate::table::{DynKind, LayoutIter, LayoutTable};
use crate::{DynamicEntry, ElfFile, Error, ProgramHeader, Result};

/// Above this many `PT_LOAD`s the memory map uses only the first ones (the
/// audit reports it). The kernel refuses more than 65536 bytes of program
/// headers, i.e. 1170 ELF64 / 2048 ELF32 entries (`load_elf_phdrs`, Linux
/// v7.0.12), so no loadable file reaches this.
pub const MAX_MAPPED_LOADS: usize = 4096;

/// At most this many replaced segments are remembered per address (the most
/// recent ones), so that thousands of identical `PT_LOAD`s stay linear.
pub const MAX_OVERRIDES: usize = 64;

/// The page size [`ElfFile::memory_map`] assumes: 4 KiB.
///
/// The kernel maps in units of `ELF_MIN_ALIGN` = max(`ELF_EXEC_PAGESIZE`,
/// `PAGE_SIZE`) (fs/binfmt_elf.c lines 82-94, Linux v7.0.12), which depends
/// on the host: 4096 on x86-64; 4 KiB, 16 KiB or 64 KiB on arm64 depending on
/// the kernel configuration (LOADER_RULES.md "Sources"). Other machines were
/// not checked. Use [`ElfFile::memory_map_with_page_size`] for another host.
pub const DEFAULT_PAGE_SIZE: u64 = 4096;

/// What one interval of the map holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fill {
    /// File bytes: address `vaddr` holds the byte at file offset
    /// `anchor_offset + (vaddr - anchor_vaddr)`. `anchor_offset` is `None`
    /// when `p_offset - PAGEOFFSET(p_vaddr)` underflows.
    File {
        anchor_vaddr: u64,
        anchor_offset: Option<u64>,
    },
    /// Anonymous zero memory (`p_filesz..p_memsz`, rounded to pages).
    Zero,
}

/// One interval of the map.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Piece {
    start: u64,
    /// Exclusive; saturates at `u64::MAX`.
    end: u64,
    segment: usize,
    ph: ProgramHeader,
    fill: Fill,
    overrides: Vec<usize>,
}

/// The address space as the kernel builds it: `PT_LOAD`s applied in table
/// order, each later one replacing earlier ones where they overlap (the
/// kernel maps every `PT_LOAD` after the first with `MAP_FIXED`;
/// fs/binfmt_elf.c `load_elf_binary`, Linux v7.0.12 lines 1065-1066).
///
/// The map is page-granular, as the kernel's is (fs/binfmt_elf.c `elf_map`
/// lines 371-411, `elf_load` lines 415-458, `padzero` lines 127-138, and
/// mm/mmap.c `vm_brk_flags`, which unmaps what was there before; Linux
/// v7.0.12). For a `PT_LOAD` with page size `P`:
/// - when `p_filesz > 0`, the pages `[PAGESTART(p_vaddr),
///   PAGEALIGN(p_vaddr + p_filesz))` map the file from offset
///   `p_offset - PAGEOFFSET(p_vaddr)`, so the bytes of the first and last
///   page outside `[p_vaddr, p_vaddr + p_filesz)` ("page slack") are file
///   bytes too;
/// - when `p_memsz > p_filesz`, the rest of the last file page is cleared by
///   `padzero` for a writable segment (for a read-only one `clear_user`
///   fails and the kernel ignores the error, so the file bytes stay; read
///   from source, not observed), and the pages up to
///   `PAGEALIGN(p_vaddr + p_memsz)` are anonymous zero memory;
/// - when `p_filesz == 0`, `[PAGESTART(p_vaddr), PAGEALIGN(p_vaddr +
///   p_memsz))` is zero memory;
/// - a later segment replaces whole pages of earlier ones.
///
/// A `PT_LOAD` with `p_filesz > p_memsz` (fatal for the kernel; the audit
/// reports it) is mapped with only `p_memsz` file bytes. The page size is
/// host-dependent ([`DEFAULT_PAGE_SIZE`]); a page size of 1 gives the
/// byte-granular reading of the program headers. Not modelled: the load bias
/// of `ET_DYN` files (addresses are the file's own `p_vaddr`s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryMap {
    pieces: Vec<Piece>,
    file_len: u64,
    total_loads: usize,
    page_size: u64,
}

impl Default for MemoryMap {
    fn default() -> Self {
        MemoryMap {
            pieces: Vec::new(),
            file_len: 0,
            total_loads: 0,
            page_size: DEFAULT_PAGE_SIZE,
        }
    }
}

/// What backs one address of a [`MemoryMap`] (owned copy of [`BackingRef`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backing {
    /// Index (in the program header table) of the `PT_LOAD` that wins here.
    pub segment: usize,
    /// Earlier `PT_LOAD`s that also covered this address and were replaced,
    /// oldest first (at most the [`MAX_OVERRIDES`] most recent).
    pub overrides: Vec<usize>,
    /// File offset of the byte, or `None` for zero-fill and for bytes past
    /// the end of the file.
    pub file_offset: Option<u64>,
    /// `p_flags` of the winning segment.
    pub flags: u32,
    /// The address is inside the winning segment's `[p_vaddr, p_vaddr +
    /// p_memsz)`. `false`: it is mapped only because the kernel maps whole
    /// pages (page slack), which depends on the page size.
    pub in_segment: bool,
}

/// What backs one address, borrowing from the map (no allocation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackingRef<'m> {
    pub segment: usize,
    pub overrides: &'m [usize],
    pub file_offset: Option<u64>,
    pub flags: u32,
    pub in_segment: bool,
}

impl BackingRef<'_> {
    pub fn to_owned(&self) -> Backing {
        Backing {
            segment: self.segment,
            overrides: self.overrides.to_vec(),
            file_offset: self.file_offset,
            flags: self.flags,
            in_segment: self.in_segment,
        }
    }
}

/// One interval of a [`MemoryMap`], as listed by [`MemoryMap::regions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub start: u64,
    /// Exclusive.
    pub end: u64,
    /// The `PT_LOAD` (program header index) that maps it.
    pub segment: usize,
    /// `p_flags` of that segment.
    pub flags: u32,
    /// File offset of `start`, or `None` for zero-fill (or past the end of
    /// the file).
    pub file_offset: Option<u64>,
}

fn page_start(v: u64, page: u64) -> u64 {
    v & !(page - 1)
}

fn page_align(v: u64, page: u64) -> u64 {
    v.checked_add(page - 1)
        .map_or(u64::MAX, |x| x & !(page - 1))
}

impl MemoryMap {
    pub(crate) fn build(
        phdrs: impl Iterator<Item = ProgramHeader>,
        file_len: u64,
        page_size: u64,
    ) -> Self {
        let page = if page_size.is_power_of_two() {
            page_size
        } else {
            DEFAULT_PAGE_SIZE
        };
        let mut map = MemoryMap {
            pieces: Vec::new(),
            file_len,
            total_loads: 0,
            page_size: page,
        };
        for (i, ph) in phdrs.enumerate() {
            if ph.p_type != PT_LOAD {
                continue;
            }
            map.total_loads += 1;
            if map.total_loads > MAX_MAPPED_LOADS || ph.memsz == 0 {
                continue;
            }
            map.load(i, ph);
        }
        map
    }

    /// Apply one `PT_LOAD` as `elf_load` does.
    fn load(&mut self, segment: usize, ph: ProgramHeader) {
        let page = self.page_size;
        let v = ph.vaddr;
        let filesz = ph.filesz.min(ph.memsz);
        let ps = page_start(v, page);
        let mem_end = page_align(v.saturating_add(ph.memsz), page);
        if filesz > 0 {
            let file_end = v.saturating_add(filesz);
            let file_pages_end = page_align(file_end, page);
            let fill = Fill::File {
                anchor_vaddr: ps,
                anchor_offset: ph.offset.checked_sub(v - ps),
            };
            self.insert(segment, ph, ps, file_pages_end, fill);
            if ph.memsz > filesz {
                if ph.flags & PF_W != 0 {
                    self.insert(segment, ph, file_end, file_pages_end, Fill::Zero);
                }
                self.insert(segment, ph, file_pages_end, mem_end, Fill::Zero);
            }
        } else {
            self.insert(segment, ph, ps, mem_end, Fill::Zero);
        }
    }

    /// Replace `[start, end)` by `fill` of `segment`.
    fn insert(&mut self, segment: usize, ph: ProgramHeader, start: u64, end: u64, fill: Fill) {
        if start >= end {
            return;
        }
        // `pieces` is sorted and non-overlapping, so the pieces the new
        // interval touches are one contiguous run `lo..hi`.
        let lo = self.pieces.partition_point(|p| p.end <= start);
        let hi = self.pieces.partition_point(|p| p.start < end).max(lo);
        let new = |s: u64, e: u64, overrides: Vec<usize>| Piece {
            start: s,
            end: e,
            segment,
            ph,
            fill,
            overrides,
        };
        let mut replacement = Vec::with_capacity(hi - lo + 2);
        let mut at = start;
        for p in self.pieces.get(lo..hi).unwrap_or(&[]) {
            if p.start < start {
                replacement.push(Piece {
                    end: start,
                    ..p.clone()
                });
            }
            let (s, e) = (p.start.max(start), p.end.min(end));
            if at < s {
                replacement.push(new(at, s, Vec::new()));
            }
            let mut ov = p.overrides.clone();
            if p.segment != segment {
                if ov.len() >= MAX_OVERRIDES {
                    ov.remove(0);
                }
                ov.push(p.segment);
            }
            replacement.push(new(s, e, ov));
            at = e;
            if p.end > end {
                if at < end {
                    replacement.push(new(at, end, Vec::new()));
                    at = end;
                }
                replacement.push(Piece {
                    start: end,
                    ..p.clone()
                });
            }
        }
        if at < end {
            replacement.push(new(at, end, Vec::new()));
        }
        self.pieces.splice(lo..hi, replacement);
    }

    fn piece(&self, vaddr: u64) -> Option<&Piece> {
        let i = self.pieces.partition_point(|p| p.start <= vaddr);
        let p = self.pieces.get(i.checked_sub(1)?)?;
        (vaddr < p.end).then_some(p)
    }

    /// The page size the map was built for.
    pub fn page_size(&self) -> u64 {
        self.page_size
    }

    /// What backs `vaddr`, if any `PT_LOAD` maps it. Copies the override
    /// list; [`MemoryMap::backing_ref`] borrows it instead.
    pub fn backing(&self, vaddr: u64) -> Option<Backing> {
        self.backing_ref(vaddr).map(|b| b.to_owned())
    }

    /// What backs `vaddr`, without allocating.
    pub fn backing_ref(&self, vaddr: u64) -> Option<BackingRef<'_>> {
        let p = self.piece(vaddr)?;
        Some(BackingRef {
            segment: p.segment,
            overrides: &p.overrides,
            file_offset: self.offset_in(p, vaddr),
            flags: p.ph.flags,
            in_segment: p.ph.vaddr <= vaddr && vaddr - p.ph.vaddr < p.ph.memsz,
        })
    }

    /// Shorthand for `backing(vaddr)?.file_offset`.
    pub fn file_offset(&self, vaddr: u64) -> Option<u64> {
        let p = self.piece(vaddr)?;
        self.offset_in(p, vaddr)
    }

    /// File bytes that back `[vaddr, ..)` contiguously, as `(file offset,
    /// length)`: from the file offset of `vaddr` up to the end of its
    /// interval of the map or the end of the file. When `vaddr` is inside its
    /// segment's declared range, the extent also stops at the end of the
    /// segment's declared file bytes (`p_offset + p_filesz`): what follows
    /// in the same page is there only because of the page size.
    pub fn file_extent(&self, vaddr: u64) -> Option<(u64, u64)> {
        let p = self.piece(vaddr)?;
        let off = self.offset_in(p, vaddr)?;
        let mut end = off.saturating_add(p.end - vaddr).min(self.file_len);
        let in_segment = p.ph.vaddr <= vaddr && vaddr - p.ph.vaddr < p.ph.memsz;
        if in_segment {
            let seg_end = p.ph.offset.saturating_add(p.ph.filesz.min(p.ph.memsz));
            end = end.min(seg_end);
        }
        Some((off, end.saturating_sub(off)))
    }

    /// The file bytes mapped contiguously from `vaddr` on (see
    /// [`MemoryMap::file_extent`]), borrowed from `data`, the file the map
    /// was built from. `None` when `vaddr` is unmapped or zero-fill.
    pub fn bytes_at<'data>(&self, data: &'data [u8], vaddr: u64) -> Option<&'data [u8]> {
        let (off, n) = self.file_extent(vaddr)?;
        let s = usize::try_from(off).ok()?;
        let e = s.checked_add(usize::try_from(n).ok()?)?;
        data.get(s..e)
    }

    fn offset_in(&self, p: &Piece, vaddr: u64) -> Option<u64> {
        match p.fill {
            Fill::Zero => None,
            Fill::File {
                anchor_vaddr,
                anchor_offset,
            } => {
                let off = anchor_offset?.checked_add(vaddr.checked_sub(anchor_vaddr)?)?;
                (off < self.file_len).then_some(off)
            }
        }
    }

    /// The intervals of the map in address order: `(start, end exclusive,
    /// winning segment)`.
    pub fn iter(&self) -> impl Iterator<Item = (u64, u64, usize)> + '_ {
        self.pieces.iter().map(|p| (p.start, p.end, p.segment))
    }

    /// The intervals of the map in address order, with flags and file
    /// offsets (e.g. to list the executable ranges). No allocation.
    pub fn regions(&self) -> impl Iterator<Item = Region> + '_ {
        self.pieces.iter().map(|p| Region {
            start: p.start,
            end: p.end,
            segment: p.segment,
            flags: p.ph.flags,
            file_offset: self.offset_in(p, p.start),
        })
    }

    /// Intervals where a later `PT_LOAD` replaced an earlier one:
    /// `(start, end exclusive, winning segment, most recently replaced segment)`.
    pub fn overrides(&self) -> impl Iterator<Item = (u64, u64, usize, usize)> + '_ {
        self.pieces
            .iter()
            .filter_map(|p| Some((p.start, p.end, p.segment, *p.overrides.last()?)))
    }

    /// Number of `PT_LOAD`s in the program header table (also those beyond
    /// [`MAX_MAPPED_LOADS`]).
    pub fn total_loads(&self) -> usize {
        self.total_loads
    }
}

/// How [`DynamicTable`] was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DynamicSource {
    /// Through `PT_DYNAMIC` `p_vaddr` and the memory map, as `ld.so` does
    /// (glibc elf/rtld.c `rtld_setup_main_map`; musl `kernel_mapped_dso`).
    Vaddr,
    /// `p_vaddr` is not file-backed; read at `p_offset` instead (an
    /// inference: no loader does this, and the audit reports it).
    Offset,
}

/// The dynamic table: the entries of the last `PT_DYNAMIC` (glibc and musl
/// both keep the last one they see) up to, not including, the first
/// `DT_NULL`, or up to the end of the file-backed bytes. A view; no copy.
#[derive(Debug, Clone, Copy)]
pub struct DynamicTable<'data> {
    entries: LayoutTable<'data, DynKind>,
    /// Index of the `PT_DYNAMIC` in the program header table.
    pub segment: usize,
    /// Where the table was read from.
    pub file_offset: u64,
    pub source: DynamicSource,
    /// A `DT_NULL` ends the table (glibc reads until it; get-dynamic-info.h).
    pub terminated: bool,
}

impl<'data> DynamicTable<'data> {
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn get(&self, i: usize) -> Option<DynamicEntry> {
        self.entries.get(i)
    }
    pub fn iter(&self) -> LayoutIter<'data, DynKind> {
        self.entries.iter()
    }
}

impl<'data> ElfFile<'data> {
    /// The memory map built from the `PT_LOAD`s, for
    /// [`DEFAULT_PAGE_SIZE`]-byte pages. Empty when the program header table
    /// is unreadable. Allocates O(number of `PT_LOAD`s).
    pub fn memory_map(&self) -> MemoryMap {
        self.memory_map_with_page_size(DEFAULT_PAGE_SIZE)
    }

    /// [`ElfFile::memory_map`] for a host whose kernel maps `page_size`-byte
    /// pages (`ELF_MIN_ALIGN`). A `page_size` that is not a power of two is
    /// replaced by [`DEFAULT_PAGE_SIZE`]; 1 gives the byte-granular reading.
    pub fn memory_map_with_page_size(&self, page_size: u64) -> MemoryMap {
        match self.program_headers() {
            Ok(p) => MemoryMap::build(p.iter(), file_len(self.data), page_size),
            Err(_) => MemoryMap {
                page_size: if page_size.is_power_of_two() {
                    page_size
                } else {
                    DEFAULT_PAGE_SIZE
                },
                ..MemoryMap::default()
            },
        }
    }

    /// The dynamic table, found as the dynamic loader finds it: through
    /// `p_vaddr` of the last `PT_DYNAMIC`, mapped to file bytes by the
    /// `PT_LOAD`s (`p_offset` is not used by glibc or musl;
    /// LOADER_RULES.md §3a, §4a). Falls back to `p_offset` when `p_vaddr`
    /// is not file-backed ([`DynamicSource::Offset`]).
    ///
    /// Section headers are not used, so this works on stripped files.
    pub fn dynamic(&self) -> Result<DynamicTable<'data>> {
        self.dynamic_with(&self.memory_map())
    }

    /// [`ElfFile::dynamic`] through an existing memory map of this file (to
    /// avoid rebuilding it).
    pub fn dynamic_with(&self, map: &MemoryMap) -> Result<DynamicTable<'data>> {
        let phdrs = self.program_headers()?;
        let (segment, ph) = phdrs
            .iter()
            .enumerate()
            .rfind(|(_, p)| p.p_type == PT_DYNAMIC)
            .ok_or(Error::Missing { what: "PT_DYNAMIC" })?;
        let (source, offset, size) = match map.file_extent(ph.vaddr) {
            Some((o, n)) => (DynamicSource::Vaddr, o, n),
            None => {
                let b = self.segment_bytes(&ph);
                if b.bytes.is_empty() {
                    return Err(Error::Missing {
                        what: "PT_DYNAMIC (p_vaddr not file-backed, p_offset outside the file)",
                    });
                }
                (DynamicSource::Offset, ph.offset, b.bytes.len() as u64)
            }
        };
        let (class, endian) = (self.header.class, self.header.endian);
        let entsize = LayoutTable::<DynKind>::entry_size(class);
        let bytes = tail(self.data, offset).unwrap_or(&[]);
        let bytes = bytes
            .get(..usize::try_from(size).unwrap_or(usize::MAX).min(bytes.len()))
            .unwrap_or(bytes);
        let all = LayoutTable::<DynKind>::new(class, endian, bytes, entsize, u64::MAX)
            .unwrap_or_else(|| LayoutTable::empty(class, endian));
        let end = all.iter().position(|e| e.tag == DT_NULL);
        Ok(DynamicTable {
            entries: all.truncated(end.unwrap_or(all.len())),
            segment,
            file_offset: offset,
            source,
            terminated: end.is_some(),
        })
    }
}

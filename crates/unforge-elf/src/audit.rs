//! The explicit audit: one walk over the file that produces every diagnostic.
//!
//! Cost: O(sections log sections + segments + loads^2 (bounded by
//! `MAX_MAPPED_LOADS`) + symbols), with the symbol part bounded by a budget
//! proportional to the file size so that many overlapping symbol tables
//! cannot make it quadratic. Memory: O(sections + loads); the symbols
//! themselves are never collected.

use crate::consts::*;
use crate::diag::{
    Alternative, Audit, Choice, Clue, Collector, Diagnostic, DiagnosticKind as K, Inference,
    InferenceSubject, Location, TableRef,
};
use crate::dynsym::DynamicSymbolCount;
use crate::layout::sizes;
use crate::memmap::{DynamicSource, DynamicTable, MAX_MAPPED_LOADS, MemoryMap};
use crate::parse::file_len;
use crate::symbols::is_symtab;
use crate::table::{LayoutTable, SymKind};
use crate::{Class, ElfFile, Endian, Error, ProgramHeader, SectionHeader, SymbolSection};

/// At most this many alternatives are listed for a "which section" inference.
const MAX_SECTION_ALTERNATIVES: usize = 8;
/// Above this many sections * segments, the section-vs-segment address check
/// is skipped (and reported as incomplete).
const MAX_ADDRESS_CHECKS: u64 = 1 << 22;

impl<'data> ElfFile<'data> {
    /// Walk the whole file and return every diagnostic, at most
    /// [`crate::MAX_DIAGNOSTICS_PER_KIND`] of each kind.
    ///
    /// Plain accessors never compute diagnostics; this is the one place that
    /// does. Loader-category diagnostics (see [`crate::Category::Loader`])
    /// describe what Linux loaders would do; kernel predictions are not
    /// included (they depend on the host, see
    /// [`ElfFile::kernel_prediction_for`]).
    pub fn audit(&self) -> Audit {
        let mut c = Collector::new();
        self.audit_header(&mut c);
        let map = self.memory_map();
        let dynamic = self.dynamic_with(&map);
        let phdrs = self.audit_segments(&mut c, &map, dynamic.as_ref().ok());
        if let Ok(d) = &dynamic {
            self.audit_dynamic_symbols(&mut c, &map, d);
        }
        let strtabs = self.strtab_candidates();
        let dups = self.audit_sections(&mut c, &map, &phdrs, &strtabs);
        self.audit_symbols(&mut c, &phdrs, &dups, &strtabs);
        c.finish()
    }

    /// `audit().diagnostics`.
    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        self.audit().diagnostics
    }

    /// Every inference the reader makes on this file (up to the per-kind cap).
    pub fn inferences(&self) -> Vec<Inference> {
        self.audit().inferences().cloned().collect()
    }

    /// Whether some inference has an alternative that is equally consistent
    /// with the file, i.e. the file has no unique interpretation. Runs the
    /// audit.
    pub fn is_ambiguous(&self) -> bool {
        self.audit().ambiguous
    }

    fn audit_header(&self, c: &mut Collector) {
        let h = &self.header;
        let at = |o: u64, n: u64| Location::table(TableRef::ElfHeader).at(o, n);
        let l = &self.layout;
        if l.is_inferred() {
            let class_code = match l.class {
                Class::Elf32 => ELFCLASS32,
                _ => ELFCLASS64,
            };
            let data_code = match l.endian {
                Endian::Little => ELFDATA2LSB,
                _ => ELFDATA2MSB,
            };
            if l.ident_class != class_code {
                c.push(
                    K::ClassMismatch {
                        claimed: l.ident_class,
                        used: l.class,
                    },
                    at(4, 1),
                );
            }
            if l.ident_data != data_code {
                c.push(
                    K::DataMismatch {
                        claimed: l.ident_data,
                        used: l.endian,
                    },
                    at(5, 1),
                );
            }
            if let Some(i) = l.inference() {
                c.infer(i, at(0, 16));
            }
        }
        if l.chosen().is_some_and(|ch| !ch.consistent) {
            c.push(
                K::LayoutInconsistent {
                    class: l.class,
                    endian: l.endian,
                },
                at(0, u64::from(sizes(l.class).0)),
            );
        }
        if h.ident_version != EV_CURRENT {
            c.push(K::IdentVersion(h.ident_version), at(6, 1));
        }
        if h.version != u32::from(EV_CURRENT) {
            c.push(K::Version(h.version), at(0x14, 4));
        }
        if h.os_abi != ELFOSABI_NONE && h.os_abi != ELFOSABI_GNU {
            c.push(K::OsAbi(h.os_abi), at(7, 1));
        }
        if h.abi_version != 0 {
            c.push(K::AbiVersion(h.abi_version), at(8, 1));
        }
        if self
            .data
            .get(9..16)
            .is_some_and(|p| p.iter().any(|&b| b != 0))
        {
            c.push(K::NonZeroPadding, at(9, 7));
        }
        let (ehsize, _, _) = sizes(h.class);
        if h.ehsize != ehsize {
            c.push(
                K::HeaderSize {
                    found: h.ehsize,
                    expected: ehsize,
                },
                Location::table(TableRef::ElfHeader),
            );
        }
    }

    /// Program header diagnostics. Returns the program headers (empty when
    /// unreadable), collected once because later checks index them.
    fn audit_segments(
        &self,
        c: &mut Collector,
        map: &MemoryMap,
        dynamic_table: Option<&DynamicTable<'data>>,
    ) -> Vec<ProgramHeader> {
        let h = &self.header;
        let len = file_len(self.data);
        let (ehsize, phentsize, _) = sizes(h.class);
        let loc = Location::table(TableRef::ProgramHeaders);
        if h.phnum > 0 && h.phentsize != phentsize {
            c.push(
                K::BadProgramHeaderEntrySize {
                    found: h.phentsize,
                    expected: phentsize,
                },
                loc,
            );
            if h.phentsize < phentsize {
                c.infer(
                    entry_size_inference(
                        InferenceSubject::ProgramHeaderEntrySize,
                        "e_phentsize",
                        h.phentsize.into(),
                        phentsize.into(),
                    ),
                    loc,
                );
            }
        }
        let phdrs: Vec<ProgramHeader> = match self.program_headers() {
            Err(error) => {
                c.push(K::ProgramHeaderTableUnreadable { error }, loc);
                Vec::new()
            }
            Ok(t) => {
                let usable = t.len() as u64;
                if usable < h.phnum {
                    c.push(
                        K::ProgramHeaderCountClipped {
                            declared: h.phnum,
                            usable,
                        },
                        loc.at(h.phoff, len.saturating_sub(h.phoff)),
                    );
                    c.infer(
                        count_inference(
                            InferenceSubject::ProgramHeaderCount,
                            "e_phnum",
                            h.phnum,
                            usable,
                            len,
                        ),
                        loc,
                    );
                }
                t.iter().collect()
            }
        };
        if !phdrs.is_empty() && h.phoff < u64::from(ehsize) {
            c.push(K::PhdrsOverlapHeader, loc.at(h.phoff, 1));
        }

        let mut prev_load: Option<u64> = None;
        let first_of =
            |c: &mut Collector, ty: u32, i: usize, first: &mut Option<usize>, keep_last: bool| {
                match *first {
                    None => *first = Some(i),
                    Some(f) => {
                        let (used, ignored) = if keep_last { (i, f) } else { (f, i) };
                        c.push(
                            K::DuplicateSegment {
                                p_type: ty,
                                used,
                                ignored,
                            },
                            Location::entry(TableRef::ProgramHeaders, i),
                        );
                        if keep_last {
                            *first = Some(i);
                        }
                    }
                }
            };
        let (mut interp, mut phdr, mut dynamic, mut stack) = (None, None, None, None);
        for (i, p) in phdrs.iter().enumerate() {
            let at = Location::entry(TableRef::ProgramHeaders, i);
            let end = p.offset.saturating_add(p.filesz);
            if p.filesz > 0 && end > len {
                c.push(
                    K::SegmentPastEof {
                        index: i,
                        end,
                        file_len: len,
                    },
                    at.at(p.offset, p.filesz),
                );
            }
            let known = p.p_type <= PT_TLS || (PT_LOOS..=PT_HIPROC).contains(&p.p_type);
            if !known {
                c.push(
                    K::UnknownSegmentType {
                        index: i,
                        p_type: p.p_type,
                    },
                    at,
                );
            }
            match p.p_type {
                PT_LOAD => {
                    // gABI ch5 "Program Header": "The file size may not be
                    // larger than the memory size". The kernel kills the
                    // process (fs/binfmt_elf.c load_elf_binary, v7.0.12
                    // line 1216); the memory map uses p_memsz file bytes.
                    if p.filesz > p.memsz {
                        c.push(
                            K::FileszExceedsMemsz {
                                index: i,
                                filesz: p.filesz,
                                memsz: p.memsz,
                            },
                            at,
                        );
                    }
                    // elf_map passes p_offset - PAGEOFFSET(p_vaddr) to
                    // vm_mmap, which fails unless it is page aligned
                    // (fs/binfmt_elf.c elf_map line 377, mm/util.c vm_mmap;
                    // LOADER_RULES.md §2). Not congruent modulo the map's
                    // page size means not congruent modulo any larger one.
                    let page = map.page_size();
                    if p.filesz > 0 && p.offset % page != p.vaddr % page {
                        c.push(
                            K::OffsetNotPageCongruent {
                                index: i,
                                offset: p.offset,
                                vaddr: p.vaddr,
                                page_size: page,
                            },
                            at,
                        );
                    }
                    if p.align > 1 && !p.align.is_power_of_two() {
                        c.push(
                            K::AlignNotPowerOfTwo {
                                index: i,
                                align: p.align,
                            },
                            at,
                        );
                    } else if p.align > 1 && p.offset % p.align != p.vaddr % p.align {
                        c.push(
                            K::AlignCongruence {
                                index: i,
                                offset: p.offset,
                                vaddr: p.vaddr,
                                align: p.align,
                            },
                            at,
                        );
                    }
                    if prev_load.is_some_and(|v| p.vaddr < v) {
                        c.push(K::LoadsNotSorted { index: i }, at);
                    }
                    prev_load = Some(p.vaddr);
                }
                PT_INTERP => first_of(c, PT_INTERP, i, &mut interp, false),
                PT_PHDR => first_of(c, PT_PHDR, i, &mut phdr, false),
                PT_DYNAMIC => first_of(c, PT_DYNAMIC, i, &mut dynamic, true),
                PT_GNU_STACK => first_of(c, PT_GNU_STACK, i, &mut stack, true),
                _ => {}
            }
        }

        // Overlapping PT_LOADs, from the memory map's override records. The
        // map is page-granular; an overlap where the two segments' declared
        // byte ranges do not meet exists only because of the page size.
        let mut page_clues: Vec<Clue> = Vec::new();
        let declared = |i: usize| {
            phdrs
                .get(i)
                .map(|p| (p.vaddr, p.vaddr.saturating_add(p.memsz)))
        };
        for (start, end, segment, overridden) in map.overrides() {
            let meet = match (declared(segment), declared(overridden)) {
                (Some((a0, a1)), Some((b0, b1))) => a0.max(b0).max(start) < a1.min(b1).min(end),
                _ => true,
            };
            if !meet && page_clues.len() < 8 {
                page_clues.push(Clue::Field {
                    field: "PT_LOAD replaced only at page granularity",
                    value: overridden as u64,
                });
            }
            c.push(
                K::LoadsOverlap {
                    earlier: overridden,
                    later: segment,
                    start,
                    end,
                },
                Location::entry(TableRef::ProgramHeaders, segment),
            );
        }
        if map.total_loads() > MAX_MAPPED_LOADS {
            c.push(
                K::MemoryMapTruncated {
                    used: MAX_MAPPED_LOADS,
                    total: map.total_loads(),
                },
                loc,
            );
        }

        // Loader expectations.
        let loadable = h.e_type == ET_EXEC || h.e_type == ET_DYN;
        if loadable && !phdrs.is_empty() {
            // AT_PHDR as the kernel computes it: the last PT_LOAD whose file
            // range holds e_phoff (fs/binfmt_elf.c v7.0.12, 1210-1214).
            let at_phdr = phdrs
                .iter()
                .filter(|p| p.p_type == PT_LOAD)
                .rfind(|p| p.offset <= h.phoff && h.phoff < p.offset.saturating_add(p.filesz))
                // Unsigned (wrapping) arithmetic, as in the kernel.
                .map(|p| (h.phoff - p.offset).wrapping_add(p.vaddr));
            if at_phdr.is_none() {
                c.push(K::PhdrsNotInLoad, loc.at(h.phoff, 1));
            }
            if let Some(pt) = phdr.and_then(|i| phdrs.get(i))
                && Some(pt.vaddr) != at_phdr
            {
                c.push(
                    K::PtPhdrMismatch {
                        pt_phdr_vaddr: pt.vaddr,
                        mapped_vaddr: at_phdr,
                    },
                    Location::entry(TableRef::ProgramHeaders, phdr.unwrap_or(0)),
                );
            }
            if h.entry != 0 {
                let backing = map.backing_ref(h.entry);
                if let Some(b) = backing.filter(|b| !b.in_segment) {
                    c.push(
                        K::EntryInPageSlack {
                            entry: h.entry,
                            segment: b.segment,
                            page_size: map.page_size(),
                        },
                        Location::table(TableRef::ElfHeader),
                    );
                    page_clues.push(Clue::Field {
                        field: "e_entry mapped only through page slack",
                        value: h.entry,
                    });
                }
                let bad = match &backing {
                    None => Some(None),
                    Some(b) if b.flags & PF_X == 0 => Some(Some(b.segment)),
                    Some(_) => None,
                };
                if let Some(backing) = bad {
                    c.push(
                        K::EntryNotExecutable {
                            entry: h.entry,
                            backing,
                        },
                        Location::table(TableRef::ElfHeader),
                    );
                }
            }
            if interp.is_some() && dynamic.is_none() {
                c.push(K::InterpWithoutDynamic, loc);
            }
        }
        if !page_clues.is_empty() {
            c.infer(
                page_size_inference(h.machine, map.page_size(), page_clues),
                loc,
            );
        }
        if let Some(d) = dynamic.and_then(|i| phdrs.get(i).map(|p| (i, p))) {
            let (i, p) = d;
            let at = Location::entry(TableRef::ProgramHeaders, i);
            let mapped = map.file_offset(p.vaddr);
            match mapped {
                Some(o) if o != p.offset => c.push(
                    K::DynamicOffsetMismatch {
                        p_offset: p.offset,
                        mapped_offset: Some(o),
                    },
                    at,
                ),
                Some(_) => {}
                None => {
                    if loadable {
                        c.push(K::DynamicNotMapped { vaddr: p.vaddr }, at);
                    }
                    c.push(
                        K::DynamicOffsetMismatch {
                            p_offset: p.offset,
                            mapped_offset: None,
                        },
                        at,
                    );
                }
            }
            if let Some(t) = dynamic_table
                && !t.terminated
            {
                let at = Location::table(TableRef::Dynamic).at(t.file_offset, 0);
                c.push(K::DynamicUnterminated { entries: t.len() }, at);
                c.infer(
                    Inference {
                        subject: InferenceSubject::DynamicEntryCount,
                        chosen: Choice::Count(t.len() as u64),
                        score: None,
                        clues: vec![
                            Clue::Field {
                                field: "dynamic table file offset",
                                value: t.file_offset,
                            },
                            Clue::FileLength(len),
                        ],
                        alternatives: vec![],
                    },
                    at,
                );
            }
            if let Some(t) = dynamic_table
                && t.source == DynamicSource::Offset
            {
                c.infer(
                    Inference {
                        subject: InferenceSubject::DynamicTableLocation,
                        chosen: Choice::FileOffset(t.file_offset),
                        score: None,
                        clues: vec![
                            Clue::Field {
                                field: "PT_DYNAMIC p_vaddr (not file-backed)",
                                value: p.vaddr,
                            },
                            Clue::Field {
                                field: "PT_DYNAMIC p_offset",
                                value: p.offset,
                            },
                        ],
                        alternatives: vec![Alternative {
                            choice: Choice::Nothing,
                            viable: true,
                            score: None,
                            clues: vec![],
                        }],
                    },
                    Location::table(TableRef::Dynamic),
                );
            }
        }
        phdrs
    }

    /// Section header diagnostics. Returns, per section index, the earlier
    /// symbol table covering identical bytes (for symbol tables only).
    fn audit_sections(
        &self,
        c: &mut Collector,
        map: &MemoryMap,
        phdrs: &[ProgramHeader],
        strtabs: &[(u32, u64)],
    ) -> Vec<Option<usize>> {
        let h = &self.header;
        let len = file_len(self.data);
        let (_, _, shentsize) = sizes(h.class);
        let loc = Location::table(TableRef::SectionHeaders);
        if h.shoff == 0 {
            if h.raw_shnum != 0 {
                c.push(K::SectionCountWithoutTable { shnum: h.raw_shnum }, loc);
                // Offset 0 holds the ELF header, so a table "at" e_shoff = 0
                // would be the header itself; gABI ch4 says e_shoff 0 means
                // no table. The reader follows e_shoff.
                c.infer(
                    Inference {
                        subject: InferenceSubject::SectionHeaderCount,
                        chosen: Choice::Count(0),
                        score: None,
                        clues: vec![Clue::Field {
                            field: "e_shoff",
                            value: 0,
                        }],
                        alternatives: vec![Alternative {
                            choice: Choice::Count(h.raw_shnum.into()),
                            viable: false,
                            score: None,
                            clues: vec![Clue::Field {
                                field: "e_shnum",
                                value: h.raw_shnum.into(),
                            }],
                        }],
                    },
                    loc,
                );
            } else {
                c.push(K::NoSectionHeaderTable, loc);
            }
            return Vec::new();
        }
        if h.shnum > 0 && h.shentsize != shentsize {
            c.push(
                K::BadSectionEntrySize {
                    found: h.shentsize,
                    expected: shentsize,
                },
                loc,
            );
            if h.shentsize < shentsize {
                c.infer(
                    entry_size_inference(
                        InferenceSubject::SectionHeaderEntrySize,
                        "e_shentsize",
                        h.shentsize.into(),
                        shentsize.into(),
                    ),
                    loc,
                );
            }
        }
        let table = match self.section_headers() {
            Err(Error::OutOfBounds { offset, size, .. }) => {
                c.push(
                    K::SectionTableOutsideFile {
                        offset,
                        size,
                        file_len: len,
                    },
                    loc.at(offset, size),
                );
                return Vec::new();
            }
            Err(error) => {
                c.push(K::SectionHeaderTableUnreadable { error }, loc);
                return Vec::new();
            }
            Ok(t) => t,
        };
        let n = table.len();
        if (n as u64) < h.shnum {
            c.push(
                K::SectionCountClipped {
                    declared: h.shnum,
                    usable: n as u64,
                },
                loc.at(h.shoff, len.saturating_sub(h.shoff)),
            );
            c.infer(
                count_inference(
                    InferenceSubject::SectionHeaderCount,
                    "e_shnum",
                    h.shnum,
                    n as u64,
                    len,
                ),
                loc,
            );
        }

        // The section name table.
        if (SHN_LORESERVE..SHN_XINDEX).contains(&h.raw_shstrndx) {
            c.push(
                K::ShstrndxReserved(h.raw_shstrndx),
                Location::table(TableRef::ElfHeader),
            );
        }
        if let Some(i) = h.shstrndx {
            match table.get(i as usize) {
                None => c.push(
                    K::ShstrndxOutOfRange {
                        index: i,
                        shnum: n as u64,
                    },
                    Location::table(TableRef::ElfHeader),
                ),
                Some(sh) if sh.sh_type != SHT_STRTAB => {
                    c.push(
                        K::ShstrndxNotStrtab {
                            index: i,
                            sh_type: sh.sh_type,
                        },
                        Location::entry(TableRef::SectionHeaders, i as usize),
                    );
                    let max_name = table.iter().map(|s| u64::from(s.name)).max().unwrap_or(0);
                    let alternatives = strtab_alternatives(strtabs, i, |size| max_name < size);
                    c.infer(
                        Inference {
                            subject: InferenceSubject::SectionNameTable,
                            chosen: Choice::Section(i),
                            score: None,
                            clues: vec![
                                Clue::Field {
                                    field: "e_shstrndx",
                                    value: i.into(),
                                },
                                Clue::SectionType {
                                    index: i,
                                    sh_type: sh.sh_type,
                                },
                            ],
                            alternatives,
                        },
                        Location::entry(TableRef::SectionHeaders, i as usize),
                    );
                }
                Some(_) => {}
            }
        }
        // gABI ch4 "String Table": "the last byte is defined to hold a null
        // character, ensuring null termination for all strings". A name that
        // starts after the last NUL cannot be read (where it ends is unknown).
        if let Ok(names) = self.section_name_table()
            && let Some(i) = h.shstrndx
        {
            if names.last().is_some_and(|&b| b != 0) {
                c.push(
                    K::StringTableUnterminated { section: i },
                    Location::entry(TableRef::Section(i as usize), i as usize),
                );
            }
            let last_nul = names.iter().rposition(|&b| b == 0);
            let len = names.len() as u64;
            let count = table
                .iter()
                .filter(|s| {
                    let o = u64::from(s.name);
                    o < len && last_nul.is_none_or(|n| o > n as u64)
                })
                .count();
            if count > 0 {
                c.push(
                    K::SectionNamesUnterminated { count },
                    Location::entry(TableRef::Section(i as usize), i as usize),
                );
            }
        }

        // Per-section checks.
        let dynamic = phdrs.iter().rposition(|p| p.p_type == PT_DYNAMIC);
        let loadable = h.e_type == ET_EXEC || h.e_type == ET_DYN;
        let loads: Vec<(usize, &ProgramHeader)> = phdrs
            .iter()
            .enumerate()
            .filter(|(_, p)| p.p_type == PT_LOAD)
            .take(MAX_MAPPED_LOADS)
            .collect();
        let address_checks = (n as u64).saturating_mul(loads.len() as u64) <= MAX_ADDRESS_CHECKS;
        if loadable && !address_checks {
            c.push(
                K::AuditIncomplete {
                    what: "section address vs segment check",
                    skipped: n as u64,
                },
                loc,
            );
        }
        let mut ranges: Vec<(u64, u64, usize)> = Vec::new();
        for (i, sh) in table.iter().enumerate() {
            if sh.sh_type == SHT_NULL {
                continue;
            }
            let at = Location::entry(TableRef::Section(i), i);
            let has_bytes = sh.sh_type != SHT_NOBITS && sh.size > 0;
            if has_bytes {
                let b = self.section_bytes(&sh);
                if b.missing > 0 {
                    c.push(
                        K::SectionClipped {
                            index: i,
                            declared: sh.size,
                            available: b.bytes.len() as u64,
                        },
                        at.at(sh.offset, sh.size),
                    );
                }
                ranges.push((sh.offset, sh.offset.saturating_add(sh.size), i));
            }
            if let Some(reason) = self.name_mismatch(&sh, map, loadable) {
                c.push(K::SectionNameMismatch { index: i, reason }, at);
            }
            let alloc = sh.flags & SHF_ALLOC != 0;
            if loadable
                && alloc
                && sh.sh_type == SHT_NOBITS
                && sh.flags & SHF_TLS == 0
                && sh.size > 0
                && let Some(b) = map.backing_ref(sh.addr)
                && b.in_segment
                && b.file_offset.is_some()
            {
                c.push(
                    K::NobitsInFileBytes {
                        index: i,
                        segment: b.segment,
                    },
                    at,
                );
            }
            if loadable && address_checks && alloc && has_bytes && sh.addr != 0 {
                let end = sh.offset.saturating_add(sh.size);
                let mut holders = loads.iter().filter(|(_, p)| {
                    p.offset <= sh.offset && end <= p.offset.saturating_add(p.filesz)
                });
                let first = holders.clone().next();
                let matches =
                    holders.any(|(_, p)| p.vaddr.wrapping_add(sh.offset - p.offset) == sh.addr);
                if let (false, Some((seg, p))) = (matches, first) {
                    c.push(
                        K::SectionAddressMismatch {
                            index: i,
                            segment: *seg,
                            expected: p.vaddr.wrapping_add(sh.offset - p.offset),
                            found: sh.addr,
                        },
                        at,
                    );
                }
            }
            if loadable && sh.sh_type == SHT_DYNAMIC {
                match dynamic.and_then(|d| phdrs.get(d)) {
                    None => c.push(
                        K::DynamicSectionMismatch {
                            section: i,
                            dynamic_offset: None,
                        },
                        at,
                    ),
                    Some(p) if p.offset != sh.offset || p.vaddr != sh.addr => c.push(
                        K::DynamicSectionMismatch {
                            section: i,
                            dynamic_offset: Some(p.offset),
                        },
                        at,
                    ),
                    Some(_) => {}
                }
            }
        }

        // Overlaps: one sweep in offset order. A section is reported once,
        // against the earlier section that reaches furthest.
        let mut dups: Vec<Option<usize>> = vec![None; n];
        ranges.sort_unstable_by_key(|&(o, e, i)| (o, e, i));
        let mut reach: Option<(u64, usize)> = None;
        let mut prev: Option<(u64, u64, usize)> = None;
        for &(o, e, i) in &ranges {
            let same = prev.filter(|&(po, pe, _)| po == o && pe == e);
            let both_symtabs = |j: usize| {
                table.get(i).is_some_and(|s| is_symtab(&s))
                    && table.get(j).is_some_and(|s| is_symtab(&s))
            };
            match same {
                Some((_, _, j)) if both_symtabs(j) => {
                    let first = dups.get(j).copied().flatten().unwrap_or(j);
                    if let Some(d) = dups.get_mut(i) {
                        *d = Some(first);
                    }
                    c.push(
                        K::DuplicateTable {
                            index: i,
                            same_as: first,
                        },
                        Location::entry(TableRef::Section(i), i).at(o, e - o),
                    );
                }
                _ => {
                    if let Some((r, j)) = reach
                        && o < r
                    {
                        c.push(
                            K::SectionsOverlap {
                                first: j,
                                second: i,
                                start: o,
                                end: r.min(e),
                            },
                            Location::entry(TableRef::Section(i), i).at(o, r.min(e) - o),
                        );
                    }
                }
            }
            if same.is_none() {
                prev = Some((o, e, i));
            }
            if reach.is_none_or(|(r, _)| e > r) {
                reach = Some((e, i));
            }
        }
        dups
    }

    /// The dynamic symbol table as `ld.so` finds it, against `SHT_DYNSYM`.
    fn audit_dynamic_symbols(&self, c: &mut Collector, map: &MemoryMap, d: &DynamicTable<'data>) {
        let Ok(ds) = self.dynamic_symbols_with(map, d) else {
            return;
        };
        let at = Location::table(TableRef::Dynamic);
        let sym_size = LayoutTable::<SymKind>::entry_size(self.header.class) as u64;
        // The first SHT_DYNSYM, as readelf and objdump use it.
        let dynsym = self
            .section_headers()
            .ok()
            .and_then(|t| t.iter().enumerate().find(|(_, s)| s.sh_type == SHT_DYNSYM));
        let section_count = dynsym.map(|(_, s)| s.size / s.entsize.max(sym_size));
        if let Some((i, s)) = dynsym {
            let mut check = |what: &'static str, dynamic: u64, section_value: u64| {
                if dynamic != section_value {
                    c.push(
                        K::DynamicSymbolsMismatch {
                            section: i,
                            what,
                            dynamic,
                            section_value,
                        },
                        Location::entry(TableRef::Section(i), i),
                    );
                }
            };
            check("address (DT_SYMTAB vs sh_addr)", ds.symtab_vaddr, s.addr);
            if ds.count != DynamicSymbolCount::Unknown {
                check(
                    "symbol count (hash table vs sh_size / sh_entsize)",
                    ds.count.count(),
                    section_count.unwrap_or(0),
                );
            }
            if let (Some(a), Ok(strsec)) = (ds.strtab_vaddr, self.section_header(s.link as usize)) {
                check(
                    "string table address (DT_STRTAB vs sh_addr of sh_link)",
                    a,
                    strsec.addr,
                );
            }
        }
        if let Some(s0) = ds.get(0)
            && (s0.name, s0.value, s0.size, s0.info, s0.other, s0.raw_shndx) != (0, 0, 0, 0, 0, 0)
        {
            c.push(K::DynamicFirstSymbolNotNull, at);
        }
        if let Some(n) = ds.syment
            && n != sym_size
        {
            c.push(K::DynamicSymbolEntrySize { found: n }, at);
        }
        // The count is given by DT_HASH (gABI); otherwise it is derived, and
        // needs a section header that agrees with it to be confirmed.
        let confirmed = matches!(ds.count, DynamicSymbolCount::Hash { .. })
            || (dynsym.is_some_and(|(_, s)| s.addr == ds.symtab_vaddr)
                && section_count == Some(ds.count.count()));
        if !confirmed {
            let source = match ds.count {
                DynamicSymbolCount::GnuHash { .. } => "DT_GNU_HASH chains",
                _ => "no readable DT_HASH or DT_GNU_HASH",
            };
            c.infer(
                Inference {
                    subject: InferenceSubject::DynamicSymbolCount,
                    chosen: Choice::Count(ds.count.count()),
                    score: None,
                    clues: vec![
                        Clue::Field {
                            field: source,
                            value: ds.count.count(),
                        },
                        Clue::Field {
                            field: "DT_SYMTAB",
                            value: ds.symtab_vaddr,
                        },
                    ],
                    alternatives: dynsym
                        .zip(section_count)
                        .filter(|&(_, n)| n != ds.count.count())
                        .map(|((i, s), n)| Alternative {
                            choice: Choice::Count(n),
                            viable: s.addr == ds.symtab_vaddr,
                            score: None,
                            clues: vec![Clue::Field {
                                field: "count from sh_size / sh_entsize of SHT_DYNSYM section",
                                value: i as u64,
                            }],
                        })
                        .into_iter()
                        .collect(),
                },
                at,
            );
        }
    }

    /// The first `SHT_STRTAB` sections, as `(index, bytes inside the file)`:
    /// enough to list [`MAX_SECTION_ALTERNATIVES`] alternatives to any one of
    /// them. Collected once per audit, so that each symbol table's string
    /// table inference costs O(1) sections, not O(e_shnum).
    fn strtab_candidates(&self) -> Vec<(u32, u64)> {
        let Ok(table) = self.section_headers() else {
            return Vec::new();
        };
        table
            .iter()
            .enumerate()
            .filter(|(_, s)| s.sh_type == SHT_STRTAB)
            .take(MAX_SECTION_ALTERNATIVES + 1)
            .map(|(j, s)| (j as u32, self.section_bytes(&s).bytes.len() as u64))
            .collect()
    }

    /// A section name that contradicts the section's flags or its segment.
    fn name_mismatch(
        &self,
        sh: &SectionHeader,
        map: &MemoryMap,
        loadable: bool,
    ) -> Option<&'static str> {
        let exec = sh.flags & SHF_EXECINSTR != 0;
        if loadable
            && exec
            && sh.flags & SHF_ALLOC != 0
            && sh.size > 0
            && let Some(b) = map.backing_ref(sh.addr)
            && b.flags & PF_X == 0
        {
            return Some("SHF_EXECINSTR section in a non-executable segment");
        }
        let name = self.section_name_bounded(sh, 64).ok()?.bytes;
        let code_name = name == b".text"
            || name.starts_with(b".text.")
            || name == b".init"
            || name == b".fini"
            || name == b".plt";
        let data_name = [&b".rodata"[..], b".data", b".bss"]
            .iter()
            .any(|p| name == *p || name.strip_prefix(*p).is_some_and(|r| r.starts_with(b".")));
        if code_name && sh.sh_type == SHT_PROGBITS && !exec {
            return Some("named like code but not SHF_EXECINSTR");
        }
        if data_name && exec {
            return Some("named like data but SHF_EXECINSTR");
        }
        None
    }

    fn audit_symbols(
        &self,
        c: &mut Collector,
        phdrs: &[ProgramHeader],
        dups: &[Option<usize>],
        strtabs: &[(u32, u64)],
    ) {
        let Ok(tables) = self.symbol_tables() else {
            return;
        };
        // SHT_SYMTAB_SHNDX sections as (sh_link, index, bytes in the file),
        // sorted, to find every one that claims a table (gABI ch4 "Symbol
        // Table" pairs one with each table; which one a reader should use
        // when several claim the same table is not specified).
        let mut shndx: Vec<(u32, u32, u64)> = self
            .section_headers()
            .map(|t| {
                t.iter()
                    .enumerate()
                    .filter(|(_, s)| s.sh_type == SHT_SYMTAB_SHNDX)
                    .map(|(j, s)| (s.link, j as u32, self.section_bytes(&s).bytes.len() as u64))
                    .collect()
            })
            .unwrap_or_default();
        shndx.sort_unstable();
        // Per table already audited: how it was read (stride, sh_link), so
        // that a duplicate read the same way is not walked again.
        let mut read_as: Vec<(usize, usize, Option<u32>)> = Vec::new();
        // String tables already reported as unterminated.
        let mut unterminated: Vec<u32> = Vec::new();
        let h = &self.header;
        let len = file_len(self.data);
        let sym_size = LayoutTable::<SymKind>::entry_size(h.class) as u64;
        let shnum = self.section_headers().map_or(0, |t| t.len()) as u64;
        // Function ranges are checked against executable PT_LOADs, except
        // where STT_FUNC symbols point at function descriptors in data
        // (64-bit PowerPC ELFv1, IA-64), and only when there are few loads.
        let descriptors =
            h.machine == EM_IA_64 || (h.machine == EM_PPC64 && h.flags & EF_PPC64_ABI != 2);
        let exec: Vec<(u64, u64)> = phdrs
            .iter()
            .filter(|p| p.p_type == PT_LOAD && p.flags & PF_X != 0)
            .map(|p| (p.vaddr, p.vaddr.saturating_add(p.memsz)))
            .collect();
        let check_funcs = (h.e_type == ET_EXEC || h.e_type == ET_DYN)
            && !descriptors
            && !exec.is_empty()
            && exec.len() <= 16;
        // Budget: a few passes over as many symbols as the file can hold.
        let mut budget = len / sym_size.max(1) * 4 + 4096;
        let mut skipped = 0u64;
        for t in tables {
            let i = t.section_index;
            // A table covering the same bytes as an earlier one is still
            // checked on its own header (its sh_entsize and sh_link may make
            // it read differently); its symbols are walked again only when
            // it is read differently.
            let same_reading = dups.get(i).copied().flatten().is_some_and(|first| {
                read_as.iter().any(|&(j, stride, link)| {
                    j == first && stride == t.entry_size() && link == t.strtab_index()
                })
            });
            read_as.push((i, t.entry_size(), t.strtab_index()));
            let at = Location::table(TableRef::SymbolTable(i));
            let sh = *t.section_header();
            if sh.entsize != sym_size {
                c.push(
                    K::SymbolEntrySize {
                        table: i,
                        found: sh.entsize,
                    },
                    at,
                );
            }
            if t.entry_size_inferred() {
                c.infer(
                    entry_size_inference(
                        InferenceSubject::SymbolEntrySize { table: i },
                        "sh_entsize",
                        sh.entsize,
                        sym_size,
                    ),
                    at,
                );
            }
            if t.trailing_bytes() != 0 {
                c.push(
                    K::SymbolTableTrailingBytes {
                        table: i,
                        bytes: t.trailing_bytes(),
                    },
                    at,
                );
            }
            if (t.len() as u64) < t.declared_len() {
                c.infer(
                    count_inference(
                        InferenceSubject::SymbolCount { table: i },
                        "sh_size / entry size",
                        t.declared_len(),
                        t.len() as u64,
                        len,
                    ),
                    at,
                );
            }
            // SHT_SYMTAB_SHNDX sections claiming this table.
            let lo = shndx.partition_point(|&(l, _, _)| (l as usize) < i);
            let claims = shndx
                .get(lo..)
                .unwrap_or(&[])
                .iter()
                .take_while(|&&(l, _, _)| l as usize == i);
            if claims.clone().nth(1).is_some() {
                let need = (t.len() as u64).saturating_mul(4);
                let mut it = claims.take(MAX_SECTION_ALTERNATIVES + 1);
                if let Some(&(_, chosen, size)) = it.next() {
                    c.infer(
                        Inference {
                            subject: InferenceSubject::ExtendedIndexTable { table: i },
                            chosen: Choice::Section(chosen),
                            score: None,
                            clues: vec![
                                Clue::Field {
                                    field: "first SHT_SYMTAB_SHNDX in section order with sh_link = this table",
                                    value: chosen.into(),
                                },
                                Clue::Field {
                                    field: "its size in the file",
                                    value: size,
                                },
                            ],
                            alternatives: it
                                .map(|&(_, j, size)| Alternative {
                                    choice: Choice::Section(j),
                                    viable: size >= need,
                                    score: None,
                                    clues: vec![Clue::Field {
                                        field: "size in the file",
                                        value: size,
                                    }],
                                })
                                .collect(),
                        },
                        at,
                    );
                }
            }
            // gABI ch4 "Symbol Table": index 0 is the undefined symbol and
            // all its fields are zero ("Symbol Table Entry: Index 0").
            if let Some(s0) = t.raw().get(0)
                && (s0.name, s0.value, s0.size, s0.info, s0.other, s0.raw_shndx)
                    != (0, 0, 0, 0, 0, 0)
            {
                c.push(K::FirstSymbolNotNull { table: i }, at);
            }
            if let (Some(link), Some(strtab)) = (t.strtab_index(), t.strtab())
                && strtab.last().is_some_and(|&b| b != 0)
                && !unterminated.contains(&link)
            {
                unterminated.push(link);
                c.push(
                    K::StringTableUnterminated { section: link },
                    Location::entry(TableRef::Section(link as usize), link as usize),
                );
            }
            match t.strtab_index() {
                None => c.push(
                    K::SymbolTableLinkInvalid {
                        table: i,
                        link: sh.link,
                    },
                    at,
                ),
                Some(link) => {
                    let ty = self.section_header(link as usize).map_or(0, |s| s.sh_type);
                    if ty != SHT_STRTAB {
                        c.push(
                            K::SymbolTableLinkNotStrtab {
                                table: i,
                                link,
                                sh_type: ty,
                            },
                            at,
                        );
                        let max_name = t
                            .iter()
                            .take(256)
                            .map(|s| u64::from(s.name))
                            .max()
                            .unwrap_or(0);
                        let alternatives =
                            strtab_alternatives(strtabs, link, |size| max_name < size);
                        c.infer(
                            Inference {
                                subject: InferenceSubject::StringTable { table: i },
                                chosen: Choice::Section(link),
                                score: None,
                                clues: vec![
                                    Clue::Field {
                                        field: "sh_link",
                                        value: link.into(),
                                    },
                                    Clue::SectionType {
                                        index: link,
                                        sh_type: ty,
                                    },
                                ],
                                alternatives,
                            },
                            at,
                        );
                    }
                }
            }
            if same_reading {
                continue;
            }
            let n = t.len() as u64;
            if n > budget {
                skipped += 1;
                continue;
            }
            budget -= n;
            let strtab_len = t.strtab().map(|s| s.len() as u64);
            let last_nul = t.strtab().and_then(|s| s.iter().rposition(|&b| b == 0));
            let (mut bad_names, mut reserved, mut unresolved, mut outside, mut past) =
                (0, 0, 0, 0, 0);
            let mut cut_names = 0usize;
            for s in t.iter() {
                let name = u64::from(s.name);
                if strtab_len.is_some_and(|l| name >= l) {
                    bad_names += 1;
                } else if strtab_len.is_some() && last_nul.is_none_or(|n| name > n as u64) {
                    cut_names += 1;
                }
                match s.section {
                    SymbolSection::Reserved(_) => reserved += 1,
                    SymbolSection::Unresolved => unresolved += 1,
                    SymbolSection::Index(x) if u64::from(x) >= shnum => past += 1,
                    _ => {}
                }
                if check_funcs
                    && s.kind() == STT_FUNC
                    && s.size > 0
                    && matches!(s.section, SymbolSection::Index(_))
                {
                    let end = s.value.saturating_add(s.size);
                    if !exec.iter().any(|&(a, b)| a <= s.value && end <= b) {
                        outside += 1;
                    }
                }
            }
            if bad_names > 0 {
                c.push(
                    K::SymbolNamesOutOfRange {
                        table: i,
                        count: bad_names,
                    },
                    at,
                );
            }
            if cut_names > 0 {
                c.push(
                    K::SymbolNamesUnterminated {
                        table: i,
                        count: cut_names,
                    },
                    at,
                );
            }
            if reserved > 0 {
                c.push(
                    K::ReservedSymbolSection {
                        table: i,
                        count: reserved,
                    },
                    at,
                );
            }
            if past > 0 {
                c.push(
                    K::SymbolSectionOutOfRange {
                        table: i,
                        count: past,
                    },
                    at,
                );
            }
            if unresolved > 0 {
                c.push(
                    K::UnresolvedExtendedIndex {
                        table: i,
                        count: unresolved,
                    },
                    at,
                );
            }
            if outside > 0 {
                c.push(
                    K::FunctionsOutsideCode {
                        table: i,
                        count: outside,
                    },
                    at,
                );
            }
        }
        if skipped > 0 {
            c.push(
                K::AuditIncomplete {
                    what: "symbol checks (symbol tables over the work budget)",
                    skipped,
                },
                Location::table(TableRef::SectionHeaders),
            );
        }
    }
}

/// The page size the memory map assumed, when a result depends on it.
///
/// Alternatives are listed only where the possible sizes were checked:
/// arm64 kernels use 4 KiB, 16 KiB or 64 KiB pages (LOADER_RULES.md
/// "Sources"); x86-64 always 4 KiB. For other machines the page sizes were
/// not checked, so no alternative is listed.
fn page_size_inference(machine: u16, page: u64, mut clues: Vec<Clue>) -> Inference {
    clues.insert(
        0,
        Clue::Field {
            field: "assumed page size (ELF_MIN_ALIGN; depends on the host kernel)",
            value: page,
        },
    );
    let others: &[u64] = match machine {
        EM_AARCH64 => &[4096, 16384, 65536],
        _ => &[],
    };
    Inference {
        subject: InferenceSubject::PageSize,
        chosen: Choice::PageSize(page),
        score: None,
        clues,
        alternatives: others
            .iter()
            .filter(|&&p| p != page)
            .map(|&p| Alternative {
                choice: Choice::PageSize(p),
                viable: true,
                score: None,
                clues: vec![Clue::Field {
                    field: "e_machine",
                    value: machine.into(),
                }],
            })
            .collect(),
    }
}

/// `SHT_STRTAB` sections other than `chosen`, as alternatives; `viable` is
/// given the section's size inside the file.
fn strtab_alternatives(
    strtabs: &[(u32, u64)],
    chosen: u32,
    viable: impl Fn(u64) -> bool,
) -> Vec<Alternative> {
    strtabs
        .iter()
        .filter(|(j, _)| *j != chosen)
        .take(MAX_SECTION_ALTERNATIVES)
        .map(|&(j, size)| Alternative {
            choice: Choice::Section(j),
            viable: viable(size),
            score: None,
            clues: vec![Clue::SectionType {
                index: j,
                sh_type: SHT_STRTAB,
            }],
        })
        .collect()
}

fn entry_size_inference(
    subject: InferenceSubject,
    field: &'static str,
    found: u64,
    size: u64,
) -> Inference {
    Inference {
        subject,
        chosen: Choice::EntrySize(size),
        score: None,
        clues: vec![
            Clue::Field {
                field,
                value: found,
            },
            Clue::StructureSize(size),
        ],
        alternatives: vec![Alternative {
            choice: Choice::EntrySize(found),
            viable: false,
            score: None,
            clues: vec![],
        }],
    }
}

fn count_inference(
    subject: InferenceSubject,
    field: &'static str,
    declared: u64,
    usable: u64,
    len: u64,
) -> Inference {
    Inference {
        subject,
        chosen: Choice::Count(usable),
        score: None,
        clues: vec![
            Clue::Field {
                field,
                value: declared,
            },
            Clue::FileLength(len),
        ],
        alternatives: vec![Alternative {
            choice: Choice::Count(declared),
            viable: false,
            score: None,
            clues: vec![],
        }],
    }
}

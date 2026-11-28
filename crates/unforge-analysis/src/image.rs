//! A loaded image, whatever its file format: the memory map from virtual
//! addresses to file bytes, and what code lives where.
//!
//! The analyses above the file readers (functions, dependencies,
//! disassembly, fingerprints, the report) need the same few things from a
//! file: the bytes at a virtual address, which addresses are code, the
//! entry point, the machine. [`Image`] answers those for ELF files (through
//! `unforge-elf`'s [`MemoryMap`], the kernel's view) and for PE files
//! (through `unforge-pe`'s section mapping, the Windows loader's view, at
//! the preferred image base). Format-specific questions go to the reader
//! itself ([`Image::elf`], [`Image::pe`]).

use unforge_elf::consts::{PF_W, PF_X, PT_LOAD};
use unforge_elf::{ElfFile, MemoryMap};
use unforge_pe::PeFile;

/// The CPU an image's code is for, as far as unforge decodes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Cpu {
    /// 32-bit x86 (`EM_386`, `IMAGE_FILE_MACHINE_I386`).
    X86,
    /// x86-64 (`EM_X86_64`, `IMAGE_FILE_MACHINE_AMD64`).
    X86_64,
    /// Anything else: the raw `e_machine` / COFF machine.
    Other(u16),
}

/// The file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Format {
    Elf,
    Pe,
}

/// One mapped interval of an image, in virtual addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappedRegion {
    pub start: u64,
    /// Exclusive.
    pub end: u64,
    /// File offset of `start`, `None` for zero fill.
    pub file_offset: Option<u64>,
    pub executable: bool,
    pub writable: bool,
}

#[derive(Debug, Clone)]
enum Inner<'data> {
    Elf {
        file: Box<ElfFile<'data>>,
        map: MemoryMap,
    },
    Pe(Box<PeFile<'data>>),
}

/// An ELF or PE file, with its memory map.
#[derive(Debug, Clone)]
pub struct Image<'data> {
    inner: Inner<'data>,
    /// Sorted by start, without overlaps.
    regions: Vec<MappedRegion>,
}

/// The file is neither an ELF file nor a PE image that can be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageError {
    Elf(unforge_elf::Error),
    Pe(unforge_pe::Error),
}

impl std::fmt::Display for ImageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageError::Elf(e) => write!(f, "{e}"),
            ImageError::Pe(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ImageError {}

impl<'data> Image<'data> {
    /// Reads `data` as a PE image when it starts with `MZ`, else as ELF.
    pub fn parse(data: &'data [u8]) -> Result<Self, ImageError> {
        if unforge_pe::looks_like_pe(data) {
            return PeFile::parse(data)
                .map(Image::from_pe)
                .map_err(ImageError::Pe);
        }
        ElfFile::parse(data)
            .map(Image::from_elf)
            .map_err(ImageError::Elf)
    }

    pub fn from_elf(file: ElfFile<'data>) -> Self {
        let map = file.memory_map();
        let mut regions: Vec<MappedRegion> = map
            .regions()
            .map(|r| MappedRegion {
                start: r.start,
                end: r.end,
                file_offset: r.file_offset,
                executable: r.flags & PF_X != 0,
                writable: r.flags & PF_W != 0,
            })
            .collect();
        regions.sort_by_key(|r| r.start);
        Image {
            inner: Inner::Elf {
                file: Box::new(file),
                map,
            },
            regions,
        }
    }

    pub fn from_pe(file: PeFile<'data>) -> Self {
        let base = file.image_base();
        let regions = file
            .regions()
            .iter()
            .filter_map(|r| {
                Some(MappedRegion {
                    start: base.checked_add(r.start)?,
                    end: base.checked_add(r.end)?,
                    file_offset: (r.file_len > 0).then_some(r.file_offset),
                    executable: r.is_executable(),
                    writable: r.is_writable(),
                })
            })
            .collect();
        Image {
            inner: Inner::Pe(Box::new(file)),
            regions,
        }
    }

    pub fn format(&self) -> Format {
        match self.inner {
            Inner::Elf { .. } => Format::Elf,
            Inner::Pe(_) => Format::Pe,
        }
    }

    /// The ELF reader, for an ELF file.
    pub fn elf(&self) -> Option<&ElfFile<'data>> {
        match &self.inner {
            Inner::Elf { file, .. } => Some(file.as_ref()),
            Inner::Pe(_) => None,
        }
    }

    /// The ELF memory map (built once), for an ELF file.
    pub fn elf_map(&self) -> Option<&MemoryMap> {
        match &self.inner {
            Inner::Elf { map, .. } => Some(map),
            Inner::Pe(_) => None,
        }
    }

    /// The PE reader, for a PE file.
    pub fn pe(&self) -> Option<&PeFile<'data>> {
        match &self.inner {
            Inner::Pe(p) => Some(p.as_ref()),
            Inner::Elf { .. } => None,
        }
    }

    pub fn data(&self) -> &'data [u8] {
        match &self.inner {
            Inner::Elf { file, .. } => file.data(),
            Inner::Pe(p) => p.data(),
        }
    }

    /// The raw machine field (`e_machine` or the COFF machine).
    pub fn machine(&self) -> u16 {
        match &self.inner {
            Inner::Elf { file, .. } => file.header().machine,
            Inner::Pe(p) => p.machine(),
        }
    }

    pub fn cpu(&self) -> Cpu {
        let m = self.machine();
        match (self.format(), m) {
            (Format::Elf, 62) | (Format::Pe, unforge_pe::MACHINE_AMD64) => Cpu::X86_64,
            (Format::Elf, 3) | (Format::Pe, unforge_pe::MACHINE_I386) => Cpu::X86,
            _ => Cpu::Other(m),
        }
    }

    /// The entry point (a virtual address), if the file has one.
    pub fn entry(&self) -> Option<u64> {
        match &self.inner {
            Inner::Elf { file, .. } => Some(file.header().entry).filter(|&e| e != 0),
            Inner::Pe(p) => p.rva_to_va(u64::from(p.entry_rva()?)),
        }
    }

    /// The file bytes from `va` to where the bytes behind its region stop
    /// (see [`MemoryMap::bytes_at`] and [`PeFile::bytes_at_va`]).
    pub fn bytes_at(&self, va: u64) -> Option<&'data [u8]> {
        match &self.inner {
            Inner::Elf { file, map } => map.bytes_at(file.data(), va),
            Inner::Pe(p) => p.bytes_at_va(va),
        }
    }

    /// The mapped intervals, sorted by start.
    pub fn regions(&self) -> &[MappedRegion] {
        &self.regions
    }

    /// The region containing `va`.
    pub fn region_at(&self, va: u64) -> Option<&MappedRegion> {
        let i = self.regions.partition_point(|r| r.start <= va);
        let r = self.regions.get(i.checked_sub(1)?)?;
        (va < r.end).then_some(r)
    }

    /// `va` is in memory that holds code.
    pub fn is_executable(&self, va: u64) -> bool {
        self.region_at(va).is_some_and(|r| r.executable)
    }

    /// `va` is mapped at all.
    pub fn is_mapped(&self, va: u64) -> bool {
        self.region_at(va).is_some()
    }

    /// The end of the executable region containing `va`.
    pub fn executable_end(&self, va: u64) -> Option<u64> {
        self.region_at(va).filter(|r| r.executable).map(|r| r.end)
    }

    /// The size of a pointer in the image's address space: 8 or 4.
    pub fn pointer_size(&self) -> usize {
        match &self.inner {
            Inner::Elf { file, .. } => match file.header().class {
                unforge_elf::Class::Elf32 => 4,
                _ => 8,
            },
            Inner::Pe(p) => p.kind().pointer_size(),
        }
    }

    /// File ranges of the loaded bytes, merged (so overlapping parts are
    /// scanned once): ELF `PT_LOAD` segments, PE section data. The whole
    /// file when there is none.
    pub fn loaded_file_ranges(&self) -> Vec<(usize, usize)> {
        let data = self.data();
        let len = data.len();
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        let clip = |off: u64, size: u64| {
            let s = usize::try_from(off).unwrap_or(usize::MAX).min(len);
            let e = usize::try_from(off.saturating_add(size))
                .unwrap_or(usize::MAX)
                .min(len);
            (s, e)
        };
        match &self.inner {
            Inner::Elf { file, .. } => {
                if let Ok(phdrs) = file.program_headers() {
                    for ph in phdrs.iter().filter(|p| p.p_type == PT_LOAD) {
                        ranges.push(clip(ph.offset, ph.filesz));
                    }
                }
            }
            Inner::Pe(p) => {
                for r in p.regions().iter().filter(|r| r.section.is_some()) {
                    ranges.push(clip(r.file_offset, r.file_len));
                }
            }
        }
        ranges.retain(|(s, e)| s < e);
        if ranges.is_empty() {
            return vec![(0, len)];
        }
        ranges.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
        for (s, e) in ranges {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        merged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pe_image() {
        let s = unforge_pe::synth::sample(true, false);
        let img = Image::parse(&s.bytes).unwrap();
        assert_eq!(img.format(), Format::Pe);
        assert_eq!(img.cpu(), Cpu::X86_64);
        assert_eq!(img.pointer_size(), 8);
        let main = s.image_base + u64::from(s.main.0);
        assert_eq!(img.entry(), Some(main));
        assert!(img.is_executable(main));
        assert!(!img.is_executable(s.image_base + u64::from(s.hello.0)));
        assert!(
            img.bytes_at(s.image_base + u64::from(s.hello.0))
                .unwrap()
                .starts_with(b"hello")
        );
        assert!(img.executable_end(main).unwrap() > main);
        let s32 = unforge_pe::synth::sample(false, false);
        let img = Image::parse(&s32.bytes).unwrap();
        assert_eq!(img.cpu(), Cpu::X86);
        assert_eq!(img.pointer_size(), 4);
    }

    #[test]
    fn errors() {
        assert!(matches!(Image::parse(b"MZ"), Err(ImageError::Pe(_))));
        assert!(matches!(Image::parse(b"nope"), Err(ImageError::Elf(_))));
    }
}

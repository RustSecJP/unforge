//! Widening the on-disk structures into the class-independent views.

use zerocopy::byteorder::ByteOrder;

use crate::consts::*;
use crate::raw::{Dyn32, Dyn64, Phdr32, Phdr64, Shdr32, Shdr64, Sym32, Sym64};
use crate::table::RawEntry;
use crate::{DynamicEntry, ProgramHeader, SectionHeader, Symbol, SymbolSection};

impl<O: ByteOrder> RawEntry for Phdr32<O> {
    type Wide = ProgramHeader;
    fn widen(&self) -> ProgramHeader {
        ProgramHeader {
            p_type: self.p_type.get(),
            flags: self.p_flags.get(),
            offset: self.p_offset.get().into(),
            vaddr: self.p_vaddr.get().into(),
            paddr: self.p_paddr.get().into(),
            filesz: self.p_filesz.get().into(),
            memsz: self.p_memsz.get().into(),
            align: self.p_align.get().into(),
        }
    }
}

impl<O: ByteOrder> RawEntry for Phdr64<O> {
    type Wide = ProgramHeader;
    fn widen(&self) -> ProgramHeader {
        ProgramHeader {
            p_type: self.p_type.get(),
            flags: self.p_flags.get(),
            offset: self.p_offset.get(),
            vaddr: self.p_vaddr.get(),
            paddr: self.p_paddr.get(),
            filesz: self.p_filesz.get(),
            memsz: self.p_memsz.get(),
            align: self.p_align.get(),
        }
    }
}

impl<O: ByteOrder> RawEntry for Shdr32<O> {
    type Wide = SectionHeader;
    fn widen(&self) -> SectionHeader {
        SectionHeader {
            name: self.sh_name.get(),
            sh_type: self.sh_type.get(),
            flags: self.sh_flags.get().into(),
            addr: self.sh_addr.get().into(),
            offset: self.sh_offset.get().into(),
            size: self.sh_size.get().into(),
            link: self.sh_link.get(),
            info: self.sh_info.get(),
            addralign: self.sh_addralign.get().into(),
            entsize: self.sh_entsize.get().into(),
        }
    }
}

impl<O: ByteOrder> RawEntry for Shdr64<O> {
    type Wide = SectionHeader;
    fn widen(&self) -> SectionHeader {
        SectionHeader {
            name: self.sh_name.get(),
            sh_type: self.sh_type.get(),
            flags: self.sh_flags.get(),
            addr: self.sh_addr.get(),
            offset: self.sh_offset.get(),
            size: self.sh_size.get(),
            link: self.sh_link.get(),
            info: self.sh_info.get(),
            addralign: self.sh_addralign.get(),
            entsize: self.sh_entsize.get(),
        }
    }
}

/// `st_shndx` before `SHN_XINDEX` resolution. `SHN_XINDEX` starts out as
/// [`SymbolSection::Unresolved`]; [`crate::SymbolTable`] replaces it when the
/// `SHT_SYMTAB_SHNDX` entry is usable.
pub(crate) fn classify_shndx(shndx: u16) -> SymbolSection {
    match shndx {
        SHN_UNDEF => SymbolSection::Undefined,
        SHN_ABS => SymbolSection::Absolute,
        SHN_COMMON => SymbolSection::Common,
        SHN_XINDEX => SymbolSection::Unresolved,
        n if n >= SHN_LORESERVE => SymbolSection::Reserved(n),
        n => SymbolSection::Index(n.into()),
    }
}

impl<O: ByteOrder> RawEntry for Sym32<O> {
    type Wide = Symbol;
    fn widen(&self) -> Symbol {
        let raw_shndx = self.st_shndx.get();
        Symbol {
            name: self.st_name.get(),
            value: self.st_value.get().into(),
            size: self.st_size.get().into(),
            info: self.st_info,
            other: self.st_other,
            raw_shndx,
            section: classify_shndx(raw_shndx),
        }
    }
}

impl<O: ByteOrder> RawEntry for Sym64<O> {
    type Wide = Symbol;
    fn widen(&self) -> Symbol {
        let raw_shndx = self.st_shndx.get();
        Symbol {
            name: self.st_name.get(),
            value: self.st_value.get(),
            size: self.st_size.get(),
            info: self.st_info,
            other: self.st_other,
            raw_shndx,
            section: classify_shndx(raw_shndx),
        }
    }
}

impl<O: ByteOrder> RawEntry for Dyn32<O> {
    type Wide = DynamicEntry;
    fn widen(&self) -> DynamicEntry {
        DynamicEntry {
            tag: self.d_tag.get().into(),
            value: self.d_val.get().into(),
        }
    }
}

impl<O: ByteOrder> RawEntry for Dyn64<O> {
    type Wide = DynamicEntry;
    fn widen(&self) -> DynamicEntry {
        DynamicEntry {
            tag: self.d_tag.get(),
            value: self.d_val.get(),
        }
    }
}

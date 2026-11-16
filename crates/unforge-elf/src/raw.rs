//! On-disk ELF structures, exactly as laid out in the file.
//!
//! Field order and widths follow the System V gABI, chapter 4:
//! <https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html> (header),
//! <https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.sheader.html> (sections),
//! <https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.symtab.html> (symbols),
//! <https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.pheader.html> (program headers).
//!
//! Design notes:
//! - Every multi-byte field is a `zerocopy::byteorder` integer (`U16<O>` etc.).
//!   These have alignment 1, so every struct here is `Unaligned`: reading from an
//!   arbitrary file offset can never fail because of alignment, only because of size.
//! - Endianness is a type parameter `O`. The file's byte order is only known at
//!   run time (see [`crate::Layout`] for how it is decided), so callers pick
//!   `LittleEndian` / `BigEndian` once and monomorphize the rest.
//! - ELF32 and ELF64 are separate types because the layouts genuinely differ
//!   (not only widths: `p_flags` and the `st_*` fields move).
//! - The sizes are asserted at compile time below; they must match the gABI.

use zerocopy::byteorder::{ByteOrder, I32, I64, U16, U32, U64};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// `e_ident`, common to both classes. 16 bytes.
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Ident {
    pub magic: [u8; 4],
    pub class: u8,
    pub data: u8,
    pub version: u8,
    pub os_abi: u8,
    pub abi_version: u8,
    pub pad: [u8; 7],
}

#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Ehdr32<O: ByteOrder> {
    pub e_ident: Ident,
    pub e_type: U16<O>,
    pub e_machine: U16<O>,
    pub e_version: U32<O>,
    pub e_entry: U32<O>,
    pub e_phoff: U32<O>,
    pub e_shoff: U32<O>,
    pub e_flags: U32<O>,
    pub e_ehsize: U16<O>,
    pub e_phentsize: U16<O>,
    pub e_phnum: U16<O>,
    pub e_shentsize: U16<O>,
    pub e_shnum: U16<O>,
    pub e_shstrndx: U16<O>,
}

#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Ehdr64<O: ByteOrder> {
    pub e_ident: Ident,
    pub e_type: U16<O>,
    pub e_machine: U16<O>,
    pub e_version: U32<O>,
    pub e_entry: U64<O>,
    pub e_phoff: U64<O>,
    pub e_shoff: U64<O>,
    pub e_flags: U32<O>,
    pub e_ehsize: U16<O>,
    pub e_phentsize: U16<O>,
    pub e_phnum: U16<O>,
    pub e_shentsize: U16<O>,
    pub e_shnum: U16<O>,
    pub e_shstrndx: U16<O>,
}

#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Phdr32<O: ByteOrder> {
    pub p_type: U32<O>,
    pub p_offset: U32<O>,
    pub p_vaddr: U32<O>,
    pub p_paddr: U32<O>,
    pub p_filesz: U32<O>,
    pub p_memsz: U32<O>,
    pub p_flags: U32<O>,
    pub p_align: U32<O>,
}

/// Note: `p_flags` is the 2nd field in ELF64 but the 7th in ELF32.
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Phdr64<O: ByteOrder> {
    pub p_type: U32<O>,
    pub p_flags: U32<O>,
    pub p_offset: U64<O>,
    pub p_vaddr: U64<O>,
    pub p_paddr: U64<O>,
    pub p_filesz: U64<O>,
    pub p_memsz: U64<O>,
    pub p_align: U64<O>,
}

#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Shdr32<O: ByteOrder> {
    pub sh_name: U32<O>,
    pub sh_type: U32<O>,
    pub sh_flags: U32<O>,
    pub sh_addr: U32<O>,
    pub sh_offset: U32<O>,
    pub sh_size: U32<O>,
    pub sh_link: U32<O>,
    pub sh_info: U32<O>,
    pub sh_addralign: U32<O>,
    pub sh_entsize: U32<O>,
}

#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Shdr64<O: ByteOrder> {
    pub sh_name: U32<O>,
    pub sh_type: U32<O>,
    pub sh_flags: U64<O>,
    pub sh_addr: U64<O>,
    pub sh_offset: U64<O>,
    pub sh_size: U64<O>,
    pub sh_link: U32<O>,
    pub sh_info: U32<O>,
    pub sh_addralign: U64<O>,
    pub sh_entsize: U64<O>,
}

#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Sym32<O: ByteOrder> {
    pub st_name: U32<O>,
    pub st_value: U32<O>,
    pub st_size: U32<O>,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: U16<O>,
}

/// Note: the field order differs from `Sym32` (`st_info`..`st_shndx` come first).
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Sym64<O: ByteOrder> {
    pub st_name: U32<O>,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: U16<O>,
    pub st_value: U64<O>,
    pub st_size: U64<O>,
}

/// gABI ch5 "Dynamic Section", `Elf32_Dyn`: `d_tag` is an `Elf32_Sword`.
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Dyn32<O: ByteOrder> {
    pub d_tag: I32<O>,
    pub d_val: U32<O>,
}

/// gABI ch5 "Dynamic Section", `Elf64_Dyn`: `d_tag` is an `Elf64_Sxword`.
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Dyn64<O: ByteOrder> {
    pub d_tag: I64<O>,
    pub d_val: U64<O>,
}

// Sizes fixed by the gABI. If any of these fail, the layout above is wrong.
const _: () = {
    use core::mem::size_of;
    use zerocopy::byteorder::LittleEndian as L;
    assert!(size_of::<Ident>() == 16);
    assert!(size_of::<Ehdr32<L>>() == 52);
    assert!(size_of::<Ehdr64<L>>() == 64);
    assert!(size_of::<Phdr32<L>>() == 32);
    assert!(size_of::<Phdr64<L>>() == 56);
    assert!(size_of::<Shdr32<L>>() == 40);
    assert!(size_of::<Shdr64<L>>() == 64);
    assert!(size_of::<Sym32<L>>() == 16);
    assert!(size_of::<Sym64<L>>() == 24);
    assert!(size_of::<Dyn32<L>>() == 8);
    assert!(size_of::<Dyn64<L>>() == 16);
};

//! Numeric constants from the System V gABI
//! (<https://www.sco.com/developers/gabi/latest/contents.html>) and, for
//! machine numbers, the registry kept in the same document.

pub const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];

pub const ELFCLASS32: u8 = 1;
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const ELFDATA2MSB: u8 = 2;
pub const EV_CURRENT: u8 = 1;

pub const ELFOSABI_NONE: u8 = 0;
pub const ELFOSABI_GNU: u8 = 3;

pub const ET_NONE: u16 = 0;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;

pub const EM_NONE: u16 = 0;
pub const EM_SPARC: u16 = 2;
pub const EM_386: u16 = 3;
pub const EM_MIPS: u16 = 8;
pub const EM_PPC: u16 = 20;
pub const EM_PPC64: u16 = 21;
pub const EM_S390: u16 = 22;
pub const EM_ARM: u16 = 40;
pub const EM_SPARCV9: u16 = 43;
pub const EM_IA_64: u16 = 50;
pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;
pub const EM_RISCV: u16 = 243;
pub const EM_LOONGARCH: u16 = 258;

/// `e_flags` mask of the 64-bit PowerPC ELF ABI version (1 = ELFv1 with
/// function descriptors, 2 = ELFv2; 64-bit PowerPC ELF ABI supplements).
pub const EF_PPC64_ABI: u32 = 3;

/// `e_phnum` value meaning "the real count is in section 0's `sh_info`".
/// gABI ch4 "ELF Header", `e_phnum`.
pub const PN_XNUM: u16 = 0xffff;

pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_LOOS: u32 = 0x6000_0000;
pub const PT_HIOS: u32 = 0x6fff_ffff;
pub const PT_LOPROC: u32 = 0x7000_0000;
pub const PT_HIPROC: u32 = 0x7fff_ffff;
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;
pub const PT_GNU_PROPERTY: u32 = 0x6474_e553;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub const SHN_UNDEF: u16 = 0;
pub const SHN_LORESERVE: u16 = 0xff00;
pub const SHN_ABS: u16 = 0xfff1;
pub const SHN_COMMON: u16 = 0xfff2;
/// "The real index is elsewhere": in section 0 (for `e_shstrndx`) or in a
/// `SHT_SYMTAB_SHNDX` section (for `st_shndx`).
pub const SHN_XINDEX: u16 = 0xffff;

pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_SHLIB: u32 = 10;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_INIT_ARRAY: u32 = 14;
pub const SHT_FINI_ARRAY: u32 = 15;
pub const SHT_PREINIT_ARRAY: u32 = 16;
pub const SHT_GROUP: u32 = 17;
pub const SHT_SYMTAB_SHNDX: u32 = 18;

pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const SHF_TLS: u64 = 0x400;

pub const DT_NULL: i64 = 0;
pub const DT_HASH: i64 = 4;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_STRSZ: i64 = 10;
pub const DT_SYMENT: i64 = 11;
/// GNU extension (not in the gABI): the GNU-style hash table.
pub const DT_GNU_HASH: i64 = 0x6fff_fef5;

/// Note type of the GNU property note (`PT_GNU_PROPERTY`).
pub const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
pub const GNU_PROPERTY_AARCH64_FEATURE_1_AND: u32 = 0xc000_0000;

pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;

pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;
pub const STT_COMMON: u8 = 5;
pub const STT_TLS: u8 = 6;

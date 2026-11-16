//! Human-readable names for ELF numeric fields.
//!
//! Unless noted otherwise, values come from the System V gABI, chapter 4
//! (<https://www.sco.com/developers/gabi/latest/ch4.eheader.html>,
//! <https://www.sco.com/developers/gabi/latest/ch4.sheader.html>,
//! <https://www.sco.com/developers/gabi/latest/ch4.symtab.html>) and chapter 5
//! (<https://www.sco.com/developers/gabi/latest/ch5.pheader.html>).
//!
//! GNU extensions (`PT_GNU_*`, `SHT_GNU_*`, `STB_GNU_UNIQUE`, `STT_GNU_IFUNC`,
//! `SHF_GNU_RETAIN`) are *not* part of the gABI; their values are taken from
//! glibc's `elf.h`. x86-64 specific values come from the System V AMD64 psABI,
//! section "Sections" (`SHT_X86_64_UNWIND`, `SHF_X86_64_LARGE`).
//! Values in OS/processor-specific ranges are only decoded when their meaning
//! is unambiguous for the given `e_machine` / `EI_OSABI`; otherwise they are
//! printed as an offset into the range (e.g. `LOOS+0x5`).

use std::fmt::Write as _;

use unforge_elf::SymbolSection;
use unforge_elf::consts::*;

/// `EI_OSABI` values that use the GNU extensions (`ELFOSABI_NONE`, `ELFOSABI_GNU`).
fn is_gnu_osabi(os_abi: u8) -> bool {
    matches!(os_abi, 0 | 3)
}

pub fn class(c: unforge_elf::Class) -> &'static str {
    match c {
        unforge_elf::Class::Elf32 => "ELF32",
        unforge_elf::Class::Elf64 => "ELF64",
        _ => "unknown class",
    }
}

pub fn endian(e: unforge_elf::Endian) -> &'static str {
    match e {
        unforge_elf::Endian::Little => "little endian (ELFDATA2LSB)",
        unforge_elf::Endian::Big => "big endian (ELFDATA2MSB)",
        _ => "unknown byte order",
    }
}

/// `EI_OSABI` (gABI ch4, "ELF Identification").
pub fn os_abi(v: u8) -> String {
    let name = match v {
        0 => "NONE (UNIX System V)",
        1 => "HPUX",
        2 => "NETBSD",
        3 => "GNU (Linux)",
        6 => "SOLARIS",
        7 => "AIX",
        8 => "IRIX",
        9 => "FREEBSD",
        10 => "TRU64",
        11 => "MODESTO",
        12 => "OPENBSD",
        13 => "OPENVMS",
        14 => "NSK",
        15 => "AROS",
        16 => "FENIXOS",
        17 => "CLOUDABI",
        18 => "OPENVOS",
        64..=255 => "processor-specific",
        _ => "unknown",
    };
    format!("{name} ({v})")
}

/// `e_type`.
pub fn e_type(v: u16) -> String {
    let name = match v {
        ET_NONE => "NONE",
        ET_REL => "REL (relocatable)",
        ET_EXEC => "EXEC (executable)",
        ET_DYN => "DYN (shared object / PIE)",
        ET_CORE => "CORE (core file)",
        0xfe00..=0xfeff => "OS-specific",
        0xff00..=0xffff => "processor-specific",
        _ => "unknown",
    };
    format!("{name} ({v:#x})")
}

/// `e_machine`. Values from the gABI ch4 `e_machine` table; `EM_BPF` and
/// `EM_LOONGARCH` as in glibc `elf.h`.
pub fn machine(v: u16) -> String {
    let name = match v {
        0 => "NONE",
        2 => "SPARC",
        3 => "386 (Intel 80386)",
        4 => "68K",
        8 => "MIPS",
        20 => "PPC (PowerPC)",
        21 => "PPC64 (64-bit PowerPC)",
        22 => "S390 (IBM System/390, also s390x)",
        40 => "ARM (32-bit)",
        42 => "SH (SuperH)",
        43 => "SPARCV9",
        50 => "IA_64",
        62 => "X86_64 (AMD x86-64)",
        183 => "AARCH64",
        243 => "RISCV",
        247 => "BPF",
        258 => "LOONGARCH",
        _ => "unknown",
    };
    format!("{name} ({v})")
}

/// Offset of `v` into `[lo, hi]`, formatted as `PREFIX+0x..`, if it is in range.
fn in_range<T>(v: T, lo: T, hi: T, prefix: &str) -> Option<String>
where
    T: PartialOrd + Copy + std::ops::Sub<Output = T> + std::fmt::LowerHex,
{
    // `v >= lo` is checked first, so the subtraction cannot underflow.
    (v >= lo && v <= hi).then(|| format!("{prefix}+{:#x}", v - lo))
}

/// `p_type`.
pub fn p_type(v: u32) -> String {
    let s = match v {
        PT_NULL => "NULL",
        PT_LOAD => "LOAD",
        PT_DYNAMIC => "DYNAMIC",
        PT_INTERP => "INTERP",
        PT_NOTE => "NOTE",
        PT_SHLIB => "SHLIB",
        PT_PHDR => "PHDR",
        PT_TLS => "TLS",
        PT_GNU_EH_FRAME => "GNU_EH_FRAME",
        PT_GNU_STACK => "GNU_STACK",
        PT_GNU_RELRO => "GNU_RELRO",
        PT_GNU_PROPERTY => "GNU_PROPERTY",
        _ => {
            return in_range(v, 0x6000_0000, 0x6fff_ffff, "LOOS")
                .or_else(|| in_range(v, 0x7000_0000, 0x7fff_ffff, "LOPROC"))
                .unwrap_or_else(|| format!("{v:#x}"));
        }
    };
    s.to_string()
}

/// `p_flags` as three letters `R`, `W`, `X` (`-` when clear), followed by
/// `+0x..` for any other bits (`PF_MASKOS` / `PF_MASKPROC` or undefined).
pub fn p_flags(v: u32) -> String {
    let mut s = String::with_capacity(3);
    s.push(if v & PF_R != 0 { 'R' } else { '-' });
    s.push(if v & PF_W != 0 { 'W' } else { '-' });
    s.push(if v & PF_X != 0 { 'X' } else { '-' });
    let rest = v & !(PF_R | PF_W | PF_X);
    if rest != 0 {
        let _ = write!(s, "+{rest:#x}");
    }
    s
}

/// `sh_type`. `machine` and `os_abi` select which specific-range values are decoded.
pub fn sh_type(v: u32, machine: u16, os_abi: u8) -> String {
    let s = match v {
        SHT_NULL => "NULL",
        SHT_PROGBITS => "PROGBITS",
        SHT_SYMTAB => "SYMTAB",
        SHT_STRTAB => "STRTAB",
        SHT_RELA => "RELA",
        SHT_HASH => "HASH",
        SHT_DYNAMIC => "DYNAMIC",
        SHT_NOTE => "NOTE",
        SHT_NOBITS => "NOBITS",
        SHT_REL => "REL",
        SHT_SHLIB => "SHLIB",
        SHT_DYNSYM => "DYNSYM",
        SHT_INIT_ARRAY => "INIT_ARRAY",
        SHT_FINI_ARRAY => "FINI_ARRAY",
        SHT_PREINIT_ARRAY => "PREINIT_ARRAY",
        SHT_GROUP => "GROUP",
        SHT_SYMTAB_SHNDX => "SYMTAB_SHNDX",
        // SHT_RELR: value from glibc elf.h. Not checked against the gABI text
        // (the sco.com draft predates it), so treat as a de-facto extension.
        19 => "RELR",
        // GNU extensions (glibc elf.h).
        0x6fff_fff5 if is_gnu_osabi(os_abi) => "GNU_ATTRIBUTES",
        0x6fff_fff6 if is_gnu_osabi(os_abi) => "GNU_HASH",
        0x6fff_fff7 if is_gnu_osabi(os_abi) => "GNU_LIBLIST",
        0x6fff_fffd if is_gnu_osabi(os_abi) => "GNU_VERDEF",
        0x6fff_fffe if is_gnu_osabi(os_abi) => "GNU_VERNEED",
        0x6fff_ffff if is_gnu_osabi(os_abi) => "GNU_VERSYM",
        // System V AMD64 psABI, "Sections".
        0x7000_0001 if machine == EM_X86_64 => "X86_64_UNWIND",
        _ => {
            return in_range(v, 0x6000_0000, 0x6fff_ffff, "LOOS")
                .or_else(|| in_range(v, 0x7000_0000, 0x7fff_ffff, "LOPROC"))
                .or_else(|| in_range(v, 0x8000_0000, 0xffff_ffff, "LOUSER"))
                .unwrap_or_else(|| format!("{v:#x}"));
        }
    };
    s.to_string()
}

/// Letters used for `sh_flags`, in the order they are printed.
/// The letters follow GNU readelf's conventions.
const SH_FLAG_LETTERS: &[(u64, char, &str)] = &[
    (SHF_WRITE, 'W', "write"),
    (SHF_ALLOC, 'A', "alloc"),
    (SHF_EXECINSTR, 'X', "execute"),
    (0x10, 'M', "merge"),
    (0x20, 'S', "strings"),
    (0x40, 'I', "info link"),
    (0x80, 'L', "link order"),
    (0x100, 'O', "OS nonconforming"),
    (0x200, 'G', "group"),
    (0x400, 'T', "TLS"),
    (0x800, 'C', "compressed"),
];

/// `SHF_GNU_RETAIN` (glibc elf.h).
const SHF_GNU_RETAIN: u64 = 0x20_0000;
/// `SHF_X86_64_LARGE` (System V AMD64 psABI, "Sections").
const SHF_X86_64_LARGE: u64 = 0x1000_0000;
/// `SHF_EXCLUDE` (glibc elf.h: "Section is excluded unless referenced or
/// allocated (Solaris)"). The bit lies in `SHF_MASKPROC` (0xf0000000, gABI ch4
/// "Sections": "reserved for processor-specific semantics"), so it is only
/// named for machines that do not give the bit another meaning.
const SHF_EXCLUDE: u64 = 0x8000_0000;

/// Machines that assign their own meaning to bit 0x80000000 of `sh_flags`.
/// Values as in glibc / binutils `elf.h` (mirrored by the `object` crate):
/// `SHF_MIPS_STRINGS` (EM_MIPS 8, EM_MIPS_RS3_LE 10), `SHF_PARISC_SBP`
/// (EM_PARISC 15), `SHF_ARM_COMDEF` (EM_ARM 40). This list is what those
/// headers define, not an exhaustive survey of every processor supplement.
fn shf_exclude_is_other(machine: u16) -> bool {
    matches!(machine, 8 | 10 | 15 | EM_ARM)
}

pub fn sh_flags_key() -> String {
    let mut s = String::from("Key to Flags:");
    for (i, (_, c, name)) in SH_FLAG_LETTERS.iter().enumerate() {
        let sep = if i == 0 { " " } else { ", " };
        let _ = write!(s, "{sep}{c} ({name})");
    }
    s.push_str(",\n  R (GNU retain), l (x86-64 large), E (exclude), +0x.. (other bits), - (none)");
    s
}

/// `sh_flags` as letters (see [`sh_flags_key`]), `-` when no flag is set.
pub fn sh_flags(v: u64, machine: u16, os_abi: u8) -> String {
    let mut s = String::new();
    let mut rest = v;
    for &(bit, c, _) in SH_FLAG_LETTERS {
        if v & bit != 0 {
            s.push(c);
            rest &= !bit;
        }
    }
    if is_gnu_osabi(os_abi) && v & SHF_GNU_RETAIN != 0 {
        s.push('R');
        rest &= !SHF_GNU_RETAIN;
    }
    if machine == EM_X86_64 && v & SHF_X86_64_LARGE != 0 {
        s.push('l');
        rest &= !SHF_X86_64_LARGE;
    }
    if !shf_exclude_is_other(machine) && v & SHF_EXCLUDE != 0 {
        s.push('E');
        rest &= !SHF_EXCLUDE;
    }
    if rest != 0 {
        let _ = write!(s, "+{rest:#x}");
    }
    if s.is_empty() {
        s.push('-');
    }
    s
}

/// `ELF_ST_BIND`.
pub fn sym_bind(v: u8, os_abi: u8) -> String {
    let s = match v {
        STB_LOCAL => "LOCAL",
        STB_GLOBAL => "GLOBAL",
        STB_WEAK => "WEAK",
        // STB_GNU_UNIQUE (glibc elf.h).
        10 if is_gnu_osabi(os_abi) => "UNIQUE",
        10..=12 => return format!("LOOS+{}", v.saturating_sub(10)),
        13..=15 => return format!("LOPROC+{}", v.saturating_sub(13)),
        _ => return format!("{v}"),
    };
    s.to_string()
}

/// `ELF_ST_TYPE`.
pub fn sym_type(v: u8, os_abi: u8) -> String {
    let s = match v {
        STT_NOTYPE => "NOTYPE",
        STT_OBJECT => "OBJECT",
        STT_FUNC => "FUNC",
        STT_SECTION => "SECTION",
        STT_FILE => "FILE",
        STT_COMMON => "COMMON",
        STT_TLS => "TLS",
        // STT_GNU_IFUNC (glibc elf.h).
        10 if is_gnu_osabi(os_abi) => "IFUNC",
        10..=12 => return format!("LOOS+{}", v.saturating_sub(10)),
        13..=15 => return format!("LOPROC+{}", v.saturating_sub(13)),
        _ => return format!("{v}"),
    };
    s.to_string()
}

/// `ELF_ST_VISIBILITY`.
pub fn sym_visibility(v: u8) -> &'static str {
    match v & 3 {
        0 => "DEFAULT",
        1 => "INTERNAL",
        2 => "HIDDEN",
        _ => "PROTECTED",
    }
}

/// `st_shndx`, after `SHN_XINDEX` resolution.
pub fn sym_section(s: SymbolSection) -> String {
    match s {
        SymbolSection::Undefined => "UND".into(),
        SymbolSection::Absolute => "ABS".into(),
        SymbolSection::Common => "COM".into(),
        SymbolSection::Index(i) => i.to_string(),
        SymbolSection::Reserved(r) => format!("{r:#x}"),
        SymbolSection::Unresolved => "XINDEX?".into(),
        _ => "?".into(),
    }
}

/// Render a name from a string table for display.
///
/// ELF names are byte strings with no required encoding. Valid UTF-8 is shown
/// as-is, except that control characters, whitespace other than U+0020 and
/// backslashes are escaped (`\n`, `\u{..}`, `\\`); bytes that are not valid
/// UTF-8 are shown as `\xNN`. The output is unambiguous and never contains
/// characters that could corrupt the table layout.
pub fn escape(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                ' ' => out.push_str("\\x20"),
                c if c.is_control() || c.is_whitespace() => {
                    out.extend(c.escape_default());
                }
                c => out.push(c),
            }
        }
        for b in chunk.invalid() {
            let _ = write!(out, "\\x{b:02x}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_keeps_plain_ascii() {
        assert_eq!(escape(b".text"), ".text");
        assert_eq!(
            escape(b"_ZN4core3fmt5write17h0123456789abcdefE"),
            "_ZN4core3fmt5write17h0123456789abcdefE"
        );
    }

    #[test]
    fn escape_non_utf8_and_controls() {
        assert_eq!(escape(b"bad\xffname"), "bad\\xffname");
        assert_eq!(escape(b"a\nb"), "a\\nb");
        assert_eq!(escape(b"a b"), "a\\x20b");
        assert_eq!(escape(b"a\\b"), "a\\\\b");
        assert_eq!(escape("é".as_bytes()), "é");
        // Truncated UTF-8 sequence.
        assert_eq!(escape(b"\xe3\x81"), "\\xe3\\x81");
    }

    #[test]
    fn flags() {
        assert_eq!(p_flags(PF_R | PF_X), "R-X");
        assert_eq!(p_flags(0x10_0000 | PF_W), "-W-+0x100000");
        assert_eq!(sh_flags(0, EM_X86_64, 0), "-");
        assert_eq!(sh_flags(SHF_ALLOC | SHF_EXECINSTR, EM_X86_64, 0), "AX");
        assert_eq!(sh_flags(0x30 | SHF_ALLOC, EM_X86_64, 0), "AMS");
        assert_eq!(sh_flags(SHF_X86_64_LARGE, EM_X86_64, 0), "l");
        assert_eq!(sh_flags(SHF_X86_64_LARGE, EM_AARCH64, 0), "+0x10000000");
        assert_eq!(sh_flags(SHF_EXCLUDE, EM_X86_64, 0), "E");
        assert_eq!(sh_flags(SHF_EXCLUDE | SHF_ALLOC, EM_AARCH64, 0), "AE");
        // SHF_MIPS_STRINGS / SHF_ARM_COMDEF share the bit: not 'E'.
        assert_eq!(sh_flags(SHF_EXCLUDE, 8, 0), "+0x80000000");
        assert_eq!(sh_flags(SHF_EXCLUDE, EM_ARM, 0), "+0x80000000");
    }

    #[test]
    fn ranges() {
        assert_eq!(p_type(0x6000_0005), "LOOS+0x5");
        assert_eq!(p_type(0x7000_0000), "LOPROC+0x0");
        assert_eq!(p_type(0x1234), "0x1234");
        assert_eq!(sh_type(0x7000_0001, EM_X86_64, 0), "X86_64_UNWIND");
        assert_eq!(sh_type(0x7000_0001, EM_ARM, 0), "LOPROC+0x1");
        assert_eq!(sh_type(0x6fff_fff6, EM_X86_64, 9), "LOOS+0xffffff6");
        assert_eq!(sym_bind(10, 3), "UNIQUE");
        assert_eq!(sym_bind(10, 9), "LOOS+0");
        assert_eq!(sym_type(15, 0), "LOPROC+2");
    }
}

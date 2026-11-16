//! Hand-made minimal ELF64 executables, byte by byte.
//!
//! Every file has the same payload: `write(1, "UNFORGE_OK\n", 11)` then
//! `exit(42)`, in position-independent code, so the oracle probe can tell
//! "the first instruction ran" from "the process died before it".
//!
//! Layout of the non-overlapping form (`Image::standard`):
//!
//! | file offset | contents |
//! |---|---|
//! | 0x000 | ELF header (64 bytes) |
//! | 0x040 | program header table (up to 4 entries) |
//! | 0x120 | code + marker string |
//! | 0x160 | `PT_INTERP` string or a `PT_GNU_PROPERTY` note |
//! | 0x1a0 | `PT_DYNAMIC` entries (5 x 16 bytes) |
//! | 0x1f0 | one NUL byte (`DT_STRTAB`) |
//! | 0x1f8 | one all-zero `Elf64_Sym` (`DT_SYMTAB`) |
//! | 0x210 | end of file |

use crate::Arch;
use crate::elf::{EM_AARCH64, EM_X86_64, PF_R, PF_X, PT_LOAD, Phdr, eh};

pub const BASE: u64 = 0x40_0000;
pub const CODE_OFF: usize = 0x120;
pub const AUX_OFF: usize = 0x160;
pub const DYN_OFF: usize = 0x1a0;
pub const STR_OFF: usize = 0x1f0;
pub const SYM_OFF: usize = 0x1f8;
pub const FILE_LEN: usize = 0x210;
pub const PHDR_OFF: usize = 0x40;

/// `write(1, marker, 11); exit(42)` followed by the marker.
pub fn payload(arch: Arch) -> Vec<u8> {
    let mut v = Vec::new();
    match arch {
        Arch::Aarch64 => {
            // A64 encodings (Arm ARM, "MOVZ", "ADR", "SVC"):
            for insn in [
                0x1000_0101u32, // adr  x1, #32       (the marker, 8 insns ahead)
                0xd280_0020,    // movz x0, #1        (fd)
                0xd280_0162,    // movz x2, #11       (len)
                0xd280_0808,    // movz x8, #64       (__NR_write)
                0xd400_0001,    // svc  #0
                0xd280_0540,    // movz x0, #42
                0xd280_0ba8,    // movz x8, #93       (__NR_exit)
                0xd400_0001,    // svc  #0
            ] {
                v.extend_from_slice(&insn.to_le_bytes());
            }
        }
        Arch::X86_64 => {
            v.extend_from_slice(&[0xbf, 1, 0, 0, 0]); // mov edi, 1
            v.extend_from_slice(&[0x48, 0x8d, 0x35, 0x18, 0, 0, 0]); // lea rsi, [rip+0x18]
            v.extend_from_slice(&[0xba, 11, 0, 0, 0]); // mov edx, 11
            v.extend_from_slice(&[0xb8, 1, 0, 0, 0]); // mov eax, 1 (__NR_write)
            v.extend_from_slice(&[0x0f, 0x05]); // syscall
            v.extend_from_slice(&[0xbf, 42, 0, 0, 0]); // mov edi, 42
            v.extend_from_slice(&[0xb8, 60, 0, 0, 0]); // mov eax, 60 (__NR_exit)
            v.extend_from_slice(&[0x0f, 0x05]); // syscall
            assert_eq!(v.len(), 36);
        }
    }
    v.extend_from_slice(b"UNFORGE_OK\n");
    v
}

pub fn machine(arch: Arch) -> u16 {
    match arch {
        Arch::Aarch64 => EM_AARCH64,
        Arch::X86_64 => EM_X86_64,
    }
}

pub fn interp_path(arch: Arch) -> &'static [u8] {
    // The glibc dynamic loader in the oracle image (Debian bookworm).
    match arch {
        Arch::Aarch64 => b"/lib/ld-linux-aarch64.so.1\0",
        Arch::X86_64 => b"/lib64/ld-linux-x86-64.so.2\0",
    }
}

/// Write an ELF64 little-endian header into `d[0..64]`.
#[allow(clippy::too_many_arguments)]
pub fn write_ehdr(d: &mut [u8], arch: Arch, e_type: u16, entry: u64, phoff: u64, phnum: u16) {
    d[0..4].copy_from_slice(b"\x7fELF");
    d[4] = 2; // ELFCLASS64
    d[5] = 1; // ELFDATA2LSB
    d[6] = 1; // EV_CURRENT
    let put16 = |d: &mut [u8], o: usize, v: u16| d[o..o + 2].copy_from_slice(&v.to_le_bytes());
    put16(d, eh::E_TYPE, e_type);
    put16(d, eh::E_MACHINE, machine(arch));
    d[eh::E_VERSION..eh::E_VERSION + 4].copy_from_slice(&1u32.to_le_bytes());
    d[eh::E_ENTRY..eh::E_ENTRY + 8].copy_from_slice(&entry.to_le_bytes());
    d[eh::E_PHOFF..eh::E_PHOFF + 8].copy_from_slice(&phoff.to_le_bytes());
    put16(d, eh::E_EHSIZE, 64);
    put16(d, eh::E_PHENTSIZE, 56);
    put16(d, eh::E_PHNUM, phnum);
}

/// The standard (non-overlapping) image with the given program headers
/// written at `PHDR_OFF`. `ET_EXEC` (2), entry at `BASE + CODE_OFF`.
pub fn standard(arch: Arch, phdrs: &[Phdr]) -> Vec<u8> {
    assert!(phdrs.len() <= 4);
    let mut d = vec![0u8; FILE_LEN];
    let code = payload(arch);
    d[CODE_OFF..CODE_OFF + code.len()].copy_from_slice(&code);
    write_ehdr(
        &mut d,
        arch,
        2,
        BASE + CODE_OFF as u64,
        PHDR_OFF as u64,
        u16::try_from(phdrs.len()).expect("phnum"),
    );
    for (i, p) in phdrs.iter().enumerate() {
        let o = PHDR_OFF + 56 * i;
        d[o..o + 56].copy_from_slice(&p.encode());
    }
    d
}

/// One `PT_LOAD` mapping the whole standard image read+execute at `BASE`.
pub fn whole_load(flags: u32) -> Phdr {
    Phdr {
        p_type: PT_LOAD,
        p_flags: flags,
        p_offset: 0,
        p_vaddr: BASE,
        p_paddr: BASE,
        p_filesz: FILE_LEN as u64,
        p_memsz: FILE_LEN as u64,
        p_align: 0x1000,
    }
}

pub fn rx_load() -> Phdr {
    whole_load(PF_R | PF_X)
}

/// The overlapping "tiny ELF" form (TECHNIQUES.md T10): `e_phoff = 0x38`, so
/// `p_type` overlaps `e_phnum` + `e_shentsize` and `p_flags` overlaps
/// `e_shnum` + `e_shstrndx`. Code at 0x70. `p_filesz`/`p_memsz`/`p_flags` are
/// parameters for the T14 variants.
pub fn overlapped(arch: Arch, flags: u32, filesz: Option<u64>, memsz: Option<u64>) -> Vec<u8> {
    let code = payload(arch);
    let len = 0x70 + code.len();
    let mut d = vec![0u8; len];
    write_ehdr(&mut d, arch, 2, BASE + 0x70, 0x38, 1);
    let ph = Phdr {
        p_type: PT_LOAD,
        p_flags: flags,
        p_offset: 0,
        p_vaddr: BASE,
        p_paddr: BASE,
        p_filesz: filesz.unwrap_or(len as u64),
        p_memsz: memsz.unwrap_or(len as u64),
        p_align: 0x1000,
    };
    // Bytes 0x38..0x40 now belong to both the ELF header and the phdr.
    d[0x38..0x70].copy_from_slice(&ph.encode());
    d[0x70..].copy_from_slice(&code);
    d
}

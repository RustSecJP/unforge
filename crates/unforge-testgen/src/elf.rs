//! A minimal ELF64 little-endian editor for building test files.
//!
//! This is deliberately independent of `unforge-elf`: the corpus it produces
//! is used to test that crate, so it must not share its parsing code. It only
//! knows fixed field offsets (gABI ch4 "ELF Header", ch4 "Sections", ch5
//! "Program Header", ELF64 layout) and panics on a seed it does not
//! understand; it is a build tool, not a reader of hostile input.

pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;

pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
pub const PT_GNU_PROPERTY: u32 = 0x6474_e553;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_NOBITS: u32 = 8;

pub const EHDR_SIZE: usize = 64;
pub const PHDR_SIZE: usize = 56;
pub const SHDR_SIZE: usize = 64;
pub const SYM_SIZE: usize = 24;

/// ELF header field offsets (ELF64).
pub mod eh {
    pub const E_TYPE: usize = 0x10;
    pub const E_MACHINE: usize = 0x12;
    pub const E_VERSION: usize = 0x14;
    pub const E_ENTRY: usize = 0x18;
    pub const E_PHOFF: usize = 0x20;
    pub const E_SHOFF: usize = 0x28;
    pub const E_FLAGS: usize = 0x30;
    pub const E_EHSIZE: usize = 0x34;
    pub const E_PHENTSIZE: usize = 0x36;
    pub const E_PHNUM: usize = 0x38;
    pub const E_SHENTSIZE: usize = 0x3a;
    pub const E_SHNUM: usize = 0x3c;
    pub const E_SHSTRNDX: usize = 0x3e;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl Phdr {
    pub fn encode(&self) -> [u8; PHDR_SIZE] {
        let mut b = [0u8; PHDR_SIZE];
        b[0..4].copy_from_slice(&self.p_type.to_le_bytes());
        b[4..8].copy_from_slice(&self.p_flags.to_le_bytes());
        b[8..16].copy_from_slice(&self.p_offset.to_le_bytes());
        b[16..24].copy_from_slice(&self.p_vaddr.to_le_bytes());
        b[24..32].copy_from_slice(&self.p_paddr.to_le_bytes());
        b[32..40].copy_from_slice(&self.p_filesz.to_le_bytes());
        b[40..48].copy_from_slice(&self.p_memsz.to_le_bytes());
        b[48..56].copy_from_slice(&self.p_align.to_le_bytes());
        b
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

impl Shdr {
    pub fn encode(&self) -> [u8; SHDR_SIZE] {
        let mut b = [0u8; SHDR_SIZE];
        b[0..4].copy_from_slice(&self.sh_name.to_le_bytes());
        b[4..8].copy_from_slice(&self.sh_type.to_le_bytes());
        b[8..16].copy_from_slice(&self.sh_flags.to_le_bytes());
        b[16..24].copy_from_slice(&self.sh_addr.to_le_bytes());
        b[24..32].copy_from_slice(&self.sh_offset.to_le_bytes());
        b[32..40].copy_from_slice(&self.sh_size.to_le_bytes());
        b[40..44].copy_from_slice(&self.sh_link.to_le_bytes());
        b[44..48].copy_from_slice(&self.sh_info.to_le_bytes());
        b[48..56].copy_from_slice(&self.sh_addralign.to_le_bytes());
        b[56..64].copy_from_slice(&self.sh_entsize.to_le_bytes());
        b
    }
}

/// An ELF64 little-endian image being edited in place.
#[derive(Debug, Clone)]
pub struct Elf {
    pub d: Vec<u8>,
}

impl Elf {
    pub fn new(d: Vec<u8>) -> Self {
        assert!(
            d.len() >= EHDR_SIZE && d[..4] == *b"\x7fELF",
            "seed is not ELF"
        );
        assert_eq!(d[4], 2, "seed must be ELFCLASS64");
        assert_eq!(d[5], 1, "seed must be ELFDATA2LSB");
        Elf { d }
    }

    pub fn u16(&self, o: usize) -> u16 {
        u16::from_le_bytes(self.d[o..o + 2].try_into().expect("2 bytes"))
    }
    pub fn u32(&self, o: usize) -> u32 {
        u32::from_le_bytes(self.d[o..o + 4].try_into().expect("4 bytes"))
    }
    pub fn u64(&self, o: usize) -> u64 {
        u64::from_le_bytes(self.d[o..o + 8].try_into().expect("8 bytes"))
    }
    pub fn set_u16(&mut self, o: usize, v: u16) {
        self.d[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }
    pub fn set_u32(&mut self, o: usize, v: u32) {
        self.d[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    pub fn set_u64(&mut self, o: usize, v: u64) {
        self.d[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }

    pub fn phoff(&self) -> usize {
        usize::try_from(self.u64(eh::E_PHOFF)).expect("phoff")
    }
    pub fn phnum(&self) -> usize {
        usize::from(self.u16(eh::E_PHNUM))
    }
    pub fn shoff(&self) -> usize {
        usize::try_from(self.u64(eh::E_SHOFF)).expect("shoff")
    }
    pub fn shnum(&self) -> usize {
        usize::from(self.u16(eh::E_SHNUM))
    }
    pub fn shstrndx(&self) -> usize {
        usize::from(self.u16(eh::E_SHSTRNDX))
    }

    pub fn ph(&self, i: usize) -> Phdr {
        let o = self.phoff() + PHDR_SIZE * i;
        Phdr {
            p_type: self.u32(o),
            p_flags: self.u32(o + 4),
            p_offset: self.u64(o + 8),
            p_vaddr: self.u64(o + 16),
            p_paddr: self.u64(o + 24),
            p_filesz: self.u64(o + 32),
            p_memsz: self.u64(o + 40),
            p_align: self.u64(o + 48),
        }
    }
    pub fn set_ph(&mut self, i: usize, p: &Phdr) {
        let o = self.phoff() + PHDR_SIZE * i;
        self.d[o..o + PHDR_SIZE].copy_from_slice(&p.encode());
    }
    pub fn phs(&self) -> Vec<Phdr> {
        (0..self.phnum()).map(|i| self.ph(i)).collect()
    }
    /// Index of the first program header of type `t`.
    pub fn ph_slot(&self, t: u32) -> usize {
        self.phs()
            .iter()
            .position(|p| p.p_type == t)
            .unwrap_or_else(|| panic!("seed has no program header of type {t:#x}"))
    }
    /// Indices of the `PT_LOAD` entries, in table order.
    pub fn loads(&self) -> Vec<usize> {
        self.phs()
            .iter()
            .enumerate()
            .filter(|(_, p)| p.p_type == PT_LOAD)
            .map(|(i, _)| i)
            .collect()
    }
    /// The executable `PT_LOAD`.
    pub fn rx_load(&self) -> usize {
        self.loads()
            .into_iter()
            .find(|&i| self.ph(i).p_flags & PF_X != 0)
            .expect("seed has an executable PT_LOAD")
    }
    /// The `PT_LOAD` with the highest file offset.
    pub fn last_load(&self) -> usize {
        self.loads()
            .into_iter()
            .max_by_key(|&i| self.ph(i).p_offset)
            .expect("seed has a PT_LOAD")
    }

    pub fn sh(&self, i: usize) -> Shdr {
        let o = self.shoff() + SHDR_SIZE * i;
        Shdr {
            sh_name: self.u32(o),
            sh_type: self.u32(o + 4),
            sh_flags: self.u64(o + 8),
            sh_addr: self.u64(o + 16),
            sh_offset: self.u64(o + 24),
            sh_size: self.u64(o + 32),
            sh_link: self.u32(o + 40),
            sh_info: self.u32(o + 44),
            sh_addralign: self.u64(o + 48),
            sh_entsize: self.u64(o + 56),
        }
    }
    pub fn set_sh(&mut self, i: usize, s: &Shdr) {
        let o = self.shoff() + SHDR_SIZE * i;
        self.d[o..o + SHDR_SIZE].copy_from_slice(&s.encode());
    }
    pub fn shs(&self) -> Vec<Shdr> {
        (0..self.shnum()).map(|i| self.sh(i)).collect()
    }
    pub fn section_name(&self, i: usize) -> String {
        let st = self.sh(self.shstrndx());
        let start = usize::try_from(st.sh_offset).expect("offset") + self.sh(i).sh_name as usize;
        let end = start
            + self.d[start..]
                .iter()
                .position(|&b| b == 0)
                .expect("NUL-terminated section name");
        String::from_utf8_lossy(&self.d[start..end]).into_owned()
    }
    pub fn idx(&self, name: &str) -> usize {
        (0..self.shnum())
            .find(|&i| self.section_name(i) == name)
            .unwrap_or_else(|| panic!("seed has no section {name}"))
    }

    pub fn align_end(&mut self, a: usize) {
        while !self.d.len().is_multiple_of(a) {
            self.d.push(0);
        }
    }

    /// Zero the section header fields of the ELF header.
    pub fn zero_section_header_fields(&mut self) {
        self.set_u64(eh::E_SHOFF, 0);
        self.set_u16(eh::E_SHNUM, 0);
        self.set_u16(eh::E_SHSTRNDX, 0);
    }

    /// The ELFkickers `sstrip` cut: `getmemorysize()` keeps
    /// `max(e_phoff + e_phnum * sizeof(phdr), e_ehsize, p_offset + p_filesz
    /// for every non-PT_NULL entry)`, and `modifyheaders()` zeroes the
    /// section header fields when the table lies past that size.
    pub fn sstrip(&mut self) {
        let mut size =
            (self.phoff() + self.phnum() * PHDR_SIZE).max(usize::from(self.u16(eh::E_EHSIZE)));
        for p in self.phs() {
            if p.p_type != PT_NULL {
                size = size.max(usize::try_from(p.p_offset + p.p_filesz).expect("size"));
            }
        }
        if self.shoff() >= size {
            self.zero_section_header_fields();
        }
        self.d.truncate(size);
    }
}

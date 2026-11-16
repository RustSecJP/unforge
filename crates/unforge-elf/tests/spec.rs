//! Spec-conformance tests built from hand-written bytes.
//!
//! Every rule exercised here is quoted from (or pointed at) the System V gABI,
//! "Object Files" chapter (abbreviated "gABI ch4" below):
//!   <https://www.sco.com/developers/gabi/latest/ch4.eheader.html>  ELF Header
//!   <https://www.sco.com/developers/gabi/latest/ch4.sheader.html>  Sections
//!   <https://www.sco.com/developers/gabi/latest/ch4.strtab.html>   String Table
//!   <https://www.sco.com/developers/gabi/latest/ch4.symtab.html>   Symbol Table
//!   <https://www.sco.com/developers/gabi/latest/ch5.pheader.html>  Program Header
//!
//! The byte builder below encodes the structures *from the gABI figures*, not
//! from `unforge_elf::raw`, so it is an independent statement of the layout.
//! `builder_agrees_with_object_crate` cross-checks the builder against the
//! `object` crate so that a mistake in the builder cannot masquerade as a
//! loader bug.

use unforge_elf::consts::*;
use unforge_elf::{
    Choice, Class, Clue, DiagnosticKind, ElfFile, Endian, Error, Header, InferenceSubject,
    LayoutSource, SymbolSection,
};

// ===========================================================================
// Byte builder
// ===========================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum C {
    E32,
    E64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum E {
    L,
    B,
}

const LAYOUTS: [(C, E); 4] = [
    (C::E32, E::L),
    (C::E32, E::B),
    (C::E64, E::L),
    (C::E64, E::B),
];

impl C {
    fn ehsize(self) -> u16 {
        match self {
            C::E32 => 52,
            C::E64 => 64,
        }
    }
    fn phentsize(self) -> u16 {
        match self {
            C::E32 => 32,
            C::E64 => 56,
        }
    }
    fn shentsize(self) -> u16 {
        match self {
            C::E32 => 40,
            C::E64 => 64,
        }
    }
    fn symsize(self) -> u64 {
        match self {
            C::E32 => 16,
            C::E64 => 24,
        }
    }
    fn class(self) -> Class {
        match self {
            C::E32 => Class::Elf32,
            C::E64 => Class::Elf64,
        }
    }
}

impl E {
    fn endian(self) -> Endian {
        match self {
            E::L => Endian::Little,
            E::B => Endian::Big,
        }
    }
}

/// Little writer for ELF primitive types (gABI ch4 "Data Representation").
struct W {
    c: C,
    e: E,
    out: Vec<u8>,
}

impl W {
    fn new(c: C, e: E) -> Self {
        W {
            c,
            e,
            out: Vec::new(),
        }
    }
    fn uchar(&mut self, v: u8) {
        self.out.push(v);
    }
    fn half(&mut self, v: u16) {
        self.out.extend(match self.e {
            E::L => v.to_le_bytes(),
            E::B => v.to_be_bytes(),
        });
    }
    fn word(&mut self, v: u32) {
        self.out.extend(match self.e {
            E::L => v.to_le_bytes(),
            E::B => v.to_be_bytes(),
        });
    }
    fn xword(&mut self, v: u64) {
        self.out.extend(match self.e {
            E::L => v.to_le_bytes(),
            E::B => v.to_be_bytes(),
        });
    }
    /// `ElfN_Addr` / `ElfN_Off`, and the fields that are `Word` in ELF32 but
    /// `Xword` in ELF64 (sizes, flags, alignments).
    fn nat(&mut self, v: u64) {
        match self.c {
            C::E32 => self.word(u32::try_from(v).expect("test value does not fit ELF32")),
            C::E64 => self.xword(v),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Ident {
    class: Option<u8>,
    data: Option<u8>,
    version: u8,
    os_abi: u8,
    abi_version: u8,
}

#[derive(Clone, Copy, Debug)]
struct Eh {
    ident: Ident,
    e_type: u16,
    machine: u16,
    version: u32,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

impl Eh {
    fn new(c: C) -> Self {
        Eh {
            ident: Ident {
                version: 1,
                ..Default::default()
            },
            e_type: ET_EXEC,
            machine: EM_X86_64,
            version: 1,
            entry: 0,
            phoff: 0,
            shoff: 0,
            flags: 0,
            ehsize: c.ehsize(),
            phentsize: c.phentsize(),
            phnum: 0,
            shentsize: c.shentsize(),
            shnum: 0,
            shstrndx: SHN_UNDEF,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Ph {
    p_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Sh {
    name: u32,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    addralign: u64,
    entsize: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Sy {
    name: u32,
    value: u64,
    size: u64,
    info: u8,
    other: u8,
    shndx: u16,
}

/// gABI ch4 "ELF Header", Figure 4-3 / "ELF Identification", Figure 4-4.
fn enc_ehdr(c: C, e: E, h: &Eh) -> Vec<u8> {
    let mut w = W::new(c, e);
    w.out.extend(ELFMAG);
    w.uchar(h.ident.class.unwrap_or(match c {
        C::E32 => ELFCLASS32,
        C::E64 => ELFCLASS64,
    }));
    w.uchar(h.ident.data.unwrap_or(match e {
        E::L => ELFDATA2LSB,
        E::B => ELFDATA2MSB,
    }));
    w.uchar(h.ident.version);
    w.uchar(h.ident.os_abi);
    w.uchar(h.ident.abi_version);
    w.out.resize(16, 0); // EI_PAD .. EI_NIDENT
    w.half(h.e_type);
    w.half(h.machine);
    w.word(h.version);
    w.nat(h.entry);
    w.nat(h.phoff);
    w.nat(h.shoff);
    w.word(h.flags);
    w.half(h.ehsize);
    w.half(h.phentsize);
    w.half(h.phnum);
    w.half(h.shentsize);
    w.half(h.shnum);
    w.half(h.shstrndx);
    assert_eq!(w.out.len(), usize::from(c.ehsize()));
    w.out
}

/// gABI ch5 "Program Header", Figure 5-1. Note p_flags is the 7th field in
/// Elf32_Phdr and the 2nd field in Elf64_Phdr.
fn enc_phdr(c: C, e: E, p: &Ph) -> Vec<u8> {
    let mut w = W::new(c, e);
    match c {
        C::E32 => {
            w.word(p.p_type);
            w.nat(p.offset);
            w.nat(p.vaddr);
            w.nat(p.paddr);
            w.nat(p.filesz);
            w.nat(p.memsz);
            w.word(p.flags);
            w.nat(p.align);
        }
        C::E64 => {
            w.word(p.p_type);
            w.word(p.flags);
            w.xword(p.offset);
            w.xword(p.vaddr);
            w.xword(p.paddr);
            w.xword(p.filesz);
            w.xword(p.memsz);
            w.xword(p.align);
        }
    }
    assert_eq!(w.out.len(), usize::from(c.phentsize()));
    w.out
}

/// gABI ch4 "Sections", Figure 4-8 "Section Header".
fn enc_shdr(c: C, e: E, s: &Sh) -> Vec<u8> {
    let mut w = W::new(c, e);
    w.word(s.name);
    w.word(s.sh_type);
    w.nat(s.flags);
    w.nat(s.addr);
    w.nat(s.offset);
    w.nat(s.size);
    w.word(s.link);
    w.word(s.info);
    w.nat(s.addralign);
    w.nat(s.entsize);
    assert_eq!(w.out.len(), usize::from(c.shentsize()));
    w.out
}

/// gABI ch4 "Symbol Table", Figure 4-15. The member order differs between
/// classes: Elf32_Sym is name,value,size,info,other,shndx while Elf64_Sym is
/// name,info,other,shndx,value,size.
fn enc_sym(c: C, e: E, s: &Sy) -> Vec<u8> {
    let mut w = W::new(c, e);
    match c {
        C::E32 => {
            w.word(s.name);
            w.nat(s.value);
            w.nat(s.size);
            w.uchar(s.info);
            w.uchar(s.other);
            w.half(s.shndx);
        }
        C::E64 => {
            w.word(s.name);
            w.uchar(s.info);
            w.uchar(s.other);
            w.half(s.shndx);
            w.xword(s.value);
            w.xword(s.size);
        }
    }
    assert_eq!(w.out.len() as u64, c.symsize());
    w.out
}

fn enc_syms(c: C, e: E, syms: &[Sy]) -> Vec<u8> {
    syms.iter().flat_map(|s| enc_sym(c, e, s)).collect()
}

fn enc_words(e: E, ws: &[u32]) -> Vec<u8> {
    let mut w = W::new(C::E32, e);
    for &x in ws {
        w.word(x);
    }
    w.out
}

/// Lays a file out as `[ehdr][blobs...][phdrs][shdrs]`, every piece 8-aligned.
struct FileBuilder {
    c: C,
    e: E,
    body: Vec<u8>,
    phdrs: Vec<Ph>,
    sections: Vec<Sh>,
    /// Extra bytes appended after each program/section header (to test
    /// e_phentsize / e_shentsize larger than the structure).
    ph_pad: usize,
    sh_pad: usize,
}

impl FileBuilder {
    fn new(c: C, e: E) -> Self {
        FileBuilder {
            c,
            e,
            body: vec![0; usize::from(c.ehsize())],
            phdrs: Vec::new(),
            sections: Vec::new(),
            ph_pad: 0,
            sh_pad: 0,
        }
    }
    fn align(&mut self) {
        while !self.body.len().is_multiple_of(8) {
            self.body.push(0);
        }
    }
    /// Append raw bytes, returning their file offset.
    fn blob(&mut self, bytes: &[u8]) -> u64 {
        self.align();
        let off = self.body.len() as u64;
        self.body.extend_from_slice(bytes);
        off
    }
    fn phdr(&mut self, p: Ph) -> usize {
        self.phdrs.push(p);
        self.phdrs.len() - 1
    }
    fn section(&mut self, s: Sh) -> usize {
        self.sections.push(s);
        self.sections.len() - 1
    }
    /// Add a section whose contents are `data`; offset and size are filled in.
    fn section_with(&mut self, mut s: Sh, data: &[u8]) -> usize {
        s.offset = self.blob(data);
        s.size = data.len() as u64;
        self.section(s)
    }
    /// Build the file. `tweak` may adjust the header after the defaults
    /// (offsets, counts) have been computed.
    fn finish(mut self, tweak: impl FnOnce(&mut Eh)) -> Vec<u8> {
        let mut h = Eh::new(self.c);
        h.phentsize += self.ph_pad as u16;
        h.shentsize += self.sh_pad as u16;
        if !self.phdrs.is_empty() {
            self.align();
            h.phoff = self.body.len() as u64;
            h.phnum = self.phdrs.len() as u16;
            for p in &self.phdrs {
                let b = enc_phdr(self.c, self.e, p);
                self.body.extend(b);
                self.body.extend(std::iter::repeat_n(0xAA, self.ph_pad));
            }
        }
        if !self.sections.is_empty() {
            self.align();
            h.shoff = self.body.len() as u64;
            h.shnum = self.sections.len() as u16;
            for s in &self.sections {
                let b = enc_shdr(self.c, self.e, s);
                self.body.extend(b);
                self.body.extend(std::iter::repeat_n(0xBB, self.sh_pad));
            }
        }
        tweak(&mut h);
        let eh = enc_ehdr(self.c, self.e, &h);
        self.body[..eh.len()].copy_from_slice(&eh);
        self.body
    }
}

fn header_only(c: C, e: E, h: &Eh) -> Vec<u8> {
    enc_ehdr(c, e, h)
}

/// A small but complete file used by several tests:
///   [0] SHT_NULL
///   [1] .text      SHT_PROGBITS
///   [2] .shstrtab  SHT_STRTAB
///   [3] .strtab    SHT_STRTAB
///   [4] .symtab    SHT_SYMTAB  (link=3, info=1)
///   one PT_LOAD
struct Sample {
    bytes: Vec<u8>,
    phdr: Ph,
    syms: Vec<Sy>,
}

const SHSTRTAB: &[u8] = b"\0.text\0.shstrtab\0.strtab\0.symtab\0";
const STRTAB: &[u8] = b"\0main\0helper\0";

fn sample(c: C, e: E) -> Sample {
    let mut f = FileBuilder::new(c, e);
    let text = [0x90u8; 16];
    let phdr = Ph {
        p_type: PT_LOAD,
        flags: PF_R | PF_X,
        offset: 0,
        vaddr: 0x40_0000,
        paddr: 0x40_0000,
        filesz: 0x123,
        memsz: 0x456,
        align: 0x1000,
    };
    f.phdr(phdr);
    f.section(Sh::default());
    f.section_with(
        Sh {
            name: 1,
            sh_type: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_EXECINSTR,
            addr: 0x40_1000,
            addralign: 16,
            ..Default::default()
        },
        &text,
    );
    f.section_with(
        Sh {
            name: 7,
            sh_type: SHT_STRTAB,
            addralign: 1,
            ..Default::default()
        },
        SHSTRTAB,
    );
    f.section_with(
        Sh {
            name: 17,
            sh_type: SHT_STRTAB,
            addralign: 1,
            ..Default::default()
        },
        STRTAB,
    );
    let syms = vec![
        Sy::default(),
        Sy {
            name: 1,
            value: 0x40_1000,
            size: 0x10,
            info: (STB_GLOBAL << 4) | STT_FUNC,
            other: 0,
            shndx: 1,
        },
        Sy {
            name: 6,
            value: 0x40_1008,
            size: 0x8,
            info: (STB_LOCAL << 4) | STT_FUNC,
            other: 2, // STV_HIDDEN
            shndx: 1,
        },
    ];
    f.section_with(
        Sh {
            name: 25,
            sh_type: SHT_SYMTAB,
            link: 3,
            info: 1,
            addralign: 8,
            entsize: c.symsize(),
            ..Default::default()
        },
        &enc_syms(c, e, &syms),
    );
    let bytes = f.finish(|h| {
        h.e_type = ET_DYN;
        h.entry = 0x40_1000;
        h.shstrndx = 2;
    });
    Sample { bytes, phdr, syms }
}

// ===========================================================================
// Oracle cross-check of the builder (object crate, test-only)
// ===========================================================================

mod oracle {
    use object::Endianness;
    use object::read::elf::{FileHeader, ProgramHeader, SectionHeader, Sym};

    #[derive(Debug, PartialEq)]
    pub struct View {
        pub e_type: u16,
        pub machine: u16,
        pub entry: u64,
        pub phoff: u64,
        pub shoff: u64,
        pub phnum: u64,
        pub shnum: u64,
        pub phdrs: Vec<[u64; 8]>,
        pub shdrs: Vec<[u64; 10]>,
        pub syms: Vec<[u64; 6]>,
    }

    pub fn view<Elf: FileHeader<Endian = Endianness>>(data: &[u8]) -> View {
        let h = Elf::parse(data).expect("object: parse");
        let e = h.endian().expect("object: endian");
        let phdrs = h
            .program_headers(e, data)
            .expect("object: phdrs")
            .iter()
            .map(|p| {
                [
                    p.p_type(e).0.into(),
                    p.p_flags(e).0.into(),
                    p.p_offset(e).into(),
                    p.p_vaddr(e).into(),
                    p.p_paddr(e).into(),
                    p.p_filesz(e).into(),
                    p.p_memsz(e).into(),
                    p.p_align(e).into(),
                ]
            })
            .collect::<Vec<_>>();
        let shdrs_raw = h.section_headers(e, data).expect("object: shdrs");
        let shdrs = shdrs_raw
            .iter()
            .map(|s| {
                [
                    s.sh_name(e).into(),
                    s.sh_type(e).0.into(),
                    s.sh_flags(e).0,
                    s.sh_addr(e).into(),
                    s.sh_offset(e).into(),
                    s.sh_size(e).into(),
                    s.sh_link(e).into(),
                    s.sh_info(e).into(),
                    s.sh_addralign(e).into(),
                    s.sh_entsize(e).into(),
                ]
            })
            .collect::<Vec<_>>();
        let table = h.sections(e, data).expect("object: sections");
        let symtab = table
            .symbols(e, data, object::elf::SHT_SYMTAB)
            .expect("object: symtab");
        let syms = symtab
            .symbols()
            .iter()
            .map(|s| {
                [
                    s.st_name(e).into(),
                    s.st_value(e).into(),
                    s.st_size(e).into(),
                    s.st_info().0.into(),
                    s.st_other().0.into(),
                    s.st_shndx(e).0.into(),
                ]
            })
            .collect();
        View {
            e_type: h.e_type(e).0,
            machine: h.e_machine(e).0,
            entry: h.e_entry(e).into(),
            phoff: h.e_phoff(e).into(),
            shoff: h.e_shoff(e).into(),
            phnum: h.phnum(e, data).expect("object: phnum").into(),
            shnum: h.shnum(e, data).expect("object: shnum").into(),
            phdrs,
            shdrs,
            syms,
        }
    }

    /// The `object` crate's resolved `e_phnum` (handles `PN_XNUM`).
    pub fn phnum<Elf: FileHeader<Endian = Endianness>>(data: &[u8]) -> object::read::Result<u32> {
        let h = Elf::parse(data)?;
        h.phnum(h.endian()?, data)
    }
}

fn oracle_view(c: C, data: &[u8]) -> oracle::View {
    match c {
        C::E32 => oracle::view::<object::elf::FileHeader32<object::Endianness>>(data),
        C::E64 => oracle::view::<object::elf::FileHeader64<object::Endianness>>(data),
    }
}

fn unforge_view(data: &[u8]) -> oracle::View {
    let f = ElfFile::parse(data).expect("unforge: parse");
    let h = f.header();
    let symtab_index = f
        .section_headers()
        .unwrap()
        .iter()
        .position(|s| s.sh_type == SHT_SYMTAB)
        .unwrap();
    let st = f.symbol_table(symtab_index).unwrap();
    oracle::View {
        e_type: h.e_type,
        machine: h.machine,
        entry: h.entry,
        phoff: h.phoff,
        shoff: h.shoff,
        phnum: h.phnum,
        shnum: h.shnum,
        phdrs: f
            .program_headers()
            .unwrap()
            .iter()
            .map(|p| {
                [
                    p.p_type.into(),
                    p.flags.into(),
                    p.offset,
                    p.vaddr,
                    p.paddr,
                    p.filesz,
                    p.memsz,
                    p.align,
                ]
            })
            .collect(),
        shdrs: f
            .section_headers()
            .unwrap()
            .iter()
            .map(|s| {
                [
                    s.name.into(),
                    s.sh_type.into(),
                    s.flags,
                    s.addr,
                    s.offset,
                    s.size,
                    s.link.into(),
                    s.info.into(),
                    s.addralign,
                    s.entsize,
                ]
            })
            .collect(),
        syms: st
            .iter()
            .map(|s| {
                [
                    s.name.into(),
                    s.value,
                    s.size,
                    s.info.into(),
                    s.other.into(),
                    s.raw_shndx.into(),
                ]
            })
            .collect(),
    }
}

/// Guards the builder itself: if this fails, the bug is in this file.
#[test]
fn builder_agrees_with_object_crate() {
    for (c, e) in LAYOUTS {
        let s = sample(c, e);
        let o = oracle_view(c, &s.bytes);
        assert_eq!(o.phdrs.len(), 1, "{c:?}/{e:?}");
        assert_eq!(o.shdrs.len(), 5, "{c:?}/{e:?}");
        assert_eq!(o.syms.len(), 3, "{c:?}/{e:?}");
        assert_eq!(o.syms[1][1], 0x40_1000, "{c:?}/{e:?}");
        assert_eq!(o.phdrs[0][1], u64::from(PF_R | PF_X), "{c:?}/{e:?}");
    }
}

/// The loader and `object` must agree on every field of every layout.
#[test]
fn loader_agrees_with_object_crate_on_sample() {
    for (c, e) in LAYOUTS {
        let s = sample(c, e);
        assert_eq!(
            unforge_view(&s.bytes),
            oracle_view(c, &s.bytes),
            "{c:?}/{e:?}"
        );
    }
}

// ===========================================================================
// The first three TDD tests
// ===========================================================================

/// (a) gABI ch4 "ELF Identification": e_ident[EI_MAG0..EI_MAG3] must be
/// 0x7f 'E' 'L' 'F'. Anything else is not an ELF file.
#[test]
fn tdd1_rejects_non_elf_magic() {
    // A full-size header with a wrong 4th magic byte.
    let mut bytes = header_only(C::E64, E::L, &Eh::new(C::E64));
    bytes[3] = b'G';
    assert_eq!(
        ElfFile::parse(&bytes).unwrap_err(),
        Error::BadMagic([0x7f, b'E', b'L', b'G'])
    );

    // A PE/COFF stub, shorter than e_ident: still identifiable as "not ELF".
    assert_eq!(
        ElfFile::parse(b"MZ\x90\x00").unwrap_err(),
        Error::BadMagic(*b"MZ\x90\x00")
    );

    // Shorter than the magic itself: must be an error, never a panic.
    for n in 0..4 {
        assert!(ElfFile::parse(&ELFMAG[..n]).is_err(), "len {n}");
    }
}

/// (b) gABI ch4 "ELF Header", Figure 4-3: every Elf64_Ehdr field round-trips.
/// Distinct, byte-asymmetric sentinels catch both swapped fields and wrong
/// byte order; 64-bit e_entry catches truncation to 32 bits.
#[test]
fn tdd2_minimal_elf64_le_header_round_trips() {
    let h = Eh {
        ident: Ident {
            version: 1,
            os_abi: 3,         // ELFOSABI_GNU / ELFOSABI_LINUX
            abi_version: 0x5a, // arbitrary sentinel
            ..Default::default()
        },
        e_type: ET_DYN,
        machine: EM_X86_64,
        version: 1,
        entry: 0x1122_3344_5566_7788,
        // No program header table (phnum = 0), but phoff carries a sentinel:
        // the reader must not use phoff when there are zero entries.
        phoff: 0x0000_0102_0304_0506,
        shoff: 0, // "If the file has no section header table, this member holds zero."
        flags: 0xA1B2_C3D4,
        ehsize: 64,
        phentsize: 56,
        phnum: 0,
        shentsize: 64,
        shnum: 0,
        shstrndx: SHN_UNDEF,
    };
    let bytes = header_only(C::E64, E::L, &h);
    assert_eq!(bytes.len(), 64);
    let f = ElfFile::parse(&bytes).expect("minimal header must parse");
    let got = f.header();
    let want = Header {
        class: Class::Elf64,
        endian: Endian::Little,
        ident_class: 2,
        ident_data: 1,
        ident_version: 1,
        os_abi: 3,
        abi_version: 0x5a,
        e_type: ET_DYN,
        machine: EM_X86_64,
        version: 1,
        entry: 0x1122_3344_5566_7788,
        phoff: 0x0000_0102_0304_0506,
        shoff: 0,
        flags: 0xA1B2_C3D4,
        ehsize: 64,
        phentsize: 56,
        shentsize: 64,
        phnum: 0,
        shnum: 0,
        shstrndx: None,
        raw_phnum: 0,
        raw_shnum: 0,
        raw_shstrndx: SHN_UNDEF,
    };
    assert_eq!(*got, want);
    assert!(f.program_headers().unwrap().is_empty());
    assert!(f.section_headers().unwrap().is_empty());
}

/// (c) The same logical file encoded in all four (class, data) combinations
/// must widen to the same values. gABI ch4 "ELF Identification": EI_CLASS
/// selects the file's class, EI_DATA "specifies the encoding of ...
/// processor-specific data in the object file".
#[test]
fn tdd3_same_file_in_every_class_and_byte_order_widens_identically() {
    let mut views = Vec::new();
    for (c, e) in LAYOUTS {
        let s = sample(c, e);
        let f = ElfFile::parse(&s.bytes).unwrap();
        let h = f.header();
        assert_eq!(h.class, c.class());
        assert_eq!(h.endian, e.endian());
        assert_eq!(h.ehsize, c.ehsize());
        assert_eq!(h.phentsize, c.phentsize());
        assert_eq!(h.shentsize, c.shentsize());
        // Everything that is not class-dependent must be identical.
        let mut v = unforge_view(&s.bytes);
        // Offsets differ between classes because the structs differ in size.
        v.phoff = 0;
        v.shoff = 0;
        for sh in &mut v.shdrs {
            sh[4] = 0; // sh_offset
            if sh[1] == u64::from(SHT_SYMTAB) {
                sh[5] /= sh[9]; // sh_size -> entry count
                sh[9] = 0; // sh_entsize differs (16 vs 24)
            }
        }
        views.push(v);
    }
    for v in &views[1..] {
        assert_eq!(v, &views[0]);
    }
}

// ===========================================================================
// Identification errors
// ===========================================================================

/// gABI ch4 "ELF Identification": ELFCLASSNONE = 0 is invalid; values other
/// than 1/2 are not defined. Same for EI_DATA (ELFDATANONE = 0).
///
/// Changed from the strict reader (UnsupportedClass / UnsupportedData
/// errors): the Linux kernel never reads these bytes (LOADER_RULES.md §1), so
/// the layout is decided from e_machine and the header sizes, and the invalid
/// byte is reported as a diagnostic and as a clue of the layout inference.
#[test]
fn invalid_class_and_data_are_diagnostics() {
    for bad in [0u8, 3, 0xff] {
        for (field, at) in [("EI_CLASS", 4), ("EI_DATA", 5)] {
            let mut bytes = header_only(C::E64, E::L, &Eh::new(C::E64));
            bytes[at] = bad;
            let f = ElfFile::parse(&bytes).unwrap_or_else(|e| panic!("{field}={bad}: {e}"));
            let h = f.header();
            assert_eq!((h.class, h.endian), (Class::Elf64, Endian::Little));
            assert_eq!(f.layout().source, LayoutSource::Machine);
            let ds = f.diagnostics();
            let mismatch = ds.iter().any(|d| match d.kind {
                DiagnosticKind::ClassMismatch { claimed, .. } => at == 4 && claimed == bad,
                DiagnosticKind::DataMismatch { claimed, .. } => at == 5 && claimed == bad,
                _ => false,
            });
            assert!(mismatch, "{field}={bad}: {ds:?}");
            let layout = f
                .inferences()
                .into_iter()
                .find(|i| i.subject == InferenceSubject::Layout)
                .expect("layout inference");
            assert!(
                layout
                    .clues
                    .contains(&Clue::InvalidIdent { field, value: bad }),
                "{layout}"
            );
        }
    }
    // With nothing at all to go on, there is no header to read.
    let mut bytes = vec![0u8; 64];
    bytes[..4].copy_from_slice(&ELFMAG);
    bytes[4] = 0x55;
    bytes[5] = 0x55;
    assert!(matches!(
        ElfFile::parse(&bytes),
        Err(Error::UndeterminedLayout {
            ident_class: 0x55,
            ident_data: 0x55
        })
    ));
}

/// A valid e_ident followed by a truncated header must be an error, not a panic.
#[test]
fn truncated_header_is_out_of_bounds() {
    for (c, e) in LAYOUTS {
        let full = header_only(c, e, &Eh::new(c));
        for n in 16..full.len() {
            match ElfFile::parse(&full[..n]) {
                Err(Error::OutOfBounds { .. }) => {}
                other => panic!("{c:?}/{e:?} len {n}: {other:?}"),
            }
        }
    }
}

// ===========================================================================
// Field-order traps
// ===========================================================================

/// gABI ch5 Figure 5-1: Elf32_Phdr = type, offset, vaddr, paddr, filesz,
/// memsz, flags, align; Elf64_Phdr = type, flags, offset, vaddr, paddr,
/// filesz, memsz, align.
#[test]
fn phdr_field_order_with_sentinels() {
    for (c, e) in LAYOUTS {
        let p = match c {
            C::E32 => Ph {
                p_type: 0x6000_0001,
                flags: 0x0000_0007,
                offset: 0x1111_1111,
                vaddr: 0x2222_2222,
                paddr: 0x3333_3333,
                filesz: 0x4444_4444,
                memsz: 0x5555_5555,
                align: 0x6666_6666,
            },
            C::E64 => Ph {
                p_type: 0x6000_0001,
                flags: 0x0000_0007,
                offset: 0x1111_1111_1111_1101,
                vaddr: 0x2222_2222_2222_2202,
                paddr: 0x3333_3333_3333_3303,
                filesz: 0x4444_4444_4444_4404,
                memsz: 0x5555_5555_5555_5505,
                align: 0x6666_6666_6666_6606,
            },
        };
        let mut f = FileBuilder::new(c, e);
        f.phdr(p);
        let bytes = f.finish(|_| {});
        let file = ElfFile::parse(&bytes).unwrap();
        let got = file.program_headers().unwrap().get(0).unwrap();
        assert_eq!(got.p_type, p.p_type, "{c:?}/{e:?}");
        assert_eq!(got.flags, p.flags, "{c:?}/{e:?}");
        assert_eq!(got.offset, p.offset, "{c:?}/{e:?}");
        assert_eq!(got.vaddr, p.vaddr, "{c:?}/{e:?}");
        assert_eq!(got.paddr, p.paddr, "{c:?}/{e:?}");
        assert_eq!(got.filesz, p.filesz, "{c:?}/{e:?}");
        assert_eq!(got.memsz, p.memsz, "{c:?}/{e:?}");
        assert_eq!(got.align, p.align, "{c:?}/{e:?}");
    }
}

/// gABI ch4 Figure 4-8: section header field order (same order in both
/// classes; flags/addr/offset/size/addralign/entsize widen to Xword/Addr/Off).
#[test]
fn shdr_field_order_with_sentinels() {
    for (c, e) in LAYOUTS {
        let wide = |v32: u64, hi: u64| match c {
            C::E32 => v32,
            C::E64 => (hi << 32) | v32,
        };
        let s = Sh {
            name: 0x0A0A_0A01,
            sh_type: 0x6FFF_FFF0,
            flags: wide(0x0C0C_0C03, 0x0C),
            addr: wide(0x0D0D_0D04, 0x0D),
            offset: wide(0x0E0E_0E05, 0x0E),
            size: wide(0x0F0F_0F06, 0x0F),
            link: 0x1010_1007,
            info: 0x1111_1108,
            addralign: wide(0x1212_1209, 0x12),
            entsize: wide(0x1313_130A, 0x13),
        };
        let mut f = FileBuilder::new(c, e);
        f.section(Sh::default());
        f.section(s);
        let bytes = f.finish(|_| {});
        let file = ElfFile::parse(&bytes).unwrap();
        let got = file.section_headers().unwrap().get(1).unwrap();
        assert_eq!(
            [
                u64::from(got.name),
                u64::from(got.sh_type),
                got.flags,
                got.addr,
                got.offset,
                got.size,
                u64::from(got.link),
                u64::from(got.info),
                got.addralign,
                got.entsize
            ],
            [
                u64::from(s.name),
                u64::from(s.sh_type),
                s.flags,
                s.addr,
                s.offset,
                s.size,
                u64::from(s.link),
                u64::from(s.info),
                s.addralign,
                s.entsize
            ],
            "{c:?}/{e:?}"
        );
    }
}

/// Build a file with a symtab containing `syms` (and an empty strtab), plus any
/// `extra` sections appended after it. Returns (bytes, symtab index).
fn with_symtab(c: C, e: E, syms: &[Sy], entsize: u64, extra: &[(Sh, Vec<u8>)]) -> (Vec<u8>, usize) {
    let mut f = FileBuilder::new(c, e);
    f.section(Sh::default());
    let strtab = f.section_with(
        Sh {
            sh_type: SHT_STRTAB,
            ..Default::default()
        },
        b"\0abc\0",
    );
    let symsize = usize::try_from(c.symsize()).unwrap();
    let stride = usize::try_from(entsize).unwrap();
    let mut data = Vec::new();
    for s in syms {
        data.extend(enc_sym(c, e, s));
        data.extend(std::iter::repeat_n(0xCC, stride - symsize));
    }
    let symtab = f.section_with(
        Sh {
            sh_type: SHT_SYMTAB,
            link: strtab as u32,
            info: 1,
            entsize,
            ..Default::default()
        },
        &data,
    );
    for (sh, d) in extra {
        f.section_with(*sh, d);
    }
    (f.finish(|_| {}), symtab)
}

/// gABI ch4 Figure 4-15: Elf32_Sym = name, value, size, info, other, shndx;
/// Elf64_Sym = name, info, other, shndx, value, size.
#[test]
fn sym_field_order_with_sentinels() {
    for (c, e) in LAYOUTS {
        let s = match c {
            C::E32 => Sy {
                name: 0x0102_0304,
                value: 0x1122_3344,
                size: 0x5566_7788,
                info: 0x9A,
                other: 0xBC,
                shndx: 0x0DEF,
            },
            C::E64 => Sy {
                name: 0x0102_0304,
                value: 0x1122_3344_5566_7788,
                size: 0x99AA_BBCC_DDEE_FF00,
                info: 0x9A,
                other: 0xBC,
                shndx: 0x0DEF,
            },
        };
        let (bytes, idx) = with_symtab(c, e, &[Sy::default(), s], c.symsize(), &[]);
        let f = ElfFile::parse(&bytes).unwrap();
        let t = f.symbol_table(idx).unwrap();
        assert_eq!(t.len(), 2);
        let got = t.get(1).unwrap();
        assert_eq!(got.name, s.name, "{c:?}/{e:?}");
        assert_eq!(got.value, s.value, "{c:?}/{e:?}");
        assert_eq!(got.size, s.size, "{c:?}/{e:?}");
        assert_eq!(got.info, s.info, "{c:?}/{e:?}");
        assert_eq!(got.other, s.other, "{c:?}/{e:?}");
        assert_eq!(got.raw_shndx, s.shndx, "{c:?}/{e:?}");
        assert_eq!(got.section, SymbolSection::Index(0x0DEF), "{c:?}/{e:?}");
    }
}

// ===========================================================================
// Extended numbering (gABI ch4 "ELF Header" and "Sections", Figure 4-10
// "Section Header Table Entry: Index 0")
// ===========================================================================

/// gABI e_shnum: "If the number of sections is greater than or equal to
/// SHN_LORESERVE (0xff00), this member has the value zero and the actual
/// number of section header table entries is contained in the sh_size field
/// of the section header at index 0."
#[test]
fn shnum_zero_with_shoff_takes_count_from_section0_sh_size() {
    for (c, e) in LAYOUTS {
        let mut f = FileBuilder::new(c, e);
        f.section(Sh {
            size: 3,
            ..Default::default()
        });
        f.section(Sh {
            name: 1,
            sh_type: SHT_PROGBITS,
            ..Default::default()
        });
        f.section(Sh {
            name: 2,
            sh_type: SHT_PROGBITS,
            ..Default::default()
        });
        let bytes = f.finish(|h| h.shnum = 0);
        let file = ElfFile::parse(&bytes).unwrap();
        assert_eq!(file.header().raw_shnum, 0, "{c:?}/{e:?}");
        assert_eq!(file.header().shnum, 3, "{c:?}/{e:?}");
        assert_eq!(file.section_headers().unwrap().len(), 3, "{c:?}/{e:?}");
        assert_eq!(
            file.section_headers().unwrap().get(2).unwrap().name,
            2,
            "{c:?}/{e:?}"
        );
    }
}

/// gABI e_shoff: "If the file has no section header table, this member holds
/// zero." and e_shnum: "If a file has no section header table, e_shnum holds
/// the value zero."
#[test]
fn shoff_zero_means_no_section_table() {
    for (c, e) in LAYOUTS {
        let bytes = header_only(c, e, &Eh::new(c));
        let f = ElfFile::parse(&bytes).unwrap();
        assert_eq!(f.header().shnum, 0);
        assert!(f.section_headers().unwrap().is_empty());
    }
}

/// Inconsistent: e_shoff == 0 ("no section header table") but e_shnum != 0.
/// The two gABI statements quoted above contradict each other here; offset 0
/// is the ELF header itself, so there cannot be a table there. Both the loader
/// and `object` (`section_headers` returns `&[]` when shoff == 0) treat this as
/// "no sections". This is a policy choice, not something the gABI states.
#[test]
fn shoff_zero_with_nonzero_shnum_means_no_sections() {
    for (c, e) in LAYOUTS {
        let mut h = Eh::new(c);
        h.shnum = 5;
        h.shstrndx = 1;
        let bytes = header_only(c, e, &h);
        let f = ElfFile::parse(&bytes).unwrap();
        assert_eq!(f.header().shnum, 0, "{c:?}/{e:?}");
        assert!(f.section_headers().unwrap().is_empty(), "{c:?}/{e:?}");
        assert!(f.section_name_table().is_err());
    }
}

/// gABI e_phnum: "If the number of program headers is greater than or equal
/// to PN_XNUM (0xffff), this member has the value PN_XNUM (0xffff). The actual
/// number of program header table entries is contained in the sh_info field
/// of the section header at index 0."
#[test]
fn pn_xnum_takes_count_from_section0_sh_info() {
    for (c, e) in LAYOUTS {
        let mut f = FileBuilder::new(c, e);
        f.phdr(Ph {
            p_type: PT_LOAD,
            ..Default::default()
        });
        f.phdr(Ph {
            p_type: PT_NOTE,
            ..Default::default()
        });
        f.section(Sh {
            info: 2,
            ..Default::default()
        });
        let bytes = f.finish(|h| h.phnum = PN_XNUM);
        let file = ElfFile::parse(&bytes).unwrap();
        assert_eq!(file.header().raw_phnum, PN_XNUM, "{c:?}/{e:?}");
        assert_eq!(file.header().phnum, 2, "{c:?}/{e:?}");
        let ph = file.program_headers().unwrap();
        assert_eq!(ph.len(), 2);
        assert_eq!(ph.get(1).unwrap().p_type, PT_NOTE);
        assert_eq!(
            u64::from(
                match c {
                    C::E32 =>
                        oracle::phnum::<object::elf::FileHeader32<object::Endianness>>(&bytes),
                    C::E64 =>
                        oracle::phnum::<object::elf::FileHeader64<object::Endianness>>(&bytes),
                }
                .unwrap()
            ),
            2
        );
    }
}

/// PN_XNUM with no section header table: the gABI says the real count is in
/// section 0's sh_info, and there is no section 0, so the count is unknowable.
/// PN_XNUM is an escape value, not a count (a file with exactly 0xffff headers
/// must also use PN_XNUM, per the quote above), so the loader must not read
/// 0xffff entries as if e_phnum were literal. `object` returns
/// "Missing ELF section headers for e_phnum overflow" here.
///
/// The file is made large enough to actually hold 0xffff entries so that a
/// "treat it as a literal count" implementation is caught (and not saved by
/// an incidental OutOfBounds).
#[test]
fn pn_xnum_without_section_table_is_an_error_for_program_headers() {
    for (c, e) in LAYOUTS {
        let ehsize = u64::from(c.ehsize());
        let mut h = Eh::new(c);
        h.phnum = PN_XNUM;
        h.phoff = ehsize;
        let mut bytes = header_only(c, e, &h);
        bytes.resize(
            usize::try_from(ehsize).unwrap() + 0xffff * usize::from(c.phentsize()),
            0,
        );
        let oracle = match c {
            C::E32 => oracle::phnum::<object::elf::FileHeader32<object::Endianness>>(&bytes),
            C::E64 => oracle::phnum::<object::elf::FileHeader64<object::Endianness>>(&bytes),
        };
        assert!(oracle.is_err(), "oracle accepted it: {oracle:?}");
        // The header itself is fine; only the program header table is unusable.
        let f = ElfFile::parse(&bytes).expect("parse should still succeed");
        assert_eq!(f.header().raw_phnum, PN_XNUM);
        assert!(
            f.program_headers().is_err(),
            "{c:?}/{e:?}: PN_XNUM without section 0 was read as {} entries",
            f.program_headers().map(|p| p.len()).unwrap_or(0)
        );
    }
}

/// gABI e_shstrndx: "If the section name string table section index is
/// greater than or equal to SHN_LORESERVE (0xff00), this member has the value
/// SHN_XINDEX (0xffff) and the actual index of the section name string table
/// section is contained in the sh_link field of the section header at index 0."
#[test]
fn shstrndx_xindex_takes_index_from_section0_sh_link() {
    for (c, e) in LAYOUTS {
        let mut f = FileBuilder::new(c, e);
        f.section(Sh {
            link: 2,
            ..Default::default()
        });
        f.section(Sh {
            name: 1,
            sh_type: SHT_PROGBITS,
            ..Default::default()
        });
        f.section_with(
            Sh {
                name: 7,
                sh_type: SHT_STRTAB,
                ..Default::default()
            },
            b"\0.text\0.shstrtab\0",
        );
        let bytes = f.finish(|h| h.shstrndx = SHN_XINDEX);
        let file = ElfFile::parse(&bytes).unwrap();
        assert_eq!(file.header().raw_shstrndx, SHN_XINDEX);
        assert_eq!(file.header().shstrndx, Some(2), "{c:?}/{e:?}");
        let sh1 = file.section_headers().unwrap().get(1).unwrap();
        assert_eq!(file.section_name(&sh1).unwrap(), b".text");
        assert_eq!(file.section_by_name(b".shstrtab").map(|(i, _)| i), Some(2));
    }
}

/// All three escapes at once, in ELF32 big-endian (section 0 read as an
/// Elf32_Shdr in MSB order).
#[test]
fn all_three_escapes_together() {
    for (c, e) in LAYOUTS {
        let mut f = FileBuilder::new(c, e);
        f.phdr(Ph {
            p_type: PT_LOAD,
            ..Default::default()
        });
        f.section(Sh {
            size: 3,
            info: 1,
            link: 2,
            ..Default::default()
        });
        f.section(Sh {
            name: 1,
            sh_type: SHT_PROGBITS,
            ..Default::default()
        });
        f.section_with(
            Sh {
                name: 7,
                sh_type: SHT_STRTAB,
                ..Default::default()
            },
            b"\0.text\0.shstrtab\0",
        );
        let bytes = f.finish(|h| {
            h.phnum = PN_XNUM;
            h.shnum = 0;
            h.shstrndx = SHN_XINDEX;
        });
        let file = ElfFile::parse(&bytes).unwrap();
        let h = file.header();
        assert_eq!(
            (h.phnum, h.shnum, h.shstrndx),
            (1, 3, Some(2)),
            "{c:?}/{e:?}"
        );
        let sh2 = file.section_headers().unwrap().get(2).unwrap();
        assert_eq!(file.section_name(&sh2).unwrap(), b".shstrtab");
    }
}

/// SHN_XINDEX in e_shstrndx with no section table: the real index is
/// unknowable. The resolved `shstrndx` must not pretend 0xffff is an index,
/// and looking up the name table must fail. (SHN_XINDEX is an escape value,
/// gABI ch4 "Sections": "This value is an escape value. It indicates that the
/// actual section header index is too large to fit in the containing field
/// and is to be found in another location".)
#[test]
fn shstrndx_xindex_without_section_table() {
    for (c, e) in LAYOUTS {
        let mut h = Eh::new(c);
        h.shstrndx = SHN_XINDEX;
        let bytes = header_only(c, e, &h);
        let f = ElfFile::parse(&bytes).unwrap();
        assert!(f.section_name_table().is_err());
        assert_ne!(
            f.header().shstrndx,
            Some(u32::from(SHN_XINDEX)),
            "{c:?}/{e:?}: unresolved SHN_XINDEX reported as a real index"
        );
    }
}

/// Loader contract (lib docs of `ElfFile`): "`parse` only fails if the
/// identification bytes or the ELF header itself are unusable. A broken
/// program header table or section header table does not make the whole file
/// unreadable". gABI-wise the escapes only redirect *counts* into section 0;
/// an unreadable section 0 makes the section table unusable, but the program
/// header table (when e_phnum is not PN_XNUM) is independent of it.
#[test]
fn unreadable_section0_with_shnum_escape_keeps_program_headers() {
    for (c, e) in LAYOUTS {
        let mut f = FileBuilder::new(c, e);
        f.phdr(Ph {
            p_type: PT_LOAD,
            ..Default::default()
        });
        let bytes = f.finish(|h| {
            h.shoff = 0x10_0000; // past EOF
            h.shnum = 0; // count would come from section 0
        });
        let file = ElfFile::parse(&bytes).expect("parse must not fail on a broken section table");
        assert_eq!(file.program_headers().unwrap().len(), 1, "{c:?}/{e:?}");
        assert!(file.section_headers().is_err(), "{c:?}/{e:?}");
    }
}

/// Same contract, with SHN_XINDEX in e_shstrndx and an unreadable section 0:
/// the segments must remain available.
#[test]
fn unreadable_section0_with_shstrndx_escape_keeps_program_headers() {
    for (c, e) in LAYOUTS {
        let mut f = FileBuilder::new(c, e);
        f.phdr(Ph {
            p_type: PT_LOAD,
            ..Default::default()
        });
        let bytes = f.finish(|h| {
            h.shoff = u64::from(u32::MAX) - 3; // past EOF, and offset+size overflows u32
            h.shnum = 4;
            h.shstrndx = SHN_XINDEX;
        });
        let file = ElfFile::parse(&bytes).expect("parse must not fail on a broken section table");
        assert_eq!(file.program_headers().unwrap().len(), 1, "{c:?}/{e:?}");
        assert!(file.section_headers().is_err(), "{c:?}/{e:?}");
        assert!(file.section_name_table().is_err(), "{c:?}/{e:?}");
    }
}

/// PN_XNUM with an unreadable section 0: parse should succeed (header is fine),
/// but the program header count is unknowable, so program_headers() errs.
#[test]
fn unreadable_section0_with_pn_xnum_errors_only_in_program_headers() {
    for (c, e) in LAYOUTS {
        let mut f = FileBuilder::new(c, e);
        f.phdr(Ph {
            p_type: PT_LOAD,
            ..Default::default()
        });
        let bytes = f.finish(|h| {
            h.shoff = 0x10_0000;
            h.shnum = 1;
            h.phnum = PN_XNUM;
        });
        let file = ElfFile::parse(&bytes).expect("parse must not fail on a broken section table");
        assert!(file.program_headers().is_err(), "{c:?}/{e:?}");
        assert!(file.section_headers().is_err(), "{c:?}/{e:?}");
    }
}

// ===========================================================================
// Broken section header table vs program headers
// ===========================================================================

#[test]
fn broken_section_table_still_exposes_program_headers() {
    for (c, e) in LAYOUTS {
        let s = sample(c, e);
        let mut bytes = s.bytes.clone();
        // Rewrite e_shoff to point past EOF. Its file offset is fixed by
        // Figure 4-3: 32 (ELF32) / 40 (ELF64).
        let mut h = Eh::new(c);
        let f0 = ElfFile::parse(&s.bytes).unwrap();
        let h0 = f0.header();
        h.e_type = h0.e_type;
        h.entry = h0.entry;
        h.phoff = h0.phoff;
        h.phnum = h0.raw_phnum;
        h.shnum = h0.raw_shnum;
        h.shstrndx = h0.raw_shstrndx;
        h.shoff = bytes.len() as u64 + 0x1000;
        let eh = enc_ehdr(c, e, &h);
        bytes[..eh.len()].copy_from_slice(&eh);

        let f = ElfFile::parse(&bytes).expect("header is fine");
        assert_eq!(
            f.program_headers().unwrap().iter().collect::<Vec<_>>(),
            vec![ph_widen(s.phdr)],
            "{c:?}/{e:?}"
        );
        assert!(matches!(
            f.section_headers(),
            Err(Error::OutOfBounds { .. })
        ));
        assert!(f.section_name_table().is_err());
        assert!(f.symbol_tables().is_err());
        assert!(f.section_by_name(b".text").is_none());
    }
}

fn ph_widen(p: Ph) -> unforge_elf::ProgramHeader {
    unforge_elf::ProgramHeader {
        p_type: p.p_type,
        flags: p.flags,
        offset: p.offset,
        vaddr: p.vaddr,
        paddr: p.paddr,
        filesz: p.filesz,
        memsz: p.memsz,
        align: p.align,
    }
}

/// An absurd e_shnum must not allocate or panic: the table is checked against
/// the file length first.
#[test]
fn huge_counts_do_not_panic() {
    for (c, e) in LAYOUTS {
        let mut h = Eh::new(c);
        h.phoff = u64::from(c.ehsize());
        h.phnum = 0xfffe;
        h.shoff = u64::from(c.ehsize());
        h.shnum = 0xfeff;
        let bytes = header_only(c, e, &h);
        let f = ElfFile::parse(&bytes).unwrap();
        assert!(f.program_headers().is_err());
        assert!(f.section_headers().is_err());
    }
}

// ===========================================================================
// st_shndx: SHN_XINDEX and the reserved range
// ===========================================================================

/// gABI ch4 "Sections", SHT_SYMTAB_SHNDX: "This section is associated with a
/// symbol table section and is required if any of the section header indexes
/// referenced by that symbol table contain the escape value SHN_XINDEX. The
/// section is an array of Elf32_Word values. Each value corresponds one to one
/// with a symbol table entry and appear in the same order as those entries."
/// Its sh_link is "The section header index of the associated symbol table
/// section" (Figure 4-14, sh_link and sh_info Interpretation).
#[test]
fn symtab_shndx_resolves_xindex() {
    for (c, e) in LAYOUTS {
        let syms = [
            Sy::default(),
            Sy {
                shndx: SHN_XINDEX,
                ..Default::default()
            },
            Sy {
                shndx: 1,
                ..Default::default()
            },
            Sy {
                shndx: SHN_XINDEX,
                ..Default::default()
            },
        ];
        // Symtab will be section 2 (0 = null, 1 = strtab). A decoy
        // SHT_SYMTAB_SHNDX linked to another section comes first.
        let decoy = (
            Sh {
                sh_type: SHT_SYMTAB_SHNDX,
                link: 7,
                entsize: 4,
                ..Default::default()
            },
            enc_words(e, &[0xdead, 0xdead, 0xdead, 0xdead]),
        );
        let real = (
            Sh {
                sh_type: SHT_SYMTAB_SHNDX,
                link: 2,
                entsize: 4,
                ..Default::default()
            },
            enc_words(e, &[0, 0x0001_2345, 0, 0x00ff_0000]),
        );
        let (bytes, idx) = with_symtab(c, e, &syms, c.symsize(), &[decoy, real]);
        assert_eq!(idx, 2);
        let f = ElfFile::parse(&bytes).unwrap();
        let t = f.symbol_table(idx).unwrap();
        assert_eq!(t.get(1).unwrap().raw_shndx, SHN_XINDEX);
        assert_eq!(
            t.get(1).unwrap().section,
            SymbolSection::Index(0x0001_2345),
            "{c:?}/{e:?}"
        );
        assert_eq!(t.get(2).unwrap().section, SymbolSection::Index(1));
        assert_eq!(
            t.get(3).unwrap().section,
            SymbolSection::Index(0x00ff_0000),
            "{c:?}/{e:?}"
        );
    }
}

/// Without the required SHT_SYMTAB_SHNDX section the real index is unknown;
/// it must not be reported as a real section index.
#[test]
fn xindex_without_symtab_shndx_is_not_an_index() {
    for (c, e) in LAYOUTS {
        let syms = [
            Sy::default(),
            Sy {
                shndx: SHN_XINDEX,
                ..Default::default()
            },
        ];
        let (bytes, idx) = with_symtab(c, e, &syms, c.symsize(), &[]);
        let f = ElfFile::parse(&bytes).unwrap();
        // Either an error or a non-Index classification is acceptable.
        if let Ok(t) = f.symbol_table(idx) {
            assert!(
                !matches!(t.get(1).unwrap().section, SymbolSection::Index(_)),
                "{c:?}/{e:?}: {:?}",
                t.get(1).unwrap().section
            );
        }
    }
}

/// gABI ch4 "Sections", Figure 4-7 Special Section Indexes: SHN_UNDEF 0,
/// SHN_LORESERVE 0xff00, SHN_LOPROC 0xff00, SHN_HIPROC 0xff1f, SHN_LOOS
/// 0xff20, SHN_HIOS 0xff3f, SHN_ABS 0xfff1, SHN_COMMON 0xfff2, SHN_XINDEX
/// 0xffff, SHN_HIRESERVE 0xffff. "The system reserves indexes between
/// SHN_LORESERVE and SHN_HIRESERVE, inclusive".
#[test]
fn st_shndx_classification() {
    let cases: &[(u16, SymbolSection)] = &[
        (0, SymbolSection::Undefined),
        (1, SymbolSection::Index(1)),
        (0xfeff, SymbolSection::Index(0xfeff)),
        (0xff00, SymbolSection::Reserved(0xff00)), // SHN_LOPROC
        (0xff1f, SymbolSection::Reserved(0xff1f)), // SHN_HIPROC
        (0xff20, SymbolSection::Reserved(0xff20)), // SHN_LOOS
        (0xff3f, SymbolSection::Reserved(0xff3f)), // SHN_HIOS
        (0xfff1, SymbolSection::Absolute),
        (0xfff2, SymbolSection::Common),
        (0xfff3, SymbolSection::Reserved(0xfff3)),
    ];
    for (c, e) in LAYOUTS {
        let mut syms = vec![Sy::default()];
        syms.extend(cases.iter().map(|&(shndx, _)| Sy {
            shndx,
            ..Default::default()
        }));
        let (bytes, idx) = with_symtab(c, e, &syms, c.symsize(), &[]);
        let f = ElfFile::parse(&bytes).unwrap();
        let t = f.symbol_table(idx).unwrap();
        for (i, &(raw, want)) in cases.iter().enumerate() {
            let s = t.get(i + 1).unwrap();
            assert_eq!(s.raw_shndx, raw);
            assert_eq!(s.section, want, "{c:?}/{e:?} shndx {raw:#x}");
        }
    }
}

// ===========================================================================
// Entry sizes
// ===========================================================================

/// gABI sh_entsize: "Some sections hold a table of fixed-size entries, such as
/// a symbol table. For such a section, this member gives the size in bytes of
/// each entry." So the stride between symbols is sh_entsize, and the count is
/// sh_size / sh_entsize. (A larger-than-struct entsize is not forbidden by the
/// gABI; it is how the format allows extension.)
#[test]
fn symtab_entsize_larger_than_struct_is_the_stride() {
    for (c, e) in LAYOUTS {
        let entsize = c.symsize() + 8;
        let syms = [
            Sy::default(),
            Sy {
                name: 1,
                value: 0x1000,
                size: 1,
                info: 0x12,
                shndx: 1,
                ..Default::default()
            },
            Sy {
                name: 2,
                value: 0x2000,
                size: 2,
                info: 0x11,
                shndx: 1,
                ..Default::default()
            },
        ];
        let (bytes, idx) = with_symtab(c, e, &syms, entsize, &[]);
        let f = ElfFile::parse(&bytes).unwrap();
        let t = f.symbol_table(idx).unwrap();
        assert_eq!(t.len(), 3, "{c:?}/{e:?}");
        assert_eq!(
            (t.get(2).unwrap().name, t.get(2).unwrap().value),
            (2, 0x2000),
            "{c:?}/{e:?}"
        );
    }
}

/// count = sh_size / sh_entsize; a trailing partial entry is not an entry.
#[test]
fn symbol_count_is_size_div_entsize() {
    for (c, e) in LAYOUTS {
        let mut f = FileBuilder::new(c, e);
        f.section(Sh::default());
        let strtab = f.section_with(
            Sh {
                sh_type: SHT_STRTAB,
                ..Default::default()
            },
            b"\0",
        );
        let mut data = enc_syms(c, e, &[Sy::default(), Sy::default(), Sy::default()]);
        data.extend([0xEE; 5]); // partial trailing entry
        let idx = f.section_with(
            Sh {
                sh_type: SHT_SYMTAB,
                link: strtab as u32,
                entsize: c.symsize(),
                ..Default::default()
            },
            &data,
        );
        let bytes = f.finish(|_| {});
        let file = ElfFile::parse(&bytes).unwrap();
        assert_eq!(file.symbol_table(idx).unwrap().len(), 3, "{c:?}/{e:?}");
    }
}

/// sh_entsize smaller than the symbol structure (including 0) cannot describe
/// a symbol table; it must never be a division by zero.
///
/// Changed from the strict reader (Err(BadEntrySize)): the structure size is
/// used as the stride, and the audit records that inference.
#[test]
fn symtab_entsize_too_small_is_inferred() {
    for (c, e) in LAYOUTS {
        for entsize in [0, 1, c.symsize() - 1] {
            let mut f = FileBuilder::new(c, e);
            f.section(Sh::default());
            let idx = f.section_with(
                Sh {
                    sh_type: SHT_SYMTAB,
                    entsize,
                    ..Default::default()
                },
                &[0; 48],
            );
            let bytes = f.finish(|_| {});
            let file = ElfFile::parse(&bytes).unwrap();
            let t = file.symbol_table(idx).unwrap();
            assert!(t.entry_size_inferred(), "{c:?}/{e:?} entsize {entsize}");
            assert_eq!(t.entry_size() as u64, c.symsize());
            assert_eq!(
                t.len() as u64,
                48 / c.symsize(),
                "{c:?}/{e:?} entsize {entsize}"
            );
            assert!(
                file.inferences().iter().any(|i| i.subject
                    == InferenceSubject::SymbolEntrySize { table: idx }
                    && i.chosen == Choice::EntrySize(c.symsize())),
                "{c:?}/{e:?} entsize {entsize}"
            );
        }
    }
}

/// gABI e_phentsize: "This member holds the size in bytes of one entry in the
/// file's program header table; all entries are the same size." Likewise
/// e_shentsize. A larger entry size is therefore the stride. Note: `object`
/// rejects any e_phentsize/e_shentsize != sizeof(struct); the gABI does not
/// state that requirement, so this is a policy difference, not a spec rule.
#[test]
fn header_entsize_larger_than_struct_is_the_stride() {
    for (c, e) in LAYOUTS {
        let mut f = FileBuilder::new(c, e);
        f.ph_pad = 8;
        f.sh_pad = 16;
        f.phdr(Ph {
            p_type: PT_LOAD,
            vaddr: 0x1000,
            ..Default::default()
        });
        f.phdr(Ph {
            p_type: PT_DYNAMIC,
            vaddr: 0x2000,
            ..Default::default()
        });
        f.section(Sh::default());
        f.section(Sh {
            name: 9,
            sh_type: SHT_NOBITS,
            ..Default::default()
        });
        f.section(Sh {
            name: 10,
            sh_type: SHT_NOTE,
            ..Default::default()
        });
        let bytes = f.finish(|_| {});
        let file = ElfFile::parse(&bytes).unwrap();
        let ph = file.program_headers().unwrap();
        assert_eq!(
            ph.iter().map(|p| (p.p_type, p.vaddr)).collect::<Vec<_>>(),
            [(PT_LOAD, 0x1000), (PT_DYNAMIC, 0x2000)],
            "{c:?}/{e:?}"
        );
        let sh = file.section_headers().unwrap();
        assert_eq!(
            sh.iter().map(|s| (s.name, s.sh_type)).collect::<Vec<_>>(),
            [(0, SHT_NULL), (9, SHT_NOBITS), (10, SHT_NOTE)],
            "{c:?}/{e:?}"
        );
    }
}

/// e_phentsize / e_shentsize smaller than the structure.
///
/// Changed from the strict reader (Err(BadEntrySize) from the accessors): the
/// structure size is used as the stride, the tables are read, and the audit
/// reports both the bad field and the inference.
#[test]
fn header_entsize_too_small_is_inferred() {
    for (c, e) in LAYOUTS {
        let s = sample(c, e);
        let mut bytes = s.bytes.clone();
        // e_phentsize / e_shentsize offsets per Figure 4-3.
        let (phent_off, shent_off) = match c {
            C::E32 => (42, 46),
            C::E64 => (54, 58),
        };
        let small = |v: u16| match e {
            E::L => v.to_le_bytes(),
            E::B => v.to_be_bytes(),
        };
        bytes[phent_off..phent_off + 2].copy_from_slice(&small(c.phentsize() - 1));
        bytes[shent_off..shent_off + 2].copy_from_slice(&small(0));
        let f = ElfFile::parse(&bytes).unwrap();
        let good = ElfFile::parse(&s.bytes).unwrap();
        assert_eq!(
            f.program_headers().unwrap().iter().collect::<Vec<_>>(),
            good.program_headers().unwrap().iter().collect::<Vec<_>>(),
            "{c:?}/{e:?}"
        );
        assert_eq!(
            f.section_headers().unwrap().iter().collect::<Vec<_>>(),
            good.section_headers().unwrap().iter().collect::<Vec<_>>(),
            "{c:?}/{e:?}"
        );
        let subjects: Vec<_> = f.inferences().iter().map(|i| i.subject).collect();
        assert!(subjects.contains(&InferenceSubject::ProgramHeaderEntrySize));
        assert!(subjects.contains(&InferenceSubject::SectionHeaderEntrySize));
        let ds = f.diagnostics();
        assert!(
            ds.iter()
                .any(|d| matches!(d.kind, DiagnosticKind::BadProgramHeaderEntrySize { .. }))
        );
        assert!(
            ds.iter()
                .any(|d| matches!(d.kind, DiagnosticKind::BadSectionEntrySize { found: 0, .. }))
        );
    }
}

// ===========================================================================
// Section data
// ===========================================================================

/// gABI sh_size: "A section of type SHT_NOBITS may have a non-zero size, but
/// it occupies no space in the file." and sh_offset: "One section type,
/// SHT_NOBITS ..., occupies no space in the file, and its sh_offset member
/// locates the conceptual placement in the file."
#[test]
fn nobits_section_data_is_empty() {
    for (c, e) in LAYOUTS {
        let mut f = FileBuilder::new(c, e);
        f.section(Sh::default());
        f.section(Sh {
            sh_type: SHT_NOBITS,
            offset: 0x7fff_0000,
            size: 0x7fff_ffff,
            ..Default::default()
        });
        let bytes = f.finish(|_| {});
        let file = ElfFile::parse(&bytes).unwrap();
        let sh = file.section_headers().unwrap().get(1).unwrap();
        assert_eq!(file.section_data(&sh).unwrap(), &[] as &[u8], "{c:?}/{e:?}");
        // A PROGBITS section with the same numbers has no bytes in the file.
        // Changed from the strict reader (Err(OutOfBounds)): the range is
        // clipped to the file (here: nothing left) and the shortfall is
        // reported by section_bytes.
        let mut pb = sh;
        pb.sh_type = SHT_PROGBITS;
        assert_eq!(file.section_data(&pb).unwrap(), &[] as &[u8]);
        assert_eq!(file.section_bytes(&pb).missing, 0x7fff_ffff);
    }
}

#[test]
fn section_data_offset_plus_size_overflow_is_an_error() {
    let s = sample(C::E64, E::L);
    let f = ElfFile::parse(&s.bytes).unwrap();
    let mut sh = f.section_headers().unwrap().get(1).unwrap();
    sh.offset = u64::MAX - 1;
    sh.size = 4;
    assert!(f.section_data(&sh).is_err());
}

/// gABI ch5 "Program Header": p_filesz is the file image size; p_memsz may be
/// larger (bss). segment_data returns p_filesz bytes.
#[test]
fn segment_data_uses_filesz() {
    let mut f = FileBuilder::new(C::E64, E::L);
    let off = f.blob(b"ABCDEFGH");
    f.phdr(Ph {
        p_type: PT_LOAD,
        offset: off,
        filesz: 4,
        memsz: 0x1_0000,
        ..Default::default()
    });
    let bytes = f.finish(|_| {});
    let file = ElfFile::parse(&bytes).unwrap();
    let ph = file.program_headers().unwrap().get(0).unwrap();
    assert_eq!(file.segment_data(&ph).unwrap(), b"ABCD");
}

// ===========================================================================
// Section names (gABI ch4 "String Table")
// ===========================================================================

/// Builds a file whose .shstrtab is `table` and whose sections use `names`
/// (sh_name offsets). The shstrtab is the last section.
fn with_names(c: C, e: E, table: &[u8], names: &[u32]) -> Vec<u8> {
    let mut f = FileBuilder::new(c, e);
    f.section(Sh::default());
    for &n in names {
        f.section(Sh {
            name: n,
            sh_type: SHT_PROGBITS,
            ..Default::default()
        });
    }
    let strndx = f.section_with(
        Sh {
            sh_type: SHT_STRTAB,
            ..Default::default()
        },
        table,
    );
    f.finish(|h| h.shstrndx = strndx as u16)
}

/// gABI "String Table": "One references a string as an index into the string
/// table section. The first byte, which is index zero, is defined to hold a
/// null character. ... A string whose index is zero specifies either no name
/// or a null name". Also: "A string table index may refer to any byte in the
/// section. A string may appear more than once; references to substrings may
/// exist; and a single string may be referenced multiple times."
#[test]
fn section_names_empty_tail_shared_and_non_utf8() {
    // Offsets: 0 = "", 1 = ".rela.text", 6 = ".text" (tail of 1),
    // 8 = "ext" (mid-string), 12 = "\xff\xfe.x" (not UTF-8).
    let table: &[u8] = b"\0.rela.text\0\xff\xfe.x\0\0";
    for (c, e) in LAYOUTS {
        let bytes = with_names(c, e, table, &[0, 1, 6, 12, 8]);
        let f = ElfFile::parse(&bytes).unwrap();
        let shs: Vec<_> = f.section_headers().unwrap().iter().collect();
        let name = |i: usize| f.section_name(&shs[i]).unwrap();
        assert_eq!(name(0), b"");
        assert_eq!(name(1), b"");
        assert_eq!(name(2), b".rela.text");
        assert_eq!(name(3), b".text");
        assert_eq!(name(4), b"\xff\xfe.x");
        assert!(std::str::from_utf8(name(4)).is_err());
        assert_eq!(name(5), b"ext");
        assert_eq!(f.section_by_name(b".text").map(|(i, _)| i), Some(3));
        assert_eq!(f.section_by_name(b"\xff\xfe.x").map(|(i, _)| i), Some(4));
        assert_eq!(f.section_by_name(b".data"), None);
    }
}

/// An sh_name past the table, or a string without its NUL terminator, is an
/// error. gABI "String Table": "the last byte, which is the last byte of the
/// section, is defined to hold a null character, ensuring null termination for
/// all strings."
#[test]
fn section_name_out_of_range_or_unterminated_is_an_error() {
    let table: &[u8] = b"\0.text\0.bad"; // last string lacks its NUL
    for (c, e) in LAYOUTS {
        let bytes = with_names(c, e, table, &[7, 11, 12, 0xffff_ffff]);
        let f = ElfFile::parse(&bytes).unwrap();
        let shs: Vec<_> = f.section_headers().unwrap().iter().collect();
        assert!(matches!(
            f.section_name(&shs[1]),
            Err(Error::BadString { .. })
        ));
        // Offset == table length: no bytes left, so no terminator.
        assert!(matches!(
            f.section_name(&shs[2]),
            Err(Error::BadString { .. })
        ));
        assert!(matches!(
            f.section_name(&shs[3]),
            Err(Error::BadString { .. })
        ));
        assert!(matches!(
            f.section_name(&shs[4]),
            Err(Error::BadString { .. })
        ));
    }
}

/// gABI e_shstrndx: "If the file has no section name string table, this member
/// holds the value SHN_UNDEF." Parse succeeds; names are unavailable.
#[test]
fn shstrndx_undef_parses_but_names_fail() {
    for (c, e) in LAYOUTS {
        let s = sample(c, e);
        let mut bytes = s.bytes.clone();
        let off = match c {
            C::E32 => 50,
            C::E64 => 62,
        };
        bytes[off..off + 2].copy_from_slice(&[0, 0]);
        let f = ElfFile::parse(&bytes).expect("SHN_UNDEF shstrndx is valid");
        assert_eq!(f.header().shstrndx, None);
        assert_eq!(f.section_headers().unwrap().len(), 5);
        let sh1 = f.section_headers().unwrap().get(1).unwrap();
        assert!(f.section_name(&sh1).is_err());
        assert!(f.section_name_table().is_err());
        assert!(f.section_by_name(b".text").is_none());
        // Symbol names use the symtab's own sh_link, not e_shstrndx.
        let t = f.symbol_table(4).unwrap();
        assert_eq!(t.name(&t.get(1).unwrap()).unwrap(), b"main");
    }
}

#[test]
fn shstrndx_past_section_count_is_an_error() {
    for (c, e) in LAYOUTS {
        let bytes = with_names(c, e, b"\0", &[0]);
        let mut patched = bytes.clone();
        let off = match c {
            C::E32 => 50,
            C::E64 => 62,
        };
        let v = match e {
            E::L => 9u16.to_le_bytes(),
            E::B => 9u16.to_be_bytes(),
        };
        patched[off..off + 2].copy_from_slice(&v);
        let f = ElfFile::parse(&patched).unwrap();
        assert!(matches!(
            f.section_name_table(),
            Err(Error::BadIndex { .. })
        ));
    }
}

// ===========================================================================
// Symbols
// ===========================================================================

/// gABI ch4 "Symbol Table": ELF32_ST_BIND(i) ((i)>>4), ELF32_ST_TYPE(i)
/// ((i)&0xf), ELF32_ST_VISIBILITY(o) ((o)&0x3); the ELF64 macros are the same.
#[test]
fn symbol_bind_kind_visibility() {
    let cases: &[(u8, u8, u8, u8, u8)] = &[
        // info, other, bind, type, visibility
        (0x00, 0x00, STB_LOCAL, STT_NOTYPE, 0),
        (0x12, 0x00, STB_GLOBAL, STT_FUNC, 0),
        (0x21, 0x01, STB_WEAK, STT_OBJECT, 1),   // STV_INTERNAL
        (0x16, 0x02, STB_GLOBAL, STT_TLS, 2),    // STV_HIDDEN
        (0x03, 0x03, STB_LOCAL, STT_SECTION, 3), // STV_PROTECTED
        (0xa4, 0xfc, 10, STT_FILE, 0),           // STB_LOOS=10; upper bits of st_other ignored
        (0xff, 0xff, 15, 15, 3),
    ];
    for (c, e) in LAYOUTS {
        let mut syms = vec![Sy::default()];
        syms.extend(cases.iter().map(|&(info, other, ..)| Sy {
            info,
            other,
            ..Default::default()
        }));
        let (bytes, idx) = with_symtab(c, e, &syms, c.symsize(), &[]);
        let f = ElfFile::parse(&bytes).unwrap();
        let t = f.symbol_table(idx).unwrap();
        for (i, &(info, _, bind, kind, vis)) in cases.iter().enumerate() {
            let s = t.get(i + 1).unwrap();
            assert_eq!(
                (s.bind(), s.kind(), s.visibility()),
                (bind, kind, vis),
                "info {info:#x}"
            );
        }
    }
}

#[test]
fn symbol_names_via_sh_link_strtab() {
    for (c, e) in LAYOUTS {
        let s = sample(c, e);
        let f = ElfFile::parse(&s.bytes).unwrap();
        let tables: Vec<_> = f.symbol_tables().unwrap().collect();
        assert_eq!(tables.len(), 1);
        let t = &tables[0];
        assert_eq!(t.section_index, 4);
        assert_eq!(t.strtab(), Some(STRTAB));
        assert_eq!(t.len(), s.syms.len());
        assert_eq!(t.name(&t.get(0).unwrap()).unwrap(), b"");
        assert_eq!(t.name(&t.get(1).unwrap()).unwrap(), b"main");
        assert_eq!(t.name(&t.get(2).unwrap()).unwrap(), b"helper");
        assert_eq!(t.get(2).unwrap().visibility(), 2);
    }
}

/// symbol_table on a non-symbol section is a typed error.
#[test]
fn symbol_table_on_wrong_section_type() {
    let s = sample(C::E64, E::L);
    let f = ElfFile::parse(&s.bytes).unwrap();
    assert!(matches!(
        f.symbol_table(1),
        Err(Error::WrongSectionType {
            sh_type: SHT_PROGBITS,
            ..
        })
    ));
    assert!(matches!(f.symbol_table(99), Err(Error::BadIndex { .. })));
}

// ===========================================================================
// Compile-time facts about the raw layer
// ===========================================================================

fn assert_unaligned<T: zerocopy::Unaligned + zerocopy::FromBytes>() {}

/// Every raw struct must be `Unaligned` (alignment 1) so that reading from any
/// file offset can only fail for size, never for alignment. Checked by trait
/// bound at compile time and by `align_of` at run time.
#[test]
fn raw_structs_are_unaligned_and_sized_per_gabi() {
    use core::mem::{align_of, size_of};
    use unforge_elf::raw::*;
    use zerocopy::byteorder::{BigEndian as B, LittleEndian as L};

    macro_rules! check {
        ($t:ty, $size:expr) => {
            assert_unaligned::<$t>();
            assert_eq!(align_of::<$t>(), 1, stringify!($t));
            assert_eq!(size_of::<$t>(), $size, stringify!($t));
        };
    }
    check!(Ident, 16); // EI_NIDENT
    check!(Ehdr32<L>, 52);
    check!(Ehdr32<B>, 52);
    check!(Ehdr64<L>, 64);
    check!(Ehdr64<B>, 64);
    check!(Phdr32<L>, 32);
    check!(Phdr64<B>, 56);
    check!(Shdr32<L>, 40);
    check!(Shdr64<B>, 64);
    check!(Sym32<L>, 16);
    check!(Sym64<B>, 24);
}

/// Parsing at an odd address must work (Unaligned in practice): feed the
/// sample file from a buffer offset by 1 byte.
#[test]
fn parse_from_misaligned_buffer() {
    for (c, e) in LAYOUTS {
        let s = sample(c, e);
        let mut buf = vec![0u8; s.bytes.len() + 1];
        buf[1..].copy_from_slice(&s.bytes);
        let f = ElfFile::parse(&buf[1..]).unwrap();
        assert_eq!(f.symbol_tables().unwrap().next().unwrap().len(), 3);
    }
}

/// Every prefix of a valid file must parse or fail without panicking.
#[test]
fn every_prefix_is_panic_free() {
    for (c, e) in LAYOUTS {
        let s = sample(c, e);
        for n in 0..=s.bytes.len() {
            let data = &s.bytes[..n];
            if let Ok(f) = ElfFile::parse(data) {
                let _ = f.program_headers();
                if let Ok(shs) = f.section_headers() {
                    for sh in shs {
                        let _ = f.section_data(&sh);
                        let _ = f.section_name(&sh);
                    }
                }
                if let Ok(ts) = f.symbol_tables() {
                    for t in ts {
                        let _ = t.iter().count();
                    }
                }
                let _ = f.audit();
            }
        }
    }
}

// ===========================================================================
// Review round: sh_link of symbol tables, SHN_XINDEX resolution, reserved
// e_shstrndx, trailing bytes, header deviations, bounded names.
// ===========================================================================

/// A symtab whose sh_link is `link`, in a file with sections
/// [0] NULL, [1] STRTAB "\0abc\0", [2] PROGBITS, [3] SYMTAB.
fn symtab_linked_to(c: C, e: E, link: u32) -> (Vec<u8>, usize) {
    let mut f = FileBuilder::new(c, e);
    f.section(Sh::default());
    f.section_with(
        Sh {
            sh_type: SHT_STRTAB,
            ..Default::default()
        },
        b"\0abc\0",
    );
    f.section_with(
        Sh {
            sh_type: SHT_PROGBITS,
            ..Default::default()
        },
        b"\0xyz\0",
    );
    let idx = f.section_with(
        Sh {
            sh_type: SHT_SYMTAB,
            link,
            entsize: c.symsize(),
            ..Default::default()
        },
        &enc_syms(
            c,
            e,
            &[
                Sy::default(),
                Sy {
                    name: 1,
                    ..Default::default()
                },
            ],
        ),
    );
    (f.finish(|_| {}), idx)
}

/// gABI ch4 "Sections", Figure 4-14: for SHT_SYMTAB / SHT_DYNSYM, sh_link is
/// "The section header index of the associated string table." Index 0 is
/// SHN_UNDEF (the SHT_NULL entry, "it does not have an associated section"),
/// and a non-SHT_STRTAB section is not a string table.
#[test]
fn symtab_sh_link_must_name_a_strtab() {
    for (c, e) in LAYOUTS {
        let (bytes, idx) = symtab_linked_to(c, e, 1);
        let f = ElfFile::parse(&bytes).unwrap();
        let t = f.symbol_table(idx).unwrap();
        assert_eq!(t.name(&t.get(1).unwrap()).unwrap(), b"abc");

        // Changed from the strict reader, which failed the whole table
        // (Err(BadIndex) for sh_link 0, Err(WrongSectionType) for a
        // non-STRTAB link, and symbol_tables() failed with it): the symbols
        // are read either way and the anomaly is a diagnostic.
        let (bytes, idx) = symtab_linked_to(c, e, 0);
        let f = ElfFile::parse(&bytes).unwrap();
        let t = f.symbol_table(idx).unwrap();
        assert!(t.len() >= 2, "{c:?}/{e:?}");
        assert_eq!(t.strtab(), None);
        assert!(matches!(
            t.name(&t.get(1).unwrap()),
            Err(Error::Missing { .. })
        ));
        assert!(f.diagnostics().iter().any(|d| matches!(
            d.kind,
            DiagnosticKind::SymbolTableLinkInvalid { link: 0, .. }
        )));

        let (bytes, idx) = symtab_linked_to(c, e, 2);
        let f = ElfFile::parse(&bytes).unwrap();
        let t = f.symbol_table(idx).unwrap();
        assert_eq!(t.strtab_index(), Some(2));
        assert!(f.diagnostics().iter().any(|d| matches!(
            d.kind,
            DiagnosticKind::SymbolTableLinkNotStrtab {
                link: 2,
                sh_type: SHT_PROGBITS,
                ..
            }
        )));
        // Which string table is meant is an inference; the SHT_STRTAB
        // section is listed as the alternative.
        let i = f
            .inferences()
            .into_iter()
            .find(|i| i.subject == InferenceSubject::StringTable { table: idx })
            .expect("string table inference");
        assert_eq!(i.chosen, Choice::Section(2));
        assert!(
            i.alternatives
                .iter()
                .any(|a| a.choice == Choice::Section(1))
        );
        assert_eq!(f.symbol_tables().unwrap().count(), 1);
    }
}

/// With extended numbering, section 0's sh_size holds the section count and
/// sh_offset is 0, so reading section 0 "as data" would return the ELF header.
/// section_data of an SHT_NULL section is empty, and a symtab linked to 0 has
/// no names (changed from the strict reader, where the table failed).
#[test]
fn extended_numbering_section0_is_not_a_string_table() {
    for (c, e) in LAYOUTS {
        let mut f = FileBuilder::new(c, e);
        f.section(Sh {
            size: 3, // real e_shnum
            ..Default::default()
        });
        f.section_with(
            Sh {
                sh_type: SHT_STRTAB,
                ..Default::default()
            },
            b"\0abc\0",
        );
        let idx = f.section_with(
            Sh {
                sh_type: SHT_SYMTAB,
                link: 0,
                entsize: c.symsize(),
                ..Default::default()
            },
            &enc_syms(
                c,
                e,
                &[
                    Sy::default(),
                    Sy {
                        name: 1,
                        ..Default::default()
                    },
                ],
            ),
        );
        let bytes = f.finish(|h| h.shnum = 0);
        let file = ElfFile::parse(&bytes).unwrap();
        assert_eq!(file.header().shnum, 3, "{c:?}/{e:?}");
        let sh0 = file.section_header(0).unwrap();
        assert_eq!(file.section_data(&sh0).unwrap(), b"", "{c:?}/{e:?}");
        let t = file.symbol_table(idx).unwrap();
        assert!(t.strtab().is_none(), "{c:?}/{e:?}");
        assert!(t.name(&t.get(1).unwrap()).is_err(), "{c:?}/{e:?}");
    }
}

/// One symtab (section 2) with symbols [null, XINDEX, 1, XINDEX] plus `extra`.
fn xindex_file(c: C, e: E, extra: &[(Sh, Vec<u8>)]) -> (Vec<u8>, usize) {
    let syms = [
        Sy::default(),
        Sy {
            shndx: SHN_XINDEX,
            ..Default::default()
        },
        Sy {
            shndx: 1,
            ..Default::default()
        },
        Sy {
            shndx: SHN_XINDEX,
            ..Default::default()
        },
    ];
    with_symtab(c, e, &syms, c.symsize(), extra)
}

fn shndx_section(link: u32) -> Sh {
    Sh {
        sh_type: SHT_SYMTAB_SHNDX,
        link,
        entsize: 4,
        ..Default::default()
    }
}

/// gABI ch4 "Sections", SHT_SYMTAB_SHNDX is "required if any of the section
/// header indexes referenced by that symbol table contain the escape value
/// SHN_XINDEX". Every way of not having a usable entry gives `Unresolved`
/// for that symbol only; the table itself still reads, and other symbols
/// are unaffected.
#[test]
fn unresolvable_xindex_is_unresolved_not_reserved() {
    use SymbolSection::{Index, Unresolved};
    for (c, e) in LAYOUTS {
        type Case = (&'static str, Vec<(Sh, Vec<u8>)>, [SymbolSection; 2]);
        let cases: Vec<Case> = vec![
            ("(a) no SHT_SYMTAB_SHNDX", vec![], [Unresolved, Unresolved]),
            (
                "(b) too short: one entry for four symbols",
                vec![(shndx_section(2), enc_words(e, &[0, 0x1_0000]))],
                [Index(0x1_0000), Unresolved],
            ),
            (
                "(d) entry is 0 (SHN_UNDEF)",
                vec![(shndx_section(2), enc_words(e, &[0, 0, 0, 0x2_0000]))],
                [Unresolved, Index(0x2_0000)],
            ),
        ];
        for (what, extra, want) in cases {
            let (bytes, idx) = xindex_file(c, e, &extra);
            let f = ElfFile::parse(&bytes).unwrap();
            let t = f.symbol_table(idx).unwrap();
            assert_eq!(
                [t.get(1).unwrap().section, t.get(3).unwrap().section],
                want,
                "{c:?}/{e:?} {what}"
            );
            assert_eq!(t.get(2).unwrap().section, Index(1), "{c:?}/{e:?} {what}");
            let n = want.iter().filter(|s| **s == Unresolved).count();
            assert_eq!(t.unresolved_count(), n, "{c:?}/{e:?} {what}");
        }

        // (c) the SHT_SYMTAB_SHNDX data is outside the file.
        let (mut bytes, idx) = xindex_file(c, e, &[(shndx_section(2), enc_words(e, &[0; 4]))]);
        // Section 3 is the SHNDX; overwrite its sh_offset.
        let h = ElfFile::parse(&bytes).unwrap().header().clone();
        let off_field = usize::try_from(h.shoff).unwrap()
            + 3 * usize::from(c.shentsize())
            + match c {
                C::E32 => 16,
                C::E64 => 24,
            };
        let mut w = W::new(c, e);
        w.nat(0xffff_0000);
        bytes[off_field..off_field + w.out.len()].copy_from_slice(&w.out);
        let f = ElfFile::parse(&bytes).unwrap();
        assert_eq!(f.section_header(3).unwrap().offset, 0xffff_0000);
        let t = f.symbol_table(idx).unwrap();
        assert_eq!(t.get(1).unwrap().section, Unresolved, "{c:?}/{e:?} (c)");
        assert_eq!(t.get(3).unwrap().section, Unresolved, "{c:?}/{e:?} (c)");
        assert_eq!(t.unresolved_count(), 2);
    }
}

/// gABI ch4 "ELF Header", e_shstrndx: "If the section name string table
/// section index is greater than or equal to SHN_LORESERVE (0xff00), this
/// member has the value SHN_XINDEX (0xffff) and the actual index ... is
/// contained in the sh_link field of the section header at index 0." So the
/// raw values 0xff00..=0xfffe break the rule.
///
/// Changed from the strict reader (shstrndx = None): the raw value is the only
/// index the file gives, so it is kept, the audit reports it, and here it is
/// past the section table, so the name table is still unavailable.
#[test]
fn reserved_shstrndx_is_reported() {
    for (c, e) in LAYOUTS {
        for raw in [SHN_LORESERVE, 0xff05, SHN_ABS, 0xfffe] {
            let mut f = FileBuilder::new(c, e);
            f.section(Sh {
                size: 0, // no extended count
                ..Default::default()
            });
            f.section_with(
                Sh {
                    name: 1,
                    sh_type: SHT_STRTAB,
                    ..Default::default()
                },
                b"\0.shstrtab\0",
            );
            let bytes = f.finish(|h| h.shstrndx = raw);
            let file = ElfFile::parse(&bytes).unwrap();
            assert_eq!(file.header().raw_shstrndx, raw);
            assert_eq!(
                file.header().shstrndx,
                Some(u32::from(raw)),
                "{c:?}/{e:?} {raw:#x}"
            );
            let ds = file.diagnostics();
            assert!(
                ds.iter()
                    .any(|d| d.kind == DiagnosticKind::ShstrndxReserved(raw)),
                "{c:?}/{e:?} {raw:#x}"
            );
            assert!(
                ds.iter()
                    .any(|d| matches!(d.kind, DiagnosticKind::ShstrndxOutOfRange { .. })),
                "{c:?}/{e:?} {raw:#x}"
            );
            assert!(
                matches!(
                    file.section_name_table(),
                    Err(Error::BadIndex { index, .. }) if index == u64::from(raw)
                ),
                "{c:?}/{e:?} {raw:#x}"
            );
        }
    }
}

/// count = sh_size / sh_entsize; the remainder is reported, not silently lost.
#[test]
fn symtab_trailing_bytes_are_reported() {
    for (c, e) in LAYOUTS {
        for extra in [0usize, 1, 5] {
            let mut f = FileBuilder::new(c, e);
            f.section(Sh::default());
            let strtab = f.section_with(
                Sh {
                    sh_type: SHT_STRTAB,
                    ..Default::default()
                },
                b"\0",
            );
            let mut data = enc_syms(c, e, &[Sy::default(), Sy::default()]);
            data.extend(std::iter::repeat_n(0xEE, extra));
            let idx = f.section_with(
                Sh {
                    sh_type: SHT_SYMTAB,
                    link: strtab as u32,
                    entsize: c.symsize(),
                    ..Default::default()
                },
                &data,
            );
            let bytes = f.finish(|_| {});
            let file = ElfFile::parse(&bytes).unwrap();
            let t = file.symbol_table(idx).unwrap();
            assert_eq!(t.len(), 2);
            assert_eq!(t.trailing_bytes(), extra as u64, "{c:?}/{e:?}");
        }
    }
}

/// gABI ch4 "ELF Identification", EI_VERSION: "Currently, this value must be
/// EV_CURRENT"; e_version: EV_CURRENT = 1; e_ehsize: "the ELF header's size in
/// bytes" (52 for Elf32_Ehdr, 64 for Elf64_Ehdr). Deviations are reported by
/// the audit (formerly `Header::deviations`, now folded into
/// `DiagnosticKind`), and `parse` still succeeds.
#[test]
fn header_deviations_are_reported() {
    let header_kinds = |f: &ElfFile<'_>| -> Vec<DiagnosticKind> {
        f.diagnostics()
            .into_iter()
            .map(|d| d.kind)
            .filter(|k| {
                matches!(
                    k,
                    DiagnosticKind::IdentVersion(_)
                        | DiagnosticKind::Version(_)
                        | DiagnosticKind::HeaderSize { .. }
                )
            })
            .collect()
    };
    for (c, e) in LAYOUTS {
        let s = sample(c, e);
        let f = ElfFile::parse(&s.bytes).unwrap();
        assert_eq!(header_kinds(&f), vec![], "{c:?}/{e:?}");

        let mut fb = FileBuilder::new(c, e);
        fb.section(Sh::default());
        let bytes = fb.finish(|h| {
            h.ident.version = 2;
            h.version = 0;
            h.ehsize = c.ehsize() - 1;
        });
        let f = ElfFile::parse(&bytes).unwrap();
        assert_eq!(
            header_kinds(&f),
            vec![
                DiagnosticKind::IdentVersion(2),
                DiagnosticKind::Version(0),
                DiagnosticKind::HeaderSize {
                    found: c.ehsize() - 1,
                    expected: c.ehsize(),
                },
            ],
            "{c:?}/{e:?}"
        );
        // The rest of the file is read as usual.
        assert_eq!(f.section_headers().unwrap().len(), 1);
    }
}

/// Bounded name lookups never read more than `max + 1` bytes of the table,
/// and a name of exactly `max` bytes is not truncated.
#[test]
fn bounded_names() {
    for (c, e) in LAYOUTS {
        let mut strtab = b"\0abcd\0".to_vec();
        let long = strtab.len() as u32;
        strtab.extend(std::iter::repeat_n(b'A', 100));
        strtab.push(0);
        let unterminated = strtab.len() as u32;
        strtab.extend(b"zz");
        let mut f = FileBuilder::new(c, e);
        f.section(Sh::default());
        let st = f.section_with(
            Sh {
                sh_type: SHT_STRTAB,
                ..Default::default()
            },
            &strtab,
        );
        let syms = [
            Sy::default(),
            Sy {
                name: 1,
                ..Default::default()
            },
            Sy {
                name: long,
                ..Default::default()
            },
            Sy {
                name: unterminated,
                ..Default::default()
            },
        ];
        let idx = f.section_with(
            Sh {
                sh_type: SHT_SYMTAB,
                link: st as u32,
                entsize: c.symsize(),
                ..Default::default()
            },
            &enc_syms(c, e, &syms),
        );
        let bytes = f.finish(|_| {});
        let file = ElfFile::parse(&bytes).unwrap();
        let t = file.symbol_table(idx).unwrap();

        let n = t.name_bounded(&t.get(1).unwrap(), 4).unwrap();
        assert_eq!((n.bytes, n.truncated), (&b"abcd"[..], false));
        let n = t.name_bounded(&t.get(1).unwrap(), 3).unwrap();
        assert_eq!((n.bytes, n.truncated), (&b"abc"[..], true));

        let n = t.name_bounded(&t.get(2).unwrap(), 16).unwrap();
        assert_eq!((n.bytes.len(), n.truncated), (16, true));
        let n = t.name_bounded(&t.get(2).unwrap(), 100).unwrap();
        assert_eq!((n.bytes.len(), n.truncated), (100, false));
        assert_eq!(t.name(&t.get(2).unwrap()).unwrap().len(), 100);

        // Unterminated at the end of the table: still an error when the
        // limit reaches past the end.
        assert!(t.name_bounded(&t.get(3).unwrap(), 16).is_err());
        assert!(t.name(&t.get(3).unwrap()).is_err());
        // With max = 1 the window ("zz") reaches the end: still an error.
        assert!(t.name_bounded(&t.get(3).unwrap(), 1).is_err());
        // With max = 0 only one byte is looked at, so the end is not reached.
        let n = t.name_bounded(&t.get(3).unwrap(), 0).unwrap();
        assert_eq!((n.bytes, n.truncated), (&b""[..], true));
    }
}

/// gABI ch4 "Sections": "Sections in a file may not overlap."
///
/// Changed from the strict reader, whose `check_symbol_tables_fit` (and with
/// it `symbol_tables`) failed with OverlappingTables: the tables are lazy
/// views, so all of them are read, and the audit reports each copy as a
/// duplicate of the first table.
#[test]
fn overlapping_symbol_tables_are_reported() {
    for (c, e) in LAYOUTS {
        let (bytes, _) = symtab_linked_to(c, e, 1);
        let f = ElfFile::parse(&bytes).unwrap();
        assert!(
            !f.diagnostics()
                .iter()
                .any(|d| matches!(d.kind, DiagnosticKind::DuplicateTable { .. })),
            "{c:?}/{e:?}"
        );

        let mut f = FileBuilder::new(c, e);
        f.section(Sh::default());
        let st = f.section_with(
            Sh {
                sh_type: SHT_STRTAB,
                ..Default::default()
            },
            b"\0",
        );
        let data = enc_syms(c, e, &[Sy::default(); 8]);
        let sh = Sh {
            sh_type: SHT_SYMTAB,
            link: st as u32,
            entsize: c.symsize(),
            ..Default::default()
        };
        let first = f.section_with(sh, &data);
        let copy = f.sections[first];
        for _ in 0..64 {
            f.section(copy);
        }
        let bytes = f.finish(|_| {});
        let file = ElfFile::parse(&bytes).unwrap();
        let tables: Vec<_> = file.symbol_tables().unwrap().map(|t| t.len()).collect();
        assert_eq!(tables, vec![8; 65], "{c:?}/{e:?}");
        let dups = file
            .diagnostics()
            .into_iter()
            .filter(|d| matches!(d.kind, DiagnosticKind::DuplicateTable { same_as, .. } if same_as == first))
            .count();
        assert_eq!(dups, unforge_elf::MAX_DIAGNOSTICS_PER_KIND, "{c:?}/{e:?}");
        assert_eq!(file.symbol_table(first).unwrap().len(), 8);
    }
}

/// gABI ch5 "Dynamic Section": the table ends with DT_NULL. Without one, the
/// reader stops at the end of the file bytes that back the table and says
/// that the count was inferred (glibc and musl would read on).
#[test]
fn unterminated_dynamic_table_is_an_inference() {
    for (c, e) in LAYOUTS {
        let entsize = match c {
            C::E32 => 8usize,
            C::E64 => 16,
        };
        let mut w = W::new(c, e);
        for tag in [21u64, 21] {
            // DT_DEBUG, value 0
            w.nat(tag);
            w.nat(0);
        }
        let mut f = FileBuilder::new(c, e);
        let off = f.blob(&w.out);
        let end = off + 2 * entsize as u64;
        f.phdr(Ph {
            p_type: PT_LOAD,
            flags: PF_R | PF_W,
            offset: 0,
            vaddr: 0x10_0000,
            filesz: end,
            memsz: end,
            align: 0x1000,
            ..Default::default()
        });
        f.phdr(Ph {
            p_type: PT_DYNAMIC,
            flags: PF_R | PF_W,
            offset: off,
            vaddr: 0x10_0000 + off,
            filesz: 2 * entsize as u64,
            memsz: 2 * entsize as u64,
            align: 8,
            ..Default::default()
        });
        let bytes = f.finish(|h| h.e_type = ET_DYN);
        let file = ElfFile::parse(&bytes).unwrap();
        let d = file.dynamic().unwrap();
        assert_eq!(d.file_offset, off, "{c:?}/{e:?}");
        assert!(!d.terminated, "{c:?}/{e:?}");
        assert_eq!(d.len(), 2, "{c:?}/{e:?}");
        assert!(d.iter().all(|x| x.tag == 21 && x.value == 0));
        assert!(
            file.diagnostics()
                .iter()
                .any(|x| x.kind == DiagnosticKind::DynamicUnterminated { entries: 2 })
        );
        assert!(
            file.inferences()
                .iter()
                .any(|i| i.subject == InferenceSubject::DynamicEntryCount
                    && i.chosen == Choice::Count(2)),
            "{c:?}/{e:?}"
        );
    }
}

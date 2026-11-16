//! Every anomalous file of the corpus, as a deterministic function of a seed.
//!
//! Names follow `testdata/anomalous/TECHNIQUES.md` (`s` = from the static
//! seed, `d` = from the static-PIE seed with `PT_DYNAMIC`, `y` = from the
//! static seed with a synthesized `.symtab`, `t` = hand-made from nothing).
//! Where a name exists in TECHNIQUES.md §4 it means the same change, applied
//! to this corpus' seeds (not to the binaries that document used).

use crate::Arch;
use crate::elf::*;
use crate::tiny;

/// Which input a variant is built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seed {
    /// `seeds/bin/<arch>/marker-static` (ET_EXEC, no PT_DYNAMIC).
    Static,
    /// `seeds/bin/<arch>/marker-static` plus a synthesized `.symtab`.
    StaticSyms,
    /// `seeds/bin/x86_64/marker-static-pie` (ET_DYN with PT_DYNAMIC).
    StaticPie,
    /// Built byte by byte (`tiny.rs`).
    None,
}

pub struct Variant {
    pub name: &'static str,
    /// Technique id in TECHNIQUES.md (`T01`..`T19`), or `control`.
    pub technique: &'static str,
    pub seed: Seed,
    /// Architectures this variant is built for.
    pub arches: &'static [Arch],
    pub what: &'static str,
    pub build: fn(Arch, Elf) -> Vec<u8>,
}

const BOTH: &[Arch] = &[Arch::Aarch64, Arch::X86_64];
const X86: &[Arch] = &[Arch::X86_64];

fn other_machine(arch: Arch) -> u16 {
    match arch {
        Arch::Aarch64 => EM_X86_64,
        Arch::X86_64 => EM_AARCH64,
    }
}

// ---------------------------------------------------------------------------
// Seed-based edits.
// ---------------------------------------------------------------------------

fn ident(e: &mut Elf, i: usize, v: u8) {
    e.d[i] = v;
}

fn set_section(e: &mut Elf, name: &str, f: impl FnOnce(&mut Shdr)) {
    let i = e.idx(name);
    let mut h = e.sh(i);
    f(&mut h);
    e.set_sh(i, &h);
}

fn many_symtabs(e: &mut Elf) {
    // A new section header table at EOF: the original entries plus 2000
    // SHT_SYMTAB entries that all describe the same .text bytes.
    let t = e.sh(e.idx(".text"));
    let old = e.shs();
    let stri = e.shstrndx() as u32;
    e.align_end(8);
    let off = e.d.len();
    let n = old.len() + 2000;
    e.d.resize(off + SHDR_SIZE * n, 0);
    e.set_u64(eh::E_SHOFF, off as u64);
    e.set_u16(eh::E_SHNUM, u16::try_from(n).expect("shnum"));
    for (i, h) in old.iter().enumerate() {
        e.set_sh(i, h);
    }
    for i in old.len()..n {
        e.set_sh(
            i,
            &Shdr {
                sh_type: SHT_SYMTAB,
                sh_offset: t.sh_offset,
                sh_size: t.sh_size / SYM_SIZE as u64 * SYM_SIZE as u64,
                sh_link: stri,
                sh_addralign: 8,
                sh_entsize: SYM_SIZE as u64,
                ..Shdr::default()
            },
        );
    }
}

fn phdr_outside(e: &mut Elf) {
    // Copy the program header table to EOF, outside every PT_LOAD.
    let o = e.phoff();
    let tbl = e.d[o..o + PHDR_SIZE * e.phnum()].to_vec();
    e.align_end(8);
    let at = e.d.len() as u64;
    e.d.extend_from_slice(&tbl);
    e.set_u64(eh::E_PHOFF, at);
}

/// Append `.symtab` + `.strtab` describing `.text` as 32 local functions and
/// `.rodata` as one object, with a fresh `.shstrtab` and section header table.
pub fn add_symtab(e: &mut Elf) {
    let text_i = e.idx(".text");
    let ro_i = e.idx(".rodata");
    let text = e.sh(text_i);
    let ro = e.sh(ro_i);
    let old = e.shs();
    let shstr_i = e.shstrndx();
    let shstr = old[shstr_i];

    // .strtab and the symbols.
    let mut strtab = vec![0u8];
    let mut syms: Vec<u8> = vec![0; SYM_SIZE]; // index 0: the null symbol
    let mut sym =
        |name: &str, info: u8, shndx: u16, value: u64, size: u64, strtab: &mut Vec<u8>| {
            let st_name = strtab.len() as u32;
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
            let mut b = [0u8; SYM_SIZE];
            b[0..4].copy_from_slice(&st_name.to_le_bytes());
            b[4] = info;
            b[6..8].copy_from_slice(&shndx.to_le_bytes());
            b[8..16].copy_from_slice(&value.to_le_bytes());
            b[16..24].copy_from_slice(&size.to_le_bytes());
            syms.extend_from_slice(&b);
        };
    let n = 32u64;
    let chunk = text.sh_size / n;
    for k in 0..n {
        // STB_LOCAL (0) << 4 | STT_FUNC (2)
        sym(
            &format!("seed_fn_{k:02}"),
            0x02,
            text_i as u16,
            text.sh_addr + k * chunk,
            chunk,
            &mut strtab,
        );
    }
    // STB_LOCAL | STT_OBJECT (1)
    sym(
        "seed_rodata",
        0x01,
        ro_i as u16,
        ro.sh_addr,
        ro.sh_size,
        &mut strtab,
    );
    let nsyms = syms.len() / SYM_SIZE;

    // New .shstrtab: the old names plus two more.
    let so = shstr.sh_offset as usize;
    let mut new_shstr = e.d[so..so + shstr.sh_size as usize].to_vec();
    let symtab_name = new_shstr.len() as u32;
    new_shstr.extend_from_slice(b".symtab\0");
    let strtab_name = new_shstr.len() as u32;
    new_shstr.extend_from_slice(b".strtab\0");

    e.align_end(8);
    let symtab_off = e.d.len() as u64;
    e.d.extend_from_slice(&syms);
    let strtab_off = e.d.len() as u64;
    e.d.extend_from_slice(&strtab);
    let shstr_off = e.d.len() as u64;
    e.d.extend_from_slice(&new_shstr);
    e.align_end(8);
    let shoff = e.d.len();

    let mut table = old.clone();
    table[shstr_i].sh_offset = shstr_off;
    table[shstr_i].sh_size = new_shstr.len() as u64;
    let strtab_index = table.len() as u32 + 1;
    table.push(Shdr {
        sh_name: symtab_name,
        sh_type: SHT_SYMTAB,
        sh_offset: symtab_off,
        sh_size: syms.len() as u64,
        sh_link: strtab_index,
        sh_info: nsyms as u32, // all symbols are local
        sh_addralign: 8,
        sh_entsize: SYM_SIZE as u64,
        ..Shdr::default()
    });
    table.push(Shdr {
        sh_name: strtab_name,
        sh_type: SHT_STRTAB,
        sh_offset: strtab_off,
        sh_size: strtab.len() as u64,
        sh_addralign: 1,
        ..Shdr::default()
    });
    e.d.resize(shoff + SHDR_SIZE * table.len(), 0);
    e.set_u64(eh::E_SHOFF, shoff as u64);
    e.set_u16(eh::E_SHNUM, table.len() as u16);
    for (i, h) in table.iter().enumerate() {
        e.set_sh(i, h);
    }
}

fn symtab(e: &Elf) -> (usize, Shdr) {
    let i = e.idx(".symtab");
    (i, e.sh(i))
}

fn for_each_sym(e: &mut Elf, mut f: impl FnMut(&mut Elf, usize, usize)) {
    let (_, h) = symtab(e);
    for k in 1..(h.sh_size as usize / SYM_SIZE) {
        let o = h.sh_offset as usize + SYM_SIZE * k;
        f(e, k, o);
    }
}

// ---------------------------------------------------------------------------
// Hand-made files.
// ---------------------------------------------------------------------------

fn std_with(arch: Arch, phdrs: &[Phdr]) -> Vec<u8> {
    tiny::standard(arch, phdrs)
}

fn interp_ph(len: u64) -> Phdr {
    Phdr {
        p_type: PT_INTERP,
        p_flags: PF_R,
        p_offset: tiny::AUX_OFF as u64,
        p_vaddr: tiny::BASE + tiny::AUX_OFF as u64,
        p_paddr: tiny::BASE + tiny::AUX_OFF as u64,
        p_filesz: len,
        p_memsz: len,
        p_align: 1,
    }
}

fn dynamic_ph() -> Phdr {
    Phdr {
        p_type: PT_DYNAMIC,
        p_flags: PF_R | PF_W,
        p_offset: tiny::DYN_OFF as u64,
        p_vaddr: tiny::BASE + tiny::DYN_OFF as u64,
        p_paddr: tiny::BASE + tiny::DYN_OFF as u64,
        p_filesz: 5 * 16,
        p_memsz: 5 * 16,
        p_align: 8,
    }
}

/// A dynamically linked hand-made file: `PT_INTERP` names glibc's ld.so and
/// `PT_DYNAMIC` holds only `DT_STRTAB`, `DT_SYMTAB`, `DT_STRSZ`, `DT_SYMENT`
/// (no `DT_NEEDED`, no relocations).
fn with_ldso(arch: Arch, edit: impl FnOnce(&mut Vec<Phdr>)) -> Vec<u8> {
    let path = tiny::interp_path(arch);
    let mut phdrs = vec![
        interp_ph(path.len() as u64),
        tiny::whole_load(PF_R | PF_W | PF_X),
        dynamic_ph(),
    ];
    edit(&mut phdrs);
    let mut d = std_with(arch, &phdrs);
    d[tiny::AUX_OFF..tiny::AUX_OFF + path.len()].copy_from_slice(path);
    let dt = [
        (5u64, tiny::BASE + tiny::STR_OFF as u64), // DT_STRTAB
        (6, tiny::BASE + tiny::SYM_OFF as u64),    // DT_SYMTAB
        (10, 1),                                   // DT_STRSZ
        (11, SYM_SIZE as u64),                     // DT_SYMENT
        (0, 0),                                    // DT_NULL
    ];
    for (k, (tag, val)) in dt.iter().enumerate() {
        let o = tiny::DYN_OFF + 16 * k;
        d[o..o + 8].copy_from_slice(&tag.to_le_bytes());
        d[o + 8..o + 16].copy_from_slice(&val.to_le_bytes());
    }
    d
}

fn put_u16(d: &mut [u8], o: usize, v: u16) {
    d[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(d: &mut [u8], o: usize, v: u64) {
    d[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

// ---------------------------------------------------------------------------
// The list.
// ---------------------------------------------------------------------------

macro_rules! v {
    ($name:expr, $t:expr, $seed:expr, $arches:expr, $what:expr, $f:expr) => {
        Variant {
            name: $name,
            technique: $t,
            seed: $seed,
            arches: $arches,
            what: $what,
            build: $f,
        }
    };
}

/// Apply an in-place edit to the seed and return its bytes.
fn ed(mut e: Elf, f: impl FnOnce(&mut Elf)) -> Vec<u8> {
    f(&mut e);
    e.d
}

pub fn all() -> Vec<Variant> {
    use Seed::*;
    vec![
        // --- static seed ------------------------------------------------------
        v!(
            "s00-baseline",
            "control",
            Static,
            BOTH,
            "the seed, unchanged",
            |_, e| e.d
        ),
        v!(
            "s01-shdr-zeroed",
            "T01",
            Static,
            BOTH,
            "e_shoff, e_shnum, e_shstrndx = 0 (table bytes kept)",
            |_, e| ed(e, |e| e.zero_section_header_fields())
        ),
        v!(
            "s02-sstrip",
            "T01",
            Static,
            BOTH,
            "ELFkickers sstrip: cut after the last byte a program header uses, section fields zeroed",
            |_, e| ed(e, |e| e.sstrip())
        ),
        v!(
            "s03-shoff-garbage",
            "T02",
            Static,
            BOTH,
            "e_shoff = 0xdeadbeefdeadbeef",
            |_, e| ed(e, |e| e.set_u64(eh::E_SHOFF, 0xdead_beef_dead_beef))
        ),
        v!(
            "s04-shoff-past-eof",
            "T02",
            Static,
            BOTH,
            "e_shoff = file size + 0x1000",
            |_, e| ed(e, |e| {
                let n = e.d.len() as u64;
                e.set_u64(eh::E_SHOFF, n + 0x1000)
            })
        ),
        v!(
            "s05-shnum-ffff",
            "T03",
            Static,
            BOTH,
            "e_shnum = 0xffff (table runs past EOF)",
            |_, e| ed(e, |e| e.set_u16(eh::E_SHNUM, 0xffff))
        ),
        v!(
            "s06-shentsize-1",
            "T04",
            Static,
            BOTH,
            "e_shentsize = 1",
            |_, e| ed(e, |e| e.set_u16(eh::E_SHENTSIZE, 1))
        ),
        v!(
            "s07-shstrndx-out-of-range",
            "T05",
            Static,
            BOTH,
            "e_shstrndx = 0x1234",
            |_, e| ed(e, |e| e.set_u16(eh::E_SHSTRNDX, 0x1234))
        ),
        v!(
            "s08-shstrndx-is-text",
            "T05",
            Static,
            BOTH,
            "e_shstrndx = index of .text (names read from code)",
            |_, e| ed(e, |e| {
                let i = e.idx(".text") as u16;
                e.set_u16(eh::E_SHSTRNDX, i)
            })
        ),
        v!(
            "s09-text-size-huge",
            "T06",
            Static,
            BOTH,
            ".text sh_size = 0xffffffffffff",
            |_, e| ed(e, |e| set_section(e, ".text", |h| h.sh_size =
                0xffff_ffff_ffff))
        ),
        v!(
            "s10-rodata-offset-past-eof",
            "T06",
            Static,
            BOTH,
            ".rodata sh_offset = file size + 0x100",
            |_, e| ed(e, |e| {
                let n = e.d.len() as u64;
                set_section(e, ".rodata", |h| h.sh_offset = n + 0x100)
            })
        ),
        v!(
            "s11-decoy-swap-text-rodata-names",
            "T07",
            Static,
            BOTH,
            "sh_name of .text and .rodata swapped",
            |_, e| ed(e, |e| {
                let (a, b) = (e.idx(".text"), e.idx(".rodata"));
                let (mut ha, mut hb) = (e.sh(a), e.sh(b));
                std::mem::swap(&mut ha.sh_name, &mut hb.sh_name);
                e.set_sh(a, &ha);
                e.set_sh(b, &hb);
            })
        ),
        v!(
            "s12-text-is-nobits",
            "T07",
            Static,
            BOTH,
            ".text sh_type = SHT_NOBITS",
            |_, e| ed(e, |e| set_section(e, ".text", |h| h.sh_type = SHT_NOBITS))
        ),
        v!(
            "s13-progbits-all-overlap-text",
            "T08",
            Static,
            BOTH,
            "every other SHT_PROGBITS section covers exactly the .text bytes",
            |_, e| ed(e, |e| {
                let ti = e.idx(".text");
                let t = e.sh(ti);
                for (i, mut h) in e.shs().into_iter().enumerate() {
                    if h.sh_type == SHT_PROGBITS && i != ti {
                        h.sh_offset = t.sh_offset;
                        h.sh_size = t.sh_size;
                        e.set_sh(i, &h);
                    }
                }
            })
        ),
        v!(
            "s14-2000-symtabs-same-bytes",
            "T08",
            Static,
            BOTH,
            "new section table at EOF: original entries + 2000 SHT_SYMTAB over the .text bytes",
            |_, e| ed(e, many_symtabs)
        ),
        v!(
            "s15-section-addr-disagree-with-segments",
            "T09",
            Static,
            BOTH,
            "sh_addr += 0x100000 for every section with a non-zero address",
            |_, e| ed(e, |e| {
                for (i, mut h) in e.shs().into_iter().enumerate() {
                    if h.sh_addr != 0 {
                        h.sh_addr += 0x10_0000;
                        e.set_sh(i, &h);
                    }
                }
            })
        ),
        v!(
            "s16-ei-class-32",
            "T12",
            Static,
            BOTH,
            "EI_CLASS = 1 (claims ELF32)",
            |_, e| ed(e, |e| ident(e, 4, 1))
        ),
        v!(
            "s17-ei-class-0x55",
            "T12",
            Static,
            BOTH,
            "EI_CLASS = 0x55 (invalid)",
            |_, e| ed(e, |e| ident(e, 4, 0x55))
        ),
        v!(
            "s18-ei-data-be",
            "T12",
            Static,
            BOTH,
            "EI_DATA = 2 (claims big-endian)",
            |_, e| ed(e, |e| ident(e, 5, 2))
        ),
        v!(
            "s19-ei-data-0",
            "T12",
            Static,
            BOTH,
            "EI_DATA = 0 (ELFDATANONE)",
            |_, e| ed(e, |e| ident(e, 5, 0))
        ),
        v!(
            "s20-ei-version-0-e_version-0",
            "T12",
            Static,
            BOTH,
            "EI_VERSION = 0 and e_version = 0",
            |_, e| ed(e, |e| {
                ident(e, 6, 0);
                e.set_u32(eh::E_VERSION, 0)
            })
        ),
        v!(
            "s21-osabi-freebsd-pad-garbage",
            "T12",
            Static,
            BOTH,
            "EI_OSABI = 9, EI_ABIVERSION = 0x42, EI_PAD = \"GARBAGE\"",
            |_, e| ed(e, |e| {
                e.d[7] = 9;
                e.d[8] = 0x42;
                e.d[9..16].copy_from_slice(b"GARBAGE")
            })
        ),
        v!(
            "s22-ehsize-0",
            "T13",
            Static,
            BOTH,
            "e_ehsize = 0",
            |_, e| ed(e, |e| e.set_u16(eh::E_EHSIZE, 0))
        ),
        v!(
            "s23-ehsize-ffff",
            "T13",
            Static,
            BOTH,
            "e_ehsize = 0xffff",
            |_, e| ed(e, |e| e.set_u16(eh::E_EHSIZE, 0xffff))
        ),
        v!(
            "s24-phdr-outside-every-load",
            "T11",
            Static,
            BOTH,
            "program header table copied to EOF (no PT_LOAD covers it), e_phoff points at the copy",
            |_, e| ed(e, phdr_outside)
        ),
        v!(
            "s25-truncated-inside-last-load",
            "T14",
            Static,
            BOTH,
            "file cut 0x10 bytes into the last PT_LOAD (writable, p_memsz > p_filesz)",
            |_, e| ed(e, |e| {
                let p = e.ph(e.last_load());
                e.d.truncate((p.p_offset + 0x10) as usize)
            })
        ),
        v!(
            "s26-last-load-filesz-past-eof",
            "T14",
            Static,
            BOTH,
            "after sstrip, last PT_LOAD p_filesz = p_memsz = old p_memsz + 0x10000",
            |_, e| ed(e, |e| {
                let i = e.last_load();
                e.sstrip();
                let mut p = e.ph(i);
                p.p_memsz += 0x1_0000;
                p.p_filesz = p.p_memsz;
                e.set_ph(i, &p);
            })
        ),
        v!(
            "s27-ptload-duplicate-of-rx",
            "T15",
            Static,
            BOTH,
            "the PT_GNU_EH_FRAME slot becomes a copy of the R-X PT_LOAD",
            |_, e| ed(e, |e| {
                let s = e.ph_slot(PT_GNU_EH_FRAME);
                let p = e.ph(e.rx_load());
                e.set_ph(s, &p)
            })
        ),
        v!(
            "s28-ptload-later-overrides-text",
            "T15",
            Static,
            BOTH,
            "the PT_GNU_EH_FRAME slot becomes a PT_LOAD mapping file page 0 over the first page of the R-X segment",
            |_, e| ed(e, |e| {
                let s = e.ph_slot(PT_GNU_EH_FRAME);
                let rx = e.ph(e.rx_load());
                let p = Phdr {
                    p_offset: 0,
                    p_filesz: 0x1000,
                    p_memsz: 0x1000,
                    p_vaddr: rx.p_vaddr & !0xfff,
                    p_paddr: rx.p_vaddr & !0xfff,
                    ..rx
                };
                e.set_ph(s, &p);
            })
        ),
        v!(
            "s29-ptload-not-sorted",
            "T15",
            Static,
            BOTH,
            "first and last PT_LOAD entries swapped",
            |_, e| ed(e, |e| {
                let l = e.loads();
                let (a, b) = (l[0], l[l.len() - 1]);
                let (pa, pb) = (e.ph(a), e.ph(b));
                e.set_ph(a, &pb);
                e.set_ph(b, &pa);
            })
        ),
        v!(
            "s30-palign-not-power-of-two",
            "T15",
            Static,
            BOTH,
            "p_align = 3 on every PT_LOAD",
            |_, e| ed(e, |e| {
                for i in e.loads() {
                    let mut p = e.ph(i);
                    p.p_align = 3;
                    e.set_ph(i, &p)
                }
            })
        ),
        v!(
            "s31-phentsize-wrong",
            "T19",
            Static,
            BOTH,
            "e_phentsize = 32 (control: the kernel refuses)",
            |_, e| ed(e, |e| e.set_u16(eh::E_PHENTSIZE, 32))
        ),
        v!(
            "s32-machine-wrong",
            "T19",
            Static,
            BOTH,
            "e_machine set to the other architecture (control)",
            |a, e| ed(e, |e| e.set_u16(eh::E_MACHINE, other_machine(a)))
        ),
        v!(
            "s33-e_flags-garbage",
            "T12",
            Static,
            BOTH,
            "e_flags = 0xdeadbeef (native kernels do not read it)",
            |_, e| ed(e, |e| e.set_u32(eh::E_FLAGS, 0xdead_beef))
        ),
        v!(
            "s34-unknown-ptype",
            "T15",
            Static,
            BOTH,
            "the PT_GNU_EH_FRAME slot gets p_type 0x12345678",
            |_, e| ed(e, |e| {
                let s = e.ph_slot(PT_GNU_EH_FRAME);
                let mut p = e.ph(s);
                p.p_type = 0x1234_5678;
                e.set_ph(s, &p)
            })
        ),
        v!(
            "s35-palign-incongruent",
            "T15",
            Static,
            BOTH,
            "p_align = 0x100000 on every PT_LOAD, so the gABI p_offset % p_align == p_vaddr % p_align rule fails (page congruence still holds)",
            |_, e| ed(e, |e| {
                for i in e.loads() {
                    let mut p = e.ph(i);
                    p.p_align = 0x10_0000;
                    e.set_ph(i, &p)
                }
            })
        ),
        // --- static seed with a synthesized .symtab -------------------------------
        v!(
            "y00-symtab-baseline",
            "control",
            StaticSyms,
            BOTH,
            "static seed + synthesized .symtab/.strtab (33 symbols)",
            |_, e| e.d
        ),
        v!(
            "y50-symtab-st_name-out-of-range",
            "T17",
            StaticSyms,
            BOTH,
            "every st_name = 0xffffff00 + k",
            |_, e| ed(e, |e| for_each_sym(e, |e, k, o| e
                .set_u32(o, 0xffff_ff00 + (k as u32 & 0xff))))
        ),
        v!(
            "y51-symtab-sh_link-to-text",
            "T17",
            StaticSyms,
            BOTH,
            ".symtab sh_link = index of .text",
            |_, e| ed(e, |e| {
                let t = e.idx(".text") as u32;
                set_section(e, ".symtab", |h| h.sh_link = t)
            })
        ),
        v!(
            "y52-symtab-entsize-0-size-ragged",
            "T17",
            StaticSyms,
            BOTH,
            ".symtab sh_entsize = 0, sh_size += 7",
            |_, e| ed(e, |e| set_section(e, ".symtab", |h| {
                h.sh_entsize = 0;
                h.sh_size += 7
            }))
        ),
        v!(
            "y53-symtab-funcs-all-same-addr-huge-size",
            "T17",
            StaticSyms,
            BOTH,
            "every STT_FUNC gets the first one's st_value and st_size = 0xffffffffffff",
            |_, e| ed(e, |e| {
                let mut first: Option<u64> = Option::None;
                for_each_sym(e, |e, _, o| {
                    if e.d[o + 4] & 0xf == 2 {
                        let v = *first.get_or_insert(e.u64(o + 8));
                        e.set_u64(o + 8, v);
                        e.set_u64(o + 16, 0xffff_ffff_ffff);
                    }
                });
            })
        ),
        v!(
            "y54-symtab-st_shndx-garbage",
            "T17",
            StaticSyms,
            BOTH,
            "every st_shndx = 0xfeee (reserved range)",
            |_, e| ed(e, |e| for_each_sym(e, |e, _, o| e.set_u16(o + 6, 0xfeee)))
        ),
        // --- static PIE seed (x86_64 only: aarch64 musl does not build one) -------
        v!(
            "d00-baseline",
            "control",
            StaticPie,
            X86,
            "the static-PIE seed, unchanged",
            |_, e| e.d
        ),
        v!(
            "d01-shdr-zeroed",
            "T01",
            StaticPie,
            X86,
            "section header fields zeroed",
            |_, e| ed(e, |e| e.zero_section_header_fields())
        ),
        v!(
            "d02-sstrip",
            "T01",
            StaticPie,
            X86,
            "ELFkickers sstrip",
            |_, e| ed(e, |e| e.sstrip())
        ),
        v!(
            "d16-ei-class-32",
            "T12",
            StaticPie,
            X86,
            "EI_CLASS = 1",
            |_, e| ed(e, |e| ident(e, 4, 1))
        ),
        v!(
            "d18-ei-data-be",
            "T12",
            StaticPie,
            X86,
            "EI_DATA = 2",
            |_, e| ed(e, |e| ident(e, 5, 2))
        ),
        v!(
            "d21-osabi-freebsd-pad-garbage",
            "T12",
            StaticPie,
            X86,
            "EI_OSABI = 9, EI_ABIVERSION = 0x42, EI_PAD garbage",
            |_, e| ed(e, |e| {
                e.d[7] = 9;
                e.d[8] = 0x42;
                e.d[9..16].copy_from_slice(b"GARBAGE")
            })
        ),
        v!(
            "d40-pt_dynamic-offset-filesz-garbage",
            "T16",
            StaticPie,
            X86,
            "PT_DYNAMIC p_offset = 0xdeadbeef, p_filesz = 0xffffffff (p_vaddr kept)",
            |_, e| ed(e, |e| {
                let i = e.ph_slot(PT_DYNAMIC);
                let mut p = e.ph(i);
                p.p_offset = 0xdead_beef;
                p.p_filesz = 0xffff_ffff;
                e.set_ph(i, &p)
            })
        ),
        v!(
            "d41-pt_dynamic-vaddr-into-rodata",
            "T16",
            StaticPie,
            X86,
            "PT_DYNAMIC p_vaddr = .rodata sh_addr",
            |_, e| ed(e, |e| {
                let r = e.sh(e.idx(".rodata")).sh_addr;
                let i = e.ph_slot(PT_DYNAMIC);
                let mut p = e.ph(i);
                p.p_vaddr = r;
                e.set_ph(i, &p)
            })
        ),
        v!(
            "d42-dynamic-section-header-garbage",
            "T06",
            StaticPie,
            X86,
            ".dynamic sh_offset = 0xdeadbeef, sh_size = 0x7fffffff",
            |_, e| ed(e, |e| set_section(e, ".dynamic", |h| {
                h.sh_offset = 0xdead_beef;
                h.sh_size = 0x7fff_ffff
            }))
        ),
        v!(
            "d43-dynsym-sh_link-to-shstrtab",
            "T17",
            StaticPie,
            X86,
            ".dynsym sh_link = index of .shstrtab",
            |_, e| ed(e, |e| {
                let s = e.idx(".shstrtab") as u32;
                set_section(e, ".dynsym", |h| h.sh_link = s)
            })
        ),
        v!(
            "d44-dynsym-section-points-at-text",
            "T07",
            StaticPie,
            X86,
            ".dynsym sh_offset = .text sh_offset",
            |_, e| ed(e, |e| {
                let t = e.sh(e.idx(".text")).sh_offset;
                set_section(e, ".dynsym", |h| h.sh_offset = t)
            })
        ),
        v!(
            "d46-pt_dynamic-removed",
            "T16",
            StaticPie,
            X86,
            "PT_DYNAMIC turned into PT_NULL",
            |_, e| ed(e, |e| {
                let i = e.ph_slot(PT_DYNAMIC);
                let mut p = e.ph(i);
                p.p_type = PT_NULL;
                e.set_ph(i, &p)
            })
        ),
        // --- hand-made --------------------------------------------------------------
        v!(
            "t60-tiny-phdr-overlaps-ehdr",
            "T10",
            None,
            BOTH,
            "e_phoff = 0x38: the PT_LOAD entry overlaps e_phnum..e_shstrndx; code at 0x70",
            |a, _| tiny::overlapped(a, PF_R | PF_X, Option::None, Option::None)
        ),
        v!(
            "t61-tiny-overlap-all-unused-fields-garbage",
            "T10",
            None,
            BOTH,
            "t60 with garbage in EI_CLASS..EI_PAD, e_version, e_shoff, e_flags, e_ehsize",
            |a, _| {
                let mut d = tiny::overlapped(a, PF_R | PF_X, Option::None, Option::None);
                d[4..16].copy_from_slice(b"\xffGARBAGE\x00!!\x01");
                d[eh::E_VERSION..eh::E_VERSION + 4].copy_from_slice(&0xcafe_babeu32.to_le_bytes());
                put_u64(&mut d, eh::E_SHOFF, 0x4141_4141_4141_4141);
                d[eh::E_FLAGS..eh::E_FLAGS + 4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
                put_u16(&mut d, eh::E_EHSIZE, 0x0bad);
                d
            }
        ),
        v!(
            "t62-rwx-filesz-past-eof-memsz-bigger",
            "T14",
            None,
            BOTH,
            "overlapped tiny, single RWX PT_LOAD p_filesz = 0x1100 (file is smaller), p_memsz = 0x3000",
            |a, _| tiny::overlapped(a, PF_R | PF_W | PF_X, Some(0x1100), Some(0x3000))
        ),
        v!(
            "t63-rx-filesz-past-eof-memsz-bigger",
            "T14",
            None,
            BOTH,
            "as t62 but R-X",
            |a, _| tiny::overlapped(a, PF_R | PF_X, Some(0x1100), Some(0x3000))
        ),
        v!(
            "t64-rx-filesz-past-eof",
            "T14",
            None,
            BOTH,
            "as t63 but p_memsz = p_filesz = 0x1100",
            |a, _| tiny::overlapped(a, PF_R | PF_X, Some(0x1100), Some(0x1100))
        ),
        v!(
            "t65-control-tiny",
            "control",
            None,
            BOTH,
            "hand-made, no overlap: ELF header, one PT_LOAD at 0x40, code at 0x120",
            |a, _| std_with(a, &[tiny::rx_load()])
        ),
        v!(
            "t70-e_type-rel",
            "T19",
            None,
            BOTH,
            "e_type = ET_REL (control)",
            |a, _| {
                let mut d = std_with(a, &[tiny::rx_load()]);
                put_u16(&mut d, eh::E_TYPE, 1);
                d
            }
        ),
        v!(
            "t71-e_phnum-0",
            "T19",
            None,
            BOTH,
            "e_phnum = 0 (control)",
            |a, _| {
                let mut d = std_with(a, &[tiny::rx_load()]);
                put_u16(&mut d, eh::E_PHNUM, 0);
                d
            }
        ),
        v!(
            "t72-e_phnum-1171",
            "T19",
            None,
            BOTH,
            "e_phnum = 1171, so e_phnum * 56 > 65536 (control)",
            |a, _| {
                let mut d = std_with(a, &[tiny::rx_load()]);
                put_u16(&mut d, eh::E_PHNUM, 1171);
                d
            }
        ),
        v!(
            "t73-phdr-table-past-eof",
            "T19",
            None,
            BOTH,
            "e_phoff points 0x10 bytes before EOF (control)",
            |a, _| {
                let mut d = std_with(a, &[tiny::rx_load()]);
                let n = d.len() as u64;
                put_u64(&mut d, eh::E_PHOFF, n - 0x10);
                d
            }
        ),
        v!(
            "t74-filesz-gt-memsz",
            "T19",
            None,
            BOTH,
            "PT_LOAD p_filesz = 0x210 > p_memsz = 0x100 (control, post point of no return)",
            |a, _| std_with(
                a,
                &[Phdr {
                    p_memsz: 0x100,
                    ..tiny::rx_load()
                }]
            )
        ),
        v!(
            "t75-interp-filesz-1",
            "T19",
            None,
            BOTH,
            "PT_INTERP p_filesz = 1 (control)",
            |a, _| std_with(a, &[interp_ph(1), tiny::rx_load()])
        ),
        v!(
            "t76-interp-not-nul-terminated",
            "T19",
            None,
            BOTH,
            "PT_INTERP \"/nonexistent\" without its NUL (control)",
            |a, _| {
                let p = b"/nonexistent";
                let mut d = std_with(a, &[interp_ph(p.len() as u64), tiny::rx_load()]);
                d[tiny::AUX_OFF..tiny::AUX_OFF + p.len()].copy_from_slice(p);
                d
            }
        ),
        v!(
            "t77-interp-missing-file",
            "T19",
            None,
            BOTH,
            "PT_INTERP \"/nonexistent/ld.so\" (control)",
            |a, _| {
                let p = b"/nonexistent/ld.so\0";
                let mut d = std_with(a, &[interp_ph(p.len() as u64), tiny::rx_load()]);
                d[tiny::AUX_OFF..tiny::AUX_OFF + p.len()].copy_from_slice(p);
                d
            }
        ),
        v!(
            "t78-entry-unmapped",
            "T19",
            None,
            BOTH,
            "e_entry = 0x10000, outside every PT_LOAD",
            |a, _| {
                let mut d = std_with(a, &[tiny::rx_load()]);
                put_u64(&mut d, eh::E_ENTRY, 0x1_0000);
                d
            }
        ),
        v!(
            "t79-entry-in-non-exec-load",
            "T19",
            None,
            BOTH,
            "the only PT_LOAD is R only",
            |a, _| std_with(a, &[tiny::whole_load(PF_R)])
        ),
        v!(
            "t80-no-pt-load",
            "T19",
            None,
            BOTH,
            "ET_EXEC whose only program header is PT_NULL",
            |a, _| std_with(a, &[Phdr::default()])
        ),
        v!(
            "t81-phnum-pn-xnum",
            "T19",
            None,
            BOTH,
            "e_phnum = PN_XNUM (0xffff) with section 0 sh_info = 1 (gABI escape; control)",
            |a, _| {
                let mut d = std_with(a, &[tiny::rx_load()]);
                put_u16(&mut d, eh::E_PHNUM, 0xffff);
                // Section header 0 at EOF, sh_info = real phnum.
                let shoff = d.len() as u64;
                let s0 = Shdr {
                    sh_info: 1,
                    ..Shdr::default()
                };
                d.extend_from_slice(&s0.encode());
                put_u64(&mut d, eh::E_SHOFF, shoff);
                put_u16(&mut d, eh::E_SHENTSIZE, SHDR_SIZE as u16);
                put_u16(&mut d, eh::E_SHNUM, 1);
                d
            }
        ),
        v!(
            "t82-offset-vaddr-not-congruent",
            "T19",
            None,
            BOTH,
            "PT_LOAD p_offset = 0 but p_vaddr = BASE + 0x10 (not congruent mod page; post point of no return)",
            |a, _| {
                let mut d = std_with(
                    a,
                    &[Phdr {
                        p_vaddr: tiny::BASE + 0x10,
                        p_paddr: tiny::BASE + 0x10,
                        ..tiny::rx_load()
                    }],
                );
                put_u64(
                    &mut d,
                    eh::E_ENTRY,
                    tiny::BASE + 0x10 + tiny::CODE_OFF as u64,
                );
                d
            }
        ),
        v!(
            "t83-et-dyn-tiny",
            "control",
            None,
            BOTH,
            "ET_DYN, PT_LOAD at p_vaddr 0 (position-independent tiny PIE)",
            |a, _| {
                let mut d = std_with(
                    a,
                    &[Phdr {
                        p_vaddr: 0,
                        p_paddr: 0,
                        ..tiny::rx_load()
                    }],
                );
                put_u16(&mut d, eh::E_TYPE, 3);
                put_u64(&mut d, eh::E_ENTRY, tiny::CODE_OFF as u64);
                d
            }
        ),
        v!(
            "t84-interp-ldso-minimal-dynamic",
            "T16",
            None,
            BOTH,
            "PT_INTERP = glibc ld.so, PT_DYNAMIC with DT_STRTAB/DT_SYMTAB/DT_STRSZ/DT_SYMENT only",
            |a, _| with_ldso(a, |_| {})
        ),
        v!(
            "t85-interp-ldso-pt_dynamic-offset-garbage",
            "T16",
            None,
            BOTH,
            "t84 with PT_DYNAMIC p_offset = 0xdeadbeef, p_filesz = 0xffffffff",
            |a, _| with_ldso(a, |p| {
                p[2].p_offset = 0xdead_beef;
                p[2].p_filesz = 0xffff_ffff
            })
        ),
        v!(
            "t86-interp-ldso-no-pt_dynamic",
            "T16",
            None,
            BOTH,
            "t84 with PT_DYNAMIC turned into PT_NULL",
            |a, _| with_ldso(a, |p| p[2] = Phdr::default())
        ),
        v!(
            "t87-phentsize-64",
            "T19",
            None,
            BOTH,
            "e_phentsize = 64 (larger than Elf64_Phdr; control)",
            |a, _| {
                let mut d = std_with(a, &[tiny::rx_load()]);
                put_u16(&mut d, eh::E_PHENTSIZE, 64);
                d
            }
        ),
        v!(
            "t88-gnu-property-bad-note-name",
            "T19",
            None,
            BOTH,
            "PT_GNU_PROPERTY note named \"XYZ\" (arm64 parses it, x86-64 v7.0.12 does not)",
            |a, _| {
                let note_ph = Phdr {
                    p_type: PT_GNU_PROPERTY,
                    p_flags: PF_R,
                    p_offset: tiny::AUX_OFF as u64,
                    p_vaddr: tiny::BASE + tiny::AUX_OFF as u64,
                    p_paddr: tiny::BASE + tiny::AUX_OFF as u64,
                    p_filesz: 32,
                    p_memsz: 32,
                    p_align: 8,
                };
                let mut d = std_with(a, &[tiny::rx_load(), note_ph]);
                let mut note = Vec::new();
                note.extend_from_slice(&4u32.to_le_bytes()); // n_namesz
                note.extend_from_slice(&16u32.to_le_bytes()); // n_descsz
                note.extend_from_slice(&5u32.to_le_bytes()); // NT_GNU_PROPERTY_TYPE_0
                note.extend_from_slice(b"XYZ\0");
                note.extend_from_slice(&0xc000_0000u32.to_le_bytes()); // pr_type (AARCH64_FEATURE_1_AND / X86 range)
                note.extend_from_slice(&4u32.to_le_bytes()); // pr_datasz
                note.extend_from_slice(&[0; 8]); // data + padding
                d[tiny::AUX_OFF..tiny::AUX_OFF + note.len()].copy_from_slice(&note);
                d
            }
        ),
        v!(
            "t89-two-interp-first-wins",
            "T19",
            None,
            BOTH,
            "first PT_INTERP names a missing file, the second names glibc ld.so (the kernel uses the first)",
            |a, _| {
                let path = tiny::interp_path(a);
                let missing = b"/nonexistent/ld.so\0";
                let mut second = interp_ph(path.len() as u64);
                second.p_offset += 0x20;
                second.p_vaddr += 0x20;
                second.p_paddr += 0x20;
                let mut d = std_with(
                    a,
                    &[
                        interp_ph(missing.len() as u64),
                        second,
                        tiny::whole_load(PF_R | PF_W | PF_X),
                        dynamic_ph(),
                    ],
                );
                d[tiny::AUX_OFF..tiny::AUX_OFF + missing.len()].copy_from_slice(missing);
                d[tiny::AUX_OFF + 0x20..tiny::AUX_OFF + 0x20 + path.len()].copy_from_slice(path);
                d
            }
        ),
        v!(
            "t90-phdr-not-in-load-no-ldso",
            "T11",
            None,
            BOTH,
            "program header table at EOF outside the PT_LOAD; code does not read AT_PHDR",
            |a, _| {
                let mut d = std_with(a, &[]);
                let at = d.len() as u64;
                d.extend_from_slice(&tiny::rx_load().encode());
                put_u64(&mut d, eh::E_PHOFF, at);
                put_u16(&mut d, eh::E_PHNUM, 1);
                d
            }
        ),
    ]
}

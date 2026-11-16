//! Hostile-input tests: the reader must never panic and must never allocate
//! more than (a small multiple of) what the input can actually back.
//!
//! The tests do not depend on any corpus: a minimal ELF builder below produces
//! a valid file for each of the four layouts (ELF32/ELF64 x LSB/MSB), checked
//! against `goblin` as an oracle, and every test mutates those. Files under
//! `testdata/bin` are used in addition when present.
//!
//! Every public API is driven by [`exercise`] inside `catch_unwind`.

use std::cell::RefCell;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Once;
use std::time::{Duration, Instant};

use unforge_elf::consts::*;
use unforge_elf::{
    Class, DiagnosticKind, ElfFile, Endian, Error, InferenceSubject, ProgramHeader, SectionHeader,
    SymbolSection,
};

// ===========================================================================
// Driving every public API
// ===========================================================================

/// Keeps the optimizer (and us) honest: every result is folded into this.
fn sink<T: core::fmt::Debug>(acc: &mut u64, v: T) {
    let s = format!("{v:?}");
    *acc = acc.wrapping_mul(31).wrapping_add(s.len() as u64);
}

fn sink_err(acc: &mut u64, e: &Error) {
    // Display must not panic either.
    let s = e.to_string();
    *acc = acc.wrapping_add(s.len() as u64);
}

/// Call every public API of `unforge-elf` on `data`.
fn exercise(data: &[u8]) -> u64 {
    let mut acc = 0u64;
    let elf = match ElfFile::parse(data) {
        Ok(elf) => elf,
        Err(e) => {
            sink_err(&mut acc, &e);
            return acc;
        }
    };
    sink(&mut acc, elf.data().len());
    let h = elf.header();
    sink(&mut acc, h);

    match elf.program_headers() {
        Ok(phs) => {
            for ph in phs {
                match elf.segment_data(&ph) {
                    Ok(d) => sink(&mut acc, d.len()),
                    Err(e) => sink_err(&mut acc, &e),
                }
                sink(&mut acc, elf.segment_bytes(&ph).missing);
            }
        }
        Err(e) => sink_err(&mut acc, &e),
    }

    let shnum = match elf.section_headers() {
        Ok(shs) => shs.len(),
        Err(e) => {
            sink_err(&mut acc, &e);
            0
        }
    };

    match elf.section_name_table() {
        Ok(t) => sink(&mut acc, t.len()),
        Err(e) => sink_err(&mut acc, &e),
    }

    // `section_header` also for indices just past the end and absurd ones.
    let probe = (0..shnum + 2).chain([usize::MAX, usize::MAX / 2, 0xffff, 0xff00]);
    for i in probe {
        let sh = match elf.section_header(i) {
            Ok(sh) => sh,
            Err(e) => {
                sink_err(&mut acc, &e);
                continue;
            }
        };
        match elf.section_data(&sh) {
            Ok(d) => sink(&mut acc, d.len()),
            Err(e) => sink_err(&mut acc, &e),
        }
        match elf.section_name(&sh) {
            Ok(name) => {
                sink(&mut acc, name);
                // section_by_name is O(shnum); only do it for a prefix so a
                // file with thousands of sections stays linear-ish.
                if i < 16 {
                    sink(&mut acc, elf.section_by_name(name).map(|(i, _)| i));
                }
            }
            Err(e) => sink_err(&mut acc, &e),
        }
    }
    for name in [
        &b".text"[..],
        b".symtab",
        b".dynsym",
        b".shstrtab",
        b"",
        b".does-not-exist",
    ] {
        sink(&mut acc, elf.section_by_name(name).map(|(i, _)| i));
    }

    let visit = |acc: &mut u64, t: &unforge_elf::SymbolTable<'_>| {
        sink(acc, t.section_index);
        sink(acc, t.strtab().map(<[u8]>::len));
        for sym in t {
            sink(acc, (sym.bind(), sym.kind(), sym.visibility(), sym.section));
            match t.name(&sym) {
                Ok(n) => sink(acc, n.len()),
                Err(e) => sink_err(acc, &e),
            }
        }
    };
    for i in (0..shnum + 2).chain([usize::MAX]) {
        match elf.symbol_table(i) {
            Ok(t) => visit(&mut acc, &t),
            Err(e) => sink_err(&mut acc, &e),
        }
    }
    match elf.symbol_tables() {
        Ok(ts) => {
            for t in ts {
                visit(&mut acc, &t);
            }
        }
        Err(e) => sink_err(&mut acc, &e),
    }

    // The loader view and the audit.
    let map = elf.memory_map();
    sink(&mut acc, map.backing(h.entry));
    match elf.dynamic() {
        Ok(d) => sink(&mut acc, d.iter().count()),
        Err(e) => sink_err(&mut acc, &e),
    }
    let audit = elf.audit();
    for d in &audit.diagnostics {
        let s = d.to_string();
        acc = acc.wrapping_add(s.len() as u64);
    }
    sink(&mut acc, (audit.ambiguous, elf.layout().source));
    for host in [EM_X86_64, EM_AARCH64] {
        sink(&mut acc, ElfFile::kernel_prediction_for(data, host));
    }
    acc
}

// ===========================================================================
// Panic capture
// ===========================================================================

thread_local! {
    static LAST_PANIC: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Replace the panic hook with one that records the message + location in a
/// thread-local instead of printing it, so thousands of mutated inputs do not
/// flood stderr. Panics that are not ours (test assertions) are recorded too,
/// but assertions run outside `catch_unwind` and still fail the test.
fn quiet_panics() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let default = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            let msg = info.to_string();
            let captured = LAST_PANIC.with(|p| {
                let mut p = p.borrow_mut();
                if IN_CATCH.with(|c| *c.borrow()) {
                    *p = Some(msg);
                    true
                } else {
                    false
                }
            });
            if !captured {
                default(info);
            }
        }));
    });
}

thread_local! {
    static IN_CATCH: RefCell<bool> = const { RefCell::new(false) };
}

#[derive(Default)]
struct Harness {
    runs: u64,
    failures: Vec<(String, String, Vec<u8>)>,
}

impl Harness {
    fn new() -> Self {
        quiet_panics();
        Self::default()
    }

    /// Run [`exercise`] on `data`, recording a panic with `label`.
    fn check(&mut self, label: impl FnOnce() -> String, data: &[u8]) {
        self.runs += 1;
        IN_CATCH.with(|c| *c.borrow_mut() = true);
        let r = panic::catch_unwind(AssertUnwindSafe(|| exercise(data)));
        IN_CATCH.with(|c| *c.borrow_mut() = false);
        if r.is_err() {
            let msg = LAST_PANIC
                .with(|p| p.borrow_mut().take())
                .unwrap_or_else(|| "<no message>".into());
            if self.failures.len() < 50 {
                // Keep small inputs so the report can show them.
                let keep = if data.len() <= 4096 {
                    data.to_vec()
                } else {
                    Vec::new()
                };
                self.failures.push((label(), msg, keep));
            } else {
                self.failures
                    .push((String::new(), String::new(), Vec::new()));
            }
        }
    }

    fn finish(self, what: &str) {
        if self.failures.is_empty() {
            eprintln!("{what}: {} inputs, no panic", self.runs);
            return;
        }
        let mut report = format!(
            "{what}: {} of {} inputs panicked. First ones:\n",
            self.failures.len(),
            self.runs
        );
        for (label, msg, bytes) in self.failures.iter().take(10) {
            report.push_str(&format!("  [{label}] {msg}\n"));
            if !bytes.is_empty() {
                report.push_str(&format!(
                    "    input ({} bytes): {:02x?}\n",
                    bytes.len(),
                    bytes
                ));
            }
        }
        panic!("{report}");
    }
}

// ===========================================================================
// Deterministic PRNG (xorshift64*, Vigna 2014)
// ===========================================================================

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

// ===========================================================================
// Minimal ELF builder (all four layouts)
// ===========================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cls {
    C32,
    C64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    L,
    B,
}

const LAYOUTS: [(Cls, End); 4] = [
    (Cls::C32, End::L),
    (Cls::C32, End::B),
    (Cls::C64, End::L),
    (Cls::C64, End::B),
];

/// Write the low `width` bytes of `v` at `off` in the given byte order.
fn put(buf: &mut [u8], end: End, off: usize, width: usize, v: u64) {
    let dst = &mut buf[off..off + width];
    match end {
        End::L => dst.copy_from_slice(&v.to_le_bytes()[..width]),
        End::B => dst.copy_from_slice(&v.to_be_bytes()[8 - width..]),
    }
}

fn get(buf: &[u8], end: End, off: usize, width: usize) -> u64 {
    let mut b = [0u8; 8];
    match end {
        End::L => {
            b[..width].copy_from_slice(&buf[off..off + width]);
            u64::from_le_bytes(b)
        }
        End::B => {
            b[8 - width..].copy_from_slice(&buf[off..off + width]);
            u64::from_be_bytes(b)
        }
    }
}

/// Offset and width of a field inside its structure, per class.
/// Offsets are from the gABI structure definitions (ch4 "ELF Header",
/// "Sections", "Symbol Table"; ch5 "Program Header").
#[derive(Clone, Copy, Debug)]
struct Field {
    name: &'static str,
    f32: (usize, usize),
    f64: (usize, usize),
}
impl Field {
    fn at(self, c: Cls) -> (usize, usize) {
        match c {
            Cls::C32 => self.f32,
            Cls::C64 => self.f64,
        }
    }
}
macro_rules! field {
    ($n:literal, $o32:expr, $w32:expr, $o64:expr, $w64:expr) => {
        Field {
            name: $n,
            f32: ($o32, $w32),
            f64: ($o64, $w64),
        }
    };
}

const E_PHOFF: Field = field!("e_phoff", 28, 4, 32, 8);
const E_SHOFF: Field = field!("e_shoff", 32, 4, 40, 8);
const E_EHSIZE: Field = field!("e_ehsize", 40, 2, 52, 2);
const E_PHENTSIZE: Field = field!("e_phentsize", 42, 2, 54, 2);
const E_PHNUM: Field = field!("e_phnum", 44, 2, 56, 2);
const E_SHENTSIZE: Field = field!("e_shentsize", 46, 2, 58, 2);
const E_SHNUM: Field = field!("e_shnum", 48, 2, 60, 2);
const E_SHSTRNDX: Field = field!("e_shstrndx", 50, 2, 62, 2);
const EHDR_FIELDS: [Field; 8] = [
    E_PHOFF,
    E_SHOFF,
    E_EHSIZE,
    E_PHENTSIZE,
    E_PHNUM,
    E_SHENTSIZE,
    E_SHNUM,
    E_SHSTRNDX,
];

const SH_NAME: Field = field!("sh_name", 0, 4, 0, 4);
const SH_TYPE: Field = field!("sh_type", 4, 4, 4, 4);
const SH_OFFSET: Field = field!("sh_offset", 16, 4, 24, 8);
const SH_SIZE: Field = field!("sh_size", 20, 4, 32, 8);
const SH_LINK: Field = field!("sh_link", 24, 4, 40, 4);
const SH_INFO: Field = field!("sh_info", 28, 4, 44, 4);
const SH_ENTSIZE: Field = field!("sh_entsize", 36, 4, 56, 8);
const SHDR_FIELDS: [Field; 7] = [
    SH_NAME, SH_TYPE, SH_OFFSET, SH_SIZE, SH_LINK, SH_INFO, SH_ENTSIZE,
];

const P_TYPE: Field = field!("p_type", 0, 4, 0, 4);
const P_OFFSET: Field = field!("p_offset", 4, 4, 8, 8);
const P_FILESZ: Field = field!("p_filesz", 16, 4, 32, 8);
const PHDR_FIELDS: [Field; 3] = [P_TYPE, P_OFFSET, P_FILESZ];

const ST_NAME: Field = field!("st_name", 0, 4, 0, 4);
const ST_SHNDX: Field = field!("st_shndx", 14, 2, 6, 2);
const SYM_FIELDS: [Field; 2] = [ST_NAME, ST_SHNDX];

/// Section indices in the built file.
const S_TEXT: usize = 1;
const S_SHSTRTAB: usize = 2;
const S_STRTAB: usize = 3;
const S_SYMTAB: usize = 4;
const S_BSS: usize = 5;
const S_SHNDX: usize = 6;
const NSECT: usize = 7;
const NSYM: usize = 4;
const NPHDR: usize = 2;

#[derive(Clone, Debug)]
struct Built {
    bytes: Vec<u8>,
    cls: Cls,
    end: End,
    phoff: usize,
    phent: usize,
    shoff: usize,
    shent: usize,
    symoff: usize,
    syment: usize,
    /// (offset, size) of .shstrtab and .strtab contents
    shstrtab: (usize, usize),
    strtab: (usize, usize),
}

impl Built {
    fn ehdr_field(&self, f: Field) -> (usize, usize) {
        f.at(self.cls)
    }
    fn shdr_field(&self, i: usize, f: Field) -> (usize, usize) {
        let (o, w) = f.at(self.cls);
        (self.shoff + i * self.shent + o, w)
    }
    fn phdr_field(&self, i: usize, f: Field) -> (usize, usize) {
        let (o, w) = f.at(self.cls);
        (self.phoff + i * self.phent + o, w)
    }
    fn sym_field(&self, i: usize, f: Field) -> (usize, usize) {
        let (o, w) = f.at(self.cls);
        (self.symoff + i * self.syment + o, w)
    }
    fn set(&mut self, (off, w): (usize, usize), v: u64) {
        put(&mut self.bytes, self.end, off, w, v);
    }
    fn label(&self) -> String {
        format!("{:?}/{:?}", self.cls, self.end)
    }
}

/// A string table from `names`; returns (bytes, offset of each name).
fn strtab(names: &[&str]) -> (Vec<u8>, Vec<usize>) {
    let mut t = vec![0u8];
    let mut offs = Vec::new();
    for n in names {
        offs.push(t.len());
        t.extend_from_slice(n.as_bytes());
        t.push(0);
    }
    (t, offs)
}

fn align(buf: &mut Vec<u8>, a: usize) {
    while !buf.len().is_multiple_of(a) {
        buf.push(0);
    }
}

/// A small but complete executable-shaped ELF:
/// 2 program headers (PT_LOAD, PT_GNU_STACK), sections
/// `[null, .text, .shstrtab, .strtab, .symtab, .bss, .symtab_shndx]`,
/// 4 symbols including one that uses `SHN_XINDEX`.
fn build(cls: Cls, end: End) -> Built {
    let (ehsize, phent, shent, syment, w) = match cls {
        Cls::C32 => (52usize, 32usize, 40usize, 16usize, 4usize),
        Cls::C64 => (64, 56, 64, 24, 8),
    };
    let (shstr, shname) = strtab(&[
        ".text",
        ".shstrtab",
        ".strtab",
        ".symtab",
        ".bss",
        ".symtab_shndx",
    ]);
    let (str_, symname) = strtab(&["helper", "main", "data"]);

    let mut b = vec![0u8; ehsize + NPHDR * phent];
    let phoff = ehsize;
    align(&mut b, 16);
    let text_off = b.len();
    b.extend_from_slice(&[0xc3; 16]);
    let shstr_off = b.len();
    b.extend_from_slice(&shstr);
    let str_off = b.len();
    b.extend_from_slice(&str_);
    align(&mut b, 8);
    let symoff = b.len();
    b.resize(symoff + NSYM * syment, 0);
    align(&mut b, 4);
    let shndx_off = b.len();
    b.resize(shndx_off + NSYM * 4, 0);
    align(&mut b, 8);
    let shoff = b.len();
    b.resize(shoff + NSECT * shent, 0);
    let file_len = b.len();

    let mut out = Built {
        bytes: b,
        cls,
        end,
        phoff,
        phent,
        shoff,
        shent,
        symoff,
        syment,
        shstrtab: (shstr_off, shstr.len()),
        strtab: (str_off, str_.len()),
    };

    // --- ELF header (gABI ch4 "ELF Header")
    {
        let bytes = &mut out.bytes;
        bytes[..4].copy_from_slice(&ELFMAG);
        bytes[4] = if cls == Cls::C32 {
            ELFCLASS32
        } else {
            ELFCLASS64
        };
        bytes[5] = if end == End::L {
            ELFDATA2LSB
        } else {
            ELFDATA2MSB
        };
        bytes[6] = EV_CURRENT;
        put(bytes, end, 16, 2, ET_EXEC.into());
        let machine = if cls == Cls::C32 { EM_386 } else { EM_X86_64 };
        put(bytes, end, 18, 2, machine.into());
        put(bytes, end, 20, 4, 1);
        put(bytes, end, 24, w, 0x1000); // e_entry
    }
    out.set(out.ehdr_field(E_PHOFF), phoff as u64);
    out.set(out.ehdr_field(E_SHOFF), shoff as u64);
    out.set(out.ehdr_field(E_EHSIZE), ehsize as u64);
    out.set(out.ehdr_field(E_PHENTSIZE), phent as u64);
    out.set(out.ehdr_field(E_PHNUM), NPHDR as u64);
    out.set(out.ehdr_field(E_SHENTSIZE), shent as u64);
    out.set(out.ehdr_field(E_SHNUM), NSECT as u64);
    out.set(out.ehdr_field(E_SHSTRNDX), S_SHSTRTAB as u64);

    // --- Program headers (gABI ch5 "Program Header")
    // (type, flags, offset, vaddr, filesz, memsz, align)
    let phdrs: [(u32, u32, u64, u64, u64, u64, u64); NPHDR] = [
        (
            PT_LOAD,
            PF_R | PF_X,
            0,
            0,
            file_len as u64,
            file_len as u64,
            0x1000,
        ),
        (PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 16),
    ];
    for (i, &(ty, flags, off, va, fsz, msz, al)) in phdrs.iter().enumerate() {
        let base = phoff + i * phent;
        let e = end;
        let bytes = &mut out.bytes;
        match cls {
            Cls::C32 => {
                put(bytes, e, base, 4, ty.into());
                put(bytes, e, base + 4, 4, off);
                put(bytes, e, base + 8, 4, va);
                put(bytes, e, base + 12, 4, va);
                put(bytes, e, base + 16, 4, fsz);
                put(bytes, e, base + 20, 4, msz);
                put(bytes, e, base + 24, 4, flags.into());
                put(bytes, e, base + 28, 4, al);
            }
            Cls::C64 => {
                put(bytes, e, base, 4, ty.into());
                put(bytes, e, base + 4, 4, flags.into());
                put(bytes, e, base + 8, 8, off);
                put(bytes, e, base + 16, 8, va);
                put(bytes, e, base + 24, 8, va);
                put(bytes, e, base + 32, 8, fsz);
                put(bytes, e, base + 40, 8, msz);
                put(bytes, e, base + 48, 8, al);
            }
        }
    }

    // --- Section headers (gABI ch4 "Sections")
    // (name, type, flags, addr, offset, size, link, info, addralign, entsize)
    type Sh = (u64, u32, u64, u64, u64, u64, u32, u32, u64, u64);
    let shdrs: [Sh; NSECT] = [
        (0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0),
        (
            shname[0] as u64,
            SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR,
            0x1000,
            text_off as u64,
            16,
            0,
            0,
            16,
            0,
        ),
        (
            shname[1] as u64,
            SHT_STRTAB,
            0,
            0,
            shstr_off as u64,
            shstr.len() as u64,
            0,
            0,
            1,
            0,
        ),
        (
            shname[2] as u64,
            SHT_STRTAB,
            0,
            0,
            str_off as u64,
            str_.len() as u64,
            0,
            0,
            1,
            0,
        ),
        // sh_link = string table, sh_info = index of first non-local symbol
        (
            shname[3] as u64,
            SHT_SYMTAB,
            0,
            0,
            symoff as u64,
            (NSYM * syment) as u64,
            S_STRTAB as u32,
            2,
            w as u64,
            syment as u64,
        ),
        (
            shname[4] as u64,
            SHT_NOBITS,
            SHF_WRITE | SHF_ALLOC,
            0x2000,
            shndx_off as u64,
            0x100,
            0,
            0,
            8,
            0,
        ),
        // sh_link of SHT_SYMTAB_SHNDX = the symbol table it extends
        (
            shname[5] as u64,
            SHT_SYMTAB_SHNDX,
            0,
            0,
            shndx_off as u64,
            (NSYM * 4) as u64,
            S_SYMTAB as u32,
            0,
            4,
            4,
        ),
    ];
    for (i, &(name, ty, flags, addr, off, size, link, info, al, es)) in shdrs.iter().enumerate() {
        let base = shoff + i * shent;
        let e = end;
        let bytes = &mut out.bytes;
        put(bytes, e, base, 4, name);
        put(bytes, e, base + 4, 4, ty.into());
        match cls {
            Cls::C32 => {
                for (k, v) in [flags, addr, off, size, link.into(), info.into(), al, es]
                    .into_iter()
                    .enumerate()
                {
                    put(bytes, e, base + 8 + 4 * k, 4, v);
                }
            }
            Cls::C64 => {
                put(bytes, e, base + 8, 8, flags);
                put(bytes, e, base + 16, 8, addr);
                put(bytes, e, base + 24, 8, off);
                put(bytes, e, base + 32, 8, size);
                put(bytes, e, base + 40, 4, link.into());
                put(bytes, e, base + 44, 4, info.into());
                put(bytes, e, base + 48, 8, al);
                put(bytes, e, base + 56, 8, es);
            }
        }
    }

    // --- Symbols (gABI ch4 "Symbol Table"); locals first.
    // (name, info, shndx, value, size, extended index)
    let syms: [(u64, u8, u16, u64, u64, u32); NSYM] = [
        (0, 0, SHN_UNDEF, 0, 0, 0),
        (
            symname[0] as u64,
            (STB_LOCAL << 4) | STT_FUNC,
            S_TEXT as u16,
            0x1000,
            8,
            0,
        ),
        (
            symname[1] as u64,
            (STB_GLOBAL << 4) | STT_FUNC,
            S_TEXT as u16,
            0x1008,
            8,
            0,
        ),
        (
            symname[2] as u64,
            (STB_GLOBAL << 4) | STT_OBJECT,
            SHN_XINDEX,
            0x2000,
            4,
            S_BSS as u32,
        ),
    ];
    for (i, &(name, info, shndx, value, size, x)) in syms.iter().enumerate() {
        let base = symoff + i * syment;
        let e = end;
        let bytes = &mut out.bytes;
        match cls {
            Cls::C32 => {
                put(bytes, e, base, 4, name);
                put(bytes, e, base + 4, 4, value);
                put(bytes, e, base + 8, 4, size);
                bytes[base + 12] = info;
                bytes[base + 13] = 0;
                put(bytes, e, base + 14, 2, shndx.into());
            }
            Cls::C64 => {
                put(bytes, e, base, 4, name);
                bytes[base + 4] = info;
                bytes[base + 5] = 0;
                put(bytes, e, base + 6, 2, shndx.into());
                put(bytes, e, base + 8, 8, value);
                put(bytes, e, base + 16, 8, size);
            }
        }
        put(&mut out.bytes, e, shndx_off + 4 * i, 4, x.into());
    }
    out
}

/// Interesting values for an integer field of any width; truncated by `put`.
fn hostile_values(file_len: usize, struct_size: Option<usize>) -> Vec<u64> {
    let mut v = vec![
        0,
        1,
        2,
        3,
        4,
        7,
        8,
        0x7f,
        0xff,
        0x7fff,
        0x8000,
        0xfeff,
        SHN_LORESERVE.into(),
        SHN_XINDEX.into(),
        0x1_0000,
        0x7fff_ffff,
        0x8000_0000,
        u32::MAX.into(),
        0x1_0000_0000,
        1 << 40,
        u64::MAX / 2,
        u64::MAX - 0x3f,
        u64::MAX - 7,
        u64::MAX - 1,
        u64::MAX,
        file_len as u64 - 1,
        file_len as u64,
        file_len as u64 + 1,
    ];
    if let Some(s) = struct_size {
        let s = s as u64;
        v.extend([s - 1, s + 1, 2 * s, s / 2]);
    }
    // Small indices, so sh_link / e_shstrndx hit every section (and itself).
    v.extend(0..=(NSECT as u64 + 1));
    v.sort_unstable();
    v.dedup();
    v
}

// ===========================================================================
// Corpus (testdata/bin), optional
// ===========================================================================

/// ELF files under `testdata/bin` (recursively, skipping dot-directories),
/// smallest first, read lazily. Empty when the directory is absent.
fn corpus() -> impl Iterator<Item = (PathBuf, Vec<u8>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/bin");
    let mut paths: Vec<(u64, PathBuf)> = Vec::new();
    let mut stack = vec![dir.clone()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.filter_map(|e| e.ok()) {
            let p = e.path();
            if p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with('.'))
            {
                continue;
            }
            match e.metadata() {
                Ok(m) if m.is_dir() => stack.push(p),
                Ok(m) if m.is_file() => paths.push((m.len(), p)),
                _ => {}
            }
        }
    }
    if paths.is_empty() {
        eprintln!(
            "note: no files under {}, corpus part skipped",
            dir.display()
        );
    }
    paths.sort();
    paths.into_iter().filter_map(|(_, p)| {
        let bytes = std::fs::read(&p).ok()?;
        bytes.starts_with(&ELFMAG).then_some((p, bytes))
    })
}

// ===========================================================================
// Tests
// ===========================================================================

/// The builder itself is correct: unforge and goblin (oracle) agree on it.
#[test]
fn builder_output_is_valid_elf() {
    for (c, e) in LAYOUTS {
        let b = build(c, e);
        let elf = ElfFile::parse(&b.bytes).unwrap_or_else(|err| panic!("{}: {err}", b.label()));
        let h = elf.header();
        assert_eq!(
            h.class,
            if c == Cls::C32 {
                Class::Elf32
            } else {
                Class::Elf64
            }
        );
        assert_eq!(
            h.endian,
            if e == End::L {
                Endian::Little
            } else {
                Endian::Big
            }
        );
        assert_eq!(elf.program_headers().unwrap().len(), NPHDR);
        let shs: Vec<SectionHeader> = elf.section_headers().unwrap().iter().collect();
        assert_eq!(shs.len(), NSECT);
        // The layout is read from EI_CLASS/EI_DATA, nothing is inferred.
        assert!(!elf.layout().is_inferred(), "{}", b.label());
        assert!(elf.inferences().is_empty(), "{}", b.label());
        assert_eq!(
            elf.section_by_name(b".symtab").map(|(i, _)| i),
            Some(S_SYMTAB)
        );
        let tabs: Vec<_> = elf.symbol_tables().unwrap().collect();
        assert_eq!(tabs.len(), 1);
        let names: Vec<&[u8]> = tabs[0].iter().map(|s| tabs[0].name(&s).unwrap()).collect();
        assert_eq!(names, [&b""[..], b"helper", b"main", b"data"]);
        assert_eq!(
            tabs[0].get(3).unwrap().section,
            SymbolSection::Index(S_BSS as u32)
        );

        let g = goblin::elf::Elf::parse(&b.bytes)
            .unwrap_or_else(|err| panic!("goblin {}: {err}", b.label()));
        assert_eq!(g.is_64, c == Cls::C64);
        assert_eq!(g.little_endian, e == End::L);
        assert_eq!(g.section_headers.len(), NSECT);
        assert_eq!(g.program_headers.len(), NPHDR);
        let gnames: Vec<&str> = g
            .syms
            .iter()
            .map(|s| g.strtab.get_at(s.st_name).unwrap_or("?"))
            .collect();
        assert_eq!(gnames, ["", "helper", "main", "data"]);
        for (i, sh) in g.section_headers.iter().enumerate() {
            assert_eq!(shs[i].offset, sh.sh_offset, "{} section {i}", b.label());
            assert_eq!(shs[i].size, sh.sh_size, "{} section {i}", b.label());
            assert_eq!(shs[i].link, sh.sh_link, "{} section {i}", b.label());
        }
        assert_ne!(exercise(&b.bytes), 0);
    }
}

#[test]
fn truncation_at_every_length() {
    let mut h = Harness::new();
    for (c, e) in LAYOUTS {
        let b = build(c, e);
        for len in 0..=b.bytes.len() {
            h.check(
                || format!("{} truncated to {len}", b.label()),
                &b.bytes[..len],
            );
        }
    }
    // Real binaries: every length up to 4 KiB, then lengths around every table
    // boundary, then a geometric sweep.
    let budget = Instant::now();
    let mut files = 0;
    for (path, bytes) in corpus() {
        if budget.elapsed() > Duration::from_secs(20) {
            eprintln!(
                "note: corpus truncation budget exhausted at {}",
                path.display()
            );
            break;
        }
        files += 1;
        let n = bytes.len();
        let mut lens: Vec<usize> = (0..=n.min(4096)).collect();
        if let Ok(elf) = ElfFile::parse(&bytes) {
            let mut edges = vec![elf.header().phoff, elf.header().shoff];
            if let Ok(shs) = elf.section_headers() {
                for sh in shs {
                    edges.push(sh.offset);
                    edges.push(sh.offset.saturating_add(sh.size));
                }
            }
            for x in edges {
                let x = x as usize;
                for d in [0usize, 1, 2, 7, 15, 63] {
                    lens.push(x.saturating_sub(d));
                    lens.push(x.saturating_add(d));
                }
            }
        }
        let mut l = 4096usize;
        while l < n {
            lens.push(l);
            l = l + l / 8 + 1;
        }
        lens.push(n.saturating_sub(1));
        lens.retain(|&l| l <= n);
        lens.sort_unstable();
        lens.dedup();
        for len in lens {
            h.check(
                || format!("{} truncated to {len}", path.display()),
                &bytes[..len],
            );
        }
    }
    eprintln!("truncation: {files} corpus files");
    h.finish("truncation");
}

#[test]
fn single_byte_and_bit_flips() {
    let mut h = Harness::new();
    let mut rng = Rng::new(0x5eed_e1f0_0000_0001);
    for (c, e) in LAYOUTS {
        let b = build(c, e);
        let mut buf = b.bytes.clone();
        // Exhaustive single-bit flips over the whole (small) file.
        for i in 0..buf.len() {
            for bit in 0..8 {
                buf[i] ^= 1 << bit;
                h.check(|| format!("{} bit {bit} of byte {i:#x}", b.label()), &buf);
                buf[i] ^= 1 << bit;
            }
        }
        // Random byte replacements.
        for _ in 0..4000 {
            let i = rng.below(buf.len());
            let old = buf[i];
            let v = rng.next() as u8;
            buf[i] = v;
            h.check(|| format!("{} byte {i:#x} := {v:#04x}", b.label()), &buf);
            buf[i] = old;
        }
        // Random multi-byte havoc (2..=16 bytes changed at once).
        for _ in 0..4000 {
            let mut m = b.bytes.clone();
            let k = 2 + rng.below(15);
            let mut desc = String::new();
            for _ in 0..k {
                let i = rng.below(m.len());
                let v = rng.next() as u8;
                m[i] = v;
                desc.push_str(&format!("{i:#x}={v:#04x} "));
            }
            h.check(|| format!("{} havoc {desc}", b.label()), &m);
        }
    }
    // Corpus: flips concentrated on the header and the tables.
    let budget = Instant::now();
    for (path, mut bytes) in corpus() {
        if budget.elapsed() > Duration::from_secs(25) {
            eprintln!(
                "note: corpus flip budget exhausted before {}",
                path.display()
            );
            break;
        }
        let mut regions: Vec<(usize, usize)> = vec![(0, 64)];
        if let Ok(elf) = ElfFile::parse(&bytes) {
            let hd = elf.header();
            let ph = (hd.phnum as usize).saturating_mul(hd.phentsize as usize);
            let sh = (hd.shnum as usize).saturating_mul(hd.shentsize as usize);
            regions.push((hd.phoff as usize, ph));
            regions.push((hd.shoff as usize, sh));
            if let Ok(shs) = elf.section_headers() {
                for s in shs {
                    if s.sh_type == SHT_SYMTAB || s.sh_type == SHT_DYNSYM {
                        regions.push((s.offset as usize, (s.size as usize).min(4096)));
                    }
                }
            }
        }
        regions.retain(|&(o, l)| l > 0 && o.checked_add(l).is_some_and(|end| end <= bytes.len()));
        if regions.is_empty() {
            continue;
        }
        for _ in 0..300 {
            let (o, l) = regions[rng.below(regions.len())];
            let i = o + rng.below(l);
            let bit = rng.below(8);
            bytes[i] ^= 1 << bit;
            h.check(
                || format!("{} bit {bit} of byte {i:#x}", path.display()),
                &bytes,
            );
            bytes[i] ^= 1 << bit;
        }
    }
    h.finish("flips");
}

#[test]
fn targeted_field_overwrites() {
    let mut h = Harness::new();
    for (c, e) in LAYOUTS {
        let base = build(c, e);
        let len = base.bytes.len();
        let mut targets: Vec<(String, (usize, usize), Option<usize>)> = Vec::new();
        for f in EHDR_FIELDS {
            let ss = match f.name {
                "e_phentsize" => Some(base.phent),
                "e_shentsize" => Some(base.shent),
                "e_ehsize" => Some(if c == Cls::C32 { 52 } else { 64 }),
                _ => None,
            };
            targets.push((f.name.to_string(), base.ehdr_field(f), ss));
        }
        for i in 0..NSECT {
            for f in SHDR_FIELDS {
                let ss = (f.name == "sh_entsize").then_some(base.syment);
                targets.push((
                    format!("section[{i}].{}", f.name),
                    base.shdr_field(i, f),
                    ss,
                ));
            }
        }
        for i in 0..NPHDR {
            for f in PHDR_FIELDS {
                targets.push((format!("phdr[{i}].{}", f.name), base.phdr_field(i, f), None));
            }
        }
        for i in 0..NSYM {
            for f in SYM_FIELDS {
                targets.push((format!("sym[{i}].{}", f.name), base.sym_field(i, f), None));
            }
        }
        // Each target alone.
        for (name, loc, ss) in &targets {
            for v in hostile_values(len, *ss) {
                let mut b = base.clone();
                b.set(*loc, v);
                h.check(|| format!("{} {name} := {v:#x}", base.label()), &b.bytes);
            }
        }
        // Pairs of targets with random hostile values (deterministic).
        let mut rng = Rng::new(0xfeed_0000 ^ len as u64);
        for _ in 0..3000 {
            let mut b = base.clone();
            let mut desc = String::new();
            for _ in 0..2 {
                let (name, loc, ss) = &targets[rng.below(targets.len())];
                let vals = hostile_values(len, *ss);
                let v = vals[rng.below(vals.len())];
                b.set(*loc, v);
                desc.push_str(&format!("{name}:={v:#x} "));
            }
            h.check(|| format!("{} {desc}", base.label()), &b.bytes);
        }
    }
    h.finish("targeted overwrites");
}

#[test]
fn ident_class_and_data_bytes() {
    for (c, e) in LAYOUTS {
        let base = build(c, e);
        let layout = |f: &ElfFile<'_>| (f.header().class, f.header().endian);
        let expected = layout(&ElfFile::parse(&base.bytes).unwrap());
        // Changed from the strict reader (which failed with
        // UnsupportedClass / UnsupportedData): the kernel never reads
        // EI_CLASS or EI_DATA (testdata/anomalous/LOADER_RULES.md §1), so the
        // layout is decided from e_machine and the header sizes and the bad
        // byte is reported.
        for v in [0u8, 3, 0x7f, 0xff] {
            let mut b = base.bytes.clone();
            b[4] = v;
            let f = ElfFile::parse(&b)
                .unwrap_or_else(|err| panic!("{} EI_CLASS={v}: {err}", base.label()));
            assert_eq!(layout(&f), expected, "{} EI_CLASS={v}", base.label());
            assert!(
                f.diagnostics().iter().any(
                    |d| matches!(d.kind, DiagnosticKind::ClassMismatch { claimed, .. } if claimed == v)
                ),
                "{} EI_CLASS={v}",
                base.label()
            );
            let mut b = base.bytes.clone();
            b[5] = v;
            let f = ElfFile::parse(&b)
                .unwrap_or_else(|err| panic!("{} EI_DATA={v}: {err}", base.label()));
            assert_eq!(layout(&f), expected, "{} EI_DATA={v}", base.label());
            assert!(
                f.diagnostics().iter().any(
                    |d| matches!(d.kind, DiagnosticKind::DataMismatch { claimed, .. } if claimed == v)
                ),
                "{} EI_DATA={v}",
                base.label()
            );
        }
        // The "other" class: an ELF64 ident in front of ELF32 tables and vice
        // versa must not panic (the header is simply reinterpreted).
        let mut b = base.bytes.clone();
        b[4] = if c == Cls::C32 {
            ELFCLASS64
        } else {
            ELFCLASS32
        };
        let mut hn = Harness::new();
        hn.check(|| format!("{} class swapped", base.label()), &b);
        // e_machine and the header sizes still identify the real class.
        assert_eq!(
            layout(&ElfFile::parse(&b).unwrap()),
            expected,
            "{} class swapped",
            base.label()
        );
        let mut b = base.bytes.clone();
        b[5] = if e == End::L {
            ELFDATA2MSB
        } else {
            ELFDATA2LSB
        };
        hn.check(|| format!("{} data swapped", base.label()), &b);
        hn.finish("ident swap");
    }
    // Bad magic and tiny inputs.
    assert!(ElfFile::parse(b"").is_err());
    assert!(ElfFile::parse(b"\x7fEL").is_err());
    assert!(matches!(
        ElfFile::parse(b"MZ\x90\0"),
        Err(Error::BadMagic(_))
    ));
    assert!(ElfFile::parse(&[0x7f, b'E', b'L', b'F', 2, 1, 1]).is_err());
}

/// gABI ch4 "Sections" (SHT_SYMTAB / sh_entsize) and the symbol/section-table
/// entry sizes: entsize 0, smaller and larger than the structure.
#[test]
fn entsize_zero_smaller_larger() {
    let mut h = Harness::new();
    for (c, e) in LAYOUTS {
        let base = build(c, e);
        for (what, loc, s) in [
            ("e_phentsize", base.ehdr_field(E_PHENTSIZE), base.phent),
            ("e_shentsize", base.ehdr_field(E_SHENTSIZE), base.shent),
            (
                "symtab sh_entsize",
                base.shdr_field(S_SYMTAB, SH_ENTSIZE),
                base.syment,
            ),
        ] {
            for v in [0, 1, s - 1, s + 1, s + 8, 2 * s, 0xffff] {
                let mut b = base.clone();
                b.set(loc, v as u64);
                h.check(|| format!("{} {what} := {v}", base.label()), &b.bytes);
            }
        }
        // Entry size 0 must never be a division by zero. Changed from the
        // strict reader (Err(BadEntrySize)): the structure size of the class
        // is used instead, and the audit records that inference.
        let inferred = |elf: &ElfFile<'_>, subject: fn(&InferenceSubject) -> bool| {
            elf.inferences().iter().any(|i| subject(&i.subject))
        };
        let mut b = base.clone();
        b.set(b.shdr_field(S_SYMTAB, SH_ENTSIZE), 0);
        let elf = ElfFile::parse(&b.bytes).unwrap();
        let t = elf.symbol_table(S_SYMTAB).unwrap();
        assert!(t.entry_size_inferred());
        assert_eq!(t.len(), NSYM, "{}", base.label());
        assert!(inferred(&elf, |s| matches!(
            s,
            InferenceSubject::SymbolEntrySize { .. }
        )));

        let mut b = base.clone();
        b.set(b.ehdr_field(E_SHENTSIZE), 0);
        let elf = ElfFile::parse(&b.bytes).unwrap();
        assert_eq!(
            elf.section_headers().unwrap().len(),
            NSECT,
            "{}",
            base.label()
        );
        assert!(inferred(&elf, |s| *s == InferenceSubject::SectionHeaderEntrySize));

        let mut b = base.clone();
        b.set(b.ehdr_field(E_PHENTSIZE), 0);
        let elf = ElfFile::parse(&b.bytes).unwrap();
        assert_eq!(
            elf.program_headers().unwrap().len(),
            NPHDR,
            "{}",
            base.label()
        );
        assert!(inferred(&elf, |s| *s == InferenceSubject::ProgramHeaderEntrySize));
    }
    h.finish("entsize");
}

#[test]
fn sh_link_self_and_out_of_range() {
    for (c, e) in LAYOUTS {
        let base = build(c, e);
        for v in [
            S_SYMTAB as u64,
            S_TEXT as u64,
            S_BSS as u64,
            NSECT as u64,
            0xffff,
            u32::MAX.into(),
        ] {
            let mut b = base.clone();
            b.set(b.shdr_field(S_SYMTAB, SH_LINK), v);
            let elf = ElfFile::parse(&b.bytes).unwrap();
            let r = panic::catch_unwind(AssertUnwindSafe(|| exercise(&b.bytes)));
            assert!(r.is_ok(), "{} symtab.sh_link={v}", base.label());
            if v >= NSECT as u64 {
                // Changed from the strict reader (Err(BadIndex) for the
                // whole table): the symbols are still read, only their names
                // are unavailable, and the audit says why.
                let t = elf.symbol_table(S_SYMTAB).unwrap();
                assert_eq!(t.len(), NSYM, "{} sh_link={v}", base.label());
                assert!(t.strtab().is_none());
                assert!(matches!(
                    t.name(&t.get(1).unwrap()),
                    Err(Error::Missing { .. })
                ));
                assert!(
                    elf.diagnostics().iter().any(|d| matches!(
                        d.kind,
                        DiagnosticKind::SymbolTableLinkInvalid {
                            table: S_SYMTAB,
                            ..
                        }
                    )),
                    "{} sh_link={v}",
                    base.label()
                );
            }
            // Also the SHT_SYMTAB_SHNDX back-link.
            let mut b = base.clone();
            b.set(b.shdr_field(S_SHNDX, SH_LINK), v);
            let r = panic::catch_unwind(AssertUnwindSafe(|| exercise(&b.bytes)));
            assert!(r.is_ok(), "{} shndx.sh_link={v}", base.label());
        }
    }
}

/// gABI ch4 "String Table": "the last byte, is defined to hold a null
/// character, ensuring null termination for all strings". A table that
/// violates it must yield an error, not a read past the table.
#[test]
fn strings_without_nul_terminator() {
    for (c, e) in LAYOUTS {
        let base = build(c, e);
        // Drop the final NUL of .shstrtab by shrinking sh_size by one: the last
        // name (".symtab_shndx") is then unterminated *within the section*,
        // even though the next byte in the file is a NUL.
        let mut b = base.clone();
        b.set(
            b.shdr_field(S_SHSTRTAB, SH_SIZE),
            (base.shstrtab.1 - 1) as u64,
        );
        let elf = ElfFile::parse(&b.bytes).unwrap();
        let sh = elf.section_header(S_SHNDX).unwrap();
        assert!(
            matches!(elf.section_name(&sh), Err(Error::BadString { .. })),
            "{}: {:?}",
            base.label(),
            elf.section_name(&sh)
        );
        assert_eq!(elf.section_by_name(b".symtab_shndx"), None);
        assert_ne!(exercise(&b.bytes), 0);

        // Same for .strtab: the last symbol name ("data") becomes unterminated.
        let mut b = base.clone();
        b.set(b.shdr_field(S_STRTAB, SH_SIZE), (base.strtab.1 - 1) as u64);
        let elf = ElfFile::parse(&b.bytes).unwrap();
        let t = elf.symbol_table(S_SYMTAB).unwrap();
        assert!(matches!(
            t.name(&t.get(3).unwrap()),
            Err(Error::BadString { .. })
        ));
        assert_eq!(t.name(&t.get(2).unwrap()).unwrap(), b"main");

        // Overwrite every NUL in .shstrtab: no name resolves.
        let mut b = base.clone();
        let (o, l) = base.shstrtab;
        for x in &mut b.bytes[o..o + l] {
            if *x == 0 {
                *x = b'A';
            }
        }
        let elf = ElfFile::parse(&b.bytes).unwrap();
        for sh in elf.section_headers().unwrap() {
            assert!(elf.section_name(&sh).is_err());
        }

        // Name offsets at, and past, the end of the table.
        for v in [l as u64 - 1, l as u64, l as u64 + 1, u32::MAX.into()] {
            let mut b = base.clone();
            b.set(b.shdr_field(S_TEXT, SH_NAME), v);
            let elf = ElfFile::parse(&b.bytes).unwrap();
            let sh = elf.section_header(S_TEXT).unwrap();
            let r = elf.section_name(&sh);
            if v == l as u64 - 1 {
                assert_eq!(
                    r.unwrap(),
                    b"",
                    "offset of the final NUL is the empty string"
                );
            } else {
                assert!(
                    matches!(r, Err(Error::BadString { .. })),
                    "{} sh_name={v}: {r:?}",
                    base.label()
                );
            }
        }
    }
}

/// gABI ch4 "Sections", table "Section Header Table Entry: Index 0":
/// `e_shnum == 0` => real count in `sh_size` of section 0;
/// `e_phnum == PN_XNUM` => real count in `sh_info` of section 0;
/// `e_shstrndx == SHN_XINDEX` => real index in `sh_link` of section 0.
#[test]
fn extended_numbering_with_hostile_section_zero() {
    let mut h = Harness::new();
    for (c, e) in LAYOUTS {
        let base = build(c, e);
        let vals = hostile_values(base.bytes.len(), None);
        for v in &vals {
            let v = *v;
            // e_shnum = 0, huge sh_size in section 0
            let mut b = base.clone();
            b.set(b.ehdr_field(E_SHNUM), 0);
            b.set(b.shdr_field(0, SH_SIZE), v);
            h.check(
                || format!("{} e_shnum=0 sh0.sh_size={v:#x}", base.label()),
                &b.bytes,
            );
            // The value actually stored (ELF32 sh_size is 4 bytes wide).
            let (off, w) = b.shdr_field(0, SH_SIZE);
            let stored = get(&b.bytes, b.end, off, w);
            if stored > (base.bytes.len() / base.shent) as u64 {
                // More entries than the file can hold. Changed from the
                // strict reader (the table had to be an error): the entries
                // inside the file are read, never more, and the clipping is
                // reported.
                let elf = ElfFile::parse(&b.bytes);
                if let Ok(elf) = elf {
                    let room = (base.bytes.len().saturating_sub(base.shoff) / base.shent) as u64;
                    if let Ok(t) = elf.section_headers() {
                        assert!(
                            (t.len() as u64) <= room,
                            "{} shnum via sh0 = {stored:#x}: {} entries",
                            base.label(),
                            t.len()
                        );
                        assert!(
                            elf.diagnostics().iter().any(|d| matches!(
                                d.kind,
                                DiagnosticKind::SectionCountClipped { .. }
                            )),
                            "{} shnum via sh0 = {stored:#x}",
                            base.label()
                        );
                    }
                }
            }
            // PN_XNUM, huge sh_info in section 0
            let mut b = base.clone();
            b.set(b.ehdr_field(E_PHNUM), PN_XNUM.into());
            b.set(b.shdr_field(0, SH_INFO), v);
            h.check(
                || format!("{} PN_XNUM sh0.sh_info={v:#x}", base.label()),
                &b.bytes,
            );
            // SHN_XINDEX, arbitrary sh_link in section 0
            let mut b = base.clone();
            b.set(b.ehdr_field(E_SHSTRNDX), SHN_XINDEX.into());
            b.set(b.shdr_field(0, SH_LINK), v);
            h.check(
                || format!("{} SHN_XINDEX sh0.sh_link={v:#x}", base.label()),
                &b.bytes,
            );
            // All three escapes at once, and e_shoff pointing near the end.
            let mut b = base.clone();
            b.set(b.ehdr_field(E_SHNUM), 0);
            b.set(b.ehdr_field(E_PHNUM), PN_XNUM.into());
            b.set(b.ehdr_field(E_SHSTRNDX), SHN_XINDEX.into());
            b.set(b.shdr_field(0, SH_SIZE), v);
            b.set(b.shdr_field(0, SH_INFO), v);
            b.set(b.shdr_field(0, SH_LINK), v);
            h.check(
                || format!("{} all escapes = {v:#x}", base.label()),
                &b.bytes,
            );
            b.set(b.ehdr_field(E_SHOFF), v);
            h.check(
                || format!("{} all escapes, e_shoff = {v:#x}", base.label()),
                &b.bytes,
            );
        }
        // Valid use of the escapes: same results as the plain header.
        let mut b = base.clone();
        b.set(b.ehdr_field(E_SHNUM), 0);
        b.set(b.shdr_field(0, SH_SIZE), NSECT as u64);
        b.set(b.ehdr_field(E_PHNUM), PN_XNUM.into());
        b.set(b.shdr_field(0, SH_INFO), NPHDR as u64);
        b.set(b.ehdr_field(E_SHSTRNDX), SHN_XINDEX.into());
        b.set(b.shdr_field(0, SH_LINK), S_SHSTRTAB as u64);
        let elf = ElfFile::parse(&b.bytes).unwrap();
        assert_eq!(elf.header().shnum, NSECT as u64);
        assert_eq!(elf.header().phnum, NPHDR as u64);
        assert_eq!(elf.header().shstrndx, Some(S_SHSTRTAB as u32));
        assert_eq!(
            elf.section_by_name(b".symtab").map(|(i, _)| i),
            Some(S_SYMTAB)
        );
    }
    h.finish("extended numbering");
}

/// A 200-byte file that declares tables of 2^40 entries (or u32::MAX program
/// headers) must be handled immediately: either refused or clipped to the
/// few entries the file holds, without trying to allocate the declared size.
#[test]
fn huge_declared_tables_fail_fast() {
    // Hand-made ELF64 LSB: header at 0, one section header at 64, padding.
    fn file(shnum: u16, phnum: u16, shentsize: u16, sh0_size: u64, sh0_info: u32) -> Vec<u8> {
        let mut b = vec![0u8; 200];
        b[..4].copy_from_slice(&ELFMAG);
        b[4] = ELFCLASS64;
        b[5] = ELFDATA2LSB;
        b[6] = EV_CURRENT;
        put(&mut b, End::L, 16, 2, ET_EXEC.into());
        put(&mut b, End::L, 18, 2, EM_X86_64.into());
        put(&mut b, End::L, 20, 4, 1);
        put(&mut b, End::L, 32, 8, 64); // e_phoff
        put(&mut b, End::L, 40, 8, 64); // e_shoff
        put(&mut b, End::L, 52, 2, 64); // e_ehsize
        put(&mut b, End::L, 54, 2, 56); // e_phentsize
        put(&mut b, End::L, 56, 2, phnum.into());
        put(&mut b, End::L, 58, 2, shentsize.into());
        put(&mut b, End::L, 60, 2, shnum.into());
        // section 0 at 64
        put(&mut b, End::L, 64 + 32, 8, sh0_size);
        put(&mut b, End::L, 64 + 44, 4, sh0_info.into());
        b
    }
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("shnum=2^40 via sh0", file(0, 0, 64, 1 << 40, 0)),
        ("shnum=u64::MAX via sh0", file(0, 0, 64, u64::MAX, 0)),
        (
            "shnum=2^40, shentsize=0xffff",
            file(0, 0, 0xffff, 1 << 40, 0),
        ),
        ("shnum=0xfffe", file(0xfffe, 0, 64, 0, 0)),
        (
            "phnum=u32::MAX via PN_XNUM",
            file(1, PN_XNUM, 64, 0, u32::MAX),
        ),
        ("both", file(0, PN_XNUM, 64, u64::MAX / 64, u32::MAX)),
    ];
    for (what, bytes) in &cases {
        let t = Instant::now();
        let r = panic::catch_unwind(AssertUnwindSafe(|| match ElfFile::parse(bytes) {
            Err(_) => (true, true),
            // Changed from the strict reader (the tables had to be errors):
            // only the entries inside the 200-byte file may be read.
            Ok(elf) => {
                let _ = exercise(bytes);
                (
                    elf.section_headers().map_or(true, |t| t.len() <= 3),
                    elf.program_headers().map_or(true, |t| t.len() <= 3),
                )
            }
        }));
        let dt = t.elapsed();
        let (sh_err, ph_err) = r.unwrap_or_else(|_| panic!("{what}: panicked"));
        assert!(sh_err, "{what}: section header table accepted");
        assert!(ph_err, "{what}: program header table accepted");
        assert!(dt < Duration::from_millis(500), "{what}: took {dt:?}");
    }
}

/// `section_data` / `segment_data` accept caller-built headers (the structs
/// have public fields), so they must cope with arbitrary values too.
#[test]
fn caller_supplied_headers() {
    let base = build(Cls::C64, End::L);
    let elf = ElfFile::parse(&base.bytes).unwrap();
    let n = base.bytes.len() as u64;
    let vals = [
        0,
        1,
        n - 1,
        n,
        n + 1,
        u32::MAX.into(),
        u64::MAX - 1,
        u64::MAX,
    ];
    for &off in &vals {
        for &size in &vals {
            for ty in [SHT_PROGBITS, SHT_NOBITS, SHT_STRTAB] {
                let sh = SectionHeader {
                    name: u32::MAX,
                    sh_type: ty,
                    flags: u64::MAX,
                    addr: u64::MAX,
                    offset: off,
                    size,
                    link: u32::MAX,
                    info: u32::MAX,
                    addralign: u64::MAX,
                    entsize: 0,
                };
                let r = panic::catch_unwind(AssertUnwindSafe(|| {
                    // Changed from the strict reader (Ok only for ranges fully
                    // inside the file): ranges are clipped to the file, and only
                    // an overflowing offset + size is an error.
                    let clipped = off.saturating_add(size).min(n) - off.min(n);
                    let d = elf.section_data(&sh);
                    if let Ok(d) = d {
                        assert!(off.checked_add(size).is_some() || ty == SHT_NOBITS);
                        assert!(d.len() as u64 == clipped || ty == SHT_NOBITS);
                    } else {
                        assert!(off.checked_add(size).is_none());
                    }
                    let b = elf.section_bytes(&sh);
                    if ty != SHT_NOBITS {
                        assert_eq!(b.bytes.len() as u64 + b.missing, size);
                    }
                    let _ = elf.section_name(&sh);
                }));
                assert!(
                    r.is_ok(),
                    "section_data off={off:#x} size={size:#x} type={ty}"
                );
            }
            let ph = ProgramHeader {
                p_type: PT_LOAD,
                flags: u32::MAX,
                offset: off,
                vaddr: u64::MAX,
                paddr: u64::MAX,
                filesz: size,
                memsz: u64::MAX,
                align: u64::MAX,
            };
            let r = panic::catch_unwind(AssertUnwindSafe(|| {
                // Changed like section_data above: clipped, not refused.
                let clipped = off.saturating_add(size).min(n) - off.min(n);
                match elf.segment_data(&ph) {
                    Ok(d) => assert_eq!(d.len() as u64, clipped),
                    Err(_) => assert!(off.checked_add(size).is_none()),
                }
                let b = elf.segment_bytes(&ph);
                assert_eq!(b.bytes.len() as u64 + b.missing, size);
            }));
            assert!(r.is_ok(), "segment_data off={off:#x} size={size:#x}");
        }
    }
}

/// Memory amplification. gABI ch4 "Sections": "Sections in a file may not
/// overlap. No byte in a file resides in more than one section." A hostile
/// file can still declare many `SHT_SYMTAB` sections over the *same* bytes.
///
/// Changed from the strict reader, which refused `symbol_tables()` when the
/// tables' sizes added up to more than the file: tables are now lazy views,
/// so all of them are read (every symbol of every table is visited) without
/// materializing anything, and the audit reports the overlap. The memory
/// bound itself is measured with a counting allocator in
/// `tests/alloc_bounds.rs`.
#[test]
fn overlapping_symbol_tables_are_read_lazily() {
    const K: usize = 1000; // overlapping SHT_SYMTAB sections
    const S: usize = 64 * 1024; // bytes they all cover
    let payload_off = 64usize;
    let shoff = payload_off + S;
    let nsect = K + 2;
    let mut b = vec![0u8; shoff + nsect * 64];
    b[..4].copy_from_slice(&ELFMAG);
    b[4] = ELFCLASS64;
    b[5] = ELFDATA2LSB;
    b[6] = EV_CURRENT;
    put(&mut b, End::L, 16, 2, ET_REL.into());
    put(&mut b, End::L, 18, 2, EM_X86_64.into());
    put(&mut b, End::L, 20, 4, 1);
    put(&mut b, End::L, 40, 8, shoff as u64);
    put(&mut b, End::L, 52, 2, 64);
    put(&mut b, End::L, 58, 2, 64);
    put(&mut b, End::L, 60, 2, nsect as u64);
    // section 1: a one-byte string table (the NUL at payload_off)
    let s1 = shoff + 64;
    put(&mut b, End::L, s1 + 4, 4, SHT_STRTAB.into());
    put(&mut b, End::L, s1 + 24, 8, payload_off as u64);
    put(&mut b, End::L, s1 + 32, 8, 1);
    for i in 2..nsect {
        let s = shoff + i * 64;
        put(&mut b, End::L, s + 4, 4, SHT_SYMTAB.into());
        put(&mut b, End::L, s + 24, 8, payload_off as u64);
        put(&mut b, End::L, s + 32, 8, S as u64);
        put(&mut b, End::L, s + 40, 4, 1); // sh_link -> section 1
        put(&mut b, End::L, s + 56, 8, 24);
    }
    let elf = ElfFile::parse(&b).unwrap();
    assert_eq!(elf.section_headers().unwrap().len(), nsect);
    let t = Instant::now();
    let mut tables = 0usize;
    let mut symbols = 0usize;
    for table in elf
        .symbol_tables()
        .expect("overlapping tables are not an error")
    {
        tables += 1;
        assert_eq!(table.len(), S / 24);
        symbols += table.iter().filter(|s| table.name(s).is_ok()).count();
    }
    assert_eq!(tables, K);
    assert_eq!(symbols, K * (S / 24));
    assert!(
        t.elapsed() < Duration::from_secs(10),
        "took {:?}",
        t.elapsed()
    );
    // The overlap is reported, boundedly.
    let audit = elf.audit();
    let dups = audit
        .diagnostics
        .iter()
        .filter(|d| matches!(d.kind, DiagnosticKind::DuplicateTable { same_as: 2, .. }))
        .count();
    assert_eq!(dups, unforge_elf::MAX_DIAGNOSTICS_PER_KIND);
    assert!(audit.diagnostics.iter().any(|d| matches!(
        d.kind,
        DiagnosticKind::Suppressed { kind: "duplicate-table", count } if count as usize == K - 1 - unforge_elf::MAX_DIAGNOSTICS_PER_KIND
    )));
}

/// Regression inputs found by `cargo fuzz` (fuzz/fuzz_targets/parse.rs).
/// Each entry: (description, minimized bytes).
const FUZZ_REGRESSIONS: &[(&str, &[u8])] = &[(
    "AT_PHDR computation e_phoff - p_offset + p_vaddr overflowed in the audit",
    b"\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\xff\xff\xff\xf6\x00\x00\x02\x00\x3e\x00\x01\x00\x00\x00\
        \x00\x10\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x78\x01\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x40\x00\x38\x00\x0a\x00\x40\x00\x20\x00\x02\x00\x28\x00\x07\x00\x00\x00\x00\x00\
        \x02\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x40\x00\x00\x02\
        \x40\x00\x00\x00\x05\x00\x00\x10\x00\x74\x74\x00\x00\x00\x00\x00\x00\x00\x01\x00\x15\x00\x00\x00\
        \x01\x00\x00\x00\xd6\x00\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\
        \xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
        \xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
        \xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
        \xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x07\xa0\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\
        \x00\x40\x00\x11\x00\x01\x28\x04\x00\x00\x41\x82\x00\x18\x28\x04\x00\x01\x40\x82\x00\x1c\x78\xa4\
        \x00\x20\x7c\x63\x21\xd2\x4e\x80\x00\x20\x78\xa4\x00\x20\x7c\x63\x22\x14\x4e\x82\x00\x20\x7c\x63\
        \x00\xd0\x4e\x80\x00\x60\x20\x00\x00\x27\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x50\x00\x00\x00\x00\x00\x00\x00\x9e\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \x04\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x05\x00\x00\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3e\
        \x00\x00\x08\x66\x02\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\
        \x00\x00\x02\x9d\x02\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x02\xff\x00\x00\x00\x01\x00\x00\
        \x48\x49\x43\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \x21\x00\x00\x00\x0a\x00\x00\x00\x03\x00\x00\x20\x00\x07\x40\x00\x01\x18\x00\x00\x01\x00\x00\x00\
        \x00\x00\x40\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x04\x40\x00\x00\x00\x00\x00",
)];

#[test]
fn fuzz_regressions() {
    let mut h = Harness::new();
    for (what, bytes) in FUZZ_REGRESSIONS {
        h.check(|| what.to_string(), bytes);
    }
    h.finish("fuzz regressions");
}

/// The builder's own integer codec.
#[test]
fn builder_put_get_roundtrip() {
    let mut buf = [0u8; 8];
    for end in [End::L, End::B] {
        for w in [1usize, 2, 4, 8] {
            put(&mut buf, end, 0, w, 0x0102_0304_0506_0708);
            let mask = if w == 8 {
                u64::MAX
            } else {
                (1u64 << (8 * w)) - 1
            };
            assert_eq!(get(&buf, end, 0, w), 0x0102_0304_0506_0708 & mask);
        }
    }
}

/// Writes the builder's four layouts as fuzz seeds:
/// `cargo test -p unforge-elf --test malformed -- --ignored write_fuzz_seeds`
#[test]
#[ignore = "only writes fuzz/corpus/parse seeds"]
fn write_fuzz_seeds() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/parse");
    std::fs::create_dir_all(&dir).unwrap();
    for (c, e) in LAYOUTS {
        let b = build(c, e);
        std::fs::write(dir.join(format!("builder-{c:?}-{e:?}")), &b.bytes).unwrap();
    }
}

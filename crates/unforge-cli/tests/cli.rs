//! End-to-end tests for the `unforge` binary.
//!
//! The `object` crate is used only as an oracle: for real binaries in
//! `testdata/bin`, the section and symbol listings printed by `unforge elf`
//! must agree with what `object` reads from the same file.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_unforge");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn run(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn unforge")
}

fn run_str(args: &[&str]) -> Output {
    let v: Vec<&std::ffi::OsStr> = args.iter().map(std::ffi::OsStr::new).collect();
    run(&v)
}

fn run_elf(path: &Path, flags: &[&str]) -> Output {
    let mut v: Vec<&std::ffi::OsStr> = vec!["elf".as_ref()];
    v.extend(flags.iter().map(std::ffi::OsStr::new));
    v.push(path.as_os_str());
    run(&v)
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).expect("stdout is not UTF-8")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// A fresh path under Cargo's per-test temporary directory.
fn temp_path(tag: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("cli-{}-{tag}-{n}", std::process::id()))
}

fn write_temp(tag: &str, bytes: &[u8]) -> PathBuf {
    let p = temp_path(tag);
    std::fs::write(&p, bytes).expect("write temp file");
    p
}

/// The process must not have panicked (exit code 101 / "panicked at") nor been
/// killed by a signal, and must exit with 0 or 1.
fn assert_no_panic(o: &Output, what: &str) {
    let err = stderr(o);
    assert!(
        !err.contains("panicked at"),
        "{what}: panic on stderr:\n{err}"
    );
    let code = o.status.code();
    assert!(
        matches!(code, Some(0 | 1)),
        "{what}: unexpected exit status {:?}\nstderr: {err}",
        o.status
    );
}

// ---------------------------------------------------------------------------
// A tiny ELF writer for hand-built inputs.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Layout {
    is64: bool,
    be: bool,
}

struct W {
    l: Layout,
    buf: Vec<u8>,
}

impl W {
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u16(&mut self, v: u16) {
        let b = if self.l.be {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        };
        self.buf.extend_from_slice(&b);
    }
    fn u32(&mut self, v: u32) {
        let b = if self.l.be {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        };
        self.buf.extend_from_slice(&b);
    }
    fn u64(&mut self, v: u64) {
        let b = if self.l.be {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        };
        self.buf.extend_from_slice(&b);
    }
    /// `ElfN_Addr` / `ElfN_Off` / `ElfN_Xword`-sized field.
    fn word(&mut self, v: u64) {
        if self.l.is64 {
            self.u64(v);
        } else {
            self.u32(u32::try_from(v).expect("value fits ELF32"));
        }
    }
    fn pad_to(&mut self, off: usize) {
        assert!(self.buf.len() <= off, "layout overlap");
        self.buf.resize(off, 0);
    }
}

fn align(v: usize, a: usize) -> usize {
    v.div_ceil(a) * a
}

/// Offsets inside a file produced by [`minimal_elf`], for targeted corruption.
#[allow(dead_code)]
struct Built {
    bytes: Vec<u8>,
    shoff: usize,
    shentsize: usize,
    symtab_off: usize,
}

const INTERP: &[u8] = b"/lib/ld-test.so\0";

/// An `ET_EXEC` for `EM_X86_64` with two segments (`PT_LOAD`, `PT_INTERP`) and
/// six sections (null, `.text`, `.interp`, `.symtab`, `.strtab`, `.shstrtab`).
///
/// The symbol table holds the null symbol, a LOCAL HIDDEN ABS object whose
/// name is not valid UTF-8, a GLOBAL FUNC `main` in `.text`, and `extra`
/// undefined GLOBAL NOTYPE symbols `sym0`, `sym1`, ...
fn minimal_elf(l: Layout, extra: usize) -> Built {
    let (ehsize, phentsize, shentsize, symsize) = if l.is64 {
        (64usize, 56usize, 64usize, 24usize)
    } else {
        (52, 32, 40, 16)
    };
    let phnum = 2usize;
    let text: &[u8] = &[0xc3, 0x90, 0x90, 0x90];

    let mut strtab = b"\0main\0bad\xffname\0".to_vec();
    let main_name = 1u32;
    let bad_name = 6u32;
    let mut extra_names = Vec::new();
    for i in 0..extra {
        extra_names.push(u32::try_from(strtab.len()).unwrap());
        strtab.extend_from_slice(format!("sym{i}\0").as_bytes());
    }
    let shstrtab = b"\0.text\0.interp\0.symtab\0.strtab\0.shstrtab\0";
    let (n_text, n_interp, n_symtab, n_strtab, n_shstrtab) = (1u32, 7, 15, 23, 31);
    let nsyms = 3 + extra;

    let phoff = ehsize;
    let text_off = align(phoff + phnum * phentsize, 16);
    let interp_off = text_off + 16;
    let symtab_off = align(interp_off + INTERP.len(), 8);
    let strtab_off = symtab_off + nsyms * symsize;
    let shstrtab_off = strtab_off + strtab.len();
    let shoff = align(shstrtab_off + shstrtab.len(), 8);
    let shnum = 6usize;
    let file_len = shoff + shnum * shentsize;
    let base = 0x40_0000u64;
    let text_addr = base + text_off as u64;

    let mut w = W {
        l,
        buf: Vec::with_capacity(file_len),
    };
    // e_ident
    w.buf.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
    w.u8(if l.is64 { 2 } else { 1 });
    w.u8(if l.be { 2 } else { 1 });
    w.u8(1); // EV_CURRENT
    w.u8(0); // ELFOSABI_NONE
    w.u8(0);
    w.buf.extend_from_slice(&[0; 7]);
    w.u16(2); // ET_EXEC
    w.u16(62); // EM_X86_64
    w.u32(1);
    w.word(text_addr);
    w.word(phoff as u64);
    w.word(shoff as u64);
    w.u32(0);
    w.u16(ehsize as u16);
    w.u16(phentsize as u16);
    w.u16(phnum as u16);
    w.u16(shentsize as u16);
    w.u16(shnum as u16);
    w.u16(5); // .shstrtab
    assert_eq!(w.buf.len(), ehsize);

    // Program headers.
    let phdr = |w: &mut W, p_type: u32, flags: u32, off: usize, size: usize, al: u64| {
        let (off, size) = (off as u64, size as u64);
        if w.l.is64 {
            w.u32(p_type);
            w.u32(flags);
            w.word(off);
            w.word(base + off);
            w.word(base + off);
            w.word(size);
            w.word(size);
            w.word(al);
        } else {
            w.u32(p_type);
            w.word(off);
            w.word(base + off);
            w.word(base + off);
            w.word(size);
            w.word(size);
            w.u32(flags);
            w.word(al);
        }
    };
    phdr(&mut w, 1, 4 | 1, 0, file_len, 0x1000); // PT_LOAD R-X
    phdr(&mut w, 3, 4, interp_off, INTERP.len(), 1); // PT_INTERP R--

    w.pad_to(text_off);
    w.buf.extend_from_slice(text);
    w.pad_to(interp_off);
    w.buf.extend_from_slice(INTERP);

    // Symbols.
    w.pad_to(symtab_off);
    let sym = |w: &mut W, name: u32, value: u64, size: u64, info: u8, other: u8, shndx: u16| {
        if w.l.is64 {
            w.u32(name);
            w.u8(info);
            w.u8(other);
            w.u16(shndx);
            w.u64(value);
            w.u64(size);
        } else {
            w.u32(name);
            w.word(value);
            w.word(size);
            w.u8(info);
            w.u8(other);
            w.u16(shndx);
        }
    };
    sym(&mut w, 0, 0, 0, 0, 0, 0);
    sym(&mut w, bad_name, 0x1234, 8, 1, 2, 0xfff1); // LOCAL OBJECT HIDDEN ABS
    sym(&mut w, main_name, text_addr, 4, (1 << 4) | 2, 0, 1); // GLOBAL FUNC .text
    for &n in &extra_names {
        sym(&mut w, n, 0, 0, 1 << 4, 0, 0); // GLOBAL NOTYPE UND
    }
    assert_eq!(w.buf.len(), strtab_off);
    w.buf.extend_from_slice(&strtab);
    w.buf.extend_from_slice(shstrtab);

    // Section headers.
    w.pad_to(shoff);
    #[allow(clippy::too_many_arguments)]
    fn shdr(
        w: &mut W,
        name: u32,
        ty: u32,
        flags: u64,
        addr: u64,
        off: usize,
        size: usize,
        link: u32,
        info: u32,
        al: u64,
        ent: u64,
    ) {
        w.u32(name);
        w.u32(ty);
        w.word(flags);
        w.word(addr);
        w.word(off as u64);
        w.word(size as u64);
        w.u32(link);
        w.u32(info);
        w.word(al);
        w.word(ent);
    }
    shdr(&mut w, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    shdr(
        &mut w,
        n_text,
        1,
        0x6,
        text_addr,
        text_off,
        text.len(),
        0,
        0,
        16,
        0,
    );
    shdr(
        &mut w,
        n_interp,
        1,
        0x2,
        base + interp_off as u64,
        interp_off,
        INTERP.len(),
        0,
        0,
        1,
        0,
    );
    shdr(
        &mut w,
        n_symtab,
        2,
        0,
        0,
        symtab_off,
        nsyms * symsize,
        4,
        2,
        8,
        symsize as u64,
    );
    shdr(
        &mut w,
        n_strtab,
        3,
        0,
        0,
        strtab_off,
        strtab.len(),
        0,
        0,
        1,
        0,
    );
    shdr(
        &mut w,
        n_shstrtab,
        3,
        0,
        0,
        shstrtab_off,
        shstrtab.len(),
        0,
        0,
        1,
        0,
    );
    assert_eq!(w.buf.len(), file_len);
    Built {
        bytes: w.buf,
        shoff,
        shentsize,
        symtab_off,
    }
}

const LAYOUTS: [Layout; 4] = [
    Layout {
        is64: true,
        be: false,
    },
    Layout {
        is64: true,
        be: true,
    },
    Layout {
        is64: false,
        be: false,
    },
    Layout {
        is64: false,
        be: true,
    },
];

// ---------------------------------------------------------------------------
// Parsing unforge's own output (for comparison with the oracle).
// ---------------------------------------------------------------------------

/// The text after the first `n` whitespace-separated tokens of `line`.
fn after_tokens(line: &str, n: usize) -> &str {
    let mut rest = line.trim_start();
    for _ in 0..n {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        rest = rest[end..].trim_start();
    }
    rest.trim_end()
}

/// Section names, in order, from the "Section headers (N):" table.
fn printed_sections(out: &str) -> Option<Vec<String>> {
    let mut lines = out.lines();
    let title = lines.find(|l| l.starts_with("Section headers ("))?;
    let n: usize = title
        .trim_start_matches("Section headers (")
        .trim_end_matches("):")
        .parse()
        .ok()?;
    lines.next()?; // column header
    let names: Vec<String> = lines
        .take(n)
        .map(|l| after_tokens(l, 10).to_string())
        .collect();
    assert_eq!(names.len(), n, "section table shorter than announced");
    Some(names)
}

/// `(section index, symbol names)` for every printed symbol table.
fn printed_symtabs(out: &str) -> Vec<(usize, Vec<String>)> {
    let mut tables = Vec::new();
    let mut lines = out.lines();
    while let Some(l) = lines.next() {
        let Some(rest) = l.strip_prefix("Symbol table '") else {
            continue;
        };
        let Some((_, tail)) = rest.rsplit_once("' (section [") else {
            continue;
        };
        let Some((idx, tail)) = tail.split_once("]) contains ") else {
            continue;
        };
        let idx: usize = idx.parse().expect("section index");
        let n: usize = tail
            .trim_end_matches(" entries:")
            .parse()
            .expect("entry count");
        lines.next().expect("column header");
        let names: Vec<String> = lines
            .by_ref()
            .take(n)
            .map(|l| after_tokens(l, 7).to_string())
            .collect();
        assert_eq!(names.len(), n, "symbol table shorter than announced");
        tables.push((idx, names));
    }
    tables
}

/// Whether unforge prints this name verbatim (no escaping applied).
fn prints_verbatim(name: &[u8]) -> bool {
    name.iter().all(|&b| b.is_ascii_graphic() && b != b'\\')
}

// ---------------------------------------------------------------------------
// The oracle (object crate).
// ---------------------------------------------------------------------------

struct Oracle {
    sections: Vec<Vec<u8>>,
    /// (section index, symbol names) for each SHT_SYMTAB / SHT_DYNSYM section.
    symtabs: Vec<(usize, Vec<Vec<u8>>)>,
}

fn oracle_for<Elf>(data: &[u8]) -> Option<Oracle>
where
    Elf: object::read::elf::FileHeader<Endian = object::Endianness>,
{
    use object::read::elf::SectionHeader as _;
    let h = Elf::parse(data).ok()?;
    let endian = h.endian().ok()?;
    let sections = h.sections(endian, data).ok()?;
    let names = sections
        .iter()
        .map(|s| {
            sections
                .section_name(endian, s)
                .map(<[u8]>::to_vec)
                .unwrap_or_else(|_| b"<oracle: bad name>".to_vec())
        })
        .collect();
    let mut symtabs = Vec::new();
    for (i, s) in sections.iter().enumerate() {
        let t = s.sh_type(endian);
        if t != object::elf::SHT_SYMTAB && t != object::elf::SHT_DYNSYM {
            continue;
        }
        let table = sections
            .symbol_table_by_index(endian, data, object::SectionIndex(i))
            .ok()?;
        let names = table
            .iter()
            .map(|sym| {
                table
                    .symbol_name(endian, sym)
                    .map(<[u8]>::to_vec)
                    .unwrap_or_else(|_| b"<oracle: bad name>".to_vec())
            })
            .collect();
        symtabs.push((i, names));
    }
    Some(Oracle {
        sections: names,
        symtabs,
    })
}

fn oracle(data: &[u8]) -> Option<Oracle> {
    match object::FileKind::parse(data).ok()? {
        object::FileKind::Elf32 => {
            oracle_for::<object::elf::FileHeader32<object::Endianness>>(data)
        }
        object::FileKind::Elf64 => {
            oracle_for::<object::elf::FileHeader64<object::Endianness>>(data)
        }
        _ => None,
    }
}

/// Run `unforge elf` on `path` and check its listing against the oracle.
/// Returns false if the oracle could not read the file (nothing compared).
fn compare_with_oracle(path: &Path) -> bool {
    let data = std::fs::read(path).expect("read input");
    let o = run_elf(path, &[]);
    assert_no_panic(&o, &path.display().to_string());
    let Some(expected) = oracle(&data) else {
        return false;
    };
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}: exit status, stderr:\n{}",
        path.display(),
        stderr(&o)
    );
    let out = stdout(&o);

    let sections = printed_sections(&out).unwrap_or_default();
    assert_eq!(
        sections.len(),
        expected.sections.len(),
        "{}: section count",
        path.display()
    );
    for (i, (got, want)) in sections.iter().zip(&expected.sections).enumerate() {
        if prints_verbatim(want) {
            assert_eq!(
                got.as_bytes(),
                &want[..],
                "{}: name of section {i}",
                path.display()
            );
        }
    }

    let symtabs = printed_symtabs(&out);
    assert_eq!(
        symtabs.iter().map(|t| (t.0, t.1.len())).collect::<Vec<_>>(),
        expected
            .symtabs
            .iter()
            .map(|t| (t.0, t.1.len()))
            .collect::<Vec<_>>(),
        "{}: (symbol table section, symbol count)",
        path.display()
    );
    for ((idx, got), (_, want)) in symtabs.iter().zip(&expected.symtabs) {
        for (n, (g, w)) in got.iter().zip(want).enumerate() {
            if prints_verbatim(w) {
                assert_eq!(
                    g.as_bytes(),
                    &w[..],
                    "{}: symbol {n} of table [{idx}]",
                    path.display()
                );
            }
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Usage errors (exit 2)
// ---------------------------------------------------------------------------

#[test]
fn no_arguments_is_a_usage_error() {
    let o = run_str(&[]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).starts_with("unforge: "), "{}", stderr(&o));
    assert!(o.stdout.is_empty());
}

#[test]
fn bad_command_lines_exit_2() {
    for args in [
        &["frobnicate"][..],
        &["elf"],
        &["elf", "--bogus", "x"],
        &["elf", "a", "b"],
        &["elf", "--header"],
        &["disasm"],
        &["disasm", "--count", "0", "x"],
        &["disasm", "--addr", "zz", "x"],
        &["disasm", "--function", "a", "--addr", "1", "x"],
    ] {
        let o = run_str(args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(
            stderr(&o).starts_with("unforge: "),
            "{args:?}: {}",
            stderr(&o)
        );
    }
}

#[test]
fn help_goes_to_stdout_and_succeeds() {
    for args in [
        &["--help"][..],
        &["-h"],
        &["elf", "--help"],
        &["disasm", "--help"],
        &["help"],
    ] {
        let o = run_str(args);
        assert_eq!(o.status.code(), Some(0), "{args:?}");
        assert!(stdout(&o).contains("Usage:"), "{args:?}");
    }
    let o = run_str(&["--version"]);
    assert_eq!(o.status.code(), Some(0));
    assert!(stdout(&o).starts_with("unforge "));
}

// ---------------------------------------------------------------------------
// I/O and parse errors (exit 1)
// ---------------------------------------------------------------------------

#[test]
fn missing_file() {
    let p = temp_path("does-not-exist");
    let o = run_elf(&p, &[]);
    assert_eq!(o.status.code(), Some(1));
    let err = stderr(&o);
    assert!(
        err.starts_with(&format!("unforge: {}: ", p.display())),
        "{err}"
    );
    assert!(o.stdout.is_empty());
}

#[test]
fn directory_is_an_io_error() {
    let o = run_elf(Path::new(env!("CARGO_TARGET_TMPDIR")), &[]);
    assert_eq!(o.status.code(), Some(1));
    assert_no_panic(&o, "directory");
}

#[test]
fn non_elf_files() {
    for (tag, bytes) in [
        ("text", &b"hello, world\n"[..]),
        ("empty", b""),
        ("short", b"\x7fEL"),
        ("macho", b"\xcf\xfa\xed\xfe\x07\x00\x00\x01"),
        ("badclass", b"\x7fELF\x09\x01\x01\0\0\0\0\0\0\0\0\0"),
    ] {
        let p = write_temp(tag, bytes);
        let o = run_elf(&p, &[]);
        assert_eq!(o.status.code(), Some(1), "{tag}");
        let err = stderr(&o);
        assert!(
            err.starts_with(&format!("unforge: {}: ", p.display())),
            "{tag}: {err}"
        );
        assert_no_panic(&o, tag);
    }
    let p = write_temp("text2", b"hello, world\n");
    assert!(stderr(&run_elf(&p, &[])).contains("not an ELF file"));
}

// ---------------------------------------------------------------------------
// Hand-built ELF
// ---------------------------------------------------------------------------

#[test]
fn minimal_elf_all_layouts() {
    for l in LAYOUTS {
        let tag = format!(
            "min-{}-{}",
            if l.is64 { 64 } else { 32 },
            if l.be { "be" } else { "le" }
        );
        let b = minimal_elf(l, 0);
        let p = write_temp(&tag, &b.bytes);
        let o = run_elf(&p, &[]);
        assert_eq!(o.status.code(), Some(0), "{tag}: {}", stderr(&o));
        assert!(o.stderr.is_empty(), "{tag}: {}", stderr(&o));
        let out = stdout(&o);
        for needle in [
            "ELF header:",
            if l.is64 { "ELF64" } else { "ELF32" },
            if l.be { "big endian" } else { "little endian" },
            "EXEC (executable)",
            "X86_64 (AMD x86-64) (62)",
            "Program headers (2):",
            "LOAD",
            "R-X",
            "INTERP",
            "[interpreter: /lib/ld-test.so]",
            "Section headers (6):",
            ".text",
            ".shstrtab",
            "PROGBITS",
            "SYMTAB",
            "STRTAB",
            "Symbol table '.symtab' (section [3]) contains 3 entries:",
            " main",
            "bad\\xffname",
            "FUNC",
            "GLOBAL",
            "LOCAL",
            "HIDDEN",
            "ABS",
        ] {
            assert!(out.contains(needle), "{tag}: missing {needle:?} in\n{out}");
        }
        // The hand-built file is also valid for the oracle.
        assert!(compare_with_oracle(&p), "{tag}: oracle rejected the file");
    }
}

#[test]
fn flags_select_parts() {
    let b = minimal_elf(LAYOUTS[0], 0);
    let p = write_temp("flags", &b.bytes);
    let cases: [(&[&str], [bool; 4]); 5] = [
        (&["--header"], [true, false, false, false]),
        (&["--segments"], [false, true, false, false]),
        (&["--sections"], [false, false, true, false]),
        (&["--symbols"], [false, false, false, true]),
        (&["--symbols", "--header"], [true, false, false, true]),
    ];
    for (flags, want) in cases {
        let o = run_elf(&p, flags);
        assert_eq!(o.status.code(), Some(0), "{flags:?}");
        let out = stdout(&o);
        let got = [
            out.contains("ELF header:"),
            out.contains("Program headers ("),
            out.contains("Section headers ("),
            out.contains("Symbol table '"),
        ];
        assert_eq!(got, want, "{flags:?}:\n{out}");
    }
}

#[test]
fn broken_section_table_still_prints_header_and_segments() {
    let mut b = minimal_elf(LAYOUTS[0], 0);
    // e_shoff (ELF64: offset 0x28) far past the end of the file.
    b.bytes[0x28..0x30].copy_from_slice(&0x7fff_0000u64.to_le_bytes());
    let p = write_temp("bad-shoff", &b.bytes);
    let o = run_elf(&p, &[]);
    assert_no_panic(&o, "bad shoff");
    // Changed from the strict reader (exit 1): the kernel never reads the
    // section header table, so the file is tolerated with a warning; only
    // --strict turns the warning into exit status 1.
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(run_elf(&p, &["--strict"]).status.code(), Some(1));
    let out = stdout(&o);
    assert!(out.contains("ELF header:"), "{out}");
    assert!(out.contains("Program headers (2):"), "{out}");
    assert!(out.contains("Section headers: unavailable"), "{out}");
    let err = stderr(&o);
    assert!(
        err.starts_with(&format!("unforge: {}: warning: ", p.display()))
            && err.contains("section header table"),
        "{err}"
    );
    // Reported once, not once per part.
    assert_eq!(err.lines().count(), 1, "{err}");
}

#[test]
fn broken_symbol_table_is_reported_and_others_still_print() {
    let mut b = minimal_elf(LAYOUTS[0], 0);
    // .symtab is section 3; corrupt its sh_entsize (ELF64 Shdr offset 0x38) to 1.
    let ent = b.shoff + 3 * b.shentsize + 0x38;
    b.bytes[ent..ent + 8].copy_from_slice(&1u64.to_le_bytes());
    let p = write_temp("bad-entsize", &b.bytes);
    let o = run_elf(&p, &[]);
    assert_no_panic(&o, "bad entsize");
    // Changed from the strict reader (exit 1, table unavailable): an
    // sh_entsize smaller than Elf64_Sym is replaced by sizeof(Elf64_Sym), the
    // table is listed, and the anomaly and the inference are reported.
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(run_elf(&p, &["--strict"]).status.code(), Some(1));
    assert!(stdout(&o).contains("Section headers (6):"));
    assert!(
        stdout(&o).contains("Symbol table '.symtab' (section [3]) contains 3 entries:"),
        "{}",
        stdout(&o)
    );
    assert!(stderr(&o).contains("symbol table [3]"), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("inferred entry size of symbol table [3]: chose 24 bytes"),
        "{}",
        stderr(&o)
    );
}

// ---------------------------------------------------------------------------
// Robustness: truncated and mutated inputs never panic.
// ---------------------------------------------------------------------------

/// Run `unforge elf` and `unforge disasm` on every input in parallel and
/// check none panicked.
fn run_all_no_panic(inputs: Vec<(String, Vec<u8>)>) {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let chunk = inputs.len().div_ceil(threads).max(1);
    std::thread::scope(|s| {
        for part in inputs.chunks(chunk) {
            s.spawn(move || {
                for (tag, bytes) in part {
                    let p = write_temp("fuzz", bytes);
                    let o = run_elf(&p, &[]);
                    assert_no_panic(&o, tag);
                    let o = run(&["disasm".as_ref(), p.as_os_str()]);
                    assert_no_panic(&o, tag);
                    let _ = std::fs::remove_file(&p);
                }
            });
        }
    });
}

#[test]
fn truncated_inputs_never_panic() {
    let mut inputs = Vec::new();
    for l in LAYOUTS {
        let b = minimal_elf(l, 0);
        for len in 0..b.bytes.len() {
            inputs.push((format!("truncate {len}"), b.bytes[..len].to_vec()));
        }
    }
    run_all_no_panic(inputs);
}

#[test]
fn mutated_inputs_never_panic() {
    let mut inputs = Vec::new();
    for l in [LAYOUTS[0], LAYOUTS[3]] {
        let b = minimal_elf(l, 0);
        for i in 0..b.bytes.len() {
            for v in [0x00u8, 0xff, 0x80, 0x01] {
                if b.bytes[i] == v {
                    continue;
                }
                let mut m = b.bytes.clone();
                m[i] = v;
                inputs.push((format!("byte {i} = {v:#x}"), m));
            }
        }
    }
    // Pseudo-random garbage after a valid identification (xorshift, fixed seed).
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for n in 0..200 {
        let mut m = minimal_elf(LAYOUTS[n % 4], 0).bytes;
        for byte in m.iter_mut().skip(16) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            if x.is_multiple_of(8) {
                *byte = x as u8;
            }
        }
        inputs.push((format!("garbage {n}"), m));
    }
    run_all_no_panic(inputs);
}

// ---------------------------------------------------------------------------
// `unforge disasm`
// ---------------------------------------------------------------------------

fn run_disasm(path: &Path, flags: &[&str]) -> Output {
    let mut v: Vec<&std::ffi::OsStr> = vec!["disasm".as_ref()];
    v.extend(flags.iter().map(std::ffi::OsStr::new));
    v.push(path.as_os_str());
    run(&v)
}

#[test]
fn disasm_minimal_elf() {
    let b = minimal_elf(LAYOUTS[0], 0);
    let p = write_temp("disasm", &b.bytes);
    // The entry point is `main`: `ret` and three `nop`s (its size is 4).
    for flags in [&[][..], &["--function", "mai"], &["--addr", "0x4000b0"]] {
        let o = run_disasm(&p, flags);
        assert_eq!(o.status.code(), Some(0), "{flags:?}: {}", stderr(&o));
        let out = stdout(&o);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 5, "{flags:?}:\n{out}");
        assert_eq!(lines[0], "00000000004000b0 <main> (4 bytes):", "{out}");
        assert!(lines[4].ends_with("  nop"), "{out}");
        assert!(lines[1].starts_with("00000000004000b0:  c3 "), "{out}");
        assert!(lines[1].ends_with("  ret"), "{out}");
    }
    // Inside the segment but not a function: decoded until the first ret.
    let o = run_disasm(&p, &["--addr", "4000b1"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(stdout(&o).contains("<<unknown>> (size unknown):"));
    // Not backed by the file.
    let o = run_disasm(&p, &["--addr", "1234"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        stderr(&o).contains("not backed by file bytes"),
        "{}",
        stderr(&o)
    );
    // No such function.
    let o = run_disasm(&p, &["--function", "nope"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        stderr(&o).contains("no recovered function"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn disasm_refuses_other_cpus() {
    let mut b = minimal_elf(LAYOUTS[0], 0).bytes;
    put_u16(&mut b, 18, 183); // EM_AARCH64
    let p = write_temp("disasm-arm", &b);
    let o = run_disasm(&p, &[]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("only x86 and x86-64"), "{}", stderr(&o));
    assert!(o.stdout.is_empty());
}

/// The `unforge` binary itself: a real Rust executable with symbols.
#[test]
fn disasm_own_binary_names_call_targets() {
    if !cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        eprintln!("skipped: needs an x86-64 Linux host");
        return;
    }
    let o = run_disasm(
        Path::new(BIN),
        &["--function", "unforge::main", "--count", "400"],
    );
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains(" <unforge::main> ("), "{out}");
    assert!(
        out.lines()
            .any(|l| l.contains(" call 0x") && l.contains("  ; -> unforge::")),
        "{out}"
    );
    // --count bounds every function.
    let o = run_disasm(Path::new(BIN), &["--function", "::", "--count", "3"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let out = stdout(&o);
    let headers = out.lines().filter(|l| l.ends_with("):")).count();
    let insns = out.lines().filter(|l| l.contains(":  ")).count();
    assert!(headers > 0 && headers <= 64, "{headers}");
    assert!(insns <= headers * 3, "{insns} > 3 * {headers}");
    assert!(
        stderr(&o).contains("showing the first 64"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn disasm_anomalous_files_never_panic() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/anomalous/files");
    let mut files = Vec::new();
    collect_files(&dir, &mut files);
    assert!(!files.is_empty(), "no files under {}", dir.display());
    for p in &files {
        for flags in [&[][..], &["--function", "a"], &["--addr", "0"]] {
            let o = run_disasm(p, flags);
            assert_no_panic(&o, &p.display().to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// Broken pipe (`unforge elf big | head`)
// ---------------------------------------------------------------------------

#[test]
fn closed_stdout_does_not_panic() {
    let b = minimal_elf(LAYOUTS[0], 20_000);
    let p = write_temp("big", &b.bytes);
    let mut child = Command::new(BIN)
        .arg("elf")
        .arg(&p)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut stdout = child.stdout.take().expect("stdout");
    let mut buf = [0u8; 256];
    stdout.read_exact(&mut buf).expect("read first bytes");
    drop(stdout);
    let o = child.wait_with_output().expect("wait");
    let err = stderr(&o);
    assert!(!err.contains("panicked at"), "{err}");
    assert_eq!(
        o.status.code(),
        Some(0),
        "status {:?}, stderr: {err}",
        o.status
    );
}

// ---------------------------------------------------------------------------
// Real binaries in testdata/bin (produced separately; skipped if absent).
// ---------------------------------------------------------------------------

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        match e.file_type() {
            Ok(t) if t.is_dir() => collect_files(&path, out),
            Ok(t) if t.is_file() => out.push(path),
            _ => {}
        }
    }
}

#[test]
fn testdata_binaries_match_object() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/bin");
    let mut files = Vec::new();
    collect_files(&dir, &mut files);
    files.sort();
    let elf_files: Vec<PathBuf> = files
        .into_iter()
        .filter(|p| std::fs::read(p).is_ok_and(|d| d.starts_with(b"\x7fELF")))
        .collect();
    if elf_files.is_empty() {
        eprintln!("skipping: no ELF files under {}", dir.display());
        return;
    }
    let compared = std::sync::atomic::AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let chunk = elf_files.len().div_ceil(threads).max(1);
    std::thread::scope(|s| {
        for part in elf_files.chunks(chunk) {
            let compared = &compared;
            s.spawn(move || {
                for p in part {
                    if compare_with_oracle(p) {
                        compared.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    eprintln!(
        "compared {} of {} ELF files with object",
        compared.load(Ordering::Relaxed),
        elf_files.len()
    );
}

// ---------------------------------------------------------------------------
// Review round: output and input stay bounded, spec violations are reported.
// All corruptions below use the ELF64 little-endian layout of `minimal_elf`:
// Elf64_Ehdr e_shnum at 0x3c, e_shstrndx at 0x3e; Elf64_Shdr sh_offset at
// 0x18, sh_size at 0x20, sh_link at 0x28 (gABI ch4 Figure 4-3 / 4-8).
// Sections: [3] .symtab, [4] .strtab, [5] .shstrtab.
// ---------------------------------------------------------------------------

fn put_u16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// M section headers that all describe the same symbol table: the table is
/// printed once and each copy gets a one-line note, so the output stays
/// linear in the file size (printing the table M times would be quadratic).
#[test]
fn overlapping_symbol_tables_do_not_amplify_output() {
    let b = minimal_elf(LAYOUTS[0], 200);
    let mut bytes = b.bytes.clone();
    let symtab_hdr = bytes[b.shoff + 3 * b.shentsize..][..b.shentsize].to_vec();
    let copies = 300usize;
    for _ in 0..copies {
        bytes.extend_from_slice(&symtab_hdr);
    }
    put_u16(&mut bytes, 0x3c, u16::try_from(6 + copies).unwrap());
    let p = write_temp("overlap", &bytes);

    let o = run_elf(&p, &["--symbols"]);
    assert_no_panic(&o, "overlap");
    // Changed from the strict reader (exit 1, "Symbol tables: unavailable"):
    // the table is listed once, the copies are noted, and the overlap is a
    // warning.
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(
        run_elf(&p, &["--symbols", "--strict"]).status.code(),
        Some(1)
    );
    let out = stdout(&o);
    assert_eq!(out.matches(" contains 203 entries:").count(), 1, "{out}");
    assert!(
        out.contains(&format!(
            "Symbol table '.symtab' (section [3]): {copies} more sections describe the same bytes and are not listed: [6]-[{}]",
            5 + copies
        )),
        "{out}"
    );
    assert!(
        out.len() < bytes.len(),
        "output {} bytes for a {}-byte file",
        out.len(),
        bytes.len()
    );
    assert!(stderr(&o).contains("overlap"), "{}", stderr(&o));

    // The unmodified file still lists its table.
    let p = write_temp("overlap-ok", &b.bytes);
    let o = run_elf(&p, &["--symbols"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(stdout(&o).contains("contains 203 entries"));
}

/// gABI ch4 "String Table" lets every entry share one long string. Each
/// printed name is capped, so output stays linear in the file size.
#[test]
fn long_shared_names_are_truncated() {
    let b = minimal_elf(LAYOUTS[0], 100);
    let mut bytes = b.bytes.clone();
    let long_off = bytes.len();
    let long_len = 100_000usize;
    bytes.extend(std::iter::repeat_n(b'A', long_len));
    bytes.push(0);
    // Point .strtab [4] and .shstrtab [5] at the long string.
    for sec in [4, 5] {
        let sh = b.shoff + sec * b.shentsize;
        put_u64(&mut bytes, sh + 0x18, long_off as u64);
        put_u64(&mut bytes, sh + 0x20, (long_len + 1) as u64);
    }
    let p = write_temp("longname", &bytes);
    let o = run_elf(&p, &["--sections", "--symbols"]);
    assert_no_panic(&o, "longname");
    let out = stdout(&o);
    let marker = "<truncated after 4096 bytes>";
    // 6 section names + 103 symbol names (st_name 0 included: all point into
    // the run of 'A's, at different offsets).
    let truncated = out.lines().filter(|l| l.contains(marker)).count();
    assert!(truncated >= 6 + 103, "{truncated} truncated lines");
    for l in out.lines() {
        assert!(l.len() < 4096 + 256, "line of {} bytes", l.len());
    }
    assert!(out.len() < 2 * bytes.len() + 4096 * 120, "{}", out.len());
}

/// Non-regular files are refused before reading: `/dev/zero` never reaches
/// end of file, so reading it whole would exhaust memory.
#[cfg(unix)]
#[test]
fn non_regular_files_are_refused() {
    let o = run_elf(Path::new("/dev/zero"), &[]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("not a regular file"), "{}", stderr(&o));
    assert!(o.stdout.is_empty());
}

/// gABI ch4 Figure 4-14: a symbol table's sh_link names its string table.
///
/// Changed from the strict reader (exit 1, table unavailable): with sh_link =
/// 0 (the SHT_NULL entry) the symbols are listed with `<bad name>`; with a
/// non-STRTAB section the names are read from that section and the choice is
/// reported as an inference with the real string table as the alternative.
#[test]
fn symtab_link_to_null_or_non_strtab_is_a_warning() {
    for link in [0u32, 1] {
        let mut b = minimal_elf(LAYOUTS[0], 0);
        put_u32(&mut b.bytes, b.shoff + 3 * b.shentsize + 0x28, link);
        let p = write_temp("symtab-link", &b.bytes);
        let o = run_elf(&p, &["--symbols"]);
        assert_no_panic(&o, "symtab link");
        assert_eq!(o.status.code(), Some(0), "link {link}");
        assert_eq!(
            run_elf(&p, &["--symbols", "--strict"]).status.code(),
            Some(1),
            "link {link}"
        );
        let out = stdout(&o);
        assert!(
            out.contains("Symbol table '.symtab' (section [3]) contains 3 entries:"),
            "link {link}: {out}"
        );
        let err = stderr(&o);
        assert!(err.contains("warning: symbol table [3]"), "{err}");
        if link == 0 {
            assert!(out.contains("<bad name 0x1>"), "{out}");
            assert!(err.contains("symbol names unavailable"), "{err}");
        } else {
            assert!(
                err.contains("inferred string table of symbol table [3]: chose section [1]"),
                "{err}"
            );
            assert!(err.contains("section [4]"), "{err}");
        }
    }
}

/// gABI ch4 "Sections", SHT_SYMTAB_SHNDX is required whenever a symbol uses
/// SHN_XINDEX. Without it the symbol is shown as `XINDEX?` and the exit
/// status is 1.
#[test]
fn unresolved_xindex_is_reported() {
    let mut b = minimal_elf(LAYOUTS[0], 0);
    // Symbol 2 (`main`): Elf64_Sym st_shndx at +6.
    put_u16(&mut b.bytes, b.symtab_off + 2 * 24 + 6, 0xffff);
    let p = write_temp("xindex", &b.bytes);
    let o = run_elf(&p, &["--symbols"]);
    assert_no_panic(&o, "xindex");
    // Changed from the strict reader (exit 1): a warning, exit 1 only with
    // --strict.
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(
        run_elf(&p, &["--symbols", "--strict"]).status.code(),
        Some(1)
    );
    let main = stdout(&o)
        .lines()
        .find(|l| l.ends_with(" main"))
        .map(str::to_owned)
        .unwrap();
    assert!(main.contains("XINDEX?"), "{main}");
    assert!(
        stderr(&o).contains("1 symbols use SHN_XINDEX"),
        "{}",
        stderr(&o)
    );
}

/// gABI ch4 "ELF Header", e_shstrndx: values >= SHN_LORESERVE are stored as
/// SHN_XINDEX, so 0xff05 is reported. Changed from the strict reader (exit 1):
/// the sections are listed without names, and the status is 1 only with
/// --strict.
#[test]
fn reserved_shstrndx_is_reported() {
    let mut b = minimal_elf(LAYOUTS[0], 0);
    put_u16(&mut b.bytes, 0x3e, 0xff05);
    let p = write_temp("shstrndx", &b.bytes);
    let o = run_elf(&p, &["--sections"]);
    assert_no_panic(&o, "shstrndx");
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(
        run_elf(&p, &["--sections", "--strict"]).status.code(),
        Some(1)
    );
    assert!(stdout(&o).contains("Section headers (6):"));
    assert!(stderr(&o).contains("e_shstrndx"), "{}", stderr(&o));
}

/// Header deviations (gABI ch4 "ELF Identification" / "ELF Header") are
/// warnings: printed on stderr, exit status unchanged.
#[test]
fn header_deviations_are_warnings() {
    let mut b = minimal_elf(LAYOUTS[0], 0);
    b.bytes[6] = 2; // EI_VERSION
    put_u16(&mut b.bytes, 0x34, 65); // e_ehsize
    let p = write_temp("deviation", &b.bytes);
    let o = run_elf(&p, &[]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let err = stderr(&o);
    assert!(err.contains("warning: e_ident[EI_VERSION] is 2"), "{err}");
    assert!(
        err.contains("warning: e_ehsize is 65, expected 64"),
        "{err}"
    );

    // A conforming file produces no warnings.
    let b = minimal_elf(LAYOUTS[0], 0);
    let p = write_temp("deviation-ok", &b.bytes);
    assert!(stderr(&run_elf(&p, &[])).is_empty());
}

/// The kernel ignores EI_CLASS (LOADER_RULES.md §1): a garbage value is read
/// through, the layout is inferred from e_machine and the header sizes, and
/// the inference is reported with its clues.
#[test]
fn garbage_ei_class_is_read_with_an_inference() {
    let mut b = minimal_elf(LAYOUTS[0], 0);
    b.bytes[4] = 0x55;
    let p = write_temp("ei-class", &b.bytes);
    let o = run_elf(&p, &[]);
    assert_no_panic(&o, "ei-class");
    assert_eq!(o.status.code(), Some(0));
    let out = stdout(&o);
    assert!(out.contains("ELF64 (inferred; EI_CLASS = 0x55)"), "{out}");
    assert!(
        out.contains("Symbol table '.symtab' (section [3]) contains 3 entries:"),
        "{out}"
    );
    let err = stderr(&o);
    assert!(err.contains("warning: EI_CLASS is 0x55"), "{err}");
    assert!(
        err.contains("inferred layout: chose Elf64 Little-endian"),
        "{err}"
    );
    assert!(err.contains("EI_CLASS = 0x55 is invalid"), "{err}");
    assert_eq!(run_elf(&p, &["--strict"]).status.code(), Some(1));
}

/// Loader expectations depend on the platform, so they are opt-in.
#[test]
fn loader_checks_are_opt_in() {
    let b = minimal_elf(LAYOUTS[0], 0);
    let p = write_temp("loader", &b.bytes);
    // minimal_elf has PT_INTERP but no PT_DYNAMIC.
    let o = run_elf(&p, &[]);
    assert!(o.stderr.is_empty(), "{}", stderr(&o));
    let o = run_elf(&p, &["--loader-checks"]);
    assert_eq!(o.status.code(), Some(0));
    let err = stderr(&o);
    assert!(
        err.contains("would not load: PT_INTERP without PT_DYNAMIC"),
        "{err}"
    );
    // A wrong e_phentsize is refused by the kernel (load_elf_phdrs).
    let mut b = minimal_elf(LAYOUTS[0], 0);
    put_u16(&mut b.bytes, 0x36, 64);
    let p = write_temp("loader-phentsize", &b.bytes);
    let o = run_elf(&p, &["--loader-checks", "--segments"]);
    let err = stderr(&o);
    assert!(
        err.contains("kernel: execve fails: PhentsizeMismatch"),
        "{err}"
    );
    assert_eq!(
        run_elf(&p, &["--loader-checks", "--strict"]).status.code(),
        Some(1)
    );
}

/// Symbol tables that overlap without being identical cannot be deduplicated;
/// the listing stops at a bound linear in the file size and says so.
#[test]
fn shifted_overlapping_symbol_tables_are_bounded() {
    let b = minimal_elf(LAYOUTS[0], 200);
    let mut bytes = b.bytes.clone();
    let symtab_hdr = bytes[b.shoff + 3 * b.shentsize..][..b.shentsize].to_vec();
    let copies = 300usize;
    for k in 0..copies {
        // Each copy starts one symbol later and has one symbol less.
        let mut h = symtab_hdr.clone();
        let off = u64::from_le_bytes(h[0x18..0x20].try_into().unwrap()) + 24 * (k as u64 % 100);
        let size = u64::from_le_bytes(h[0x20..0x28].try_into().unwrap()) - 24 * (k as u64 % 100);
        h[0x18..0x20].copy_from_slice(&off.to_le_bytes());
        h[0x20..0x28].copy_from_slice(&size.to_le_bytes());
        // Same bytes only when k % 100 repeats: also exercises the dedup.
        bytes.extend_from_slice(&h);
    }
    put_u16(&mut bytes, 0x3c, u16::try_from(6 + copies).unwrap());
    let p = write_temp("shifted", &bytes);
    let o = run_elf(&p, &["--symbols"]);
    assert_no_panic(&o, "shifted");
    assert_eq!(o.status.code(), Some(0));
    let out = stdout(&o);
    let listed: usize = printed_symtabs(&out).iter().map(|t| t.1.len()).sum();
    let budget = 2 * bytes.len() / 24 + 1024;
    assert!(listed <= budget, "{listed} symbols listed, budget {budget}");
    assert!(
        out.contains("entries not listed (output bound reached"),
        "{out}"
    );
    assert!(
        stderr(&o).contains("symbol tables not listed"),
        "{}",
        stderr(&o)
    );
}

/// Review finding safety-cli-name-output-amplification: 16000 sections that
/// all name one 4 KiB string of control bytes used to print ~320x the input.
/// The escaped name text is now capped at four times the input plus 1 MiB.
#[test]
fn shared_long_names_do_not_amplify_output() {
    let n = 16_000usize;
    let mut name = vec![1u8; 4096];
    name.push(0);
    let strtab_off = (64 + 64 * n) as u64;
    let mut d = vec![0u8; 64];
    d[..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    put_u16(&mut d, 0x10, 1);
    put_u16(&mut d, 0x12, 62);
    put_u32(&mut d, 0x14, 1);
    put_u64(&mut d, 0x28, 64);
    put_u16(&mut d, 0x34, 64);
    put_u16(&mut d, 0x3a, 64);
    put_u16(&mut d, 0x3c, n as u16);
    put_u16(&mut d, 0x3e, 1);
    for i in 0..n {
        let mut s = [0u8; 64];
        let ty: u32 = match i {
            0 => 0,
            1 => 3,
            _ => 1,
        };
        s[4..8].copy_from_slice(&ty.to_le_bytes());
        if i == 1 {
            s[24..32].copy_from_slice(&strtab_off.to_le_bytes());
            s[32..40].copy_from_slice(&(name.len() as u64).to_le_bytes());
        }
        d.extend_from_slice(&s);
    }
    d.extend_from_slice(&name);
    let p = write_temp("shared-names", &d);
    let o = run_elf(&p, &["--sections"]);
    assert_no_panic(&o, "shared names");
    assert_eq!(o.status.code(), Some(0));
    let limit = 4 * d.len() + (1 << 20) + 200 * n;
    assert!(
        o.stdout.len() < limit,
        "{} bytes of output for {} bytes",
        o.stdout.len(),
        d.len()
    );
    assert!(stdout(&o).contains("<name elided>"));
    assert!(stderr(&o).contains("names elided"));
    let _ = std::fs::remove_file(p);
}

/// Review finding tolerance-dynsym-not-crosschecked: a file without section
/// headers still lists the dynamic symbols ld.so finds through PT_DYNAMIC.
#[test]
fn sstripped_file_lists_dynamic_symbols() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/anomalous/files/x86_64/d02-sstrip.elf");
    let o = run_elf(&p, &["--symbols"]);
    assert_eq!(o.status.code(), Some(0));
    let out = stdout(&o);
    assert!(
        out.contains("Dynamic symbol table (PT_DYNAMIC DT_SYMTAB"),
        "{out}"
    );
    assert!(!out.contains("There are no symbol tables."));
}

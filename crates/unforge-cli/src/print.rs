//! `unforge elf`: readelf-like tables for one ELF file.
//!
//! Policy: the reader is tolerant, and so is the listing. Every table that
//! can be read is printed; a table that cannot be read at all is shown as
//! "unavailable" and the reason is one of the diagnostics printed on stderr
//! (`main.rs`). A single unreadable *name* is shown inline as
//! `<bad name 0x..>`.
//!
//! Output stays linear in the input size, with a small constant:
//! - names are cut at [`MAX_NAME_LEN`] bytes;
//! - the escaped name text printed in total is capped at [`name_budget`]
//!   bytes; later names are shown as `<name elided>` and one warning says
//!   so (without it, every entry could name the same 4 KiB string and the
//!   output would be about 24 KiB per 24-byte symbol);
//! - symbol tables that cover exactly the same bytes (same offset, size,
//!   entry size and string table) are listed once, followed by one line
//!   naming the other sections (index runs compressed, at most
//!   [`MAX_RUNS`] runs);
//! - the symbols listed in total are capped at a small multiple of the
//!   number of symbols the file could hold ([`symbol_budget`]); tables past
//!   the cap get a one-line note and a warning.
//!
//! Every write to stdout goes through `io::Result`, so a closed pipe surfaces
//! as an error the caller can handle, instead of a panic from `println!`.

use std::collections::HashMap;
use std::fmt::Display;
use std::io::{self, Write};
use std::path::Path;

use unforge_elf::{BoundedName, Class, ElfFile, SectionHeader};

use crate::args::Show;
use crate::names;

/// Longest name (in bytes, before escaping) printed in full. Longer names are
/// cut and marked. gABI ch4 "String Table" lets any number of entries share one
/// string of any length, so without a cap the output could grow as
/// entries * string length from a file of size entries + string length.
/// (GNU readelf also truncates names unless `-W` is given.)
pub const MAX_NAME_LEN: usize = 4096;

/// How many symbol lines may be printed for a file of `len` bytes whose
/// symbols are `sym_size` bytes: twice as many as the file could hold, plus
/// a constant. Well-formed files never come close (their tables do not
/// overlap, gABI ch4 "Sections").
pub fn symbol_budget(len: usize, sym_size: usize) -> u64 {
    (len / sym_size.max(1)) as u64 * 2 + 1024
}

/// How many bytes of escaped name text may be printed for a file of `len`
/// bytes: four times the file plus 1 MiB. Well-formed files stay far below
/// (their names are distinct strings stored in the file).
pub fn name_budget(len: usize) -> u64 {
    (len as u64).saturating_mul(4).saturating_add(1 << 20)
}

/// At most this many index runs are printed for the copies of one symbol table.
pub const MAX_RUNS: usize = 16;

/// `[3]-[7], [9], [12]-[300]`, at most `MAX_RUNS` runs, then `and N more`.
fn runs(indices: &[usize]) -> String {
    let mut out = String::new();
    let mut shown = 0usize;
    let mut i = 0usize;
    while let Some(&start) = indices.get(i) {
        let mut end = start;
        let mut j = i + 1;
        while indices.get(j) == Some(&(end + 1)) {
            end += 1;
            j += 1;
        }
        if shown == MAX_RUNS {
            out.push_str(&format!(", and {} more", indices.len() - i));
            break;
        }
        if shown > 0 {
            out.push_str(", ");
        }
        if start == end {
            out.push_str(&format!("[{start}]"));
        } else {
            out.push_str(&format!("[{start}]-[{end}]"));
        }
        shown += 1;
        i = j;
    }
    out
}

/// A name for display: escaped, with a marker if it was cut at `MAX_NAME_LEN`.
/// The marker starts with a space, which `names::escape` never emits, so it
/// cannot be confused with part of a name.
fn show_name(n: BoundedName<'_>) -> String {
    let mut s = names::escape(n.bytes);
    if n.truncated {
        s.push_str(" <truncated after ");
        s.push_str(&MAX_NAME_LEN.to_string());
        s.push_str(" bytes>");
    }
    s
}

/// Output sink plus the warning reporter for one file.
pub struct Printer<'a, W: Write> {
    out: W,
    path: &'a Path,
    warned: bool,
    /// Escaped name bytes that may still be printed (see [`name_budget`]).
    names_left: u64,
    /// Names replaced by `<name elided>`.
    names_elided: u64,
}

impl<'a, W: Write> Printer<'a, W> {
    pub fn new(out: W, path: &'a Path) -> Self {
        Printer {
            out,
            path,
            warned: false,
            names_left: u64::MAX,
            names_elided: 0,
        }
    }

    /// Charge a name against the budget; past it, the name is elided.
    fn name(&mut self, shown: String) -> String {
        let n = shown.len() as u64;
        if n <= self.names_left {
            self.names_left -= n;
            shown
        } else {
            self.names_left = 0;
            self.names_elided += 1;
            "<name elided>".into()
        }
    }

    /// Whether the listing itself reported a warning (on top of the file's
    /// diagnostics).
    pub fn warned(&self) -> bool {
        self.warned
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    /// Report a warning of the listing on stderr as
    /// `unforge: <path>: warning: ..`. Stdout is flushed first so that the
    /// message appears after the output that precedes it on a terminal.
    fn warn(&mut self, w: impl Display) -> io::Result<()> {
        self.warned = true;
        self.out.flush()?;
        // If stderr itself is gone there is nobody left to tell.
        let _ = writeln!(
            io::stderr(),
            "unforge: {}: warning: {w}",
            self.path.display()
        );
        Ok(())
    }

    pub fn print(&mut self, elf: &ElfFile<'_>, show: Show) -> io::Result<()> {
        self.names_left = name_budget(elf.data().len());
        self.names_elided = 0;
        let mut first = true;
        let mut gap = |p: &mut Self| -> io::Result<()> {
            if !first {
                writeln!(p.out)?;
            }
            first = false;
            Ok(())
        };
        if show.header {
            gap(self)?;
            self.header(elf)?;
        }
        if show.segments {
            gap(self)?;
            self.segments(elf)?;
        }
        if show.sections {
            gap(self)?;
            self.sections(elf)?;
        }
        if show.symbols {
            gap(self)?;
            self.symbols(elf)?;
        }
        if self.names_elided > 0 {
            let n = self.names_elided;
            self.warn(format_args!(
                "{n} names elided: the names printed already exceed {} bytes (four times the file size plus 1 MiB), so entries share long strings",
                name_budget(elf.data().len())
            ))?;
        }
        Ok(())
    }

    fn header(&mut self, elf: &ElfFile<'_>) -> io::Result<()> {
        let h = elf.header();
        let inferred = elf.layout().is_inferred();
        let o = &mut self.out;
        writeln!(o, "ELF header:")?;
        write!(o, "  Magic:                    ")?;
        for b in elf.data().iter().take(16) {
            write!(o, " {b:02x}")?;
        }
        writeln!(o)?;
        write!(o, "  Class:                     {}", names::class(h.class))?;
        if inferred {
            write!(o, " (inferred; EI_CLASS = {:#x})", h.ident_class)?;
        }
        writeln!(o)?;
        write!(
            o,
            "  Data:                      {}",
            names::endian(h.endian)
        )?;
        if inferred {
            write!(o, " (inferred; EI_DATA = {:#x})", h.ident_data)?;
        }
        writeln!(o)?;
        writeln!(o, "  Ident version:             {}", h.ident_version)?;
        writeln!(
            o,
            "  OS/ABI:                    {}",
            names::os_abi(h.os_abi)
        )?;
        writeln!(o, "  ABI version:               {}", h.abi_version)?;
        writeln!(
            o,
            "  Type:                      {}",
            names::e_type(h.e_type)
        )?;
        writeln!(
            o,
            "  Machine:                   {}",
            names::machine(h.machine)
        )?;
        writeln!(o, "  Version:                   {:#x}", h.version)?;
        writeln!(o, "  Entry point:               {:#x}", h.entry)?;
        writeln!(o, "  Program header offset:     {:#x}", h.phoff)?;
        writeln!(o, "  Section header offset:     {:#x}", h.shoff)?;
        writeln!(o, "  Flags:                     {:#x}", h.flags)?;
        writeln!(o, "  ELF header size:           {}", h.ehsize)?;
        writeln!(o, "  Program header entry size: {}", h.phentsize)?;
        write!(o, "  Program header count:      {}", h.phnum)?;
        if u64::from(h.raw_phnum) != h.phnum {
            write!(
                o,
                " (e_phnum = {:#x}, real count from section 0)",
                h.raw_phnum
            )?;
        }
        writeln!(o)?;
        writeln!(o, "  Section header entry size: {}", h.shentsize)?;
        write!(o, "  Section header count:      {}", h.shnum)?;
        if u64::from(h.raw_shnum) != h.shnum {
            write!(o, " (e_shnum = {}", h.raw_shnum)?;
            if h.shoff == 0 {
                write!(o, ", ignored because e_shoff = 0)")?;
            } else {
                write!(o, ", real count from section 0)")?;
            }
        }
        writeln!(o)?;
        match h.shstrndx {
            Some(i) => write!(o, "  Section name table index:  {i}")?,
            None => write!(o, "  Section name table index:  none")?,
        }
        if h.shstrndx.map(u64::from) != Some(u64::from(h.raw_shstrndx)) && h.raw_shstrndx != 0 {
            write!(o, " (e_shstrndx = {:#x})", h.raw_shstrndx)?;
        }
        writeln!(o)?;
        Ok(())
    }

    /// Hex digits for an address of this class.
    fn addr_width(elf: &ElfFile<'_>) -> usize {
        match elf.header().class {
            Class::Elf32 => 8,
            _ => 16,
        }
    }

    fn segments(&mut self, elf: &ElfFile<'_>) -> io::Result<()> {
        let Ok(phdrs) = elf.program_headers() else {
            return writeln!(self.out, "Program headers: unavailable");
        };
        if phdrs.is_empty() {
            writeln!(self.out, "There are no program headers.")?;
            return Ok(());
        }
        let w = Self::addr_width(elf);
        let o = &mut self.out;
        writeln!(o, "Program headers ({}):", phdrs.len())?;
        writeln!(
            o,
            "  {:<14} {:<w2$} {:<w2$} {:<w2$} {:<w2$} {:<w2$} {:<5} Align",
            "Type",
            "Offset",
            "VirtAddr",
            "PhysAddr",
            "FileSiz",
            "MemSiz",
            "Flags",
            w2 = w.saturating_add(2),
        )?;
        for p in phdrs {
            writeln!(
                o,
                "  {:<14} {:#0w2$x} {:#0w2$x} {:#0w2$x} {:#0w2$x} {:#0w2$x} {:<5} {:#x}",
                names::p_type(p.p_type),
                p.offset,
                p.vaddr,
                p.paddr,
                p.filesz,
                p.memsz,
                names::p_flags(p.flags),
                p.align,
                w2 = w.saturating_add(2),
            )?;
            if p.p_type == unforge_elf::consts::PT_INTERP {
                let b = elf.segment_bytes(&p);
                // The interpreter path is NUL-terminated (gABI ch5 "Program
                // Interpreter" / PT_INTERP); show it without the NUL.
                let path = b.bytes.split(|&c| c == 0).next().unwrap_or(b.bytes);
                write!(o, "      [interpreter: {}", names::escape(path))?;
                if b.missing > 0 {
                    write!(o, " <{} bytes past the end of the file>", b.missing)?;
                }
                writeln!(o, "]")?;
            }
        }
        Ok(())
    }

    fn sections(&mut self, elf: &ElfFile<'_>) -> io::Result<()> {
        let Ok(shdrs) = elf.section_headers() else {
            return writeln!(self.out, "Section headers: unavailable");
        };
        if shdrs.is_empty() {
            writeln!(self.out, "There are no section headers.")?;
            return Ok(());
        }
        let names = SectionNames::of(elf);
        let h = elf.header();
        let w = Self::addr_width(elf);
        writeln!(self.out, "Section headers ({}):", shdrs.len())?;
        writeln!(
            self.out,
            "  {:<6} {:<14} {:<w2$} {:<10} {:<10} {:<6} {:<5} {:>4} {:>4} {:>5} Name",
            "[Nr]",
            "Type",
            "Address",
            "Offset",
            "Size",
            "EntSz",
            "Flags",
            "Link",
            "Info",
            "Align",
            w2 = w.saturating_add(2),
        )?;
        for (i, sh) in shdrs.iter().enumerate() {
            let name = self.name(names.display(elf, &sh));
            writeln!(
                self.out,
                "  {:<6} {:<14} {:#0w2$x} {:#010x} {:#010x} {:<#6x} {:<5} {:>4} {:>4} {:>5} {}",
                format!("[{i}]"),
                names::sh_type(sh.sh_type, h.machine, h.os_abi),
                sh.addr,
                sh.offset,
                sh.size,
                sh.entsize,
                names::sh_flags(sh.flags, h.machine, h.os_abi),
                sh.link,
                sh.info,
                sh.addralign,
                name,
                w2 = w.saturating_add(2),
            )?;
        }
        writeln!(self.out, "{}", names::sh_flags_key())?;
        Ok(())
    }

    fn symbols(&mut self, elf: &ElfFile<'_>) -> io::Result<()> {
        let h = elf.header();
        let sym_size = match h.class {
            Class::Elf32 => 16,
            _ => 24,
        };
        let mut budget = symbol_budget(elf.data().len(), sym_size);
        let mut any = false;
        let mut dynsym_addrs: Vec<u64> = Vec::new();
        match elf.symbol_tables() {
            Err(_) => {
                writeln!(self.out, "Symbol tables: unavailable (no section headers)")?;
                any = true;
            }
            Ok(tables) => {
                let names = SectionNames::of(elf);
                // Copies: (sh_offset, sh_size, entry size, sh_link) -> the
                // first section with that key, and the later ones.
                // O(number of tables).
                let key = |t: &unforge_elf::SymbolTable<'_>| {
                    let sh = t.section_header();
                    (sh.offset, sh.size, t.entry_size(), sh.link)
                };
                let mut first_of: HashMap<(u64, u64, usize, u32), usize> = HashMap::new();
                let mut copies: HashMap<usize, Vec<usize>> = HashMap::new();
                for t in tables.clone() {
                    match first_of.get(&key(&t)) {
                        Some(&first) => copies.entry(first).or_default().push(t.section_index),
                        None => {
                            first_of.insert(key(&t), t.section_index);
                        }
                    }
                }
                let mut over_budget = 0u64;
                for table in tables {
                    let i = table.section_index;
                    let sh = *table.section_header();
                    if sh.sh_type == unforge_elf::consts::SHT_DYNSYM && dynsym_addrs.len() < 64 {
                        dynsym_addrs.push(sh.addr);
                    }
                    if first_of.get(&key(&table)) != Some(&i) {
                        continue; // a copy, named after its first table
                    }
                    if any {
                        writeln!(self.out)?;
                    }
                    any = true;
                    let title = self.name(names.display(elf, &sh));
                    if let Some(c) = copies.get(&i) {
                        writeln!(
                            self.out,
                            "Symbol table '{title}' (section [{i}]): {} more sections describe the same bytes and are not listed: {}",
                            c.len(),
                            runs(c)
                        )?;
                    }
                    let n = table.len() as u64;
                    if n > budget {
                        writeln!(
                            self.out,
                            "Symbol table '{title}' (section [{i}]): {n} entries not listed (output bound reached; tables overlap)"
                        )?;
                        over_budget += 1;
                        continue;
                    }
                    budget -= n;
                    writeln!(
                        self.out,
                        "Symbol table '{title}' (section [{i}]) contains {n} entries:"
                    )?;
                    self.symbol_rows(elf, table.iter(), |s| table.name_bounded(s, MAX_NAME_LEN))?;
                }
                if over_budget > 0 {
                    self.warn(format_args!(
                        "{over_budget} symbol tables not listed: the symbols listed already exceed twice what the file can hold, so the tables overlap"
                    ))?;
                }
            }
        }
        // The dynamic symbol table ld.so uses, when no SHT_DYNSYM section
        // describes it (stripped section headers, or a decoy SHT_DYNSYM).
        if let Ok(ds) = elf.dynamic_symbols()
            && !dynsym_addrs.contains(&ds.symtab_vaddr)
        {
            if any {
                writeln!(self.out)?;
            }
            any = true;
            let n = ds.len() as u64;
            let source = match ds.count {
                unforge_elf::DynamicSymbolCount::Hash { .. } => "count from DT_HASH",
                unforge_elf::DynamicSymbolCount::GnuHash { .. } => "count from DT_GNU_HASH",
                _ => "no hash table: count unknown",
            };
            if n > budget {
                writeln!(
                    self.out,
                    "Dynamic symbol table (PT_DYNAMIC DT_SYMTAB {:#x}): {n} entries not listed (output bound reached)",
                    ds.symtab_vaddr
                )?;
            } else {
                writeln!(
                    self.out,
                    "Dynamic symbol table (PT_DYNAMIC DT_SYMTAB {:#x}, {source}) contains {n} entries:",
                    ds.symtab_vaddr
                )?;
                self.symbol_rows(elf, ds.iter(), |s| ds.name_bounded(s, MAX_NAME_LEN))?;
            }
        }
        if !any {
            writeln!(self.out, "There are no symbol tables.")?;
        }
        Ok(())
    }

    fn symbol_rows<'d>(
        &mut self,
        elf: &ElfFile<'_>,
        symbols: impl Iterator<Item = unforge_elf::Symbol>,
        name: impl Fn(&unforge_elf::Symbol) -> unforge_elf::Result<BoundedName<'d>>,
    ) -> io::Result<()> {
        let h = elf.header();
        let w = Self::addr_width(elf);
        writeln!(
            self.out,
            "  {:>6} {:<w2$} {:>8} {:<8} {:<7} {:<9} {:>5} Name",
            "Num:",
            "Value",
            "Size",
            "Type",
            "Bind",
            "Vis",
            "Ndx",
            w2 = w.saturating_add(2),
        )?;
        for (n, sym) in symbols.enumerate() {
            let shown = match name(&sym) {
                Ok(n) => show_name(n),
                Err(_) => format!("<bad name {:#x}>", sym.name),
            };
            let shown = self.name(shown);
            writeln!(
                self.out,
                "  {:>6} {:#0w2$x} {:>8} {:<8} {:<7} {:<9} {:>5} {}",
                format!("{n}:"),
                sym.value,
                sym.size,
                names::sym_type(sym.kind(), h.os_abi),
                names::sym_bind(sym.bind(), h.os_abi),
                names::sym_visibility(sym.visibility()),
                names::sym_section(sym.section),
                shown,
                w2 = w.saturating_add(2),
            )?;
        }
        Ok(())
    }
}

/// How section names are shown, decided once per listing.
#[derive(Clone, Copy)]
enum SectionNames {
    /// `e_shstrndx` is `SHN_UNDEF`: sections have no names.
    NoTable,
    /// The name table could not be read (a diagnostic says why).
    Broken,
    Ok,
}

impl SectionNames {
    fn of(elf: &ElfFile<'_>) -> Self {
        if elf.header().raw_shstrndx == unforge_elf::consts::SHN_UNDEF {
            SectionNames::NoTable
        } else if elf.section_name_table().is_ok() {
            SectionNames::Ok
        } else {
            SectionNames::Broken
        }
    }

    fn display(self, elf: &ElfFile<'_>, sh: &SectionHeader) -> String {
        match self {
            SectionNames::NoTable => String::new(),
            SectionNames::Broken => "<?>".into(),
            SectionNames::Ok => match elf.section_name_bounded(sh, MAX_NAME_LEN) {
                Ok(n) => show_name(n),
                Err(_) => format!("<bad name {:#x}>", sh.name),
            },
        }
    }
}

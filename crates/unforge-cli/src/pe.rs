//! `unforge pe`: the structure of one PE image (headers, sections,
//! imports, exports, the x64 exception table, TLS, debug), as tables.
//!
//! Like `unforge elf`, everything readable is printed and the reader's
//! diagnostics go to stderr (`main.rs`). Names are escaped
//! ([`names::escape`]) and cut by the reader at
//! [`unforge_pe::MAX_NAME_LEN`] bytes; every list the reader returns is
//! already capped, so the output stays linear in the input.

use std::io::{self, Write};

use unforge_pe::{ImportKind, PeFile, PeKind, dir};

use crate::args::PeShow;
use crate::names;

/// At most this many `.pdata` entries are listed (all are counted).
pub const MAX_PDATA_ROWS: usize = 1 << 16;

fn machine(m: u16) -> String {
    match m {
        unforge_pe::MACHINE_AMD64 => "x86-64 (0x8664)".to_owned(),
        unforge_pe::MACHINE_I386 => "x86 (0x14c)".to_owned(),
        unforge_pe::MACHINE_ARM64 => "AArch64 (0xaa64)".to_owned(),
        unforge_pe::MACHINE_ARMNT => "ARM (0x1c4)".to_owned(),
        _ => format!("{m:#x}"),
    }
}

fn section_flags(c: u32) -> String {
    [
        (unforge_pe::SCN_MEM_READ, 'R'),
        (unforge_pe::SCN_MEM_WRITE, 'W'),
        (unforge_pe::SCN_MEM_EXECUTE, 'X'),
        (unforge_pe::SCN_CNT_CODE, 'C'),
        (unforge_pe::SCN_CNT_INITIALIZED_DATA, 'I'),
        (unforge_pe::SCN_CNT_UNINITIALIZED_DATA, 'U'),
        (unforge_pe::SCN_MEM_DISCARDABLE, 'D'),
    ]
    .iter()
    .map(|&(b, ch)| if c & b != 0 { ch } else { '-' })
    .collect()
}

/// Prints the parts of `pe` selected by `show`.
pub fn print<W: Write>(out: &mut W, pe: &PeFile<'_>, show: PeShow) -> io::Result<()> {
    let base = pe.image_base();
    let mut first = true;
    let mut gap = |out: &mut W| -> io::Result<()> {
        if !first {
            writeln!(out)?;
        }
        first = false;
        Ok(())
    };
    if show.header {
        gap(out)?;
        let c = pe.coff();
        writeln!(out, "PE header:")?;
        writeln!(out, "  Machine:              {}", machine(c.machine))?;
        writeln!(
            out,
            "  Kind:                 {}",
            if pe.is_dll() { "DLL" } else { "executable" }
        )?;
        writeln!(out, "  Characteristics:      {:#06x}", c.characteristics)?;
        writeln!(out, "  TimeDateStamp:        {:#010x}", c.time_date_stamp)?;
        writeln!(out, "  Sections:             {}", c.number_of_sections)?;
        if c.pointer_to_symbol_table != 0 {
            writeln!(
                out,
                "  COFF symbols:         {} at {:#x}",
                c.number_of_symbols, c.pointer_to_symbol_table
            )?;
        }
        match pe.optional() {
            None => writeln!(out, "  Optional header:      none")?,
            Some(o) => {
                writeln!(
                    out,
                    "  Format:               {} (magic {:#x})",
                    match o.kind {
                        PeKind::Pe32 => "PE32",
                        _ => "PE32+",
                    },
                    o.magic
                )?;
                writeln!(out, "  ImageBase:            {:#x}", o.image_base)?;
                writeln!(
                    out,
                    "  Entry point:          {}",
                    match pe.entry_rva() {
                        Some(e) => format!("{:#x} (RVA {e:#x})", base.wrapping_add(u64::from(e))),
                        None => "none".to_owned(),
                    }
                )?;
                writeln!(
                    out,
                    "  Alignment:            section {:#x}, file {:#x}",
                    o.section_alignment, o.file_alignment
                )?;
                writeln!(
                    out,
                    "  SizeOfImage:          {:#x}, SizeOfHeaders {:#x}",
                    o.size_of_image, o.size_of_headers
                )?;
                writeln!(
                    out,
                    "  Subsystem:            {}, DllCharacteristics {:#06x}",
                    o.subsystem, o.dll_characteristics
                )?;
                writeln!(
                    out,
                    "  Linker:               {}.{}",
                    o.major_linker_version, o.minor_linker_version
                )?;
                writeln!(out, "  Data directories:")?;
                for (i, d) in o.data_directories.iter().enumerate() {
                    if d.rva == 0 && d.size == 0 {
                        continue;
                    }
                    let name = dir::NAMES.get(i).copied().unwrap_or("?");
                    writeln!(
                        out,
                        "    {name:<13} {} {:#x} size {:#x}",
                        if i == dir::SECURITY { "offset" } else { "RVA" },
                        d.rva,
                        d.size
                    )?;
                }
            }
        }
        if let Some(cv) = pe.codeview() {
            writeln!(
                out,
                "  PDB:                  {} (age {})",
                names::escape(cv.path),
                cv.age
            )?;
        }
        if let Some((at, len)) = pe.overlay() {
            writeln!(out, "  Overlay:              {len:#x} bytes at {at:#x}")?;
        }
    }
    if show.sections {
        gap(out)?;
        writeln!(out, "Sections ({}):", pe.sections().len())?;
        writeln!(
            out,
            "  {:>3}  {:<8}  {:>16}  {:>10}  {:>10}  {:>10}  {:>10}  Flags",
            "Nr", "Name", "Address", "VirtSize", "RawOffset", "RawSize", "Mapped"
        )?;
        for s in pe.sections() {
            let mapped = pe
                .regions()
                .iter()
                .find(|r| r.section == Some(s.index))
                .map_or(0, |r| r.file_len);
            writeln!(
                out,
                "  {:>3}  {:<8}  {:>16x}  {:>10x}  {:>10x}  {:>10x}  {:>10x}  {}",
                s.index,
                names::escape(pe.section_name(s).as_bytes()),
                base.wrapping_add(u64::from(s.virtual_address)),
                s.virtual_size,
                s.pointer_to_raw_data,
                s.size_of_raw_data,
                mapped,
                section_flags(s.characteristics)
            )?;
        }
        writeln!(
            out,
            "  (Mapped: file bytes the loader maps; Flags: R W X, C code, I data, U bss, D discardable)"
        )?;
    }
    if show.imports {
        gap(out)?;
        let imports = pe.imports();
        let n: usize = imports.iter().map(|d| d.entries.len()).sum();
        writeln!(out, "Imports ({} DLLs, {n} functions):", imports.len())?;
        for d in &imports {
            writeln!(out, "  {}", names::escape(d.name))?;
            for e in &d.entries {
                let what = match &e.kind {
                    ImportKind::Name { hint, name } => {
                        format!("{} (hint {hint})", names::escape(name))
                    }
                    ImportKind::Ordinal(o) => format!("#{o}"),
                    ImportKind::Unreadable(t) => format!("<unreadable thunk {t:#x}>"),
                };
                writeln!(
                    out,
                    "    {:>16x}  {what}",
                    base.wrapping_add(u64::from(e.slot_rva))
                )?;
            }
        }
    }
    if show.exports {
        gap(out)?;
        match pe.exports() {
            None => writeln!(out, "Exports: none")?,
            Some(e) => {
                writeln!(
                    out,
                    "Exports ({}{}):",
                    e.entries.len(),
                    e.dll_name
                        .map(|n| format!(", {}", names::escape(n)))
                        .unwrap_or_default()
                )?;
                for x in &e.entries {
                    let name = x.name.map(names::escape).unwrap_or_default();
                    match x.forwarder {
                        Some(f) => writeln!(
                            out,
                            "  {:>5}  {:>16}  {name} -> {}",
                            x.ordinal,
                            "forwarded",
                            names::escape(f)
                        )?,
                        None => writeln!(
                            out,
                            "  {:>5}  {:>16x}  {name}",
                            x.ordinal,
                            base.wrapping_add(u64::from(x.rva))
                        )?,
                    }
                }
            }
        }
    }
    if show.pdata {
        gap(out)?;
        let rf = pe.runtime_functions();
        let chained = rf.iter().filter(|r| r.chained).count();
        writeln!(
            out,
            "Exception table (.pdata): {} entries, {} function starts, {chained} chained parts",
            rf.len(),
            rf.len() - chained
        )?;
        for r in rf.iter().take(MAX_PDATA_ROWS) {
            writeln!(
                out,
                "  {:>16x}  {:>16x}  size {:>6x}  unwind {:#x}{}",
                base.wrapping_add(u64::from(r.begin)),
                base.wrapping_add(u64::from(r.end)),
                r.end - r.begin,
                r.unwind_info,
                if r.chained { "  (chained)" } else { "" }
            )?;
        }
        if rf.len() > MAX_PDATA_ROWS {
            writeln!(out, "  ... {} more", rf.len() - MAX_PDATA_ROWS)?;
        }
        match pe.tls() {
            None => writeln!(out, "TLS: none")?,
            Some(t) => {
                writeln!(out, "TLS callbacks ({}):", t.callbacks.len())?;
                for cb in &t.callbacks {
                    writeln!(out, "  {cb:>16x}")?;
                }
            }
        }
        writeln!(out, "Base relocations: {}", pe.relocations().count())?;
    }
    Ok(())
}

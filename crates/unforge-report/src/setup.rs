//! What Mekiki's decompiler helper (`mekiki/decompiler`, Ghidra's C++
//! decompiler) is told about a file before it decompiles anything, as the
//! text commands it reads on stdin:
//!
//! ```text
//! seg <vaddr> <fileoff> <filesz> <flags>   a PT_LOAD mapping (PE: a section), flags like RE
//! sym <addr> <name>                         a recovered function (FUN_<addr> when unnamed)
//! ptr <slot> <value>                        an 8-byte pointer the loader writes at
//!                                           <slot> (a relocation), so indirect calls
//!                                           through the GOT resolve to their target
//! ext <slot> <name>                         <slot> points to the imported symbol <name>
//! ```
//!
//! Numbers are hex. Names never contain control characters.
//!
//! For a PE image, addresses are at the preferred image base (`ImageBase +
//! RVA`), where the image's own absolute pointers point, so no `ptr` lines
//! are needed; every IAT slot gets an `ext` line named `dll!function`
//! (`KERNEL32.dll!CreateFileW`, or `dll!#<ordinal>`), so a call through
//! the IAT prints as a call to that name. The language uses Ghidra's
//! `windows` compiler spec (the Microsoft x64 / Win32 calling conventions).

use std::fmt::Write as _;

use unforge_analysis::{Analysis, Image};
use unforge_elf::ElfFile;
use unforge_pe::PeFile;

/// At most this many relocated pointer slots are reported.
pub const MAX_SLOTS: usize = 1 << 20;
/// Function names longer than this are cut.
const MAX_NAME: usize = 1024;

const DT_PLTRELSZ: i64 = 2;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_JMPREL: i64 = 23;
const R_X86_64_64: u32 = 1;
const R_X86_64_GLOB_DAT: u32 = 6;
const R_X86_64_JUMP_SLOT: u32 = 7;
const R_X86_64_RELATIVE: u32 = 8;
const EM_X86_64: u16 = 62;
const EM_386: u16 = 3;
const SHN_UNDEF: u16 = 0;

/// What a relocated pointer slot holds once the program is loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotTarget {
    /// An address inside the file (the image is not relocated: base 0).
    Address(u64),
    /// An imported symbol, by name.
    Import(String),
}

/// Ghidra's language id for the file, if the decompiler handles its CPU.
pub fn language(elf: &ElfFile<'_>) -> Option<&'static str> {
    match elf.header().machine {
        EM_X86_64 => Some("x86:LE:64:default:gcc"),
        EM_386 => Some("x86:LE:32:default:gcc"),
        _ => None,
    }
}

/// Ghidra's language id for a PE image, if the decompiler handles its CPU.
/// Both ids exist in `mekiki/decompiler/specs/x86/x86.ldefs` (compiler
/// `windows`: `x86-64-win.cspec`, `x86win.cspec`).
pub fn pe_language(pe: &PeFile<'_>) -> Option<&'static str> {
    match pe.machine() {
        unforge_pe::MACHINE_AMD64 => Some("x86:LE:64:default:windows"),
        unforge_pe::MACHINE_I386 => Some("x86:LE:32:default:windows"),
        _ => None,
    }
}

/// The relocated pointer slots of an x86-64 ELF (`DT_RELA` and `DT_JMPREL`
/// tables of `Elf64_Rela`): `R_X86_64_RELATIVE` gives its addend,
/// `R_X86_64_64` / `GLOB_DAT` / `JUMP_SLOT` give the symbol's address when
/// it is defined in the file, or its name when it is imported. Other files
/// and relocation types give nothing.
pub fn pointer_slots(elf: &ElfFile<'_>) -> Vec<(u64, SlotTarget)> {
    if elf.header().machine != EM_X86_64 {
        return Vec::new();
    }
    let Ok(dynamic) = elf.dynamic() else {
        return Vec::new();
    };
    let (mut rela, mut relasz, mut relaent, mut jmprel, mut pltrelsz) =
        (0u64, 0u64, 24u64, 0u64, 0u64);
    for e in dynamic.iter() {
        match e.tag {
            DT_RELA => rela = e.value,
            DT_RELASZ => relasz = e.value,
            DT_RELAENT => relaent = e.value,
            DT_JMPREL => jmprel = e.value,
            DT_PLTRELSZ => pltrelsz = e.value,
            _ => {}
        }
    }
    if relaent < 24 {
        return Vec::new();
    }
    let map = elf.memory_map();
    let symbols = elf.dynamic_symbols().ok();
    let mut out = Vec::new();
    for (start, size) in [(rela, relasz), (jmprel, pltrelsz)] {
        if start == 0 || size == 0 {
            continue;
        }
        let Some(bytes) = map.bytes_at(elf.data(), start) else {
            continue;
        };
        let bytes = bytes
            .get(..usize::try_from(size).unwrap_or(usize::MAX).min(bytes.len()))
            .unwrap_or_default();
        for entry in bytes.chunks_exact(usize::try_from(relaent).unwrap_or(24)) {
            if out.len() >= MAX_SLOTS {
                return out;
            }
            let (Some(offset), Some(info), Some(addend)) =
                (le64(entry, 0), le64(entry, 8), le64(entry, 16))
            else {
                continue;
            };
            let kind = (info & 0xffff_ffff) as u32;
            let sym = (info >> 32) as usize;
            let target = match kind {
                R_X86_64_RELATIVE => Some(SlotTarget::Address(addend)),
                R_X86_64_64 | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                    symbols.as_ref().and_then(|t| {
                        let s = t.get(sym)?;
                        if s.raw_shndx != SHN_UNDEF && s.value != 0 {
                            let add = if kind == R_X86_64_64 { addend } else { 0 };
                            Some(SlotTarget::Address(s.value.wrapping_add(add)))
                        } else {
                            let name = t.name_bounded(&s, MAX_NAME).ok()?;
                            let name = clean(&String::from_utf8_lossy(name.bytes));
                            (!name.is_empty()).then_some(SlotTarget::Import(name))
                        }
                    })
                }
                _ => None,
            };
            if let Some(t) = target {
                out.push((offset, t));
            }
        }
    }
    out
}

fn le64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

fn clean(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME)
        .collect()
}

/// The language id and the setup commands for the decompiler helper, or
/// `None` when the file cannot be decompiled (neither ELF nor PE, or
/// another CPU).
pub fn decompiler_setup(data: &[u8]) -> Option<(&'static str, String)> {
    let analysis = Analysis::new(data).ok()?;
    let fns: Vec<(u64, Option<String>)> = analysis
        .functions()
        .into_iter()
        .map(|f| (f.start, f.name))
        .collect();
    decompiler_setup_for(data, &fns)
}

/// [`decompiler_setup`] for a given list of functions (`start`, name), for
/// example a report's rows after fingerprints added starts and names.
pub fn decompiler_setup_for(
    data: &[u8],
    functions: &[(u64, Option<String>)],
) -> Option<(&'static str, String)> {
    let image = Image::parse(data).ok()?;
    if let Some(pe) = image.pe() {
        return pe_setup(pe, functions);
    }
    let elf = image.elf()?;
    let lang = language(elf)?;
    let mut out = String::new();
    if let Ok(phdrs) = elf.program_headers() {
        for p in phdrs.iter() {
            if p.p_type != 1 {
                continue;
            }
            let flags: String = [(4, 'R'), (2, 'W'), (1, 'E')]
                .iter()
                .filter(|&&(b, _)| p.flags & b != 0)
                .map(|&(_, c)| c)
                .collect();
            let _ = writeln!(
                out,
                "seg {:x} {:x} {:x} {}",
                p.vaddr,
                p.offset,
                p.filesz,
                if flags.is_empty() { "R" } else { &flags }
            );
        }
    }
    // Every known function start, named or not: the decompiler also uses
    // them as boundaries, so flow does not run on into the next function.
    sym_lines(&mut out, functions);
    for (slot, target) in pointer_slots(elf) {
        let _ = match target {
            SlotTarget::Address(a) => writeln!(out, "ptr {slot:x} {a:x}"),
            SlotTarget::Import(n) => writeln!(out, "ext {slot:x} {n}"),
        };
    }
    Some((lang, out))
}

/// `sym` lines for the functions: every known start, named or not (the
/// decompiler also uses them as boundaries).
fn sym_lines(out: &mut String, functions: &[(u64, Option<String>)]) {
    for (start, name) in functions {
        match name.as_deref().map(clean).filter(|n| !n.is_empty()) {
            Some(name) => writeln!(out, "sym {start:x} {name}"),
            None => writeln!(out, "sym {start:x} FUN_{start:08x}"),
        }
        .ok();
    }
}

/// [`decompiler_setup_for`] for a PE image: one `seg` per section with file
/// bytes, then the functions, then one `ext` per IAT slot.
fn pe_setup(
    pe: &PeFile<'_>,
    functions: &[(u64, Option<String>)],
) -> Option<(&'static str, String)> {
    let lang = pe_language(pe)?;
    let base = pe.image_base();
    let mut out = String::new();
    for r in pe.regions().iter().filter(|r| r.section.is_some()) {
        if r.file_len == 0 {
            continue;
        }
        let flags: String = [
            (unforge_pe::SCN_MEM_READ, 'R'),
            (unforge_pe::SCN_MEM_WRITE, 'W'),
            (unforge_pe::SCN_MEM_EXECUTE | unforge_pe::SCN_CNT_CODE, 'E'),
        ]
        .iter()
        .filter(|&&(b, _)| r.characteristics & b != 0)
        .map(|&(_, c)| c)
        .collect();
        let _ = writeln!(
            out,
            "seg {:x} {:x} {:x} {}",
            base.saturating_add(r.start),
            r.file_offset,
            r.file_len,
            if flags.is_empty() { "R" } else { &flags }
        );
    }
    sym_lines(&mut out, functions);
    for (slot, name) in pe.iat_names().into_iter().take(MAX_SLOTS) {
        let name = clean(&name);
        if !name.is_empty() {
            let _ = writeln!(out, "ext {:x} {name}", base.saturating_add(u64::from(slot)));
        }
    }
    Some((lang, out))
}

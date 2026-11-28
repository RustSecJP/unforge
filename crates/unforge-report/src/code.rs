//! Disassembly for the Listing, in two steps so a big binary stays cheap:
//!
//! - [`code_map`]: once per file, the length of every instruction of every
//!   recovered function, packed in a compact binary form. The UI builds its
//!   rows from it without any text.
//! - [`disasm_at`]: the text of the few instructions on screen.
//!
//! Only x86 / x86-64 files have code (see [`unforge_disasm::bitness_for`]).

use serde::Serialize;
use unforge_analysis::Analysis;
use unforge_disasm::{
    Bitness, Flow, bitness_for, disassemble, disassemble_function_bytes, function_bytes_in,
};
use unforge_elf::{ElfFile, MemoryMap};

/// At most this many instructions in one code map (all functions).
pub const MAX_CODE_MAP_INSNS: usize = 20_000_000;
/// At most this many instructions per function in a code map.
pub const MAX_INSNS_PER_FUNCTION: usize = 1 << 20;
/// At most this many addresses per [`disasm_at`] call.
pub const MAX_DISASM_AT: usize = 4096;
/// The longest x86 instruction.
const MAX_INSN_LEN: usize = 15;

/// For every recovered function that is backed by file bytes, in address
/// order: `start: u64`, `count: u32`, then `count` instruction lengths of
/// one byte each. Integers are little-endian. Empty when the file is not
/// x86 / x86-64 or not an ELF file at all.
///
/// A function of known size is decoded over its whole size; one of
/// unknown size up to its first `ret` (see
/// [`unforge_disasm::disassemble_function`]).
pub fn code_map(data: &[u8]) -> Vec<u8> {
    let Ok(analysis) = Analysis::new(data) else {
        return Vec::new();
    };
    let fns: Vec<(u64, u64)> = analysis
        .functions()
        .iter()
        .map(|f| (f.start, f.size))
        .collect();
    code_map_for(data, &fns)
}

/// [`code_map`] for a given list of functions (`start`, `size`; 0 = unknown),
/// for example a report's rows after fingerprints added starts. The list
/// must be sorted by start.
pub fn code_map_for(data: &[u8], functions: &[(u64, u64)]) -> Vec<u8> {
    let Ok(elf) = ElfFile::parse(data) else {
        return Vec::new();
    };
    let Some(bitness) = bitness_of(&elf) else {
        return Vec::new();
    };
    let map = elf.memory_map();
    let mut out = Vec::new();
    let mut total = 0usize;
    for &(start, size) in functions {
        if total >= MAX_CODE_MAP_INSNS {
            break;
        }
        let Some(bytes) = function_bytes_in(&map, data, start, size) else {
            continue;
        };
        let max = MAX_INSNS_PER_FUNCTION.min(MAX_CODE_MAP_INSNS - total);
        let insns = disassemble_function_bytes(bytes, start, size, bitness, max);
        if insns.is_empty() {
            continue;
        }
        total += insns.len();
        out.extend_from_slice(&start.to_le_bytes());
        out.extend_from_slice(&u32::try_from(insns.len()).unwrap_or(u32::MAX).to_le_bytes());
        out.extend(insns.iter().map(|i| i.len));
    }
    out
}

/// The text of one instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InsnText {
    pub addr: u64,
    pub len: u8,
    pub mnemonic: String,
    pub operands: String,
    /// `next`, `call`, `jump`, `cond_jump`, `return`, `interrupt`, `invalid`.
    pub flow: &'static str,
    /// Direct branch / call target, or the address a RIP-relative operand
    /// points to.
    pub target: Option<u64>,
}

/// Decodes one instruction at each of `addrs` (at most [`MAX_DISASM_AT`]).
/// `None` for an address that is not backed by file bytes, or for every
/// address when the file is not x86 / x86-64.
pub fn disasm_at(data: &[u8], addrs: &[u64]) -> Vec<Option<InsnText>> {
    let addrs = addrs
        .get(..addrs.len().min(MAX_DISASM_AT))
        .unwrap_or_default();
    let Ok(elf) = ElfFile::parse(data) else {
        return vec![None; addrs.len()];
    };
    let Some(bitness) = bitness_of(&elf) else {
        return vec![None; addrs.len()];
    };
    let map = elf.memory_map();
    addrs.iter().map(|&a| one(&map, data, a, bitness)).collect()
}

fn one(map: &MemoryMap, data: &[u8], addr: u64, bitness: Bitness) -> Option<InsnText> {
    let bytes = map.bytes_at(data, addr)?;
    let bytes = bytes.get(..bytes.len().min(MAX_INSN_LEN))?;
    let i = disassemble(bytes, addr, bitness, 1).into_iter().next()?;
    Some(InsnText {
        addr: i.addr,
        len: i.len,
        mnemonic: i.mnemonic,
        operands: i.operands,
        flow: match i.flow {
            Flow::Next => "next",
            Flow::Call => "call",
            Flow::Jump => "jump",
            Flow::CondJump => "cond_jump",
            Flow::Return => "return",
            Flow::Interrupt => "interrupt",
            Flow::Invalid => "invalid",
        },
        target: i.target,
    })
}

fn bitness_of(elf: &ElfFile<'_>) -> Option<Bitness> {
    let h = elf.header();
    bitness_for(h.machine, h.class)
}

/// Splits a [`code_map`] back into `(start, lengths)` records; stops at the
/// first malformed record.
pub fn parse_code_map(bytes: &[u8]) -> Vec<(u64, &[u8])> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while let Some((head, tail)) = rest.split_at_checked(12) {
        let (Some(start), Some(count)) = (head.get(..8), head.get(8..12)) else {
            break;
        };
        let start = u64::from_le_bytes(start.try_into().unwrap_or([0; 8]));
        let count = u32::from_le_bytes(count.try_into().unwrap_or([0; 4])) as usize;
        let Some((lens, after)) = tail.split_at_checked(count) else {
            break;
        };
        out.push((start, lens));
        rest = after;
    }
    out
}

/// A panic location (`core::panic::Location`): where in the source a panic
/// would be raised. rustc keeps these even in stripped release builds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanicLocation {
    pub file: String,
    pub line: u32,
    pub col: u32,
}

/// Longest string literal [`annotate`] reads.
pub const MAX_STR: u64 = 4096;

/// Reads `len` bytes at `addr` as a string literal: valid UTF-8, no NULs and
/// no control characters other than tab / newline.
pub fn str_at(data: &[u8], map: &MemoryMap, addr: u64, len: u64) -> Option<String> {
    if len == 0 || len > MAX_STR {
        return None;
    }
    let bytes = map
        .bytes_at(data, addr)?
        .get(..usize::try_from(len).ok()?)?;
    let s = std::str::from_utf8(bytes).ok()?;
    s.chars()
        .all(|c| !c.is_control() || c == '\t' || c == '\n')
        .then(|| s.to_owned())
}

/// Pointer values the loader writes (relocations), by slot address. In a
/// PIE the file holds 0 where a relocated pointer goes.
pub type Relocated = std::collections::HashMap<u64, u64>;

/// [`Relocated`] for a file (see [`crate::setup::pointer_slots`]).
pub fn relocated(elf: &ElfFile<'_>) -> Relocated {
    crate::setup::pointer_slots(elf)
        .into_iter()
        .filter_map(|(slot, t)| match t {
            crate::setup::SlotTarget::Address(a) => Some((slot, a)),
            crate::setup::SlotTarget::Import(_) => None,
        })
        .collect()
}

/// The panic location stored at `addr` (64-bit layout: file pointer, file
/// length, line, column), if it looks like one: a UTF-8 path ending in
/// `.rs`, line and column in a sane range. The file pointer is taken from
/// `relocs` when the loader writes it.
pub fn panic_location_at(
    data: &[u8],
    map: &MemoryMap,
    relocs: &Relocated,
    addr: u64,
) -> Option<PanicLocation> {
    let b = map.bytes_at(data, addr)?.get(..24)?;
    let word = |i: usize| -> Option<u64> {
        if let Some(&v) = relocs.get(&addr.wrapping_add(i as u64)) {
            return Some(v);
        }
        Some(u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?))
    };
    let half =
        |i: usize| -> Option<u32> { Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?)) };
    let (ptr, len, line, col) = (word(0)?, word(8)?, half(16)?, half(20)?);
    if !(1..=10_000_000).contains(&line) || col > 100_000 || !(4..=1024).contains(&len) {
        return None;
    }
    let file = str_at(data, map, ptr, len)?;
    (file.ends_with(".rs") && !file.contains('\n')).then_some(PanicLocation { file, line, col })
}

/// Adds comment lines to decompiled code (C or Rust from the helper), above
/// the statement, for the constants it can explain:
///
/// - an address of a panic location: `// at src/main.rs:12:5`
/// - an `(address, length)` pair of arguments that is a string literal:
///   `// "called `Result::unwrap()` on an `Err` value"`
///
/// Only x86-64 files (the layout read above); others come back unchanged.
pub fn annotate(data: &[u8], code: &str) -> String {
    let Ok(elf) = ElfFile::parse(data) else {
        return code.to_owned();
    };
    if bitness_of(&elf) != Some(Bitness::B64) {
        return code.to_owned();
    }
    let map = elf.memory_map();
    let relocs = relocated(&elf);
    let regions = string_regions(&elf);
    let in_strings = |a: u64, len: u64| {
        regions
            .iter()
            .any(|&(s, e)| a >= s && a.saturating_add(len) <= e)
    };
    let lines: Vec<&str> = code.split('\n').collect();
    // index of the line a note goes above -> notes
    let mut notes_at: std::collections::BTreeMap<usize, Vec<String>> = Default::default();
    for (li, body) in lines.iter().enumerate() {
        let mut notes: Vec<String> = Vec::new();
        let nums = numbers(body);
        for (i, &(n, is_hex)) in nums.iter().enumerate() {
            if !is_hex {
                continue;
            }
            if let Some(loc) = panic_location_at(data, &map, &relocs, n) {
                notes.push(format!("at {}:{}:{}", loc.file, loc.line, loc.col));
                continue;
            }
            if let Some(&(len, _)) = nums.get(i + 1)
                && in_strings(n, len)
                && let Some(s) = str_at(data, &map, n, len)
            {
                let shown: String = s.chars().take(120).collect();
                let more = if s.chars().count() > 120 { "…" } else { "" };
                notes.push(format!("{shown:?}{more}"));
            }
        }
        if notes.is_empty() {
            continue;
        }
        // A call's arguments wrapped onto their own line: note the statement.
        let mut at = li;
        while at > 0
            && lines
                .get(at)
                .is_some_and(|l| l.trim_start().starts_with('('))
        {
            at -= 1;
        }
        notes_at.entry(at).or_default().extend(notes);
    }
    let mut out = String::with_capacity(code.len() + notes_at.len() * 40);
    for (li, body) in lines.iter().enumerate() {
        if let Some(notes) = notes_at.get(&li) {
            let indent: String = body.chars().take_while(|c| *c == ' ').collect();
            for note in notes {
                out.push_str(&indent);
                out.push_str("// ");
                out.push_str(note);
                out.push('\n');
            }
        }
        out.push_str(body);
        if li + 1 < lines.len() {
            out.push('\n');
        }
    }
    out
}

/// Where string literals live: `.rodata*` sections, or when the section
/// table is gone, read-only non-executable `PT_LOAD`s past the ELF header.
fn string_regions(elf: &ElfFile<'_>) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    if let Ok(table) = elf.section_headers() {
        for i in 0..table.len() {
            let Some(sh) = table.get(i) else { continue };
            let named_rodata = elf
                .section_name_bounded(&sh, 64)
                .is_ok_and(|n| n.bytes.starts_with(b".rodata"));
            if named_rodata && sh.addr != 0 {
                out.push((sh.addr, sh.addr.saturating_add(sh.size)));
            }
        }
    }
    if out.is_empty()
        && let Ok(phdrs) = elf.program_headers()
    {
        for p in phdrs.iter() {
            if p.p_type == 1 && p.flags & 0b011 == 0 {
                let start = if p.offset == 0 {
                    p.vaddr.saturating_add(0x40)
                } else {
                    p.vaddr
                };
                out.push((start, p.vaddr.saturating_add(p.filesz)));
            }
        }
    }
    out
}

/// The integer literals of a line, in order: (value, written in hex).
/// Identifiers that contain digits (`uVar3`, `FUN_1234`) are skipped.
fn numbers(line: &str) -> Vec<(u64, bool)> {
    let b = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b.get(i).copied().unwrap_or(0);
        let prev_ident = i > 0
            && b.get(i - 1)
                .is_some_and(|p| p.is_ascii_alphanumeric() || *p == b'_');
        if c.is_ascii_digit() && !prev_ident {
            let hex = c == b'0' && matches!(b.get(i + 1), Some(b'x') | Some(b'X'));
            let start = if hex { i + 2 } else { i };
            let mut j = start;
            while b.get(j).is_some_and(|d| {
                if hex {
                    d.is_ascii_hexdigit()
                } else {
                    d.is_ascii_digit()
                }
            }) {
                j += 1;
            }
            let next_ident = b
                .get(j)
                .is_some_and(|d| d.is_ascii_alphanumeric() || *d == b'_');
            if j > start && !next_ident {
                let text = line.get(start..j).unwrap_or("0");
                if let Ok(v) = u64::from_str_radix(text, if hex { 16 } else { 10 }) {
                    out.push((v, hex));
                }
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    out
}

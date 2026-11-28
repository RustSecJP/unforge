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
    let elf = analysis.elf();
    let Some(bitness) = bitness_of(elf) else {
        return Vec::new();
    };
    let map = elf.memory_map();
    let mut out = Vec::new();
    let mut total = 0usize;
    for f in analysis.functions() {
        if total >= MAX_CODE_MAP_INSNS {
            break;
        }
        let Some(bytes) = function_bytes_in(&map, data, f.start, f.size) else {
            continue;
        };
        let max = MAX_INSNS_PER_FUNCTION.min(MAX_CODE_MAP_INSNS - total);
        let insns = disassemble_function_bytes(bytes, f.start, f.size, bitness, max);
        if insns.is_empty() {
            continue;
        }
        total += insns.len();
        out.extend_from_slice(&f.start.to_le_bytes());
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

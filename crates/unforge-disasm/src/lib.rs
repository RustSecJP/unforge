//! x86 and x86-64 disassembly for unforge.
//!
//! This crate turns machine code into a list of [`Insn`]s: address, length,
//! Intel-syntax text, how control flow leaves the instruction ([`Flow`]),
//! and the address it refers to ([`Insn::target`]). It is the first step
//! from "where are the functions" (`unforge-analysis`) to "what do they do".
//!
//! - [`disassemble`] decodes a byte slice loaded at a given address.
//! - [`function_bytes`] finds the file bytes of a function in an ELF file
//!   through its `PT_LOAD` segments; [`disassemble_function`] does both.
//! - [`bitness_for`] picks the decoder mode for an ELF `e_machine`.
//!
//! # Decoder
//!
//! Decoding and formatting are done by the [`iced_x86`] crate, the one
//! third-party instruction decoder in the workspace. Only its `std`,
//! `decoder`, `intel` and `instr_info` features are enabled (no encoder,
//! no other syntaxes).
//!
//! # Bounds
//!
//! Like the rest of unforge, nothing here panics on any input. Decoding is
//! linear in the number of bytes, each call returns at most `max_insns`
//! instructions, and the text of one instruction is bounded by what an
//! instruction of at most 15 bytes can say.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter,
    MemorySizeOptions, OpKind,
};
use unforge_elf::consts::{EM_386, EM_X86_64};
use unforge_elf::{Class, ElfFile, MemoryMap};

/// Decoder mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bitness {
    /// 32-bit protected mode (i386).
    B32,
    /// 64-bit long mode (x86-64).
    B64,
}

impl Bitness {
    fn bits(self) -> u32 {
        match self {
            Bitness::B32 => 32,
            Bitness::B64 => 64,
        }
    }
}

/// How control leaves an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Falls through to the next instruction.
    Next,
    /// A call, direct or indirect (also `syscall`/`sysenter`, which iced
    /// classifies as calls).
    Call,
    /// An unconditional jump, direct or indirect.
    Jump,
    /// A conditional jump (`jcc`, `loop`, `jrcxz`, `xbegin`).
    CondJump,
    /// A return (`ret`, `iret`, `sysret`, ...).
    Return,
    /// An interrupt or a trap that does not come back in the usual way:
    /// `int3`, `int n`, and also `ud2` / `ud0` (Rust's `unreachable` and
    /// abort paths end in `ud2`).
    Interrupt,
    /// Bytes that do not decode (see [`INVALID_MNEMONIC`]).
    Invalid,
}

/// The mnemonic of an [`Insn`] made from undecodable bytes.
pub const INVALID_MNEMONIC: &str = "(bad)";

/// One decoded instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Insn {
    /// Virtual address of the instruction.
    pub addr: u64,
    /// Length in bytes (1 for an invalid byte, at most 15).
    pub len: u8,
    /// Intel syntax, lowercase, with prefixes (`mov`, `rep stosb`,
    /// `lock cmpxchg`), or [`INVALID_MNEMONIC`].
    pub mnemonic: String,
    /// Operands in Intel syntax (`rax, qword ptr [rbp-8]`); empty if none.
    /// Numbers are hexadecimal with `0x` (small ones decimal), every memory
    /// operand says its size, and branch targets and RIP-relative operands
    /// are shown as absolute addresses (`call 0x401020`,
    /// `lea rdi, [0x404010]`), the same value as [`Insn::target`].
    pub operands: String,
    pub flow: Flow,
    /// The direct branch or call target, or else the address a RIP-relative
    /// memory operand refers to (`lea rdi, [rip+0x1234]`; for
    /// `call qword ptr [rip+0x10]` it is the address of the pointer, not of
    /// the callee). `None` otherwise.
    pub target: Option<u64>,
}

impl Insn {
    /// Whether this is the end of a straight-line run: a return, an
    /// unconditional jump, an interrupt/trap or invalid bytes.
    pub fn ends_block(&self) -> bool {
        matches!(
            self.flow,
            Flow::Return | Flow::Jump | Flow::Interrupt | Flow::Invalid
        )
    }
}

/// Bitness for an ELF `e_machine` and class: `EM_X86_64` gives
/// [`Bitness::B64`], `EM_386` gives [`Bitness::B32`], any other CPU gives
/// `None`.
///
/// The machine decides, not the class: an `ELFCLASS32` file for
/// `EM_X86_64` (the x32 ABI) still holds 64-bit code, and an `ELFCLASS64`
/// file for `EM_386` (not produced by any toolchain) is decoded as 32-bit.
pub fn bitness_for(machine: u16, class: Class) -> Option<Bitness> {
    let _ = class;
    match machine {
        EM_X86_64 => Some(Bitness::B64),
        EM_386 => Some(Bitness::B32),
        _ => None,
    }
}

/// The intel formatter with the options unforge prints with.
fn formatter() -> IntelFormatter {
    let mut f = IntelFormatter::new();
    let o = f.options_mut();
    o.set_uppercase_all(false);
    o.set_hex_prefix("0x");
    o.set_hex_suffix("");
    o.set_uppercase_hex(false);
    o.set_add_leading_zero_to_hex_numbers(false);
    o.set_branch_leading_zeros(false);
    o.set_space_after_operand_separator(true);
    o.set_show_branch_size(false);
    // `qword ptr` on every memory operand, as objdump prints it.
    o.set_memory_size_options(MemorySizeOptions::Always);
    f
}

fn flow_of(insn: &Instruction) -> Flow {
    if insn.is_invalid() {
        return Flow::Invalid;
    }
    match insn.flow_control() {
        FlowControl::Next => Flow::Next,
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => Flow::Jump,
        FlowControl::ConditionalBranch => Flow::CondJump,
        FlowControl::Return => Flow::Return,
        FlowControl::Call | FlowControl::IndirectCall => Flow::Call,
        FlowControl::Interrupt | FlowControl::Exception => Flow::Interrupt,
        // xbegin branches to its fallback address on abort; xabort and xend
        // continue (or abort the transaction, which is xbegin's branch).
        FlowControl::XbeginXabortXend if has_near_branch(insn) => Flow::CondJump,
        _ => Flow::Next,
    }
}

fn has_near_branch(insn: &Instruction) -> bool {
    insn.op_count() > 0
        && matches!(
            insn.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        )
}

fn target_of(insn: &Instruction) -> Option<u64> {
    if has_near_branch(insn) {
        Some(insn.near_branch_target())
    } else if insn.is_ip_rel_memory_operand() {
        Some(insn.ip_rel_memory_address())
    } else {
        None
    }
}

fn invalid(addr: u64) -> Insn {
    Insn {
        addr,
        len: 1,
        mnemonic: INVALID_MNEMONIC.to_owned(),
        operands: String::new(),
        flow: Flow::Invalid,
        target: None,
    }
}

/// Decodes up to `max_insns` instructions from `bytes`, which are loaded at
/// `addr`. Never panics; stops at the end of `bytes`. Undecodable bytes
/// become a 1-byte [`Insn`] with flow [`Flow::Invalid`] (mnemonic
/// [`INVALID_MNEMONIC`]), and decoding resumes at the next byte; an
/// instruction cut off by the end of `bytes` is undecodable too.
///
/// Addresses wrap around at the top of the address space.
pub fn disassemble(bytes: &[u8], addr: u64, bitness: Bitness, max_insns: usize) -> Vec<Insn> {
    let mut out = Vec::with_capacity(max_insns.min(bytes.len()));
    decode_while(bytes, addr, bitness, max_insns, |insn| {
        out.push(insn);
        true
    });
    out
}

/// Like [`disassemble`], but stops after the first instruction for which
/// `keep_going` returns `false` (that instruction is included).
pub fn disassemble_until(
    bytes: &[u8],
    addr: u64,
    bitness: Bitness,
    max_insns: usize,
    mut keep_going: impl FnMut(&Insn) -> bool,
) -> Vec<Insn> {
    let mut out = Vec::with_capacity(max_insns.min(bytes.len()));
    decode_while(bytes, addr, bitness, max_insns, |insn| {
        let more = keep_going(&insn);
        out.push(insn);
        more
    });
    out
}

fn decode_while(
    bytes: &[u8],
    addr: u64,
    bitness: Bitness,
    max_insns: usize,
    mut sink: impl FnMut(Insn) -> bool,
) {
    let Ok(mut decoder) = Decoder::try_with_ip(bitness.bits(), bytes, addr, DecoderOptions::NONE)
    else {
        return;
    };
    let mut fmt = formatter();
    let mut insn = Instruction::default();
    let mut count = 0usize;
    while count < max_insns && decoder.can_decode() {
        let pos = decoder.position();
        let ip = addr.wrapping_add(pos as u64);
        decoder.decode_out(&mut insn);
        count += 1;
        let decoded = if insn.is_invalid() || insn.len() == 0 {
            // Resume right after the first byte.
            let next = pos.saturating_add(1);
            if decoder.set_position(next).is_err() {
                // Only past the end of `bytes`; nothing is left to decode.
                let _ = sink(invalid(ip));
                return;
            }
            decoder.set_ip(addr.wrapping_add(next as u64));
            invalid(ip)
        } else {
            let mut mnemonic = String::new();
            fmt.format_mnemonic(&insn, &mut mnemonic);
            let mut operands = String::new();
            fmt.format_all_operands(&insn, &mut operands);
            Insn {
                addr: ip,
                len: u8::try_from(insn.len()).unwrap_or(u8::MAX),
                mnemonic,
                operands,
                flow: flow_of(&insn),
                target: target_of(&insn),
            }
        };
        if !sink(decoded) {
            return;
        }
    }
}

/// How many bytes [`function_bytes`] returns for a function of unknown size
/// (size 0): enough for most functions, small enough that guessing wrong
/// costs little.
pub const UNKNOWN_SIZE_LIMIT: u64 = 4096;

/// The file bytes of the function at virtual address `start` with `size`
/// bytes, found through the `PT_LOAD` segments of `elf` (the kernel's view,
/// [`ElfFile::memory_map`]).
///
/// The result is cut where the mapped file bytes stop: at the end of the
/// file (a clipped segment), at the end of the segment's `p_filesz` (the
/// rest of the segment is zero-fill, not code), or where another segment
/// takes over the address range. It may therefore be shorter than `size`.
/// When `size` is 0 (unknown), at most [`UNKNOWN_SIZE_LIMIT`] bytes are
/// returned.
///
/// `None` when `start` is not backed by file bytes.
pub fn function_bytes<'d>(elf: &ElfFile<'d>, start: u64, size: u64) -> Option<&'d [u8]> {
    function_bytes_in(&elf.memory_map(), elf.data(), start, size)
}

/// [`function_bytes`] with a memory map built once (`elf.memory_map()`)
/// and the file's bytes (`elf.data()`), for many functions of one file.
pub fn function_bytes_in<'d>(
    map: &MemoryMap,
    data: &'d [u8],
    start: u64,
    size: u64,
) -> Option<&'d [u8]> {
    let bytes = map.bytes_at(data, start)?;
    let want = if size == 0 { UNKNOWN_SIZE_LIMIT } else { size };
    let n = usize::try_from(want).unwrap_or(usize::MAX).min(bytes.len());
    bytes.get(..n)
}

/// Disassembles the function at `start` with `size` bytes (0 = unknown) of
/// an x86 / x86-64 ELF file, at most `max_insns` instructions.
///
/// With a known size, every instruction inside `size` bytes is decoded.
/// With an unknown size, decoding stops after the first [`Flow::Return`]
/// (or at [`UNKNOWN_SIZE_LIMIT`] bytes). Tail calls (`jmp`) and `ud2` do
/// not stop it, because Rust code often continues past them inside the
/// same function.
///
/// `None` when the file is not for x86 ([`bitness_for`]) or `start` is not
/// backed by file bytes ([`function_bytes`]).
pub fn disassemble_function(
    elf: &ElfFile<'_>,
    start: u64,
    size: u64,
    max_insns: usize,
) -> Option<Vec<Insn>> {
    let header = elf.header();
    let bitness = bitness_for(header.machine, header.class)?;
    let bytes = function_bytes(elf, start, size)?;
    Some(disassemble_function_bytes(
        bytes, start, size, bitness, max_insns,
    ))
}

/// The decoding step of [`disassemble_function`], for bytes already found
/// (for example with [`function_bytes_in`]).
pub fn disassemble_function_bytes(
    bytes: &[u8],
    start: u64,
    size: u64,
    bitness: Bitness,
    max_insns: usize,
) -> Vec<Insn> {
    if size == 0 {
        disassemble_until(bytes, start, bitness, max_insns, |i| i.flow != Flow::Return)
    } else {
        disassemble(bytes, start, bitness, max_insns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(bytes: &[u8], addr: u64, b: Bitness) -> Insn {
        let v = disassemble(bytes, addr, b, 1);
        assert_eq!(v.len(), 1, "{bytes:02x?}");
        v.into_iter().next().unwrap()
    }

    #[test]
    fn mov_with_memory_operand() {
        // mov rax, qword ptr [rbp-8]
        let i = one(&[0x48, 0x8b, 0x45, 0xf8], 0x1000, Bitness::B64);
        assert_eq!(i.addr, 0x1000);
        assert_eq!(i.len, 4);
        assert_eq!(i.mnemonic, "mov");
        assert_eq!(i.operands, "rax, qword ptr [rbp-8]");
        assert_eq!(i.flow, Flow::Next);
        assert_eq!(i.target, None);
    }

    #[test]
    fn flows_and_targets() {
        let cases: &[(&[u8], Flow, Option<u64>, &str)] = &[
            // call rel32 -> 0x1000 + 5 + 0x10
            (&[0xe8, 0x10, 0, 0, 0], Flow::Call, Some(0x1015), "call"),
            // jmp rel8 -> 0x1000 + 2 - 2
            (&[0xeb, 0xfe], Flow::Jump, Some(0x1000), "jmp"),
            // je rel8
            (&[0x74, 0x05], Flow::CondJump, Some(0x1007), "je"),
            // jne rel32
            (
                &[0x0f, 0x85, 0, 1, 0, 0],
                Flow::CondJump,
                Some(0x1106),
                "jne",
            ),
            (&[0xc3], Flow::Return, None, "ret"),
            (&[0xc2, 0x08, 0x00], Flow::Return, None, "ret"),
            (&[0xcc], Flow::Interrupt, None, "int3"),
            (&[0xcd, 0x80], Flow::Interrupt, None, "int"),
            (&[0x0f, 0x0b], Flow::Interrupt, None, "ud2"),
            // call rax
            (&[0xff, 0xd0], Flow::Call, None, "call"),
            // jmp rax
            (&[0xff, 0xe0], Flow::Jump, None, "jmp"),
            // call qword ptr [rip+0x10]: the pointer's address
            (
                &[0xff, 0x15, 0x10, 0, 0, 0],
                Flow::Call,
                Some(0x1016),
                "call",
            ),
            // lea rdi, [rip+0x20]
            (
                &[0x48, 0x8d, 0x3d, 0x20, 0, 0, 0],
                Flow::Next,
                Some(0x1027),
                "lea",
            ),
            (&[0x90], Flow::Next, None, "nop"),
            (&[0xe2, 0xfe], Flow::CondJump, Some(0x1000), "loop"),
        ];
        for &(bytes, flow, target, mnemonic) in cases {
            let i = one(bytes, 0x1000, Bitness::B64);
            assert_eq!(i.flow, flow, "{bytes:02x?} {i:?}");
            assert_eq!(i.target, target, "{bytes:02x?} {i:?}");
            assert_eq!(i.mnemonic, mnemonic, "{bytes:02x?} {i:?}");
            assert_eq!(usize::from(i.len), bytes.len(), "{bytes:02x?}");
        }
    }

    #[test]
    fn branch_target_text_is_absolute_hex() {
        let i = one(&[0xe8, 0x10, 0, 0, 0], 0x401000, Bitness::B64);
        assert_eq!(i.operands, "0x401015");
    }

    #[test]
    fn bitness_matters() {
        // 0x48 is `dec eax` in 32-bit mode and a REX prefix in 64-bit mode.
        let v = disassemble(&[0x48, 0x89, 0xe5], 0, Bitness::B64, 10);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].operands, "rbp, rsp");
        let v = disassemble(&[0x48, 0x89, 0xe5], 0, Bitness::B32, 10);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].mnemonic, "dec");
        assert_eq!(v[1].operands, "ebp, esp");
        // 32-bit near call target wraps at 4 GiB.
        let i = one(&[0xe8, 0xfb, 0xff, 0xff, 0xff], 0, Bitness::B32);
        assert_eq!(i.target, Some(0));
        let i = one(&[0xe8, 0xf0, 0xff, 0xff, 0xff], 0, Bitness::B32);
        assert_eq!(i.target, Some(0xffff_fff5));
    }

    #[test]
    fn prefixes_are_part_of_the_mnemonic() {
        let i = one(&[0xf3, 0x48, 0xab], 0, Bitness::B64);
        assert_eq!(i.mnemonic, "rep stosq");
        let i = one(&[0xf0, 0x48, 0x0f, 0xb1, 0x0e], 0, Bitness::B64);
        assert_eq!(i.mnemonic, "lock cmpxchg");
    }

    #[test]
    fn invalid_bytes_become_one_byte_insns() {
        // 0x06 (push es) is invalid in 64-bit mode; then a ret.
        let v = disassemble(&[0x06, 0x06, 0xc3], 0x10, Bitness::B64, 100);
        assert_eq!(v.len(), 3);
        for (k, i) in v.iter().take(2).enumerate() {
            assert_eq!(i.addr, 0x10 + k as u64);
            assert_eq!(i.len, 1);
            assert_eq!(i.flow, Flow::Invalid);
            assert_eq!(i.mnemonic, INVALID_MNEMONIC);
            assert_eq!(i.operands, "");
            assert_eq!(i.target, None);
        }
        assert_eq!(v[2].mnemonic, "ret");
        assert_eq!(v[2].addr, 0x12);
        // In 32-bit mode it is valid.
        assert_eq!(one(&[0x06], 0, Bitness::B32).mnemonic, "push");
    }

    #[test]
    fn truncated_instruction_at_the_end() {
        // `mov eax, imm32` cut after 3 bytes, three times over: every byte
        // is reported, none is skipped and nothing is read past the end.
        let v = disassemble(&[0x90, 0xb8, 0xb8, 0xb8], 0, Bitness::B64, 100);
        assert_eq!(v.len(), 4);
        assert_eq!(v[0].mnemonic, "nop");
        assert!(v[1..].iter().all(|i| i.flow == Flow::Invalid && i.len == 1));
        let total: usize = v.iter().map(|i| usize::from(i.len)).sum();
        assert_eq!(total, 4);
    }

    #[test]
    fn limits() {
        assert!(disassemble(&[], 0, Bitness::B64, 10).is_empty());
        assert!(disassemble(&[0x90; 8], 0, Bitness::B64, 0).is_empty());
        assert_eq!(disassemble(&[0x90; 8], 0, Bitness::B64, 3).len(), 3);
        // Addresses wrap.
        let v = disassemble(&[0x90, 0x90], u64::MAX, Bitness::B64, 10);
        assert_eq!(v[1].addr, 0);
    }

    #[test]
    fn until_includes_the_stopping_insn() {
        let bytes = [0x90, 0xc3, 0x90, 0x90];
        let v = disassemble_until(&bytes, 0, Bitness::B64, 10, |i| i.flow != Flow::Return);
        assert_eq!(v.len(), 2);
        let v = disassemble_function_bytes(&bytes, 0, 0, Bitness::B64, 10);
        assert_eq!(v.len(), 2);
        let v = disassemble_function_bytes(&bytes, 0, 4, Bitness::B64, 10);
        assert_eq!(v.len(), 4);
    }

    #[test]
    fn bitness_for_machines() {
        assert_eq!(bitness_for(EM_X86_64, Class::Elf64), Some(Bitness::B64));
        assert_eq!(bitness_for(EM_X86_64, Class::Elf32), Some(Bitness::B64));
        assert_eq!(bitness_for(EM_386, Class::Elf32), Some(Bitness::B32));
        assert_eq!(bitness_for(183, Class::Elf64), None);
        assert_eq!(bitness_for(0, Class::Elf64), None);
    }
}

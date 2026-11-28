//! Position-independent normal form of a function's instructions.
//!
//! See the crate documentation ("Fingerprint") for the reasons behind the
//! rules. In short, every instruction becomes one line
//! `mnemonic operands`, where the operand text of `unforge-disasm` is kept
//! except for numbers that depend on where things were linked:
//!
//! | number in the operand text | becomes |
//! |---|---|
//! | the instruction's [`Insn::target`] inside the function | `L<offset from the start, hex>` |
//! | the instruction's [`Insn::target`] elsewhere (call, jump, RIP-relative data) | `T` |
//! | a displacement inside an `fs:[..]` / `gs:[..]` operand, other than 0 | `F` |
//! | a displacement from `ebx` (`[ebx+0xe8]`, i386 PIC: offset from the GOT) | `G` |
//! | any other number for which `is_layout_dependent` is true (`>= 0x1000` and a mapped address in 64-bit code; any number in `0x1000..0xffff_0000` in 32-bit code) | `A` |
//! | anything else (immediates, stack and field offsets, scales) | kept |
//!
//! Registers, mnemonics, prefixes, memory operand sizes and the shape of
//! the operands (`qword ptr [rax+rcx*8+0x10]`) are kept as they are.

use unforge_disasm::{Flow, Insn};

use crate::fnv::Fnv64;

/// Numbers below this are never treated as addresses (rule `A`): small
/// constants and field offsets are far more common there than real
/// addresses, and no x86 Linux binary maps its code or data that low.
pub const MIN_ADDRESS: u64 = 0x1000;

/// At most this many instructions of one function are hashed. Longer
/// functions are fingerprinted by this prefix (and their real instruction
/// count is still capped at this value).
pub const MAX_INSNS: usize = 1 << 16;

/// The fingerprint of one function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint {
    /// FNV-1a 64 ([`crate::fnv`]) of the normalized lines, each followed by
    /// `\n`, then of the instruction count (`u32`, little-endian).
    pub hash: u64,
    /// Instructions hashed (after trailing padding was removed).
    pub insns: u32,
    /// Bytes those instructions cover.
    pub bytes: u32,
}

/// Whether an instruction is alignment padding: `nop` in any form
/// (`nop dword ptr [rax]`, `data16 cs nop ...`), `xchg ax, ax` (the 2-byte
/// nop) and `int3`. Only trailing padding is removed.
fn is_padding(i: &Insn) -> bool {
    let last = i.mnemonic.rsplit(' ').next().unwrap_or("");
    last == "nop" || last == "int3" || (i.mnemonic == "xchg" && i.operands == "ax, ax")
}

/// `insns` without trailing padding (`nop` in any form, `xchg ax, ax`,
/// `int3`) and capped at [`MAX_INSNS`].
pub fn trim_padding(insns: &[Insn]) -> &[Insn] {
    let insns = insns.get(..insns.len().min(MAX_INSNS)).unwrap_or(insns);
    let keep = insns
        .iter()
        .rposition(|i| !is_padding(i))
        .map_or(0, |p| p + 1);
    insns.get(..keep).unwrap_or(insns)
}

fn is_branch(flow: Flow) -> bool {
    matches!(flow, Flow::Call | Flow::Jump | Flow::CondJump)
}

/// Parses an operand number as `unforge-disasm` prints it: `0x` hex or
/// decimal.
fn parse_number(tok: &str) -> Option<u64> {
    match tok.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => tok.parse().ok(),
    }
}

/// Appends the normal form of one instruction (without a newline) to
/// `out`. `start..end` is the function's address range;
/// `layout_dependent` says whether a number may depend on the layout
/// (rule `A`; see `Fingerprinter::is_layout_dependent`).
pub fn normalize_into(
    out: &mut String,
    insn: &Insn,
    start: u64,
    end: u64,
    layout_dependent: &dyn Fn(u64) -> bool,
) {
    out.push_str(&insn.mnemonic);
    if insn.operands.is_empty() {
        return;
    }
    out.push(' ');
    let ops = insn.operands.as_bytes();
    let mut i = 0usize;
    // Inside `fs:[` .. `]` (or gs).
    let mut in_segment_mem = false;
    let mut prev_ident: &str = "";
    while let Some(&c) = ops.get(i) {
        if c.is_ascii_digit() {
            let j = ops
                .iter()
                .skip(i)
                .position(|b| !(b.is_ascii_hexdigit() || *b == b'x'))
                .map_or(ops.len(), |p| i + p);
            let tok = insn.operands.get(i..j).unwrap_or("");
            match parse_number(tok) {
                Some(v) if insn.target == Some(v) => {
                    if is_branch(insn.flow) && start <= v && v < end {
                        out.push_str(&format!("L{:x}", v - start));
                    } else {
                        out.push('T');
                    }
                }
                Some(v) if in_segment_mem && v != 0 => out.push('F'),
                Some(_) if out.ends_with("[ebx+") || out.ends_with("[ebx-") => out.push('G'),
                Some(v) if v >= MIN_ADDRESS && layout_dependent(v) => out.push('A'),
                _ => out.push_str(tok),
            }
            prev_ident = "";
            i = j.max(i + 1);
        } else if c.is_ascii_alphabetic() || c == b'_' {
            let j = ops
                .iter()
                .skip(i)
                .position(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
                .map_or(ops.len(), |p| i + p);
            let tok = insn.operands.get(i..j).unwrap_or("");
            out.push_str(tok);
            prev_ident = tok;
            i = j.max(i + 1);
        } else {
            if c == b':' && (prev_ident == "fs" || prev_ident == "gs") {
                in_segment_mem = true;
            } else if c == b']' {
                in_segment_mem = false;
            }
            if c != b':' {
                prev_ident = "";
            }
            out.push(char::from(c));
            i += 1;
        }
    }
}

/// The normalized lines of a function, one per instruction after trailing
/// padding is removed ([`trim_padding`]). For debugging and tests;
/// [`fingerprint_insns`] hashes exactly these lines.
pub fn normalized_lines(
    insns: &[Insn],
    start: u64,
    layout_dependent: &dyn Fn(u64) -> bool,
) -> Vec<String> {
    let end = function_end(insns, start);
    trim_padding(insns)
        .iter()
        .map(|i| {
            let mut s = String::new();
            normalize_into(&mut s, i, start, end, layout_dependent);
            s
        })
        .collect()
}

/// The end of the code `insns` covers (before trimming): one past the last
/// byte of the last instruction, or `start` when empty.
fn function_end(insns: &[Insn], start: u64) -> u64 {
    insns
        .last()
        .map_or(start, |i| i.addr.wrapping_add(u64::from(i.len)))
}

/// The fingerprint of the function at `start` whose instructions are
/// `insns` (as decoded from its whole size). `layout_dependent` tells
/// whether a number may depend on the layout (rule `A` of the module docs).
///
/// `None` when nothing is left after trailing padding is removed.
pub fn fingerprint_insns(
    insns: &[Insn],
    start: u64,
    layout_dependent: &dyn Fn(u64) -> bool,
) -> Option<Fingerprint> {
    let end = function_end(insns, start);
    let body = trim_padding(insns);
    if body.is_empty() {
        return None;
    }
    let mut h = Fnv64::new();
    let mut line = String::new();
    let mut bytes = 0u32;
    for i in body {
        line.clear();
        normalize_into(&mut line, i, start, end, layout_dependent);
        h.write(line.as_bytes());
        h.write(b"\n");
        bytes = bytes.saturating_add(u32::from(i.len));
    }
    let insns = u32::try_from(body.len()).unwrap_or(u32::MAX);
    h.write(&insns.to_le_bytes());
    Some(Fingerprint {
        hash: h.finish(),
        insns,
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use unforge_disasm::{Bitness, disassemble};

    fn never(_: u64) -> bool {
        false
    }

    fn lines(bytes: &[u8], addr: u64) -> Vec<String> {
        let v = disassemble(bytes, addr, Bitness::B64, 100);
        normalized_lines(&v, addr, &never)
    }

    #[test]
    fn calls_and_rip_relative_are_masked() {
        // call rel32; lea rdi, [rip+0x20]; mov rax, qword ptr [rip+0x10]
        let code = [
            0xe8, 0x10, 0, 0, 0, 0x48, 0x8d, 0x3d, 0x20, 0, 0, 0, 0x48, 0x8b, 0x05, 0x10, 0, 0, 0,
        ];
        assert_eq!(
            lines(&code, 0x401000),
            vec!["call T", "lea rdi, [T]", "mov rax, qword ptr [T]"]
        );
    }

    #[test]
    fn local_branches_keep_their_offset() {
        // 0: test eax, eax; 2: je +2 (-> 6); 4: xor eax, eax; 6: ret
        let code = [0x85, 0xc0, 0x74, 0x02, 0x31, 0xc0, 0xc3];
        assert_eq!(
            lines(&code, 0x5000),
            vec!["test eax, eax", "je L6", "xor eax, eax", "ret"]
        );
        // A jump out of the function (tail call) is masked.
        let code = [0x85, 0xc0, 0x0f, 0x84, 0, 1, 0, 0, 0xc3];
        assert_eq!(lines(&code, 0x5000)[1], "je T");
    }

    #[test]
    fn small_numbers_and_registers_stay() {
        // mov rax, qword ptr [rbp-8]; add rsp, 0x28; mov edi, 0x2a
        let code = [
            0x48, 0x8b, 0x45, 0xf8, 0x48, 0x83, 0xc4, 0x28, 0xbf, 0x2a, 0, 0, 0,
        ];
        assert_eq!(
            lines(&code, 0),
            vec![
                "mov rax, qword ptr [rbp-8]",
                "add rsp, 0x28",
                "mov edi, 0x2a"
            ]
        );
    }

    #[test]
    fn mapped_addresses_and_tls_offsets_are_masked() {
        // mov edi, 0x4a3000 (an absolute address in a non-PIE file)
        let code = [0xbf, 0x00, 0x30, 0x4a, 0x00];
        let v = disassemble(&code, 0x401000, Bitness::B64, 10);
        let mapped = |a: u64| (0x400000..0x500000).contains(&a);
        assert_eq!(normalized_lines(&v, 0x401000, &mapped), vec!["mov edi, A"]);
        assert_eq!(
            normalized_lines(&v, 0x401000, &never),
            vec!["mov edi, 0x4a3000"]
        );
        // mov rax, qword ptr fs:[0]; mov rax, qword ptr fs:[0xfffffffffffffff8]
        let code = [
            0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x64, 0x48, 0x8b, 0x04, 0x25, 0xf8, 0xff,
            0xff, 0xff,
        ];
        let l = lines(&code, 0);
        assert_eq!(l[0], "mov rax, qword ptr fs:[0]");
        assert_eq!(l[1], "mov rax, qword ptr fs:[F]");
    }

    #[test]
    fn i386_got_offsets_are_masked() {
        // lea eax, [ebx-0x10e0]; mov eax, dword ptr [ebx+0xe8];
        // mov eax, dword ptr [ecx+0xe8]
        let code = [
            0x8d, 0x83, 0x20, 0xef, 0xff, 0xff, 0x8b, 0x83, 0xe8, 0, 0, 0, 0x8b, 0x81, 0xe8, 0, 0,
            0,
        ];
        let v = disassemble(&code, 0x8049000, Bitness::B32, 10);
        assert_eq!(
            normalized_lines(&v, 0x8049000, &never),
            vec![
                "lea eax, [ebx-G]",
                "mov eax, dword ptr [ebx+G]",
                "mov eax, dword ptr [ecx+0xe8]"
            ]
        );
    }

    #[test]
    fn trailing_padding_is_trimmed() {
        // ret; nop dword ptr [rax+rax]; int3; xchg ax, ax
        let code = [0xc3, 0x0f, 0x1f, 0x44, 0, 0, 0xcc, 0x66, 0x90];
        let v = disassemble(&code, 0, Bitness::B64, 10);
        assert_eq!(v.len(), 4);
        assert_eq!(trim_padding(&v).len(), 1);
        let fp = fingerprint_insns(&v, 0, &never).unwrap();
        assert_eq!((fp.insns, fp.bytes), (1, 1));
        // Only padding: no fingerprint.
        let v = disassemble(&[0x90, 0xcc], 0, Bitness::B64, 10);
        assert_eq!(fingerprint_insns(&v, 0, &never), None);
    }

    /// The same code at two addresses, calling the same (relative) callee
    /// that moved with it, and the same code calling a different place.
    #[test]
    fn same_code_elsewhere_same_fingerprint() {
        // push rbx; mov rbx, rdi; call rel32; lea rsi, [rip+X]; test eax,
        // eax; jne +1; pop rbx; ret; ud2
        let mk = |call: i32, rip: i32| {
            let mut c = vec![0x53, 0x48, 0x89, 0xfb, 0xe8];
            c.extend_from_slice(&call.to_le_bytes());
            c.extend_from_slice(&[0x48, 0x8d, 0x35]);
            c.extend_from_slice(&rip.to_le_bytes());
            c.extend_from_slice(&[0x85, 0xc0, 0x75, 0x02, 0x5b, 0xc3, 0x0f, 0x0b]);
            c
        };
        let a = mk(0x100, 0x2000);
        let b = mk(-0x5_0000, 0x7_1234);
        let fa = fingerprint_insns(
            &disassemble(&a, 0x401000, Bitness::B64, 100),
            0x401000,
            &never,
        );
        let fb = fingerprint_insns(
            &disassemble(&b, 0x9_3a10, Bitness::B64, 100),
            0x9_3a10,
            &never,
        );
        assert!(fa.is_some());
        assert_eq!(fa, fb);
        assert_eq!(fa.unwrap().insns, 9);
    }

    #[test]
    fn different_immediates_differ() {
        let a = disassemble(&[0xbf, 0x2a, 0, 0, 0, 0xc3], 0, Bitness::B64, 10);
        let b = disassemble(&[0xbf, 0x2b, 0, 0, 0, 0xc3], 0, Bitness::B64, 10);
        assert_ne!(
            fingerprint_insns(&a, 0, &never),
            fingerprint_insns(&b, 0, &never)
        );
        // Different registers differ too.
        let c = disassemble(&[0xbe, 0x2a, 0, 0, 0, 0xc3], 0, Bitness::B64, 10);
        assert_ne!(
            fingerprint_insns(&a, 0, &never),
            fingerprint_insns(&c, 0, &never)
        );
    }

    #[test]
    fn odd_operand_text_does_not_panic() {
        let mut s = String::new();
        for ops in [
            "",
            "0x",
            "0xzz",
            "fs:",
            "fs:[",
            "]",
            "99999999999999999999999",
            "a:b:0x1",
        ] {
            let i = Insn {
                addr: 0,
                len: 1,
                mnemonic: "x".into(),
                operands: ops.into(),
                flow: Flow::Next,
                target: Some(1),
            };
            s.clear();
            normalize_into(&mut s, &i, 0, 1, &|_| true);
        }
    }
}

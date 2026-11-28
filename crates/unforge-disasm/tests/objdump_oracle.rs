//! Compares the disassembly of real functions against GNU objdump.
//!
//! The input is the test executable itself (`std::env::current_exe()`): a
//! real Rust ELF with symbols, built by the pinned toolchain. Functions come
//! from `unforge-analysis` (symbol start and size), their bytes from
//! [`unforge_disasm::function_bytes`], and the reference is one run of
//! `objdump -d --no-show-raw-insn -M intel` over the same file.
//!
//! For every compared function the instruction boundaries (address and
//! length of each instruction) must be identical, and so must the
//! mnemonics after the spelling differences listed in [`normalize`].
//!
//! When objdump is not installed, or the host is not x86-64, the test prints
//! why and passes without comparing anything.

use std::collections::BTreeMap;
use std::process::Command;

use unforge_disasm::{Flow, Insn, function_bytes};

/// At most this many functions are compared (spread over the whole file).
const MAX_FUNCTIONS: usize = 2000;
/// Functions larger than this are skipped (keeps the test fast).
const MAX_FUNCTION_SIZE: u64 = 1 << 16;

/// Instruction prefixes objdump prints as separate words.
const PREFIXES: &[&str] = &[
    "rep", "repz", "repnz", "repe", "repne", "lock", "data16", "addr32", "cs", "ds", "es", "ss",
    "fs", "gs", "notrack", "bnd", "xacquire", "xrelease", "rex", "rex.w", "rex.wb", "rex.b",
];

/// The mnemonic without prefixes, in one spelling for both disassemblers.
fn normalize(m: &str) -> String {
    let base = m
        .split_whitespace()
        .rfind(|w| !PREFIXES.contains(w) && !w.starts_with("rex"))
        .unwrap_or("")
        .to_ascii_lowercase();
    // Same instruction, different name.
    let alias = match base.as_str() {
        // objdump spells the string instructions with operands (`stos`,
        // `movs`); iced puts the size in the mnemonic (`stosq`, `movsb`).
        "stosb" | "stosw" | "stosd" | "stosq" => "stos",
        "movsb" | "movsw" | "movsq" => "movs",
        "lodsb" | "lodsw" | "lodsd" | "lodsq" => "lods",
        "scasb" | "scasw" | "scasd" | "scasq" => "scas",
        "cmpsb" | "cmpsw" | "cmpsq" => "cmps",
        // `movsd` is both a string move and an SSE2 move; objdump says
        // `movs` for the string form only, so map both to one name.
        "movsd" => "movs",
        "ret" | "retq" | "retn" => "ret",
        "call" | "callq" => "call",
        "jmp" | "jmpq" => "jmp",
        // Condition-code aliases: the two tools pick different defaults.
        "jb" | "jc" | "jnae" => "jb",
        "jae" | "jnb" | "jnc" => "jae",
        "je" | "jz" => "je",
        "jne" | "jnz" => "jne",
        "jbe" | "jna" => "jbe",
        "ja" | "jnbe" => "ja",
        "jp" | "jpe" => "jp",
        "jnp" | "jpo" => "jnp",
        "jl" | "jnge" => "jl",
        "jge" | "jnl" => "jge",
        "jle" | "jng" => "jle",
        "jg" | "jnle" => "jg",
        "setb" | "setc" | "setnae" => "setb",
        "setae" | "setnb" | "setnc" => "setae",
        "sete" | "setz" => "sete",
        "setne" | "setnz" => "setne",
        "setbe" | "setna" => "setbe",
        "seta" | "setnbe" => "seta",
        "setp" | "setpe" => "setp",
        "setnp" | "setpo" => "setnp",
        "setl" | "setnge" => "setl",
        "setge" | "setnl" => "setge",
        "setle" | "setng" => "setle",
        "setg" | "setnle" => "setg",
        "cmovb" | "cmovc" | "cmovnae" => "cmovb",
        "cmovae" | "cmovnb" | "cmovnc" => "cmovae",
        "cmove" | "cmovz" => "cmove",
        "cmovne" | "cmovnz" => "cmovne",
        "cmovbe" | "cmovna" => "cmovbe",
        "cmova" | "cmovnbe" => "cmova",
        "cmovp" | "cmovpe" => "cmovp",
        "cmovnp" | "cmovpo" => "cmovnp",
        "cmovl" | "cmovnge" => "cmovl",
        "cmovge" | "cmovnl" => "cmovge",
        "cmovle" | "cmovng" => "cmovle",
        "cmovg" | "cmovnle" => "cmovg",
        // AT&T-era names objdump keeps in Intel mode.
        "cqo" | "cqto" => "cqo",
        "cdq" | "cltd" => "cdq",
        "cdqe" | "cltq" => "cdqe",
        "cwde" | "cwtl" => "cwde",
        "movabs" => "mov",
        other => other,
    };
    alias.to_owned()
}

/// `addr -> instruction text` from `objdump -d`, or why it could not run.
fn objdump(path: &std::path::Path) -> Result<BTreeMap<u64, String>, String> {
    let out = Command::new("objdump")
        .args([
            "-d",
            "--no-show-raw-insn",
            "-M",
            "intel",
            "-j",
            ".text",
            "-w",
        ])
        .arg(path)
        .output()
        .map_err(|e| format!("objdump not available: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "objdump failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut map = BTreeMap::new();
    for line in text.lines() {
        // "  401000:\tmov    rbp,rsp"
        let Some((addr, rest)) = line.split_once(":\t") else {
            continue;
        };
        let Ok(addr) = u64::from_str_radix(addr.trim(), 16) else {
            continue;
        };
        map.insert(addr, rest.trim().to_owned());
    }
    Ok(map)
}

/// The mnemonic part of an objdump instruction text: prefixes and the
/// mnemonic, without operands. objdump separates the mnemonic from the
/// operands with spaces, and prefixes from the mnemonic with one space, so
/// take words until the first one that contains an operand character.
fn objdump_mnemonic(text: &str) -> String {
    let text = text.split('#').next().unwrap_or("");
    let text = text.split('<').next().unwrap_or("");
    let mut words: Vec<&str> = Vec::new();
    for w in text.split_whitespace() {
        let is_prefix = PREFIXES.contains(&w) || w.starts_with("rex");
        words.push(w);
        if !is_prefix {
            break;
        }
    }
    words.join(" ")
}

#[test]
fn matches_objdump_on_own_executable() {
    if !cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        eprintln!("skipped: the oracle test needs an x86-64 Linux host");
        return;
    }
    let exe = std::env::current_exe().expect("current_exe");
    let reference = match objdump(&exe) {
        Ok(m) if !m.is_empty() => m,
        Ok(_) => {
            eprintln!("skipped: objdump printed no instructions");
            return;
        }
        Err(e) => {
            eprintln!("skipped: {e}");
            return;
        }
    };
    let data = std::fs::read(&exe).expect("read current_exe");
    let analysis = unforge_analysis::Analysis::new(&data).expect("parse current_exe");
    let elf = analysis.elf().expect("an ELF file");
    let (text_start, text_end) = {
        let (_, sh) = elf.section_by_name(b".text").expect(".text");
        (sh.addr, sh.addr + sh.size)
    };
    let funcs: Vec<_> = analysis
        .functions()
        .into_iter()
        .filter(|f| {
            f.size > 0
                && f.size <= MAX_FUNCTION_SIZE
                && f.start >= text_start
                && f.start + f.size <= text_end
                && reference.contains_key(&f.start)
        })
        .collect();
    assert!(
        funcs.len() > 100,
        "too few functions in the test executable: {}",
        funcs.len()
    );
    let step = funcs.len().div_ceil(MAX_FUNCTIONS).max(1);

    let mut compared = 0usize;
    let mut insns = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for f in funcs.iter().step_by(step) {
        let name = f.name.as_deref().unwrap_or("?");
        let bytes = function_bytes(elf, f.start, f.size).expect("function bytes");
        assert_eq!(bytes.len() as u64, f.size, "{name}: bytes cut short");
        let ours: Vec<Insn> =
            unforge_disasm::disassemble(bytes, f.start, unforge_disasm::Bitness::B64, usize::MAX);
        let theirs: Vec<(u64, &String)> = reference
            .range(f.start..f.start + f.size)
            .map(|(a, t)| (*a, t))
            .collect();
        compared += 1;
        insns += ours.len();

        let our_addrs: Vec<u64> = ours.iter().map(|i| i.addr).collect();
        let their_addrs: Vec<u64> = theirs.iter().map(|(a, _)| *a).collect();
        if our_addrs != their_addrs {
            failures.push(format!(
                "{name} at {:#x}: instruction boundaries differ (ours {}, objdump {})",
                f.start,
                ours.len(),
                theirs.len()
            ));
            continue;
        }
        let total: u64 = ours.iter().map(|i| u64::from(i.len)).sum();
        if total != f.size {
            failures.push(format!("{name}: lengths sum to {total}, size {}", f.size));
        }
        for (i, (a, t)) in ours.iter().zip(&theirs) {
            let theirs_m = objdump_mnemonic(t);
            assert!(!normalize(&theirs_m).is_empty(), "{name} at {a:#x}: `{t}`");
            if normalize(&i.mnemonic) != normalize(&theirs_m) {
                failures.push(format!(
                    "{name} at {a:#x}: ours `{} {}`, objdump `{t}`",
                    i.mnemonic, i.operands
                ));
            }
            if theirs_m == "(bad)" {
                assert_eq!(i.flow, Flow::Invalid, "{name} at {a:#x}");
            }
        }
    }
    eprintln!(
        "objdump oracle: compared {compared} functions, {insns} instructions, {} mismatches",
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "{} mismatches, first ones:\n{}",
        failures.len(),
        failures
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

//! `unforge disasm`: x86 / x86-64 disassembly of recovered functions.
//!
//! One block per function: a header line with its address and name, then
//! one line per instruction:
//!
//! ```text
//! 0000000000401000:  55                             push rbp
//! 0000000000401001:  e8 1a 00 00 00                 call 0x401020  ; -> mytool::run
//! ```
//!
//! Output is bounded: at most [`MAX_MATCHES`] functions, at most `--count`
//! instructions each, and every name is escaped ([`show_name`]) and comes
//! from `unforge-analysis`, which caps names at its `MAX_NAME_LEN`.

use std::collections::BTreeMap;
use std::io::{self, Write};

use unforge_analysis::FunctionGuess;
use unforge_disasm::{Bitness, Insn};

use crate::args::DisasmTarget;

/// At most this many functions are printed for one `--function` pattern.
pub const MAX_MATCHES: usize = 64;

/// Bytes shown in the bytes column before it overflows into the text.
const BYTES_COLUMN: usize = 10;

/// A function name for display. Like `names::escape`, but spaces stay
/// spaces: demangled names contain them (`<T as Trait>::f`), and the name
/// is the last thing on its line, so they cannot break the layout.
pub fn show_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ' ' => out.push(' '),
            c if c.is_control() || c.is_whitespace() => out.extend(c.escape_default()),
            c => out.push(c),
        }
    }
    out
}

/// One function (or address) to disassemble.
pub struct Job {
    pub start: u64,
    /// 0 when unknown.
    pub size: u64,
    pub name: Option<String>,
}

/// What to disassemble for `target`, and how many functions matched in
/// total (more than the jobs when the list was cut at [`MAX_MATCHES`]).
pub fn jobs(target: &DisasmTarget, entry: u64, funcs: &[FunctionGuess]) -> (Vec<Job>, usize) {
    let at = |start: u64| {
        let f = funcs
            .binary_search_by_key(&start, |f| f.start)
            .ok()
            .and_then(|i| funcs.get(i));
        Job {
            start,
            size: f.map_or(0, |f| f.size),
            name: f.and_then(|f| f.name.clone()),
        }
    };
    match target {
        DisasmTarget::Entry => (vec![at(entry)], 1),
        DisasmTarget::Addr(a) => (vec![at(*a)], 1),
        DisasmTarget::Function(pattern) => {
            let matching = funcs.iter().filter(|f| {
                f.name
                    .as_deref()
                    .is_some_and(|n| n.contains(pattern.as_str()))
            });
            let total = matching.clone().count();
            let jobs = matching
                .take(MAX_MATCHES)
                .map(|f| Job {
                    start: f.start,
                    size: f.size,
                    name: f.name.clone(),
                })
                .collect();
            (jobs, total)
        }
    }
}

/// Function names by start address, for `; -> name`.
pub fn name_index(funcs: &[FunctionGuess]) -> BTreeMap<u64, &str> {
    funcs
        .iter()
        .filter_map(|f| f.name.as_deref().map(|n| (f.start, n)))
        .collect()
}

/// Prints one function's header line and instructions.
pub fn print_function<W: Write>(
    out: &mut W,
    job: &Job,
    bytes: &[u8],
    insns: &[Insn],
    bitness: Bitness,
    names_by_start: &BTreeMap<u64, &str>,
) -> io::Result<()> {
    let width = match bitness {
        Bitness::B32 => 8,
        Bitness::B64 => 16,
    };
    let name = job
        .name
        .as_deref()
        .map_or_else(|| "<unknown>".to_owned(), show_name);
    let size = if job.size == 0 {
        "size unknown".to_owned()
    } else {
        format!("{} bytes", job.size)
    };
    writeln!(out, "{:0width$x} <{name}> ({size}):", job.start)?;
    let mut offset = 0usize;
    let mut hex = String::new();
    for i in insns {
        hex.clear();
        let len = usize::from(i.len);
        let raw = bytes.get(offset..offset.saturating_add(len)).unwrap_or(&[]);
        offset = offset.saturating_add(len);
        for (k, b) in raw.iter().enumerate() {
            if k > 0 {
                hex.push(' ');
            }
            hex.push_str(&format!("{b:02x}"));
        }
        let text = if i.operands.is_empty() {
            i.mnemonic.clone()
        } else {
            format!("{} {}", i.mnemonic, i.operands)
        };
        write!(
            out,
            "{:0width$x}:  {hex:<bw$}  {text}",
            i.addr,
            bw = BYTES_COLUMN * 3 - 1
        )?;
        if let Some(n) = i.target.and_then(|t| names_by_start.get(&t)) {
            write!(out, "  ; -> {}", show_name(n))?;
        }
        writeln!(out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_name_keeps_spaces_and_escapes_controls() {
        assert_eq!(show_name("<a as b>::c"), "<a as b>::c");
        assert_eq!(show_name("a\nb\\c\u{85}"), "a\\nb\\\\c\\u{85}");
    }
}

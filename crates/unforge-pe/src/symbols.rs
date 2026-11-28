//! The COFF symbol table and its string table.
//!
//! Images linked by MSVC or lld-link have no symbol table (names are in
//! the PDB), but MinGW's GNU ld and lld in MinGW mode keep one unless the
//! image is stripped, with every function's name. The string table follows
//! the symbols directly: a `u32` size (including itself), then the strings.

use crate::diag::{DiagnosticKind as K, Severity, Sink};
use crate::read::{cstr, u16_at, u32_at, usize_of};
use crate::{MAX_NAME_LEN, MAX_SYMBOLS, PeFile};

/// Size of one `IMAGE_SYMBOL` record.
const SYMBOL_SIZE: usize = 18;

/// One COFF symbol (`IMAGE_SYMBOL`). Auxiliary records are skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoffSymbol<'data> {
    /// The name, from the record or from the string table.
    pub name: &'data [u8],
    /// For a symbol in a section: the offset from the section's start.
    pub value: u32,
    /// 1-based section number; 0 undefined, -1 absolute, -2 debug.
    pub section_number: i16,
    /// `0x20` for functions (`IMAGE_SYM_DTYPE_FUNCTION << 4`).
    pub type_: u16,
    /// `IMAGE_SYM_CLASS_*`: 2 external, 3 static, 6 label, 103 file, ...
    pub storage_class: u8,
}

impl CoffSymbol<'_> {
    /// The symbol is a function (`DTYPE_FUNCTION`).
    pub fn is_function(&self) -> bool {
        (self.type_ >> 4) & 0x3 == 2
    }
}

impl<'data> PeFile<'data> {
    /// The COFF symbols with names (at most [`MAX_SYMBOLS`]).
    pub fn coff_symbols(&self) -> Vec<CoffSymbol<'data>> {
        coff_symbols(self, &mut Sink::quiet())
    }

    /// The RVA of a symbol in a section (`None` for undefined, absolute
    /// and debug symbols, or a section number past the table).
    pub fn symbol_rva(&self, s: &CoffSymbol<'_>) -> Option<u64> {
        let idx = usize::try_from(s.section_number).ok()?.checked_sub(1)?;
        let sec = self.sections().get(idx)?;
        Some(u64::from(sec.virtual_address) + u64::from(s.value))
    }
}

/// The symbol table bytes and the string table bytes after it.
fn tables<'data>(pe: &PeFile<'data>) -> Option<(&'data [u8], &'data [u8], usize)> {
    let c = pe.coff();
    if c.pointer_to_symbol_table == 0 {
        return None;
    }
    let at = usize_of(u64::from(c.pointer_to_symbol_table));
    let declared = usize_of(u64::from(c.number_of_symbols)).min(MAX_SYMBOLS);
    let data = pe.data();
    let rest = data.get(at..)?;
    let n = (rest.len() / SYMBOL_SIZE).min(declared);
    let syms = rest.get(..n * SYMBOL_SIZE)?;
    let strings = if n == declared {
        rest.get(n * SYMBOL_SIZE..).unwrap_or_default()
    } else {
        &[][..]
    };
    let size = usize_of(u64::from(u32_at(strings, 0).unwrap_or(0)));
    let strings = strings.get(..size.min(strings.len())).unwrap_or_default();
    Some((syms, strings, declared))
}

/// The string at `offset` of the COFF string table.
pub(crate) fn string_at<'data>(pe: &PeFile<'data>, offset: u32) -> Option<&'data [u8]> {
    let (_, strings, _) = tables(pe)?;
    let s = strings.get(usize_of(u64::from(offset))..)?;
    let (name, _) = cstr(s, MAX_NAME_LEN);
    (offset >= 4 && !name.is_empty()).then_some(name)
}

fn coff_symbols<'data>(pe: &PeFile<'data>, sink: &mut Sink) -> Vec<CoffSymbol<'data>> {
    let mut out = Vec::new();
    let Some((syms, strings, declared)) = tables(pe) else {
        return out;
    };
    let n = syms.len() / SYMBOL_SIZE;
    if n < declared {
        sink.push(
            Severity::Warning,
            K::SymbolTableTruncated,
            Some(u64::from(pe.coff().pointer_to_symbol_table)),
            || format!("the COFF symbol table declares {declared} records, {n} fit in the file"),
        );
    }
    let mut i = 0usize;
    while i < n {
        let o = i * SYMBOL_SIZE;
        let Some(r) = syms.get(o..o + SYMBOL_SIZE) else {
            break;
        };
        let aux = usize::from(r.get(17).copied().unwrap_or(0));
        let name = if r.get(..4) == Some(&[0, 0, 0, 0]) {
            let off = usize_of(u64::from(u32_at(r, 4).unwrap_or(0)));
            strings
                .get(off..)
                .filter(|_| off >= 4)
                .map(|s| cstr(s, MAX_NAME_LEN).0)
                .unwrap_or_default()
        } else {
            cstr(r.get(..8).unwrap_or_default(), 8).0
        };
        if !name.is_empty() {
            out.push(CoffSymbol {
                name,
                value: u32_at(r, 8).unwrap_or(0),
                section_number: u16_at(r, 12).unwrap_or(0) as i16,
                type_: u16_at(r, 14).unwrap_or(0),
                storage_class: r.get(16).copied().unwrap_or(0),
            });
        }
        i = i.saturating_add(1 + aux);
    }
    out
}

pub(crate) fn audit(pe: &PeFile<'_>, sink: &mut Sink) {
    let _ = coff_symbols(pe, sink);
}

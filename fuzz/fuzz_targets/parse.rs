//! Drive every public API of `unforge-elf` on arbitrary bytes.
//! The only property checked is "no panic, no abort, bounded memory"
//! (libFuzzer's -rss_limit_mb / -malloc_limit_mb catch the latter).
#![no_main]

use libfuzzer_sys::fuzz_target;
use unforge_elf::{ElfFile, SymbolTable};

/// Symbols visited per input, across all tables: overlapping tables may
/// declare far more symbols than the input holds, and visiting all of them is
/// allowed but slow. The bound keeps each run short.
const MAX_SYMBOLS: usize = 1 << 16;

fn visit(t: &SymbolTable<'_>, budget: &mut usize) -> usize {
    let mut n = t.section_index ^ t.strtab().map_or(0, <[u8]>::len) ^ t.len();
    n ^= t.trailing_bytes() as usize ^ t.entry_size() ^ t.declared_len() as usize;
    let _ = t.get(t.len().wrapping_sub(1));
    let _ = t.get(usize::MAX);
    for sym in t.iter() {
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        n ^= usize::from(sym.bind()) ^ usize::from(sym.kind()) ^ usize::from(sym.visibility());
        n ^= format!("{:?}", sym.section).len();
        match t.name(&sym) {
            Ok(name) => n ^= name.len(),
            Err(e) => n ^= e.to_string().len(),
        }
        for max in [0, 1, 64] {
            match t.name_bounded(&sym, max) {
                Ok(name) => n ^= name.bytes.len() ^ usize::from(name.truncated),
                Err(e) => n ^= e.to_string().len(),
            }
        }
    }
    n
}

fuzz_target!(|data: &[u8]| {
    for host in [62, 183, 3] {
        let p = ElfFile::kernel_prediction_for(data, host);
        std::hint::black_box(p.to_string());
    }
    let elf = match ElfFile::parse(data) {
        Ok(elf) => elf,
        Err(e) => {
            let _ = e.to_string();
            return;
        }
    };
    let mut acc = elf.data().len() ^ format!("{:?}", elf.header()).len();
    acc ^= format!("{:?}", elf.layout()).len();
    if let Some(i) = elf.layout().inference() {
        acc ^= i.to_string().len();
    }
    if let Ok(phs) = elf.program_headers() {
        let _ = phs.get(phs.len());
        for ph in phs.iter().rev() {
            if let Ok(d) = elf.segment_data(&ph) {
                acc ^= d.len();
            }
            acc ^= elf.segment_bytes(&ph).missing as usize;
        }
    }
    let shnum = elf.section_headers().map(|s| s.len()).unwrap_or(0);
    let _ = elf.section_name_table().map(|t| t.len());
    for i in (0..shnum + 2).chain([usize::MAX]) {
        let Ok(sh) = elf.section_header(i) else {
            continue;
        };
        if let Ok(d) = elf.section_data(&sh) {
            acc ^= d.len();
        }
        match elf.section_name_bounded(&sh, 16) {
            Ok(name) => acc ^= name.bytes.len() ^ usize::from(name.truncated),
            Err(e) => acc ^= e.to_string().len(),
        }
        match elf.section_name(&sh) {
            // section_by_name is O(shnum): only for a prefix.
            Ok(name) if i < 16 => acc ^= elf.section_by_name(name).map_or(0, |(i, _)| i),
            Ok(name) => acc ^= name.len(),
            Err(e) => acc ^= e.to_string().len(),
        }
    }
    for name in [&b".text"[..], b".symtab", b"", b".nope"] {
        acc ^= elf.section_by_name(name).map_or(0, |(i, _)| i);
    }
    let mut budget = MAX_SYMBOLS;
    for i in (0..shnum.min(64) + 2).chain([usize::MAX]) {
        match elf.symbol_table(i) {
            Ok(t) => acc ^= visit(&t, &mut budget),
            Err(e) => acc ^= e.to_string().len(),
        }
    }
    match elf.symbol_tables() {
        Ok(ts) => ts.for_each(|t| acc ^= visit(&t, &mut budget)),
        Err(e) => acc ^= e.to_string().len(),
    }
    let map = elf.memory_map();
    acc ^= map.iter().count() ^ map.overrides().count();
    acc ^= format!("{:?}", map.backing(elf.header().entry)).len();
    acc ^= map.regions().filter(|r| r.flags & 1 != 0).count();
    acc ^= map
        .bytes_at(data, elf.header().entry)
        .map_or(0, <[u8]>::len);
    for page in [1, 65536] {
        let m = elf.memory_map_with_page_size(page);
        acc ^= m.iter().count() ^ usize::from(m.backing_ref(elf.header().entry).is_some());
    }
    match elf.dynamic_with(&map) {
        Ok(d) => {
            acc ^= d.iter().count() ^ d.len();
            match elf.dynamic_symbols_with(&map, &d) {
                Ok(ds) => {
                    for s in ds.iter().take(budget) {
                        acc ^= ds.name_bounded(&s, 64).map_or(0, |n| n.bytes.len());
                    }
                }
                Err(e) => acc ^= e.to_string().len(),
            }
        }
        Err(e) => acc ^= e.to_string().len(),
    }
    acc ^= elf.section_by_name(b".text").map_or(0, |(i, _)| i);
    let audit = elf.audit();
    for d in &audit.diagnostics {
        acc ^= d.to_string().len() ^ d.kind.name().len();
    }
    acc ^= usize::from(audit.ambiguous) ^ usize::from(audit.inferred);
    std::hint::black_box(acc);
});

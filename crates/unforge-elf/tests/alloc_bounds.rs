//! Memory bound of the lazy views, measured with a counting global allocator.
//!
//! The file below declares 1000 `SHT_SYMTAB` sections over the same 64 KiB
//! (gABI ch4 "Sections": "Sections in a file may not overlap", but nothing
//! stops a file from declaring it). Reading every symbol of every table
//! visits 1000 * 2730 symbols; collecting them would need about
//! 2.7 M * size_of::<Symbol>() bytes. The views must need O(1) memory beyond
//! the input instead.
//!
//! `dhat` provides the counting allocator; implementing `GlobalAlloc` here
//! would need `unsafe`, which the workspace forbids. dhat counts the whole
//! process, so this file holds a single test (no other test thread runs).

use unforge_elf::consts::*;
use unforge_elf::{DiagnosticKind, ElfFile, Symbol};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const TABLES: usize = 1000;
const COVERED: usize = 64 * 1024;
const SYM: usize = 24;

fn put(b: &mut [u8], off: usize, v: &[u8]) {
    b[off..off + v.len()].copy_from_slice(v);
}

/// ELF64 LSB `ET_REL` with: [0] null, [1] a string table, [2..] `TABLES`
/// symbol tables that all cover the same `COVERED` bytes. Every symbol's
/// name is "f" (offset 1 of the string table).
fn overlapping_symtabs() -> Vec<u8> {
    let strtab_off = 64usize;
    let strtab = b"\0f\0";
    let syms_off = 128usize;
    let shoff = syms_off + COVERED;
    let nsect = TABLES + 2;
    let mut b = vec![0u8; shoff + nsect * 64];
    put(&mut b, 0, &ELFMAG);
    b[4] = ELFCLASS64;
    b[5] = ELFDATA2LSB;
    b[6] = EV_CURRENT;
    put(&mut b, 16, &ET_REL.to_le_bytes());
    put(&mut b, 18, &EM_X86_64.to_le_bytes());
    put(&mut b, 20, &1u32.to_le_bytes());
    put(&mut b, 40, &(shoff as u64).to_le_bytes());
    put(&mut b, 52, &64u16.to_le_bytes());
    put(&mut b, 58, &64u16.to_le_bytes());
    put(&mut b, 60, &(nsect as u16).to_le_bytes());
    put(&mut b, strtab_off, strtab);
    for i in 0..COVERED / SYM {
        put(&mut b, syms_off + i * SYM, &1u32.to_le_bytes()); // st_name
        b[syms_off + i * SYM + 4] = (STB_GLOBAL << 4) | STT_FUNC;
    }
    let s1 = shoff + 64;
    put(&mut b, s1 + 4, &SHT_STRTAB.to_le_bytes());
    put(&mut b, s1 + 24, &(strtab_off as u64).to_le_bytes());
    put(&mut b, s1 + 32, &(strtab.len() as u64).to_le_bytes());
    for i in 2..nsect {
        let s = shoff + i * 64;
        put(&mut b, s + 4, &SHT_SYMTAB.to_le_bytes());
        put(&mut b, s + 24, &(syms_off as u64).to_le_bytes());
        put(&mut b, s + 32, &(COVERED as u64).to_le_bytes());
        put(&mut b, s + 40, &1u32.to_le_bytes()); // sh_link -> [1]
        put(&mut b, s + 56, &(SYM as u64).to_le_bytes());
    }
    b
}

#[test]
fn reading_1000_overlapping_symbol_tables_needs_constant_memory() {
    // The input is built before profiling starts: only what the reader
    // allocates is counted.
    let data = overlapping_symtabs();
    let _profiler = dhat::Profiler::builder().testing().build();

    // 1. parse: no allocation at all.
    let before = dhat::HeapStats::get();
    let elf = ElfFile::parse(&data).expect("parse");
    let after = dhat::HeapStats::get();
    eprintln!(
        "parse: {} blocks, {} bytes",
        after.total_blocks - before.total_blocks,
        after.total_bytes - before.total_bytes
    );
    assert_eq!(
        after.total_blocks - before.total_blocks,
        0,
        "parse allocated"
    );

    // 2. Every symbol of every table, with its name.
    let base = dhat::HeapStats::get();
    let mut tables = 0usize;
    let mut symbols = 0usize;
    let mut name_bytes = 0usize;
    for t in elf.symbol_tables().expect("tables") {
        tables += 1;
        for s in t.iter() {
            symbols += 1;
            name_bytes += t.name(&s).expect("name").len();
        }
        // Random access too.
        let last = t.get(t.len() - 1).expect("last symbol");
        assert_eq!(last.kind(), STT_FUNC);
    }
    let walk = dhat::HeapStats::get();
    assert_eq!(tables, TABLES);
    assert_eq!(symbols, TABLES * (COVERED / SYM));
    assert_eq!(name_bytes, symbols);
    let extra_peak = walk.max_bytes.saturating_sub(base.curr_bytes);
    let blocks = walk.total_blocks - base.total_blocks;
    let materialized = symbols * size_of::<Symbol>();
    eprintln!(
        "listing {symbols} symbols of {tables} tables: {blocks} allocations, peak extra {extra_peak} bytes \
         (collecting them would need {materialized} bytes)"
    );
    assert_eq!(blocks, 0, "listing symbols allocated");
    assert!(
        extra_peak <= 1024,
        "peak extra allocation {extra_peak} bytes"
    );

    // 3. The audit allocates per section, not per symbol, and reports the
    //    overlap (bounded).
    let base = dhat::HeapStats::get();
    let audit = elf.audit();
    let done = dhat::HeapStats::get();
    let audit_peak = done.max_bytes.saturating_sub(base.curr_bytes);
    eprintln!(
        "audit: peak extra {audit_peak} bytes, {} diagnostics",
        audit.diagnostics.len()
    );
    assert!(
        audit_peak < 1 << 20,
        "audit peak {audit_peak} bytes for {TABLES} tables"
    );
    assert!(audit_peak < materialized / 50);
    assert!(
        audit
            .diagnostics
            .iter()
            .any(|d| matches!(d.kind, DiagnosticKind::DuplicateTable { same_as: 2, .. }))
    );
    assert!(audit.diagnostics.len() <= 64, "{}", audit.diagnostics.len());
}

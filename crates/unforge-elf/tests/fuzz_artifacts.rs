//! Replays every input in tests/data/fuzz-artifacts (inputs that once made a
//! fuzz target abort) through the whole API, and checks the invariant R-2 was
//! about: every symbol table, duplicate or not, that is read with an
//! unexpected or inferred entry size is reported.

use std::path::PathBuf;

use unforge_elf::{Class, DiagnosticKind, ElfFile, InferenceSubject, MAX_DIAGNOSTICS_PER_KIND};

#[test]
fn fuzz_artifacts_are_read_and_reported() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/fuzz-artifacts");
    let mut n = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        if !p
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("crash-")
        {
            continue;
        }
        n += 1;
        let data = std::fs::read(&p).unwrap();
        let Ok(elf) = ElfFile::parse(&data) else {
            continue;
        };
        let audit = elf.audit();
        let _ = elf.memory_map().regions().count();
        let _ = elf.dynamic_symbols().map(|d| d.len());
        let Ok(tables) = elf.symbol_tables() else {
            continue;
        };
        let size = match elf.header().class {
            Class::Elf32 => 16,
            _ => 24,
        };
        let odd: Vec<_> = tables
            .clone()
            .filter(|t| t.section_header().entsize != size)
            .collect();
        if odd.len() <= MAX_DIAGNOSTICS_PER_KIND {
            for t in &odd {
                let i = t.section_index;
                assert!(
                    audit.diagnostics.iter().any(|d| matches!(d.kind, DiagnosticKind::SymbolEntrySize { table, .. } if table == i)),
                    "{}: table [{i}] has sh_entsize {} but no SymbolEntrySize",
                    p.display(),
                    t.section_header().entsize
                );
            }
        }
        let inferred: Vec<_> = tables.filter(|t| t.entry_size_inferred()).collect();
        if inferred.len() <= MAX_DIAGNOSTICS_PER_KIND {
            for t in &inferred {
                let i = t.section_index;
                assert!(
                    audit
                        .inferences()
                        .any(|x| x.subject == InferenceSubject::SymbolEntrySize { table: i }),
                    "{}: table [{i}] stride inferred silently",
                    p.display()
                );
            }
        }
    }
    assert!(n >= 100, "only {n} artifacts found in {}", dir.display());
}

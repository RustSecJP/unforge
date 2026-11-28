//! The report Mekiki shows, on real and broken inputs.

use std::path::Path;

use unforge_report::{FoundIn, REPORT_VERSION, is_crate_name, report, report_json};

/// This test binary itself: a real Rust executable that links serde_json.
fn own_exe() -> Vec<u8> {
    std::fs::read(std::env::current_exe().unwrap()).unwrap()
}

#[test]
fn real_rust_binary() {
    let r = report(&own_exe()).unwrap();
    assert_eq!(r.version, REPORT_VERSION);
    assert!(r.file.class.starts_with("ELF"));
    assert!(r.file.size > 0);
    assert!(r.functions.total > 0);
    assert!(r.functions.std > 0, "std functions should be recognized");
    assert_eq!(
        r.functions.total,
        r.functions.user + r.functions.dependency + r.functions.std + r.functions.unknown
    );
    // serde_json is compiled in from the registry, so its source path (with
    // the version) is in the file.
    let sj = r
        .crates
        .iter()
        .find(|c| c.name == "serde_json")
        .expect("serde_json listed");
    assert!(sj.version.is_some());
    assert_ne!(sj.found_in, FoundIn::Symbols);
    // serde's derives put functions in `const _: () = { .. }`; `_` is not a crate.
    assert!(
        r.crates.iter().all(|c| is_crate_name(&c.name)),
        "{:?}",
        r.crates
    );
    // `rustc` is not a crate row; it goes to rustc_commit.
    assert!(r.crates.iter().all(|c| c.name != "rustc"));
    // sorted by name
    let names: Vec<String> = r.crates.iter().map(|c| c.name.replace('-', "_")).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
}

#[test]
fn json_has_the_fields_the_ui_reads() {
    let v: serde_json::Value = serde_json::from_str(&report_json(&own_exe())).unwrap();
    for key in [
        "version",
        "file",
        "rustc_commit",
        "functions",
        "crates",
        "warnings",
        "warnings_omitted",
    ] {
        assert!(v.get(key).is_some(), "missing {key}");
    }
    assert!(v["file"]["machine"].is_string());
}

#[test]
fn not_an_elf_file() {
    for data in [&b""[..], b"hello", b"\x7fELF", &[0u8; 64][..]] {
        let v: serde_json::Value = serde_json::from_str(&report_json(data)).unwrap();
        assert!(v["error"].is_string(), "{data:?} -> {v}");
        assert_eq!(v["version"], REPORT_VERSION);
    }
}

#[test]
fn broken_files_never_panic() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/anomalous/files");
    let mut n = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let data = std::fs::read(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&report_json(&data)).unwrap();
        assert!(
            v.get("error").is_some() || v.get("file").is_some(),
            "{}",
            path.display()
        );
        n += 1;
    }
    assert!(n > 0, "no files in {}", dir.display());
}

#[test]
fn crate_names() {
    for ok in ["serde", "serde_json", "regex-automata", "_private", "a1"] {
        assert!(is_crate_name(ok), "{ok}");
    }
    for bad in ["", "_", "1abc", "<impl", "a b", "foo::bar"] {
        assert!(!is_crate_name(bad), "{bad}");
    }
}

#[test]
fn lists_functions_sections_and_segments() {
    let r = report(&own_exe()).unwrap();
    assert_eq!(
        r.function_rows.len() + r.functions_omitted,
        r.functions.total
    );
    assert!(
        r.function_rows.windows(2).all(|w| w[0].start < w[1].start),
        "sorted, one per address"
    );
    assert!(
        r.function_rows
            .iter()
            .any(|f| f.owner.as_deref() == Some("std"))
    );
    assert!(
        r.function_rows
            .iter()
            .all(|f| f.owner.as_deref() != Some("dep:_"))
    );

    let text = r
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .expect(".text");
    assert_eq!(text.kind, "PROGBITS");
    assert!(text.flags.contains('A') && text.flags.contains('X'));
    assert!(!text.nobits);
    assert!(r.sections.iter().any(|s| s.name == ".bss" && s.nobits));
    assert_eq!(r.sections.len() as u64, r.file.sections);

    assert!(
        r.segments
            .iter()
            .any(|p| p.kind == "LOAD" && p.flags == "R-E")
    );
    assert_eq!(r.segments.len() as u64, r.file.segments);
}

//! Functions and dependencies of PE images: hand-built ones
//! (`unforge_pe::synth`) and, when `testdata/pe/build.sh` has been run,
//! real Rust PE files checked against the linker's map.

use std::collections::BTreeMap;
use std::path::PathBuf;

use unforge_analysis::{Analysis, DependencyGuess, Format};
use unforge_pe::synth::{SAMPLE_RUSTC_COMMIT, sample};

#[test]
fn synthetic_functions() {
    let s = sample(true, false);
    let a = Analysis::new(&s.bytes).unwrap();
    assert_eq!(a.image().format(), Format::Pe);
    assert!(a.elf().is_none());
    let base = s.image_base;
    let f: Vec<(u64, u64)> = a.functions().iter().map(|f| (f.start, f.size)).collect();
    // .pdata gives main, helper and the TLS callback with sizes; the
    // chained fragment is not a function; `leaf` has no unwind entry.
    assert_eq!(
        f,
        vec![
            (base + u64::from(s.main.0), u64::from(s.main.1)),
            (base + u64::from(s.helper.0), u64::from(s.helper.1)),
            (base + u64::from(s.tls_callback), 1),
        ]
    );
    // x86: no .pdata; the entry point and the TLS callback remain.
    let s = sample(false, false);
    let a = Analysis::new(&s.bytes).unwrap();
    let f: Vec<u64> = a.functions().iter().map(|f| f.start).collect();
    let base = s.image_base;
    assert_eq!(
        f,
        vec![base + u64::from(s.main.0), base + u64::from(s.tls_callback)]
    );
}

#[test]
fn synthetic_exports_are_named() {
    let s = sample(true, true);
    let a = Analysis::new(&s.bytes).unwrap();
    let helper = s.image_base + u64::from(s.helper.0);
    let f = a.functions();
    let h = f.iter().find(|f| f.start == helper).unwrap();
    assert_eq!(h.name.as_deref(), Some("helper"));
    assert_eq!(h.size, u64::from(s.helper.1));
}

#[test]
fn synthetic_dependencies() {
    for p in [true, false] {
        let s = sample(p, false);
        let deps = Analysis::new(&s.bytes).unwrap().dependencies();
        assert_eq!(
            deps,
            vec![
                DependencyGuess {
                    name: "fakecrate".into(),
                    version: Some("1.2.3".into())
                },
                DependencyGuess {
                    name: "rustc".into(),
                    version: Some(SAMPLE_RUSTC_COMMIT.into())
                },
            ]
        );
    }
}

#[test]
fn truncated_images_never_panic() {
    let s = sample(true, true);
    for n in (0..s.bytes.len()).step_by(7) {
        if let Ok(a) = Analysis::new(&s.bytes[..n]) {
            let _ = a.functions();
            let _ = a.dependencies();
        }
    }
}

/// `Publics by Value` of a lld-link map: address -> mangled names.
fn map_symbols(map: &str) -> BTreeMap<u64, Vec<String>> {
    let mut out: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for line in map.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.len() < 3 || !t[0].contains(':') || t[2].len() < 8 {
            continue;
        }
        if let Ok(addr) = u64::from_str_radix(t[2], 16) {
            out.entry(addr).or_default().push(t[1].to_owned());
        }
    }
    out
}

#[test]
fn real_pe_files() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pe/bin");
    let mut seen = 0;
    for target in ["x86_64-pc-windows-msvc", "i686-pc-windows-msvc"] {
        for f in ["winapp-O0.exe", "winapp-O2.exe", "windll.dll"] {
            let p = dir.join(target).join(f);
            let Ok(data) = std::fs::read(&p) else {
                continue;
            };
            seen += 1;
            let map = map_symbols(&std::fs::read_to_string(p.with_extension("map")).unwrap());
            let a = Analysis::new(&data).unwrap();
            let funcs = a.functions();
            let deps = a.dependencies();
            // The dependency, with its version, from the Windows registry
            // path; the toolchain from /rustc/<commit>/library\...
            assert!(
                deps.iter()
                    .any(|d| d.name == "fakedep" && d.version.as_deref() == Some("1.2.3")),
                "{}: {deps:?}",
                p.display()
            );
            assert!(deps.iter().any(|d| d.name == "rustc"), "{deps:?}");
            let in_map = funcs.iter().filter(|f| map.contains_key(&f.start)).count();
            if target.starts_with("x86_64") {
                // .pdata: hundreds of functions, nearly all at map symbols.
                assert!(funcs.len() > 200, "{}: {}", p.display(), funcs.len());
                assert!(
                    in_map * 100 >= funcs.len() * 95,
                    "{in_map} / {}",
                    funcs.len()
                );
                // The program's main has a .pdata entry with its size.
                if f.starts_with("winapp") {
                    let (&main, _) = map
                        .iter()
                        .find(|(_, n)| n.iter().any(|n| n.ends_with("6winapp4main")))
                        .unwrap();
                    let m = funcs.iter().find(|f| f.start == main).unwrap();
                    assert!(m.size > 16);
                }
            } else {
                // x86 has no unwind table: only the entry point, the TLS
                // callback and the exports.
                assert!(!funcs.is_empty() && funcs.len() <= 4, "{funcs:?}");
                assert_eq!(in_map, funcs.len());
            }
            if f == "windll.dll" {
                let named: Vec<&str> = funcs.iter().filter_map(|f| f.name.as_deref()).collect();
                assert_eq!(named, vec!["windll_count_words", "windll_version"]);
            }
        }
    }
    if seen == 0 {
        eprintln!("skipped: run testdata/pe/build.sh to build the PE corpus");
    }
}

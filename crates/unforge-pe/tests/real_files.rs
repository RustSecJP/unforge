//! The reader against real Rust PE files built by `testdata/pe/build.sh`,
//! with the linker's `/MAP` file as the ground truth. Skipped (with a
//! message) when the files have not been built.

use std::collections::BTreeMap;
use std::path::PathBuf;

use unforge_pe::{ImportKind, PeFile};

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pe/bin")
}

/// The files of the corpus: (path of the image, its map).
fn corpus() -> Vec<(PathBuf, PathBuf)> {
    let mut out = Vec::new();
    for target in ["x86_64-pc-windows-msvc", "i686-pc-windows-msvc"] {
        for f in ["winapp-O0.exe", "winapp-O2.exe", "windll.dll"] {
            let p = dir().join(target).join(f);
            if p.exists() {
                out.push((p.clone(), p.with_extension("map")));
            }
        }
    }
    if out.is_empty() {
        eprintln!("skipped: run testdata/pe/build.sh to build the PE corpus");
    }
    out
}

/// `Publics by Value` of a lld-link map: address -> names.
pub fn map_symbols(map: &str) -> BTreeMap<u64, Vec<String>> {
    let mut out: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for line in map.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.len() < 3 || !t[0].contains(':') {
            continue;
        }
        let Ok(addr) = u64::from_str_radix(t[2], 16) else {
            continue;
        };
        if t[2].len() < 8 {
            continue;
        }
        out.entry(addr).or_default().push(t[1].to_owned());
    }
    out
}

#[test]
fn pdata_starts_are_functions() {
    for (exe, map) in corpus() {
        let data = std::fs::read(&exe).unwrap();
        let pe = PeFile::parse(&data).unwrap();
        let syms = map_symbols(&std::fs::read_to_string(&map).unwrap());
        assert!(syms.len() > 100, "{}", map.display());
        let base = pe.image_base();
        let rf = pe.runtime_functions();
        if pe.machine() != unforge_pe::MACHINE_AMD64 {
            assert!(rf.is_empty());
            continue;
        }
        assert!(rf.len() > 100, "{}: {} entries", exe.display(), rf.len());
        let named = rf
            .iter()
            .filter(|r| !r.chained && syms.contains_key(&(base + u64::from(r.begin))))
            .count();
        // Every unwind entry starts at a public symbol, except the few
        // functions the linker or LLVM split (`.text$unlikely` parts).
        assert!(
            named * 100 >= rf.len() * 95,
            "{}: {named} of {} .pdata starts are map symbols",
            exe.display(),
            rf.len()
        );
    }
}

#[test]
fn imports_tls_codeview() {
    for (exe, map) in corpus() {
        let data = std::fs::read(&exe).unwrap();
        let pe = PeFile::parse(&data).unwrap();
        let syms = map_symbols(&std::fs::read_to_string(&map).unwrap());
        let imps = pe.imports();
        let k32 = imps
            .iter()
            .find(|d| d.name.eq_ignore_ascii_case(b"kernel32.dll"))
            .unwrap();
        assert!(k32.entries.iter().any(|e| matches!(
            e.kind,
            ImportKind::Name {
                name: b"CreateFileW",
                ..
            }
        )));
        // Every IAT slot lies in the image's file bytes.
        for (slot, _) in pe.iat_names() {
            assert!(pe.rva_to_offset(u64::from(slot)).is_some());
        }
        let cv = pe.codeview().unwrap();
        assert!(cv.path.ends_with(b".pdb"));
        let tls = pe.tls().unwrap();
        if exe.to_string_lossy().contains("winapp") {
            // The program's own TLS callback (`on_tls`).
            assert_eq!(tls.callbacks.len(), 1, "{}", exe.display());
            let names = syms.get(&tls.callbacks[0]).unwrap();
            assert!(names.iter().any(|n| n.contains("on_tls")), "{names:?}");
            assert!(pe.exports().is_none());
        } else {
            let e = pe.exports().unwrap();
            let names: Vec<&[u8]> = e.entries.iter().filter_map(|x| x.name).collect();
            assert_eq!(names, vec![&b"windll_count_words"[..], b"windll_version"]);
            for x in &e.entries {
                assert!(pe.is_executable_rva(u64::from(x.rva)));
            }
        }
        // The relocations all patch words inside the image.
        let n = pe.relocations().count();
        assert!(n > 0);
        assert!(
            pe.relocations()
                .all(|r| pe.rva_to_offset(r.rva).is_some() || pe.region_at(r.rva).is_some())
        );
        let worst = pe.diagnostics().into_iter().map(|d| d.severity).max();
        assert!(
            worst <= Some(unforge_pe::Severity::Info),
            "{}: {:?}",
            exe.display(),
            pe.diagnostics()
        );
    }
}

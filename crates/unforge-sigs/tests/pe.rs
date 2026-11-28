//! Fingerprints of PE images: the hand-built sample (`unforge_pe::synth`)
//! and, when `testdata/pe/build.sh` has been run, real Rust PE files. The
//! names of the real files come from the linker's map (MSVC-style images
//! keep their names only in the PDB).

use std::collections::BTreeMap;
use std::path::PathBuf;

use unforge_analysis::Analysis;
use unforge_pe::synth::{SynthPe, sample};
use unforge_sigs::{
    Db, Fingerprinter, MatchStatus, Options, SigName, function_starts, generic_base, match_elf,
};

#[test]
fn starts_include_call_targets() {
    let s = sample(true, false);
    let a = Analysis::new(&s.bytes).unwrap();
    let fpr = Fingerprinter::new(a.image()).unwrap();
    let starts: Vec<u64> = function_starts(&a, &fpr).iter().map(|f| f.start).collect();
    // `leaf` has no .pdata entry; it is found as the target of a call.
    assert!(
        starts.contains(&(s.image_base + u64::from(s.leaf))),
        "{starts:x?}"
    );
    assert!(starts.contains(&(s.image_base + u64::from(s.main.0))));
}

#[test]
fn fingerprints_do_not_depend_on_the_image_base() {
    let s = sample(true, false);
    let main = (s.image_base + u64::from(s.main.0), u64::from(s.main.1));
    let a = Analysis::new(&s.bytes).unwrap();
    let fp = Fingerprinter::new(a.image())
        .unwrap()
        .fingerprint(main.0, main.1)
        .unwrap();
    // The same image at another preferred base (x64 code is RIP-relative).
    let mut moved = s.bytes.clone();
    let at = SynthPe::PE_OFFSET + 24 + 24;
    let base = 0x7ff6_0000_0000u64;
    moved[at..at + 8].copy_from_slice(&base.to_le_bytes());
    let b = Analysis::new(&moved).unwrap();
    let fp2 = Fingerprinter::new(b.image())
        .unwrap()
        .fingerprint(base + u64::from(s.main.0), main.1)
        .unwrap();
    assert_eq!(fp, fp2);
    // And a database built from one names the other.
    let mut db = Db::new(Options::NONE);
    db.insert(
        fp,
        SigName {
            name: "synth::main".into(),
            krate: Some("synth".into()),
        },
    );
    let m = match_elf(&db, &moved).unwrap();
    let hit = m
        .iter()
        .find(|m| m.start == base + u64::from(s.main.0))
        .unwrap();
    assert_eq!(hit.status, MatchStatus::Unique);
    assert_eq!(hit.names[0].name, "synth::main");
}

#[test]
fn x86_images_fingerprint_too() {
    let s = sample(false, false);
    let a = Analysis::new(&s.bytes).unwrap();
    let fpr = Fingerprinter::new(a.image()).unwrap();
    let main = s.image_base + u64::from(s.main.0);
    let lines = fpr.normalized_lines(main, u64::from(s.main.1));
    // `push offset hello` and `call [IAT slot]`: absolute addresses masked.
    assert!(lines.iter().any(|l| l == "push A"), "{lines:?}");
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("call") && l.contains('A')),
        "{lines:?}"
    );
}

/// `Publics by Value` of a lld-link map: address -> demangled name.
fn map_names(map: &str) -> BTreeMap<u64, String> {
    let mut out = BTreeMap::new();
    for line in map.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.len() < 3 || !t[0].starts_with("0001:") || t[2].len() < 8 {
            continue;
        }
        let Ok(addr) = u64::from_str_radix(t[2], 16) else {
            continue;
        };
        let raw = t[1].trim_start_matches('_');
        let raw = raw.rsplit_once('@').map_or(raw, |(n, _)| n);
        let name = rustc_demangle::try_demangle(&format!("_{raw}"))
            .map(|d| format!("{d:#}"))
            .unwrap_or_else(|_| t[1].to_owned());
        out.entry(addr).or_insert(name);
    }
    out
}

/// A database from the functions of `data`, named by its map.
fn db_from(data: &[u8], names: &BTreeMap<u64, String>) -> Db {
    let a = Analysis::new(data).unwrap();
    let fpr = Fingerprinter::new(a.image()).unwrap();
    let mut db = Db::new(Options::default());
    for f in function_starts(&a, &fpr) {
        let (Some(name), Some(fp)) = (names.get(&f.start), fpr.fingerprint(f.start, f.size)) else {
            continue;
        };
        if Options::default().keeps(fp) {
            let krate = unforge_analysis::names::crate_of_demangled(name)
                .map(unforge_analysis::names::normalize_crate);
            db.insert(
                fp,
                SigName {
                    name: name.clone(),
                    krate,
                },
            );
        }
    }
    db
}

/// (named, correct, functions of `b` whose name the database has).
fn score(
    db: &Db,
    a_names: &BTreeMap<u64, String>,
    b: &[u8],
    b_names: &BTreeMap<u64, String>,
) -> (usize, usize, usize) {
    let known: std::collections::BTreeSet<&String> = a_names.values().collect();
    let (mut named, mut ok, mut possible) = (0, 0, 0);
    for m in match_elf(db, b).unwrap() {
        let Some(truth) = b_names.get(&m.start) else {
            continue;
        };
        if known.contains(truth)
            && m.status != MatchStatus::TooSmall
            && m.status != MatchStatus::Unreadable
        {
            possible += 1;
        }
        match m.status {
            MatchStatus::Unique => {
                named += 1;
                ok += usize::from(&m.names[0].name == truth);
            }
            MatchStatus::SameGeneric => {
                named += 1;
                ok += usize::from(generic_base(&m.names[0].name) == generic_base(truth));
            }
            _ => {}
        }
    }
    (named, ok, possible)
}

#[test]
fn real_pe_files() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pe/bin");
    let mut seen = 0;
    for target in ["x86_64-pc-windows-msvc", "i686-pc-windows-msvc"] {
        let read = |f: &str| -> Option<(Vec<u8>, BTreeMap<u64, String>)> {
            let p = dir.join(target).join(f);
            let data = std::fs::read(&p).ok()?;
            let map = std::fs::read_to_string(p.with_extension("map")).ok()?;
            Some((data, map_names(&map)))
        };
        let (Some((a, a_names)), Some((b, b_names))) = (read("winapp-O2.exe"), read("windll.dll"))
        else {
            continue;
        };
        seen += 1;
        let db = db_from(&a, &a_names);
        // Same file: every function named is named correctly.
        let (named, ok, possible) = score(&db, &a_names, &a, &a_names);
        eprintln!("{target} winapp-O2 -> itself: {ok}/{named} correct, {possible} possible");
        assert!(named > 0 && ok * 100 >= named * 98, "{ok}/{named}");
        // Another program with the same std: most of std is found again.
        let (named, ok, possible) = score(&db, &a_names, &b, &b_names);
        eprintln!("{target} winapp-O2 -> windll: {ok}/{named} correct, {possible} possible");
        assert!(named > 0 && ok * 100 >= named * 90, "{ok}/{named}");
        if target.starts_with("x86_64") {
            assert!(ok * 2 >= possible, "recall {ok}/{possible}");
        }
    }
    if seen == 0 {
        eprintln!("skipped: run testdata/pe/build.sh to build the PE corpus");
    }
}

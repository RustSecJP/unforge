//! The report, code map, disassembly, decompiler setup and comments for PE
//! images: the hand-built sample (`unforge_pe::synth`) and, when
//! `testdata/pe/build.sh` has been run, real Rust PE files.

use std::path::PathBuf;

use unforge_pe::synth::{SAMPLE_RUSTC_COMMIT, sample};
use unforge_report::code::{annotate, code_map_for, disasm_at, parse_code_map};
use unforge_report::setup::decompiler_setup_for;
use unforge_report::{report, report_json, report_with_signatures};

#[test]
fn summary_sections_imports() {
    for (p, dll) in [(true, false), (true, true), (false, false)] {
        let s = sample(p, dll);
        let r = report(&s.bytes).unwrap();
        assert_eq!(r.file.format, "PE");
        assert_eq!(r.file.class, if p { "PE32+" } else { "PE32" });
        assert_eq!(r.file.machine, if p { "x86-64" } else { "x86" });
        assert_eq!(r.file.kind, if dll { "PE DLL" } else { "PE executable" });
        assert_eq!(r.file.pdb_path.as_deref(), Some(s.pdb_path));
        assert!(r.file.stripped);
        let main = s.image_base + u64::from(s.main.0);
        if !dll {
            assert_eq!(r.file.entry, main);
        }
        let text = r.sections.iter().find(|x| x.name == ".text").unwrap();
        assert_eq!(text.addr, s.image_base + 0x1000);
        assert_eq!(text.flags, "AX");
        assert_eq!(text.kind, "CODE");
        assert!(!text.nobits);
        assert_eq!(r.segments.len(), r.sections.len());
        assert_eq!(r.segments[0].flags, "R-E");
        let imports: Vec<(u64, String)> = r
            .imports
            .iter()
            .map(|i| (i.slot, format!("{}!{}", i.dll, i.name)))
            .collect();
        let want: Vec<(u64, String)> = s
            .iat
            .iter()
            .map(|(slot, n)| (s.image_base + u64::from(*slot), n.clone()))
            .collect();
        assert_eq!(imports, want);
        assert_eq!(r.rustc_commit.as_deref(), Some(SAMPLE_RUSTC_COMMIT));
        assert!(
            r.crates
                .iter()
                .any(|c| c.name == "fakecrate" && c.version.as_deref() == Some("1.2.3"))
        );
        assert!(
            r.warnings.iter().all(|w| w.severity == "note"),
            "{:?}",
            r.warnings
        );
        if p {
            // .pdata: main, helper, the TLS callback.
            assert_eq!(r.functions.total, 3);
        }
        let json = report_json(&s.bytes);
        assert!(json.contains("\"format\":\"PE\""), "{json}");
    }
}

#[test]
fn signature_starts_do_not_break_pe() {
    let s = sample(true, false);
    let (r, _) = report_with_signatures(&s.bytes, None).unwrap();
    let main = s.image_base + u64::from(s.main.0);
    assert!(r.function_rows.iter().any(|f| f.start == main));
}

#[test]
fn code_map_and_disasm() {
    for p in [true, false] {
        let s = sample(p, false);
        let r = report(&s.bytes).unwrap();
        let map = code_map_for(&s.bytes, &r.function_spans());
        let recs = parse_code_map(&map);
        let main = s.image_base + u64::from(s.main.0);
        let (_, lens) = recs.iter().find(|(a, _)| *a == main).unwrap();
        assert!(lens.len() >= 7);
        let t = disasm_at(&s.bytes, &[main, 0]);
        let first = t[0].as_ref().unwrap();
        assert_eq!(first.mnemonic, "push");
        assert!(t[1].is_none());
    }
}

#[test]
fn comments_for_locations_and_strings() {
    for p in [true, false] {
        let s = sample(p, false);
        let loc = s.image_base + u64::from(s.location);
        let hello = s.image_base + u64::from(s.hello.0);
        let code = format!(
            "void f(void) {{\n  core::panicking::panic_bounds_check(3,2,{loc:#x});\n  print({hello:#x},{});\n}}\n",
            s.hello.1
        );
        let out = annotate(&s.bytes, &code);
        assert!(
            out.contains(&format!("// at {}:7:5", s.location_file)),
            "{out}"
        );
        assert!(out.contains("// \"hello from synth\""), "{out}");
    }
}

#[test]
fn decompiler_setup() {
    for p in [true, false] {
        let s = sample(p, false);
        let r = report(&s.bytes).unwrap();
        let (lang, lines) = decompiler_setup_for(&s.bytes, &r.function_names()).unwrap();
        assert_eq!(
            lang,
            if p {
                "x86:LE:64:default:windows"
            } else {
                "x86:LE:32:default:windows"
            }
        );
        let segs: Vec<&str> = lines.lines().filter(|l| l.starts_with("seg ")).collect();
        assert_eq!(
            segs[0],
            format!("seg {:x} 400 200 RE", s.image_base + 0x1000)
        );
        assert!(segs.iter().any(|l| l.ends_with(" RW")), "{segs:?}");
        let slot = s.image_base + u64::from(s.iat[0].0);
        assert!(
            lines.contains(&format!("ext {slot:x} KERNEL32.dll!CreateFileW\n")),
            "{lines}"
        );
        assert!(lines.contains("KERNEL32.dll!ExitProcess"));
        assert!(lines.contains("WS2_32.dll!#115"));
        let main = s.image_base + u64::from(s.main.0);
        assert!(lines.contains(&format!("sym {main:x} ")));
        assert!(!lines.contains("ptr "));
        assert!(!lines.chars().any(|c| c.is_control() && c != '\n'));
    }
}

#[test]
fn never_panics_on_truncated_pe() {
    let s = sample(true, true);
    for n in (0..s.bytes.len()).step_by(3) {
        let b = &s.bytes[..n];
        let _ = report_json(b);
        let _ = code_map_for(b, &[(s.image_base + 0x1000, 0)]);
        let _ = disasm_at(b, &[s.image_base + 0x1000]);
        let _ = decompiler_setup_for(b, &[]);
        let _ = annotate(b, "f(0x140002040);");
    }
}

#[test]
fn real_pe_reports() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pe/bin");
    let mut seen = 0;
    for target in ["x86_64-pc-windows-msvc", "i686-pc-windows-msvc"] {
        for f in ["winapp-O2.exe", "windll.dll"] {
            let p = dir.join(target).join(f);
            let Ok(data) = std::fs::read(&p) else {
                continue;
            };
            seen += 1;
            let (r, _) = report_with_signatures(&data, None).unwrap();
            assert!(
                r.crates
                    .iter()
                    .any(|c| c.name == "fakedep" && c.version.as_deref() == Some("1.2.3")),
                "{:?}",
                r.crates
            );
            assert!(r.rustc_commit.is_some());
            assert!(r.imports.iter().any(|i| i.name == "CreateFileW"));
            assert!(
                r.warnings.iter().all(|w| w.severity == "note"),
                "{:?}",
                r.warnings
            );
            let map = code_map_for(&data, &r.function_spans());
            assert!(parse_code_map(&map).len() >= r.function_rows.len() / 2);
            let (_, lines) = decompiler_setup_for(&data, &r.function_names()).unwrap();
            assert!(lines.contains("!CreateFileW\n"));
            // Panic locations of the program's own code and of the
            // dependency, at absolute addresses in .rdata.
            let rdata = r.sections.iter().find(|s| s.name == ".rdata").unwrap();
            let step = if target.starts_with("x86_64") { 8 } else { 4 };
            let mut files = std::collections::BTreeSet::new();
            for a in (rdata.addr..rdata.addr + rdata.size).step_by(step) {
                let out = annotate(&data, &format!("f({a:#x});"));
                if let Some(at) = out.strip_prefix("// at ") {
                    // `<file>:<line>:<col>`; the file may be `C:\...`.
                    files.insert(at.rsplitn(3, ':').nth(2).unwrap().to_owned());
                }
            }
            assert!(
                files.iter().any(|f| f.contains("fakedep-1.2.3")),
                "{}: {files:?}",
                p.display()
            );
            if f.starts_with("winapp") {
                assert!(files.iter().any(|f| f.ends_with("winapp.rs")), "{files:?}");
            }
        }
    }
    if seen == 0 {
        eprintln!("skipped: run testdata/pe/build.sh to build the PE corpus");
    }
}

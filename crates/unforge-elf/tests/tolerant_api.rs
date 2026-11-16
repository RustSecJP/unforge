//! Tests for the tolerant-reader API (testdata/anomalous/API_PROPOSAL.md, as
//! realized in `unforge-elf`).
//!
//! Each test names an anomalous file from `testdata/anomalous/files` and the
//! diagnostic TECHNIQUES.md says a tolerant reader should report for it. The
//! kernel-prediction test at the end compares `ElfFile::kernel_prediction_for`
//! with the authoritative (`source = kernel`) rows of `verdicts.tsv`.
//!
//! Differences from the proposal: `validate()` is `diagnostics()` (the audit,
//! `ElfFile::audit`), tables and the dynamic table are lazy views instead of
//! `Vec`s, and `OverlappingFunctions` is `FunctionsOutsideCode` (what is
//! detected is a function range outside every executable `PT_LOAD`).

use std::path::{Path, PathBuf};

use unforge_elf::{
    Choice, Class, Clue, Diagnostic, DiagnosticKind, ElfFile, Endian, Inference, InferenceSubject,
    KernelPrediction, KernelRule, LayoutSource, Severity,
};

const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;

const ARCHES: [&str; 2] = ["aarch64", "x86_64"];

fn anomalous_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/anomalous")
}

fn load(arch: &str, name: &str) -> Vec<u8> {
    let p = anomalous_dir().join(format!("files/{arch}/{name}.elf"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// `diagnostics()` of the named file. `parse` must succeed for every file a
/// tolerant reader is asked about here (rule: only a bad magic or an
/// unreadable program header table may stop the loader view).
fn validate(arch: &str, name: &str) -> Vec<Diagnostic> {
    let data = load(arch, name);
    let file = ElfFile::parse(&data).unwrap_or_else(|e| panic!("{arch}/{name}: parse failed: {e}"));
    file.diagnostics()
}

fn show(ds: &[Diagnostic]) -> String {
    ds.iter().map(|d| format!("  {d}\n")).collect()
}

/// Assert that, on both architectures, `validate()` of `$name` contains a
/// diagnostic whose kind matches `$pat` (with an optional guard).
macro_rules! expect_diag {
    ($name:expr, $pat:pat $(if $guard:expr)?) => {
        for arch in ARCHES {
            let ds = validate(arch, $name);
            assert!(
                ds.iter().any(|d| matches!(&d.kind, $pat $(if $guard)?)),
                "{arch}/{}: expected {}, got:\n{}",
                $name,
                stringify!($pat),
                show(&ds)
            );
        }
    };
}

// ---------------------------------------------------------------------------
// Controls: no warnings on well-formed files.
// ---------------------------------------------------------------------------

#[test]
fn controls_have_no_warnings() {
    for name in [
        "s00-baseline",
        "y00-symtab-baseline",
        "t65-control-tiny",
        "t83-et-dyn-tiny",
        "t84-interp-ldso-minimal-dynamic",
    ] {
        for arch in ARCHES {
            let ds = validate(arch, name);
            let bad: Vec<_> = ds
                .iter()
                .filter(|d| d.severity != Severity::Info)
                .cloned()
                .collect();
            assert!(bad.is_empty(), "{arch}/{name}:\n{}", show(&bad));
        }
    }
    let ds = validate("x86_64", "d00-baseline");
    assert!(
        ds.iter().all(|d| d.severity == Severity::Info),
        "{}",
        show(&ds)
    );
}

// ---------------------------------------------------------------------------
// T01-T09: the section header table is a claim, not a requirement.
// ---------------------------------------------------------------------------

#[test]
fn t01_no_section_header_table_is_info() {
    for name in ["s01-shdr-zeroed", "s02-sstrip"] {
        for arch in ARCHES {
            let ds = validate(arch, name);
            let d = ds
                .iter()
                .find(|d| matches!(d.kind, DiagnosticKind::NoSectionHeaderTable))
                .unwrap_or_else(|| panic!("{arch}/{name}:\n{}", show(&ds)));
            assert_eq!(d.severity, Severity::Info);
        }
    }
}

#[test]
fn t02_section_table_outside_file() {
    expect_diag!(
        "s03-shoff-garbage",
        DiagnosticKind::SectionTableOutsideFile {
            offset: 0xdead_beef_dead_beef,
            ..
        }
    );
    expect_diag!(
        "s04-shoff-past-eof",
        DiagnosticKind::SectionTableOutsideFile { .. }
    );
}

#[test]
fn t03_section_count_clipped() {
    expect_diag!("s05-shnum-ffff", DiagnosticKind::SectionCountClipped { declared: 0xffff, usable } if *usable < 0xffff);
    // The section headers that do fit are still decoded.
    for arch in ARCHES {
        let data = load(arch, "s05-shnum-ffff");
        let f = ElfFile::parse(&data).expect("parse");
        assert!(!f.section_headers().expect("clipped table").is_empty());
    }
}

#[test]
fn t03_t10_shnum_without_table() {
    expect_diag!(
        "t60-tiny-phdr-overlaps-ehdr",
        DiagnosticKind::SectionCountWithoutTable { shnum: 5 }
    );
    // Choosing "no sections" over e_shnum is recorded as an inference.
    for arch in ARCHES {
        let data = load(arch, "t60-tiny-phdr-overlaps-ehdr");
        let i = ElfFile::parse(&data).expect("parse").inferences();
        assert!(
            i.iter()
                .any(|i| i.subject == InferenceSubject::SectionHeaderCount
                    && i.chosen == Choice::Count(0)
                    && i.alternatives.iter().any(|a| a.choice == Choice::Count(5))),
            "{arch}: {i:?}"
        );
    }
}

#[test]
fn t04_bad_section_entry_size() {
    expect_diag!(
        "s06-shentsize-1",
        DiagnosticKind::BadSectionEntrySize {
            found: 1,
            expected: 64
        }
    );
}

#[test]
fn t05_bad_shstrndx() {
    expect_diag!(
        "s07-shstrndx-out-of-range",
        DiagnosticKind::ShstrndxOutOfRange { index: 0x1234, .. }
    );
    expect_diag!(
        "s08-shstrndx-is-text",
        DiagnosticKind::ShstrndxNotStrtab { sh_type: 1, .. }
    );
    // Sections are kept; only their names become unknown.
    for arch in ARCHES {
        let data = load(arch, "s07-shstrndx-out-of-range");
        let f = ElfFile::parse(&data).expect("parse");
        assert!(f.section_headers().expect("sections still readable").len() > 10);
    }
}

#[test]
fn t06_sections_clipped_to_file() {
    expect_diag!(
        "s09-text-size-huge",
        DiagnosticKind::SectionClipped {
            declared: 0xffff_ffff_ffff,
            ..
        }
    );
    expect_diag!(
        "s10-rodata-offset-past-eof",
        DiagnosticKind::SectionClipped { available: 0, .. }
    );
    let ds = validate("x86_64", "d42-dynamic-section-header-garbage");
    assert!(
        ds.iter()
            .any(|d| matches!(d.kind, DiagnosticKind::DynamicSectionMismatch { .. })),
        "{}",
        show(&ds)
    );
}

#[test]
fn t07_decoy_sections() {
    expect_diag!(
        "s11-decoy-swap-text-rodata-names",
        DiagnosticKind::SectionNameMismatch { .. }
    );
    expect_diag!(
        "s12-text-is-nobits",
        DiagnosticKind::NobitsInFileBytes { .. }
    );
}

#[test]
fn t08_overlap_is_reported_and_bounded() {
    expect_diag!(
        "s13-progbits-all-overlap-text",
        DiagnosticKind::SectionsOverlap { .. }
    );
    for arch in ARCHES {
        let ds = validate(arch, "s14-2000-symtabs-same-bytes");
        // 2019 sections over the same bytes: the report must stay small
        // (TECHNIQUES.md §2 rule 7) and say how much was suppressed.
        assert!(ds.len() <= 256, "{arch}: {} diagnostics", ds.len());
        assert!(
            ds.iter()
                .any(|d| matches!(d.kind, DiagnosticKind::Suppressed { .. })),
            "{}",
            show(&ds)
        );
        // The tables are views: reading all of them is allowed and bounded.
        let data = load(arch, "s14-2000-symtabs-same-bytes");
        let f = ElfFile::parse(&data).expect("parse");
        assert!(
            f.symbol_tables().is_ok(),
            "overlapping tables must not be a hard error"
        );
    }
}

#[test]
fn t09_section_addresses_disagree_with_segments() {
    expect_diag!(
        "s15-section-addr-disagree-with-segments",
        DiagnosticKind::SectionAddressMismatch { .. }
    );
}

// ---------------------------------------------------------------------------
// T10-T13: header tricks.
// ---------------------------------------------------------------------------

#[test]
fn t10_phdrs_overlap_header() {
    expect_diag!(
        "t60-tiny-phdr-overlaps-ehdr",
        DiagnosticKind::PhdrsOverlapHeader
    );
}

#[test]
fn t11_phdrs_not_in_load() {
    expect_diag!(
        "s24-phdr-outside-every-load",
        DiagnosticKind::PhdrsNotInLoad
    );
    expect_diag!(
        "s24-phdr-outside-every-load",
        DiagnosticKind::PtPhdrMismatch { .. }
    );
    expect_diag!(
        "t90-phdr-not-in-load-no-ldso",
        DiagnosticKind::PhdrsNotInLoad
    );
}

#[test]
fn t12_layout_comes_from_the_machine() {
    for (name, claimed_class) in [("s16-ei-class-32", 1u8), ("s17-ei-class-0x55", 0x55)] {
        for arch in ARCHES {
            let data = load(arch, name);
            let f = ElfFile::parse(&data).expect("EI_CLASS is ignored by the kernel");
            let l = f.layout();
            assert_eq!(
                (l.class, l.endian, l.source),
                (Class::Elf64, Endian::Little, LayoutSource::Machine)
            );
            let ds = f.diagnostics();
            assert!(
                ds.iter().any(|d| matches!(d.kind, DiagnosticKind::ClassMismatch { claimed, used: Class::Elf64 } if claimed == claimed_class)),
                "{arch}/{name}:\n{}",
                show(&ds)
            );
        }
    }
    expect_diag!(
        "s18-ei-data-be",
        DiagnosticKind::DataMismatch {
            claimed: 2,
            used: Endian::Little
        }
    );
    expect_diag!(
        "s19-ei-data-0",
        DiagnosticKind::DataMismatch {
            claimed: 0,
            used: Endian::Little
        }
    );
    expect_diag!(
        "t61-tiny-overlap-all-unused-fields-garbage",
        DiagnosticKind::ClassMismatch {
            claimed: 0xff,
            used: Class::Elf64
        }
    );
    let ds = validate("x86_64", "d16-ei-class-32");
    assert!(
        ds.iter()
            .any(|d| matches!(d.kind, DiagnosticKind::ClassMismatch { claimed: 1, .. }))
    );
}

#[test]
fn t12_ident_fields_the_kernel_ignores_are_info() {
    expect_diag!(
        "s20-ei-version-0-e_version-0",
        DiagnosticKind::IdentVersion(0)
    );
    expect_diag!("s20-ei-version-0-e_version-0", DiagnosticKind::Version(0));
    expect_diag!("s21-osabi-freebsd-pad-garbage", DiagnosticKind::OsAbi(9));
    expect_diag!(
        "s21-osabi-freebsd-pad-garbage",
        DiagnosticKind::AbiVersion(0x42)
    );
    expect_diag!(
        "s21-osabi-freebsd-pad-garbage",
        DiagnosticKind::NonZeroPadding
    );
    for arch in ARCHES {
        for d in validate(arch, "s21-osabi-freebsd-pad-garbage") {
            if matches!(
                d.kind,
                DiagnosticKind::OsAbi(_)
                    | DiagnosticKind::AbiVersion(_)
                    | DiagnosticKind::NonZeroPadding
            ) {
                assert_eq!(d.severity, Severity::Info, "{d}");
            }
        }
    }
}

#[test]
fn t13_header_size() {
    expect_diag!(
        "s22-ehsize-0",
        DiagnosticKind::HeaderSize {
            found: 0,
            expected: 64
        }
    );
    expect_diag!(
        "s23-ehsize-ffff",
        DiagnosticKind::HeaderSize {
            found: 0xffff,
            expected: 64
        }
    );
}

// ---------------------------------------------------------------------------
// T14-T16: segments.
// ---------------------------------------------------------------------------

#[test]
fn t14_segment_past_eof_is_clipped_not_dropped() {
    for name in [
        "s25-truncated-inside-last-load",
        "s26-last-load-filesz-past-eof",
        "t62-rwx-filesz-past-eof-memsz-bigger",
        "t63-rx-filesz-past-eof-memsz-bigger",
        "t64-rx-filesz-past-eof",
    ] {
        for arch in ARCHES {
            let data = load(arch, name);
            let f = ElfFile::parse(&data).expect("parse");
            let ds = f.diagnostics();
            assert!(
                ds.iter()
                    .any(|d| matches!(d.kind, DiagnosticKind::SegmentPastEof { .. })),
                "{arch}/{name}:\n{}",
                show(&ds)
            );
            for p in f
                .program_headers()
                .expect("phdrs")
                .iter()
                .filter(|p| p.p_type == PT_LOAD)
            {
                let b = f.segment_bytes(&p);
                assert_eq!(b.bytes.len() as u64 + b.missing, p.filesz, "{arch}/{name}");
            }
        }
    }
}

#[test]
fn t15_load_overlap_order_and_alignment() {
    expect_diag!(
        "s27-ptload-duplicate-of-rx",
        DiagnosticKind::LoadsOverlap { .. }
    );
    expect_diag!(
        "s28-ptload-later-overrides-text",
        DiagnosticKind::LoadsOverlap { .. }
    );
    expect_diag!(
        "s29-ptload-not-sorted",
        DiagnosticKind::LoadsNotSorted { .. }
    );
    expect_diag!(
        "s30-palign-not-power-of-two",
        DiagnosticKind::AlignNotPowerOfTwo { align: 3, .. }
    );
    expect_diag!(
        "s34-unknown-ptype",
        DiagnosticKind::UnknownSegmentType {
            p_type: 0x1234_5678,
            ..
        }
    );
    expect_diag!(
        "s35-palign-incongruent",
        DiagnosticKind::AlignCongruence { .. }
    );
    // The memory map applies PT_LOADs in table order; the later one wins.
    for arch in ARCHES {
        let data = load(arch, "s28-ptload-later-overrides-text");
        let f = ElfFile::parse(&data).expect("parse");
        let phdrs = f.program_headers().expect("phdrs");
        let injected = phdrs
            .iter()
            .rposition(|p| p.p_type == PT_LOAD && p.offset == 0 && p.filesz == 0x1000)
            .expect("injected PT_LOAD");
        let b = f
            .memory_map()
            .backing(f.header().entry)
            .expect("entry is mapped");
        assert_eq!(b.segment, injected, "{arch}");
        assert!(
            !b.overrides.is_empty(),
            "{arch}: should record the overridden segment"
        );
    }
}

#[test]
fn t16_dynamic_found_by_vaddr() {
    let good_data = load("x86_64", "d00-baseline");
    let good = ElfFile::parse(&good_data).expect("parse");
    let bad_data = load("x86_64", "d40-pt_dynamic-offset-filesz-garbage");
    let bad = ElfFile::parse(&bad_data).expect("parse");
    // ld.so uses p_vaddr only (glibc rtld.c rtld_setup_main_map), so the
    // table must be found and be identical.
    let entries = |f: &ElfFile<'_>| f.dynamic().expect("dynamic").iter().collect::<Vec<_>>();
    assert!(!entries(&good).is_empty());
    assert_eq!(entries(&bad), entries(&good));
    assert!(bad.diagnostics().iter().any(|d| matches!(
        d.kind,
        DiagnosticKind::DynamicOffsetMismatch {
            p_offset: 0xdead_beef,
            ..
        }
    )));
    expect_diag!(
        "t85-interp-ldso-pt_dynamic-offset-garbage",
        DiagnosticKind::DynamicOffsetMismatch { .. }
    );
    expect_diag!(
        "t86-interp-ldso-no-pt_dynamic",
        DiagnosticKind::InterpWithoutDynamic
    );
    // Without section headers the dynamic table is still reachable.
    let stripped = load("x86_64", "d01-shdr-zeroed");
    let f = ElfFile::parse(&stripped).expect("parse");
    assert_eq!(entries(&f), entries(&good));
}

// ---------------------------------------------------------------------------
// T17: symbol tables.
// ---------------------------------------------------------------------------

#[test]
fn t17_symbol_tables() {
    expect_diag!(
        "y50-symtab-st_name-out-of-range",
        DiagnosticKind::SymbolNamesOutOfRange { count: 33, .. }
    );
    expect_diag!(
        "y51-symtab-sh_link-to-text",
        DiagnosticKind::SymbolTableLinkNotStrtab { .. }
    );
    expect_diag!(
        "y52-symtab-entsize-0-size-ragged",
        DiagnosticKind::SymbolEntrySize { found: 0, .. }
    );
    expect_diag!(
        "y52-symtab-entsize-0-size-ragged",
        DiagnosticKind::SymbolTableTrailingBytes { bytes: 7, .. }
    );
    expect_diag!(
        "y53-symtab-funcs-all-same-addr-huge-size",
        DiagnosticKind::FunctionsOutsideCode { .. }
    );
    // 0xfeee is below SHN_LORESERVE (0xff00; gABI ch4 "Special Section
    // Indexes"), so it is an ordinary index past the section header table,
    // not a reserved value.
    expect_diag!(
        "y54-symtab-st_shndx-garbage",
        DiagnosticKind::SymbolSectionOutOfRange { count: 33, .. }
    );
    // Symbols are kept even when their names or links are bad.
    for name in [
        "y51-symtab-sh_link-to-text",
        "y52-symtab-entsize-0-size-ragged",
    ] {
        for arch in ARCHES {
            let data = load(arch, name);
            let f = ElfFile::parse(&data).expect("parse");
            let tables = f.symbol_tables().expect("tables are readable");
            assert_eq!(tables.map(|t| t.len()).sum::<usize>(), 34, "{arch}/{name}");
        }
    }
}

// ---------------------------------------------------------------------------
// T19 and the oracle: the reader predicts the kernel's verdict.
// ---------------------------------------------------------------------------

#[test]
fn t19_kernel_rules_are_named() {
    let host = EM_AARCH64;
    type Check = fn(&KernelPrediction) -> bool;
    let cases: [(&str, Check); 11] = [
        ("s31-phentsize-wrong", |p| {
            matches!(
                p,
                KernelPrediction::RejectedAtExec(KernelRule::PhentsizeMismatch {
                    found: 32,
                    expected: 56
                })
            )
        }),
        ("t70-e_type-rel", |p| {
            matches!(p, KernelPrediction::RejectedAtExec(KernelRule::BadType(1)))
        }),
        ("t71-e_phnum-0", |p| {
            matches!(
                p,
                KernelPrediction::RejectedAtExec(KernelRule::PhnumOutOfRange(0))
            )
        }),
        ("t72-e_phnum-1171", |p| {
            matches!(
                p,
                KernelPrediction::RejectedAtExec(KernelRule::PhnumOutOfRange(1171))
            )
        }),
        ("t73-phdr-table-past-eof", |p| {
            matches!(
                p,
                KernelPrediction::RejectedAtExec(KernelRule::PhdrsOutsideFile)
            )
        }),
        ("t75-interp-filesz-1", |p| {
            matches!(
                p,
                KernelPrediction::RejectedAtExec(KernelRule::InterpSize(1))
            )
        }),
        ("t76-interp-not-nul-terminated", |p| {
            matches!(
                p,
                KernelPrediction::RejectedAtExec(KernelRule::InterpNotTerminated)
            )
        }),
        ("t81-phnum-pn-xnum", |p| {
            matches!(
                p,
                KernelPrediction::RejectedAtExec(KernelRule::PhnumOutOfRange(0xffff))
            )
        }),
        ("t87-phentsize-64", |p| {
            matches!(
                p,
                KernelPrediction::RejectedAtExec(KernelRule::PhentsizeMismatch { found: 64, .. })
            )
        }),
        ("t74-filesz-gt-memsz", |p| {
            matches!(
                p,
                KernelPrediction::AbortedAfterPointOfNoReturn(KernelRule::FileszExceedsMemsz {
                    index: 0
                })
            )
        }),
        ("t82-offset-vaddr-not-congruent", |p| {
            matches!(
                p,
                KernelPrediction::AbortedAfterPointOfNoReturn(
                    KernelRule::OffsetVaddrNotCongruent { index: 0 }
                )
            )
        }),
    ];
    for (name, ok) in cases {
        let data = load("aarch64", name);
        // parse may legitimately fail only where the program header table
        // itself is unreadable; the prediction must still be available.
        let p = ElfFile::kernel_prediction_for(&data, host);
        assert!(ok(&p), "aarch64/{name}: got {p:?}");
    }
    let data = load("aarch64", "s32-machine-wrong");
    assert!(matches!(
        ElfFile::kernel_prediction_for(&data, host),
        KernelPrediction::RejectedAtExec(KernelRule::BadMachine(62))
    ));
    let data = load("aarch64", "t88-gnu-property-bad-note-name");
    assert!(matches!(
        ElfFile::kernel_prediction_for(&data, host),
        KernelPrediction::RejectedAtExec(KernelRule::GnuPropertyMalformed)
    ));
    let data = load("aarch64", "t62-rwx-filesz-past-eof-memsz-bigger");
    assert!(matches!(
        ElfFile::kernel_prediction_for(&data, host),
        KernelPrediction::AbortedAfterPointOfNoReturn(KernelRule::PaddingFault { index: 0 })
    ));
    expect_diag!(
        "t78-entry-unmapped",
        DiagnosticKind::EntryNotExecutable { backing: None, .. }
    );
    expect_diag!(
        "t79-entry-in-non-exec-load",
        DiagnosticKind::EntryNotExecutable {
            backing: Some(0),
            ..
        }
    );
    expect_diag!(
        "t89-two-interp-first-wins",
        DiagnosticKind::DuplicateSegment { p_type: 3, .. }
    );
}

/// Compare `kernel_prediction_for` with every authoritative verdict.
///
/// - kernel-accepted verdicts must be predicted `Loads`;
/// - `exec_rejected:*` must be predicted `RejectedAtExec`, except `ENOENT`
///   (a missing interpreter is a property of the file system, not the file);
/// - `ambiguous:*` may be `Loads` or `AbortedAfterPointOfNoReturn`.
#[test]
fn kernel_prediction_agrees_with_the_oracle() {
    let text = std::fs::read_to_string(anomalous_dir().join("verdicts.tsv")).expect("verdicts.tsv");
    let mut wrong = Vec::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with("path\t"))
    {
        let f: Vec<&str> = line.split('\t').collect();
        let (path, arch, source, verdict) = (f[0], f[2], f[4], f[6]);
        if source != "kernel" {
            continue;
        }
        let host = match arch {
            "aarch64" => EM_AARCH64,
            _ => continue,
        };
        let data = std::fs::read(anomalous_dir().join(path)).expect("file");
        let p = ElfFile::kernel_prediction_for(&data, host);
        let ok = if verdict == "exec_rejected:ENOENT" {
            true
        } else if verdict.starts_with("exec_rejected:") {
            matches!(p, KernelPrediction::RejectedAtExec(_))
        } else if verdict.starts_with("ambiguous:") {
            matches!(
                p,
                KernelPrediction::Loads | KernelPrediction::AbortedAfterPointOfNoReturn(_)
            )
        } else {
            matches!(p, KernelPrediction::Loads)
        };
        if !ok {
            wrong.push(format!("{path}: observed {verdict}, predicted {p:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

// ---------------------------------------------------------------------------
// Inferences: every interpretation the reader chooses is recorded, with its
// clues and alternatives, and the file reports whether it is ambiguous.
// ---------------------------------------------------------------------------

fn inferences(arch: &str, name: &str) -> Vec<Inference> {
    let data = load(arch, name);
    ElfFile::parse(&data).expect("parse").inferences()
}

#[test]
fn well_formed_files_need_no_inference() {
    for name in ["s00-baseline", "y00-symtab-baseline", "t65-control-tiny"] {
        for arch in ARCHES {
            let data = load(arch, name);
            let f = ElfFile::parse(&data).expect("parse");
            assert_eq!(f.layout().source, LayoutSource::Ident, "{arch}/{name}");
            assert!(
                f.inferences().is_empty(),
                "{arch}/{name}: {:?}",
                f.inferences()
            );
            assert!(!f.is_ambiguous(), "{arch}/{name}");
        }
    }
}

#[test]
fn layout_inference_names_choice_clues_and_alternatives() {
    for arch in ARCHES {
        let data = load(arch, "s16-ei-class-32");
        let f = ElfFile::parse(&data).expect("parse");
        let i = f
            .inferences()
            .into_iter()
            .find(|i| i.subject == InferenceSubject::Layout)
            .unwrap_or_else(|| panic!("{arch}: no layout inference"));
        assert_eq!(
            i.chosen,
            Choice::Layout {
                class: Class::Elf64,
                endian: Endian::Little
            }
        );
        let machine = f.header().machine;
        assert!(
            i.clues
                .iter()
                .any(|c| matches!(c, Clue::MachineReadsAs { machine: m, .. } if *m == machine)),
            "{arch}: {i}"
        );
        assert!(
            i.clues.iter().any(|c| matches!(
                c,
                Clue::EntrySizeMatches {
                    field: "e_phentsize",
                    value: 56
                }
            )),
            "{arch}: {i}"
        );
        // The claimed ELF32 reading is listed, and it does not fit the header.
        let elf32 = i
            .alternatives
            .iter()
            .find(|a| {
                a.choice
                    == Choice::Layout {
                        class: Class::Elf32,
                        endian: Endian::Little,
                    }
            })
            .unwrap_or_else(|| panic!("{arch}: ELF32 alternative missing: {i}"));
        assert!(!elf32.viable, "{arch}: {i}");
        assert!(
            elf32.clues.iter().any(|c| matches!(
                c,
                Clue::IdentClaims {
                    field: "EI_CLASS",
                    value: 1
                }
            )),
            "{arch}: {i}"
        );
        assert!(!f.is_ambiguous(), "{arch}: {i}");
        // The rendered text says what was chosen and from what.
        let text = i.to_string();
        assert!(text.contains("chose Elf64 Little-endian"), "{text}");
        assert!(text.contains("e_phentsize = 56"), "{text}");
    }
    // An invalid EI_DATA is named as a clue.
    let i = inferences("aarch64", "s19-ei-data-0");
    let l = i
        .iter()
        .find(|i| i.subject == InferenceSubject::Layout)
        .expect("layout");
    assert!(
        l.clues.iter().any(|c| matches!(
            c,
            Clue::InvalidIdent {
                field: "EI_DATA",
                value: 0
            }
        )),
        "{l}"
    );
}

/// A header that is consistent as ELF32 and as ELF64 at once: the ELF32 size
/// fields live at 0x28..0x34 and the ELF64 ones at 0x34..0x40, so both can
/// hold the right values. With `EI_CLASS` invalid and `e_machine` =
/// `EM_X86_64` (used by Linux in both classes), nothing decides.
#[test]
fn a_file_with_two_consistent_layouts_is_ambiguous() {
    let mut b = vec![0u8; 64];
    b[..4].copy_from_slice(b"\x7fELF");
    b[4] = 0x55; // EI_CLASS invalid
    b[5] = 1; // ELFDATA2LSB
    b[6] = 1;
    b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    b[0x12..0x14].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // e_version
    // ELF32: e_ehsize 52, e_phentsize 32, e_phnum 0, e_shentsize 40.
    b[0x28..0x2a].copy_from_slice(&52u16.to_le_bytes());
    b[0x2a..0x2c].copy_from_slice(&32u16.to_le_bytes());
    b[0x2e..0x30].copy_from_slice(&40u16.to_le_bytes());
    // ELF64: e_ehsize 64, e_phentsize 56, e_phnum 0, e_shentsize 64.
    b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
    b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    b[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
    let f = ElfFile::parse(&b).expect("parse");
    assert!(f.layout().is_inferred());
    assert!(f.layout().viable_alternatives().next().is_some());
    assert!(f.is_ambiguous());
    let i = f
        .inferences()
        .into_iter()
        .find(|i| i.subject == InferenceSubject::Layout)
        .expect("layout inference");
    assert!(i.is_ambiguous());
    let chosen = i.chosen;
    let other = i
        .alternatives
        .iter()
        .find(|a| a.viable)
        .expect("viable alternative");
    assert_ne!(other.choice, chosen);
    assert_eq!(other.score, i.score, "the two readings tie: {i}");
    let d = f
        .diagnostics()
        .into_iter()
        .find(|d| d.inference().is_some())
        .expect("diagnostic");
    assert_eq!(
        d.severity,
        Severity::Warning,
        "an ambiguous inference warns"
    );
    assert!(d.to_string().contains("no unique interpretation"), "{d}");
}

#[test]
fn string_table_choice_is_an_inference_with_alternatives() {
    for arch in ARCHES {
        let data = load(arch, "y51-symtab-sh_link-to-text");
        let f = ElfFile::parse(&data).expect("parse");
        let i = f
            .inferences()
            .into_iter()
            .find(|i| matches!(i.subject, InferenceSubject::StringTable { .. }))
            .unwrap_or_else(|| panic!("{arch}: no string table inference"));
        let text_idx = f.section_by_name(b".text").expect(".text").0 as u32;
        assert_eq!(i.chosen, Choice::Section(text_idx));
        let strtab_idx = f.section_by_name(b".strtab").expect(".strtab").0 as u32;
        assert!(
            i.alternatives
                .iter()
                .any(|a| a.choice == Choice::Section(strtab_idx) && a.viable),
            "{arch}: {i}"
        );
        assert!(f.is_ambiguous(), "{arch}");
    }
}

#[test]
fn clipped_counts_and_entry_sizes_are_inferences() {
    for arch in ARCHES {
        let i = inferences(arch, "s05-shnum-ffff");
        let c = i
            .iter()
            .find(|i| i.subject == InferenceSubject::SectionHeaderCount)
            .unwrap_or_else(|| panic!("{arch}: {i:?}"));
        assert!(matches!(c.chosen, Choice::Count(n) if n < 0xffff));
        assert!(
            c.alternatives
                .iter()
                .any(|a| a.choice == Choice::Count(0xffff) && !a.viable)
        );
        assert!(c.clues.iter().any(|c| matches!(c, Clue::FileLength(_))));

        let i = inferences(arch, "y52-symtab-entsize-0-size-ragged");
        let e = i
            .iter()
            .find(|i| matches!(i.subject, InferenceSubject::SymbolEntrySize { .. }))
            .unwrap_or_else(|| panic!("{arch}: {i:?}"));
        assert_eq!(e.chosen, Choice::EntrySize(24));
        assert!(e.clues.contains(&Clue::Field {
            field: "sh_entsize",
            value: 0
        }));
    }
    // Inferences with no viable alternative do not make the file ambiguous.
    let data = load("aarch64", "s05-shnum-ffff");
    assert!(!ElfFile::parse(&data).expect("parse").is_ambiguous());
}

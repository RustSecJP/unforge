//! The reader against hand-built images whose layout is known
//! (`unforge_pe::synth`).

use unforge_pe::synth::{SAMPLE_CRATE_PATH, SynthPe, SynthSection, sample, section_name};
use unforge_pe::{
    DiagnosticKind, ImportKind, MACHINE_AMD64, MACHINE_I386, PeFile, PeKind, SCN_CNT_CODE,
    SCN_MEM_EXECUTE, SCN_MEM_READ, dir,
};

#[test]
fn headers_and_sections() {
    for pe32_plus in [true, false] {
        let s = sample(pe32_plus, false);
        let pe = PeFile::parse(&s.bytes).unwrap();
        assert_eq!(
            pe.machine(),
            if pe32_plus {
                MACHINE_AMD64
            } else {
                MACHINE_I386
            }
        );
        assert_eq!(
            pe.kind(),
            if pe32_plus {
                PeKind::Pe32Plus
            } else {
                PeKind::Pe32
            }
        );
        assert_eq!(pe.image_base(), s.image_base);
        assert_eq!(pe.entry_rva(), Some(s.main.0));
        assert!(!pe.is_dll());
        let names: Vec<String> = pe.sections().iter().map(|x| pe.section_name(x)).collect();
        let want: Vec<&str> = if pe32_plus {
            vec![".text", ".rdata", ".pdata", ".data", ".reloc"]
        } else {
            vec![".text", ".rdata", ".data", ".reloc"]
        };
        assert_eq!(names, want);
        // Headers region, then one per section.
        assert_eq!(pe.regions().len(), want.len() + 1);
        assert!(pe.is_executable_rva(u64::from(s.main.0)));
        assert!(!pe.is_executable_rva(u64::from(s.hello.0)));
        let b = pe.bytes_at_rva(u64::from(s.hello.0)).unwrap();
        assert!(b.starts_with(b"hello from synth"));
        assert_eq!(pe.bytes_at_va(s.image_base + u64::from(s.hello.0)), Some(b));
        // .data: 0x20 file bytes, file-aligned to 0x200 (more than the
        // virtual size 0x100, but less than its page).
        let data = pe
            .sections()
            .iter()
            .find(|x| x.short_name() == b".data")
            .unwrap();
        let r = pe.region_at(u64::from(data.virtual_address)).unwrap();
        assert_eq!(r.end - r.start, 0x1000);
        assert_eq!(r.file_len, 0x200);
        assert!(r.is_writable());
        assert_eq!(
            pe.rva_to_offset(u64::from(data.virtual_address) + 0x200),
            None
        );
        // Clean: nothing worse than a note.
        let d = pe.diagnostics();
        assert!(
            d.iter().all(|x| x.severity == unforge_pe::Severity::Info),
            "{d:#?}"
        );
    }
}

#[test]
fn imports() {
    for pe32_plus in [true, false] {
        let s = sample(pe32_plus, false);
        let pe = PeFile::parse(&s.bytes).unwrap();
        let imps = pe.imports();
        assert_eq!(imps.len(), 2);
        assert_eq!(imps[0].name, b"KERNEL32.dll");
        assert_eq!(imps[0].entries.len(), 2);
        assert!(matches!(
            imps[0].entries[0].kind,
            ImportKind::Name {
                name: b"CreateFileW",
                ..
            }
        ));
        assert_eq!(imps[1].entries[0].kind, ImportKind::Ordinal(115));
        assert_eq!(pe.iat_names(), s.iat);
    }
}

#[test]
fn exports_with_forwarder() {
    let s = sample(true, true);
    let pe = PeFile::parse(&s.bytes).unwrap();
    assert!(pe.is_dll());
    let e = pe.exports().unwrap();
    assert_eq!(e.dll_name, Some(&b"synth.dll"[..]));
    assert_eq!(e.entries.len(), 3);
    assert_eq!(e.entries[0].name, Some(&b"helper"[..]));
    assert_eq!(e.entries[0].rva, s.helper.0);
    assert_eq!(e.entries[0].ordinal, 1);
    assert_eq!(e.entries[1].name, None);
    assert_eq!(e.entries[1].ordinal, 2);
    assert_eq!(
        e.entries[2].forwarder,
        Some(&b"NTDLL.RtlExitUserThread"[..])
    );
    assert!(
        PeFile::parse(&sample(true, false).bytes)
            .unwrap()
            .exports()
            .is_none()
    );
}

#[test]
fn pdata_tls_debug_relocs() {
    let s = sample(true, false);
    let pe = PeFile::parse(&s.bytes).unwrap();
    let rf = pe.runtime_functions();
    assert_eq!(rf.len(), 4);
    assert_eq!((rf[0].begin, rf[0].end), (s.main.0, s.main.0 + s.main.1));
    assert!(!rf[0].chained);
    assert!(rf[2].chained);
    assert!(!rf[3].chained);
    let tls = pe.tls().unwrap();
    assert_eq!(
        tls.callbacks,
        vec![s.image_base + u64::from(s.tls_callback)]
    );
    let cv = pe.codeview().unwrap();
    assert_eq!(&cv.signature, b"RSDS");
    assert_eq!(cv.path, s.pdb_path.as_bytes());
    assert_eq!(cv.age, 1);
    let relocs: Vec<_> = pe.relocations().collect();
    assert!(relocs.iter().all(|r| r.kind == 10));
    assert!(relocs.iter().any(|r| r.rva == u64::from(s.location)));
    // x86: no .pdata, HIGHLOW relocations.
    let s = sample(false, false);
    let pe = PeFile::parse(&s.bytes).unwrap();
    assert!(pe.runtime_functions().is_empty());
    assert!(pe.relocations().all(|r| r.kind == 3));
    assert_eq!(pe.tls().unwrap().callbacks.len(), 1);
    // The registry path is in .rdata.
    let rdata = pe
        .sections()
        .iter()
        .find(|x| x.short_name() == b".rdata")
        .unwrap();
    let b = pe.bytes_at_rva(u64::from(rdata.virtual_address)).unwrap();
    assert!(
        b.windows(SAMPLE_CRATE_PATH.len())
            .any(|w| w == SAMPLE_CRATE_PATH.as_bytes())
    );
}

#[test]
fn coff_symbols_and_long_names() {
    let mut pe = SynthPe::new(true);
    pe.sections.push(SynthSection {
        name: *b"/4\0\0\0\0\0\0",
        rva: 0x1000,
        data: vec![0xc3; 16],
        virtual_size: 0,
        characteristics: SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ,
    });
    pe.symbols = vec![
        ("_ZN4main4main17h0123456789abcdefE".to_owned(), 1, 4, 0x20),
        ("data".to_owned(), 1, 8, 0),
    ];
    let bytes = pe.build();
    let file = PeFile::parse(&bytes).unwrap();
    let syms = file.coff_symbols();
    assert_eq!(syms.len(), 2);
    assert!(syms[0].is_function());
    assert_eq!(syms[0].name, b"_ZN4main4main17h0123456789abcdefE");
    assert_eq!(file.symbol_rva(&syms[0]), Some(0x1004));
    assert!(!syms[1].is_function());
    // "/4" names the string at offset 4: the first long symbol name.
    assert_eq!(
        file.section_name(&file.sections()[0]),
        "_ZN4main4main17h0123456789abcdefE"
    );
}

#[test]
fn alignment_quirks() {
    // PointerToRawData is rounded down to 512, SizeOfRawData up to the
    // file alignment.
    let mut pe = SynthPe::new(true);
    pe.sections.push(SynthSection {
        name: section_name(".text"),
        rva: 0x1000,
        data: vec![0x90; 0x300],
        virtual_size: 0,
        characteristics: SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ,
    });
    let mut bytes = pe.build();
    let sec = SynthPe::PE_OFFSET + 24 + 240;
    let ptr = u32::from_le_bytes(bytes[sec + 20..sec + 24].try_into().unwrap());
    bytes[sec + 20..sec + 24].copy_from_slice(&(ptr + 0x13).to_le_bytes());
    let file = PeFile::parse(&bytes).unwrap();
    assert_eq!(file.rva_to_offset(0x1000), Some(u64::from(ptr)));

    // Low alignment: RVA = file offset.
    let mut pe = SynthPe::new(false);
    pe.section_alignment = 0x200;
    pe.file_alignment = 0x200;
    pe.sections.push(SynthSection {
        name: section_name(".text"),
        rva: 0x200,
        data: vec![0xc3; 0x10],
        virtual_size: 0,
        characteristics: SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ,
    });
    let bytes = pe.build();
    let file = PeFile::parse(&bytes).unwrap();
    assert_eq!(file.rva_to_offset(0x200), Some(0x200));
    assert!(file.is_executable_rva(0x200));
    assert!(
        file.diagnostics()
            .iter()
            .any(|d| d.kind == DiagnosticKind::LowAlignment)
    );
}

#[test]
fn anomalies_are_reported() {
    let s = sample(true, false);
    // A section past the end of the file.
    let cut = &s.bytes[..s.bytes.len() - 0x100];
    let pe = PeFile::parse(cut).unwrap();
    let kinds: Vec<_> = pe.diagnostics().iter().map(|d| d.kind).collect();
    assert!(
        kinds.contains(&DiagnosticKind::SectionPastEndOfFile),
        "{kinds:?}"
    );
    // An entry point outside the image, and an overlay.
    let mut pe = SynthPe::new(true);
    pe.entry_rva = 0x9000;
    pe.overlay = vec![1, 2, 3];
    let pe_bytes = pe.build();
    let file = PeFile::parse(&pe_bytes).unwrap();
    let kinds: Vec<_> = file.diagnostics().iter().map(|d| d.kind).collect();
    assert!(
        kinds.contains(&DiagnosticKind::EntryOutsideImage),
        "{kinds:?}"
    );
    // Overlapping sections.
    let mut pe = SynthPe::new(true);
    for rva in [0x1000, 0x1000] {
        pe.sections.push(SynthSection {
            name: section_name(".x"),
            rva,
            data: vec![0; 0x10],
            virtual_size: 0,
            characteristics: SCN_MEM_READ,
        });
    }
    let bytes = pe.build();
    let file = PeFile::parse(&bytes).unwrap();
    assert!(
        file.diagnostics()
            .iter()
            .any(|d| d.kind == DiagnosticKind::SectionsOverlap)
    );
    assert_eq!(file.regions().len(), 2);
    // A directory pointing nowhere.
    let mut pe = SynthPe::new(true);
    pe.directories[dir::IMPORT] = (0x7000_0000, 20);
    let bytes = pe.build();
    let file = PeFile::parse(&bytes).unwrap();
    assert!(file.imports().is_empty());
    assert!(
        file.diagnostics()
            .iter()
            .any(|d| d.kind == DiagnosticKind::DirectoryUnmapped)
    );
}

/// Exercises every accessor; used by the never-panics tests.
fn read_everything(b: &[u8]) {
    let Ok(pe) = PeFile::parse(b) else { return };
    for s in pe.sections() {
        let _ = pe.section_name(s);
    }
    for r in pe.regions() {
        let _ = pe.bytes_at_rva(r.start);
        let _ = pe.bytes_at_rva(r.end.saturating_sub(1));
    }
    let _ = pe.imports();
    let _ = pe.iat_names();
    let _ = pe.exports();
    let _ = pe.relocations().take(1 << 16).count();
    let _ = pe.runtime_functions();
    let _ = pe.tls();
    let _ = pe.debug_entries();
    let _ = pe.codeview();
    for s in pe.coff_symbols() {
        let _ = pe.symbol_rva(&s);
    }
    let _ = pe.overlay();
    let _ = pe.diagnostics();
}

#[test]
fn never_panics_on_truncated_input() {
    for (p, d) in [(true, false), (true, true), (false, false), (false, true)] {
        let s = sample(p, d);
        for n in 0..s.bytes.len() {
            read_everything(&s.bytes[..n]);
        }
    }
}

#[test]
fn never_panics_on_mutated_input() {
    // A deterministic xorshift; every byte of the headers, and a sample of
    // the rest, set to interesting values.
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for (p, d) in [(true, true), (false, true)] {
        let s = sample(p, d);
        let header_end = 0x400.min(s.bytes.len());
        for i in 0..header_end {
            for v in [0x00, 0xff, 0x7f, 0x80, 0x01] {
                let mut b = s.bytes.clone();
                b[i] = v;
                read_everything(&b);
            }
        }
        for _ in 0..3000 {
            let mut b = s.bytes.clone();
            for _ in 0..1 + rnd() % 8 {
                let i = (rnd() as usize) % b.len();
                b[i] = rnd() as u8;
            }
            read_everything(&b);
        }
    }
}

#[test]
fn huge_counts_stay_bounded() {
    // Every count field set to its maximum: parsing must stay fast and small.
    let s = sample(true, true);
    let mut b = s.bytes.clone();
    let fh = SynthPe::PE_OFFSET + 4;
    b[fh + 2..fh + 4].copy_from_slice(&u16::MAX.to_le_bytes());
    b[fh + 8..fh + 12].copy_from_slice(&0x200u32.to_le_bytes());
    b[fh + 12..fh + 16].copy_from_slice(&u32::MAX.to_le_bytes());
    let oh = fh + 20;
    // Exception directory size: 4 GiB.
    let dirs = oh + 112;
    b[dirs + 3 * 8 + 4..dirs + 3 * 8 + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    b[dirs + 5 * 8 + 4..dirs + 5 * 8 + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    read_everything(&b);
}

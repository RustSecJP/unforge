//! Disassembly of PE images: the hand-built sample (`unforge_pe::synth`),
//! truncated and mutated copies of it, and the real Rust PE files of
//! `testdata/pe/bin` when they have been built.

use std::path::PathBuf;

use unforge_disasm::{Bitness, Flow, bitness_for_pe, disassemble_pe_function, pe_function_bytes};
use unforge_pe::PeFile;
use unforge_pe::synth::sample;

#[test]
fn machines() {
    assert_eq!(bitness_for_pe(0x8664), Some(Bitness::B64));
    assert_eq!(bitness_for_pe(0x14c), Some(Bitness::B32));
    assert_eq!(bitness_for_pe(0xaa64), None);
}

#[test]
fn sample_main_x64() {
    let s = sample(true, false);
    let pe = PeFile::parse(&s.bytes).unwrap();
    let main = s.image_base + u64::from(s.main.0);
    let insns = disassemble_pe_function(&pe, main, u64::from(s.main.1), 100).unwrap();
    let text: Vec<String> = insns
        .iter()
        .map(|i| format!("{} {}", i.mnemonic, i.operands))
        .collect();
    assert_eq!(text[0], "push rbx");
    assert_eq!(insns.last().unwrap().flow, Flow::Return);
    // lea rcx, [Location]; call [IAT slot of CreateFileW]; call helper; call leaf
    let lea = insns.iter().find(|i| i.mnemonic == "lea").unwrap();
    assert_eq!(lea.target, Some(s.image_base + u64::from(s.location)));
    let calls: Vec<Option<u64>> = insns
        .iter()
        .filter(|i| i.flow == Flow::Call)
        .map(|i| i.target)
        .collect();
    let slot = s
        .iat
        .iter()
        .find(|(_, n)| n.ends_with("CreateFileW"))
        .unwrap()
        .0;
    assert_eq!(
        calls,
        vec![
            Some(s.image_base + u64::from(slot)),
            Some(s.image_base + u64::from(s.helper.0)),
            Some(s.image_base + u64::from(s.leaf)),
        ]
    );
    // Unknown size: up to the first ret.
    let until_ret = disassemble_pe_function(&pe, main, 0, 100).unwrap();
    assert_eq!(until_ret.len(), insns.len());
}

#[test]
fn sample_main_x86() {
    let s = sample(false, false);
    let pe = PeFile::parse(&s.bytes).unwrap();
    let main = s.image_base + u64::from(s.main.0);
    let insns = disassemble_pe_function(&pe, main, 0, 100).unwrap();
    assert_eq!(insns[0].mnemonic, "push");
    assert_eq!(insns[0].operands, "ebp");
    let slot = s.image_base + u64::from(s.iat[0].0);
    assert!(
        insns
            .iter()
            .any(|i| i.flow == Flow::Call && i.operands.contains(&format!("{slot:x}"))),
        "{insns:?}"
    );
    assert_eq!(insns.last().unwrap().flow, Flow::Return);
}

#[test]
fn outside_the_image() {
    let s = sample(true, false);
    let pe = PeFile::parse(&s.bytes).unwrap();
    assert!(pe_function_bytes(&pe, 0, 16).is_none());
    assert!(pe_function_bytes(&pe, s.image_base + 0x10_0000, 16).is_none());
    // Zero-fill of .data is not code.
    assert!(pe_function_bytes(&pe, s.image_base + 0x4000 + 0x300, 16).is_none());
}

#[test]
fn never_panics() {
    for p in [true, false] {
        let s = sample(p, true);
        let main = s.image_base + u64::from(s.main.0);
        for n in 0..s.bytes.len() {
            if let Ok(pe) = PeFile::parse(&s.bytes[..n]) {
                let _ = disassemble_pe_function(&pe, main, 0, 64);
                let _ = disassemble_pe_function(&pe, main, u64::MAX, 64);
            }
        }
    }
}

#[test]
fn real_pe_main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pe/bin");
    let mut seen = 0;
    for target in ["x86_64-pc-windows-msvc", "i686-pc-windows-msvc"] {
        let p = dir.join(target).join("winapp-O2.exe");
        let Ok(data) = std::fs::read(&p) else {
            continue;
        };
        seen += 1;
        let map = std::fs::read_to_string(p.with_extension("map")).unwrap();
        // The program's main: `_RNv...6winapp4main` in the map.
        let line = map.lines().find(|l| l.contains("6winapp4main")).unwrap();
        let addr = u64::from_str_radix(line.split_whitespace().nth(2).unwrap(), 16).unwrap();
        let pe = PeFile::parse(&data).unwrap();
        let insns = disassemble_pe_function(&pe, addr, 0, 4000).unwrap();
        assert!(insns.len() > 10, "{}", p.display());
        assert!(insns.iter().all(|i| i.flow != Flow::Invalid), "{insns:?}");
        assert!(insns.iter().any(|i| i.flow == Flow::Call));
    }
    if seen == 0 {
        eprintln!("skipped: run testdata/pe/build.sh to build the PE corpus");
    }
}

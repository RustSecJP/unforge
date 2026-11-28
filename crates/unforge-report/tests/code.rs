//! The code map and instruction text the Listing uses.

use std::path::Path;

use unforge_report::code::{code_map, disasm_at, parse_code_map};
use unforge_report::report;

fn own_exe() -> Vec<u8> {
    std::fs::read(std::env::current_exe().unwrap()).unwrap()
}

#[test]
fn code_map_covers_the_functions() {
    let data = own_exe();
    let map = code_map(&data);
    let recs = parse_code_map(&map);
    assert!(recs.len() > 100, "{} functions with code", recs.len());
    // every byte of the map is used: no trailing garbage
    let used: usize = recs.iter().map(|(_, l)| 12 + l.len()).sum();
    assert_eq!(used, map.len());
    assert!(recs.windows(2).all(|w| w[0].0 < w[1].0), "address order");
    // a function of known size decodes to exactly its size
    let r = report(&data).unwrap();
    let mut checked = 0;
    for (start, lens) in &recs {
        let f = r.function_rows.iter().find(|f| f.start == *start).unwrap();
        assert!(lens.iter().all(|&l| (1..=15).contains(&l)));
        if f.size > 0 {
            let sum: u64 = lens.iter().map(|&l| u64::from(l)).sum();
            assert!(sum <= f.size + 14, "{:#x}: {sum} vs {}", f.start, f.size);
            checked += 1;
        }
    }
    assert!(checked > 100);
}

#[test]
fn text_of_instructions_on_screen() {
    let data = own_exe();
    let map = code_map(&data);
    let recs = parse_code_map(&map);
    let (start, lens) = recs.iter().find(|(_, l)| l.len() > 5).unwrap();
    let mut addrs = vec![*start];
    for l in &lens[..4] {
        addrs.push(addrs.last().unwrap() + u64::from(*l));
    }
    let text = disasm_at(&data, &addrs);
    assert_eq!(text.len(), addrs.len());
    for (i, t) in text.iter().enumerate() {
        let t = t.as_ref().unwrap();
        assert_eq!(t.addr, addrs[i]);
        if i < 4 {
            assert_eq!(t.len, lens[i]);
        }
        assert!(!t.mnemonic.is_empty());
    }
    // an address with no file bytes
    assert_eq!(disasm_at(&data, &[u64::MAX - 32]), vec![None]);
}

#[test]
fn no_code_for_other_cpus_or_garbage() {
    assert!(code_map(b"not an elf").is_empty());
    assert_eq!(disasm_at(b"not an elf", &[0, 1]), vec![None, None]);
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/anomalous/files/aarch64");
    let f = std::fs::read_dir(dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(code_map(&std::fs::read(f).unwrap()).is_empty());
}

#[test]
fn parse_stops_at_a_short_record() {
    let mut m = Vec::new();
    m.extend_from_slice(&0x1000u64.to_le_bytes());
    m.extend_from_slice(&2u32.to_le_bytes());
    m.extend_from_slice(&[1, 2]);
    m.extend_from_slice(&0x2000u64.to_le_bytes());
    m.extend_from_slice(&9u32.to_le_bytes());
    m.push(1);
    assert_eq!(parse_code_map(&m), vec![(0x1000, &[1u8, 2][..])]);
}

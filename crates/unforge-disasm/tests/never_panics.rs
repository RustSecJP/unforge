//! Nothing in `unforge-disasm` panics, whatever the bytes: the hand-made
//! anomalous ELF files in `testdata/anomalous/files`, random bytes, and
//! real code cut at every length.

use std::path::{Path, PathBuf};

use unforge_disasm::{
    Bitness, Flow, disassemble, disassemble_function, disassemble_function_bytes, function_bytes,
};

/// Checks the invariants every result must hold.
fn check(v: &[unforge_disasm::Insn], bytes: &[u8], addr: u64, max: usize) {
    assert!(v.len() <= max);
    let mut next = addr;
    let mut total = 0usize;
    for i in v {
        assert_eq!(i.addr, next, "instructions are contiguous");
        assert!((1..=15).contains(&i.len), "{i:?}");
        if i.flow == Flow::Invalid {
            assert_eq!(i.len, 1);
        } else {
            assert!(!i.mnemonic.is_empty());
        }
        assert!(i.mnemonic.len() + i.operands.len() < 256, "{i:?}");
        next = next.wrapping_add(u64::from(i.len));
        total += usize::from(i.len);
    }
    assert!(total <= bytes.len());
    if v.len() < max {
        assert_eq!(total, bytes.len(), "stops only at the end of the bytes");
    }
}

fn every_mode(bytes: &[u8], addr: u64, max: usize) {
    for b in [Bitness::B32, Bitness::B64] {
        let v = disassemble(bytes, addr, b, max);
        check(&v, bytes, addr, max);
        for size in [0, 1, bytes.len() as u64] {
            let v = disassemble_function_bytes(bytes, addr, size, b, max);
            assert!(v.len() <= max);
        }
    }
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_files(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// Disassembles every function `unforge-analysis` finds, plus addresses
/// around the entry point and the segment boundaries.
fn whole_file(data: &[u8]) {
    every_mode(data.get(..4096).unwrap_or(data), 0, 2000);
    let Ok(analysis) = unforge_analysis::Analysis::new(data) else {
        return;
    };
    let Some(elf) = analysis.elf() else {
        return;
    };
    for f in analysis.functions().iter().take(2000) {
        for size in [f.size, 0, u64::MAX] {
            if let Some(v) = disassemble_function(elf, f.start, size, 500) {
                assert!(v.len() <= 500);
            }
            if let Some(b) = function_bytes(elf, f.start, size)
                && size != 0
            {
                assert!(b.len() as u64 <= size);
            }
        }
    }
    let mut addrs = vec![elf.header().entry, 0, u64::MAX];
    if let Ok(phs) = elf.program_headers() {
        for ph in phs.iter().take(64) {
            for a in [
                ph.vaddr,
                ph.vaddr.wrapping_add(ph.filesz),
                ph.vaddr.wrapping_add(ph.memsz),
            ] {
                addrs.extend([a.wrapping_sub(1), a, a.wrapping_add(1)]);
            }
        }
    }
    for a in addrs {
        for size in [0, 1, 16, u64::MAX] {
            let _ = disassemble_function(elf, a, size, 200);
        }
    }
}

#[test]
fn anomalous_files() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/anomalous/files");
    let mut files = Vec::new();
    collect_files(&dir, &mut files);
    assert!(!files.is_empty(), "no files under {}", dir.display());
    for p in &files {
        let data = std::fs::read(p).expect("read testdata");
        whole_file(&data);
    }
    eprintln!("checked {} anomalous files", files.len());
}

/// xorshift64*: deterministic random bytes without a dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

#[test]
fn random_bytes() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for round in 0..2000 {
        let n = (rng.next() % 300) as usize;
        let bytes = rng.bytes(n);
        let addr = if round % 3 == 0 {
            u64::MAX - (rng.next() % 64)
        } else {
            rng.next()
        };
        every_mode(&bytes, addr, usize::MAX);
        every_mode(&bytes, addr, (rng.next() % 8) as usize);
    }
    // Long prefix runs: the decoder must reject them, not loop.
    for b in [0x66u8, 0xf0, 0xf2, 0xf3, 0x2e, 0x48, 0x0f, 0xc4, 0x62, 0x8f] {
        every_mode(&[b; 64], 0x1000, usize::MAX);
    }
}

#[test]
fn real_code_truncated_at_every_length() {
    let exe = std::env::current_exe().expect("current_exe");
    let data = std::fs::read(&exe).expect("read current_exe");
    let elf = unforge_elf::ElfFile::parse(&data).expect("parse current_exe");
    let (_, text) = elf.section_by_name(b".text").expect(".text");
    let code = elf.section_data(&text).expect(".text bytes");
    let mut rng = Rng(7);
    for _ in 0..200 {
        let start = (rng.next() as usize) % code.len().max(1);
        let window = code.get(start..(start + 64).min(code.len())).unwrap_or(&[]);
        for len in 0..=window.len() {
            every_mode(&window[..len], text.addr + start as u64, usize::MAX);
        }
    }
    // The whole ELF file through the ELF helpers, too.
    whole_file(&data);
}

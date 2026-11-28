//! Drive `unforge-disasm` on arbitrary bytes, both as raw code and as an
//! ELF file. The only property checked is "no panic, no abort, bounded
//! memory", plus the invariants every decoded instruction list must hold.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unforge_disasm::{Bitness, Flow, disassemble, disassemble_function, function_bytes};

/// Instructions decoded per call.
const MAX_INSNS: usize = 1 << 12;

fuzz_target!(|data: &[u8]| {
    let addr = data
        .get(..8)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map_or(0, u64::from_le_bytes);
    for bitness in [Bitness::B32, Bitness::B64] {
        let v = disassemble(data, addr, bitness, MAX_INSNS);
        let mut next = addr;
        let mut total = 0usize;
        for i in &v {
            assert_eq!(i.addr, next);
            assert!((1..=15).contains(&i.len));
            assert!(i.flow != Flow::Invalid || i.len == 1);
            next = next.wrapping_add(u64::from(i.len));
            total += usize::from(i.len);
        }
        assert!(total <= data.len());
        assert!(v.len() == MAX_INSNS || total == data.len());
    }
    let Ok(elf) = unforge_elf::ElfFile::parse(data) else {
        return;
    };
    let entry = elf.header().entry;
    for start in [entry, addr, entry.wrapping_add(1)] {
        for size in [0, 1, 64, u64::MAX] {
            if let Some(b) = function_bytes(&elf, start, size) {
                assert!(size == 0 || b.len() as u64 <= size);
            }
            let _ = disassemble_function(&elf, start, size, 256);
        }
    }
});

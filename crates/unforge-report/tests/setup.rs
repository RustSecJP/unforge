//! What the decompiler helper is told about a file, and the comments added
//! to its output.

use unforge_elf::ElfFile;
use unforge_report::code::{annotate, panic_location_at, relocated};
use unforge_report::setup::{SlotTarget, decompiler_setup, pointer_slots};

fn own_exe() -> Vec<u8> {
    std::fs::read(std::env::current_exe().unwrap()).unwrap()
}

#[test]
fn relocated_pointer_slots() {
    let data = own_exe();
    let elf = ElfFile::parse(&data).unwrap();
    let slots = pointer_slots(&elf);
    // A Rust test binary is a PIE full of relative relocations (vtables,
    // panic locations, the GOT).
    let addresses = slots
        .iter()
        .filter(|(_, t)| matches!(t, SlotTarget::Address(_)))
        .count();
    assert!(addresses > 100, "{addresses} relocated addresses");
    // and imports libc symbols by name
    assert!(
        slots
            .iter()
            .any(|(_, t)| matches!(t, SlotTarget::Import(n) if !n.is_empty()))
    );
}

#[test]
fn setup_commands() {
    let data = own_exe();
    let (lang, lines) = decompiler_setup(&data).unwrap();
    assert_eq!(lang, "x86:LE:64:default:gcc");
    let mut kinds = std::collections::BTreeMap::new();
    for l in lines.lines() {
        let mut p = l.split(' ');
        let kind = p.next().unwrap();
        *kinds.entry(kind).or_insert(0) += 1;
        let addr = p.next().unwrap();
        assert!(u64::from_str_radix(addr, 16).is_ok(), "{l}");
        assert!(!l.chars().any(|c| c.is_control()), "{l:?}");
    }
    for k in ["seg", "sym", "ptr", "ext"] {
        assert!(kinds.contains_key(k), "no {k} lines: {kinds:?}");
    }
    assert!(decompiler_setup(b"not an elf").is_none());
}

#[test]
fn finds_panic_locations() {
    // Panic locations sit in relocated read-only data: try every slot.
    let data = own_exe();
    let elf = ElfFile::parse(&data).unwrap();
    let map = elf.memory_map();
    let relocs = relocated(&elf);
    let found: Vec<_> = relocs
        .keys()
        .filter_map(|&a| panic_location_at(&data, &map, &relocs, a))
        .collect();
    assert!(found.len() > 10, "{} panic locations", found.len());
    assert!(found.iter().all(|l| l.file.ends_with(".rs") && l.line > 0));
    // and annotate() names one when its address appears in code
    let (addr, loc) = relocs
        .keys()
        .find_map(|&a| panic_location_at(&data, &map, &relocs, a).map(|l| (a, l)))
        .unwrap();
    let code = format!("  core::panicking::panic_bounds_check(i,4,{addr:#x});\n");
    let out = annotate(&data, &code);
    assert!(
        out.contains(&format!("// at {}:{}:{}", loc.file, loc.line, loc.col)),
        "{out}"
    );
}

#[test]
fn annotate_leaves_other_code_alone() {
    let data = own_exe();
    let code = "  uVar3 = FUN_1234(0x1, 2);\n  return iVar1;\n";
    assert_eq!(annotate(&data, code), code);
    assert_eq!(annotate(b"garbage", code), code);
}

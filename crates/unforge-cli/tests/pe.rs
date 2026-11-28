//! `unforge pe`, and `unforge disasm` / `unforge sig` on PE images, end to
//! end, with the hand-built images of `unforge_pe::synth`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use unforge_pe::synth::sample;

const BIN: &str = env!("CARGO_BIN_EXE_unforge");

fn run(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn unforge")
}

fn write_temp(tag: &str, bytes: &[u8]) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let p = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("cli-pe-{}-{tag}-{n}", std::process::id()));
    std::fs::write(&p, bytes).expect("write temp file");
    p
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn no_panic(o: &Output, what: &str) {
    assert!(!err(o).contains("panicked at"), "{what}: {}", err(o));
    assert!(
        matches!(o.status.code(), Some(0 | 1)),
        "{what}: {:?}",
        o.status
    );
}

#[test]
fn pe_prints_every_part() {
    let s = sample(true, true);
    let p = write_temp("dll", &s.bytes);
    let o = run(&["pe".as_ref(), p.as_os_str()]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    let text = out(&o);
    for want in [
        "Machine:              x86-64 (0x8664)",
        "Kind:                 DLL",
        "PE32+ (magic 0x20b)",
        "ImageBase:            0x180000000",
        "PDB:                  C:\\\\Users",
        "Sections (5):",
        ".pdata",
        "KERNEL32.dll",
        "CreateFileW (hint 0)",
        "#115",
        "Exports (3, synth.dll):",
        "helper",
        "-> NTDLL.RtlExitUserThread",
        "Exception table (.pdata): 4 entries, 3 function starts, 1 chained parts",
        "TLS callbacks (1):",
        "Base relocations: ",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    // One part only.
    let o = run(&["pe".as_ref(), "--imports".as_ref(), p.as_os_str()]);
    let text = out(&o);
    assert!(text.starts_with("Imports (2 DLLs, 3 functions):"), "{text}");
    assert!(!text.contains("Sections"));
}

#[test]
fn pe_strict_and_errors() {
    let s = sample(false, false);
    let cut = write_temp("cut", &s.bytes[..s.bytes.len() - 0x100]);
    let o = run(&["pe".as_ref(), cut.as_os_str()]);
    assert_eq!(o.status.code(), Some(0));
    assert!(err(&o).contains("warning:"), "{}", err(&o));
    let o = run(&["pe".as_ref(), "--strict".as_ref(), cut.as_os_str()]);
    assert_eq!(o.status.code(), Some(1));
    let elf = write_temp("notpe", b"\x7fELF");
    let o = run(&["pe".as_ref(), elf.as_os_str()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("not a PE file"), "{}", err(&o));
    let o = run(&["pe".as_ref()]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn disasm_pe_entry_and_iat_names() {
    let s = sample(true, false);
    let p = write_temp("exe", &s.bytes);
    let o = run(&["disasm".as_ref(), p.as_os_str()]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    let text = out(&o);
    let main = s.image_base + u64::from(s.main.0);
    assert!(
        text.starts_with(&format!("{main:016x} <<unknown>> (34 bytes):")),
        "{text}"
    );
    assert!(text.contains("push rbx"));
    assert!(text.contains("; -> KERNEL32.dll!CreateFileW"), "{text}");
    // x86
    let s = sample(false, false);
    let p = write_temp("exe32", &s.bytes);
    let o = run(&[
        "disasm".as_ref(),
        "--addr".as_ref(),
        format!("{:x}", s.image_base + u64::from(s.main.0)).as_ref(),
        p.as_os_str(),
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(out(&o).contains("push ebp"), "{}", out(&o));
}

#[test]
fn sig_accepts_pe() {
    let s = sample(true, true);
    let p = write_temp("sigdll", &s.bytes);
    let db = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("pe-{}.db", std::process::id()));
    // The DLL's exports are names: `helper` is too small for the default
    // threshold, so build without one.
    let o = run(&[
        "sig".as_ref(),
        "build".as_ref(),
        "--min-insns".as_ref(),
        "1".as_ref(),
        "--min-bytes".as_ref(),
        "1".as_ref(),
        "-o".as_ref(),
        db.as_os_str(),
        p.as_os_str(),
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    let o = run(&[
        "sig".as_ref(),
        "match".as_ref(),
        "--db".as_ref(),
        db.as_os_str(),
        p.as_os_str(),
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(out(&o).contains("helper"), "{}", out(&o));
}

#[test]
fn truncated_pe_never_panics() {
    let s = sample(true, true);
    for n in (0..s.bytes.len()).step_by(97) {
        let p = write_temp("trunc", &s.bytes[..n]);
        for cmd in ["pe", "disasm"] {
            let o = run(&[cmd.as_ref(), p.as_os_str()]);
            no_panic(&o, cmd);
        }
        let _ = std::fs::remove_file(p);
    }
}

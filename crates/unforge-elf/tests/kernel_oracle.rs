//! The Linux kernel as the oracle for what a tolerant ELF reader must accept.
//!
//! Inputs, all under `testdata/anomalous/` (see its README.md):
//! - `files/<arch>/<name>.elf`: anomalous files written by
//!   `cargo run -p unforge-testgen -- generate` from committed seeds;
//! - `verdicts.tsv`: what happened when each file was `execve`d in a
//!   locked-down container (`run_oracle.sh`, `probe/probe.rs`).
//!
//! The rule under test: if the kernel's ELF loader (`fs/binfmt_elf.c`,
//! Linux v7.0.12) loaded a file, a reader whose job is to show what runs must
//! read the parts the loader used, and must not fail because of anything the
//! loader ignores (testdata/anomalous/LOADER_RULES.md §1, §2, §5).
//!
//! Only verdicts with `source = kernel` are authoritative. Verdicts produced
//! by an emulator (Rosetta / qemu-user reached through binfmt_misc) are
//! checked the same way but only reported, never asserted: emulators are both
//! stricter and laxer than the kernel (README.md, "Kernel or emulator").
//!
//! "Kernel-accepted" = verdict `ran`, `loaded_then_signal:*`,
//! `loaded_then_exit:*` or `ldso_rejected`. `exec_rejected:*` (execve
//! returned an errno) and `ambiguous:*` (SIGSEGV/SIGKILL without the marker,
//! which may be the kernel aborting the exec after the point of no return,
//! `fs/exec.c:bprm_execve` v7.0.12 lines 1768-1769) are excluded.
//!
//! This file uses only the current public API of `unforge-elf`. Checks that
//! need the proposed diagnostics API are in `tolerant_api.rs`
//! (testdata/anomalous/API_PROPOSAL.md).

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

use unforge_elf::{ElfFile, ProgramHeader};

// gABI / Linux values, spelled out here rather than taken from the code under test.
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
/// `PATH_MAX`, the upper bound `load_elf_binary` puts on `PT_INTERP`
/// `p_filesz` (fs/binfmt_elf.c v7.0.12, lines 890-892).
const PATH_MAX: u64 = 4096;

fn anomalous_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/anomalous")
}

// ---------------------------------------------------------------------------
// verdicts.tsv
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Row {
    path: String,
    sha256: String,
    arch: String,
    technique: String,
    source: String,
    uname_r: String,
    verdict: String,
    detail: String,
}

impl Row {
    fn is_kernel(&self) -> bool {
        self.source == "kernel"
    }
    fn is_emulator(&self) -> bool {
        self.source.starts_with("emulator:")
    }
    /// The loader mapped the file and started user space (or ld.so).
    fn kernel_accepted(&self) -> bool {
        self.verdict == "ran"
            || self.verdict == "ldso_rejected"
            || self.verdict.starts_with("loaded_then_signal:")
            || self.verdict.starts_with("loaded_then_exit:")
    }
    fn label(&self) -> String {
        format!("{} [{} {}]", self.path, self.source, self.verdict)
    }
}

#[derive(Debug)]
struct Verdicts {
    kernel_uname_r: String,
    kernel_uname_m: String,
    rows: Vec<Row>,
}

/// Read verdicts.tsv and refuse it unless its provenance is consistent:
/// every `source=kernel` row must have been produced by the kernel the header
/// declares (same `uname -r`, file architecture = kernel architecture), and
/// every source must be `kernel` or `emulator:*`.
fn verdicts() -> Verdicts {
    let path = anomalous_dir().join("verdicts.tsv");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e}. Run testdata/anomalous/run_oracle.sh to produce it.",
            path.display()
        )
    });
    let mut kernel_uname_r = None;
    let mut kernel_uname_m = None;
    let mut rows = Vec::new();
    let mut saw_columns = false;
    for line in text.lines() {
        if let Some(meta) = line.strip_prefix("# ") {
            if let Some(v) = meta.strip_prefix("kernel_uname_r=") {
                kernel_uname_r = Some(v.to_string());
            } else if let Some(v) = meta.strip_prefix("kernel_uname_m=") {
                kernel_uname_m = Some(v.to_string());
            }
            continue;
        }
        if line.starts_with("path\t") {
            assert_eq!(
                line, "path\tsha256\tarch\ttechnique\tsource\tuname_r\tverdict\tdetail",
                "unexpected verdicts.tsv columns"
            );
            saw_columns = true;
            continue;
        }
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f.len(), 8, "malformed verdicts.tsv row: {line}");
        rows.push(Row {
            path: f[0].into(),
            sha256: f[1].into(),
            arch: f[2].into(),
            technique: f[3].into(),
            source: f[4].into(),
            uname_r: f[5].into(),
            verdict: f[6].into(),
            detail: f[7].into(),
        });
    }
    assert!(saw_columns, "verdicts.tsv has no column header line");
    let kernel_uname_r = kernel_uname_r.expect("verdicts.tsv header lacks kernel_uname_r");
    let kernel_uname_m = kernel_uname_m.expect("verdicts.tsv header lacks kernel_uname_m");

    let mut refused = Vec::new();
    for r in &rows {
        if !r.is_kernel() && !r.is_emulator() {
            refused.push(format!("{}: unknown source {:?}", r.path, r.source));
        }
        if r.is_kernel() && r.uname_r != kernel_uname_r {
            refused.push(format!(
                "{}: source=kernel but uname_r {:?} differs from the declared kernel {:?}",
                r.path, r.uname_r, kernel_uname_r
            ));
        }
        if r.is_kernel() && r.arch != kernel_uname_m {
            refused.push(format!(
                "{}: source=kernel but the file is {} and the declared kernel is {}",
                r.path, r.arch, kernel_uname_m
            ));
        }
    }
    assert!(
        refused.is_empty(),
        "refusing verdicts.tsv: its rows do not match its own provenance header:\n{}",
        refused.join("\n")
    );
    Verdicts {
        kernel_uname_r,
        kernel_uname_m,
        rows,
    }
}

fn read_file(row: &Row) -> Vec<u8> {
    let p = anomalous_dir().join(&row.path);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4), so the verdicts can be tied to exact bytes without a
// new dev-dependency.
// ---------------------------------------------------------------------------

fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, c) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [
                t1.wrapping_add(t2),
                v[0],
                v[1],
                v[2],
                v[3].wrapping_add(t1),
                v[4],
                v[5],
                v[6],
            ];
        }
        for (a, b) in h.iter_mut().zip(v) {
            *a = a.wrapping_add(b);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

#[test]
fn sha256_known_answer() {
    // FIPS 180-4 examples.
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

// ---------------------------------------------------------------------------
// The kernel's own view of a file, decoded independently of the reader.
// ---------------------------------------------------------------------------

/// The ELF header fields and program headers `load_elf_binary` uses.
///
/// The native handler reads `bprm->buf` as the host's `struct elfhdr` and
/// never looks at `EI_CLASS` or `EI_DATA` (LOADER_RULES.md §1;
/// fs/binfmt_elf.c v7.0.12 `load_elf_binary`, `load_elf_phdrs`). For the two
/// architectures in this corpus that is ELF64 little-endian.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KernelView {
    e_type: u16,
    e_machine: u16,
    e_entry: u64,
    e_phoff: u64,
    e_phnum: u16,
    phdrs: Vec<ProgramHeader>,
}

fn le16(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?))
}
fn le32(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?))
}
fn le64(d: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(o..o + 8)?.try_into().ok()?))
}

fn kernel_view(data: &[u8], arch: &str) -> Option<KernelView> {
    assert!(
        arch == "aarch64" || arch == "x86_64",
        "kernel_view: unknown arch {arch}"
    );
    let e_phoff = le64(data, 0x20)?;
    let e_phnum = le16(data, 0x38)?;
    let mut phdrs = Vec::new();
    for i in 0..u64::from(e_phnum) {
        let o = usize::try_from(e_phoff.checked_add(i * 56)?).ok()?;
        phdrs.push(ProgramHeader {
            p_type: le32(data, o)?,
            flags: le32(data, o + 4)?,
            offset: le64(data, o + 8)?,
            vaddr: le64(data, o + 16)?,
            paddr: le64(data, o + 24)?,
            filesz: le64(data, o + 32)?,
            memsz: le64(data, o + 40)?,
            align: le64(data, o + 48)?,
        });
    }
    Some(KernelView {
        e_type: le16(data, 0x10)?,
        e_machine: le16(data, 0x12)?,
        e_entry: le64(data, 0x18)?,
        e_phoff,
        e_phnum,
        phdrs,
    })
}

/// The `PT_LOAD` that backs `addr` at run time. Segments are mapped in table
/// order and every one after the first uses `MAP_FIXED`, so the last entry
/// that covers an address wins (fs/binfmt_elf.c v7.0.12, `load_elf_binary`
/// `elf_map` loop; LOADER_RULES.md §2 "Overlap between PT_LOADs"). Coverage is
/// checked per byte over `[p_vaddr, p_vaddr + p_memsz)`, a simplification of
/// the kernel's page-granular mapping that is exact for this corpus.
fn backing_load(phdrs: &[ProgramHeader], addr: u64) -> Option<(usize, &ProgramHeader)> {
    phdrs
        .iter()
        .enumerate()
        .rfind(|(_, p)| p.p_type == PT_LOAD && addr >= p.vaddr && addr - p.vaddr < p.memsz)
}

// ---------------------------------------------------------------------------
// The invariants.
// ---------------------------------------------------------------------------

/// Everything a tolerant reader must get right for a file the kernel loaded.
/// Returns the violations; empty means the reader is fine on this file.
fn tolerant_reader_violations(row: &Row, data: &[u8], notes: &mut Vec<String>) -> Vec<String> {
    let mut v = Vec::new();
    let Some(k) = kernel_view(data, &row.arch) else {
        // The kernel read these bytes, so this cannot happen for an accepted file.
        v.push("ORACLE: the kernel-view decoder could not read the header/phdrs".into());
        return v;
    };

    // 1. parse must succeed: nothing the kernel ignores may be fatal.
    let file = match ElfFile::parse(data) {
        Ok(f) => f,
        Err(e) => {
            v.push(format!(
                "ElfFile::parse failed ({e}); the kernel loaded this file (e_ident after the magic, e_version, e_ehsize, e_flags and all section header fields are ignored by fs/binfmt_elf.c)"
            ));
            return v;
        }
    };

    // 2. The header fields the loader uses must be read as the loader reads them.
    let h = file.header();
    let pairs: [(&str, u64, u64); 5] = [
        ("e_type", h.e_type.into(), k.e_type.into()),
        ("e_machine", h.machine.into(), k.e_machine.into()),
        ("e_entry", h.entry, k.e_entry),
        ("e_phoff", h.phoff, k.e_phoff),
        ("e_phnum", h.phnum, k.e_phnum.into()),
    ];
    for (what, ours, kernel) in pairs {
        if ours != kernel {
            v.push(format!(
                "header {what}: reader {ours:#x}, kernel {kernel:#x} (layout chosen from EI_CLASS/EI_DATA instead of the machine's native layout?)"
            ));
        }
    }
    if k.e_machine != EM_AARCH64 && k.e_machine != EM_X86_64 {
        notes.push(format!(
            "e_machine {:#x} is not this corpus' machine",
            k.e_machine
        ));
    }

    // 3. Program headers must be readable and identical to the kernel's.
    let phdrs = match file.program_headers() {
        Ok(p) => p.iter().collect::<Vec<_>>(),
        Err(e) => {
            v.push(format!("program_headers() failed: {e}"));
            return v;
        }
    };
    if phdrs != k.phdrs {
        v.push(format!(
            "program headers differ from the kernel's decoding: reader has {} entries, kernel {}{}",
            phdrs.len(),
            k.phdrs.len(),
            phdrs
                .iter()
                .zip(&k.phdrs)
                .position(|(a, b)| a != b)
                .map(|i| format!(", first difference at #{i}"))
                .unwrap_or_default()
        ));
        return v;
    }

    // 4. Every PT_LOAD's file bytes must be readable. Clipping to the end of
    //    the file is the only allowed deviation, and only because the kernel
    //    tolerated it for this file: vm_mmap does not check the file size,
    //    so a mapping past EOF succeeds (LOADER_RULES.md §2, "p_offset +
    //    p_filesz beyond end of file").
    let len = data.len() as u64;
    for (i, p) in phdrs
        .iter()
        .enumerate()
        .filter(|(_, p)| p.p_type == PT_LOAD)
    {
        let end = p.offset.saturating_add(p.filesz);
        let start = p.offset.min(len);
        let expected = &data[start as usize..end.min(len) as usize];
        match file.segment_data(p) {
            Ok(bytes) if bytes == expected => {}
            Ok(bytes) => v.push(format!(
                "PT_LOAD #{i}: segment_data returned {} bytes, expected the {} file bytes at {:#x}",
                bytes.len(),
                expected.len(),
                p.offset
            )),
            Err(e) if end > len => v.push(format!(
                "PT_LOAD #{i}: file range [{:#x}, {end:#x}) runs past EOF ({len:#x}); the kernel mapped it anyway, so the reader must return the {} in-file bytes, got error: {e}",
                p.offset,
                expected.len()
            )),
            Err(e) => v.push(format!("PT_LOAD #{i}: segment_data failed: {e}")),
        }
        if end > len {
            // The kernel's rule (fs/binfmt_elf.c v7.0.12 elf_load/padzero):
            // a writable segment with p_memsz > p_filesz whose last file page
            // lies past EOF makes padzero fail with -EFAULT after the point of
            // no return. A kernel-accepted file should not match that rule.
            // padzero() clears from the end of the file data to the end of
            // that page, so the page that matters is the one containing
            // `end` (nothing is written when `end` is page-aligned). Page size
            // assumed 4 KiB here (not verified for linuxkit).
            let zero_page = end & !0xfff;
            if p.flags & PF_W != 0 && p.memsz > p.filesz && end % 0x1000 != 0 && zero_page >= len {
                notes.push(format!(
                    "PT_LOAD #{i}: kernel accepted the file although the padzero rule predicts -EFAULT (page size may differ from 4 KiB)"
                ));
            }
        }
    }

    // 5. The entry point must lie in an executable PT_LOAD, using the kernel's
    //    "later mapping wins" order.
    match backing_load(&phdrs, k.e_entry) {
        Some((_, p)) if p.flags & PF_X != 0 => {}
        Some((i, _)) if row.verdict == "ran" => v.push(format!(
            "entry {:#x} is backed by non-executable PT_LOAD #{i}, but the code ran",
            k.e_entry
        )),
        None if row.verdict == "ran" => v.push(format!(
            "entry {:#x} is not inside any PT_LOAD, but the code ran",
            k.e_entry
        )),
        // Loaded and then crashed: a bad entry is a property of the file.
        _ => notes.push(format!(
            "entry {:#x} not in an executable PT_LOAD (verdict {})",
            k.e_entry, row.verdict
        )),
    }

    // 6. PT_INTERP: the kernel uses the first one and reads p_filesz bytes
    //    from p_offset; it requires 2 <= p_filesz <= PATH_MAX and a final NUL
    //    (fs/binfmt_elf.c v7.0.12 lines 875-934).
    if let Some((i, p)) = phdrs
        .iter()
        .enumerate()
        .find(|(_, p)| p.p_type == PT_INTERP)
    {
        match file.segment_data(p) {
            Ok(b) => {
                if !(2..=PATH_MAX).contains(&p.filesz) || b.last() != Some(&0) {
                    notes.push(format!(
                        "PT_INTERP #{i}: kernel accepted an interpreter string the rules say it refuses"
                    ));
                }
                if b.len() as u64 != p.filesz {
                    v.push(format!(
                        "PT_INTERP #{i}: read {} of {} bytes",
                        b.len(),
                        p.filesz
                    ));
                }
            }
            Err(e) => v.push(format!("PT_INTERP #{i}: not readable: {e}")),
        }
    }

    // 7. The linker view may fail softly, but reading it must not panic.
    if let Err(p) = catch_unwind(AssertUnwindSafe(|| exercise_linker_view(&file))) {
        v.push(format!(
            "panic in the section/symbol accessors: {}",
            panic_text(&p)
        ));
    }
    v
}

/// Call every section and symbol accessor, ignoring errors.
fn exercise_linker_view(file: &ElfFile<'_>) {
    let _ = file.audit();
    if let Ok(sections) = file.section_headers() {
        for sh in sections.iter() {
            let _ = file.section_data(&sh);
            let _ = file.section_name_bounded(&sh, 256);
        }
    }
    if let Ok(tables) = file.symbol_tables() {
        for t in tables {
            for s in t.iter().take(10_000) {
                let _ = t.name_bounded(&s, 256);
            }
        }
    }
    let _ = file.section_name_table();
}

fn panic_text(p: &Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<String>()
        .cloned()
        .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_else(|| "<non-string panic>".into())
}

fn check_rows<'a>(rows: impl Iterator<Item = &'a Row>) -> (usize, Vec<String>, Vec<String>) {
    let mut checked = 0;
    let mut failures = Vec::new();
    let mut notes = Vec::new();
    for row in rows {
        checked += 1;
        let data = read_file(row);
        let mut n = Vec::new();
        let res = catch_unwind(AssertUnwindSafe(|| {
            tolerant_reader_violations(row, &data, &mut n)
        }));
        let violations = res.unwrap_or_else(|p| vec![format!("panic: {}", panic_text(&p))]);
        for x in violations {
            failures.push(format!("{} ({}): {x}", row.label(), row.technique));
        }
        for x in n {
            notes.push(format!("{}: {x}", row.label()));
        }
    }
    (checked, failures, notes)
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

/// verdicts.tsv describes exactly the committed files, byte for byte.
#[test]
fn oracle_provenance_matches_the_files() {
    let vs = verdicts();
    assert!(!vs.kernel_uname_r.is_empty());
    let mut problems = Vec::new();
    for r in &vs.rows {
        let data = read_file(r);
        let sha = sha256_hex(&data);
        if sha != r.sha256 {
            problems.push(format!(
                "{}: sha256 {sha} != recorded {} (regenerate files and rerun run_oracle.sh)",
                r.path, r.sha256
            ));
        }
        if !r.path.starts_with(&format!("files/{}/", r.arch)) {
            problems.push(format!(
                "{}: arch column {} disagrees with the path",
                r.path, r.arch
            ));
        }
    }
    let in_tsv: BTreeSet<&str> = vs.rows.iter().map(|r| r.path.as_str()).collect();
    let manifest = std::fs::read_to_string(anomalous_dir().join("files/MANIFEST.tsv"))
        .expect("files/MANIFEST.tsv");
    let in_manifest: BTreeSet<&str> = manifest
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split('\t').next())
        .collect();
    for p in in_manifest.symmetric_difference(&in_tsv) {
        problems.push(format!("{p}: in only one of MANIFEST.tsv and verdicts.tsv"));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert!(
        vs.rows.iter().any(|r| r.is_kernel() && r.kernel_accepted()),
        "no authoritative kernel-accepted verdicts at all (kernel {} {})",
        vs.kernel_uname_r,
        vs.kernel_uname_m
    );
}

/// The strict test: every file the real kernel loaded must satisfy the
/// tolerant-reader invariants. Only `source = kernel` verdicts are used.
#[test]
fn kernel_accepted_files_satisfy_tolerant_reader_invariants() {
    let vs = verdicts();
    let (checked, failures, notes) = check_rows(
        vs.rows
            .iter()
            .filter(|r| r.is_kernel() && r.kernel_accepted()),
    );
    for n in &notes {
        eprintln!("note: {n}");
    }
    eprintln!(
        "{checked} kernel-accepted files (kernel {} {}), {} violations",
        vs.kernel_uname_r,
        vs.kernel_uname_m,
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "{} violation(s) on files the kernel loaded:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Emulator verdicts are not authoritative: run the same checks, report the
/// results, never fail on them.
#[test]
fn emulator_verdicts_are_reported_not_asserted() {
    let vs = verdicts();
    let (checked, failures, _) = check_rows(
        vs.rows
            .iter()
            .filter(|r| r.is_emulator() && r.kernel_accepted()),
    );
    eprintln!(
        "{checked} emulator-accepted files; {} would-be violations (informational only):",
        failures.len()
    );
    for f in &failures {
        eprintln!("  emulator-only: {f}");
    }
    let mut sources: BTreeSet<&str> = BTreeSet::new();
    for r in vs.rows.iter().filter(|r| r.is_emulator()) {
        sources.insert(&r.source);
    }
    eprintln!("emulator sources seen: {sources:?}");
}

/// Files the kernel refused (or whose fate is ambiguous) are still input a
/// reader will meet. It may reject them, but must not panic, on any accessor.
#[test]
fn every_file_is_read_without_panic() {
    let vs = verdicts();
    let mut panics = Vec::new();
    let mut rejected = 0;
    for r in &vs.rows {
        if r.is_kernel() && r.verdict.starts_with("exec_rejected:") {
            rejected += 1;
        }
        let data = read_file(r);
        let res = catch_unwind(AssertUnwindSafe(|| {
            if let Ok(f) = ElfFile::parse(&data) {
                if let Ok(phdrs) = f.program_headers() {
                    for p in phdrs {
                        let _ = f.segment_data(&p);
                    }
                }
                exercise_linker_view(&f);
            }
        }));
        if let Err(p) = res {
            panics.push(format!("{}: {}", r.label(), panic_text(&p)));
        }
    }
    assert!(
        rejected > 0,
        "the corpus should contain kernel-rejected controls"
    );
    assert!(panics.is_empty(), "panics:\n{}", panics.join("\n"));
}

/// Every verdict row carries enough detail to audit it (the probe's notes,
/// the machine the container reported).
#[test]
fn verdict_details_name_the_container_machine() {
    let vs = verdicts();
    for r in &vs.rows {
        assert!(
            r.detail.starts_with("uname_m="),
            "{}: detail does not start with uname_m=: {}",
            r.path,
            r.detail
        );
    }
}

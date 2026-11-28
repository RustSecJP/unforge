//! Signatures on real Rust binaries: the test executable itself, and two
//! small std-only programs compiled here with `rustc` (skipped when rustc
//! or objcopy is not available). Only this repository's own code and std
//! are compiled; nothing from crates.io.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use unforge_sigs::{Db, MatchStatus, Options, generic_base, match_elf};

fn tmp(name: &str) -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("sigs-{}-{name}", std::process::id()))
}

fn strip(path: &Path) -> Option<Vec<u8>> {
    let out = tmp(&format!("{}.stripped", path.file_name()?.to_string_lossy()));
    let ok = Command::new("objcopy")
        .arg("--strip-all")
        .arg(path)
        .arg(&out)
        .status()
        .ok()?
        .success();
    if !ok {
        return None;
    }
    std::fs::read(out).ok()
}

/// Precision and recall of matching `b_stripped` against `db`, with
/// `b`'s own symbols as the truth (see the crate README for the rules).
fn score(db: &Db, a_names: &BTreeMap<String, ()>, b: &[u8], b_stripped: &[u8]) -> (f64, f64) {
    let an = unforge_analysis::Analysis::new(b).unwrap();
    let fpr = unforge_sigs::Fingerprinter::new(an.elf().unwrap()).unwrap();
    let truth: BTreeMap<u64, (String, u64)> = an
        .functions()
        .into_iter()
        .filter_map(|f| Some((f.start, (f.name?, f.size))))
        .collect();
    let matches = match_elf(db, b_stripped).unwrap();
    let (mut named, mut ok) = (0usize, 0usize);
    for m in &matches {
        let t = truth.get(&m.start).map_or("", |(n, _)| n.as_str());
        match m.status {
            MatchStatus::Unique => {
                named += 1;
                ok += usize::from(m.names[0].name == t);
            }
            MatchStatus::SameGeneric => {
                named += 1;
                ok += usize::from(generic_base(&m.names[0].name) == generic_base(t));
            }
            _ => {}
        }
    }
    let possible = truth
        .iter()
        .filter(|(start, (name, size))| {
            a_names.contains_key(name)
                && fpr
                    .fingerprint(**start, *size)
                    .is_some_and(|fp| db.options().keeps(fp))
        })
        .count();
    let precision = ok as f64 / named.max(1) as f64;
    let recall = ok as f64 / possible.max(1) as f64;
    eprintln!(
        "named {named}, correct {ok}, possible {possible}: precision {precision:.4}, recall {recall:.4}"
    );
    (precision, recall)
}

fn names_of(data: &[u8]) -> BTreeMap<String, ()> {
    unforge_analysis::Analysis::new(data)
        .unwrap()
        .functions()
        .into_iter()
        .filter(|f| f.size > 0)
        .filter_map(|f| Some((f.name?, ())))
        .collect()
}

fn x86_64_linux() -> bool {
    cfg!(all(target_arch = "x86_64", target_os = "linux"))
}

#[test]
fn same_binary_stripped() {
    if !x86_64_linux() {
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let data = std::fs::read(&exe).unwrap();
    let Some(stripped) = strip(&exe) else {
        eprintln!("skipped: objcopy not found");
        return;
    };
    let mut db = Db::new(Options::default());
    let stats = db.add_elf(&data).unwrap();
    assert!(stats.added > 1000, "{stats:?}");
    // The stripped copy has no symbols left: names come from the database.
    let m = match_elf(&db, &stripped).unwrap();
    let with_symbol = m.iter().filter(|m| m.symbol.is_some()).count();
    assert!(
        with_symbol < 16,
        "{with_symbol} functions still have symbols"
    );
    let (precision, recall) = score(&db, &names_of(&data), &data, &stripped);
    assert!(precision > 0.95, "precision {precision}");
    assert!(recall > 0.6, "recall {recall}");
    // Deterministic: building twice gives the same bytes.
    let mut again = Db::new(Options::default());
    again.add_elf(&data).unwrap();
    assert_eq!(again.to_bytes(), db.to_bytes());
    assert_eq!(Db::from_bytes(&db.to_bytes()).unwrap(), db);
}

const PROGRAM_A: &str = r#"
use std::collections::HashMap;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut m: HashMap<String, usize> = HashMap::new();
    for a in &args { *m.entry(a.clone()).or_default() += a.len(); }
    let mut v: Vec<_> = m.into_iter().collect();
    v.sort();
    println!("{v:?}");
    if args.len() > 5 { panic!("too many: {}", args.len()); }
}
"#;

const PROGRAM_B: &str = r#"
use std::collections::BTreeMap;
use std::io::Write;
fn main() {
    let mut t: BTreeMap<u32, String> = BTreeMap::new();
    for (i, a) in std::env::args().enumerate() { t.insert(i as u32 * 7, a.to_uppercase()); }
    let s = format!("{t:#?}");
    std::io::stderr().write_all(s.as_bytes()).unwrap();
    let n: u64 = s.bytes().map(u64::from).sum();
    std::process::exit((n % 3) as i32);
}
"#;

/// Compiles a std-only program with `rustc -O`, or `None` if that fails.
fn compile(name: &str, src: &str) -> Option<PathBuf> {
    let src_path = tmp(&format!("{name}.rs"));
    std::fs::write(&src_path, src).ok()?;
    let out = tmp(name);
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let ok = Command::new(rustc)
        .args(["--edition", "2021", "-C", "opt-level=3", "-o"])
        .arg(&out)
        .arg(&src_path)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .ok()?
        .success();
    ok.then_some(out)
}

/// The real test: a database from one program names the standard library
/// in a different, stripped program.
#[test]
fn cross_binary() {
    if !x86_64_linux() {
        return;
    }
    let (Some(a), Some(b)) = (compile("prog_a", PROGRAM_A), compile("prog_b", PROGRAM_B)) else {
        eprintln!("skipped: rustc failed");
        return;
    };
    let Some(b_stripped) = strip(&b) else {
        eprintln!("skipped: objcopy not found");
        return;
    };
    let a_data = std::fs::read(&a).unwrap();
    let b_data = std::fs::read(&b).unwrap();
    for options in [Options::default(), Options::NONE] {
        let mut db = Db::new(options);
        db.add_elf(&a_data).unwrap();
        let (precision, recall) = score(&db, &names_of(&a_data), &b_data, &b_stripped);
        assert!(precision > 0.95, "{options:?}: precision {precision}");
        assert!(recall > 0.6, "{options:?}: recall {recall}");
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

/// xorshift64*: deterministic random bytes without a dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

#[test]
fn anomalous_files_and_garbage_never_panic() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/anomalous/files");
    let mut files = Vec::new();
    collect_files(&dir, &mut files);
    assert!(!files.is_empty(), "no files under {}", dir.display());
    let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let mut db = Db::new(Options::NONE);
    db.add_elf(&exe).unwrap();
    for p in &files {
        let data = std::fs::read(p).unwrap();
        let mut d = Db::new(Options::NONE);
        let _ = d.add_elf(&data);
        let _ = Db::from_bytes(&d.to_bytes()).unwrap();
        let _ = match_elf(&db, &data);
        let _ = unforge_sigs::uncovered_dependencies(&db, &data);
        let _ = Db::from_bytes(&data);
    }
    // Random bytes, and random bytes after a valid header.
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let good = db.to_bytes();
    for _ in 0..3000 {
        let n = (rng.next() % 200) as usize;
        let mut b: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        let _ = Db::from_bytes(&b);
        let _ = match_elf(&db, &b);
        b.splice(
            0..0,
            good.iter().take(12 + (rng.next() % 64) as usize).copied(),
        );
        if let Ok(d) = Db::from_bytes(&b) {
            assert_eq!(d.to_bytes(), b);
        }
    }
    // The test executable cut at random lengths, and with random bytes
    // overwritten, still never panics.
    for _ in 0..6 {
        let mut b = exe.clone();
        let cut = (rng.next() as usize) % b.len();
        b.truncate(cut.max(64));
        for _ in 0..64 {
            let i = (rng.next() as usize) % b.len();
            b[i] = rng.next() as u8;
        }
        let _ = match_elf(&db, &b);
    }
}

//! `unforge-bench`: ground truth and scoring for unforge's analysis.
//!
//! ```text
//! unforge-bench truth <debug-binary> -o <truth.json> [--meta <meta.json>]
//! unforge-bench score --stripped <binary> --truth <truth.json> [--json]
//! unforge-bench run <corpus-dir> [--split train|eval] [--out-dir DIR] [--json]
//! unforge-bench split <crate>...
//! ```
//!
//! See `bench/README.md`.

#![forbid(unsafe_code)]

mod lock;
mod model;
mod run;
mod score;
mod truth;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use model::Meta;
use run::Split;

const USAGE: &str = "\
usage:
  unforge-bench truth <debug-binary> -o <truth.json> [--meta <meta.json>]
  unforge-bench score --stripped <binary> --truth <truth.json> [--json]
  unforge-bench run <corpus-dir> [--split train|eval] [--out-dir DIR] [--json]
  unforge-bench split <crate>...

truth   read the ground truth from the DWARF of <debug-binary>. --meta
        defaults to <stem>.meta.json next to a <stem>.debug file.
score   analyse the stripped binary with unforge and compare with the truth.
run     score every <id>.meta.json / <id>.stripped (/ <id>.truth.json) in a
        corpus directory and write <out-dir>/<date>-<split>.json
        (default out-dir: bench/results).
split   print which split (train/eval) each crate belongs to.
";

/// Largest input read, as in the `unforge` CLI (whole files are read).
const MAX_INPUT_LEN: u64 = 4 << 30;

pub(crate) fn read_input(path: &Path) -> Result<Vec<u8>, String> {
    let err = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
    let meta = std::fs::metadata(path).map_err(|e| err(&e))?;
    if !meta.is_file() {
        return Err(err(&"not a regular file"));
    }
    if meta.len() > MAX_INPUT_LEN {
        return Err(err(&"file too large"));
    }
    let mut data = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| err(&e))?
        .take(MAX_INPUT_LEN)
        .read_to_end(&mut data)
        .map_err(|e| err(&e))?;
    Ok(data)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("truth") => cmd_truth(&args[1..]),
        Some("score") => cmd_score(&args[1..]),
        Some("run") => cmd_run(&args[1..]),
        Some("split") => cmd_split(&args[1..]),
        Some("-h" | "--help" | "help") => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => Err(format!("missing or unknown command\n{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "unforge-bench: {e}");
            ExitCode::from(1)
        }
    }
}

/// Splits `args` into positional arguments and `--flag [value]` options.
struct Args {
    positional: Vec<String>,
    options: Vec<(String, Option<String>)>,
}

impl Args {
    fn parse(args: &[String], with_value: &[&str], flags: &[&str]) -> Result<Args, String> {
        let mut a = Args {
            positional: Vec::new(),
            options: Vec::new(),
        };
        let mut it = args.iter();
        while let Some(s) = it.next() {
            if with_value.contains(&s.as_str()) {
                let v = it.next().ok_or_else(|| format!("{s} needs a value"))?;
                a.options.push((s.clone(), Some(v.clone())));
            } else if flags.contains(&s.as_str()) {
                a.options.push((s.clone(), None));
            } else if s.starts_with('-') && s.len() > 1 {
                return Err(format!("unknown option {s}\n{USAGE}"));
            } else {
                a.positional.push(s.clone());
            }
        }
        Ok(a)
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.options
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .and_then(|(_, v)| v.as_deref())
    }

    fn flag(&self, name: &str) -> bool {
        self.options.iter().any(|(k, _)| k == name)
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let b = read_input(path)?;
    serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))
}

fn write_json<T: serde::Serialize>(path: &Path, v: &T) -> Result<(), String> {
    let mut s = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    s.push('\n');
    std::fs::write(path, s).map_err(|e| format!("{}: {e}", path.display()))
}

fn cmd_truth(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args, &["-o", "--meta"], &[])?;
    let [bin] = a.positional.as_slice() else {
        return Err(format!("truth needs one binary\n{USAGE}"));
    };
    let out = a.value("-o").ok_or("truth needs -o <truth.json>")?;
    let bin = PathBuf::from(bin);
    let meta_path = match a.value("--meta") {
        Some(m) => Some(PathBuf::from(m)),
        None => {
            let s = bin.to_string_lossy();
            s.strip_suffix(".debug")
                .map(|stem| PathBuf::from(format!("{stem}.meta.json")))
                .filter(|p| p.is_file())
        }
    };
    let meta: Option<Meta> = meta_path.as_deref().map(read_json).transpose()?;
    let data = read_input(&bin)?;
    let name = bin
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let t = truth::extract(&data, &name, meta.as_ref())?;
    write_json(Path::new(out), &t)?;
    let mut groups = std::collections::BTreeMap::<&str, u64>::new();
    for f in &t.functions {
        let g = if f.group.starts_with("dep:") {
            "dep"
        } else {
            f.group.as_str()
        };
        *groups.entry(g).or_default() += 1;
    }
    let _ = writeln!(
        std::io::stderr(),
        "{name}: {} functions ({}), {} linked dependencies (of {} in Cargo.lock), rustc {}",
        t.functions.len(),
        groups
            .iter()
            .map(|(k, v)| format!("{k} {v}"))
            .collect::<Vec<_>>()
            .join(", "),
        t.dependencies.len(),
        t.lock_packages.len(),
        t.rustc_commit.as_deref().unwrap_or("unknown"),
    );
    Ok(())
}

fn cmd_score(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args, &["--stripped", "--truth"], &["--json"])?;
    let stripped = a
        .value("--stripped")
        .ok_or("score needs --stripped <bin>")?;
    let truth_path = a
        .value("--truth")
        .ok_or("score needs --truth <truth.json>")?;
    let t: model::Truth = read_json(Path::new(truth_path))?;
    let s = run::score_file(Path::new(stripped), &t)?;
    let mut out = std::io::stdout().lock();
    let text = if a.flag("--json") {
        serde_json::to_string_pretty(&s).map_err(|e| e.to_string())? + "\n"
    } else {
        format_score(stripped, &s)
    };
    out.write_all(text.as_bytes()).map_err(|e| e.to_string())
}

fn format_score(name: &str, s: &score::Score) -> String {
    let f = &s.m1_functions;
    let m2 = &s.m2_attribution;
    let d = &s.m3_dependencies;
    let mut o = format!("{name}\n");
    o += &format!(
        "  M1 starts    P {:6.2}  R {:6.2}  F1 {:6.2}   ({} found / {} claimed / {} true)\n",
        f.starts.precision, f.starts.recall, f.starts.f1, f.matched, f.predicted, f.truth
    );
    o += &format!(
        "  M1 bytes     P {:6.2}  R {:6.2}  F1 {:6.2}   ({} / {} / {} bytes)\n",
        f.bytes.precision,
        f.bytes.recall,
        f.bytes.f1,
        f.overlap_bytes,
        f.predicted_bytes,
        f.truth_bytes
    );
    o += &format!(
        "  M2 group     acc {:6.2}  user/lib {:6.2}  coverage {:6.2}   ({} right of {} found)\n",
        m2.accuracy, m2.user_vs_library_accuracy, m2.coverage, m2.correct, m2.matched
    );
    o += &format!(
        "  M3 deps      P {:6.2}  R {:6.2}  F1 {:6.2}   names F1 {:6.2}  ({} / {} / {})\n",
        d.pairs.precision, d.pairs.recall, d.pairs.f1, d.names.f1, d.matched, d.predicted, d.truth
    );
    o += &format!(
        "  total {:6.2}   (strict {:6.2})\n",
        s.total, s.total_strict
    );
    o
}

fn cmd_run(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args, &["--split", "--out-dir"], &["--json"])?;
    let [dir] = a.positional.as_slice() else {
        return Err(format!("run needs one corpus directory\n{USAGE}"));
    };
    let split = match a.value("--split") {
        None | Some("all") => None,
        Some("train") => Some(Split::Train),
        Some("eval") => Some(Split::Eval),
        Some(s) => return Err(format!("unknown split {s} (train, eval, all)")),
    };
    let date = run::today();
    let r = run::run(Path::new(dir), split, &date)?;
    let out_dir = PathBuf::from(a.value("--out-dir").unwrap_or("bench/results"));
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("{}: {e}", out_dir.display()))?;
    let out = out_dir.join(format!("{date}-{}.json", r.split));
    write_json(&out, &r)?;

    let mut o = String::new();
    if a.flag("--json") {
        o = serde_json::to_string_pretty(&r).map_err(|e| e.to_string())? + "\n";
    } else {
        o += &format!(
            "{:<44} {:>5} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7}\n",
            "item", "split", "M1-F1", "M1-byte", "M2-acc", "M2-u/l", "M3-F1", "total"
        );
        for it in &r.items {
            match &it.score {
                Some(s) => {
                    o += &format!(
                        "{:<44} {:>5} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>7.2}\n",
                        it.id,
                        it.split.name(),
                        s.m1_functions.starts.f1,
                        s.m1_functions.bytes.f1,
                        s.m2_attribution.accuracy,
                        s.m2_attribution.user_vs_library_accuracy,
                        s.m3_dependencies.pairs.f1,
                        s.total
                    )
                }
                None => {
                    o += &format!(
                        "{:<44} {:>5} FAILED: {}\n",
                        it.id,
                        it.split.name(),
                        it.error.as_deref().unwrap_or("")
                    )
                }
            }
        }
        o += "\n";
        let mut rows: Vec<(String, &run::Aggregate)> = vec![("ALL".to_owned(), &r.overall)];
        rows.extend(r.per_split.iter().map(|(k, v)| (format!("split {k}"), v)));
        rows.extend(
            r.per_variant
                .iter()
                .map(|(k, v)| (format!("variant {k}"), v)),
        );
        o += &format!(
            "{:<20} {:>5} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7}\n",
            "aggregate",
            "n",
            "M1-F1",
            "M1-byte",
            "M2-acc",
            "M2-u/l",
            "M2-cov",
            "M3-F1",
            "total",
            "strict"
        );
        for (k, v) in rows {
            o += &format!(
                "{:<20} {:>5} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>7.2}\n",
                k,
                v.items - v.failed,
                v.m1_start_f1,
                v.m1_byte_f1,
                v.m2_accuracy,
                v.m2_user_vs_library,
                v.m2_coverage,
                v.m3_f1,
                v.total,
                v.total_strict
            );
        }
        o += &format!("\nwritten: {}\n", out.display());
    }
    std::io::stdout()
        .lock()
        .write_all(o.as_bytes())
        .map_err(|e| e.to_string())
}

fn cmd_split(args: &[String]) -> Result<(), String> {
    let mut o = String::new();
    for c in args {
        o += &format!("{c}\t{}\n", run::split_of(c).name());
    }
    std::io::stdout()
        .lock()
        .write_all(o.as_bytes())
        .map_err(|e| e.to_string())
}

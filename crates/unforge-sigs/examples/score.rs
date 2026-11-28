//! Precision and recall of signature matching (see the crate README).
//!
//! ```text
//! cargo run --release -p unforge-sigs --example score -- [--no-threshold] [--diff N] \
//!     <B-with-symbols> <B-stripped> <A-with-symbols>...
//! ```
//!
//! Builds a database from the A files, matches the stripped copy of B and
//! scores the names against B's own symbols (same addresses: `strip` does
//! not move code). `--diff N` prints up to N functions that A and B both
//! name but that were not named correctly: the differing normalized lines,
//! or, when the code is the same, what the match found at that start.
//!
//! Scoring, per matched start of B:
//! - `unique`: one name; correct when it is B's name.
//! - `generic`: several instantiations of one generic function; correct
//!   when B's name is an instantiation of that same function
//!   (`generic_base`), "exact" when B's own name is among those kept.
//! - `ambiguous`: unrelated names; not counted as a name given.
//!
//! precision = correct / (unique + generic); recall = correct / functions
//! of B that pass the threshold and whose name A has too.

use std::collections::{BTreeMap, BTreeSet};

use unforge_sigs::{Db, Fingerprinter, MatchStatus, Options, generic_base, match_elf};

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut options = Options::default();
    let mut diff = 0usize;
    if let Some(p) = args.iter().position(|a| a == "--no-threshold") {
        args.remove(p);
        options = Options::NONE;
    }
    if let Some(p) = args.iter().position(|a| a == "--diff") {
        args.remove(p);
        diff = args.remove(p).parse().expect("--diff N");
    }
    let [b_sym, b_stripped, a_files @ ..] = args.as_slice() else {
        eprintln!("usage: score [--no-threshold] [--diff N] <B> <B-stripped> <A>...");
        std::process::exit(2);
    };
    let read = |p: &str| std::fs::read(p).unwrap_or_else(|e| panic!("{p}: {e}"));

    let mut db = Db::new(options);
    let mut a_code: BTreeMap<String, (usize, u64, u64)> = BTreeMap::new();
    let a_data: Vec<Vec<u8>> = a_files.iter().map(|a| read(a)).collect();
    for (k, data) in a_data.iter().enumerate() {
        let stats = db.add_elf(data).expect("build");
        eprintln!("A {}: {stats:?}", a_files[k]);
        let an = unforge_analysis::Analysis::new(data).expect("A");
        for f in an.functions() {
            if let Some(n) = f.name
                && f.size > 0
            {
                a_code.entry(n).or_insert((k, f.start, f.size));
            }
        }
    }
    let bytes = db.to_bytes();
    let names: usize = db.entries().map(|(_, e)| e.names.len()).sum();
    let name_bytes: usize = db
        .entries()
        .flat_map(|(_, e)| e.names.iter().map(|n| n.name.len()))
        .sum();
    println!(
        "db: {} fingerprints, {names} names, {} bytes ({:.0} bytes per 10k fingerprints, \
         {:.1}% name text)",
        db.len(),
        bytes.len(),
        bytes.len() as f64 * 10_000.0 / db.len().max(1) as f64,
        100.0 * name_bytes as f64 / bytes.len().max(1) as f64
    );

    let b_data = read(b_sym);
    let b_an = unforge_analysis::Analysis::new(&b_data).expect("B");
    let b_fpr = Fingerprinter::new(b_an.image()).expect("B");
    let truth: BTreeMap<u64, (String, u64)> = b_an
        .functions()
        .into_iter()
        .filter_map(|f| Some((f.start, (f.name?, f.size))))
        .collect();

    let matches = match_elf(&db, &read(b_stripped)).expect("match");
    let (mut unique, mut unique_ok) = (0usize, 0usize);
    let (mut generic, mut generic_ok, mut generic_exact) = (0usize, 0usize, 0usize);
    let (mut ambiguous, mut ambiguous_with_truth) = (0usize, 0usize);
    let mut wrong: Vec<String> = Vec::new();
    let mut ok_starts: BTreeSet<u64> = BTreeSet::new();
    for m in matches.iter().filter(|m| m.status.is_match()) {
        let t = truth.get(&m.start).map(|(n, _)| n.as_str()).unwrap_or("");
        let exact = m.names.iter().any(|n| n.name == t);
        let ok = match m.status {
            MatchStatus::Unique => {
                unique += 1;
                unique_ok += usize::from(exact);
                exact
            }
            MatchStatus::SameGeneric => {
                generic += 1;
                generic_exact += usize::from(exact);
                let ok = m
                    .names
                    .first()
                    .is_some_and(|n| generic_base(&n.name) == generic_base(t));
                generic_ok += usize::from(ok);
                ok
            }
            _ => {
                ambiguous += 1;
                ambiguous_with_truth += usize::from(exact);
                continue;
            }
        };
        if ok {
            ok_starts.insert(m.start);
        } else if wrong.len() < 10 {
            wrong.push(format!(
                "  wrong {:#x}: true {t} / given {}",
                m.start,
                m.display_name().unwrap_or_default()
            ));
        }
    }

    let mut possible = 0usize;
    let mut shown = 0usize;
    for (&start, (name, size)) in &truth {
        let Some(&(k, a_start, a_size)) = a_code.get(name) else {
            continue;
        };
        let Some(fp) = b_fpr.fingerprint(start, *size) else {
            continue;
        };
        if !options.keeps(fp) {
            continue;
        }
        possible += 1;
        if shown >= diff || ok_starts.contains(&start) {
            continue;
        }
        shown += 1;
        let a_an = unforge_analysis::Analysis::new(&a_data[k]).expect("A");
        let a_fpr = Fingerprinter::new(a_an.image()).expect("A");
        let la = a_fpr.normalized_lines(a_start, a_size);
        let lb = b_fpr.normalized_lines(start, *size);
        if la == lb {
            let m = matches.iter().find(|m| m.start == start);
            println!(
                "== same code, not named: {name} at {start:#x} size {size}: {:?}",
                m.map(|m| (m.size, m.status, m.names.len()))
            );
        } else {
            println!("== {name} (A {a_start:#x}, B {start:#x})");
            for i in 0..la.len().max(lb.len()) {
                let x = la.get(i).map_or("", String::as_str);
                let y = lb.get(i).map_or("", String::as_str);
                if x != y {
                    println!("  {i:4}  A: {x:40}  B: {y}");
                }
            }
        }
    }

    let pct = |a: usize, b: usize| 100.0 * a as f64 / b.max(1) as f64;
    let named = unique + generic;
    let ok = unique_ok + generic_ok;
    println!(
        "threshold {}/{}: starts {}, possible {possible}; unique {unique} ({unique_ok} ok), \
         generic {generic} ({generic_ok} ok, {generic_exact} exact), ambiguous {ambiguous} \
         ({ambiguous_with_truth} with the true name)",
        options.min_insns,
        options.min_bytes,
        matches.len(),
    );
    println!(
        "precision {:.2}% (unique only {:.2}%), recall {:.2}%",
        pct(ok, named),
        pct(unique_ok, unique),
        pct(ok, possible)
    );
    for w in &wrong {
        println!("{w}");
    }
}

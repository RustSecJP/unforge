//! Comparing an analysis with the ground truth.
//!
//! Every metric is a percentage (0-100). See `bench/README.md` for what each
//! one means for an analyst.
//!
//! - **M1 function boundaries**: precision / recall / F1 of recovered start
//!   addresses (exact match), and of byte coverage (the union of
//!   `[start, start + size)` ranges).
//! - **M2 crate attribution**: among functions whose start was found, how
//!   many have the right group (`user`, `dep:<crate>`, `std`); and, as a
//!   separate number, how many are right about "program's own code or
//!   not". A missing group is wrong.
//! - **M3 dependency recovery**: precision / recall / F1 of (package,
//!   version) pairs, `rustc` with its commit included. Names are compared
//!   with `-`/`_` and case folded.
//!
//! `total` = mean(M1 start F1, M2 accuracy, M3 F1), as specified.
//! `total_strict` replaces M2 accuracy with M2 coverage (right groups /
//! all truth functions), which cannot be raised by finding fewer functions.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use unforge_analysis::names::normalize_crate;
use unforge_analysis::{DependencyGuess, FunctionGuess, Group};

use crate::model::{Package, Truth, TruthFunction};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Prf {
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

impl Prf {
    /// From counts. With nothing to find and nothing claimed, all three are
    /// 100; with nothing claimed, precision is 0 (not undefined), so an
    /// empty answer never scores well.
    pub fn from_counts(matched: u64, predicted: u64, truth: u64) -> Prf {
        if truth == 0 && predicted == 0 {
            return Prf {
                precision: 100.0,
                recall: 100.0,
                f1: 100.0,
            };
        }
        let p = pct(matched, predicted);
        let r = pct(matched, truth);
        let f1 = if p + r > 0.0 {
            2.0 * p * r / (p + r)
        } else {
            0.0
        };
        Prf {
            precision: p,
            recall: r,
            f1,
        }
    }
}

fn pct(n: u64, d: u64) -> f64 {
    if d == 0 {
        0.0
    } else {
        100.0 * n as f64 / d as f64
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FunctionScore {
    pub truth: u64,
    pub predicted: u64,
    pub matched: u64,
    pub starts: Prf,
    pub truth_bytes: u64,
    pub predicted_bytes: u64,
    pub overlap_bytes: u64,
    pub bytes: Prf,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AttributionScore {
    /// Matched functions (M1) that have a truth group.
    pub matched: u64,
    pub correct: u64,
    /// `correct / matched` (0 when nothing matched).
    pub accuracy: f64,
    pub user_vs_library_correct: u64,
    pub user_vs_library_accuracy: f64,
    /// `correct / all truth functions`.
    pub coverage: f64,
    /// Per truth group (`user`, `std`, `dep`): matched and correct.
    pub by_group: BTreeMap<String, (u64, u64)>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DependencyScore {
    pub truth: u64,
    pub predicted: u64,
    pub matched: u64,
    pub pairs: Prf,
    /// The same, comparing names only.
    pub names: Prf,
    pub missed: Vec<String>,
    pub wrong: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Score {
    pub m1_functions: FunctionScore,
    pub m2_attribution: AttributionScore,
    pub m3_dependencies: DependencyScore,
    pub total: f64,
    pub total_strict: f64,
}

pub fn score(truth: &Truth, funcs: &[FunctionGuess], deps: &[DependencyGuess]) -> Score {
    let m1 = score_functions(&truth.functions, funcs);
    let m2 = score_attribution(&truth.functions, funcs);
    let m3 = score_dependencies(&truth.dependencies, deps);
    let total = (m1.starts.f1 + m2.accuracy + m3.pairs.f1) / 3.0;
    let total_strict = (m1.starts.f1 + m2.coverage + m3.pairs.f1) / 3.0;
    Score {
        m1_functions: m1,
        m2_attribution: m2,
        m3_dependencies: m3,
        total,
        total_strict,
    }
}

pub fn score_functions(truth: &[TruthFunction], funcs: &[FunctionGuess]) -> FunctionScore {
    let t: BTreeSet<u64> = truth.iter().map(|f| f.start).collect();
    let p: BTreeSet<u64> = funcs.iter().map(|f| f.start).collect();
    let matched = t.intersection(&p).count() as u64;
    let ti = union(
        truth
            .iter()
            .map(|f| (f.start, f.start.saturating_add(f.size))),
    );
    let pi = union(
        funcs
            .iter()
            .map(|f| (f.start, f.start.saturating_add(f.size))),
    );
    let tb = total_len(&ti);
    let pb = total_len(&pi);
    let ob = overlap(&ti, &pi);
    FunctionScore {
        truth: t.len() as u64,
        predicted: p.len() as u64,
        matched,
        starts: Prf::from_counts(matched, p.len() as u64, t.len() as u64),
        truth_bytes: tb,
        predicted_bytes: pb,
        overlap_bytes: ob,
        bytes: Prf::from_counts(ob, pb, tb),
    }
}

pub fn score_attribution(truth: &[TruthFunction], funcs: &[FunctionGuess]) -> AttributionScore {
    let pred: BTreeMap<u64, &FunctionGuess> = funcs.iter().map(|f| (f.start, f)).collect();
    let mut s = AttributionScore::default();
    let mut total = 0u64;
    for t in truth {
        let Some(tg) = Group::from_label(&t.group) else {
            continue;
        };
        total += 1;
        let Some(p) = pred.get(&t.start) else {
            continue;
        };
        s.matched += 1;
        let key = match tg {
            Group::User => "user",
            Group::Std => "std",
            Group::Dependency(_) => "dep",
        };
        let e = s.by_group.entry(key.to_owned()).or_insert((0, 0));
        e.0 += 1;
        if let Some(pg) = &p.group {
            if same_group(pg, &tg) {
                s.correct += 1;
                e.1 += 1;
            }
            if pg.is_user() == tg.is_user() {
                s.user_vs_library_correct += 1;
            }
        }
    }
    s.accuracy = pct(s.correct, s.matched);
    s.user_vs_library_accuracy = pct(s.user_vs_library_correct, s.matched);
    s.coverage = pct(s.correct, total);
    s
}

fn same_group(a: &Group, b: &Group) -> bool {
    match (a, b) {
        (Group::Dependency(x), Group::Dependency(y)) => normalize_crate(x) == normalize_crate(y),
        _ => a == b,
    }
}

pub fn score_dependencies(truth: &[Package], deps: &[DependencyGuess]) -> DependencyScore {
    let key = |n: &str, v: Option<&str>| (normalize_crate(n), v.map(str::to_owned));
    let t: BTreeSet<(String, Option<String>)> = truth
        .iter()
        .map(|p| key(&p.name, Some(&p.version)))
        .collect();
    let p: BTreeSet<(String, Option<String>)> = deps
        .iter()
        .map(|d| key(&d.name, d.version.as_deref()))
        .collect();
    let matched = t.intersection(&p).count() as u64;
    let tn: BTreeSet<&String> = t.iter().map(|(n, _)| n).collect();
    let pn: BTreeSet<&String> = p.iter().map(|(n, _)| n).collect();
    let name_matched = tn.intersection(&pn).count() as u64;
    let show = |(n, v): &(String, Option<String>)| match v {
        Some(v) => format!("{n}@{v}"),
        None => n.clone(),
    };
    DependencyScore {
        truth: t.len() as u64,
        predicted: p.len() as u64,
        matched,
        pairs: Prf::from_counts(matched, p.len() as u64, t.len() as u64),
        names: Prf::from_counts(name_matched, pn.len() as u64, tn.len() as u64),
        missed: t.difference(&p).map(show).collect(),
        wrong: p.difference(&t).map(show).collect(),
    }
}

/// Sorted, merged, non-empty intervals.
fn union(it: impl Iterator<Item = (u64, u64)>) -> Vec<(u64, u64)> {
    let mut v: Vec<(u64, u64)> = it.filter(|(s, e)| e > s).collect();
    v.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        match out.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

fn total_len(v: &[(u64, u64)]) -> u64 {
    v.iter().map(|(s, e)| e - s).sum()
}

/// Total length of the intersection of two sorted, merged interval lists.
fn overlap(a: &[(u64, u64)], b: &[(u64, u64)]) -> u64 {
    let (mut i, mut j, mut n) = (0usize, 0usize, 0u64);
    while let (Some(&(as_, ae)), Some(&(bs, be))) = (a.get(i), b.get(j)) {
        let s = as_.max(bs);
        let e = ae.min(be);
        if e > s {
            n += e - s;
        }
        if ae < be {
            i += 1;
        } else {
            j += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tf(start: u64, size: u64, group: &str) -> TruthFunction {
        TruthFunction {
            start,
            size,
            name: None,
            krate: None,
            group: group.into(),
            origin: "dwarf".into(),
        }
    }

    fn fg(start: u64, size: u64, group: Option<Group>) -> FunctionGuess {
        FunctionGuess {
            start,
            size,
            name: None,
            group,
        }
    }

    fn pkg(n: &str, v: &str) -> Package {
        Package {
            name: n.into(),
            version: v.into(),
        }
    }

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn prf_edge_cases() {
        assert_eq!(Prf::from_counts(0, 0, 0).f1, 100.0);
        let p = Prf::from_counts(0, 0, 10);
        assert_eq!((p.precision, p.recall, p.f1), (0.0, 0.0, 0.0));
        let p = Prf::from_counts(0, 5, 0);
        assert_eq!(p.f1, 0.0);
        let p = Prf::from_counts(5, 10, 20);
        assert!(close(p.precision, 50.0) && close(p.recall, 25.0));
        assert!(close(p.f1, 2.0 * 50.0 * 25.0 / 75.0));
    }

    #[test]
    fn function_starts_and_bytes() {
        let truth = vec![
            tf(0x1000, 0x10, "user"),
            tf(0x1010, 0x10, "std"),
            tf(0x2000, 0x20, "std"),
        ];
        // One exact start, one wrong start inside a function, sizes overlapping.
        let pred = vec![fg(0x1000, 0x20, None), fg(0x2008, 0x8, None)];
        let s = score_functions(&truth, &pred);
        assert_eq!((s.truth, s.predicted, s.matched), (3, 2, 1));
        assert!(close(s.starts.precision, 50.0));
        assert!(close(s.starts.recall, 100.0 / 3.0));
        assert_eq!(s.truth_bytes, 0x40);
        assert_eq!(s.predicted_bytes, 0x28);
        assert_eq!(s.overlap_bytes, 0x28);
        assert!(close(s.bytes.precision, 100.0));
        assert!(close(s.bytes.recall, 100.0 * 0x28 as f64 / 0x40 as f64));
    }

    #[test]
    fn duplicate_predictions_count_once() {
        let truth = vec![tf(0x1000, 0x10, "user")];
        let pred = vec![fg(0x1000, 0, None), fg(0x1000, 0, None)];
        let s = score_functions(&truth, &pred);
        assert_eq!((s.predicted, s.matched), (1, 1));
        assert!(close(s.starts.f1, 100.0));
    }

    #[test]
    fn attribution() {
        let truth = vec![
            tf(1, 1, "user"),
            tf(2, 1, "std"),
            tf(3, 1, "dep:regex_automata"),
            tf(4, 1, "dep:serde"),
            tf(5, 1, "std"),
        ];
        let pred = vec![
            fg(1, 1, Some(Group::User)),
            fg(2, 1, Some(Group::Dependency("core".into()))),
            fg(3, 1, Some(Group::Dependency("regex-automata".into()))),
            fg(4, 1, None),
            // 5 not found
        ];
        let s = score_attribution(&truth, &pred);
        assert_eq!((s.matched, s.correct), (4, 2));
        assert!(close(s.accuracy, 50.0));
        // user/library: 1 right (user), 2 right (lib vs lib), 3 right, 4 no answer.
        assert_eq!(s.user_vs_library_correct, 3);
        assert!(close(s.coverage, 40.0));
        assert_eq!(s.by_group.get("dep"), Some(&(2, 1)));
    }

    #[test]
    fn attribution_with_no_matches_is_zero() {
        let truth = vec![tf(1, 1, "user")];
        let s = score_attribution(&truth, &[]);
        assert_eq!((s.accuracy, s.coverage), (0.0, 0.0));
    }

    #[test]
    fn dependencies() {
        let truth = vec![
            pkg("regex-automata", "0.4.9"),
            pkg("serde", "1.0.200"),
            pkg("rustc", "abc"),
        ];
        let pred = vec![
            DependencyGuess {
                name: "regex_automata".into(),
                version: Some("0.4.9".into()),
            },
            DependencyGuess {
                name: "serde".into(),
                version: Some("1.0.199".into()),
            },
            DependencyGuess {
                name: "rustc".into(),
                version: None,
            },
        ];
        let s = score_dependencies(&truth, &pred);
        assert_eq!((s.truth, s.predicted, s.matched), (3, 3, 1));
        assert!(close(s.pairs.f1, 100.0 / 3.0));
        assert!(close(s.names.f1, 100.0));
        assert_eq!(s.missed, vec!["rustc@abc", "serde@1.0.200"]);
    }

    #[test]
    fn total_is_mean_of_three() {
        let truth = Truth {
            schema: String::new(),
            binary: String::new(),
            package: None,
            rustc_commit: None,
            functions: vec![tf(1, 1, "std"), tf(2, 1, "std")],
            dependencies: vec![pkg("rustc", "abc")],
            lock_packages: vec![],
        };
        let pred = vec![fg(1, 1, Some(Group::Std))];
        let deps = vec![DependencyGuess {
            name: "rustc".into(),
            version: Some("abc".into()),
        }];
        let s = score(&truth, &pred, &deps);
        let f1 = 2.0 * 100.0 * 50.0 / 150.0;
        assert!(close(s.total, (f1 + 100.0 + 100.0) / 3.0));
        assert!(close(s.total_strict, (f1 + 50.0 + 100.0) / 3.0));
    }

    #[test]
    fn overlap_of_intervals() {
        let a = union([(0, 10), (5, 15), (20, 30)].into_iter());
        assert_eq!(a, vec![(0, 15), (20, 30)]);
        let b = union([(10, 25)].into_iter());
        assert_eq!(overlap(&a, &b), 5 + 5);
    }
}

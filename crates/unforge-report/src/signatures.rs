//! Function starts and names from fingerprints ([`unforge_sigs`]) folded
//! into a [`Report`].
//!
//! Stripped binaries (most malware) have almost no symbols, so
//! [`unforge_analysis::Analysis::functions`] finds few functions. The
//! fingerprint matcher collects starts on its own (`.eh_frame_hdr`, call and
//! tail-jump targets), so its starts are added even without a database.
//! With a database, functions without a symbol get the matched name, marked
//! `named_by: "signature"` so the UI can show that it is inferred.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;
use unforge_analysis::{Analysis, names};
use unforge_sigs::{Db, FunctionMatch, MatchStatus, function_starts, match_elf};

use crate::{CrateRow, FoundIn, FunctionCounts, FunctionRow, MAX_FUNCTION_ROWS, Report};

/// At most this many candidate names are kept per function.
pub const MAX_CANDIDATES: usize = 8;

/// Crates whose code counts as the standard library.
const STD_CRATES: &[&str] = &[
    "std",
    "core",
    "alloc",
    "compiler_builtins",
    "panic_unwind",
    "panic_abort",
    "std_detect",
    "hashbrown",
    "rustc_demangle",
    "addr2line",
    "gimli",
    "miniz_oxide",
    "object",
    "memchr",
    "adler2",
    "unwind",
    "libc",
    "cfg_if",
];

/// The fingerprint verdict for one function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignatureInfo {
    /// `unique`, `same_generic` (all candidates instantiate one generic
    /// function) or `ambiguous` (candidates disagree; no name was given).
    pub status: &'static str,
    /// Candidate names, at most [`MAX_CANDIDATES`].
    pub candidates: Vec<String>,
    /// Candidates beyond the ones listed.
    pub more: usize,
}

/// What [`apply`] did, for the UI to report.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct Applied {
    /// Function starts found by the matcher that the report did not have.
    pub added_starts: usize,
    /// Functions named by a unique or same-generic match.
    pub named: usize,
    /// Functions whose candidates disagree (left unnamed).
    pub ambiguous: usize,
}

/// Adds the matcher's function starts to `report`, and with `db` the names
/// of matched functions that have no symbol. Recounts functions and crate
/// totals afterwards.
pub fn apply(report: &mut Report, data: &[u8], db: Option<&Db>) -> Applied {
    let mut applied = Applied::default();
    let matches: Vec<FunctionMatch> = match db {
        Some(db) => match_elf(db, data).unwrap_or_default(),
        None => starts_only(data),
    };
    let mut index: HashMap<u64, usize> = report
        .function_rows
        .iter()
        .enumerate()
        .map(|(i, f)| (f.start, i))
        .collect();
    for m in matches {
        let row = match index.get(&m.start) {
            Some(&i) => i,
            None => {
                if report.function_rows.len() >= MAX_FUNCTION_ROWS {
                    report.functions_omitted += 1;
                    continue;
                }
                report.function_rows.push(FunctionRow {
                    start: m.start,
                    size: m.size,
                    name: None,
                    owner: None,
                    named_by: None,
                    signature: None,
                });
                applied.added_starts += 1;
                index.insert(m.start, report.function_rows.len() - 1);
                report.function_rows.len() - 1
            }
        };
        let Some(f) = report.function_rows.get_mut(row) else {
            continue;
        };
        if f.size == 0 {
            f.size = m.size;
        }
        if !m.status.is_match() {
            continue;
        }
        let status = match m.status {
            MatchStatus::Unique => "unique",
            MatchStatus::SameGeneric => "same_generic",
            _ => "ambiguous",
        };
        let mut candidates: Vec<String> = m.names.iter().map(|n| n.name.clone()).collect();
        let more = candidates.len().saturating_sub(MAX_CANDIDATES) + usize::from(m.names_truncated);
        candidates.truncate(MAX_CANDIDATES);
        f.signature = Some(SignatureInfo {
            status,
            candidates,
            more,
        });
        if status == "ambiguous" {
            applied.ambiguous += 1;
            continue;
        }
        if f.name.is_none() {
            f.name = m.display_name();
            f.named_by = Some("signature");
            if f.owner.is_none() {
                f.owner = m
                    .names
                    .first()
                    .and_then(|n| n.krate.as_deref())
                    .and_then(owner_of);
            }
            applied.named += 1;
        }
    }
    report.function_rows.sort_by_key(|f| f.start);
    recount(report);
    applied
}

/// Function starts without names, when there is no database.
fn starts_only(data: &[u8]) -> Vec<FunctionMatch> {
    let Ok(analysis) = Analysis::new(data) else {
        return Vec::new();
    };
    let Some(elf) = analysis.elf() else {
        return Vec::new();
    };
    let Ok(fpr) = unforge_sigs::Fingerprinter::new(elf) else {
        return Vec::new();
    };
    function_starts(&analysis, &fpr)
        .into_iter()
        .map(|f| FunctionMatch {
            start: f.start,
            size: f.size,
            fingerprint: None,
            status: MatchStatus::NoMatch,
            names: Vec::new(),
            names_truncated: false,
            symbol: f.symbol,
        })
        .collect()
}

/// The owner label for a crate name from a fingerprint, or None when it is
/// not a real crate name (`_` of `const _` blocks, `__rustc` internals).
fn owner_of(krate: &str) -> Option<String> {
    let k = names::normalize_crate(krate);
    if !crate::is_crate_name(&k) || k.starts_with('_') {
        return None;
    }
    Some(if STD_CRATES.contains(&k.as_str()) {
        "std".to_owned()
    } else {
        format!("dep:{k}")
    })
}

/// Recomputes [`FunctionCounts`] and the crate rows' function counts and
/// sizes from the function rows.
fn recount(report: &mut Report) {
    let mut c = FunctionCounts {
        total: report.function_rows.len() + report.functions_omitted,
        ..Default::default()
    };
    let mut by_crate: BTreeMap<String, (usize, u64)> = BTreeMap::new();
    for f in &report.function_rows {
        match f.owner.as_deref() {
            Some("user") => c.user += 1,
            Some("std") => c.std += 1,
            Some(o) if o.starts_with("dep:") => {
                c.dependency += 1;
                let e = by_crate
                    .entry(o.trim_start_matches("dep:").to_owned())
                    .or_default();
                e.0 += 1;
                e.1 = e.1.saturating_add(f.size);
            }
            _ => c.unknown += 1,
        }
    }
    c.unknown += report.functions_omitted;
    report.functions = c;
    for row in &mut report.crates {
        // several versions of one crate share one count: the first row gets it
        match by_crate.remove(&names::normalize_crate(&row.name)) {
            Some((n, b)) => {
                row.functions = n;
                row.bytes = b;
                if row.found_in == FoundIn::Path {
                    row.found_in = FoundIn::Both;
                }
            }
            None => {
                row.functions = 0;
                row.bytes = 0;
            }
        }
    }
    for (name, (n, b)) in by_crate {
        report.crates.push(CrateRow {
            name,
            version: None,
            functions: n,
            bytes: b,
            found_in: FoundIn::Signatures,
        });
    }
    report.crates.sort_by(|a, b| {
        names::normalize_crate(&a.name)
            .cmp(&names::normalize_crate(&b.name))
            .then_with(|| a.version.cmp(&b.version))
    });
}

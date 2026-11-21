//! Scoring a whole corpus directory, the train/eval split, and the summary.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use unforge_analysis::Analysis;
use unforge_analysis::names::normalize_crate;

use crate::model::{Meta, RESULTS_SCHEMA, Truth};
use crate::score::{Score, score};
use crate::{read_input, truth};

/// Which part of the corpus an item belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Split {
    Train,
    Eval,
}

impl Split {
    pub fn name(self) -> &'static str {
        match self {
            Split::Train => "train",
            Split::Eval => "eval",
        }
    }
}

/// Out of [`SPLIT_BUCKETS`] buckets, this many are eval (30 %).
pub const EVAL_BUCKETS: u64 = 3;
pub const SPLIT_BUCKETS: u64 = 10;

/// The split of a crate: FNV-1a 64 of the normalized crate name
/// (`-`/`_` and case folded), modulo [`SPLIT_BUCKETS`]; buckets below
/// [`EVAL_BUCKETS`] are eval. The hash is fixed here (not `std`'s
/// `DefaultHasher`, which may change between releases), so the split of a
/// crate never changes, and every variant and version of one crate is on
/// the same side.
pub fn split_of(krate: &str) -> Split {
    if fnv1a64(normalize_crate(krate).as_bytes()) % SPLIT_BUCKETS < EVAL_BUCKETS {
        Split::Eval
    } else {
        Split::Train
    }
}

pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemResult {
    pub id: String,
    #[serde(rename = "crate")]
    pub krate: String,
    pub version: String,
    pub variant: String,
    pub split: Split,
    pub score: Option<Score>,
    pub error: Option<String>,
}

/// Means of the headline numbers over a set of items (each binary weighs
/// the same).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Aggregate {
    pub items: u64,
    pub failed: u64,
    pub m1_start_precision: f64,
    pub m1_start_recall: f64,
    pub m1_start_f1: f64,
    pub m1_byte_f1: f64,
    pub m2_accuracy: f64,
    pub m2_user_vs_library: f64,
    pub m2_coverage: f64,
    pub m3_precision: f64,
    pub m3_recall: f64,
    pub m3_f1: f64,
    pub m3_name_f1: f64,
    pub total: f64,
    pub total_strict: f64,
}

impl Aggregate {
    pub fn of<'a>(items: impl Iterator<Item = &'a ItemResult>) -> Aggregate {
        let mut a = Aggregate::default();
        let mut n = 0u64;
        for it in items {
            a.items += 1;
            let Some(s) = &it.score else {
                a.failed += 1;
                continue;
            };
            n += 1;
            a.m1_start_precision += s.m1_functions.starts.precision;
            a.m1_start_recall += s.m1_functions.starts.recall;
            a.m1_start_f1 += s.m1_functions.starts.f1;
            a.m1_byte_f1 += s.m1_functions.bytes.f1;
            a.m2_accuracy += s.m2_attribution.accuracy;
            a.m2_user_vs_library += s.m2_attribution.user_vs_library_accuracy;
            a.m2_coverage += s.m2_attribution.coverage;
            a.m3_precision += s.m3_dependencies.pairs.precision;
            a.m3_recall += s.m3_dependencies.pairs.recall;
            a.m3_f1 += s.m3_dependencies.pairs.f1;
            a.m3_name_f1 += s.m3_dependencies.names.f1;
            a.total += s.total;
            a.total_strict += s.total_strict;
        }
        if n > 0 {
            let d = n as f64;
            for v in [
                &mut a.m1_start_precision,
                &mut a.m1_start_recall,
                &mut a.m1_start_f1,
                &mut a.m1_byte_f1,
                &mut a.m2_accuracy,
                &mut a.m2_user_vs_library,
                &mut a.m2_coverage,
                &mut a.m3_precision,
                &mut a.m3_recall,
                &mut a.m3_f1,
                &mut a.m3_name_f1,
                &mut a.total,
                &mut a.total_strict,
            ] {
                *v /= d;
            }
        }
        a
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResults {
    pub schema: String,
    pub date: String,
    pub analysis_api_version: u32,
    /// `train`, `eval` or `all`.
    pub split: String,
    pub corpus: String,
    pub overall: Aggregate,
    pub per_split: BTreeMap<String, Aggregate>,
    pub per_variant: BTreeMap<String, Aggregate>,
    pub items: Vec<ItemResult>,
}

/// The items of a corpus directory: every `<id>.meta.json`, sorted by id.
pub fn corpus_items(dir: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut v: Vec<(String, PathBuf)> = rd
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let id = name.strip_suffix(".meta.json")?.to_owned();
            Some((id, e.path()))
        })
        .collect();
    v.sort();
    Ok(v)
}

/// Truth for item `id`: `<id>.truth.json` if present, else extracted from
/// `<id>.debug` (and not written back).
pub fn load_truth(dir: &Path, id: &str, meta: &Meta) -> Result<Truth, String> {
    let tp = dir.join(format!("{id}.truth.json"));
    if tp.is_file() {
        let bytes = read_input(&tp)?;
        return serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", tp.display()));
    }
    let dp = dir.join(format!("{id}.debug"));
    let data = read_input(&dp)?;
    truth::extract(&data, &format!("{id}.debug"), Some(meta))
}

pub fn score_file(stripped: &Path, truth: &Truth) -> Result<Score, String> {
    let data = read_input(stripped)?;
    let a = Analysis::new(&data).map_err(|e| format!("{}: {e}", stripped.display()))?;
    Ok(score(truth, &a.functions(), &a.dependencies()))
}

pub fn run(dir: &Path, only: Option<Split>, date: &str) -> Result<RunResults, String> {
    let mut items = Vec::new();
    for (id, meta_path) in corpus_items(dir)? {
        let meta: Meta = match read_input(&meta_path)
            .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
        {
            Ok(m) => m,
            Err(e) => {
                items.push(ItemResult {
                    id: id.clone(),
                    krate: String::new(),
                    version: String::new(),
                    variant: String::new(),
                    split: Split::Train,
                    score: None,
                    error: Some(format!("meta: {e}")),
                });
                continue;
            }
        };
        let split = split_of(&meta.krate);
        if only.is_some_and(|s| s != split) {
            continue;
        }
        let result = load_truth(dir, &id, &meta)
            .and_then(|t| score_file(&dir.join(format!("{id}.stripped")), &t));
        let (score, error) = match result {
            Ok(s) => (Some(s), None),
            Err(e) => (None, Some(e)),
        };
        items.push(ItemResult {
            id,
            krate: meta.krate.clone(),
            version: meta.version.clone(),
            variant: meta.variant.name.clone(),
            split,
            score,
            error,
        });
    }
    let mut per_split = BTreeMap::new();
    for s in [Split::Train, Split::Eval] {
        if items.iter().any(|i| i.split == s) {
            per_split.insert(
                s.name().to_owned(),
                Aggregate::of(items.iter().filter(|i| i.split == s)),
            );
        }
    }
    let mut variants: Vec<&str> = items.iter().map(|i| i.variant.as_str()).collect();
    variants.sort_unstable();
    variants.dedup();
    let per_variant = variants
        .iter()
        .map(|v| {
            (
                (*v).to_owned(),
                Aggregate::of(items.iter().filter(|i| i.variant == *v)),
            )
        })
        .collect();
    Ok(RunResults {
        schema: RESULTS_SCHEMA.to_owned(),
        date: date.to_owned(),
        analysis_api_version: unforge_analysis::API_VERSION,
        split: only.map_or("all", Split::name).to_owned(),
        corpus: dir.display().to_string(),
        overall: Aggregate::of(items.iter()),
        per_split,
        per_variant,
        items,
    })
}

/// Today's date (UTC) as `YYYY-MM-DD`.
pub fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    civil_date(secs / 86_400)
}

/// Days since 1970-01-01 to `YYYY-MM-DD` (proleptic Gregorian; Howard
/// Hinnant's `civil_from_days`).
pub fn civil_date(days: u64) -> String {
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv_reference_values() {
        // Published FNV-1a 64 test vectors.
        assert_eq!(fnv1a64(b""), 0xcbf29ce484222325);
        assert_eq!(fnv1a64(b"a"), 0xaf63dc4c8601ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x85944171f73967e8);
    }

    #[test]
    fn split_is_spelling_independent_and_stable() {
        assert_eq!(split_of("fd-find"), split_of("fd_find"));
        assert_eq!(split_of("FD-find"), split_of("fd-find"));
        // Pinned so that a change of the rule shows up as a test failure.
        let eval: Vec<&str> = ["ripgrep", "fd-find", "bat", "tokei", "sd", "rage", "xh"]
            .into_iter()
            .filter(|c| split_of(c) == Split::Eval)
            .collect();
        assert_eq!(eval, EXPECTED_EVAL_SAMPLE);
    }

    const EXPECTED_EVAL_SAMPLE: &[&str] = &["fd-find", "bat", "sd", "rage"];

    #[test]
    fn dates() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(20_413), "2025-11-21");
        assert_eq!(civil_date(11_016), "2000-02-29");
    }

    fn item(variant: &str, split: Split, total: Option<f64>) -> ItemResult {
        ItemResult {
            id: String::new(),
            krate: String::new(),
            version: String::new(),
            variant: variant.into(),
            split,
            score: total.map(|t| Score {
                total: t,
                ..Score::default()
            }),
            error: None,
        }
    }

    #[test]
    fn aggregate_is_a_mean_over_scored_items() {
        let v = [
            item("o0", Split::Train, Some(10.0)),
            item("o0", Split::Train, Some(30.0)),
            item("o3", Split::Train, None),
        ];
        let a = Aggregate::of(v.iter());
        assert_eq!((a.items, a.failed), (3, 1));
        assert!((a.total - 20.0).abs() < 1e-9);
    }
}

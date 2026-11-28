//! Function starts and names from fingerprints, on a stripped copy of this
//! test executable.

use std::process::Command;

use unforge_report::{report, report_with_signatures};
use unforge_sigs::{Db, Options, generic_base};

fn own_exe() -> Vec<u8> {
    std::fs::read(std::env::current_exe().unwrap()).unwrap()
}

/// A copy of this executable without symbols, or None when `strip` is missing.
fn stripped() -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join(format!("unforge-report-sig-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let out = dir.join("stripped");
    let ok = Command::new("strip")
        .arg("--strip-all")
        .arg("-o")
        .arg(&out)
        .arg(std::env::current_exe().ok()?)
        .status()
        .ok()?
        .success();
    let data = if ok { std::fs::read(&out).ok() } else { None };
    let _ = std::fs::remove_dir_all(&dir);
    data
}

#[test]
fn stripped_file_gets_starts_and_names() {
    let Some(stripped) = stripped() else {
        eprintln!("skipped: strip is not installed");
        return;
    };
    let truth = report(&own_exe()).unwrap();
    let named_in_truth = |start: u64| {
        truth
            .function_rows
            .iter()
            .find(|f| f.start == start)
            .and_then(|f| f.name.clone())
    };

    // Without a database: many more function starts than the stripped file's own.
    let bare = report(&stripped).unwrap();
    let (with_starts, applied) = report_with_signatures(&stripped, None).unwrap();
    assert!(applied.added_starts > 100, "{applied:?}");
    assert!(with_starts.function_rows.len() > bare.function_rows.len() + 100);
    assert!(
        with_starts
            .function_rows
            .windows(2)
            .all(|w| w[0].start < w[1].start)
    );
    assert_eq!(applied.named, 0);

    // With a database built from the unstripped file: names come back, marked.
    let mut db = Db::new(Options::default());
    db.add_elf(&own_exe()).unwrap();
    let (named, applied) = report_with_signatures(&stripped, Some(&db)).unwrap();
    assert!(applied.named > 100, "{applied:?}");
    let by_sig: Vec<_> = named
        .function_rows
        .iter()
        .filter(|f| f.named_by == Some("signature"))
        .collect();
    assert_eq!(by_sig.len(), applied.named);
    let correct = by_sig
        .iter()
        .filter(|f| {
            let shown = f.name.clone().unwrap();
            let t = named_in_truth(f.start).unwrap_or_default();
            // a same-generic match shows the generic function, `base<..>`
            shown == t || shown == format!("{}<..>", generic_base(&t))
        })
        .count();
    assert!(
        correct * 100 >= by_sig.len() * 90,
        "{correct} of {} names correct",
        by_sig.len()
    );
    assert!(by_sig.iter().all(|f| f.signature.is_some()));
    assert_eq!(
        named.functions.total,
        named.function_rows.len() + named.functions_omitted
    );
}

#[test]
fn files_with_symbols_keep_their_names() {
    let data = own_exe();
    let mut db = Db::new(Options::default());
    db.add_elf(&data).unwrap();
    let (r, applied) = report_with_signatures(&data, Some(&db)).unwrap();
    assert_eq!(applied.named, 0, "symbols win over fingerprints");
    assert!(
        r.function_rows
            .iter()
            .all(|f| f.named_by != Some("signature"))
    );
}

//! What Mekiki gets for a file, on the command line (the browser preview of
//! Mekiki calls this too):
//!
//! ```text
//! report <file>                      the report, as JSON
//! report --code-map <file>           code_map, raw bytes on stdout
//! report --disasm <file> <addr>...   disasm_at, as JSON (addresses in decimal or 0x hex)
//! report --decomp-setup <file>       the decompiler's language id, then its setup commands
//! report --annotate <file>           decompiled code on stdin, with explaining comments on stdout
//!
//! With `--sigs <db>` first, the report, code map and decompiler setup also
//! use the fingerprint database (names for stripped functions). Without
//! it, the fingerprint matcher's function starts are still added.
//! ```
use std::io::Write;

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let db = if args.first().map(String::as_str) == Some("--sigs") && args.len() > 1 {
        let path = args.remove(1);
        args.remove(0);
        match std::fs::read(&path)
            .map_err(|e| e.to_string())
            .and_then(|b| unforge_sigs::Db::from_bytes(&b).map_err(|e| format!("{e:?}")))
        {
            Ok(db) => Some(db),
            Err(e) => {
                eprintln!("{path}: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };
    let (mode, path, rest) = match args.first().map(String::as_str) {
        Some("--code-map") | Some("--disasm") | Some("--decomp-setup") | Some("--annotate") => (
            args[0].as_str(),
            args.get(1),
            args.get(2..).unwrap_or_default(),
        ),
        Some(_) => ("", args.first(), &[][..]),
        None => ("", None, &[][..]),
    };
    let Some(path) = path else {
        eprintln!("usage: report [--code-map | --disasm] <file> [addr...]");
        std::process::exit(2);
    };
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{path}: {e}");
            std::process::exit(1);
        }
    };
    match mode {
        "--code-map" => {
            let spans = unforge_report::report_with_signatures(&data, db.as_ref())
                .map(|(r, _)| r.function_spans())
                .unwrap_or_default();
            let _ = std::io::stdout().write_all(&unforge_report::code::code_map_for(&data, &spans));
        }
        "--annotate" => {
            let mut code = String::new();
            let _ = std::io::Read::read_to_string(&mut std::io::stdin(), &mut code);
            print!("{}", unforge_report::code::annotate(&data, &code));
        }
        "--decomp-setup" => match unforge_report::report_with_signatures(&data, db.as_ref())
            .ok()
            .and_then(|(r, _)| {
                unforge_report::setup::decompiler_setup_for(&data, &r.function_names())
            }) {
            Some((lang, lines)) => print!("{lang}\n{lines}"),
            None => std::process::exit(1),
        },
        "--disasm" => {
            let addrs: Vec<u64> = rest
                .iter()
                .filter_map(|a| match a.strip_prefix("0x") {
                    Some(h) => u64::from_str_radix(h, 16).ok(),
                    None => a.parse().ok(),
                })
                .collect();
            let out = unforge_report::code::disasm_at(&data, &addrs);
            println!(
                "{}",
                serde_json::to_string(&out).unwrap_or_else(|_| "[]".to_owned())
            );
        }
        _ => {
            let json = match unforge_report::report_with_signatures(&data, db.as_ref()) {
                Ok((r, applied)) => {
                    serde_json::json!({ "report": r, "signatures": applied }).to_string()
                }
                Err(f) => serde_json::to_string(&f).unwrap_or_default(),
            };
            println!("{json}");
        }
    }
}

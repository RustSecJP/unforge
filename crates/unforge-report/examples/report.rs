//! What Mekiki gets for a file, on the command line (the browser preview of
//! Mekiki calls this too):
//!
//! ```text
//! report <file>                      the report, as JSON
//! report --code-map <file>           code_map, raw bytes on stdout
//! report --disasm <file> <addr>...   disasm_at, as JSON (addresses in decimal or 0x hex)
//! ```
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mode, path, rest) = match args.first().map(String::as_str) {
        Some("--code-map") | Some("--disasm") => (
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
            let _ = std::io::stdout().write_all(&unforge_report::code::code_map(&data));
        }
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
        _ => println!("{}", unforge_report::report_json(&data)),
    }
}

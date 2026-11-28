//! Prints the report Mekiki would show for a file: `cargo run -p unforge-report --example report -- <file>`.
fn main() {
    let Some(path) = std::env::args_os().nth(1) else {
        eprintln!("usage: report <file>");
        std::process::exit(2);
    };
    match std::fs::read(&path) {
        Ok(data) => println!("{}", unforge_report::report_json(&data)),
        Err(e) => {
            eprintln!("{}: {e}", path.to_string_lossy());
            std::process::exit(1);
        }
    }
}

//! Seed program for the anomalous-ELF corpus: print a marker line, exit 42.
//!
//! The oracle runner (`../run_oracle.sh`, `../probe/`) counts a file as "ran"
//! only if it sees exactly this marker on stdout and exit status 42.

use std::io::Write;

fn main() {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(b"UNFORGE_OK\n");
    let _ = out.flush();
    std::process::exit(42);
}

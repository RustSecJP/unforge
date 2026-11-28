//! `unforge`: read Rust binaries as Rust.
//!
//! Commands: `unforge elf <file>` (the ELF loader), `unforge disasm
//! <file>` (x86 / x86-64 disassembly of recovered functions) and `unforge
//! sig build|match` (function signatures, see `sig.rs`).
//!
//! This binary must never panic on any input or environment: no `unwrap`,
//! `expect`, or slice indexing on data derived from the file, and every write
//! is checked (Rust ignores `SIGPIPE` by default, so a closed pipe shows up as
//! `io::ErrorKind::BrokenPipe`, which `println!` would turn into a panic).

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

mod args;
mod disasm;
mod names;
mod print;
mod sig;

use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::Path;
use std::process::ExitCode;

use args::{Command, DisasmArgs, ElfArgs, HELP, SigBuildArgs, SigMatchArgs};

/// Exit status for I/O and parse errors.
const EXIT_FAILURE: u8 = 1;
/// Exit status for command-line errors.
const EXIT_USAGE: u8 = 2;

/// Largest input file accepted, in bytes (4 GiB). The whole file is read into
/// memory (memory-mapping would need `unsafe`), so this bounds memory use.
const MAX_INPUT_LEN: u64 = 4 << 30;

/// Read a whole regular file of at most [`MAX_INPUT_LEN`] bytes.
///
/// Anything that is not a regular file is refused before it is read: a
/// character device such as `/dev/zero` or a FIFO may never reach end of
/// file, and reading it to the end would grow memory without bound.
fn read_input(path: &Path) -> io::Result<Vec<u8>> {
    let not_regular = || io::Error::new(io::ErrorKind::InvalidInput, "not a regular file");
    let too_large = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file is larger than the {MAX_INPUT_LEN}-byte limit"),
        )
    };
    // Check the path first: opening a FIFO blocks until a writer appears.
    if !std::fs::metadata(path)?.is_file() {
        return Err(not_regular());
    }
    let file = File::open(path)?;
    // And the opened file, in case the path changed in between.
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(not_regular());
    }
    if meta.len() > MAX_INPUT_LEN {
        return Err(too_large());
    }
    let mut data = Vec::new();
    // `take(MAX + 1)` stops a file that grows while being read.
    file.take(MAX_INPUT_LEN.saturating_add(1))
        .read_to_end(&mut data)?;
    if data.len() as u64 > MAX_INPUT_LEN {
        return Err(too_large());
    }
    Ok(data)
}

fn main() -> ExitCode {
    let cmd = match args::parse(std::env::args_os().skip(1)) {
        Ok(c) => c,
        Err(args::UsageError(msg)) => {
            let _ = writeln!(
                io::stderr(),
                "unforge: {msg}\nTry 'unforge --help' for more information."
            );
            return ExitCode::from(EXIT_USAGE);
        }
    };
    match cmd {
        Command::Help => write_stdout(HELP.as_bytes()),
        Command::Version => {
            write_stdout(concat!("unforge ", env!("CARGO_PKG_VERSION"), "\n").as_bytes())
        }
        Command::Elf(a) => elf(&a),
        Command::Disasm(a) => disasm(&a),
        Command::SigBuild(a) => sig_build(&a),
        Command::SigMatch(a) => sig_match(&a),
    }
}

/// `unforge sig build`: adds every input (ELF files with symbols, or
/// databases, which are merged) and writes the database. Exits with
/// status 1, writing nothing, if any input cannot be used.
fn sig_build(a: &SigBuildArgs) -> ExitCode {
    let mut db = unforge_sigs::Db::new(a.options);
    let mut err = io::stderr().lock();
    for path in &a.inputs {
        let report = |e: &dyn std::fmt::Display| {
            let _ = writeln!(io::stderr(), "unforge: {}: {e}", path.display());
            ExitCode::from(EXIT_FAILURE)
        };
        let data = match read_input(path) {
            Ok(d) => d,
            Err(e) => return report(&e),
        };
        if data.starts_with(unforge_sigs::db::MAGIC) {
            match unforge_sigs::Db::from_bytes(&data) {
                Ok(other) => {
                    let _ = writeln!(
                        err,
                        "unforge: {}: note: merging {} fingerprints",
                        path.display(),
                        other.len()
                    );
                    db.merge(other);
                }
                Err(e) => return report(&e),
            }
            continue;
        }
        match db.add_elf(&data) {
            Ok(s) => {
                let _ = writeln!(
                    err,
                    "unforge: {}: note: {} of {} named functions added \
                     ({} below the size threshold, {} without readable code)",
                    path.display(),
                    s.added,
                    s.named,
                    s.too_small,
                    s.unreadable
                );
                if s.named == 0 {
                    let _ = writeln!(
                        err,
                        "unforge: {}: warning: no named functions (stripped?)",
                        path.display()
                    );
                }
            }
            Err(e) => return report(&e),
        }
    }
    let bytes = db.to_bytes();
    if let Err(e) = std::fs::write(&a.output, &bytes) {
        let _ = writeln!(err, "unforge: {}: {e}", a.output.display());
        return ExitCode::from(EXIT_FAILURE);
    }
    let _ = writeln!(
        err,
        "unforge: {}: note: {} fingerprints, {} bytes",
        a.output.display(),
        db.len(),
        bytes.len()
    );
    ExitCode::SUCCESS
}

/// `unforge sig match`: see `sig.rs` for the output format.
fn sig_match(a: &SigMatchArgs) -> ExitCode {
    let fail = |p: &Path, e: &dyn std::fmt::Display| {
        let _ = writeln!(io::stderr(), "unforge: {}: {e}", p.display());
        ExitCode::from(EXIT_FAILURE)
    };
    let db = match read_input(&a.db) {
        Ok(d) => match unforge_sigs::Db::from_bytes(&d) {
            Ok(db) => db,
            Err(e) => return fail(&a.db, &e),
        },
        Err(e) => return fail(&a.db, &e),
    };
    let data = match read_input(&a.path) {
        Ok(d) => d,
        Err(e) => return fail(&a.path, &e),
    };
    let matches = match unforge_sigs::match_elf(&db, &data) {
        Ok(m) => m,
        Err(e) => return fail(&a.path, &e),
    };
    let mut out = BufWriter::new(io::stdout().lock());
    if let Err(e) = sig::print_matches(&mut out, &matches).and_then(|()| out.flush()) {
        return stdout_error(&e);
    }
    let mut err = io::stderr().lock();
    let summary = sig::Summary::of(&matches);
    let _ = writeln!(err, "unforge: {}: note: {summary}", a.path.display());
    if let Ok(missing) = unforge_sigs::uncovered_dependencies(&db, &data)
        && !missing.is_empty()
    {
        let shown: Vec<String> = missing
            .iter()
            .take(sig::MAX_UNCOVERED_SHOWN)
            .map(|m| disasm::show_name(m))
            .collect();
        let more = missing.len().saturating_sub(shown.len());
        let _ = writeln!(
            err,
            "unforge: {}: note: not covered by the database: {}{}",
            a.path.display(),
            shown.join(", "),
            if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            }
        );
    }
    ExitCode::SUCCESS
}

fn write_stdout(bytes: &[u8]) -> ExitCode {
    let mut out = io::stdout().lock();
    match out.write_all(bytes).and_then(|()| out.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => stdout_error(&e),
    }
}

/// Exit status after a failed write to stdout.
///
/// A broken pipe means the reader (e.g. `head`) has seen enough; that is not
/// an error of ours, so exit quietly with success.
fn stdout_error(e: &io::Error) -> ExitCode {
    if e.kind() == io::ErrorKind::BrokenPipe {
        return ExitCode::SUCCESS;
    }
    let _ = writeln!(io::stderr(), "unforge: stdout: {e}");
    ExitCode::from(EXIT_FAILURE)
}

fn elf(a: &ElfArgs) -> ExitCode {
    let report = |e: &dyn std::fmt::Display| {
        let _ = writeln!(io::stderr(), "unforge: {}: {e}", a.path.display());
        ExitCode::from(EXIT_FAILURE)
    };
    let data = match read_input(&a.path) {
        Ok(d) => d,
        Err(e) => return report(&e),
    };
    let file = match unforge_elf::ElfFile::parse(&data) {
        Ok(f) => f,
        Err(e) => return report(&e),
    };

    let warned = report_diagnostics(&file, &data, a);
    let out = BufWriter::new(io::stdout().lock());
    let mut p = print::Printer::new(out, &a.path);
    let result = p.print(&file, a.show).and_then(|()| p.flush());
    let failed = a.strict && (warned || p.warned());
    match result {
        Ok(()) if failed => ExitCode::from(EXIT_FAILURE),
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe && failed => ExitCode::from(EXIT_FAILURE),
        Err(e) => stdout_error(&e),
    }
    // Dropping `p` flushes the BufWriter again; after a broken pipe that flush
    // fails silently (BufWriter's Drop ignores errors), which is what we want.
}

/// `unforge disasm`: see `disasm.rs` for the output format.
///
/// Exits with status 1 when the file cannot be read, is not for x86, when
/// no function matches `--function`, or when nothing could be disassembled
/// (the address is not backed by file bytes). ELF diagnostics are not
/// printed here; `unforge elf` reports them.
fn disasm(a: &DisasmArgs) -> ExitCode {
    let report = |e: &dyn std::fmt::Display| {
        let _ = writeln!(io::stderr(), "unforge: {}: {e}", a.path.display());
        ExitCode::from(EXIT_FAILURE)
    };
    let data = match read_input(&a.path) {
        Ok(d) => d,
        Err(e) => return report(&e),
    };
    let analysis = match unforge_analysis::Analysis::new(&data) {
        Ok(an) => an,
        Err(e) => return report(&e),
    };
    let Some(elf) = analysis.elf() else {
        return report(&"disassembling PE files is not supported yet");
    };
    let header = elf.header();
    let Some(bitness) = unforge_disasm::bitness_for(header.machine, header.class) else {
        return report(&format!(
            "cannot disassemble code for {}: only x86 and x86-64 are supported",
            names::machine(header.machine)
        ));
    };
    let funcs = analysis.functions();
    let (jobs, total) = disasm::jobs(&a.target, header.entry, &funcs);
    if let args::DisasmTarget::Function(pattern) = &a.target {
        if jobs.is_empty() {
            return report(&format!(
                "no recovered function name contains '{}'",
                names::escape(pattern.as_bytes())
            ));
        }
        if total > jobs.len() {
            let _ = writeln!(
                io::stderr(),
                "unforge: {}: note: {total} functions match; showing the first {}",
                a.path.display(),
                jobs.len()
            );
        }
    }
    let by_start = disasm::name_index(&funcs);
    let map = elf.memory_map();
    let mut out = BufWriter::new(io::stdout().lock());
    let mut printed = 0usize;
    let mut unmapped = 0usize;
    for (k, job) in jobs.iter().enumerate() {
        let Some(bytes) = unforge_disasm::function_bytes_in(&map, &data, job.start, job.size)
        else {
            unmapped += 1;
            let _ = writeln!(
                io::stderr(),
                "unforge: {}: warning: {:#x} is not backed by file bytes",
                a.path.display(),
                job.start
            );
            continue;
        };
        let insns = unforge_disasm::disassemble_function_bytes(
            bytes, job.start, job.size, bitness, a.count,
        );
        let result = (if k > 0 { writeln!(out) } else { Ok(()) }).and_then(|()| {
            disasm::print_function(&mut out, job, bytes, &insns, bitness, &by_start)
        });
        if let Err(e) = result {
            return stdout_error(&e);
        }
        printed += 1;
    }
    if let Err(e) = out.flush() {
        return stdout_error(&e);
    }
    if printed == 0 && unmapped > 0 {
        ExitCode::from(EXIT_FAILURE)
    } else {
        ExitCode::SUCCESS
    }
}

/// Print the file's diagnostics on stderr, before the listing:
/// `unforge: <path>: warning: ..` (severity Warning and above) or
/// `unforge: <path>: note: ..` (Info). Loader-category diagnostics and the
/// kernel's predicted verdict are printed only with `--loader-checks`, since
/// they depend on the platform the file would run on. Returns whether any
/// warning was printed.
fn report_diagnostics(file: &unforge_elf::ElfFile<'_>, data: &[u8], a: &ElfArgs) -> bool {
    use unforge_elf::{Category, Diagnostic, DiagnosticKind, KernelPrediction, Location, Severity};
    let audit = file.audit();
    let mut diags: Vec<Diagnostic> = audit
        .diagnostics
        .into_iter()
        .filter(|d| a.loader_checks || d.category() != Category::Loader)
        .collect();
    if a.loader_checks {
        let host = file.header().machine;
        match unforge_elf::ElfFile::kernel_prediction_for(data, host) {
            KernelPrediction::Loads => {}
            p => {
                let mut d = Diagnostic::new(DiagnosticKind::Kernel(p), Location::default());
                if matches!(p, KernelPrediction::NotModelled { .. }) {
                    d.severity = Severity::Info;
                }
                diags.push(d);
            }
        }
    }
    let mut err = io::stderr().lock();
    let mut warned = false;
    for d in &diags {
        let label = match d.severity {
            Severity::Info => "note",
            Severity::Warning => "warning",
            _ => "warning: would not load",
        };
        warned |= d.severity >= Severity::Warning;
        // If stderr itself is gone there is nobody left to tell.
        let _ = writeln!(err, "unforge: {}: {label}: {d}", a.path.display());
    }
    warned
}

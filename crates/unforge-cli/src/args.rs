//! Command-line parsing with `std` only.
//!
//! Grammar:
//!
//! ```text
//! unforge --help | -h | help
//! unforge --version | -V
//! unforge elf [--header] [--segments] [--sections] [--symbols]
//!             [--strict] [--loader-checks] [--] <file>
//! unforge disasm [--function <name-substring> | --addr <hex>] [--count <n>]
//!                [--] <file>
//! unforge sig build -o <db> [--min-insns <n>] [--min-bytes <n>] [--] <file>...
//! unforge sig match --db <db> [--] <file>
//! ```

use std::ffi::OsString;
use std::path::PathBuf;

/// Which parts of the file `unforge elf` prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Show {
    pub header: bool,
    pub segments: bool,
    pub sections: bool,
    pub symbols: bool,
}

impl Show {
    const ALL: Show = Show {
        header: true,
        segments: true,
        sections: true,
        symbols: true,
    };

    fn any(self) -> bool {
        self.header || self.segments || self.sections || self.symbols
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfArgs {
    pub path: PathBuf,
    pub show: Show,
    /// Exit with status 1 if any warning is printed.
    pub strict: bool,
    /// Also report what Linux loaders would do with the file.
    pub loader_checks: bool,
}

/// Where `unforge disasm` starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisasmTarget {
    /// The entry point (`e_entry`).
    Entry,
    /// Every recovered function whose name contains this text.
    Function(String),
    /// This virtual address.
    Addr(u64),
}

/// Instructions printed per function when `--count` is not given.
pub const DEFAULT_COUNT: usize = 1000;

/// Largest `--count` accepted.
pub const MAX_COUNT: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisasmArgs {
    pub path: PathBuf,
    pub target: DisasmTarget,
    /// At most this many instructions per function.
    pub count: usize,
}

/// Largest `--min-insns` / `--min-bytes` accepted.
pub const MAX_THRESHOLD: u32 = 1 << 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigBuildArgs {
    /// Where the database is written.
    pub output: PathBuf,
    /// ELF files with symbols, or existing databases to merge.
    pub inputs: Vec<PathBuf>,
    pub options: unforge_sigs::Options,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigMatchArgs {
    pub db: PathBuf,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help,
    Version,
    Elf(ElfArgs),
    Disasm(DisasmArgs),
    SigBuild(SigBuildArgs),
    SigMatch(SigMatchArgs),
}

/// A problem with the command line itself (exit code 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError(pub String);

pub const HELP: &str = "\
unforge - read Rust binaries as Rust

Usage:
  unforge elf [OPTIONS] <FILE>    Print the ELF structure of FILE
  unforge disasm [OPTIONS] <FILE> Disassemble x86 / x86-64 code in FILE
  unforge sig build -o <DB> [OPTIONS] <FILE>...
                                  Build a signature database from FILEs
                                  with symbols (or merge databases)
  unforge sig match --db <DB> <FILE>
                                  Name the functions of FILE from DB
  unforge --help                  Print this help
  unforge --version               Print the version

Options for `elf` (default: all parts):
      --header         Print the ELF header
      --segments       Print the program headers (segments)
      --sections       Print the section headers
      --symbols        Print the symbol tables (.symtab / .dynsym)
      --strict         Exit with status 1 if any warning is reported
      --loader-checks  Also report what the Linux kernel and ld.so would do
                       with the file (for the machine in its header)
  -h, --help           Print this help

Options for `disasm` (default: the entry point):
      --function <TEXT>  Every recovered function whose name contains TEXT
                         (at most 64 functions)
      --addr <HEX>       The code at this virtual address (0x prefix optional)
      --count <N>        At most N instructions per function (default 1000)

Options for `sig build`:
  -o, --output <DB>      Write the database here (required)
      --min-insns <N>    Skip functions of fewer than N instructions
                         (default 6)
      --min-bytes <N>    Skip functions of fewer than N bytes (default 16)
An input that is already a signature database is merged.

`sig match` prints one line per named function: address, name, and
`[generic: N]` when N instantiations of one generic function have that
code, or `[ambiguous: N]` when N unrelated names do (the first is shown).
A summary, and the dependencies of FILE that no input of DB had, go to
stderr.

`disasm` prints one instruction per line: address, bytes, Intel syntax.
Branches, calls and RIP-relative references to a recovered function end in
`; -> name`. A function of unknown size is disassembled up to its first
return, at most 4096 bytes.

The file is read tolerantly: everything readable is printed, and anomalies
(including every value the reader had to infer) are reported on stderr as
warnings and notes.

Exit status: 0 on success (also with warnings, unless --strict), 1 if the
file could not be read or has no readable ELF header, or with --strict if a
warning was reported, or for `disasm` if the file is not for x86 / x86-64,
no function name matches, or no requested address is backed by file bytes,
or for `sig` if an input or the database cannot be read or is not for
x86 / x86-64, 2 on a command-line error.
";

/// Parse the arguments after the program name.
pub fn parse<I>(args: I) -> Result<Command, UsageError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let Some(first) = args.next() else {
        return Err(UsageError("missing command".into()));
    };
    match first.to_str() {
        Some("--help" | "-h" | "help") => Ok(Command::Help),
        Some("--version" | "-V") => Ok(Command::Version),
        Some("elf") => parse_elf(args),
        Some("disasm") => parse_disasm(args),
        Some("sig") => parse_sig(args),
        _ => Err(UsageError(format!(
            "unknown command '{}'",
            first.to_string_lossy()
        ))),
    }
}

fn parse_elf(args: impl Iterator<Item = OsString>) -> Result<Command, UsageError> {
    let mut show = Show::default();
    let mut strict = false;
    let mut loader_checks = false;
    let mut path: Option<OsString> = None;
    let mut only_positional = false;

    for arg in args {
        let is_option = !only_positional
            && arg.as_encoded_bytes().starts_with(b"-")
            && arg.as_encoded_bytes() != b"-";
        if !is_option {
            if path.is_some() {
                return Err(UsageError(format!(
                    "unexpected extra argument '{}'",
                    arg.to_string_lossy()
                )));
            }
            path = Some(arg);
            continue;
        }
        match arg.to_str() {
            Some("--") => only_positional = true,
            Some("--help" | "-h") => return Ok(Command::Help),
            Some("--header") => show.header = true,
            Some("--segments") => show.segments = true,
            Some("--sections") => show.sections = true,
            Some("--symbols") => show.symbols = true,
            Some("--strict") => strict = true,
            Some("--loader-checks") => loader_checks = true,
            _ => {
                return Err(UsageError(format!(
                    "unknown option '{}'",
                    arg.to_string_lossy()
                )));
            }
        }
    }

    let Some(path) = path else {
        return Err(UsageError("missing <FILE> for 'elf'".into()));
    };
    Ok(Command::Elf(ElfArgs {
        path: path.into(),
        show: if show.any() { show } else { Show::ALL },
        strict,
        loader_checks,
    }))
}

fn parse_hex(s: &str) -> Option<u64> {
    let digits = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if digits.is_empty() || digits.starts_with('+') {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// The value after an option such as `--count`.
fn value(args: &mut impl Iterator<Item = OsString>, opt: &str) -> Result<OsString, UsageError> {
    args.next()
        .ok_or_else(|| UsageError(format!("missing value for '{opt}'")))
}

fn parse_disasm(mut args: impl Iterator<Item = OsString>) -> Result<Command, UsageError> {
    let mut function: Option<String> = None;
    let mut addr: Option<u64> = None;
    let mut count: Option<usize> = None;
    let mut path: Option<OsString> = None;
    let mut only_positional = false;

    while let Some(arg) = args.next() {
        let is_option = !only_positional
            && arg.as_encoded_bytes().starts_with(b"-")
            && arg.as_encoded_bytes() != b"-";
        if !is_option {
            if path.is_some() {
                return Err(UsageError(format!(
                    "unexpected extra argument '{}'",
                    arg.to_string_lossy()
                )));
            }
            path = Some(arg);
            continue;
        }
        match arg.to_str() {
            Some("--") => only_positional = true,
            Some("--help" | "-h") => return Ok(Command::Help),
            Some(opt @ "--function") => {
                let v = value(&mut args, opt)?;
                let Some(v) = v.to_str().filter(|v| !v.is_empty()) else {
                    return Err(UsageError(format!(
                        "invalid name for '--function': '{}'",
                        v.to_string_lossy()
                    )));
                };
                function = Some(v.to_owned());
            }
            Some(opt @ "--addr") => {
                let v = value(&mut args, opt)?;
                let Some(a) = v.to_str().and_then(parse_hex) else {
                    return Err(UsageError(format!(
                        "invalid hex address for '--addr': '{}'",
                        v.to_string_lossy()
                    )));
                };
                addr = Some(a);
            }
            Some(opt @ "--count") => {
                let v = value(&mut args, opt)?;
                let n = v
                    .to_str()
                    .and_then(|s| s.parse::<usize>().ok())
                    .filter(|n| (1..=MAX_COUNT).contains(n));
                let Some(n) = n else {
                    return Err(UsageError(format!(
                        "invalid count for '--count': '{}' (1 to {MAX_COUNT})",
                        v.to_string_lossy()
                    )));
                };
                count = Some(n);
            }
            _ => {
                return Err(UsageError(format!(
                    "unknown option '{}'",
                    arg.to_string_lossy()
                )));
            }
        }
    }

    let target = match (function, addr) {
        (Some(_), Some(_)) => {
            return Err(UsageError(
                "'--function' and '--addr' cannot be used together".into(),
            ));
        }
        (Some(f), None) => DisasmTarget::Function(f),
        (None, Some(a)) => DisasmTarget::Addr(a),
        (None, None) => DisasmTarget::Entry,
    };
    let Some(path) = path else {
        return Err(UsageError("missing <FILE> for 'disasm'".into()));
    };
    Ok(Command::Disasm(DisasmArgs {
        path: path.into(),
        target,
        count: count.unwrap_or(DEFAULT_COUNT),
    }))
}

fn is_option(arg: &OsString, only_positional: bool) -> bool {
    !only_positional && arg.as_encoded_bytes().starts_with(b"-") && arg.as_encoded_bytes() != b"-"
}

fn threshold(args: &mut impl Iterator<Item = OsString>, opt: &str) -> Result<u32, UsageError> {
    let v = value(args, opt)?;
    v.to_str()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|n| *n <= MAX_THRESHOLD)
        .ok_or_else(|| {
            UsageError(format!(
                "invalid number for '{opt}': '{}' (0 to {MAX_THRESHOLD})",
                v.to_string_lossy()
            ))
        })
}

fn parse_sig(mut args: impl Iterator<Item = OsString>) -> Result<Command, UsageError> {
    let Some(sub) = args.next() else {
        return Err(UsageError(
            "missing subcommand for 'sig' (build or match)".into(),
        ));
    };
    match sub.to_str() {
        Some("--help" | "-h") => Ok(Command::Help),
        Some("build") => parse_sig_build(args),
        Some("match") => parse_sig_match(args),
        _ => Err(UsageError(format!(
            "unknown subcommand 'sig {}' (build or match)",
            sub.to_string_lossy()
        ))),
    }
}

fn parse_sig_build(mut args: impl Iterator<Item = OsString>) -> Result<Command, UsageError> {
    let mut output: Option<OsString> = None;
    let mut inputs: Vec<PathBuf> = Vec::new();
    let mut options = unforge_sigs::Options::default();
    let mut only_positional = false;
    while let Some(arg) = args.next() {
        if !is_option(&arg, only_positional) {
            inputs.push(arg.into());
            continue;
        }
        match arg.to_str() {
            Some("--") => only_positional = true,
            Some("--help" | "-h") => return Ok(Command::Help),
            Some(opt @ ("-o" | "--output")) => {
                if output.is_some() {
                    return Err(UsageError(format!("'{opt}' given twice")));
                }
                output = Some(value(&mut args, opt)?);
            }
            Some(opt @ "--min-insns") => options.min_insns = threshold(&mut args, opt)?,
            Some(opt @ "--min-bytes") => options.min_bytes = threshold(&mut args, opt)?,
            _ => {
                return Err(UsageError(format!(
                    "unknown option '{}'",
                    arg.to_string_lossy()
                )));
            }
        }
    }
    let Some(output) = output else {
        return Err(UsageError("missing '-o <DB>' for 'sig build'".into()));
    };
    if inputs.is_empty() {
        return Err(UsageError("missing <FILE> for 'sig build'".into()));
    }
    Ok(Command::SigBuild(SigBuildArgs {
        output: output.into(),
        inputs,
        options,
    }))
}

fn parse_sig_match(mut args: impl Iterator<Item = OsString>) -> Result<Command, UsageError> {
    let mut db: Option<OsString> = None;
    let mut path: Option<OsString> = None;
    let mut only_positional = false;
    while let Some(arg) = args.next() {
        if !is_option(&arg, only_positional) {
            if path.is_some() {
                return Err(UsageError(format!(
                    "unexpected extra argument '{}'",
                    arg.to_string_lossy()
                )));
            }
            path = Some(arg);
            continue;
        }
        match arg.to_str() {
            Some("--") => only_positional = true,
            Some("--help" | "-h") => return Ok(Command::Help),
            Some(opt @ "--db") => {
                if db.is_some() {
                    return Err(UsageError(format!("'{opt}' given twice")));
                }
                db = Some(value(&mut args, opt)?);
            }
            _ => {
                return Err(UsageError(format!(
                    "unknown option '{}'",
                    arg.to_string_lossy()
                )));
            }
        }
    }
    let Some(db) = db else {
        return Err(UsageError("missing '--db <DB>' for 'sig match'".into()));
    };
    let Some(path) = path else {
        return Err(UsageError("missing <FILE> for 'sig match'".into()));
    };
    Ok(Command::SigMatch(SigMatchArgs {
        db: db.into(),
        path: path.into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command, UsageError> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn default_shows_everything() {
        assert_eq!(
            p(&["elf", "a.out"]),
            Ok(Command::Elf(ElfArgs {
                path: "a.out".into(),
                show: Show::ALL,
                strict: false,
                loader_checks: false,
            }))
        );
    }

    #[test]
    fn strict_and_loader_checks() {
        let Ok(Command::Elf(a)) = p(&["elf", "--strict", "x", "--loader-checks"]) else {
            panic!("expected elf command");
        };
        assert!(a.strict && a.loader_checks);
        assert_eq!(a.show, Show::ALL);
    }

    #[test]
    fn flags_select_parts() {
        let Ok(Command::Elf(a)) = p(&["elf", "--symbols", "x", "--header"]) else {
            panic!("expected elf command");
        };
        assert_eq!(
            a.show,
            Show {
                header: true,
                symbols: true,
                ..Show::default()
            }
        );
    }

    #[test]
    fn double_dash_allows_dash_paths() {
        let Ok(Command::Elf(a)) = p(&["elf", "--", "--header"]) else {
            panic!("expected elf command");
        };
        assert_eq!(a.path, PathBuf::from("--header"));
        assert_eq!(a.show, Show::ALL);
    }

    #[test]
    fn usage_errors() {
        assert!(p(&[]).is_err());
        assert!(p(&["nope"]).is_err());
        assert!(p(&["elf"]).is_err());
        assert!(p(&["elf", "--bogus", "x"]).is_err());
        assert!(p(&["elf", "a", "b"]).is_err());
    }

    #[test]
    fn help_anywhere() {
        assert_eq!(p(&["--help"]), Ok(Command::Help));
        assert_eq!(p(&["elf", "x", "-h"]), Ok(Command::Help));
        assert_eq!(p(&["disasm", "x", "--help"]), Ok(Command::Help));
    }

    #[test]
    fn disasm_defaults_to_entry() {
        assert_eq!(
            p(&["disasm", "a.out"]),
            Ok(Command::Disasm(DisasmArgs {
                path: "a.out".into(),
                target: DisasmTarget::Entry,
                count: DEFAULT_COUNT,
            }))
        );
    }

    #[test]
    fn disasm_function_addr_and_count() {
        let Ok(Command::Disasm(a)) = p(&["disasm", "--function", "main", "x", "--count", "5"])
        else {
            panic!("expected disasm command");
        };
        assert_eq!(a.target, DisasmTarget::Function("main".into()));
        assert_eq!(a.count, 5);
        for (text, want) in [("401000", 0x401000), ("0x401000", 0x401000), ("0XfF", 0xff)] {
            let Ok(Command::Disasm(a)) = p(&["disasm", "--addr", text, "x"]) else {
                panic!("expected disasm command");
            };
            assert_eq!(a.target, DisasmTarget::Addr(want));
        }
        // A value may start with a dash.
        let Ok(Command::Disasm(a)) = p(&["disasm", "--function", "-x", "--", "-f"]) else {
            panic!("expected disasm command");
        };
        assert_eq!(a.target, DisasmTarget::Function("-x".into()));
        assert_eq!(a.path, PathBuf::from("-f"));
    }

    #[test]
    fn disasm_usage_errors() {
        assert!(p(&["disasm"]).is_err());
        assert!(p(&["disasm", "--function"]).is_err());
        assert!(p(&["disasm", "--function", "", "x"]).is_err());
        assert!(p(&["disasm", "--addr", "xyz", "x"]).is_err());
        assert!(p(&["disasm", "--addr", "0x", "x"]).is_err());
        assert!(p(&["disasm", "--addr", "+1", "x"]).is_err());
        assert!(p(&["disasm", "--addr", "10000000000000000", "x"]).is_err());
        assert!(p(&["disasm", "--count", "0", "x"]).is_err());
        assert!(p(&["disasm", "--count", "-1", "x"]).is_err());
        assert!(p(&["disasm", "--count", "99999999999", "x"]).is_err());
        assert!(p(&["disasm", "--function", "a", "--addr", "1", "x"]).is_err());
        assert!(p(&["disasm", "--header", "x"]).is_err());
        assert!(p(&["disasm", "a", "b"]).is_err());
    }

    #[test]
    fn sig_build() {
        assert_eq!(
            p(&["sig", "build", "-o", "x.db", "a", "b"]),
            Ok(Command::SigBuild(SigBuildArgs {
                output: "x.db".into(),
                inputs: vec!["a".into(), "b".into()],
                options: unforge_sigs::Options::default(),
            }))
        );
        let Ok(Command::SigBuild(a)) = p(&[
            "sig",
            "build",
            "a",
            "--min-insns",
            "0",
            "--output",
            "-",
            "--min-bytes",
            "3",
            "--",
            "-b",
        ]) else {
            panic!("expected sig build");
        };
        assert_eq!(a.output, PathBuf::from("-"));
        assert_eq!(a.inputs, vec![PathBuf::from("a"), PathBuf::from("-b")]);
        assert_eq!((a.options.min_insns, a.options.min_bytes), (0, 3));
    }

    #[test]
    fn sig_match() {
        assert_eq!(
            p(&["sig", "match", "f", "--db", "x.db"]),
            Ok(Command::SigMatch(SigMatchArgs {
                db: "x.db".into(),
                path: "f".into(),
            }))
        );
        assert_eq!(p(&["sig", "match", "--help"]), Ok(Command::Help));
        assert_eq!(p(&["sig", "-h"]), Ok(Command::Help));
    }

    #[test]
    fn sig_usage_errors() {
        assert!(p(&["sig"]).is_err());
        assert!(p(&["sig", "nope"]).is_err());
        assert!(p(&["sig", "build"]).is_err());
        assert!(p(&["sig", "build", "a"]).is_err());
        assert!(p(&["sig", "build", "-o"]).is_err());
        assert!(p(&["sig", "build", "-o", "x"]).is_err());
        assert!(p(&["sig", "build", "-o", "x", "-o", "y", "a"]).is_err());
        assert!(p(&["sig", "build", "-o", "x", "--min-insns", "-1", "a"]).is_err());
        assert!(p(&["sig", "build", "-o", "x", "--min-bytes", "99999999", "a"]).is_err());
        assert!(p(&["sig", "build", "-o", "x", "--bogus", "a"]).is_err());
        assert!(p(&["sig", "match"]).is_err());
        assert!(p(&["sig", "match", "f"]).is_err());
        assert!(p(&["sig", "match", "--db", "x"]).is_err());
        assert!(p(&["sig", "match", "--db"]).is_err());
        assert!(p(&["sig", "match", "--db", "x", "a", "b"]).is_err());
        assert!(p(&["sig", "match", "--db", "x", "--db", "y", "a"]).is_err());
    }
}

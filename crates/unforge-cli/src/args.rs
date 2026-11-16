//! Command-line parsing with `std` only.
//!
//! Grammar:
//!
//! ```text
//! unforge --help | -h | help
//! unforge --version | -V
//! unforge elf [--header] [--segments] [--sections] [--symbols]
//!             [--strict] [--loader-checks] [--] <file>
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help,
    Version,
    Elf(ElfArgs),
}

/// A problem with the command line itself (exit code 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError(pub String);

pub const HELP: &str = "\
unforge - read Rust binaries as Rust

Usage:
  unforge elf [OPTIONS] <FILE>    Print the ELF structure of FILE
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

The file is read tolerantly: everything readable is printed, and anomalies
(including every value the reader had to infer) are reported on stderr as
warnings and notes.

Exit status: 0 on success (also with warnings, unless --strict), 1 if the
file could not be read or has no readable ELF header, or with --strict if a
warning was reported, 2 on a command-line error.
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
    }
}

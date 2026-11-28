//! `unforge sig`: build signature databases and name functions with them.
//!
//! `sig match` prints one line per named function:
//!
//! ```text
//! 0000000000401000  core::fmt::write
//! 0000000000401230  core::ptr::drop_in_place<..>  [generic: 3]
//! 0000000000401400  <u64 as core::fmt::Debug>::fmt  [ambiguous: 2]
//! ```
//!
//! Output is bounded by the number of functions `unforge-sigs` finds
//! (`unforge_analysis::MAX_FUNCTIONS`) and the name length cap; names are
//! escaped like `unforge disasm` does ([`crate::disasm::show_name`]).

use std::io::{self, Write};

use unforge_sigs::{FunctionMatch, MatchStatus};

/// At most this many uncovered dependencies are listed in the summary.
pub const MAX_UNCOVERED_SHOWN: usize = 8;

/// One output line (without the newline) for a matched function, or
/// `None` when the function was not named.
pub fn line(m: &FunctionMatch) -> Option<String> {
    let name = crate::disasm::show_name(&m.display_name()?);
    let more = if m.names_truncated { "+" } else { "" };
    Some(match m.status {
        MatchStatus::Unique => format!("{:016x}  {name}", m.start),
        MatchStatus::SameGeneric => {
            format!(
                "{:016x}  {name}  [generic: {}{more}]",
                m.start,
                m.candidates()
            )
        }
        _ => format!(
            "{:016x}  {name}  [ambiguous: {}{more}]",
            m.start,
            m.candidates()
        ),
    })
}

/// Counts of a match run, for the summary on stderr.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    pub functions: usize,
    pub unique: usize,
    pub generic: usize,
    pub ambiguous: usize,
    pub no_match: usize,
    pub too_small: usize,
    pub unreadable: usize,
}

impl Summary {
    pub fn of(matches: &[FunctionMatch]) -> Summary {
        let mut s = Summary {
            functions: matches.len(),
            ..Summary::default()
        };
        for m in matches {
            match m.status {
                MatchStatus::Unique => s.unique += 1,
                MatchStatus::SameGeneric => s.generic += 1,
                MatchStatus::Ambiguous => s.ambiguous += 1,
                MatchStatus::NoMatch => s.no_match += 1,
                MatchStatus::TooSmall => s.too_small += 1,
                MatchStatus::Unreadable => s.unreadable += 1,
            }
        }
        s
    }

    pub fn named(&self) -> usize {
        self.unique + self.generic + self.ambiguous
    }
}

impl std::fmt::Display for Summary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "named {} of {} functions ({} unique, {} generic, {} ambiguous); \
             {} not in the database, {} below the size threshold, {} without readable code",
            self.named(),
            self.functions,
            self.unique,
            self.generic,
            self.ambiguous,
            self.no_match,
            self.too_small,
            self.unreadable
        )
    }
}

/// Writes the lines of every named function.
pub fn print_matches(out: &mut impl Write, matches: &[FunctionMatch]) -> io::Result<()> {
    for m in matches {
        if let Some(l) = line(m) {
            writeln!(out, "{l}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use unforge_sigs::SigName;

    fn m(status: MatchStatus, names: &[&str]) -> FunctionMatch {
        FunctionMatch {
            start: 0x401000,
            size: 32,
            fingerprint: None,
            status,
            names: names
                .iter()
                .map(|n| SigName {
                    name: (*n).into(),
                    krate: None,
                })
                .collect(),
            names_truncated: false,
            symbol: None,
        }
    }

    #[test]
    fn lines() {
        assert_eq!(
            line(&m(MatchStatus::Unique, &["core::fmt::write"])).as_deref(),
            Some("0000000000401000  core::fmt::write")
        );
        assert_eq!(
            line(&m(MatchStatus::SameGeneric, &["a::f<u16>", "a::f<u8>"])).as_deref(),
            Some("0000000000401000  a::f<..>  [generic: 2]")
        );
        let mut a = m(MatchStatus::Ambiguous, &["<u32 as x::D>::fmt", "y\nz"]);
        a.names_truncated = true;
        assert_eq!(
            line(&a).as_deref(),
            Some("0000000000401000  <u32 as x::D>::fmt  [ambiguous: 2+]")
        );
        assert_eq!(line(&m(MatchStatus::NoMatch, &[])), None);
        assert_eq!(line(&m(MatchStatus::TooSmall, &[])), None);
    }

    #[test]
    fn summary() {
        let v = vec![
            m(MatchStatus::Unique, &["a"]),
            m(MatchStatus::Ambiguous, &["a", "b"]),
            m(MatchStatus::NoMatch, &[]),
        ];
        let s = Summary::of(&v);
        assert_eq!(s.named(), 2);
        assert_eq!(
            s.to_string(),
            "named 2 of 3 functions (1 unique, 0 generic, 1 ambiguous); \
             1 not in the database, 0 below the size threshold, 0 without readable code"
        );
    }
}

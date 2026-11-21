//! Source paths that end up in Rust binaries, and what they say about the
//! crate a piece of code came from.
//!
//! rustc writes source paths into panic location strings (`.rodata`) and
//! debug info. Their shape tells where the code was compiled from:
//!
//! | path | origin |
//! |---|---|
//! | `/rustc/<40 hex commit>/library/<crate>/...` | the standard library of the rustc release with that commit (official builds remap their source directory to this) |
//! | `/rust/deps/<crate>-<version>/...` | a crate vendored by the standard library (current official builds) |
//! | `/cargo/registry/src/<index>/<crate>-<version>/...` with a standard-library crate | the same, in older official builds |
//! | `.../registry/src/<index>/<crate>-<version>/...` (`/` or `\`) | a crates.io dependency, unpacked by cargo into `$CARGO_HOME` |
//! | anything else | the program's own sources (or a path / git dependency) |

use crate::names;

/// What a source path says about where code came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathOrigin {
    /// The standard library, or a crate it vendors.
    Std,
    /// A package unpacked by cargo from a registry: name and version as in
    /// the directory name (package spelling, e.g. `regex-automata`).
    Registry { name: String, version: String },
    /// Neither of the above.
    Other,
}

/// Classifies a source path (see the module documentation).
pub fn classify_path(path: &str) -> PathOrigin {
    if path.starts_with("/rustc/") || path.starts_with("/rust/deps/") {
        return PathOrigin::Std;
    }
    if let Some((name, version)) = registry_package(path) {
        if path.starts_with("/cargo/registry/") && names::is_std_crate(&name) {
            return PathOrigin::Std;
        }
        return PathOrigin::Registry { name, version };
    }
    PathOrigin::Other
}

/// `<crate>-<version>` from the component after `registry/src/<index>/`,
/// with either path separator.
pub fn registry_package(path: &str) -> Option<(String, String)> {
    let b = path.as_bytes();
    let mut from = 0usize;
    while let Some(i) = find(b.get(from..)?, b"registry") {
        let at = from + i;
        if let Some((pkg, _)) = registry_component_at(b, at) {
            return Some(pkg);
        }
        from = at + 1;
    }
    None
}

/// Parses `registry<sep>src<sep><index><sep><name>-<version><sep>` starting
/// at `at` (the `r` of `registry`). Returns the package and the offset just
/// past the package component.
fn registry_component_at(b: &[u8], at: usize) -> Option<((String, String), usize)> {
    let mut p = at.checked_add(b"registry".len())?;
    let sep = *b.get(p)?;
    if sep != b'/' && sep != b'\\' {
        return None;
    }
    p += 1;
    if b.get(p..p.checked_add(3)?)? != b"src" || *b.get(p + 3)? != sep {
        return None;
    }
    p += 4;
    // The index directory (`index.crates.io-<hash>`, `github.com-<hash>`).
    let idx_len = component_len(b.get(p..)?, sep)?;
    if idx_len == 0 {
        return None;
    }
    p += idx_len + 1;
    let pkg_len = component_len(b.get(p..)?, sep)?;
    let pkg = std::str::from_utf8(b.get(p..p + pkg_len)?).ok()?;
    let (name, version) = split_name_version(pkg)?;
    Some(((name.to_owned(), version.to_owned()), p + pkg_len))
}

/// Length of the path component at the start of `s`, which must be followed
/// by `sep`. Only printable ASCII is accepted, at most 200 bytes.
fn component_len(s: &[u8], sep: u8) -> Option<usize> {
    const MAX: usize = 200;
    for (i, &c) in s.iter().enumerate().take(MAX + 1) {
        if c == sep {
            return Some(i);
        }
        if !(0x21..0x7f).contains(&c) || c == b'/' || c == b'\\' {
            return None;
        }
    }
    None
}

/// Splits `regex-automata-0.4.9` into (`regex-automata`, `0.4.9`): the
/// version starts at the first `-` followed by something that parses as a
/// semver version (`MAJOR.MINOR.PATCH`, optional `-pre` / `+build`).
pub fn split_name_version(s: &str) -> Option<(&str, &str)> {
    let mut search = 0usize;
    while let Some(i) = s.get(search..)?.find('-') {
        let dash = search + i;
        let (name, ver) = (s.get(..dash)?, s.get(dash + 1..)?);
        if !name.is_empty() && is_semver(ver) && is_package_name(name) {
            return Some((name, ver));
        }
        search = dash + 1;
    }
    None
}

fn is_package_name(s: &str) -> bool {
    s.len() <= 64
        && s.starts_with(|c: char| c.is_ascii_alphabetic())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn is_semver(s: &str) -> bool {
    let (core, _build) = s.split_once('+').unwrap_or((s, ""));
    let (core, pre) = match core.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (core, None),
    };
    let mut parts = core.split('.');
    let ok = (0..3).all(|_| {
        parts.next().is_some_and(|p| {
            !p.is_empty() && p.len() <= 20 && p.bytes().all(|b| b.is_ascii_digit())
        })
    });
    ok && parts.next().is_none()
        && pre.is_none_or(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        })
}

/// The rustc commit hash in `/rustc/<40 lowercase hex>/`, if `path` starts
/// with one.
pub fn rustc_commit(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/rustc/")?;
    let hash = rest.get(..40)?;
    let ok = hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        && rest.as_bytes().get(40) == Some(&b'/');
    ok.then_some(hash)
}

/// One dependency clue found in a byte string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathClue {
    /// `/rustc/<commit>/`: the toolchain.
    Rustc { commit: String },
    /// `.../registry/src/<index>/<name>-<version>/`.
    Registry { name: String, version: String },
}

/// Scans `data` for registry package paths and `/rustc/<commit>/` and calls
/// `found` for each occurrence. Linear in `data.len()`; no allocation except
/// for the reported names.
///
/// Panic location strings are not NUL-terminated and are packed next to each
/// other in `.rodata`, so the scan looks for the path patterns anywhere, not
/// for C strings.
///
/// Registry paths of standard-library crates rooted at `/cargo/` (older
/// official builds) are skipped: they are the toolchain's, not the program's.
pub fn scan_path_clues(data: &[u8], mut found: impl FnMut(PathClue)) {
    let mut i = 0usize;
    while i < data.len() {
        let Some(rest) = data.get(i..) else { break };
        // Both patterns start with `r` (`registry`, `rustc/`); jump to the
        // next `r` preceded by a path separator.
        let Some(off) = rest.iter().position(|&c| c == b'r') else {
            break;
        };
        let at = i + off;
        i = at + 1;
        let prev = at.checked_sub(1).and_then(|p| data.get(p)).copied();
        if prev != Some(b'/') && prev != Some(b'\\') {
            continue;
        }
        if let Some(t) = data.get(at..)
            && t.starts_with(b"rustc/")
        {
            if let Some(h) = t.get(6..46) {
                let ok = h.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                    && t.get(46) == Some(&b'/');
                if ok {
                    if let Ok(commit) = std::str::from_utf8(h) {
                        found(PathClue::Rustc {
                            commit: commit.to_owned(),
                        });
                    }
                    i = at + 46;
                }
            }
            continue;
        }
        if let Some(((name, version), end)) = registry_component_at(data, at) {
            let vendored_by_std = at
                .checked_sub(7)
                .and_then(|s| data.get(s..at))
                .is_some_and(|p| p == b"/cargo/")
                && names::is_std_crate(&name);
            if !vendored_by_std {
                found(PathClue::Registry { name, version });
            }
            i = end.max(i);
        }
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_version() {
        assert_eq!(
            split_name_version("regex-automata-0.4.9"),
            Some(("regex-automata", "0.4.9"))
        );
        assert_eq!(
            split_name_version("windows_x86_64_gnu-0.52.6"),
            Some(("windows_x86_64_gnu", "0.52.6"))
        );
        assert_eq!(
            split_name_version("foo-1.0.0-beta.1"),
            Some(("foo", "1.0.0-beta.1"))
        );
        assert_eq!(split_name_version("foo-bar"), None);
        assert_eq!(split_name_version("foo-1.0"), None);
    }

    #[test]
    fn classify() {
        assert_eq!(
            classify_path(
                "/rustc/b940084d7eb6a299eb4bfeb8e34901bc051e7ac4/library/core/src/fmt/mod.rs"
            ),
            PathOrigin::Std
        );
        assert_eq!(
            classify_path("/rust/deps/memchr-2.8.3/src/lib.rs"),
            PathOrigin::Std
        );
        assert_eq!(
            classify_path(
                "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/lib.rs"
            ),
            PathOrigin::Registry {
                name: "tokio".into(),
                version: "1.47.1".into()
            }
        );
        assert_eq!(
            classify_path(
                "C:\\Users\\a\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\aes-0.8.4\\src\\lib.rs"
            ),
            PathOrigin::Registry {
                name: "aes".into(),
                version: "0.8.4".into()
            }
        );
        assert_eq!(
            classify_path(
                "/cargo/registry/src/github.com-1ecc6299db9ec823/hashbrown-0.12.3/src/raw/mod.rs"
            ),
            PathOrigin::Std
        );
        assert_eq!(classify_path("src/main.rs"), PathOrigin::Other);
        assert_eq!(classify_path("/unforge/src/enums.rs"), PathOrigin::Other);
    }

    #[test]
    fn rustc_hash() {
        assert_eq!(
            rustc_commit("/rustc/b940084d7eb6a299eb4bfeb8e34901bc051e7ac4/library/std/src/lib.rs"),
            Some("b940084d7eb6a299eb4bfeb8e34901bc051e7ac4")
        );
        assert_eq!(rustc_commit("/rustc/b940084d/library"), None);
    }

    #[test]
    fn scan() {
        // Panic location strings are packed without separators.
        let data = b"xx/rustc/b940084d7eb6a299eb4bfeb8e34901bc051e7ac4/library/core/src/str/mod.rs\
            called `Option::unwrap()`/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde_json-1.0.145/src/de.rs\
            /cargo/registry/src/github.com-1ecc6299db9ec823/hashbrown-0.12.3/src/raw/mod.rs\
            registry/src/x/notapath/";
        let mut got = Vec::new();
        scan_path_clues(data, |c| got.push(c));
        assert_eq!(
            got,
            vec![
                PathClue::Rustc {
                    commit: "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4".into()
                },
                PathClue::Registry {
                    name: "serde_json".into(),
                    version: "1.0.145".into()
                },
            ]
        );
    }

    #[test]
    fn scan_never_panics_on_truncated_input() {
        let full =
            b"/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.0.0/src/lib.rs";
        for n in 0..full.len() {
            scan_path_clues(full.get(..n).unwrap_or(&[]), |_| {});
        }
    }
}

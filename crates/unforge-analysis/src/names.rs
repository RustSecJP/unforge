//! Crate names: which crate a demangled Rust path belongs to, and which
//! crates count as the standard library.
//!
//! These rules are shared with the benchmark's ground truth extractor
//! (`unforge-bench truth`), so that "the crate of a function" means the same
//! thing on both sides of the comparison.

/// Crates that ship with the toolchain: the standard library itself, its
/// runtime pieces, and the crates.io crates that `std` vendors (built from
/// `/rust/deps/<crate>-<version>` in current official builds). Code from
/// these is grouped as "std" in the benchmark.
///
/// Some of the vendored names (`hashbrown`, `memchr`, `libc`, `cfg_if`,
/// `gimli`, `object`, `miniz_oxide`, ...) are also ordinary dependencies of
/// many programs. A bare name cannot tell the two copies apart; callers that
/// have a source path should decide with [`crate::paths::classify_path`]
/// first and use this list only as a fallback.
pub const STD_CRATES: &[&str] = &[
    "std",
    "core",
    "alloc",
    "proc_macro",
    "test",
    "compiler_builtins",
    "panic_unwind",
    "panic_abort",
    "unwind",
    "std_detect",
    "rustc_demangle",
    "rustc_std_workspace_core",
    "rustc_std_workspace_alloc",
    "rustc_std_workspace_std",
    "addr2line",
    "gimli",
    "object",
    "miniz_oxide",
    "adler",
    "adler2",
    "hashbrown",
    "memchr",
    "libc",
    "cfg_if",
    "getopts",
    "unicode_width",
    "dlmalloc",
    "wasi",
    "r_efi",
    "fortanix_sgx_abi",
    "hermit_abi",
];

/// Whether `name` (a crate name, `-` or `_` spelling) is one of [`STD_CRATES`].
pub fn is_std_crate(name: &str) -> bool {
    let n = normalize_crate(name);
    STD_CRATES.iter().any(|s| *s == n)
}

/// The crate name as rustc writes it in paths: `-` replaced by `_`,
/// lowercase. crates.io treats `-` and `_` in package names as the same
/// name, and the crate name of a package is its name with `-` turned into
/// `_`, so this also maps a package name (`regex-automata`) to its crate
/// name (`regex_automata`).
pub fn normalize_crate(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c == '-' {
                '_'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

/// The crate a demangled Rust path belongs to (its first path segment).
///
/// - `core::ptr::drop_in_place<alloc::string::String>` -> `core`
/// - `<alloc::vec::Vec<T> as core::ops::drop::Drop>::drop` -> `alloc` (the
///   crate of the self type; an `impl` of a trait for a type is usually in
///   the type's crate or the trait's crate, and the type comes first)
/// - `<u8 as mycrate::Trait>::f` -> `mycrate` (primitive self type: use the
///   trait)
/// - `<&mut T as Trait>`, `<[T] as ...>`, `<*const T as ...>`: the
///   reference/slice/pointer wrapper is skipped
///
/// Returns `None` when no crate name can be found (for example a C symbol
/// such as `memcpy`, which has no `::`).
pub fn crate_of_demangled(path: &str) -> Option<&str> {
    let path = path.trim();
    if let Some(rest) = path.strip_prefix('<') {
        let (self_ty, trait_path) = split_qualified(rest);
        if let Some(c) = first_segment(strip_type_wrappers(self_ty))
            && !is_primitive(c)
        {
            return Some(c);
        }
        return trait_path.and_then(|t| first_segment(strip_type_wrappers(t)));
    }
    if !path.contains("::") {
        return None;
    }
    first_segment(path)
}

/// Splits `Self as Trait>::rest` into (`Self`, `Some(Trait)`); `Self>::rest`
/// into (`Self`, None). Nesting of `<...>` is respected.
fn split_qualified(s: &str) -> (&str, Option<&str>) {
    let mut depth = 0usize;
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'<' => depth += 1,
            b'>' => {
                if depth == 0 {
                    return (s.get(..i).unwrap_or(""), None);
                }
                depth -= 1;
            }
            b' ' if depth == 0 && s.get(i..).is_some_and(|t| t.starts_with(" as ")) => {
                let self_ty = s.get(..i).unwrap_or("");
                let rest = s.get(i + 4..).unwrap_or("");
                return (self_ty, Some(rest));
            }
            _ => {}
        }
        i += 1;
    }
    (s, None)
}

fn strip_type_wrappers(mut s: &str) -> &str {
    loop {
        let t = s.trim_start();
        let t = t
            .strip_prefix('&')
            .or_else(|| t.strip_prefix("*const "))
            .or_else(|| t.strip_prefix("*mut "))
            .or_else(|| t.strip_prefix("mut "))
            .or_else(|| t.strip_prefix("dyn "))
            .or_else(|| t.strip_prefix('['))
            .or_else(|| t.strip_prefix('('))
            .or_else(|| t.strip_prefix('<'));
        match t {
            Some(t) => s = t,
            None => return s.trim_start(),
        }
    }
}

/// The identifier before the first `::`, if it looks like a crate name.
fn first_segment(s: &str) -> Option<&str> {
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(s.len());
    let seg = s.get(..end)?;
    let rest = s.get(end..)?;
    if seg.is_empty() || seg.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    // A bare identifier with no path after it is a type or function name,
    // not a crate (except primitives, which callers filter out).
    if !rest.starts_with("::") && !is_primitive(seg) {
        return None;
    }
    Some(seg)
}

fn is_primitive(s: &str) -> bool {
    matches!(
        s,
        "u8" | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
            | "f16"
            | "f32"
            | "f64"
            | "f128"
            | "bool"
            | "char"
            | "str"
            | "fn"
            | "_"
    )
}

/// Demangles a Rust symbol name (legacy `_ZN...E` or v0 `_R...`) without the
/// trailing hash. `None` for anything that is not a Rust symbol.
pub fn demangle_rust(raw: &str) -> Option<String> {
    let d = rustc_demangle::try_demangle(raw).ok()?;
    Some(format!("{d:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_paths() {
        assert_eq!(
            crate_of_demangled("core::ptr::drop_in_place<alloc::string::String>"),
            Some("core")
        );
        assert_eq!(crate_of_demangled("enums::main"), Some("enums"));
        assert_eq!(crate_of_demangled("memcpy"), None);
        assert_eq!(crate_of_demangled("_start"), None);
    }

    #[test]
    fn qualified_paths() {
        assert_eq!(
            crate_of_demangled("<alloc::vec::Vec<T> as core::ops::drop::Drop>::drop"),
            Some("alloc")
        );
        assert_eq!(
            crate_of_demangled("<u8 as mycrate::Trait>::f"),
            Some("mycrate")
        );
        assert_eq!(
            crate_of_demangled(
                "<&mut serde_json::de::Deserializer<R> as serde::de::Deserializer>::x"
            ),
            Some("serde_json")
        );
        assert_eq!(
            crate_of_demangled("<[T] as core::fmt::Debug>::fmt"),
            Some("core")
        );
        assert_eq!(crate_of_demangled("<std::io::Error>::new"), Some("std"));
    }

    #[test]
    fn std_set() {
        assert!(is_std_crate("core"));
        assert!(is_std_crate("compiler-builtins"));
        assert!(!is_std_crate("tokio"));
        assert_eq!(normalize_crate("Regex-Automata"), "regex_automata");
    }

    #[test]
    fn demangling() {
        assert_eq!(
            demangle_rust("_ZN5enums4main17h0123456789abcdefE").as_deref(),
            Some("enums::main")
        );
        assert_eq!(demangle_rust("memcpy"), None);
    }
}

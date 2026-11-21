//! Ground truth from DWARF: every function, its crate and group, and the
//! packages whose code is in the binary.
//!
//! # Functions
//!
//! Every `DW_TAG_subprogram` with an address (`DW_AT_low_pc`/`DW_AT_high_pc`
//! or `DW_AT_ranges`) is a function. That includes concrete out-of-line
//! copies of inlined functions, which carry `DW_AT_abstract_origin` instead
//! of their own name; names, declarations and namespaces are taken from the
//! DIE that `DW_AT_abstract_origin` / `DW_AT_specification` points to.
//! Addresses outside the executable sections (linker tombstones for
//! discarded code: 0, -1, -2) are dropped. Function symbols in `.symtab`
//! with no DWARF entry (C runtime start files, libc in static binaries,
//! assembly) are added with origin `symtab`.
//!
//! # Crate and group
//!
//! The crate is the outermost `DW_TAG_namespace` around the function (rustc
//! nests every item in namespaces named after its path, starting with the
//! crate that *defines* it; monomorphized generic code of `core` called from
//! the program is `core`'s code). The group is decided from the source
//! file the function is declared in (`DW_AT_decl_file`), because the crate
//! name alone is ambiguous (`hashbrown`, `memchr`, ... are both crates that
//! `std` vendors and ordinary dependencies):
//!
//! 1. a standard-library path (`/rustc/<commit>/...`, `/rust/deps/...`) is
//!    `std`;
//! 2. a registry path `<crate>-<version>` is the built package itself
//!    (`user`) when it matches the meta file's crate and version, else
//!    `dep:<crate>`;
//! 3. otherwise (or without a declaration) the crate's compilation units
//!    decide: each CU's `DW_AT_name` is `<crate root file>/@/<crate>.<hash>-cgu.N`,
//!    and the root file's path is classified the same way;
//! 4. otherwise the crate name: a standard-library crate is `std`, a crate
//!    of the `Cargo.lock` is a dependency, anything else is `user`.
//!
//! Functions without a Rust crate (C code with no namespace) use rules 1-2
//! on their declaration path, and are `std` when that says nothing (C
//! runtime, libc).
//!
//! # Dependencies
//!
//! See [`linked_dependencies`].

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use gimli::{AttributeValue, EndianSlice, RunTimeEndian};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use unforge_analysis::Group;
use unforge_analysis::names::{crate_of_demangled, demangle_rust, is_std_crate, normalize_crate};
use unforge_analysis::paths::{PathOrigin, classify_path, rustc_commit};

use crate::lock;
use crate::model::{Meta, Package, TRUTH_SCHEMA, Truth, TruthFunction};

type R<'a> = EndianSlice<'a, RunTimeEndian>;

/// Follow at most this many `DW_AT_abstract_origin`/`DW_AT_specification`
/// links (they can form a chain, never legitimately a long one).
const MAX_ORIGIN_HOPS: usize = 8;
/// At most this many enclosing scopes are walked for a namespace path.
const MAX_SCOPE_DEPTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Unit,
    Namespace,
    Type,
    Subprogram,
}

/// What is kept of one DIE: enough to name a function and find its scope.
#[derive(Debug, Default, Clone)]
struct Node {
    scope: Option<Scope>,
    parent: Option<u64>,
    name: Option<String>,
    linkage: Option<String>,
    decl_path: Option<String>,
    origin: Option<u64>,
}

/// One compilation unit.
#[derive(Debug, Clone)]
struct UnitInfo {
    /// `<crate>` of `<root>/@/<crate>.<hash>-cgu.N`.
    krate: Option<String>,
    /// Absolute path of the crate root file (or the CU name for C).
    root: Option<String>,
    comp_dir: Option<String>,
}

/// A function as found in DWARF, before classification.
struct RawFunction {
    start: u64,
    size: u64,
    die: u64,
}

pub fn extract(data: &[u8], file_name: &str, meta: Option<&Meta>) -> Result<Truth, String> {
    let obj = object::File::parse(data).map_err(|e| format!("not an object file: {e}"))?;
    let endian = if obj.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let text: Vec<(u64, u64)> = obj
        .sections()
        .filter(|s| s.kind() == SectionKind::Text && s.address() != 0)
        .map(|s| (s.address(), s.address().saturating_add(s.size())))
        .collect();
    let in_text = |a: u64| text.iter().any(|&(s, e)| a >= s && a < e);

    let sections = gimli::DwarfSections::load(|id| -> Result<Cow<'_, [u8]>, String> {
        match obj.section_by_name(id.name()) {
            Some(s) => s
                .uncompressed_data()
                .map_err(|e| format!("{}: {e}", id.name())),
            None => Ok(Cow::Borrowed(&[])),
        }
    })?;
    let dwarf = sections.borrow(|s| EndianSlice::new(s, endian));

    let mut nodes: HashMap<u64, Node> = HashMap::new();
    let mut units: Vec<UnitInfo> = Vec::new();
    let mut raw: Vec<RawFunction> = Vec::new();
    let mut headers = dwarf.units();
    while let Some(header) = headers.next().map_err(|e| format!("DWARF: {e}"))? {
        let unit = match dwarf.unit(header) {
            Ok(u) => u,
            Err(_) => continue,
        };
        units.push(unit_info(&unit));
        walk_unit(&dwarf, &unit, &mut nodes, &mut raw);
    }

    let package = meta.filter(|m| !m.krate.is_empty()).map(|m| Package {
        name: m.krate.clone(),
        version: m.version.clone(),
    });
    let lock_entries = meta
        .and_then(|m| m.cargo_lock.as_deref())
        .map(lock::parse)
        .unwrap_or_default();
    let lock_crates: BTreeSet<String> = lock_entries
        .iter()
        .filter(|e| e.is_registry())
        .map(|e| normalize_crate(&e.name))
        .collect();

    let ctx = Classifier {
        package: package.as_ref(),
        unit_kinds: unit_kinds(&units, package.as_ref()),
        lock_crates,
    };

    // Functions from DWARF.
    let mut by_start: BTreeMap<u64, TruthFunction> = BTreeMap::new();
    let mut seen_crates: BTreeSet<String> = BTreeSet::new();
    let mut registry_seen: BTreeSet<Package> = BTreeSet::new();
    for u in &units {
        if let Some(root) = &u.root
            && let PathOrigin::Registry { name, version } = classify_path(root)
        {
            registry_seen.insert(Package { name, version });
        }
        if let Some(k) = &u.krate {
            seen_crates.insert(normalize_crate(k));
        }
    }
    for f in &raw {
        if f.start == 0 || !in_text(f.start) {
            continue;
        }
        let info = describe(&nodes, f.die);
        if let Some(PathOrigin::Registry { name, version }) =
            info.decl_path.as_deref().map(classify_path)
        {
            registry_seen.insert(Package { name, version });
        }
        if let Some(k) = &info.krate {
            seen_crates.insert(k.clone());
        }
        let group = ctx.group(info.krate.as_deref(), info.decl_path.as_deref());
        let tf = TruthFunction {
            start: f.start,
            size: f.size,
            name: info.name,
            krate: info.krate,
            group: group.label(),
            origin: "dwarf".to_owned(),
        };
        // Several DIEs can describe the same address (identical code
        // folding, a declaration and its definition); keep the first named one.
        match by_start.get_mut(&f.start) {
            Some(e) => {
                if e.name.is_none() {
                    *e = tf;
                }
            }
            None => {
                by_start.insert(f.start, tf);
            }
        }
    }

    // Function symbols without DWARF.
    for sym in obj.symbols() {
        if sym.kind() != SymbolKind::Text || !sym.is_definition() {
            continue;
        }
        let a = sym.address();
        if a == 0 || !in_text(a) || by_start.contains_key(&a) {
            continue;
        }
        let raw_name = sym.name().ok().filter(|n| !n.is_empty());
        let rust = raw_name.and_then(demangle_rust);
        let krate = rust
            .as_deref()
            .and_then(crate_of_demangled)
            .map(normalize_crate);
        let group = match &krate {
            Some(k) => ctx.group(Some(k), None),
            None => Group::Std,
        };
        by_start.insert(
            a,
            TruthFunction {
                start: a,
                size: sym.size(),
                name: rust.or_else(|| raw_name.map(str::to_owned)),
                krate,
                group: group.label(),
                origin: "symtab".to_owned(),
            },
        );
    }

    let rustc = units
        .iter()
        .filter_map(|u| {
            u.comp_dir
                .as_deref()
                .and_then(|d| rustc_commit(&format!("{d}/")).map(str::to_owned))
        })
        .next()
        .or_else(|| meta.and_then(|m| m.rustc_commit()).map(str::to_owned));

    let lock_packages: Vec<Package> = lock_entries
        .iter()
        .filter(|e| e.is_registry())
        .map(|e| e.package())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut dependencies = linked_dependencies(
        &lock_packages,
        &registry_seen,
        &seen_crates,
        package.as_ref(),
    );
    if let Some(c) = &rustc {
        dependencies.push(Package {
            name: "rustc".to_owned(),
            version: c.clone(),
        });
    }

    Ok(Truth {
        schema: TRUTH_SCHEMA.to_owned(),
        binary: file_name.to_owned(),
        package,
        rustc_commit: rustc,
        functions: by_start.into_values().collect(),
        dependencies,
        lock_packages,
    })
}

/// The packages whose code is in the binary.
///
/// A `Cargo.lock` lists every package any platform or feature set could
/// need (`windows-sys` in a Linux build, build-only and proc-macro crates),
/// so scoring recall against all of it would ask for crates that are not in
/// the file. A lock package counts as linked when
/// - its `<name>-<version>` directory appears in a source path of the debug
///   info (a CU root or a function's declaration), or
/// - no version of it appears in a path, but its crate name is the crate of
///   a CU or of a function (code with no path of its own, e.g. generated).
///
/// Registry packages seen in paths but missing from the lock are kept too
/// (and are all there is when the build had no lock file). The built package
/// itself is not a dependency.
pub fn linked_dependencies(
    lock_packages: &[Package],
    registry_seen: &BTreeSet<Package>,
    seen_crates: &BTreeSet<String>,
    package: Option<&Package>,
) -> Vec<Package> {
    let is_self = |p: &Package| {
        package.is_some_and(|me| {
            normalize_crate(&me.name) == normalize_crate(&p.name) && me.version == p.version
        })
    };
    let seen_names: BTreeSet<String> = registry_seen
        .iter()
        .map(|p| normalize_crate(&p.name))
        .collect();
    let mut out: BTreeSet<Package> = BTreeSet::new();
    for p in lock_packages {
        let n = normalize_crate(&p.name);
        let by_path = registry_seen.contains(p);
        let by_name = !seen_names.contains(&n) && seen_crates.contains(&n);
        if (by_path || by_name) && !is_self(p) {
            out.insert(p.clone());
        }
    }
    for p in registry_seen {
        if !is_self(p) && !is_std_crate(&p.name) {
            out.insert(p.clone());
        }
    }
    out.into_iter().collect()
}

struct Classifier<'a> {
    package: Option<&'a Package>,
    /// Group of each crate as given by its compilation units.
    unit_kinds: HashMap<String, Group>,
    lock_crates: BTreeSet<String>,
}

impl Classifier<'_> {
    fn group(&self, krate: Option<&str>, decl_path: Option<&str>) -> Group {
        let krate = krate.map(normalize_crate);
        if let Some(path) = decl_path {
            match classify_path(path) {
                PathOrigin::Std => return Group::Std,
                PathOrigin::Registry { name, version } => {
                    if self.is_package(&name, &version) {
                        return Group::User;
                    }
                    return Group::Dependency(krate.unwrap_or_else(|| normalize_crate(&name)));
                }
                PathOrigin::Other => {}
            }
        }
        let Some(k) = krate else { return Group::Std };
        if let Some(g) = self.unit_kinds.get(&k) {
            return g.clone();
        }
        if is_std_crate(&k) {
            Group::Std
        } else if self.lock_crates.contains(&k) {
            Group::Dependency(k)
        } else {
            Group::User
        }
    }

    fn is_package(&self, name: &str, version: &str) -> bool {
        self.package.is_some_and(|p| {
            normalize_crate(&p.name) == normalize_crate(name) && p.version == version
        })
    }
}

/// The group of every crate that has compilation units, from the CU root
/// paths. A crate whose CUs disagree (should not happen) keeps the first.
fn unit_kinds(units: &[UnitInfo], package: Option<&Package>) -> HashMap<String, Group> {
    let mut out = HashMap::new();
    for u in units {
        let (Some(k), Some(root)) = (&u.krate, &u.root) else {
            continue;
        };
        let k = normalize_crate(k);
        let g = match classify_path(root) {
            PathOrigin::Std => Group::Std,
            PathOrigin::Registry { name, version } => {
                let me = package.is_some_and(|p| {
                    normalize_crate(&p.name) == normalize_crate(&name) && p.version == version
                });
                if me {
                    Group::User
                } else {
                    Group::Dependency(k.clone())
                }
            }
            PathOrigin::Other => {
                if is_std_crate(&k) {
                    Group::Std
                } else {
                    Group::User
                }
            }
        };
        out.entry(k).or_insert(g);
    }
    out
}

fn unit_info(unit: &gimli::Unit<R<'_>>) -> UnitInfo {
    let name = unit.name.map(|n| n.to_string_lossy().into_owned());
    let comp_dir = unit.comp_dir.map(|n| n.to_string_lossy().into_owned());
    let (root, krate) = match name.as_deref().and_then(|n| n.split_once("/@/")) {
        Some((root, cgu)) => (
            Some(root.to_owned()),
            cgu.split('.')
                .next()
                .filter(|s| !s.is_empty())
                .map(str::to_owned),
        ),
        None => (name.clone(), None),
    };
    let root = root.map(|r| absolute(&r, comp_dir.as_deref()));
    UnitInfo {
        krate,
        root,
        comp_dir,
    }
}

fn absolute(path: &str, base: Option<&str>) -> String {
    if path.starts_with('/') || path.contains(":\\") {
        return path.to_owned();
    }
    match base {
        Some(b) if !b.is_empty() => format!("{}/{}", b.trim_end_matches('/'), path),
        _ => path.to_owned(),
    }
}

fn walk_unit(
    dwarf: &gimli::Dwarf<R<'_>>,
    unit: &gimli::Unit<R<'_>>,
    nodes: &mut HashMap<u64, Node>,
    raw: &mut Vec<RawFunction>,
) {
    let mut cursor = unit.entries();
    let mut depth: isize = 0;
    // stack[d] = the kept DIE at depth d, if any.
    let mut stack: Vec<Option<u64>> = Vec::new();
    // A parse error ends the unit: what was read so far is kept.
    while let Ok(Some((delta, entry))) = cursor.next_dfs() {
        depth += delta;
        let Ok(d) = usize::try_from(depth) else { break };
        stack.truncate(d);
        let parent = stack.iter().rev().flatten().next().copied();
        let Some(off) = entry
            .offset()
            .to_debug_info_offset(&unit.header)
            .map(|o| o.0 as u64)
        else {
            stack.push(None);
            continue;
        };
        let scope = match entry.tag() {
            gimli::DW_TAG_compile_unit | gimli::DW_TAG_partial_unit => Some(Scope::Unit),
            gimli::DW_TAG_namespace => Some(Scope::Namespace),
            gimli::DW_TAG_structure_type
            | gimli::DW_TAG_enumeration_type
            | gimli::DW_TAG_union_type
            | gimli::DW_TAG_class_type => Some(Scope::Type),
            gimli::DW_TAG_subprogram => Some(Scope::Subprogram),
            _ => None,
        };
        let Some(scope) = scope else {
            stack.push(None);
            continue;
        };
        let mut node = Node {
            scope: Some(scope),
            parent,
            ..Node::default()
        };
        let string = |v: AttributeValue<R<'_>>| {
            dwarf
                .attr_string(unit, v)
                .ok()
                .map(|s| s.to_string_lossy().into_owned())
        };
        if let Ok(Some(v)) = entry.attr_value(gimli::DW_AT_name) {
            node.name = string(v);
        }
        if scope == Scope::Subprogram {
            for at in [gimli::DW_AT_linkage_name, gimli::DW_AT_MIPS_linkage_name] {
                if node.linkage.is_none()
                    && let Ok(Some(v)) = entry.attr_value(at)
                {
                    node.linkage = string(v);
                }
            }
            if let Ok(Some(v)) = entry.attr_value(gimli::DW_AT_decl_file) {
                node.decl_path = file_path(dwarf, unit, v);
            }
            for at in [gimli::DW_AT_abstract_origin, gimli::DW_AT_specification] {
                if node.origin.is_none()
                    && let Ok(Some(v)) = entry.attr_value(at)
                {
                    node.origin = reference(unit, v);
                }
            }
            if let Some((start, size)) = code_range(dwarf, unit, entry) {
                raw.push(RawFunction {
                    start,
                    size,
                    die: off,
                });
            }
        }
        nodes.insert(off, node);
        stack.push(Some(off));
    }
}

fn reference(unit: &gimli::Unit<R<'_>>, v: AttributeValue<R<'_>>) -> Option<u64> {
    match v {
        AttributeValue::UnitRef(o) => o.to_debug_info_offset(&unit.header).map(|o| o.0 as u64),
        AttributeValue::DebugInfoRef(o) => Some(o.0 as u64),
        _ => None,
    }
}

/// Entry address and size of a subprogram's code.
fn code_range(
    dwarf: &gimli::Dwarf<R<'_>>,
    unit: &gimli::Unit<R<'_>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, R<'_>>,
) -> Option<(u64, u64)> {
    let mut ranges = dwarf.die_ranges(unit, entry).ok()?;
    let mut all: Vec<gimli::Range> = Vec::new();
    while let Ok(Some(r)) = ranges.next() {
        if r.end > r.begin {
            all.push(r);
        }
        if all.len() > 4096 {
            break;
        }
    }
    let entry_pc = match entry.attr_value(gimli::DW_AT_entry_pc) {
        Ok(Some(v)) => dwarf.attr_address(unit, v).ok().flatten(),
        _ => None,
    };
    let low_pc = match entry.attr_value(gimli::DW_AT_low_pc) {
        Ok(Some(v)) => dwarf.attr_address(unit, v).ok().flatten(),
        _ => None,
    };
    let start = entry_pc
        .or(low_pc)
        .or_else(|| all.iter().map(|r| r.begin).min())?;
    let size = all
        .iter()
        .find(|r| start >= r.begin && start < r.end)
        .map(|r| r.end - start)
        .unwrap_or(0);
    if size == 0 {
        return None;
    }
    Some((start, size))
}

fn file_path(
    dwarf: &gimli::Dwarf<R<'_>>,
    unit: &gimli::Unit<R<'_>>,
    v: AttributeValue<R<'_>>,
) -> Option<String> {
    let index = match v {
        AttributeValue::FileIndex(i) => i,
        AttributeValue::Udata(i) => i,
        AttributeValue::Data1(i) => i.into(),
        AttributeValue::Data2(i) => i.into(),
        AttributeValue::Data4(i) => i.into(),
        _ => return None,
    };
    let lp = unit.line_program.as_ref()?;
    let header = lp.header();
    let file = header.file(index)?;
    let name = dwarf
        .attr_string(unit, file.path_name())
        .ok()?
        .to_string_lossy()
        .into_owned();
    if name.starts_with('/') {
        return Some(name);
    }
    let dir = file
        .directory(header)
        .and_then(|d| dwarf.attr_string(unit, d).ok())
        .map(|d| d.to_string_lossy().into_owned());
    let comp_dir = unit.comp_dir.map(|d| d.to_string_lossy().into_owned());
    let dir = dir.map(|d| absolute(&d, comp_dir.as_deref())).or(comp_dir);
    Some(absolute(&name, dir.as_deref()))
}

struct Described {
    name: Option<String>,
    krate: Option<String>,
    decl_path: Option<String>,
}

/// Name, crate and declaration of the function whose concrete DIE is `die`.
fn describe(nodes: &HashMap<u64, Node>, die: u64) -> Described {
    let mut linkage = None;
    let mut name = None;
    let mut decl_path = None;
    let mut scope_die = die;
    let mut cur = Some(die);
    for _ in 0..MAX_ORIGIN_HOPS {
        let Some(n) = cur.and_then(|c| nodes.get(&c)) else {
            break;
        };
        if let Some(c) = cur {
            // The namespaces of the most abstract DIE are the item's path.
            scope_die = c;
        }
        linkage = linkage.or_else(|| n.linkage.clone());
        name = name.or_else(|| n.name.clone());
        decl_path = decl_path.or_else(|| n.decl_path.clone());
        cur = n.origin;
    }

    // Enclosing namespaces, innermost first.
    let mut path: Vec<&str> = Vec::new();
    let mut p = nodes.get(&scope_die).and_then(|n| n.parent);
    for _ in 0..MAX_SCOPE_DEPTH {
        let Some(n) = p.and_then(|o| nodes.get(&o)) else {
            break;
        };
        match n.scope {
            Some(Scope::Unit) => break,
            Some(Scope::Namespace | Scope::Type | Scope::Subprogram) => {
                if let Some(s) = n.name.as_deref() {
                    path.push(s);
                }
            }
            None => {}
        }
        p = n.parent;
    }
    let demangled = linkage.as_deref().and_then(demangle_rust);
    let krate = path
        .last()
        .map(|s| (*s).to_owned())
        .or_else(|| {
            demangled
                .as_deref()
                .and_then(crate_of_demangled)
                .map(str::to_owned)
        })
        .map(|k| normalize_crate(&k));
    let full = demangled.or_else(|| linkage.clone()).or_else(|| {
        name.as_ref().map(|n| {
            let mut parts: Vec<&str> = path.iter().rev().copied().collect();
            parts.push(n);
            parts.join("::")
        })
    });
    Described {
        name: full,
        krate,
        decl_path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(n: &str, v: &str) -> Package {
        Package {
            name: n.into(),
            version: v.into(),
        }
    }

    #[test]
    fn linked_dependencies_prefers_paths() {
        let lock = vec![
            pkg("bitflags", "1.3.2"),
            pkg("bitflags", "2.6.0"),
            pkg("windows-sys", "0.59.0"),
            pkg("regex-automata", "0.4.9"),
            pkg("mytool", "1.0.0"),
        ];
        let seen: BTreeSet<Package> = [pkg("bitflags", "2.6.0"), pkg("mytool", "1.0.0")].into();
        let crates: BTreeSet<String> = ["bitflags", "regex_automata", "core"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let me = pkg("mytool", "1.0.0");
        let got = linked_dependencies(&lock, &seen, &crates, Some(&me));
        assert_eq!(
            got,
            vec![pkg("bitflags", "2.6.0"), pkg("regex-automata", "0.4.9")]
        );
    }

    #[test]
    fn classifier_rules() {
        let me = pkg("ripgrep", "14.1.1");
        let ctx = Classifier {
            package: Some(&me),
            unit_kinds: [(
                "hashbrown".to_string(),
                Group::Dependency("hashbrown".into()),
            )]
            .into(),
            lock_crates: ["hashbrown".to_string(), "memchr".to_string()].into(),
        };
        let reg = "/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f";
        assert_eq!(
            ctx.group(
                Some("rg"),
                Some(&format!("{reg}/ripgrep-14.1.1/crates/core/main.rs"))
            ),
            Group::User
        );
        assert_eq!(
            ctx.group(
                Some("memchr"),
                Some(&format!("{reg}/memchr-2.7.4/src/lib.rs"))
            ),
            Group::Dependency("memchr".into())
        );
        assert_eq!(
            ctx.group(Some("memchr"), Some("/rust/deps/memchr-2.8.3/src/lib.rs")),
            Group::Std
        );
        assert_eq!(
            ctx.group(
                Some("core"),
                Some("/rustc/b940084d7eb6a299eb4bfeb8e34901bc051e7ac4/library/core/src/fmt/mod.rs")
            ),
            Group::Std
        );
        // No path: CU table, then name lists.
        assert_eq!(
            ctx.group(Some("hashbrown"), None),
            Group::Dependency("hashbrown".into())
        );
        assert_eq!(ctx.group(Some("alloc"), None), Group::Std);
        assert_eq!(ctx.group(Some("memchr"), None), Group::Std);
        assert_eq!(ctx.group(Some("grep_cli"), None), Group::User);
        assert_eq!(ctx.group(None, None), Group::Std);
    }

    #[test]
    fn cu_names() {
        assert_eq!(absolute("src/main.rs", Some("/b")), "/b/src/main.rs");
        assert_eq!(absolute("/x/y.rs", Some("/b")), "/x/y.rs");
    }
}

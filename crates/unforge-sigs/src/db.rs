//! The signature database and its file format.
//!
//! # File format (version 1)
//!
//! Integers marked `varint` are unsigned LEB128 (7 bits per byte, low bits
//! first, at most 10 bytes); a `str` is a `varint` byte length followed by
//! that many bytes of UTF-8 (at most [`MAX_NAME_LEN`]).
//!
//! ```text
//! magic        8 bytes  "UFSIGDB\0"
//! version      u32 LE   1 (FORMAT_VERSION)
//! min_insns    varint   build options (Options) the entries were made with
//! min_bytes    varint
//! n_sources    varint   then n_sources × str, sorted, distinct
//! n_crates     varint   then n_crates × str, sorted, distinct
//! n_entries    varint   then n_entries × entry, sorted by hash, distinct
//!
//! entry:
//!   hash       u64 LE   Fingerprint::hash
//!   insns      varint   Fingerprint::insns
//!   bytes      varint   Fingerprint::bytes
//!   flags      u8       bit 0: more names were seen than are stored
//!                       (Entry::truncated); other bits 0
//!   n_names    varint   1..=MAX_NAMES, then n_names × name, sorted, distinct
//!
//! name:
//!   name       str      demangled, without the hash
//!   crate      varint   0 = unknown, k = the k-th crate string (1-based)
//! ```
//!
//! Nothing may follow the last entry. Every list is sorted and free of
//! duplicates, so one database has exactly one encoding:
//! `Db::from_bytes(b)?.to_bytes() == b`, and building from the same inputs
//! always gives the same bytes. Readers reject anything else (unknown
//! version, unsorted lists, unknown flag bits, trailing bytes) instead of
//! guessing.
//!
//! "Sources" are the `name version` lines of the dependencies
//! (`unforge_analysis::Analysis::dependencies`) of every file the database
//! was built from, e.g. `rustc b940084d7eb6a299eb4bfeb8e34901bc051e7ac4`
//! or `serde 1.0.228`. They say which code the signatures can recognize.
//!
//! A binary format was chosen over JSON for three reasons. Size: the name
//! text is 84 to 95 % of a database, the rest is about 15 bytes per entry
//! here, while a JSON object per entry with a hex hash, keys, quotes and a
//! crate per name adds some 70 bytes, about 1.6× in total for release
//! code. Strictness: one canonical byte layout is easy to check while
//! reading (sorted, no duplicates, no trailing bytes), so equal databases
//! are equal files. Dependencies: it needs no JSON library in this crate.

use std::collections::{BTreeMap, BTreeSet};

use crate::Options;
use crate::normalize::Fingerprint;

/// File magic.
pub const MAGIC: &[u8; 8] = b"UFSIGDB\0";
/// Current file format version.
pub const FORMAT_VERSION: u32 = 1;
/// Names kept per fingerprint. More names are counted by
/// [`Entry::truncated`] but not stored: a fingerprint with that many
/// different names (typically a tiny generic shim) identifies none of them.
pub const MAX_NAMES: usize = 16;
/// Longest string accepted in a database (names, crates, sources).
pub const MAX_NAME_LEN: usize = unforge_analysis::MAX_NAME_LEN;
/// Most sources kept.
pub const MAX_SOURCES: usize = 1 << 14;
/// Most crate strings kept.
pub const MAX_CRATES: usize = 1 << 16;

/// One name a fingerprint was seen with.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SigName {
    /// Demangled name without the hash (`unforge_analysis` spelling), or
    /// the raw name of a non-Rust symbol.
    pub name: String,
    /// Crate of the name (first path segment, `_` spelling), when the
    /// name is a Rust path.
    pub krate: Option<String>,
}

/// Everything known about one fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub insns: u32,
    pub bytes: u32,
    /// Sorted, distinct, at most [`MAX_NAMES`], never empty.
    pub names: Vec<SigName>,
    /// More distinct names were seen than [`MAX_NAMES`].
    pub truncated: bool,
}

impl Entry {
    fn add(&mut self, name: SigName) {
        match self.names.binary_search(&name) {
            Ok(_) => {}
            Err(pos) => {
                self.names.insert(pos, name);
                if self.names.len() > MAX_NAMES {
                    // Keep the first MAX_NAMES in sort order: deterministic
                    // whatever order the names came in.
                    self.names.truncate(MAX_NAMES);
                    self.truncated = true;
                }
            }
        }
    }
}

/// A signature database: fingerprint hash → names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Db {
    pub(crate) options: Options,
    pub(crate) entries: BTreeMap<u64, Entry>,
    pub(crate) sources: BTreeSet<String>,
}

/// Why a database file could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbError {
    /// Does not start with [`MAGIC`].
    BadMagic,
    /// A format version this build does not read.
    UnsupportedVersion(u32),
    /// Ends in the middle of something.
    Truncated,
    /// Well-formed bytes that break a rule of the format.
    Invalid(&'static str),
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbError::BadMagic => write!(f, "not an unforge signature database"),
            DbError::UnsupportedVersion(v) => write!(
                f,
                "signature database format version {v} is not supported (this build reads {FORMAT_VERSION})"
            ),
            DbError::Truncated => write!(f, "signature database is truncated"),
            DbError::Invalid(why) => write!(f, "invalid signature database: {why}"),
        }
    }
}

impl std::error::Error for DbError {}

impl Db {
    /// An empty database whose entries are made with `options`.
    pub fn new(options: Options) -> Db {
        Db {
            options,
            entries: BTreeMap::new(),
            sources: BTreeSet::new(),
        }
    }

    /// The options the entries were made with.
    pub fn options(&self) -> Options {
        self.options
    }

    /// Number of distinct fingerprints.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry for a fingerprint, if any.
    pub fn get(&self, fp: &Fingerprint) -> Option<&Entry> {
        self.entries.get(&fp.hash)
    }

    /// All entries, sorted by hash.
    pub fn entries(&self) -> impl Iterator<Item = (u64, &Entry)> + '_ {
        self.entries.iter().map(|(h, e)| (*h, e))
    }

    /// The dependencies (`name version`) of the files the database was built
    /// from, sorted.
    pub fn sources(&self) -> impl Iterator<Item = &str> + '_ {
        self.sources.iter().map(String::as_str)
    }

    /// Adds one name for a fingerprint. Fingerprints below the database's
    /// [`Options`] are ignored.
    pub fn insert(&mut self, fp: Fingerprint, name: SigName) {
        if !self.options.keeps(fp) || name.name.is_empty() || name.name.len() > MAX_NAME_LEN {
            return;
        }
        let name = SigName {
            krate: name
                .krate
                .filter(|k| !k.is_empty() && k.len() <= MAX_NAME_LEN),
            ..name
        };
        self.entries
            .entry(fp.hash)
            .or_insert_with(|| Entry {
                insns: fp.insns,
                bytes: fp.bytes,
                names: Vec::new(),
                truncated: false,
            })
            .add(name);
    }

    /// Records a source (`name version`).
    pub fn add_source(&mut self, source: String) {
        if self.sources.len() < MAX_SOURCES && !source.is_empty() && source.len() <= MAX_NAME_LEN {
            self.sources.insert(source);
        }
    }

    /// Merges `other` into `self`. The result keeps the stricter of the two
    /// options (the larger thresholds), and drops entries below them.
    pub fn merge(&mut self, other: Db) {
        let options = Options {
            min_insns: self.options.min_insns.max(other.options.min_insns),
            min_bytes: self.options.min_bytes.max(other.options.min_bytes),
        };
        self.options = options;
        self.entries.retain(|_, e| {
            options.keeps(Fingerprint {
                hash: 0,
                insns: e.insns,
                bytes: e.bytes,
            })
        });
        for (hash, e) in other.entries {
            let fp = Fingerprint {
                hash,
                insns: e.insns,
                bytes: e.bytes,
            };
            if !options.keeps(fp) {
                continue;
            }
            let truncated = e.truncated;
            for n in e.names {
                self.insert(fp, n);
            }
            if truncated && let Some(mine) = self.entries.get_mut(&hash) {
                mine.truncated = true;
            }
        }
        for s in other.sources {
            self.add_source(s);
        }
    }

    /// The canonical encoding (see the module docs).
    pub fn to_bytes(&self) -> Vec<u8> {
        let crates: BTreeSet<&str> = self
            .entries
            .values()
            .flat_map(|e| e.names.iter().filter_map(|n| n.krate.as_deref()))
            .collect();
        let crates: Vec<&str> = crates.into_iter().take(MAX_CRATES).collect();
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        put_varint(&mut out, u64::from(self.options.min_insns));
        put_varint(&mut out, u64::from(self.options.min_bytes));
        put_varint(&mut out, self.sources.len() as u64);
        for s in &self.sources {
            put_str(&mut out, s);
        }
        put_varint(&mut out, crates.len() as u64);
        for c in &crates {
            put_str(&mut out, c);
        }
        put_varint(&mut out, self.entries.len() as u64);
        for (hash, e) in &self.entries {
            out.extend_from_slice(&hash.to_le_bytes());
            put_varint(&mut out, u64::from(e.insns));
            put_varint(&mut out, u64::from(e.bytes));
            out.push(u8::from(e.truncated));
            put_varint(&mut out, e.names.len() as u64);
            for n in &e.names {
                put_str(&mut out, &n.name);
                let k = n
                    .krate
                    .as_deref()
                    .and_then(|k| crates.binary_search(&k).ok())
                    .map_or(0, |i| i as u64 + 1);
                put_varint(&mut out, k);
            }
        }
        out
    }

    /// Reads [`Db::to_bytes`]. Never panics; memory use is bounded by the
    /// input size.
    pub fn from_bytes(bytes: &[u8]) -> Result<Db, DbError> {
        let mut r = Reader { b: bytes };
        if r.take(MAGIC.len()).map_err(|_| DbError::BadMagic)? != MAGIC {
            return Err(DbError::BadMagic);
        }
        let v = r.take(4)?;
        let version = u32::from_le_bytes([
            *v.first().unwrap_or(&0),
            *v.get(1).unwrap_or(&0),
            *v.get(2).unwrap_or(&0),
            *v.get(3).unwrap_or(&0),
        ]);
        if version != FORMAT_VERSION {
            return Err(DbError::UnsupportedVersion(version));
        }
        let options = Options {
            min_insns: r.u32()?,
            min_bytes: r.u32()?,
        };
        let mut db = Db::new(options);

        let n = r.count(1)?;
        let mut prev: Option<String> = None;
        for _ in 0..n {
            let s = r.str()?;
            if prev.as_deref().is_some_and(|p| p >= s.as_str()) {
                return Err(DbError::Invalid("sources not sorted"));
            }
            if s.is_empty() || db.sources.len() >= MAX_SOURCES {
                return Err(DbError::Invalid("bad source"));
            }
            db.sources.insert(s.clone());
            prev = Some(s);
        }

        let n = r.count(1)?;
        if n > MAX_CRATES {
            return Err(DbError::Invalid("too many crates"));
        }
        let mut crates: Vec<String> = Vec::with_capacity(n);
        for _ in 0..n {
            let s = r.str()?;
            if s.is_empty() || crates.last().is_some_and(|p| p >= &s) {
                return Err(DbError::Invalid("crates not sorted"));
            }
            crates.push(s);
        }

        let n = r.count(8 + 4)?;
        let mut prev_hash: Option<u64> = None;
        for _ in 0..n {
            let h = r.take(8)?;
            let mut hb = [0u8; 8];
            hb.iter_mut().zip(h).for_each(|(d, s)| *d = *s);
            let hash = u64::from_le_bytes(hb);
            if prev_hash.is_some_and(|p| p >= hash) {
                return Err(DbError::Invalid("entries not sorted"));
            }
            prev_hash = Some(hash);
            let insns = r.u32()?;
            let bytes_ = r.u32()?;
            let flags = *r.take(1)?.first().unwrap_or(&0);
            if flags & !1 != 0 {
                return Err(DbError::Invalid("unknown entry flags"));
            }
            let k = r.count(2)?;
            if k == 0 || k > MAX_NAMES {
                return Err(DbError::Invalid("bad name count"));
            }
            let mut names: Vec<SigName> = Vec::with_capacity(k);
            for _ in 0..k {
                let name = r.str()?;
                if name.is_empty() {
                    return Err(DbError::Invalid("empty name"));
                }
                let ci = r.varint()?;
                let krate = if ci == 0 {
                    None
                } else {
                    let i = usize::try_from(ci - 1).map_err(|_| DbError::Invalid("crate index"))?;
                    Some(
                        crates
                            .get(i)
                            .cloned()
                            .ok_or(DbError::Invalid("crate index out of range"))?,
                    )
                };
                let n = SigName { name, krate };
                if names.last().is_some_and(|p| p >= &n) {
                    return Err(DbError::Invalid("names not sorted"));
                }
                names.push(n);
            }
            db.entries.insert(
                hash,
                Entry {
                    insns,
                    bytes: bytes_,
                    names,
                    truncated: flags & 1 != 0,
                },
            );
        }
        if !r.b.is_empty() {
            return Err(DbError::Invalid("trailing bytes"));
        }
        // Canonical: the crate table lists exactly the crates names use.
        let used: BTreeSet<&str> = db
            .entries
            .values()
            .flat_map(|e| e.names.iter().filter_map(|n| n.krate.as_deref()))
            .collect();
        if used.len() != crates.len() {
            return Err(DbError::Invalid("unused crate string"));
        }
        Ok(db)
    }
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_varint(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DbError> {
        if self.b.len() < n {
            return Err(DbError::Truncated);
        }
        let (head, rest) = self.b.split_at(n);
        self.b = rest;
        Ok(head)
    }

    fn varint(&mut self) -> Result<u64, DbError> {
        let mut v = 0u64;
        for i in 0..10u32 {
            let b = *self.take(1)?.first().unwrap_or(&0);
            let bits = u64::from(b & 0x7f);
            if i == 9 && bits > 1 {
                return Err(DbError::Invalid("varint overflows 64 bits"));
            }
            v |= bits << (7 * i);
            if b & 0x80 == 0 {
                // Canonical: no redundant trailing zero groups.
                if i > 0 && b == 0 {
                    return Err(DbError::Invalid("non-canonical varint"));
                }
                return Ok(v);
            }
        }
        Err(DbError::Invalid("varint too long"))
    }

    fn u32(&mut self) -> Result<u32, DbError> {
        u32::try_from(self.varint()?).map_err(|_| DbError::Invalid("number too large"))
    }

    /// A count of items of at least `min_size` bytes each: never more than
    /// the bytes left could hold, so preallocation stays bounded.
    fn count(&mut self, min_size: usize) -> Result<usize, DbError> {
        let n = self.varint()?;
        let n = usize::try_from(n).map_err(|_| DbError::Truncated)?;
        if n > self.b.len() / min_size.max(1) {
            return Err(DbError::Truncated);
        }
        Ok(n)
    }

    fn str(&mut self) -> Result<String, DbError> {
        let n = self.varint()?;
        let n = usize::try_from(n).map_err(|_| DbError::Truncated)?;
        if n > MAX_NAME_LEN {
            return Err(DbError::Invalid("string too long"));
        }
        let b = self.take(n)?;
        String::from_utf8(b.to_vec()).map_err(|_| DbError::Invalid("string is not UTF-8"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(hash: u64, insns: u32) -> Fingerprint {
        Fingerprint {
            hash,
            insns,
            bytes: insns * 3,
        }
    }

    fn n(name: &str, krate: Option<&str>) -> SigName {
        SigName {
            name: name.into(),
            krate: krate.map(Into::into),
        }
    }

    fn sample() -> Db {
        let mut db = Db::new(Options::default());
        db.insert(fp(7, 10), n("core::fmt::write", Some("core")));
        db.insert(fp(3, 12), n("memcpy", None));
        db.insert(fp(7, 10), n("alloc::fmt::format", Some("alloc")));
        db.insert(fp(7, 10), n("core::fmt::write", Some("core")));
        db.insert(fp(u64::MAX, 300), n("zz::ü", Some("zz")));
        db.add_source("rustc b940084d7eb6a299eb4bfeb8e34901bc051e7ac4".into());
        db.add_source("serde 1.0.228".into());
        db
    }

    #[test]
    fn round_trip_is_canonical() {
        let db = sample();
        let b = db.to_bytes();
        let back = Db::from_bytes(&b).unwrap();
        assert_eq!(back, db);
        assert_eq!(back.to_bytes(), b);
        assert_eq!(db.len(), 3);
        let e = db.get(&fp(7, 10)).unwrap();
        assert_eq!(e.names.len(), 2);
        assert_eq!(e.names[0].name, "alloc::fmt::format");
        // Insertion order does not matter.
        let mut other = Db::new(Options::default());
        other.add_source("serde 1.0.228".into());
        other.insert(fp(u64::MAX, 300), n("zz::ü", Some("zz")));
        other.insert(fp(7, 10), n("core::fmt::write", Some("core")));
        other.insert(fp(7, 10), n("alloc::fmt::format", Some("alloc")));
        other.add_source("rustc b940084d7eb6a299eb4bfeb8e34901bc051e7ac4".into());
        other.insert(fp(3, 12), n("memcpy", None));
        assert_eq!(other.to_bytes(), b);
    }

    #[test]
    fn empty_round_trip() {
        let db = Db::new(Options::NONE);
        assert_eq!(Db::from_bytes(&db.to_bytes()).unwrap(), db);
    }

    #[test]
    fn small_functions_are_not_inserted() {
        let mut db = Db::new(Options::default());
        db.insert(fp(1, 2), n("tiny", None));
        assert!(db.is_empty());
    }

    #[test]
    fn names_are_capped() {
        let mut db = Db::new(Options::default());
        for i in (0..40).rev() {
            db.insert(fp(1, 10), n(&format!("f{i:02}"), None));
        }
        let e = db.get(&fp(1, 10)).unwrap();
        assert_eq!(e.names.len(), MAX_NAMES);
        assert!(e.truncated);
        assert_eq!(e.names[0].name, "f00");
        let b = db.to_bytes();
        assert_eq!(Db::from_bytes(&b).unwrap(), db);
    }

    #[test]
    fn merge_unions_and_keeps_stricter_options() {
        let mut a = Db::new(Options::NONE);
        a.insert(fp(1, 2), n("tiny", None));
        a.insert(fp(2, 20), n("big_a", None));
        let mut b = Db::new(Options::default());
        b.insert(fp(2, 20), n("big_b", None));
        b.insert(fp(5, 30), n("other", None));
        b.add_source("x 1".into());
        a.merge(b);
        assert_eq!(a.options(), Options::default());
        assert!(a.get(&fp(1, 2)).is_none());
        assert_eq!(a.get(&fp(2, 20)).unwrap().names.len(), 2);
        assert_eq!(a.len(), 2);
        assert_eq!(a.sources().collect::<Vec<_>>(), vec!["x 1"]);
    }

    #[test]
    fn rejects_bad_files() {
        let good = sample().to_bytes();
        assert_eq!(Db::from_bytes(b""), Err(DbError::BadMagic));
        assert_eq!(Db::from_bytes(b"UFSIGDB"), Err(DbError::BadMagic));
        assert_eq!(
            Db::from_bytes(b"NOTADB\0\0\x01\0\0\0"),
            Err(DbError::BadMagic)
        );
        let mut v2 = good.clone();
        v2[8] = 2;
        assert_eq!(Db::from_bytes(&v2), Err(DbError::UnsupportedVersion(2)));
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(Db::from_bytes(&trailing).is_err());
        // Every prefix is an error, never a panic.
        for len in 0..good.len() {
            assert!(Db::from_bytes(&good[..len]).is_err(), "prefix {len}");
        }
        // Every single-byte change either fails or reads back canonically.
        for i in 0..good.len() {
            for x in [0x01u8, 0x80, 0xff] {
                let mut b = good.clone();
                b[i] ^= x;
                if let Ok(db) = Db::from_bytes(&b) {
                    assert_eq!(db.to_bytes(), b, "byte {i} ^ {x:#x}");
                }
            }
        }
        // A huge declared count does not allocate.
        let mut huge = Vec::from(&MAGIC[..]);
        huge.extend_from_slice(&1u32.to_le_bytes());
        huge.extend_from_slice(&[
            6, 16, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
        ]);
        assert!(Db::from_bytes(&huge).is_err());
    }
}

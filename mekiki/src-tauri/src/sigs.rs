//! Fingerprint databases (`unforge_sigs::Db`) for naming functions in
//! stripped binaries. They live as `.db` files in the app's data folder,
//! `signatures/`, and are merged into one database when loaded.

use std::path::{Path, PathBuf};

use unforge_sigs::{Db, Options};

/// The user's own database: files added with "Add This File to Signatures".
pub const MINE: &str = "mine.db";

#[derive(Default)]
pub struct Signatures {
    pub dir: PathBuf,
    /// Every readable `.db` file of `dir`, by file name.
    pub dbs: Vec<(String, Db)>,
    pub files: Vec<String>,
    /// Files that could not be read, with the reason.
    pub broken: Vec<String>,
}

/// The databases chosen for one file, merged.
pub struct Choice {
    pub db: Option<Db>,
    /// File names of the databases used.
    pub files: Vec<String>,
    /// Why these were chosen, for the Console; None when nothing to say.
    pub note: Option<String>,
}

/// The `rustc` commits a database was built from (its `rustc <commit>`
/// sources). Standard-library code is the same only for the same commit.
pub fn rustc_commits(db: &Db) -> Vec<&str> {
    db.sources().filter_map(|s| s.strip_prefix("rustc ")).collect()
}

/// Which databases to use for a file built with `commit` (from
/// `Report::rustc_commit`):
///
/// - commit unknown: all of them;
/// - otherwise the ones built with that commit, plus the ones without any
///   `rustc` source (name lists);
/// - when none was built with that commit, all of them, with a note: std
///   code from another rustc rarely matches and adds ambiguous candidates.
pub fn choose<'a>(dbs: &'a [(String, Db)], commit: Option<&str>) -> (Vec<&'a (String, Db)>, Option<String>) {
    let Some(commit) = commit else {
        return (dbs.iter().collect(), None);
    };
    let same: Vec<_> = dbs.iter().filter(|(_, db)| rustc_commits(db).contains(&commit)).collect();
    if same.is_empty() {
        let note = (!dbs.is_empty()).then(|| {
            format!(
                "No fingerprint database was built with this file's rustc ({}); using all of them. Load the std database for that commit for better names.",
                &commit[..commit.len().min(9)]
            )
        });
        return (dbs.iter().collect(), note);
    }
    let unversioned = dbs.iter().filter(|(_, db)| rustc_commits(db).is_empty());
    let mut chosen: Vec<_> = same.into_iter().chain(unversioned).collect();
    chosen.sort_by(|a, b| a.0.cmp(&b.0));
    let skipped = dbs.len() - chosen.len();
    let note = (skipped > 0).then(|| format!("Using the {} fingerprint database(s) built with this file's rustc; skipped {skipped} built with other versions.", chosen.len()));
    (chosen, note)
}

#[derive(serde::Serialize)]
pub struct Summary {
    pub dir: String,
    pub files: Vec<String>,
    pub broken: Vec<String>,
    pub fingerprints: usize,
}

impl Signatures {
    pub fn summary(&self) -> Summary {
        Summary {
            dir: self.dir.display().to_string(),
            files: self.files.clone(),
            broken: self.broken.clone(),
            fingerprints: self.dbs.iter().map(|(_, db)| db.len()).sum(),
        }
    }

    /// The databases for a file built with `commit`, merged into one.
    pub fn for_commit(&self, commit: Option<&str>) -> Choice {
        let (chosen, note) = choose(&self.dbs, commit);
        let mut db: Option<Db> = None;
        for (_, d) in &chosen {
            match db.as_mut() {
                Some(all) => all.merge(d.clone()),
                None => db = Some(d.clone()),
            }
        }
        Choice { db, files: chosen.iter().map(|(n, _)| n.clone()).collect(), note }
    }

    /// (Re)reads every `.db` file of `dir`.
    pub fn load(dir: PathBuf) -> Signatures {
        let mut s = Signatures { dir, ..Default::default() };
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&s.dir)
            .map(|rd| rd.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.extension().is_some_and(|x| x == "db")).collect())
            .unwrap_or_default();
        paths.sort();
        for p in paths {
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            match std::fs::read(&p).map_err(|e| e.to_string()).and_then(|b| Db::from_bytes(&b).map_err(|e| format!("{e:?}"))) {
                Ok(db) => {
                    s.files.push(name.clone());
                    s.dbs.push((name, db));
                }
                Err(e) => s.broken.push(format!("{name}: {e}")),
            }
        }
        s
    }
}

/// Copies database files into `dir`, after checking each one reads.
pub fn import(dir: &Path, paths: &[PathBuf]) -> Result<Vec<String>, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut added = Vec::new();
    for p in paths {
        let bytes = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
        Db::from_bytes(&bytes).map_err(|e| format!("{} is not a fingerprint database: {e:?}", p.display()))?;
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "imported.db".into());
        let name = if name.ends_with(".db") { name } else { format!("{name}.db") };
        std::fs::write(dir.join(&name), &bytes).map_err(|e| e.to_string())?;
        added.push(name);
    }
    Ok(added)
}

/// Adds the fingerprints of `data` (a file that still has symbols) to the
/// user's own database in `dir`. Returns the number of names added.
pub fn add_to_mine(dir: &Path, data: &[u8]) -> Result<usize, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = dir.join(MINE);
    let mut db = match std::fs::read(&path) {
        Ok(b) => Db::from_bytes(&b).map_err(|e| format!("{MINE}: {e:?}"))?,
        Err(_) => Db::new(Options::default()),
    };
    let stats = db.add_elf(data).map_err(|e| format!("{e:?}"))?;
    let tmp = dir.join(format!("{MINE}.tmp"));
    std::fs::write(&tmp, db.to_bytes()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(stats.added)
}

#[cfg(test)]
mod tests {
    use super::*;
    use unforge_sigs::{Fingerprint, SigName};

    fn db(sources: &[&str]) -> Db {
        let mut db = Db::new(Options::NONE);
        db.insert(Fingerprint { hash: 1, insns: 10, bytes: 40 }, SigName { name: "f".into(), krate: None });
        for s in sources {
            db.add_source((*s).to_owned());
        }
        db
    }

    fn names(c: &[&(String, Db)]) -> Vec<String> {
        c.iter().map(|(n, _)| n.clone()).collect()
    }

    #[test]
    fn picks_the_databases_of_the_files_rustc() {
        let dbs = vec![
            ("std-1.98.db".to_owned(), db(&["rustc aaaa"])),
            ("std-1.99.db".to_owned(), db(&["rustc bbbb"])),
            ("crates-1.99.db".to_owned(), db(&["rustc bbbb", "tokio 1.54.1"])),
            ("names.db".to_owned(), db(&[])),
        ];
        let (c, note) = choose(&dbs, Some("bbbb"));
        assert_eq!(names(&c), ["crates-1.99.db", "names.db", "std-1.99.db"]);
        assert!(note.unwrap().contains("skipped 1"));
        // unknown commit: everything, quietly
        let (c, note) = choose(&dbs, None);
        assert_eq!(c.len(), 4);
        assert!(note.is_none());
        // no database for this commit: everything, with a note
        let (c, note) = choose(&dbs, Some("cccc"));
        assert_eq!(c.len(), 4);
        assert!(note.unwrap().contains("cccc"));
    }
}

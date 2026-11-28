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
    /// All `.db` files of `dir`, merged; None when there are none.
    pub db: Option<Db>,
    pub files: Vec<String>,
    /// Files that could not be read, with the reason.
    pub broken: Vec<String>,
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
            fingerprints: self.db.as_ref().map_or(0, Db::len),
        }
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
                    match s.db.as_mut() {
                        Some(all) => all.merge(db),
                        None => s.db = Some(db),
                    }
                    s.files.push(name);
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

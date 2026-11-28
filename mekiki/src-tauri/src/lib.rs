//! The Tauri side of Mekiki: opens a file, runs the unforge report on it in
//! this process, and serves byte ranges of it to the Listing.

mod decomp;
mod sigs;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tauri::ipc::Response;
use tauri::{AppHandle, Manager, State};

/// Files larger than this are refused (they are read into memory whole).
const MAX_FILE: u64 = 2 << 30;
/// At most this many bytes per `read_range` call.
const MAX_RANGE: u64 = 1 << 20;

#[derive(Default)]
struct Opened {
    path: Option<PathBuf>,
    bytes: Arc<Vec<u8>>,
    /// The report's functions (start, size), for the code map
    spans: Vec<(u64, u64)>,
}

#[derive(Default)]
struct SigState(Mutex<sigs::Signatures>);

#[derive(Default)]
struct AppState(Mutex<Opened>);

#[derive(Default)]
struct DecompState {
    decompiler: Arc<Mutex<decomp::Decompiler>>,
    killer: decomp::Killer,
}

/// Reads the file at `path`, keeps its bytes for `read_range`, and returns
/// the report (see `unforge_report::Report`) with the fingerprint databases
/// applied, plus the file name.
#[tauri::command]
fn open_file(
    path: PathBuf,
    state: State<'_, AppState>,
    dstate: State<'_, DecompState>,
    sstate: State<'_, SigState>,
) -> Result<serde_json::Value, String> {
    let meta = std::fs::metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a file", path.display()));
    }
    if meta.len() > MAX_FILE {
        return Err(format!("{} is larger than 2 GB", path.display()));
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let started = std::time::Instant::now();
    // The fingerprint databases for this file's rustc (its std code differs
    // between rustc versions).
    let base = unforge_report::report(&bytes);
    let commit = base.as_ref().ok().and_then(|r| r.rustc_commit.clone());
    let choice = sstate.0.lock().map_err(|_| "busy".to_owned())?.for_commit(commit.as_deref());
    let result = base.map(|mut r| {
        let applied = unforge_report::signatures::apply(&mut r, &bytes, choice.db.as_ref());
        (r, applied)
    });
    let sig_files = choice.files.clone();
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let (report, applied, spans, functions) = match result {
        Ok((r, applied)) => {
            let spans = r.function_spans();
            let functions = r.function_names();
            (serde_json::to_value(&r).map_err(|e| e.to_string())?, Some(applied), spans, functions)
        }
        Err(f) => (serde_json::to_value(&f).map_err(|e| e.to_string())?, None, Vec::new(), Vec::new()),
    };
    let bytes = Arc::new(bytes);
    if let Ok(mut opened) = state.0.lock() {
        opened.bytes = bytes.clone();
        opened.path = Some(path.clone());
        opened.spans = spans;
    }
    dstate.killer.kill();
    if let Ok(mut d) = dstate.decompiler.lock() {
        d.reset(decomp::target(path.clone(), bytes, &functions));
    }
    Ok(serde_json::json!({
        "name": name,
        "path": path.display().to_string(),
        "elapsed_ms": elapsed_ms,
        "report": report,
        "signatures": applied,
        "signature_files": sig_files,
        "signature_note": choice.note,
    }))
}

/// Opens Mekiki's own executable: a real Rust binary to practice on in the
/// tutorial, with nothing to download.
#[tauri::command]
fn open_self(
    state: State<'_, AppState>,
    dstate: State<'_, DecompState>,
    sstate: State<'_, SigState>,
) -> Result<serde_json::Value, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    open_file(exe, state, dstate, sstate)
}

/// The fingerprint databases in use.
#[tauri::command]
fn signatures(sstate: State<'_, SigState>) -> Result<sigs::Summary, String> {
    Ok(sstate.0.lock().map_err(|_| "busy".to_owned())?.summary())
}

/// Copies fingerprint databases into the signatures folder and reloads.
#[tauri::command]
fn import_signatures(paths: Vec<PathBuf>, sstate: State<'_, SigState>) -> Result<sigs::Summary, String> {
    let mut s = sstate.0.lock().map_err(|_| "busy".to_owned())?;
    sigs::import(&s.dir, &paths)?;
    *s = sigs::Signatures::load(s.dir.clone());
    Ok(s.summary())
}

/// Adds the open file's functions (it must still have symbols) to the
/// user's own database, and reloads. Returns how many names were added.
#[tauri::command]
fn add_to_signatures(state: State<'_, AppState>, sstate: State<'_, SigState>) -> Result<usize, String> {
    let bytes = state.0.lock().map_err(|_| "busy".to_owned())?.bytes.clone();
    if bytes.is_empty() {
        return Err("No file is open.".to_owned());
    }
    let mut s = sstate.0.lock().map_err(|_| "busy".to_owned())?;
    let added = sigs::add_to_mine(&s.dir, &bytes)?;
    *s = sigs::Signatures::load(s.dir.clone());
    Ok(added)
}

/// The path of the open file, to open it again after the databases change.
#[tauri::command]
fn current_path(state: State<'_, AppState>) -> Option<String> {
    state.0.lock().ok()?.path.as_ref().map(|p| p.display().to_string())
}

/// The decompiler helper sits next to the app executable (a Tauri sidecar).
fn helper_path() -> PathBuf {
    let dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())).unwrap_or_default();
    dir.join(if cfg!(windows) { "mekiki-decomp.exe" } else { "mekiki-decomp" })
}

/// The processor specs are bundled resources; during development they are
/// read from the source tree.
fn specs_path(app: &AppHandle) -> PathBuf {
    let bundled = app.path().resource_dir().map(|d| d.join("specs").join("x86")).unwrap_or_default();
    if bundled.join("x86.ldefs").exists() {
        return bundled;
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../decompiler/specs/x86")
}

/// Code of the function at `addr` from Ghidra's decompiler, in `lang`
/// (`rust` or `c`).
#[tauri::command]
async fn decompile(addr: u64, lang: String, app: AppHandle) -> Result<decomp::Decompiled, String> {
    let specs = specs_path(&app);
    let (decompiler, killer) = {
        let s = app.state::<DecompState>();
        (s.decompiler.clone(), s.killer.clone())
    };
    tauri::async_runtime::spawn_blocking(move || {
        let mut d = decompiler.lock().map_err(|_| "busy".to_owned())?;
        d.decompile(addr, &lang, &helper_path(), &specs, &killer)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Stops the decompile in flight (the user moved to another function).
#[tauri::command]
fn cancel_decompile(dstate: State<'_, DecompState>) -> bool {
    dstate.killer.kill()
}

/// `len` bytes of the open file from `offset` (fewer at the end of the
/// file), as raw bytes (an ArrayBuffer on the JavaScript side).
#[tauri::command]
fn read_range(offset: u64, len: u64, state: State<'_, AppState>) -> Response {
    let opened = match state.0.lock() {
        Ok(o) => o,
        Err(_) => return Response::new(Vec::new()),
    };
    let size = opened.bytes.len() as u64;
    let start = offset.min(size);
    let end = start.saturating_add(len.min(MAX_RANGE)).min(size);
    let slice = opened.bytes.get(start as usize..end as usize).unwrap_or_default();
    Response::new(slice.to_vec())
}

/// Instruction lengths of every recovered function (see
/// `unforge_report::code::code_map`), as raw bytes.
#[tauri::command]
fn code_map(state: State<'_, AppState>) -> Response {
    match state.0.lock() {
        Ok(o) => Response::new(unforge_report::code::code_map_for(&o.bytes, &o.spans)),
        Err(_) => Response::new(Vec::new()),
    }
}

/// The text of one instruction at each address (null where there is none).
#[tauri::command]
fn disasm_at(addrs: Vec<u64>, state: State<'_, AppState>) -> Vec<Option<unforge_report::code::InsnText>> {
    match state.0.lock() {
        Ok(o) => unforge_report::code::disasm_at(&o.bytes, &addrs),
        Err(_) => vec![None; addrs.len()],
    }
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .manage(DecompState::default())
        .setup(|app| {
            let dir = app.path().app_data_dir().map(|d| d.join("signatures")).unwrap_or_default();
            let _ = std::fs::create_dir_all(&dir);
            app.manage(SigState(Mutex::new(sigs::Signatures::load(dir))));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            open_file,
            open_self,
            read_range,
            code_map,
            disasm_at,
            decompile,
            cancel_decompile,
            signatures,
            import_signatures,
            add_to_signatures,
            current_path
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| eprintln!("mekiki: {e}"));
}

//! The Tauri side of Mekiki: opens a file, runs the unforge report on it in
//! this process, and serves byte ranges of it to the Listing.

mod decomp;

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
    bytes: Vec<u8>,
}

#[derive(Default)]
struct AppState(Mutex<Opened>);

#[derive(Default)]
struct DecompState {
    decompiler: Arc<Mutex<decomp::Decompiler>>,
    killer: decomp::Killer,
}

/// Reads the file at `path`, keeps its bytes for `read_range`, and returns
/// the report JSON (see `unforge_report::Report`), plus the file name.
#[tauri::command]
fn open_file(path: PathBuf, state: State<'_, AppState>, dstate: State<'_, DecompState>) -> Result<serde_json::Value, String> {
    let meta = std::fs::metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a file", path.display()));
    }
    if meta.len() > MAX_FILE {
        return Err(format!("{} is larger than 2 GB", path.display()));
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let started = std::time::Instant::now();
    let json = unforge_report::report_json(&bytes);
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let report: serde_json::Value = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if let Ok(mut opened) = state.0.lock() {
        opened.bytes = bytes;
    }
    dstate.killer.kill();
    if let Ok(mut d) = dstate.decompiler.lock() {
        d.reset(decomp::Target {
            path: path.clone(),
            language: decomp::language(&report),
            setup: decomp::setup_lines(&report),
        });
    }
    Ok(serde_json::json!({
        "name": name,
        "path": path.display().to_string(),
        "elapsed_ms": elapsed_ms,
        "report": report,
    }))
}

/// Opens Mekiki's own executable: a real Rust binary to practice on in the
/// tutorial, with nothing to download.
#[tauri::command]
fn open_self(state: State<'_, AppState>, dstate: State<'_, DecompState>) -> Result<serde_json::Value, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    open_file(exe, state, dstate)
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

/// C-like code of the function at `addr`, from Ghidra's decompiler.
#[tauri::command]
async fn decompile(addr: u64, app: AppHandle) -> Result<decomp::Decompiled, String> {
    let specs = specs_path(&app);
    let (decompiler, killer) = {
        let s = app.state::<DecompState>();
        (s.decompiler.clone(), s.killer.clone())
    };
    tauri::async_runtime::spawn_blocking(move || {
        let mut d = decompiler.lock().map_err(|_| "busy".to_owned())?;
        d.decompile(addr, &helper_path(), &specs, &killer)
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
        Ok(o) => Response::new(unforge_report::code::code_map(&o.bytes)),
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
        .invoke_handler(tauri::generate_handler![open_file, open_self, read_range, code_map, disasm_at, decompile, cancel_decompile])
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| eprintln!("mekiki: {e}"));
}

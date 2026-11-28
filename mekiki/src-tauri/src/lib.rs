//! The Tauri side of Mekiki: opens a file, runs the unforge report on it in
//! this process, and serves byte ranges of it to the Listing.

use std::path::PathBuf;
use std::sync::Mutex;

use tauri::ipc::Response;
use tauri::State;

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

/// Reads the file at `path`, keeps its bytes for `read_range`, and returns
/// the report JSON (see `unforge_report::Report`), plus the file name.
#[tauri::command]
fn open_file(path: PathBuf, state: State<'_, AppState>) -> Result<serde_json::Value, String> {
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
    Ok(serde_json::json!({
        "name": name,
        "path": path.display().to_string(),
        "elapsed_ms": elapsed_ms,
        "report": report,
    }))
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

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![open_file, read_range])
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| eprintln!("mekiki: {e}"));
}

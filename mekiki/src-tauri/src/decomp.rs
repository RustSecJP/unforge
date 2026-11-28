//! Runs the decompiler helper (`mekiki-decomp`, Ghidra's C++ decompiler
//! without Java) as a separate process and talks to it over stdin/stdout.
//!
//! The helper is started lazily, on the first decompile of an opened file,
//! and kept for the next requests. A request that takes too long, or that
//! the UI cancels (the user moved on), kills the process; the next request
//! starts a fresh one. A crash in the helper therefore never takes Mekiki
//! down with it.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A request is killed after this long.
pub const TIMEOUT: Duration = Duration::from_secs(60);
/// The helper is restarted after this many requests, to give back memory.
const MAX_REQUESTS: u32 = 200;
/// Output lines longer than this are cut (hostile names).
const MAX_LINE: usize = 64 * 1024;

/// What the helper needs to know about the open file.
#[derive(Clone, Default)]
pub struct Target {
    pub path: PathBuf,
    /// Ghidra language id, e.g. `x86:LE:64:default:gcc`; None = unsupported
    pub language: Option<String>,
    /// `seg` and `sym` command lines, sent once when the helper starts
    pub setup: String,
}

struct Running {
    child: Arc<Mutex<Child>>,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    requests: u32,
}

#[derive(Default)]
pub struct Decompiler {
    target: Option<Target>,
    running: Option<Running>,
}

#[derive(serde::Serialize)]
pub struct Decompiled {
    pub code: String,
    /// Time the decompiler itself took, in ms
    pub ms: u64,
    /// Including starting the helper, in ms
    pub total_ms: u64,
}

/// The process of the request in flight, so another thread can kill it.
#[derive(Default, Clone)]
pub struct Killer(Arc<Mutex<Option<Arc<Mutex<Child>>>>>);

impl Killer {
    pub fn kill(&self) -> bool {
        let Ok(slot) = self.0.lock() else { return false };
        match slot.as_ref().and_then(|c| c.lock().ok()) {
            Some(mut c) => c.kill().is_ok(),
            None => false,
        }
    }
    fn set(&self, c: Option<Arc<Mutex<Child>>>) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = c;
        }
    }
}

impl Decompiler {
    /// A new file was opened: forget the old helper.
    pub fn reset(&mut self, target: Target) {
        self.stop();
        self.target = Some(target);
    }

    fn stop(&mut self) {
        if let Some(r) = self.running.take() {
            if let Ok(mut c) = r.child.lock() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    pub fn decompile(&mut self, addr: u64, helper: &Path, specs: &Path, killer: &Killer) -> Result<Decompiled, String> {
        let started = Instant::now();
        let target = self.target.clone().ok_or("No file is open.")?;
        let language = target
            .language
            .clone()
            .ok_or("Decompiling is only available for x86 and x86-64 files for now.")?;
        if self.running.as_ref().is_some_and(|r| r.requests >= MAX_REQUESTS) {
            self.stop();
        }
        if self.running.is_none() {
            self.running = Some(start(helper, specs, &target.path, &language, &target.setup)?);
        }
        let r = self.running.as_mut().ok_or("The decompiler did not start.")?;
        r.requests += 1;
        killer.set(Some(r.child.clone()));
        // Watchdog: kill the helper if this request runs too long.
        let done = Arc::new(Mutex::new(false));
        {
            let done = done.clone();
            let child = r.child.clone();
            std::thread::spawn(move || {
                std::thread::sleep(TIMEOUT);
                if done.lock().is_ok_and(|d| !*d) {
                    if let Ok(mut c) = child.lock() {
                        let _ = c.kill();
                    }
                }
            });
        }
        let result = request(r, addr);
        if let Ok(mut d) = done.lock() {
            *d = true;
        }
        killer.set(None);
        match result {
            Ok((code, ms)) => Ok(Decompiled { code, ms, total_ms: started.elapsed().as_millis() as u64 }),
            Err(e) => {
                let timed_out = started.elapsed() >= TIMEOUT;
                self.stop();
                Err(if timed_out {
                    format!("Stopped after {} s: this function is too large or too complex to decompile.", TIMEOUT.as_secs())
                } else {
                    e
                })
            }
        }
    }
}

fn start(helper: &Path, specs: &Path, file: &Path, language: &str, setup: &str) -> Result<Running, String> {
    let mut child = Command::new(helper)
        .arg(specs)
        .arg(file)
        .arg(language)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Could not start the decompiler ({}): {e}", helper.display()))?;
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout = BufReader::new(child.stdout.take().ok_or("no stdout")?);
    stdin.write_all(setup.as_bytes()).map_err(|e| e.to_string())?;
    Ok(Running { child: Arc::new(Mutex::new(child)), stdin, stdout, requests: 0 })
}

fn request(r: &mut Running, addr: u64) -> Result<(String, u64), String> {
    writeln!(r.stdin, "decompile {addr:x}").map_err(|_| "The decompiler stopped.".to_owned())?;
    r.stdin.flush().map_err(|_| "The decompiler stopped.".to_owned())?;
    let mut code = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        let n = r.stdout.read_line(&mut line).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("Cancelled.".to_owned());
        }
        if let Some(rest) = line.strip_prefix("@@END ") {
            let ms = rest.trim().trim_end_matches("ms").parse().unwrap_or(0);
            return Ok((code, ms));
        }
        if let Some(rest) = line.strip_prefix("@@ERROR ") {
            return Err(format!("The decompiler could not handle this function: {}", rest.trim()));
        }
        if line.len() > MAX_LINE {
            line.truncate(MAX_LINE);
            line.push('\n');
        }
        code.push_str(&line);
    }
}

/// The setup lines for a report: PT_LOAD mappings and every function name.
pub fn setup_lines(report: &serde_json::Value) -> String {
    let mut out = String::new();
    for s in report["segments"].as_array().into_iter().flatten() {
        if s["kind"] != "LOAD" {
            continue;
        }
        let n = |k: &str| s[k].as_u64().unwrap_or(0);
        out.push_str(&format!(
            "seg {:x} {:x} {:x} {}\n",
            n("vaddr"),
            n("offset"),
            n("filesz"),
            s["flags"].as_str().unwrap_or("R").replace('-', "")
        ));
    }
    for f in report["function_rows"].as_array().into_iter().flatten() {
        if let (Some(start), Some(name)) = (f["start"].as_u64(), f["name"].as_str()) {
            let name: String = name.chars().filter(|c| !c.is_control()).take(1024).collect();
            if !name.is_empty() {
                out.push_str(&format!("sym {start:x} {name}\n"));
            }
        }
    }
    out
}

/// Ghidra's language id for a report's file, if we can decompile it.
pub fn language(report: &serde_json::Value) -> Option<String> {
    let file = &report["file"];
    match (file["machine"].as_str()?, file["class"].as_str()?) {
        ("x86-64", _) => Some("x86:LE:64:default:gcc".to_owned()),
        ("x86", "ELF32") => Some("x86:LE:32:default:gcc".to_owned()),
        _ => None,
    }
}

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
/// ... or once it holds more than this much memory (KB). Ghidra keeps what
/// a large function needed even after the function is done.
const MAX_RSS_KB: u64 = 1_500_000;
/// Output lines longer than this are cut (hostile names).
const MAX_LINE: usize = 64 * 1024;

/// What the helper needs to know about the open file.
#[derive(Clone, Default)]
pub struct Target {
    pub path: PathBuf,
    /// The file's bytes, to explain constants in the output
    pub data: Arc<Vec<u8>>,
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
    /// Resident memory the helper last reported (KB)
    rss_kb: u64,
    /// Output language the helper is set to (`rust` or `c`)
    lang: &'static str,
}

/// The output languages the helper can write.
pub fn lang_name(lang: &str) -> &'static str {
    if lang == "c" { "c" } else { "rust" }
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

    pub fn decompile(&mut self, addr: u64, lang: &str, helper: &Path, specs: &Path, killer: &Killer) -> Result<Decompiled, String> {
        let started = Instant::now();
        let target = self.target.clone().ok_or("No file is open.")?;
        let language = target
            .language
            .clone()
            .ok_or("Decompiling is only available for x86 and x86-64 files for now.")?;
        if self.running.as_ref().is_some_and(|r| r.requests >= MAX_REQUESTS || r.rss_kb > MAX_RSS_KB) {
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
        let result = request(r, addr, lang_name(lang));
        if let Ok(mut d) = done.lock() {
            *d = true;
        }
        killer.set(None);
        match result {
            Ok((code, ms)) => Ok(Decompiled {
                code: unforge_report::code::annotate(&target.data, &code),
                ms,
                total_ms: started.elapsed().as_millis() as u64,
            }),
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
    Ok(Running { child: Arc::new(Mutex::new(child)), stdin, stdout, requests: 0, rss_kb: 0, lang: "rust" })
}

fn request(r: &mut Running, addr: u64, lang: &'static str) -> Result<(String, u64), String> {
    if r.lang != lang {
        writeln!(r.stdin, "lang {lang}").map_err(|_| "The decompiler stopped.".to_owned())?;
        r.lang = lang;
    }
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
            // "@@END <ms>ms <rss>kb"
            let mut parts = rest.split_whitespace();
            let ms = parts.next().and_then(|p| p.trim_end_matches("ms").parse().ok()).unwrap_or(0);
            r.rss_kb = parts.next().and_then(|p| p.trim_end_matches("kb").parse().ok()).unwrap_or(0);
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

/// What the helper needs for a file (see `unforge_report::setup`).
pub fn target(path: PathBuf, data: Arc<Vec<u8>>) -> Target {
    let (language, setup) = match unforge_report::setup::decompiler_setup(&data) {
        Some((lang, lines)) => (Some(lang.to_owned()), lines),
        None => (None, String::new()),
    };
    Target { path, data, language, setup }
}

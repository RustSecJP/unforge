//! Oracle probe: start one file with `execve` and classify what happened.
//!
//! Built as a static musl program for the container's architecture by
//! `../run_oracle.sh` and run inside a locked-down container:
//!
//! ```text
//! probe <target> [timeout-ms]
//! ```
//!
//! It prints `key=value` lines on stdout (see `main`). The verdict vocabulary
//! is documented in `../README.md`. In short:
//!
//! - `exec_rejected:<ERRNO>`: `spawn()` failed, so `execve` returned an error.
//!   That happens only before the point of no return (`begin_new_exec`,
//!   `fs/binfmt_elf.c:load_elf_binary`, Linux v7.0.12), i.e. the loader
//!   refused the file.
//! - `ran`: exit status 42 and the seed marker on stdout.
//! - `loaded_then_exit:<code>`, `loaded_then_signal:<SIG>`: the file was
//!   loaded and user code ended some other way.
//! - `ldso_rejected`: exit 127 with a dynamic-loader message on stderr.
//! - `ambiguous:<SIG>`: killed by SIGSEGV or SIGKILL without printing the
//!   marker. After the point of no return the kernel cannot return an errno;
//!   `fs/exec.c:bprm_execve` (v7.0.12, lines 1768-1769) calls
//!   `force_fatal_sig(SIGSEGV)` unless a fatal signal is already pending. Such
//!   a kill is indistinguishable, from outside, from a SIGSEGV raised by the
//!   first user instruction, so the probe does not decide.
//! - `timeout`: still running after the timeout; it was killed.
//!
//! The probe deliberately uses `std::process::Command` with an absolute path:
//! no `PATH` search and no shell, so an `ENOEXEC` is reported as an error
//! instead of being retried as a shell script (POSIX `execvp` behaviour).

use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Printed by every seed and every hand-made file (see `../seeds/marker.rs`).
const MARKER: &[u8] = b"UNFORGE_OK\n";
/// Exit status of every seed and every hand-made file.
const EXPECTED_EXIT: i32 = 42;
/// Captured output is cut at this many bytes per stream.
const CAPTURE_LIMIT: usize = 64 * 1024;

fn errno_name(e: i32) -> &'static str {
    // Linux generic errno values (include/uapi/asm-generic/errno-base.h and
    // errno.h); identical on aarch64 and x86_64.
    match e {
        1 => "EPERM",
        2 => "ENOENT",
        5 => "EIO",
        7 => "E2BIG",
        8 => "ENOEXEC",
        12 => "ENOMEM",
        13 => "EACCES",
        14 => "EFAULT",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        26 => "ETXTBSY",
        36 => "ENAMETOOLONG",
        40 => "ELOOP",
        79 => "ELIBACC",
        80 => "ELIBBAD",
        _ => "E?",
    }
}

fn signal_name(s: i32) -> &'static str {
    // Signal numbers shared by aarch64 and x86_64 Linux.
    match s {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        31 => "SIGSYS",
        _ => "SIG?",
    }
}

/// Make arbitrary bytes safe for one TSV field.
fn escape(bytes: &[u8], max: usize) -> String {
    let mut s = String::new();
    for &b in bytes.iter().take(max) {
        match b {
            b'\n' => s.push_str("\\n"),
            b'\t' => s.push_str("\\t"),
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7e => s.push(char::from(b)),
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    if bytes.len() > max {
        s.push_str("...");
    }
    s
}

fn read_capped(mut r: impl Read) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if out.len() < CAPTURE_LIMIT {
                    let room = CAPTURE_LIMIT - out.len();
                    out.extend_from_slice(&buf[..n.min(room)]);
                }
            }
        }
    }
    out
}

/// What the probe itself runs under. In a foreign-architecture container the
/// probe is emulated too; Rosetta shows up in `/proc/self/maps`, qemu-user
/// usually hides itself.
fn emulator_hint() -> String {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    if maps.contains("/rosetta") {
        "rosetta".to_string()
    } else if maps.contains("qemu") {
        "qemu".to_string()
    } else {
        "none-visible".to_string()
    }
}

/// glibc and musl dynamic-loader failure messages (exit status 127).
fn looks_like_ldso(stderr: &[u8]) -> bool {
    let s = String::from_utf8_lossy(stderr);
    [
        "error while loading shared libraries",
        "Inconsistency detected by ld.so",
        "ld-linux",
        "ld.so",
        "Error relocating",
        "Error loading shared library",
    ]
    .iter()
    .any(|p| s.contains(p))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let Some(target) = args.get(1) else {
        println!("verdict=probe_error");
        println!("detail=usage: probe <target> [timeout-ms]");
        std::process::exit(2);
    };
    let timeout = Duration::from_millis(args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3000));

    println!("emulator_hint={}", emulator_hint());
    println!(
        "osrelease={}",
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim()
    );

    let spawned = Command::new(target)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            let code = e.raw_os_error().unwrap_or(-1);
            println!("verdict=exec_rejected:{}", errno_name(code));
            println!(
                "detail=errno={code} {}",
                escape(e.to_string().as_bytes(), 200)
            );
            return;
        }
    };

    let out_reader = child
        .stdout
        .take()
        .map(|s| std::thread::spawn(move || read_capped(s)));
    let err_reader = child
        .stderr
        .take()
        .map(|s| std::thread::spawn(move || read_capped(s)));

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => break None,
        }
    };
    let stdout = out_reader.and_then(|h| h.join().ok()).unwrap_or_default();
    let stderr = err_reader.and_then(|h| h.join().ok()).unwrap_or_default();
    let marker = stdout.windows(MARKER.len()).any(|w| w == MARKER);

    let (verdict, why) = match status {
        None => ("timeout".to_string(), String::new()),
        Some(st) => {
            if let Some(sig) = st.signal() {
                let name = signal_name(sig);
                if marker {
                    (
                        format!("loaded_then_signal:{name}"),
                        "marker seen".to_string(),
                    )
                } else if sig == 11 || sig == 9 {
                    (
                        format!("ambiguous:{name}"),
                        "no marker: a post-point-of-no-return kill and a fault before the marker look the same"
                            .to_string(),
                    )
                } else {
                    (
                        format!("loaded_then_signal:{name}"),
                        "not SIGSEGV/SIGKILL, so not the exec abort path".to_string(),
                    )
                }
            } else {
                let code = st.code().unwrap_or(-1);
                if code == EXPECTED_EXIT && marker {
                    ("ran".to_string(), String::new())
                } else if code == 127 && looks_like_ldso(&stderr) {
                    ("ldso_rejected".to_string(), String::new())
                } else {
                    (
                        format!("loaded_then_exit:{code}"),
                        if marker { "marker seen" } else { "no marker" }.to_string(),
                    )
                }
            }
        }
    };
    println!("verdict={verdict}");
    println!(
        "detail={why}{}stdout={} stderr={}",
        if why.is_empty() { "" } else { "; " },
        escape(&stdout, 60),
        escape(&stderr, 160)
    );
}

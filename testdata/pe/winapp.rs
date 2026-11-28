//! A small Windows program with what Rust malware tends to have: a TLS
//! callback (runs before `main`, often used for anti-debugging), file and
//! environment access through std (so `CreateFileW` and friends are
//! imported), a dependency crate (`fakedep`) and panics with locations.
//!
//! The program is never run by the tests; it is only read.

use std::hint::black_box;

/// Called by the loader for every process and thread attach / detach.
extern "system" fn on_tls(_module: *mut u8, reason: u32, _reserved: *mut u8) {
    black_box(reason);
}

#[link_section = ".CRT$XLB"]
#[used]
static TLS_CALLBACK: extern "system" fn(*mut u8, u32, *mut u8) = on_tls;

#[inline(never)]
fn read_config(path: &str) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}

#[inline(never)]
fn checksum(data: &[u8]) -> u32 {
    data.iter()
        .fold(0x811c_9dc5u32, |h, &b| (h ^ u32::from(b)).wrapping_mul(0x0100_0193))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).map(String::as_str).unwrap_or("config.txt");
    let text = read_config(path).unwrap_or_default();
    let counts = fakedep::word_counts(black_box("hello hello world"));
    let v: Vec<u32> = counts.values().map(|&c| c as u32).collect();
    println!(
        "{} {:08x} {}",
        text.len(),
        checksum(text.as_bytes()),
        fakedep::nth(&v, args.len() - 1)
    );
    if args.len() > 3 {
        panic!("too many arguments: {}", args.len());
    }
}

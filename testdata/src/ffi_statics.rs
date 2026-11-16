//! C-ABI exports, statics and thread-locals.
//!
//! Compiled with --edition 2021 on purpose: in edition 2024 `no_mangle` must
//! be written as an unsafe attribute, and this project avoids the `unsafe`
//! keyword everywhere (including test data).
//!
//! Ground truth: `unforge_add` and `UNFORGE_COUNTER` keep their unmangled names
//! in the symbol table. `PER_THREAD` lives in a TLS segment (PT_TLS / STT_TLS)
//! when the target supports native TLS (x86_64 Linux does).

use std::cell::Cell;
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};

#[no_mangle]
pub static UNFORGE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[no_mangle]
pub static UNFORGE_TABLE: [u32; 8] = [1, 1, 2, 3, 5, 8, 13, 21];

/// Ends up in `.rodata` (or is folded away): no `no_mangle`.
static GREETING: &str = "statics and thread locals";

thread_local! {
    static PER_THREAD: Cell<u64> = const { Cell::new(100) };
    static NAME: std::cell::RefCell<String> = std::cell::RefCell::new(String::from("main"));
}

#[no_mangle]
pub extern "C" fn unforge_add(a: u64, b: u64) -> u64 {
    UNFORGE_COUNTER.fetch_add(1, Ordering::Relaxed);
    a.wrapping_add(b)
}

#[no_mangle]
pub extern "C" fn unforge_fib(i: u32) -> u32 {
    UNFORGE_TABLE.get(i as usize).copied().unwrap_or(0)
}

#[inline(never)]
fn bump() -> u64 {
    PER_THREAD.with(|c| {
        c.set(c.get() + 1);
        c.get()
    })
}

fn main() {
    println!("{GREETING}");
    let x = unforge_add(black_box(40), black_box(2));
    println!("add={x} fib(6)={}", unforge_fib(black_box(6)));
    let h = std::thread::spawn(|| {
        NAME.with(|n| n.borrow_mut().push_str("-child"));
        (bump(), NAME.with(|n| n.borrow().clone()))
    });
    let child = h.join().unwrap_or((0, String::new()));
    println!("main bump={} child={child:?}", bump());
    println!("calls={}", UNFORGE_COUNTER.load(Ordering::Relaxed));
}

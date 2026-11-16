//! A cdylib-style library: a C ABI surface over Rust internals.
//!
//! Compiled with --edition 2021 (see ffi_statics.rs for why). Built as
//! `--crate-type cdylib` where linking works and as an object file otherwise.
//! Ground truth: exactly the `#[no_mangle] extern "C"` functions below are
//! exported in `.dynsym` of the cdylib; the generic helper is internal.

use std::sync::atomic::{AtomicUsize, Ordering};

static CALLS: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Status {
    Ok = 0,
    Negative = 1,
    TooBig = 2,
}

fn clamp_generic<T: PartialOrd>(x: T, lo: T, hi: T) -> T {
    if x < lo {
        lo
    } else if x > hi {
        hi
    } else {
        x
    }
}

#[no_mangle]
pub extern "C" fn clib_manhattan(a: Point, b: Point) -> i64 {
    CALLS.fetch_add(1, Ordering::Relaxed);
    (i64::from(a.x) - i64::from(b.x)).abs() + (i64::from(a.y) - i64::from(b.y)).abs()
}

#[no_mangle]
pub extern "C" fn clib_classify(x: i64) -> Status {
    CALLS.fetch_add(1, Ordering::Relaxed);
    if x < 0 {
        Status::Negative
    } else if x > 1000 {
        Status::TooBig
    } else {
        Status::Ok
    }
}

#[no_mangle]
pub extern "C" fn clib_clamp_i32(x: i32, lo: i32, hi: i32) -> i32 {
    clamp_generic(x, lo, hi)
}

#[no_mangle]
pub extern "C" fn clib_clamp_f64(x: f64, lo: f64, hi: f64) -> f64 {
    clamp_generic(x, lo, hi)
}

/// Sum a C array given as an optional pointer + length, without `unsafe`:
/// the caller passes a Rust slice via `Option<&[u32; 4]>` (FFI-safe because of
/// the null-pointer optimisation guaranteed for `Option<&T>`).
#[no_mangle]
pub extern "C" fn clib_sum4(v: Option<&[u32; 4]>) -> u64 {
    CALLS.fetch_add(1, Ordering::Relaxed);
    v.map_or(0, |a| a.iter().map(|&x| u64::from(x)).sum())
}

#[no_mangle]
pub extern "C" fn clib_calls() -> usize {
    CALLS.load(Ordering::Relaxed)
}

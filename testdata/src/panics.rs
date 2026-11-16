//! Panic paths: explicit panic!, unwrap/expect, bounds checks, arithmetic
//! overflow checks (only emitted with -C overflow-checks, which is on by
//! default at opt-level 0 / debug-assertions), division by zero, slicing.
//!
//! The program chooses which path to take from argv so that the binary
//! contains all of them but exits 0 when run without arguments.

use std::hint::black_box;

#[inline(never)]
fn get(v: &[i32], i: usize) -> i32 {
    v[i]
}

#[inline(never)]
fn slice(v: &[i32], a: usize, b: usize) -> &[i32] {
    &v[a..b]
}

#[inline(never)]
fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[inline(never)]
fn div(a: i32, b: i32) -> i32 {
    a / b
}

#[inline(never)]
fn must(x: Option<i32>) -> i32 {
    x.expect("value must be present")
}

#[inline(never)]
fn checked(r: Result<i32, String>) -> i32 {
    r.unwrap()
}

#[inline(never)]
fn explicit(code: u8) -> ! {
    panic!("explicit panic with code {code}")
}

#[inline(never)]
fn unreachable_branch(x: u8) -> u8 {
    match x {
        0..=9 => x,
        _ => unreachable!("x was {x}"),
    }
}

fn main() {
    let v = black_box(vec![1, 2, 3]);
    let which = std::env::args().nth(1).unwrap_or_default();
    let r = match which.as_str() {
        "index" => get(&v, 10),
        "slice" => slice(&v, 2, 1).len() as i32,
        "overflow" => add(i32::MAX, black_box(1)),
        "div" => div(1, black_box(0)),
        "expect" => must(black_box(None)),
        "unwrap" => checked(black_box(Err("bad".into()))),
        "panic" => explicit(7),
        "unreachable" => i32::from(unreachable_branch(black_box(42))),
        _ => {
            get(&v, 0)
                + slice(&v, 0, 2).len() as i32
                + add(1, 2)
                + div(6, 3)
                + must(Some(1))
                + checked(Ok(1))
                + i32::from(unreachable_branch(3))
        }
    };
    println!("result {r}");
}

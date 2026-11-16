//! String / Vec / iterator shapes.
//!
//! Ground truth for later stages: `String` and `Vec<T>` are (ptr, cap, len)
//! triples in memory, but the *order* of those fields is NOT guaranteed by the
//! language (Rust Reference, "Type layout": default `repr(Rust)` layout is
//! unspecified). Stage 5 must check the actual order per rustc version.

use std::hint::black_box;

#[inline(never)]
fn make_greeting(name: &str, times: usize) -> String {
    let mut s = String::with_capacity(16);
    for i in 0..times {
        if i > 0 {
            s.push_str(", ");
        }
        s.push_str("hello ");
        s.push_str(name);
    }
    s
}

#[inline(never)]
fn squares(n: u32) -> Vec<u64> {
    (0..n).map(|x| u64::from(x) * u64::from(x)).collect()
}

#[inline(never)]
fn sum_even(v: &[u64]) -> u64 {
    // An iterator chain that LLVM will usually inline and vectorize at -O3.
    v.iter().copied().filter(|x| x % 2 == 0).sum()
}

#[inline(never)]
fn index_checked(v: &[u64], i: usize) -> u64 {
    // A plain index: emits a bounds check that branches to
    // core::panicking::panic_bounds_check.
    v[i]
}

#[inline(never)]
fn words(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_uppercase).collect()
}

#[inline(never)]
fn nested() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for i in 0..4u8 {
        out.push(vec![i; usize::from(i) + 1]);
    }
    out
}

fn main() {
    let g = make_greeting(black_box("world"), black_box(3));
    println!("{g} ({} bytes)", g.len());

    let sq = squares(black_box(10));
    println!("squares={sq:?} sum_even={}", sum_even(&sq));
    println!("sq[3]={}", index_checked(&sq, black_box(3)));

    let w = words(black_box("the quick brown fox"));
    println!("{w:?}");

    let n = nested();
    let total: usize = n.iter().map(Vec::len).sum();
    println!("nested lens total={total}");

    let mut sorted = black_box(vec![5i32, -1, 3, 9, 0]);
    sorted.sort_unstable();
    let joined: Vec<String> = sorted.iter().map(i32::to_string).collect();
    println!("{}", joined.join("-"));
}

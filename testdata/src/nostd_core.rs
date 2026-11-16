//! A `#![no_std]` library compiled to an object file. Only needs `core`, so it
//! builds for any target whose `core` is installed (used for big-endian and
//! other non-x86 objects). Compiled with --edition 2021 for `no_mangle`.

#![no_std]

#[derive(Clone, Copy)]
pub enum Op {
    Add(u32),
    Mul(u32),
    Neg,
}

#[no_mangle]
pub static NOSTD_MAGIC: u64 = 0x0102_0304_0506_0708;

#[inline(never)]
fn apply(acc: i64, op: Op) -> i64 {
    match op {
        Op::Add(x) => acc.wrapping_add(i64::from(x)),
        Op::Mul(x) => acc.wrapping_mul(i64::from(x)),
        Op::Neg => acc.wrapping_neg(),
    }
}

#[no_mangle]
pub extern "C" fn nostd_eval(seed: i64, n: u32) -> i64 {
    let ops = [Op::Add(3), Op::Mul(7), Op::Neg, Op::Add(n)];
    ops.iter().fold(seed, |acc, &op| apply(acc, op))
}

#[no_mangle]
pub extern "C" fn nostd_checksum(data: Option<&[u8; 16]>) -> u32 {
    let Some(d) = data else { return 0 };
    d.iter()
        .enumerate()
        .fold(0u32, |h, (i, &b)| h.rotate_left(5) ^ (u32::from(b) + i as u32))
}

pub fn generic_max<T: Ord + Copy>(a: T, b: T) -> T {
    if a > b { a } else { b }
}

#[no_mangle]
pub extern "C" fn nostd_max_u16(a: u16, b: u16) -> u16 {
    generic_max(a, b)
}

#[no_mangle]
pub extern "C" fn nostd_max_i64(a: i64, b: i64) -> i64 {
    generic_max(a, b)
}

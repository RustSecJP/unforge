//! Option / Result / data-carrying enums.
//!
//! Ground truth for later stages. What IS guaranteed: `Option<&T>`,
//! `Option<Box<T>>`, `Option<NonZero*>` etc. have the same size as the inner
//! type with `None` represented as all-zero (Rust std docs, "Representation" in
//! `core::option`). Everything else here (tag position, tag width, which niche
//! rustc picks for `Shape` or `Result<u32, Error>`) is NOT guaranteed and may
//! change between rustc versions.

use std::hint::black_box;
use std::num::NonZeroU32;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Shape {
    Circle { r: f64 },
    Rect { w: f64, h: f64 },
    Triangle(f64, f64, f64),
    Empty,
}

#[derive(Debug)]
pub enum ParseError {
    Empty,
    BadDigit(char),
    Overflow { at: usize },
}

#[inline(never)]
fn area(s: &Shape) -> f64 {
    match *s {
        Shape::Circle { r } => std::f64::consts::PI * r * r,
        Shape::Rect { w, h } => w * h,
        Shape::Triangle(a, b, c) => {
            let p = (a + b + c) / 2.0;
            (p * (p - a) * (p - b) * (p - c)).sqrt()
        }
        Shape::Empty => 0.0,
    }
}

#[inline(never)]
fn parse_u32(s: &str) -> Result<u32, ParseError> {
    if s.is_empty() {
        return Err(ParseError::Empty);
    }
    let mut n: u32 = 0;
    for (i, c) in s.chars().enumerate() {
        let d = c.to_digit(10).ok_or(ParseError::BadDigit(c))?;
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(d))
            .ok_or(ParseError::Overflow { at: i })?;
    }
    Ok(n)
}

#[inline(never)]
fn first_even(v: &[u32]) -> Option<&u32> {
    v.iter().find(|x| *x % 2 == 0)
}

#[inline(never)]
fn nonzero(x: u32) -> Option<NonZeroU32> {
    NonZeroU32::new(x)
}

#[inline(never)]
fn boxed(x: Option<u8>) -> Option<Box<u64>> {
    x.map(|b| Box::new(u64::from(b) << 32))
}

#[inline(never)]
fn chain(s: &str) -> Result<u64, String> {
    let a = parse_u32(s).map_err(|e| format!("{e:?}"))?;
    Ok(u64::from(a) * 2)
}

fn main() {
    let shapes = black_box([
        Shape::Circle { r: 1.0 },
        Shape::Rect { w: 2.0, h: 3.0 },
        Shape::Triangle(3.0, 4.0, 5.0),
        Shape::Empty,
    ]);
    for s in &shapes {
        println!("{s:?} area={:.3}", area(s));
    }
    for input in ["123", "", "12x", "99999999999"] {
        println!("{input:?} -> {:?}", parse_u32(black_box(input)));
    }
    println!("{:?}", first_even(black_box(&[1, 3, 8, 5])));
    println!("{:?} {:?}", nonzero(black_box(0)), nonzero(black_box(7)));
    println!("{:?} {:?}", boxed(black_box(None)), boxed(black_box(Some(1))));
    println!("{:?} {:?}", chain(black_box("21")), chain(black_box("x")));
    println!(
        "sizes: Shape={} Option<Shape>={} Result<u32,ParseError>={} Option<NonZeroU32>={}",
        size_of::<Shape>(),
        size_of::<Option<Shape>>(),
        size_of::<Result<u32, ParseError>>(),
        size_of::<Option<NonZeroU32>>()
    );
}

//! Trait objects (vtables) and generics monomorphized several times.
//!
//! Ground truth for later stages: `describe::<T>` is instantiated for four
//! types, so the binary contains four copies with different mangled hashes.
//! The vtable layout (drop_in_place, size, align, then methods) is a rustc
//! implementation detail, NOT a language guarantee (see rustc
//! `compiler/rustc_middle/src/ty/vtable.rs`, `COMMON_VTABLE_ENTRIES`).

use std::fmt::Debug;
use std::hint::black_box;

pub trait Animal {
    fn name(&self) -> &str;
    fn legs(&self) -> u32;
    fn speak(&self) -> String {
        format!("{} makes a sound", self.name())
    }
}

pub struct Dog {
    name: String,
}

pub struct Bird {
    wingspan_cm: u16,
}

pub struct Spider;

impl Animal for Dog {
    fn name(&self) -> &str {
        &self.name
    }
    fn legs(&self) -> u32 {
        4
    }
    fn speak(&self) -> String {
        format!("{} says woof", self.name)
    }
}

impl Animal for Bird {
    fn name(&self) -> &str {
        "bird"
    }
    fn legs(&self) -> u32 {
        2
    }
}

impl Animal for Spider {
    fn name(&self) -> &str {
        "spider"
    }
    fn legs(&self) -> u32 {
        8
    }
}

impl Drop for Dog {
    fn drop(&mut self) {
        println!("drop dog {}", self.name);
    }
}

#[inline(never)]
fn total_legs(zoo: &[Box<dyn Animal>]) -> u32 {
    zoo.iter().map(|a| a.legs()).sum()
}

#[inline(never)]
fn describe<T: Debug>(x: T) -> String {
    format!("<{x:?}>")
}

#[inline(never)]
fn largest<T: PartialOrd + Copy>(v: &[T]) -> Option<T> {
    let mut it = v.iter().copied();
    let mut best = it.next()?;
    for x in it {
        if x > best {
            best = x;
        }
    }
    Some(best)
}

pub struct Stack<T> {
    items: Vec<T>,
}

impl<T: Clone> Stack<T> {
    fn new() -> Self {
        Stack { items: Vec::new() }
    }
    #[inline(never)]
    fn push(&mut self, x: T) {
        self.items.push(x);
    }
    #[inline(never)]
    fn pop(&mut self) -> Option<T> {
        self.items.pop()
    }
}

fn main() {
    let zoo: Vec<Box<dyn Animal>> = vec![
        Box::new(Dog { name: black_box("rex").to_string() }),
        Box::new(Bird { wingspan_cm: black_box(30) }),
        Box::new(Spider),
    ];
    for a in &zoo {
        println!("{} ({} legs)", a.speak(), a.legs());
    }
    println!("total legs {}", total_legs(&zoo));
    if let Some(b) = zoo.get(1) {
        println!("second is {}", b.name());
    }
    let _ = Bird { wingspan_cm: 1 }.wingspan_cm;

    println!("{}", describe(black_box(1u8)));
    println!("{}", describe(black_box(-2i64)));
    println!("{}", describe(black_box("three")));
    println!("{}", describe(black_box(vec![4.0f32])));

    println!("{:?}", largest(black_box(&[3, 9, 2])));
    println!("{:?}", largest(black_box(&[1.5f64, -2.0])));
    println!("{:?}", largest::<char>(black_box(&[])));

    let mut s = Stack::new();
    s.push(black_box(String::from("a")));
    s.push(String::from("b"));
    let mut t = Stack::new();
    t.push(black_box(7u16));
    println!("{:?} {:?} {:?}", s.pop(), t.pop(), t.pop());
}

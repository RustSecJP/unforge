//! A DLL that uses std, like a Rust loader DLL: exported C functions that
//! read a file and the environment and call into `fakedep`.

use std::ffi::{c_char, CStr};

/// Counts the words of the file named by `WINDLL_FILE`, or returns -1.
#[no_mangle]
pub extern "C" fn windll_count_words() -> i64 {
    let name = std::env::var("WINDLL_FILE").unwrap_or_default();
    match std::fs::read_to_string(name) {
        Ok(text) => fakedep::word_counts(&text).values().sum::<usize>() as i64,
        Err(_) => -1,
    }
}

/// The version of this DLL, as a C string.
#[no_mangle]
pub extern "C" fn windll_version() -> *const c_char {
    static VERSION: &CStr = c"windll 0.1";
    VERSION.as_ptr()
}

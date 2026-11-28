//! Entry point of the decompiler helper: hands argv to the C++ driver in
//! `src/mekiki_decomp.cc`, which reads commands from stdin.

use std::ffi::{CString, c_char, c_int};

unsafe extern "C" {
    fn mekiki_decomp_main(argc: c_int, argv: *mut *mut c_char) -> c_int;
}

fn main() {
    let args: Vec<CString> = std::env::args_os()
        .map(|a| CString::new(a.into_encoded_bytes()).unwrap_or_default())
        .collect();
    let mut argv: Vec<*mut c_char> = args.iter().map(|a| a.as_ptr().cast_mut()).collect();
    argv.push(std::ptr::null_mut());
    let argc = c_int::try_from(args.len()).unwrap_or(c_int::MAX);
    // SAFETY: argv holds `argc` valid NUL-terminated strings followed by a
    // null pointer, all alive (in `args`) for the whole call; the C++ side
    // only reads them.
    let code = unsafe { mekiki_decomp_main(argc, argv.as_mut_ptr()) };
    std::process::exit(code);
}

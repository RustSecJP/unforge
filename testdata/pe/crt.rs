//! A stand-in for the few MSVC C runtime objects a Rust program needs at
//! link time, so that `testdata/pe/build.sh` can link real Rust PE files
//! with rust-lld alone (no Visual Studio, no Windows SDK, no MinGW).
//!
//! The files are never run: they only have to look like what MSVC's link
//! produces. This provides:
//!
//! - `mainCRTStartup`, the entry point: calls the `main` that rustc
//!   generates and passes its result to `ExitProcess`; or, built with
//!   `--cfg dll`, `_DllMainCRTStartup`, which only returns TRUE;
//! - `_tls_used` (the TLS directory the linker points `IMAGE_DIRECTORY_ENTRY_TLS`
//!   at), `_tls_index`, and the `.tls` / `.CRT$XL*` bounds around the
//!   thread-local data and the TLS callback array (`tlssup.obj` in the CRT);
//! - `_fltused` and the `type_info` vtable, which the code rustc emits refers to.
//!
//! Everything is written with `global_asm!`, so no `unsafe` is needed.

#![no_std]

#[cfg(all(target_arch = "x86_64", not(dll)))]
core::arch::global_asm!(
    ".section .text,\"xr\"",
    ".globl mainCRTStartup",
    "mainCRTStartup:",
    "sub rsp, 40",
    "xor ecx, ecx",
    "xor edx, edx",
    "call main",
    "mov ecx, eax",
    "call qword ptr [rip + __imp_ExitProcess]",
    "int3",
);

#[cfg(all(target_arch = "x86_64", dll))]
core::arch::global_asm!(
    ".section .text,\"xr\"",
    ".globl _DllMainCRTStartup",
    "_DllMainCRTStartup:",
    "mov eax, 1",
    "ret",
);

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".data",
    ".globl _tls_index",
    "_tls_index:",
    ".long 0",
    ".globl _fltused",
    "_fltused:",
    ".long 0",
    ".section .tls,\"dw\"",
    "_tls_start:",
    ".byte 0",
    ".section .tls$ZZZ,\"dw\"",
    "_tls_end:",
    ".byte 0",
    ".section .CRT$XLA,\"dr\"",
    "__xl_a:",
    ".quad 0",
    ".section .CRT$XLZ,\"dr\"",
    "__xl_z:",
    ".quad 0",
    ".section .rdata$T,\"dr\"",
    ".globl _tls_used",
    "_tls_used:",
    ".quad _tls_start",
    ".quad _tls_end",
    ".quad _tls_index",
    ".quad __xl_a + 8",
    ".long 0",
    ".long 0",
    ".section .rdata,\"dr\"",
    ".globl \"??_7type_info@@6B@\"",
    "\"??_7type_info@@6B@\":",
    ".quad 0",
    ".quad 0",
);

#[cfg(all(target_arch = "x86", not(dll)))]
core::arch::global_asm!(
    ".section .text,\"xr\"",
    ".globl _mainCRTStartup",
    "_mainCRTStartup:",
    "push 0",
    "push 0",
    "call _main",
    "add esp, 8",
    "push eax",
    "call dword ptr [__imp__ExitProcess@4]",
    "int3",
);

#[cfg(all(target_arch = "x86", dll))]
core::arch::global_asm!(
    ".section .text,\"xr\"",
    ".globl __DllMainCRTStartup@12",
    "__DllMainCRTStartup@12:",
    "mov eax, 1",
    "ret 12",
);

#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    ".data",
    ".globl __tls_index",
    "__tls_index:",
    ".long 0",
    ".globl __fltused",
    "__fltused:",
    ".long 0",
    ".section .tls,\"dw\"",
    "__tls_start:",
    ".byte 0",
    ".section .tls$ZZZ,\"dw\"",
    "__tls_end:",
    ".byte 0",
    ".section .CRT$XLA,\"dr\"",
    "___xl_a:",
    ".long 0",
    ".section .CRT$XLZ,\"dr\"",
    "___xl_z:",
    ".long 0",
    ".section .rdata$T,\"dr\"",
    ".globl __tls_used",
    "__tls_used:",
    ".long __tls_start",
    ".long __tls_end",
    ".long __tls_index",
    ".long ___xl_a + 4",
    ".long 0",
    ".long 0",
    ".section .rdata,\"dr\"",
    ".globl \"??_7type_info@@6B@\"",
    "\"??_7type_info@@6B@\":",
    ".long 0",
    ".long 0",
);

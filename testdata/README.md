# testdata: real-binary corpus

`src/` holds small Rust programs whose source is the ground truth for every
roadmap stage (types, functions, panics, vtables, ...). `build.sh` compiles them
into `bin/` in many variants. `bin/` is not committed (see `.gitignore`); every
file in it can be rebuilt, and `bin/MANIFEST.txt` records, for every file, its
sha256 and the exact command that produced it, plus the compiler, linker, CRT
objects and docker image that were used (see "Reproducibility" below).

```sh
testdata/build.sh              # build what is missing / out of date (idempotent)
testdata/build.sh --force      # rebuild everything
testdata/build.sh --no-docker  # skip the glibc/system part
testdata/build.sh --out DIR    # build into DIR instead of bin/
testdata/build.sh --verify     # rebuild from scratch into a temp dir, diff hashes
cargo test -p unforge-elf --test corpus_oracle
```

`corpus_oracle` skips (with a message) when `bin/` does not exist.

## Windows PE files (`pe/`)

`pe/build.sh` builds real Rust PE files into `pe/bin/<target>/` for
`x86_64-pc-windows-msvc` and `i686-pc-windows-msvc` (whichever std is
installed: `rustup target add ...`), with nothing but rustup's own pieces:
rust-lld links the official std rlibs, import libraries are generated with
`llvm-dlltool` (from `rustup component add llvm-tools`, any toolchain) from
the symbols a first link attempt reports missing, and `pe/crt.rs` stands in
for the few MSVC CRT objects (entry point, TLS directory). No Visual Studio,
Windows SDK or MinGW is needed. The files are never run.

| file | what it exercises |
|---|---|
| `winapp-O0.exe`, `winapp-O2.exe` | `pe/winapp.rs`: a TLS callback, file and environment access through std, the dependency `fakedep` (compiled with its source remapped to `C:\Users\dev\.cargo\registry\src\index.crates.io-...\fakedep-1.2.3\`), panics |
| `windll.dll` | `pe/windll.rs`: a `cdylib` with two exported functions that use std |

Each image comes with the linker's `/MAP` file (function addresses and
mangled names: the ground truth, since the names are otherwise only in the
PDB) and the `.pdb`. `cargo test -p unforge-pe --test real_files` and the
PE tests of the other crates skip when `pe/bin/` does not exist (it is not
committed either).

## Programs (`src/`)

| file | what it exercises |
|---|---|
| `collections.rs` | `String`, `Vec`, nested `Vec`, iterator chains, slice indexing (bounds check), sorting |
| `enums.rs` | data-carrying enums, `Option`/`Result`, `?`, `NonZeroU32`, `Option<Box<_>>`, `Option<&T>` |
| `traits.rs` | `dyn Trait` (vtables), default methods, `Drop`, generics monomorphized for several types |
| `panics.rs` | `panic!`, `unwrap`/`expect`, bounds checks, slicing, overflow, division by zero, `unreachable!` (chosen by argv; exits 0 with no args) |
| `ffi_statics.rs` | `#[no_mangle] extern "C"`, `#[no_mangle]` statics, `thread_local!`, a spawned thread |
| `clib.rs` | a cdylib-style C ABI (`repr(C)` struct, `repr(u8)` enum, `Option<&T>` FFI) |
| `nostd_core.rs` | `#![no_std]` library; only needs `core`, so it builds for any installed target |

All programs are compiled with `--edition 2021`: from edition 2024 on,
`#[no_mangle]` must be written as an unsafe attribute, and this project keeps
the `unsafe` keyword out of the tree entirely.

Comments in the sources say which layout facts are guaranteed by the language
and which are rustc implementation details (most of them). Stage 5 must check
the latter against the rustc version recorded in `MANIFEST.txt`.

## Variants (`bin/`)

| directory | kind | variants |
|---|---|---|
| `x86_64-unknown-linux-musl/` | ELF64 LE, `ET_DYN` static-pie (default) and `ET_EXEC` (`-C relocation-model=static`) | opt-level 0/1/3/s × debuginfo 0/2; `-C strip=debuginfo/symbols`; `panic=abort`; `codegen-units=1` + fat/thin LTO |
| `x86_64-unknown-linux-gnu/` | `ET_REL` objects (`--emit=obj`) | opt 0/3 × debuginfo 0/2, `Os`+abort, `clib`, `nostd_core` |
| `i686-unknown-linux-musl/` | ELF32 LE `ET_EXEC` + `ET_REL` | opt 0/3, stripped, `.o` with debuginfo |
| `aarch64-unknown-linux-musl/` | ELF64 LE, `EM_AARCH64` | opt 0, opt 3 stripped |
| `powerpc64-unknown-linux-gnu/`, `s390x-unknown-linux-gnu/` | ELF64 **big-endian** `ET_REL` | opt 0/3 |
| `ext-numbering/` | > 65280 sections (see below) | x86_64, i686 (ELF32), s390x (BE) |
| `glibc/` (docker) | dynamically linked glibc PIE exes, `crt-static` glibc exes, linked `cdylib`s, a Rust `dylib` | built by the docker image's rustc, gcc and GNU ld (versions in `MANIFEST.txt`) |
| `system/` (docker) | real-world files copied from the Debian image: `ls`, `bash`, `libc.so.6`, `ld-linux-x86-64.so.2`, `crt1.o`, and the Rust release binaries `cargo`, `rustdoc`, `rustup` | |

### Extended section numbering

The gABI (ch. 4, "ELF Header" and "Sections", table "Section Header Table Entry:
Index 0", <https://www.sco.com/developers/gabi/latest/ch4.sheader.html>) says
that when the section count is `>= SHN_LORESERVE` (0xff00) `e_shnum` is 0 and
the real count is in section 0's `sh_size`; when the section name table's
index is `>= SHN_LORESERVE`, `e_shstrndx` is `SHN_XINDEX` (0xffff) and the real
index is in section 0's `sh_link`; symbols in such sections have
`st_shndx == SHN_XINDEX` and the real index in an `SHT_SYMTAB_SHNDX` section.

`build.sh` generates `bin/.gen/src/many_sections.rs` with 70000 `#[no_mangle]`
functions. rustc emits one section per function on Linux targets (function
sections are on by default there; this is target configuration, not a
language rule), which gives ~70000 sections:

* `many_sections-<target>.o` (straight from rustc/LLVM): `e_shnum == 0`, but
  LLVM puts its string table at index 1, so `e_shstrndx` is a small number.
* `many_sections-<target>.relinked.o` (the same file through `rust-lld -r`):
  lld places `.shstrtab` near the end, so `e_shstrndx == SHN_XINDEX` too.

`PN_XNUM` (`e_phnum == 0xffff`) is not covered by a real file: no normal
toolchain output has 65535 program headers. It has to be covered by hand-built
(synthetic) inputs instead.

## Host requirements

* The toolchain pinned in the repository's `rust-toolchain.toml` (currently
  1.99.0) with the targets listed there: `x86_64-unknown-linux-musl`,
  `x86_64-unknown-linux-gnu`, `i686-unknown-linux-musl`,
  `aarch64-unknown-linux-musl`, `powerpc64-unknown-linux-gnu`,
  `s390x-unknown-linux-gnu`. `rustup toolchain install` in the repository root
  installs exactly that. `build.sh` resolves the compiler with `rustup which
  rustc` from the repository root and refuses to run if its `release:` does not
  match the pinned channel (a `RUSTC=` override is checked the same way).
* Linux executables are linked with the toolchain's own `rust-lld` and
  `-C link-self-contained=yes`, so no cross toolchain is needed for musl.
* glibc-linked files need docker. The image is pinned by digest
  (`rust:1.99.0-slim-bookworm`, linux/amd64 manifest; override with
  `DOCKER_IMAGE=name@sha256:...`, a bare tag is refused). Without docker that
  part is skipped and noted in `MANIFEST.txt`.
* `python3` is optional; `--verify` uses it for the per-section explanation of
  a mismatch and falls back to a byte count without it.

A variant that fails to build is listed in `MANIFEST.txt` as `FAILED` (no
hash) and the script continues.

## Reproducibility

### What is pinned

| input | how it is pinned | where it is recorded |
|---|---|---|
| host `rustc` | `rust-toolchain.toml` (`channel = "1.99.0"`), checked against `rustc -vV` | `rustc -vV` in the manifest header |
| host linker | `-C linker=$SYSROOT/lib/rustlib/<host>/bin/rust-lld -C linker-flavor=ld.lld`: an absolute path into the pinned toolchain and an explicit flavor, so rustc neither searches `PATH` nor goes through a `cc` driver | `rust-lld -flavor gnu --version` and its sha256; the first words of the link line rustc really ran (`--print link-args` of a throwaway build per musl target), checked to start with that `rust-lld -flavor gnu` |
| musl CRT / libc | `-C link-self-contained=yes`: `rcrt1.o`/`crt1.o`, `crti.o`, `crtbegin*.o`, `crtend*.o`, `crtn.o`, `libc.a`, `libunwind.a` from `$SYSROOT/lib/rustlib/<target>/lib/self-contained/` (part of the target's `rust-std` component) | sha256 of every file in those directories, and which `.o` files appear on the link line |
| docker toolchain | image pinned by digest, run with `--network none` | image reference and config id; inside the image: `uname -m`, which emulator is mapped into processes (Rosetta / qemu), `cc` and its real path, `cc --version`, `ld --version` (binutils), `ldd --version` (glibc), `dpkg` versions of gcc/binutils/libc6/libgcc-s1, whether gcc passes `--build-id`, `rustc -vV` |
| sources | | sha256 of `src/*.rs`, the generated `many_sections.rs` and `build.sh` itself |

Not recorded: the musl release that the toolchain's `libc.a` was built from
(the static library carries no version string; only musl's dynamic loader
prints one). The sha256 of `libc.a` pins it anyway.

For `--emit=obj` files no linker runs at all; for `*.relinked.o` the same
pinned `rust-lld` is called directly (`-flavor gnu -r`).

The `glibc/` and `system/` files are produced on an aarch64 host inside a
linux/amd64 container, i.e. by x86_64 binaries running under Docker Desktop's
user-mode emulator (the manifest names it), not on a native x86_64 kernel.

### Path independence

rustc writes the working directory into `DW_AT_comp_dir` and source paths into
`DW_AT_name` and into panic location strings. `build.sh` therefore runs rustc
in a fixed directory and passes

```
--remap-path-prefix=<testdata>/src=/unforge/src
--remap-path-prefix=<out>/.gen/src=/unforge/gen
--remap-path-prefix=<out>/.gen/work=/unforge/build
```

so the output does not depend on where the repository is checked out or which
`--out` directory is used. The previous script ran each rustc in a fresh
`mktemp -d` directory and did not remap: every file with debug info embedded
a random working directory (not reproducible even on the same machine; checked
by building the same command twice from two directories), and every file with
a panic location or debug info embedded the absolute checkout path. The standard library is already remapped to `/rustc/<commit>`
by the official builds. After a build, the manifest lists any output file that
still contains `$HOME`, the `testdata/` path or the output path.

Paths inside the docker image are fixed (`/src`, `/tmp/w`) and remapped the
same way.

### `--verify`

`build.sh --verify` builds everything with `--force` into a new temporary
directory (`$TMPDIR/unforge-verify.*`) and compares the sha256 of every file
against `bin/MANIFEST.txt`. Each file is reported as identical, `DIFFERENT`,
`MISSING` (in the manifest but not rebuilt), `NEW` (rebuilt but not in the
manifest), or `STALE` (the file in `bin/` no longer matches its own manifest
line). For a `DIFFERENT` ELF file the report lists the sections whose bytes
differ, a few strings found only in one of the two versions, and a guess at
the cause: embedded host/temporary paths, timestamp-like strings, changed
legacy symbol hashes (`17h<16 hex>E`: the crate's metadata hash changed),
`.comment` version strings, debug info, and the GNU build id (with
`--build-id=sha1`/`fast` the linker hashes the output, so a different build id
only follows from other differences; a lone build-id difference points to
`--build-id=uuid`, see the GNU ld manual, option `--build-id`). The guess is a
heuristic, not proof. The rebuilt tree and `verify-report.txt` are kept when
something differs; the exit status is 1 in that case.

`--verify --no-docker` skips the docker part and does not count the
`glibc/`/`system/` files.

### What is not guaranteed

Bit-for-bit identical output for identical inputs is a goal of rustc and LLVM
(and of lld), but this was not checked against their documentation or
source here, and it is not treated as a guarantee for every flag combination; the current result is whatever the
last `--verify` reported (see the numbers below). Results on a different host
OS/architecture are not verified: the host rustc and rust-lld are different
binaries there (same source), and nothing here proves they emit identical
bytes. The docker image digest pins its files, but the host's Docker
Desktop/Rosetta version is not pinned; a bug in the emulator could change
what the x86_64 compiler inside produces, which `--verify` would show.

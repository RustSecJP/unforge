# Developing Mekiki

This page is for people who want to build Mekiki or use its parts. To just use the app, see the [README](README.md).

## Build from source

You need Rust (the version in `rust-toolchain.toml` is installed by `rustup` on first use), Node.js 22 or newer, a C++17 compiler and zlib (for the decompiler helper), and the system libraries Tauri needs (on Linux, `libwebkit2gtk-4.1-dev` and friends; see [Tauri's prerequisites](https://v2.tauri.app/start/prerequisites/)).

```sh
cd mekiki
npm ci
npm run dev          # run the app in development mode
npm run build        # build the app and installers into src-tauri/target/release/bundle/
npm run dev:web      # the UI alone in a browser, with sample data (http://localhost:5176)
npm test             # UI unit tests
```

`npm run build` first builds the decompiler helper (`scripts/build-decomp.mjs`) and places it in `src-tauri/binaries/` as a Tauri sidecar; the processor files in `decompiler/specs/x86/` are bundled as resources.

`mekiki/src-tauri` and `mekiki/decompiler` are not members of the root Cargo workspace, so Tauri's large dependency tree stays out of the libraries' `Cargo.lock`.

## Repository layout

| Path | What it is |
| --- | --- |
| `mekiki/` | The desktop app (Tauri + React). [mekiki/README.md](mekiki/README.md) (Japanese) |
| `mekiki/decompiler/` | `mekiki-decomp`: Ghidra's C++ decompiler as a helper process, without Java (Apache-2.0) |
| `crates/unforge-elf` | Panic-free ELF reader built on zerocopy; reports anomalies instead of failing |
| `crates/unforge-pe` | Tolerant, panic-free PE/COFF reader (imports, exports, `.pdata`, TLS, PDB path) |
| `crates/unforge-analysis` | Functions and dependencies (crates and versions) of a Rust binary |
| `crates/unforge-disasm` | x86 / x86-64 disassembly of functions in ELF and PE files (iced-x86) |
| `crates/unforge-sigs` | Function fingerprints for naming functions in stripped binaries |
| `crates/unforge-report` | What Mekiki shows about a file, as plain data |
| `crates/unforge-cli` | The `unforge` command-line tool |
| `crates/unforge-bench` | Ground truth from DWARF and scoring of the analysis ([bench/README.md](bench/README.md)) |
| `crates/unforge-testgen` | Generator for the anomalous-ELF test corpus |
| `sigs/` | Workflow inputs for building fingerprint databases in CI ([sigs/README.md](sigs/README.md)) |
| `testdata/`, `fuzz/` | Test programs and fuzz targets |
| `site/` | The product page, published to GitHub Pages |

## The `unforge` command-line tool

Prebuilt archives (`unforge-<target>.tar.gz`, `.zip` on Windows) are attached to each [release](https://github.com/RustSecJP/mekiki/releases/latest). From source:

```sh
cargo run -p unforge -- elf --header --segments --sections --symbols path/to/binary
cargo run -p unforge -- pe --imports --pdata path/to/program.exe
cargo run -p unforge -- disasm --function main --count 50 path/to/binary
cargo run -p unforge -- sig build -o std.db path/to/with-symbols...
cargo run -p unforge -- sig match --db std.db path/to/stripped
```

More detail on each library (Japanese): [docs/unforge.ja.md](docs/unforge.ja.md).

## Tests

```sh
cargo test --workspace
(cd mekiki && npm test)
```

Some tests read the test executable itself as an x86-64 ELF, so run them on x86-64 Linux.

## Releases

Pushing a `v*` tag runs `.github/workflows/release.yml`: it builds the app for macOS (universal), Linux (AppImage, .deb) and Windows, the `unforge` CLI for several targets, and publishes them with `SHA256SUMS`. Asset names carry no version, so `https://github.com/RustSecJP/mekiki/releases/latest/download/<name>` always works. The product page in `site/` is deployed by `.github/workflows/pages.yml`.

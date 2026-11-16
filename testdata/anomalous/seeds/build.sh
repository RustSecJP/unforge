#!/bin/sh
# Rebuild the seed binaries in seeds/bin/ from seeds/marker.rs.
#
# The seeds are committed, so the generator (crates/unforge-testgen) is
# deterministic without this script. Rebuilding with another toolchain gives
# different bytes, and then every generated file and verdicts.tsv change too.
#
# Why nightly: with the prebuilt (stable) std a static musl "print and exit"
# program is ~330 KB, because std's panic/backtrace machinery is linked in.
# Rebuilding std with panic = "immediate-abort" (-Z build-std) gives ~25-36 KB,
# which keeps the committed corpus small. The flags otherwise follow the task:
# opt-level=s, abort on panic, symbols stripped, linked by rust-lld against
# stable's self-contained musl objects (crt1.o, libc.a).
#
# Requirements: a nightly toolchain with rust-src, a stable toolchain with the
# aarch64/x86_64 musl targets installed (for the crt objects).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=${TMPDIR:-/tmp}/unforge-seeds.$$
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/src"
cp "$here/marker.rs" "$work/src/main.rs"
cat > "$work/Cargo.toml" <<'TOML'
[package]
name = "marker"
version = "0.0.0"
edition = "2024"

[profile.release]
opt-level = "s"
panic = "abort"
lto = "fat"
codegen-units = 1
strip = "symbols"

[workspace]
TOML

stable_sysroot=$(rustc +stable --print sysroot)

build() { # build <arch> <relocation-model> <output name>
  arch=$1; reloc=$2; out=$3
  triple=$arch-unknown-linux-musl
  sc=$stable_sysroot/lib/rustlib/$triple/lib/self-contained
  # rustc names the crt objects without a directory when the nightly
  # toolchain has no musl target installed, so put them in the cwd.
  rm -f "$work"/*.o
  cp "$sc"/*.o "$work/"
  (cd "$work" && RUSTFLAGS="-C linker=rust-lld -C link-self-contained=yes \
      -C target-feature=+crt-static -C relocation-model=$reloc \
      -Zunstable-options -Cpanic=immediate-abort -L $sc" \
    cargo +nightly build --release -q --target "$triple" \
      --target-dir "$work/target-$reloc" -Z build-std=std,panic_abort)
  mkdir -p "$here/bin/$arch"
  cp "$work/target-$reloc/$triple/release/marker" "$here/bin/$arch/$out"
  chmod 0755 "$here/bin/$arch/$out"
}

build aarch64 static marker-static
build x86_64 static marker-static
# aarch64-unknown-linux-musl does not produce a static PIE (the target spec
# does not enable it), so only x86_64 has a static-pie seed with PT_DYNAMIC.
build x86_64 pie marker-static-pie

{
  echo "# seeds built by seeds/build.sh"
  echo "# $(rustc +nightly -V)"
  echo "# crt objects and libc.a from: $(rustc +stable -V)"
  (cd "$here/bin" && shasum -a 256 */*)
} > "$here/SEEDS.txt"
cat "$here/SEEDS.txt"

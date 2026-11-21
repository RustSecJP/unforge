#!/usr/bin/env bash
# Build the repository's own testdata/src programs into a benchmark corpus
# directory (same layout as the crates.io corpus built by
# .github/workflows/bench-corpus.yml):
#
#   <out>/<id>.debug       built with -C debuginfo=2
#   <out>/<id>.stripped    objcopy --strip-all of the same file
#   <out>/<id>.meta.json   how it was built (bench/scripts/write-meta.py)
#   <out>/<id>.truth.json  ground truth (unforge-bench truth), when the
#                          unforge-bench binary is available
#
# Usage: bench/build-testdata.sh [--out DIR] [--bench PATH] [--targets "T1 T2"]
#   --out      output directory (default: bench/corpus/testdata, not committed)
#   --bench    unforge-bench binary (default: target/release/unforge-bench,
#              then target/debug/unforge-bench; truth is skipped without one)
#   --targets  default: "x86_64-unknown-linux-gnu x86_64-unknown-linux-musl"
#
# Only our own sources are compiled (plain rustc, no cargo, no build
# scripts). The gnu target is linked by the host cc against glibc; the musl
# target with the toolchain's rust-lld and self-contained CRT, as in
# testdata/build.sh. A variant that fails to build is reported and skipped.

set -uo pipefail
export LC_ALL=C TZ=UTC

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
SRC="$REPO/testdata/src"
OUT="$HERE/corpus/testdata"
BENCH=""
TARGETS="x86_64-unknown-linux-gnu x86_64-unknown-linux-musl"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out) shift; OUT="${1:?--out needs a directory}" ;;
        --bench) shift; BENCH="${1:?--bench needs a path}" ;;
        --targets) shift; TARGETS="${1:?--targets needs a list}" ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done
if [[ -z "$BENCH" ]]; then
    for b in "$REPO/target/release/unforge-bench" "$REPO/target/debug/unforge-bench"; do
        [[ -x "$b" ]] && { BENCH="$b"; break; }
    done
fi

RUSTC="$(cd "$REPO" && rustup which rustc 2> /dev/null || command -v rustc)"
SYSROOT="$("$RUSTC" --print sysroot)"
HOST="$("$RUSTC" -vV | sed -n 's/^host: //p')"
LLD="$SYSROOT/lib/rustlib/$HOST/bin/rust-lld"
export LD_LIBRARY_PATH="$SYSROOT/lib"

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
"$RUSTC" -vV > "$WORK/rustc-vV.txt"

# name | opt-level | lto | panic  (the same variants as bench/corpus.toml)
VARIANTS=(
    "o0|0|off|unwind"
    "o3|3|off|unwind"
    "oz-fat-abort|z|fat|abort"
)
PROGRAMS=(collections enums traits panics ffi_statics)

ok=0
failed=0
for T in $TARGETS; do
    case "$T" in
        *-musl) short=musl; LINK=(-C "linker=$LLD" -C linker-flavor=ld.lld -C link-self-contained=yes) ;;
        *-gnu) short=gnu; LINK=() ;;
        *) short="$T"; LINK=() ;;
    esac
    for p in "${PROGRAMS[@]}"; do
        for v in "${VARIANTS[@]}"; do
            IFS='|' read -r vname opt lto panic <<< "$v"
            id="$p-$short-$vname"
            flags=(--edition 2021 --target "$T" -C "opt-level=$opt" -C debuginfo=2
                   -C codegen-units=1 -C strip=none -C "panic=$panic")
            [[ "$lto" != off ]] && flags+=(-C "lto=$lto")
            rm -rf "$WORK/b"; mkdir -p "$WORK/b"
            if ! (cd "$WORK/b" && "$RUSTC" "${flags[@]}" "${LINK[@]}" \
                    --remap-path-prefix="$SRC=/unforge/src" --remap-path-prefix="$WORK/b=/unforge/build" \
                    "$SRC/$p.rs" -o "$OUT/$id.debug" > "$WORK/log" 2>&1); then
                echo "FAILED: $id" >&2; sed -n '1,10p' "$WORK/log" >&2
                failed=$((failed + 1)); rm -f "$OUT/$id.debug"; continue
            fi
            objcopy --strip-all "$OUT/$id.debug" "$OUT/$id.stripped"
            python3 -I "$HERE/scripts/write-meta.py" --out "$OUT/$id.meta.json" --id "$id" \
                --crate "$p" --version 0.0.0 --bin "$p" --source testdata --target "$T" \
                --variant "$vname" --opt-level "$opt" --lto "$lto" --panic "$panic" \
                --debug "$OUT/$id.debug" --stripped "$OUT/$id.stripped" --rustc-vv "$WORK/rustc-vV.txt"
            if [[ -n "$BENCH" ]]; then
                "$BENCH" truth "$OUT/$id.debug" -o "$OUT/$id.truth.json" || failed=$((failed + 1))
            fi
            ok=$((ok + 1))
        done
    done
done
echo "built=$ok failed=$failed into $OUT${BENCH:+ (truth: $BENCH)}" >&2

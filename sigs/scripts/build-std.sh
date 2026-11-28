#!/usr/bin/env bash
# Build the std fingerprint database of one Rust release.
#
# Usage: sigs/scripts/build-std.sh <release> <out-dir> <unforge>
#
# Compiles the repository's own std-only programs (testdata/src/*.rs
# executables and sigs/std/*.rs) with that release, for several targets and
# profiles, keeping the symbols, and turns all of them into one database:
#   <out>/std-<release>-<commit9>.db     the database
#   <out>/std-<release>-<commit9>.json   release, full rustc commit, LLVM,
#                                        counts (what the database is for)
#   <out>/std-<release>.stats.tsv        per executable: named / added
#   <out>/FAILED-std-<release>.txt       variants that did not build
#
# Only our own sources are compiled (plain rustc, no cargo, no build
# scripts, no crates.io code). The toolchain and its targets must already be
# installed (rustup toolchain install <release> --target ...). A variant that
# fails to build is logged and skipped.
#
# std itself ships precompiled, so its non-generic functions are the same in
# every program built with one release. Generic and #[inline] std code is
# compiled at the program's own optimization level, hence the profiles.

set -uo pipefail
export LC_ALL=C TZ=UTC

V="${1:?release}"; OUT="${2:?out dir}"; UNFORGE="${3:?unforge}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
FAILED="$OUT/FAILED-std-$V.txt"
: > "$FAILED"

WORK="${RUNNER_TEMP:-$(mktemp -d)}/std-$V"
rm -rf "$WORK"; mkdir -p "$WORK/bin" "$WORK/b"
: > "$WORK/list"
# Outside the checkout, so ../rust-toolchain.toml does not pick the
# toolchain; `+$V` does.
cd "$WORK" || exit 2

VV="$(rustc "+$V" -vV)" || { echo "toolchain $V is not installed" >&2; exit 2; }
RELEASE="$(sed -n 's/^release: //p' <<< "$VV")"
COMMIT="$(sed -n 's/^commit-hash: //p' <<< "$VV")"
DATE="$(sed -n 's/^commit-date: //p' <<< "$VV")"
HOST="$(sed -n 's/^host: //p' <<< "$VV")"
LLVM="$(sed -n 's/^LLVM version: //p' <<< "$VV")"
if [[ "$RELEASE" != "$V" || ! "$COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    echo "rustc +$V reports release '$RELEASE', commit '$COMMIT'" >&2
    exit 2
fi
SHORT="${COMMIT:0:9}"
LLD="$(rustc "+$V" --print sysroot)/lib/rustlib/$HOST/bin/rust-lld"

PROGRAMS=()
for p in collections enums traits panics ffi_statics; do
    PROGRAMS+=("$REPO/testdata/src/$p.rs")
done
for p in "$REPO"/sigs/std/*.rs; do
    PROGRAMS+=("$p")
done

# name | rustc flags. o3 / os / oz / o0 are what `cargo build` gives with
# opt-level 3, s, z and the dev profile; the last two are the panic=abort
# and "min-sized-rust" recipes common in malware.
VARIANTS=(
    "o3|-C opt-level=3"
    "os|-C opt-level=s"
    "oz|-C opt-level=z"
    "o0|-C opt-level=0 -C debug-assertions=on -C overflow-checks=on"
    "o3-abort|-C opt-level=3 -C panic=abort"
    "oz-min|-C opt-level=z -C lto=fat -C codegen-units=1 -C panic=abort"
)
TARGETS=(x86_64-unknown-linux-gnu x86_64-unknown-linux-musl i686-unknown-linux-musl)

ok=0
for T in "${TARGETS[@]}"; do
    case "$T" in
        # glibc: the host cc links, as cargo would.
        *-gnu) LINK=() ;;
        # musl: the toolchain's rust-lld with the self-contained CRT, as in
        # testdata/build.sh (no musl-gcc needed).
        *-musl) LINK=(-C "linker=$LLD" -C linker-flavor=ld.lld -C link-self-contained=yes) ;;
    esac
    short="${T%%-unknown-*}-${T##*-}"
    for src in "${PROGRAMS[@]}"; do
        p="$(basename "$src" .rs)"
        for v in "${VARIANTS[@]}"; do
            IFS='|' read -r vname vflags <<< "$v"
            # shellcheck disable=SC2206 # the flags are split on purpose
            flags=($vflags)
            exe="$WORK/bin/$p-$short-$vname"
            if (cd "$WORK/b" && rustc "+$V" --edition 2021 --target "$T" "${flags[@]}" \
                    -C debuginfo=0 -C strip=none "${LINK[@]}" \
                    --remap-path-prefix="$REPO=/unforge" --remap-path-prefix="$WORK=/build" \
                    "$src" -o "$exe" > "$WORK/log" 2>&1); then
                ok=$((ok + 1))
                echo "$exe" >> "$WORK/list"
            else
                { echo "FAILED $p $T $vname"; sed -n '1,15p' "$WORK/log"; } | tee -a "$FAILED" >&2
            fi
        done
    done
done

DB="std-$V-$SHORT.db"
res="$(bash "$HERE/make-db.sh" "$UNFORGE" "$OUT/$DB" "$OUT/std-$V.stats.tsv" "$WORK/list")"
fps="$(sed -n 's/^fingerprints=//p' <<< "$res")"; fps="${fps:-0}"
bytes="$(sed -n 's/^bytes=//p' <<< "$res")"; bytes="${bytes:-0}"
failed="$(grep -c '^FAILED' "$FAILED")"
sed -i "s|$WORK/bin/||" "$OUT/std-$V.stats.tsv"

python3 -I - "$OUT/std-$V-$SHORT.json" "$V" "$COMMIT" "$DATE" "$LLVM" "$HOST" "$DB" \
    "$fps" "$bytes" "$ok" "$failed" "${TARGETS[*]}" "${VARIANTS[*]}" << 'PY'
import json, sys
(out, release, commit, date, llvm, host, db, fps, size, ok, failed, targets,
 variants) = sys.argv[1:]
with open(out, "w") as f:
    json.dump({
        "release": release,
        "rustc_commit": commit,
        "rustc_commit_short": commit[:9],
        "commit_date": date,
        "llvm": llvm,
        "host": host,
        "db": db if int(fps) > 0 else None,
        "fingerprints": int(fps),
        "bytes": int(size),
        "executables": int(ok),
        "failed_variants": int(failed),
        "targets": targets.split(),
        "variants": [v.split("|")[0] for v in variants.split(" ") if "|" in v],
    }, f, indent=2)
    f.write("\n")
PY
echo "std $V ($SHORT): $ok executables, $failed failed, $fps fingerprints, $bytes bytes" >&2
rm -rf "$WORK"
[[ "$fps" -gt 0 ]]

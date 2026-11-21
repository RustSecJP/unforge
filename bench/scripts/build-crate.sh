#!/usr/bin/env bash
# Build one crates.io binary crate in every enabled variant of
# bench/corpus.toml and write the corpus files for each installed binary:
#   <out>/<id>.debug, <id>.stripped, <id>.meta.json, <id>.truth.json
# with <id> = <crate>-<version>-<bin>-<target short>-<variant>.
#
# Usage: bench/scripts/build-crate.sh <crate> <version> <out-dir> <unforge-bench>
#
# SAFETY: `cargo install` compiles and RUNS the build scripts and proc macros
# of the crate and of all its dependencies. That is third-party code. This
# script is meant for the isolated GitHub Actions job in
# .github/workflows/bench-corpus.yml (no secrets, read-only token) and
# refuses to run anywhere else. Never run it on a developer machine.
#
# A variant that fails is logged to <out>/FAILED-<crate>.txt and skipped;
# the script itself always exits 0 so that one crate cannot fail the run.

set -uo pipefail
export LC_ALL=C TZ=UTC

if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
    echo "build-crate.sh runs third-party build scripts; it only runs in GitHub Actions." >&2
    exit 2
fi

CRATE="${1:?crate}"; VERSION="${2:?version}"; OUT="${3:?out dir}"; BENCH="${4:?unforge-bench}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPEC="$HERE/../corpus.toml"
REPO="$(cd "$HERE/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)".*/\1/p' "$REPO/rust-toolchain.toml")"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
FAILED="$OUT/FAILED-$CRATE.txt"

# Everything cargo touches lives under a throwaway directory outside the
# checkout, so the crate's code never sees the repository.
WORK="${RUNNER_TEMP:-/tmp}/bench-$CRATE"
rm -rf "$WORK"; mkdir -p "$WORK"
export CARGO_HOME="$WORK/cargo-home"
cd "$WORK" || exit 2

declare -A COMMON
while IFS='=' read -r k v; do COMMON[$k]="$v"; done < <(python3 -I "$HERE/corpus.py" "$SPEC" common)

rustc "+$TOOLCHAIN" -vV > "$WORK/rustc-vV.txt"

while read -r T; do
    case "$T" in
        *-linux-gnu) short=gnu ;;
        *-linux-musl) short=musl ;;
        *) short="$T" ;;
    esac
    while read -r vname opt lto panic; do
        echo "::group::$CRATE $VERSION $T $vname"
        root="$WORK/root-$short-$vname"
        rm -rf "$root"
        if ! env \
            CARGO_PROFILE_RELEASE_OPT_LEVEL="$opt" \
            CARGO_PROFILE_RELEASE_LTO="$lto" \
            CARGO_PROFILE_RELEASE_PANIC="$panic" \
            CARGO_PROFILE_RELEASE_CODEGEN_UNITS="${COMMON[codegen_units]:-1}" \
            CARGO_PROFILE_RELEASE_DEBUG="${COMMON[debug]:-2}" \
            CARGO_PROFILE_RELEASE_STRIP="${COMMON[strip]:-none}" \
            CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO=off \
            CARGO_PROFILE_RELEASE_INCREMENTAL=false \
            cargo "+$TOOLCHAIN" install --locked --root "$root" \
                --target "$T" --target-dir "$WORK/target" \
                "$CRATE@$VERSION" > "$WORK/build.log" 2>&1; then
            echo "FAILED $CRATE $VERSION $T $vname" >> "$FAILED"
            tail -40 "$WORK/build.log" | tee -a "$FAILED"
            echo "::endgroup::"
            rm -rf "$WORK/target"
            continue
        fi
        # The Cargo.lock that --locked used: the one published in the crate.
        lock="$(find "$CARGO_HOME/registry/src" -mindepth 3 -maxdepth 3 -path "*/$CRATE-$VERSION/Cargo.lock" 2> /dev/null | head -1)"
        for bin in "$root"/bin/*; do
            [[ -f "$bin" ]] || continue
            b="$(basename "$bin")"
            id="$CRATE-$VERSION-$b-$short-$vname"
            cp "$bin" "$OUT/$id.debug"
            objcopy --strip-all "$OUT/$id.debug" "$OUT/$id.stripped"
            python3 -I "$HERE/write-meta.py" --out "$OUT/$id.meta.json" --id "$id" \
                --crate "$CRATE" --version "$VERSION" --bin "$b" --source crates.io \
                --target "$T" --variant "$vname" --opt-level "$opt" --lto "$lto" \
                --panic "$panic" --codegen-units "${COMMON[codegen_units]:-1}" \
                --debuginfo "${COMMON[debug]:-2}" \
                --debug "$OUT/$id.debug" --stripped "$OUT/$id.stripped" \
                --rustc-vv "$WORK/rustc-vV.txt" ${lock:+--cargo-lock "$lock"}
            "$BENCH" truth "$OUT/$id.debug" -o "$OUT/$id.truth.json" \
                || echo "TRUTH FAILED $id" >> "$FAILED"
        done
        # Keep the runner's disk in check: fat-LTO debug builds are large.
        rm -rf "$WORK/target"
        echo "::endgroup::"
    done < <(python3 -I "$HERE/corpus.py" "$SPEC" variants)
done < <(python3 -I "$HERE/corpus.py" "$SPEC" targets)

rm -rf "$WORK"
exit 0

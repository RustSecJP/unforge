#!/usr/bin/env bash
# Build the executables of one crates.io crate that the crate DB is made of.
#
# Usage: sigs/scripts/build-crate.sh <crate> <version> <rustc> <out-dir>
#
# No per-crate harness: the published source of <crate> <version> is fetched
# with cargo, and the crate's OWN tests, examples and benches are built in
# it (`cargo test --no-run --release`). They call most of its API, so these
# executables contain most of its code, with symbols (sigs/crates.toml has
# the feature sets tried). Output:
#   <out>/bin/<profile>/<executable>   ELF executables with symbols
#   <out>/status.json                  what was built, and how
#   <out>/build-<profile>.log          the end of the cargo log
# Always exits 0: a crate that does not build is recorded in status.json.
#
# SAFETY: this compiles and RUNS the build scripts and proc macros of the
# crate and of all its (dev-)dependencies. That is third-party code. This
# script is meant for the isolated job `crate-build` of
# .github/workflows/sigs.yml (no secrets, read-only token, nothing from it
# is executed later) and refuses to run anywhere else. Never run it on a
# developer machine. The executables are untrusted: they are only parsed
# (by `unforge sig build`, in another job), never run.

set -uo pipefail
export LC_ALL=C TZ=UTC

if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
    echo "build-crate.sh runs third-party build scripts; it only runs in GitHub Actions." >&2
    exit 2
fi

CRATE="${1:?crate}"; VERSION="${2:?version}"; R="${3:?rustc}"; OUT="${4:?out dir}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPEC="$HERE/../crates.toml"
mkdir -p "$OUT/bin"
OUT="$(cd "$OUT" && pwd)"
# Most executables kept per profile (tokio has about a hundred test files).
MAX_EXES=400

# Everything cargo touches lives under a throwaway directory outside the
# checkout, with its own CARGO_HOME, so the crate's code never sees the
# repository's files or a shared cargo cache.
WORK="${RUNNER_TEMP:?}/crate-$CRATE-$VERSION-$R"
rm -rf "$WORK"; mkdir -p "$WORK"
export CARGO_HOME="$WORK/cargo-home"
# The toolchain is chosen here, not by a rust-toolchain file in the crate.
export RUSTUP_TOOLCHAIN="$R"
# Resolve dev-dependencies to versions that support this rustc.
export CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback
export CARGO_TERM_COLOR=never CARGO_INCREMENTAL=0
cd "$WORK" || exit 2

status() {
    python3 -I - "$OUT/status.json" "$CRATE" "$VERSION" "$R" "$COMMIT" "$@" << 'PY'
import json, sys
out, crate, version, rustc, commit, status, detail, *profiles = sys.argv[1:]
prof = {}
for p in profiles:
    name, attempt, n = p.split("|")
    prof[name] = {"attempt": attempt, "executables": int(n)}
with open(out, "w") as f:
    json.dump({"crate": crate, "version": version, "rustc": rustc,
               "rustc_commit": commit, "status": status, "detail": detail,
               "profiles": prof,
               "executables": sum(p["executables"] for p in prof.values())},
              f, indent=2)
    f.write("\n")
PY
}

COMMIT="$(rustc -vV | sed -n 's/^commit-hash: //p')"

# --- Options from sigs/crates.toml -----------------------------------------
FEATURES=""
while IFS= read -r line; do
    case "$line" in
        features=*) FEATURES="${line#features=}" ;;
        env=*) kv="${line#env=}"; export "${kv%%=*}=${kv#*=}" ;;
    esac
done < <(python3 -I "$HERE/spec.py" crate-opts "$SPEC" "$CRATE" "$VERSION")

# --- Fetch the published source (no third-party code runs here) ------------
# A throwaway package that depends on exactly this version; `cargo fetch`
# downloads the .crate and checks it against the registry index checksum.
if ! cargo new --lib --vcs none --name unforge_sigs_fetch fetch > "$WORK/fetch.log" 2>&1; then
    cp "$WORK/fetch.log" "$OUT/build-fetch.log"
    status failed "cargo new failed"
    exit 0
fi
printf '%s = "=%s"\n' "$CRATE" "$VERSION" >> fetch/Cargo.toml
if ! (cd fetch && cargo fetch > "$WORK/fetch.log" 2>&1); then
    cp "$WORK/fetch.log" "$OUT/build-fetch.log"
    status failed "cargo fetch failed"
    exit 0
fi
archive="$(find "$CARGO_HOME/registry/cache" -name "$CRATE-$VERSION.crate" | head -1)"
if [[ -z "$archive" ]]; then
    status failed "no $CRATE-$VERSION.crate after cargo fetch"
    exit 0
fi
# Unpacked under a `registry/src/<index>/<crate>-<version>/` path, like
# cargo does: the panic location strings then carry that path, and
# unforge-analysis records `<crate> <version>` as a source of the database.
SRCROOT="$WORK/registry/src/index.crates.io"
mkdir -p "$SRCROOT"
tar -xzf "$archive" -C "$SRCROOT" --no-same-owner --no-same-permissions || {
    status failed "cannot unpack $archive"
    exit 0
}
CRATE_DIR="$SRCROOT/$CRATE-$VERSION"
# Configuration that would change the toolchain or the flags.
rm -rf "$CRATE_DIR/.cargo" "$CRATE_DIR/rust-toolchain" "$CRATE_DIR/rust-toolchain.toml"

# --- Build ------------------------------------------------------------------
attempts=()
if [[ -n "$FEATURES" ]]; then
    attempts+=("--features $FEATURES --all-targets" "--features $FEATURES")
fi
attempts+=("--all-features --all-targets" "--all-features" "--all-targets" "" "--lib")

results=()
built=0
while read -r pname opt; do
    [[ -n "$pname" ]] || continue
    mkdir -p "$OUT/bin/$pname"
    used="none"
    n=0
    for a in "${attempts[@]}"; do
        echo "::group::$CRATE $VERSION $pname: cargo test --no-run --release $a"
        # shellcheck disable=SC2086 # $a is a list of arguments on purpose
        if (cd "$CRATE_DIR" && env \
                CARGO_PROFILE_RELEASE_OPT_LEVEL="$opt" CARGO_PROFILE_BENCH_OPT_LEVEL="$opt" \
                CARGO_PROFILE_RELEASE_DEBUG=false CARGO_PROFILE_BENCH_DEBUG=false \
                CARGO_PROFILE_RELEASE_STRIP=debuginfo CARGO_PROFILE_BENCH_STRIP=debuginfo \
                CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_BENCH_LTO=false \
                CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 CARGO_PROFILE_BENCH_CODEGEN_UNITS=16 \
                CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false CARGO_PROFILE_BENCH_DEBUG_ASSERTIONS=false \
                CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=false CARGO_PROFILE_BENCH_OVERFLOW_CHECKS=false \
                CARGO_PROFILE_RELEASE_INCREMENTAL=false CARGO_PROFILE_BENCH_INCREMENTAL=false \
                timeout 45m cargo test --no-run --release --target-dir "$WORK/target" \
                    --message-format=json-render-diagnostics $a \
                    > "$WORK/messages.json" 2> "$WORK/build.log"); then
            used="${a:-default}"
            echo "::endgroup::"
            break
        fi
        tail -30 "$WORK/build.log"
        echo "::endgroup::"
    done
    tail -200 "$WORK/build.log" > "$OUT/build-$pname.log"
    if [[ "$used" != "none" ]]; then
        # The executables cargo reports (tests, examples, benches, bins).
        while IFS= read -r exe; do
            [[ -f "$exe" ]] || continue
            [[ "$(head -c 4 "$exe" | od -An -tx1 | tr -d ' \n')" == "7f454c46" ]] || continue
            [[ "$n" -lt "$MAX_EXES" ]] || break
            dest="$OUT/bin/$pname/$(basename "$exe")"
            [[ -e "$dest" ]] && dest="$dest-$n"
            cp "$exe" "$dest"
            n=$((n + 1))
        done < <(python3 -I -c '
import json, sys
seen = set()
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    try:
        m = json.loads(line)
    except ValueError:
        continue
    exe = m.get("executable") if m.get("reason") == "compiler-artifact" else None
    if exe and exe not in seen:
        seen.add(exe)
        print(exe)
' "$WORK/messages.json")
    fi
    built=$((built + n))
    results+=("$pname|$used|$n")
    # Keep the runner's disk in check between profiles.
    rm -rf "$WORK/target"
done < <(python3 -I "$HERE/spec.py" profiles "$SPEC")

if [[ "$built" -gt 0 ]]; then
    status ok "" "${results[@]}"
else
    status failed "no executable built (see build-*.log)" "${results[@]}"
fi
rm -rf "$WORK"
exit 0

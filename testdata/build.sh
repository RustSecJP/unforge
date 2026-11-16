#!/usr/bin/env bash
# Build the real-binary test corpus into testdata/bin/.
#
# Usage: testdata/build.sh [--force] [--no-docker] [--out DIR]
#        testdata/build.sh --verify [--no-docker]
#   --force      rebuild every file even if it is newer than its source
#   --no-docker  skip the docker part (glibc-linked builds, system files)
#   --out DIR    build into DIR instead of testdata/bin
#   --verify     rebuild everything from scratch into a temporary directory and
#                compare the sha256 of every file with testdata/bin/MANIFEST.txt;
#                lists every file that is not bit-for-bit reproducible together
#                with the sections / strings that differ. Exit status 1 if any
#                file differs.
#
# Idempotent: an output that already exists and is newer than its source is
# not rebuilt (unless the toolchain, the docker image or this script changed),
# but MANIFEST.txt is always regenerated from the files that are actually in
# the output directory, so the manifest always describes exactly what is there.
#
# Reproducibility measures (see README.md for what is and is not guaranteed):
#   * rustc is the toolchain pinned in ../rust-toolchain.toml (checked).
#   * Host-built Linux executables are linked by the toolchain's own rust-lld,
#     passed by absolute path with an explicit linker flavor, against the
#     self-contained musl CRT objects/libc of the target. No host cc/ld is
#     involved; the link line rustc actually used is recorded in MANIFEST.txt.
#   * --remap-path-prefix maps the source dir, the generated-source dir and the
#     working dir to fixed virtual paths, so no checkout/temp path is embedded
#     (DW_AT_comp_dir, DW_AT_name, panic location strings).
#   * The docker image is pinned by digest and run with --network none.
#
# A variant that fails to build is logged (in MANIFEST.txt and on stderr) and
# skipped; the script never aborts half-way because one target is missing.

set -uo pipefail
export LC_ALL=C TZ=UTC

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
SRC="$HERE/src"
BIN="$HERE/bin"
FORCE=0
DOCKER=1
VERIFY=0
OUT=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force) FORCE=1 ;;
        --no-docker) DOCKER=0 ;;
        --verify) VERIFY=1 ;;
        --out) shift; OUT="${1:?--out needs a directory}" ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

log() { printf '%s\n' "$*" >&2; }

if command -v sha256sum > /dev/null 2>&1; then
    sha256() { sha256sum "$1" | cut -d' ' -f1; }
else
    sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

# ---------------------------------------------------------------------------
# --verify: rebuild into a temporary directory and compare hashes.
# ---------------------------------------------------------------------------

# diagnose <reference file> <rebuilt file>: explain how two files differ.
# Needs python3 for the per-section view; falls back to cmp otherwise.
diagnose() {
    if ! command -v python3 > /dev/null 2>&1; then
        local n
        n="$(cmp -l "$1" "$2" 2> /dev/null | wc -l | tr -d ' ')"
        echo "    sizes $(wc -c < "$1" | tr -d ' ') vs $(wc -c < "$2" | tr -d ' '), $n differing bytes (python3 not found: no per-section view)"
        return
    fi
    python3 -I - "$1" "$2" << 'PY'
import re, struct, sys

a = open(sys.argv[1], "rb").read()
b = open(sys.argv[2], "rb").read()


def sections(d):
    """[(name, offset, size)] from the section header table, or None."""
    if d[:4] != b"\x7fELF" or len(d) < 0x34:
        return None
    e = "<" if d[5] == 1 else ">"
    try:
        if d[4] == 2:
            (shoff,) = struct.unpack_from(e + "Q", d, 0x28)
            shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", d, 0x3A)
            fmt = e + "IIQQQQIIQQ"
        else:
            (shoff,) = struct.unpack_from(e + "I", d, 0x20)
            shentsize, shnum, shstrndx = struct.unpack_from(e + "HHH", d, 0x2E)
            fmt = e + "IIIIIIIIII"
        if shoff == 0:
            return []
        sh = lambda i: struct.unpack_from(fmt, d, shoff + i * shentsize)
        # gABI extended numbering: real values live in section header 0.
        if shnum == 0:
            shnum = sh(0)[5]
        if shstrndx == 0xFFFF:
            shstrndx = sh(0)[6]
        hdrs = [sh(i) for i in range(shnum)]
        so = hdrs[shstrndx][4]
        out = []
        for h in hdrs:
            n = d[so + h[0] : d.index(b"\0", so + h[0])].decode("latin1")
            size = 0 if h[1] == 8 else h[5]  # SHT_NOBITS occupies no file bytes
            out.append((n or "<null>", h[4], size))
        return out
    except Exception:
        return None


STR = re.compile(rb"[\x20-\x7e]{6,}")
HINTS = [
    (re.compile(r"17h[0-9a-f]{16}E"), "legacy-mangled symbol hash (17h<16 hex>E) differs: crate metadata / StableCrateId changed"),
    (re.compile(r"(/tmp/|/var/folders/|/private/|/Users/|/home/|rustc[A-Za-z0-9]{6})"), "embeds a host or temporary path"),
    (re.compile(r"(19|20)\d\d-[01]\d-[0-3]\d|[0-2]\d:[0-5]\d:[0-5]\d"), "embeds a date/time-like string (timestamp?)"),
]


def strdiff(x, y):
    sx, sy = set(STR.findall(x)), set(STR.findall(y))
    return sorted(sx - sy)[:3], sorted(sy - sx)[:3]


def show(label, strs):
    for s in strs:
        t = s.decode("latin1")
        # Long paths usually differ near the end (temp dir names).
        t = t if len(t) <= 100 else "..." + t[-97:]
        print(f"        {label}: {t!r}")


def hints(strs):
    found = set()
    for s in strs:
        t = s.decode("latin1")
        for rx, msg in HINTS:
            if rx.search(t):
                found.add(msg)
    return found


print(f"    size {len(a)} (reference) vs {len(b)} (rebuilt)")
sa, sb = sections(a), sections(b)
allstrs, why = [], set()
if sa is None or sb is None:
    n = sum(1 for i in range(min(len(a), len(b))) if a[i] != b[i])
    print(f"    not an ELF file with a readable section table; {n} differing bytes in the common prefix")
    ua, ub = strdiff(a, b)
    show("only in reference", ua)
    show("only in rebuilt  ", ub)
    allstrs = ua + ub
else:
    first_a = min([o for _, o, s in sa if s] or [len(a)])
    first_b = min([o for _, o, s in sb if s] or [len(b)])
    if a[:first_a] != b[:first_b]:
        print("    ELF header / program headers differ (layout or entry point changed)")
    if len(sa) != len(sb):
        print(f"    section count {len(sa)} vs {len(sb)}")
    seen = {}
    keyed_b = {}
    for n, o, s in sb:
        k = (n, seen.get(("b", n), 0))
        seen[("b", n)] = k[1] + 1
        keyed_b[k] = (o, s)
    differ = []
    for n, o, s in sa:
        k = (n, seen.get(("a", n), 0))
        seen[("a", n)] = k[1] + 1
        if k not in keyed_b:
            differ.append(n)
            print(f"    section {n}: missing in rebuilt file")
            continue
        ob, s2 = keyed_b[k]
        x, y = a[o : o + s], b[ob : ob + s2]
        if x == y:
            continue
        differ.append(n)
        nb = sum(1 for i in range(min(len(x), len(y))) if x[i] != y[i]) if len(x) == len(y) else None
        what = f"{nb} bytes differ" if nb is not None else f"size {s} vs {s2}"
        print(f"    section {n}: {what}")
        ua, ub = strdiff(x, y)
        show("only in reference", ua)
        show("only in rebuilt  ", ub)
        allstrs += ua + ub
    if ".note.gnu.build-id" in differ:
        if differ == [".note.gnu.build-id"]:
            why.add("only the build id differs: the linker used a random (uuid) build id, not a content hash")
        else:
            why.add("build id differs as a consequence of the other differences (sha1/fast build ids hash the output)")
    if any(n.startswith(".debug") for n in differ):
        why.add("debug info differs (DW_AT_comp_dir / DW_AT_name paths, or codegen differences)")
    if ".comment" in differ:
        why.add(".comment differs: different compiler/linker version strings")
    if any(n in (".symtab", ".strtab", ".dynsym", ".dynstr") for n in differ):
        why.add("symbol table differs (symbol names or values)")
why |= hints(allstrs)
for w in sorted(why):
    print(f"    => {w}")
if not why:
    print("    => cause not classified; compare the two files by hand")
PY
}

# read_manifest <MANIFEST.txt>: "<sha256> <path>" for every built file.
read_manifest() {
    awk -F'\t' '/^[0-9a-f]{64}\t/ { print $1 " " $2 }' "$1" | sort -k2
}

if [[ $VERIFY -eq 1 ]]; then
    REF="$BIN/MANIFEST.txt"
    if [[ ! -f "$REF" ]] || ! grep -qE '^[0-9a-f]{64}	' "$REF"; then
        log "no hashed manifest at $REF; run testdata/build.sh first"
        exit 2
    fi
    VTMP="$(mktemp -d "${TMPDIR:-/tmp}/unforge-verify.XXXXXX")"
    # Resolve symlinks (macOS: /var -> /private/var) so --remap-path-prefix
    # matches the path rustc actually sees.
    VTMP="$(cd "$VTMP" && pwd -P)"
    args=(--force --out "$VTMP/bin")
    [[ $DOCKER -eq 0 ]] && args+=(--no-docker)
    log "verify: rebuilding into $VTMP/bin"
    bash "$HERE/build.sh" "${args[@]}" || { log "verify: rebuild failed"; exit 2; }
    REPORT="$VTMP/verify-report.txt"
    read_manifest "$REF" > "$VTMP/ref.txt"
    read_manifest "$VTMP/bin/MANIFEST.txt" > "$VTMP/new.txt"
    same=0; diff_n=0; missing=0; extra=0; skipped_docker=0; stale=0
    {
        echo "# unforge corpus verify report ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
        echo "# reference: $REF"
        echo "# rebuilt:   $VTMP/bin"
        while read -r h rel; do
            nh="$(awk -v p="$rel" '$2 == p { print $1 }' "$VTMP/new.txt")"
            if [[ -f "$BIN/$rel" && "$(sha256 "$BIN/$rel")" != "$h" ]]; then
                stale=$((stale + 1))
                echo "STALE      $rel (testdata/bin file no longer matches its manifest hash)"
            fi
            if [[ -z "$nh" ]]; then
                case "$rel" in
                    glibc/*|system/*)
                        if [[ $DOCKER -eq 0 ]]; then
                            skipped_docker=$((skipped_docker + 1)); continue
                        fi ;;
                esac
                missing=$((missing + 1))
                echo "MISSING    $rel (not produced by the rebuild)"
            elif [[ "$nh" == "$h" ]]; then
                same=$((same + 1))
            else
                diff_n=$((diff_n + 1))
                echo "DIFFERENT  $rel"
                echo "    sha256 $h (reference) vs $nh (rebuilt)"
                if [[ -f "$BIN/$rel" ]]; then
                    diagnose "$BIN/$rel" "$VTMP/bin/$rel"
                else
                    echo "    reference file is gone from testdata/bin; cannot compare contents"
                fi
            fi
        done < "$VTMP/ref.txt"
        while read -r nh rel; do
            if ! awk -v p="$rel" '$2 == p { f = 1 } END { exit !f }' "$VTMP/ref.txt"; then
                extra=$((extra + 1))
                echo "NEW        $rel (produced by the rebuild, not in the reference manifest)"
            fi
        done < "$VTMP/new.txt"
        total=$((same + diff_n + missing))
        echo
        echo "reproducible: $same / $total files bit-for-bit identical"
        echo "different: $diff_n  missing: $missing  new: $extra  stale-in-bin: $stale"
        [[ $skipped_docker -gt 0 ]] && echo "not rebuilt (--no-docker): $skipped_docker glibc/system files"
        [[ $diff_n -eq 0 && $missing -eq 0 && $extra -eq 0 ]] && echo "VERIFY OK" || echo "VERIFY FAILED"
    } > "$REPORT"
    cat "$REPORT"
    if grep -q '^VERIFY OK$' "$REPORT"; then
        rm -rf "$VTMP"
        exit 0
    fi
    log "verify: rebuilt tree and report kept in $VTMP"
    exit 1
fi

# ---------------------------------------------------------------------------
# Build.
# ---------------------------------------------------------------------------
OUT="${OUT:-$BIN}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
GEN="$OUT/.gen"          # generated sources, logs, metadata (ignored by the tests)
GENSRC="$GEN/src"        # generated Rust sources
WORK="$GEN/work"         # rustc's working directory (fixed, remapped)
MANIFEST="$OUT/MANIFEST.txt"
ENTRIES="$GEN/entries.txt"
mkdir -p "$GEN" "$GENSRC"
: > "$ENTRIES"

# --- Toolchain: the one pinned in rust-toolchain.toml ----------------------
PINNED="$(sed -n 's/^channel *= *"\(.*\)".*/\1/p' "$REPO/rust-toolchain.toml" 2> /dev/null)"
if [[ -z "${RUSTC:-}" ]]; then
    # Resolve the real compiler binary (not the rustup proxy) from the repo
    # root, so the toolchain file applies even though rustc later runs in
    # directories outside the repository (--out, --verify).
    if command -v rustup > /dev/null 2>&1; then
        RUSTC="$(cd "$REPO" && rustup which rustc 2> /dev/null)" || {
            log "rustup cannot find toolchain $PINNED; run: (cd $REPO && rustup toolchain install)"
            exit 2
        }
    else
        RUSTC=rustc
    fi
fi
RUSTC_VV="$("$RUSTC" -vV)" || { log "cannot run $RUSTC"; exit 2; }
RELEASE="$(sed -n 's/^release: //p' <<< "$RUSTC_VV")"
if [[ -n "$PINNED" && "$RELEASE" != "$PINNED" ]]; then
    log "rustc release $RELEASE does not match rust-toolchain.toml channel $PINNED"
    exit 2
fi
SYSROOT="$("$RUSTC" --print sysroot)"
HOST="$(sed -n 's/^host: //p' <<< "$RUSTC_VV")"
LLD="$SYSROOT/lib/rustlib/$HOST/bin/rust-lld"
# rust-lld is linked against the toolchain's libLLVM shared library
# (@rpath/libLLVM.dylib on macOS, which its rpath does not find in a rustup
# install). The rustup proxy sets the library path for the toolchain's lib/;
# since the real rustc binary is called here, set it the same way, for rustc
# and for the rust-lld it spawns.
export DYLD_LIBRARY_PATH="$SYSROOT/lib" LD_LIBRARY_PATH="$SYSROOT/lib"
lld() { "$LLD" "$@"; }
LLD_VERSION="$(lld -flavor gnu --version 2>&1)" || { log "cannot run $LLD: $LLD_VERSION"; exit 2; }

# --- Docker image: pinned by digest ----------------------------------------
# rust:1.99.0-slim-bookworm, index digest
# sha256:2c3a22f0a5533ea2dd5a16627bc841228151faa2d4de2644ac9987e4a2f1f2fa;
# the digest below is that index's linux/amd64 manifest. A tag can be moved
# to a new image at any time, a digest cannot.
DOCKER_IMAGE="${DOCKER_IMAGE:-rust@sha256:ba81bc3eaa4422af576c0262515d96b0111a628a6ccc2c86557cf55c9a4bbee0}"
if [[ "$DOCKER_IMAGE" != *@sha256:* ]]; then
    log "DOCKER_IMAGE must be pinned by digest (name@sha256:...), got: $DOCKER_IMAGE"
    exit 2
fi

# Anything that changes the outputs without touching the sources forces a
# full rebuild: toolchain, linker, docker image, or this script's flags.
STAMP="$(printf '%s\n%s\n%s\n%s\n' "$RUSTC_VV" "$LLD_VERSION" "$DOCKER_IMAGE" "$(sha256 "$HERE/build.sh")")"
if [[ ! -f "$GEN/stamp" ]] || [[ "$(cat "$GEN/stamp")" != "$STAMP" ]]; then
    FORCE=1
fi

# Linking Linux executables on a non-Linux host: the toolchain's rust-lld by
# absolute path, explicit flavor (no inference from the name, no cc driver),
# plus the self-contained musl CRT objects/libc that ship with the musl targets.
LINK=(-C "linker=$LLD" -C linker-flavor=ld.lld -C link-self-contained=yes)
# Edition 2021 for every program: in 2024 `#[no_mangle]` must be spelled as an
# unsafe attribute, and this project keeps the `unsafe` keyword out entirely.
ED=(--edition 2021)
# Fixed virtual paths for everything that ends up in debug info or panic
# location strings. The three prefixes do not overlap.
REMAP=(--remap-path-prefix="$SRC=/unforge/src" --remap-path-prefix="$GENSRC=/unforge/gen"
       --remap-path-prefix="$WORK=/unforge/build")

ok=0
skipped=0
failed=0

# Print a command with machine-specific paths replaced by placeholders.
san() {
    local s="$*"
    s="${s//"$SYSROOT"/\$SYSROOT}"
    s="${s//"$OUT"/\$OUT}"
    s="${s//"$HERE"/testdata}"
    printf '%s' "$s"
}

# record <relative path> <description...>
record() {
    local rel="$1"; shift
    printf '%s\t%s\n' "$rel" "$*" >> "$ENTRIES"
}

# rb <out (relative to OUT)> <source file> <rustc args...>
# Builds one file with `rustc <args> <remaps> <source> -o <out>`.
rb() {
    local rel="$1" src="$2"; shift 2
    local out="$OUT/$rel"
    mkdir -p "$(dirname "$out")"
    local cmd=("$RUSTC" "$@" "${REMAP[@]}" "$src" -o "$out")
    local shown
    shown="$(san "rustc $* ${REMAP[*]} $src")"
    if [[ $FORCE -eq 0 && -f "$out" && "$out" -nt "$src" ]]; then
        skipped=$((skipped + 1))
        record "$rel" "$shown"
        return 0
    fi
    # rustc writes temporaries next to -o; keep them out of the corpus. The
    # working directory is always the same path (and remapped), because it is
    # recorded as DW_AT_comp_dir.
    rm -rf "$WORK"; mkdir -p "$WORK"
    if (cd "$WORK" && "${cmd[@]}" > "$GEN/rustc.log" 2>&1); then
        ok=$((ok + 1))
        record "$rel" "$shown"
    else
        failed=$((failed + 1))
        rm -f "$out"
        # A failed link leaves rustc's intermediate objects next to -o.
        rm -f "$(dirname "$out")"/*.rcgu.o
        log "FAILED: $rel"
        sed -n '1,15p' "$GEN/rustc.log" >&2
        printf 'FAILED\t%s\t%s\n' "$rel" "$shown" >> "$GEN/failed.txt"
    fi
}
: > "$GEN/failed.txt"

EXES=(collections enums traits panics ffi_statics)

# ---------------------------------------------------------------------------
# x86_64 musl executables (static-pie by default for this target).
# ---------------------------------------------------------------------------
T=x86_64-unknown-linux-musl
for p in "${EXES[@]}"; do
    for o in 0 1 3 s; do
        for g in 0 2; do
            rb "$T/$p-O$o-g$g" "$SRC/$p.rs" "${ED[@]}" --target $T "${LINK[@]}" \
                -C opt-level=$o -C debuginfo=$g -C strip=none
        done
    done
    rb "$T/$p-O3-g2-strip-debuginfo" "$SRC/$p.rs" "${ED[@]}" --target $T "${LINK[@]}" \
        -C opt-level=3 -C debuginfo=2 -C strip=debuginfo
    rb "$T/$p-O3-g2-strip-symbols" "$SRC/$p.rs" "${ED[@]}" --target $T "${LINK[@]}" \
        -C opt-level=3 -C debuginfo=2 -C strip=symbols
    rb "$T/$p-O0-g2-strip-symbols" "$SRC/$p.rs" "${ED[@]}" --target $T "${LINK[@]}" \
        -C opt-level=0 -C debuginfo=2 -C strip=symbols
    rb "$T/$p-O3-abort" "$SRC/$p.rs" "${ED[@]}" --target $T "${LINK[@]}" \
        -C opt-level=3 -C panic=abort
    rb "$T/$p-O0-abort" "$SRC/$p.rs" "${ED[@]}" --target $T "${LINK[@]}" \
        -C opt-level=0 -C panic=abort
    rb "$T/$p-O3-cgu1-lto" "$SRC/$p.rs" "${ED[@]}" --target $T "${LINK[@]}" \
        -C opt-level=3 -C codegen-units=1 -C lto=fat
    rb "$T/$p-O3-cgu1-thinlto-abort-strip" "$SRC/$p.rs" "${ED[@]}" --target $T "${LINK[@]}" \
        -C opt-level=3 -C codegen-units=1 -C lto=thin -C panic=abort -C strip=symbols
    rb "$T/$p-O0-g2-pie" "$SRC/$p.rs" "${ED[@]}" --target $T "${LINK[@]}" \
        -C opt-level=0 -C debuginfo=2 -C relocation-model=pie
    for o in 0 3; do
        rb "$T/$p-O$o-nopie" "$SRC/$p.rs" "${ED[@]}" --target $T "${LINK[@]}" \
            -C opt-level=$o -C relocation-model=static
    done
    rb "$T/$p-O3-nopie-strip-symbols" "$SRC/$p.rs" "${ED[@]}" --target $T "${LINK[@]}" \
        -C opt-level=3 -C relocation-model=static -C strip=symbols
done

# ---------------------------------------------------------------------------
# x86_64 glibc target: relocatable objects (no glibc needed to emit these).
# ---------------------------------------------------------------------------
T=x86_64-unknown-linux-gnu
for p in "${EXES[@]}"; do
    for o in 0 3; do
        for g in 0 2; do
            rb "$T/$p-O$o-g$g.o" "$SRC/$p.rs" "${ED[@]}" --target $T --emit=obj \
                -C codegen-units=1 -C opt-level=$o -C debuginfo=$g
        done
    done
    rb "$T/$p-Os-abort.o" "$SRC/$p.rs" "${ED[@]}" --target $T --emit=obj \
        -C codegen-units=1 -C opt-level=s -C panic=abort
done
for o in 0 3; do
    rb "$T/clib-O$o.o" "$SRC/clib.rs" "${ED[@]}" --target $T --crate-type cdylib --emit=obj \
        -C codegen-units=1 -C opt-level=$o
    rb "$T/nostd_core-O$o.o" "$SRC/nostd_core.rs" "${ED[@]}" --target $T --crate-type lib \
        --emit=obj -C codegen-units=1 -C opt-level=$o
done
# Linking a gnu cdylib needs glibc's libc.so, libgcc_s etc., which a macOS host
# does not have (rust-lld: "unable to find library -lgcc_s ... -lc"), and the
# musl target cannot link a cdylib with only the self-contained static musl
# either. Linked cdylibs are therefore built in docker below (glibc/libclib-*).

# ---------------------------------------------------------------------------
# ELF32: i686 musl executables (and objects).
# ---------------------------------------------------------------------------
T=i686-unknown-linux-musl
for p in "${EXES[@]}"; do
    for o in 0 3; do
        rb "$T/$p-O$o" "$SRC/$p.rs" "${ED[@]}" --target $T "${LINK[@]}" -C opt-level=$o
    done
    rb "$T/$p-O3-strip-symbols" "$SRC/$p.rs" "${ED[@]}" --target $T "${LINK[@]}" \
        -C opt-level=3 -C strip=symbols
    rb "$T/$p-O1-g2.o" "$SRC/$p.rs" "${ED[@]}" --target $T --emit=obj \
        -C codegen-units=1 -C opt-level=1 -C debuginfo=2
done

# ---------------------------------------------------------------------------
# aarch64 musl executables (a second EM_*, little-endian ELF64).
# ---------------------------------------------------------------------------
T=aarch64-unknown-linux-musl
for p in "${EXES[@]}"; do
    rb "$T/$p-O0" "$SRC/$p.rs" "${ED[@]}" --target $T "${LINK[@]}" -C opt-level=0
    rb "$T/$p-O3-strip-symbols" "$SRC/$p.rs" "${ED[@]}" --target $T "${LINK[@]}" \
        -C opt-level=3 -C strip=symbols
done

# ---------------------------------------------------------------------------
# Big-endian ELF64 objects.
# ---------------------------------------------------------------------------
for T in powerpc64-unknown-linux-gnu s390x-unknown-linux-gnu; do
    for o in 0 3; do
        rb "$T/nostd_core-O$o.o" "$SRC/nostd_core.rs" "${ED[@]}" --target $T --crate-type lib \
            --emit=obj -C codegen-units=1 -C opt-level=$o
        for p in collections enums traits; do
            rb "$T/$p-O$o.o" "$SRC/$p.rs" "${ED[@]}" --target $T --emit=obj \
                -C codegen-units=1 -C opt-level=$o -C debuginfo=2
        done
    done
done

# ---------------------------------------------------------------------------
# Extended section numbering (gABI ch4 "Sections": e_shnum == 0 and
# e_shstrndx == SHN_XINDEX with the real values in section header 0, plus
# SHT_SYMTAB_SHNDX for st_shndx). Needs > SHN_LORESERVE (0xff00 = 65280)
# sections. rustc puts every function in its own section on Linux targets
# (function sections are on by default there), so 70000 exported functions
# give ~70000 sections.
#
# LLVM's object writer places .strtab (its combined string table) at index 1,
# so rustc's own .o gets e_shnum == 0 but a *small* e_shstrndx. `ld.lld -r`
# re-emits the object with .shstrtab near the end, i.e. at an index >= 0xff00,
# which forces e_shstrndx == SHN_XINDEX as well. Both files are kept.
# ---------------------------------------------------------------------------
MANY="$GENSRC/many_sections.rs"
if [[ ! -f "$MANY" ]]; then
    {
        echo '//! Generated by testdata/build.sh: 70000 functions -> >65280 sections.'
        echo '#![no_std]'
        seq -f '%05g' 0 69999 | awk '{printf "#[no_mangle]\npub extern \"C\" fn manysec_%s() -> u32 { %d }\n", $1, NR}'
    } > "$MANY"
    touch -r "$HERE/build.sh" "$MANY" 2> /dev/null || true
fi
for T in x86_64-unknown-linux-gnu i686-unknown-linux-musl s390x-unknown-linux-gnu; do
    rb "ext-numbering/many_sections-$T.o" "$MANY" "${ED[@]}" --target $T --crate-type lib \
        --emit=obj -C codegen-units=1 -C opt-level=0
    in="$OUT/ext-numbering/many_sections-$T.o"
    rel="ext-numbering/many_sections-$T.relinked.o"
    out="$OUT/$rel"
    desc="\$SYSROOT/lib/rustlib/$HOST/bin/rust-lld -flavor gnu -r ext-numbering/many_sections-$T.o"
    if [[ -f "$in" ]]; then
        if [[ $FORCE -eq 1 || ! -f "$out" || "$in" -nt "$out" ]]; then
            if lld -flavor gnu -r "$in" -o "$out" 2> "$GEN/lld.log"; then
                ok=$((ok + 1)); record "$rel" "$desc"
            else
                failed=$((failed + 1)); cat "$GEN/lld.log" >&2
                printf 'FAILED\t%s\t%s\n' "$rel" "$desc" >> "$GEN/failed.txt"
            fi
        else
            skipped=$((skipped + 1)); record "$rel" "$desc"
        fi
    fi
done

# ---------------------------------------------------------------------------
# Link-line evidence: the exact linker invocation rustc used for each musl
# target (via --print link-args on a throwaway build), so MANIFEST.txt shows
# that rust-lld, not a host cc/ld, linked the executables.
# ---------------------------------------------------------------------------
LINKCHECK="$GEN/link-check"
rm -rf "$LINKCHECK"; mkdir -p "$LINKCHECK"
for T in x86_64-unknown-linux-musl i686-unknown-linux-musl aarch64-unknown-linux-musl; do
    rm -rf "$WORK"; mkdir -p "$WORK"
    (cd "$WORK" && "$RUSTC" "${ED[@]}" --target $T "${LINK[@]}" "${REMAP[@]}" --print link-args \
        "$SRC/enums.rs" -o "$LINKCHECK/enums-$T" > "$LINKCHECK/$T.txt" 2>&1) \
        || echo "LINK CHECK BUILD FAILED" >> "$LINKCHECK/$T.txt"
done
rm -rf "$WORK"

# ---------------------------------------------------------------------------
# Docker (linux/amd64): glibc-linked Rust binaries and real-world system ELF
# files. On an aarch64 host the container runs under user-mode amd64
# emulation (Docker Desktop: Rosetta or qemu-user via binfmt_misc), recorded
# in MANIFEST.txt. Inside the image, linking goes through the image's
# cc (gcc driver) and GNU ld; their versions are recorded too.
# ---------------------------------------------------------------------------
DOCKER_NOTE=""
DMETA="$GEN/docker"
if [[ $DOCKER -eq 1 ]] && command -v docker > /dev/null 2>&1 && docker info > /dev/null 2>&1; then
    if [[ $FORCE -eq 1 || ! -f "$DMETA/DONE" ]]; then
        rm -rf "$OUT/glibc" "$OUT/system" "$DMETA"
        mkdir -p "$OUT/glibc" "$OUT/system" "$DMETA"
        start=$(date +%s)
        if docker run --rm --platform linux/amd64 --network none \
            -v "$SRC:/src:ro" -v "$OUT/glibc:/out" -v "$OUT/system:/sys-out" -v "$DMETA:/meta" \
            "$DOCKER_IMAGE" bash -euo pipefail -c '
                export LC_ALL=C TZ=UTC
                mkdir -p /tmp/w && cd /tmp/w
                CC="$(command -v cc)"
                {
                    echo "uname -m: $(uname -m)"
                    emu="$(grep -o -m1 -E "/[^ ]*(rosetta|qemu)[^ ]*" /proc/self/maps || true)"
                    echo "emulator mapped into processes: ${emu:-none found (native or undetected)}"
                    echo "debian_version: $(cat /etc/debian_version)"
                    echo "cc: $CC -> $(readlink -f "$CC")"
                    echo "cc --version: $("$CC" --version | head -1)"
                    echo "ld --version: $(ld --version | head -1)"
                    echo "ldd --version: $(ldd --version | head -1)"
                    echo "dpkg:"
                    dpkg-query -W -f "  \${Package} \${Version}\n" gcc gcc-12 binutils libc6 libc6-dev libgcc-s1
                    echo "gcc passes to ld (from gcc -dumpspecs, build-id):"
                    if gcc -dumpspecs | grep -q -- "--build-id"; then echo "  --build-id (content hash)"; else echo "  no --build-id"; fi
                } > /meta/toolchain.txt
                rustc -vV > /meta/rustc-vV.txt
                R="rustc --edition 2021 -C linker=$CC --remap-path-prefix=/src=/unforge/src --remap-path-prefix=/tmp/w=/unforge/build"
                e() { printf "%s\t%s\n" "$1" "$2 (docker; x86_64-unknown-linux-gnu)" >> /meta/entries.txt; }
                for p in collections enums traits panics ffi_statics; do
                    for o in 0 3; do
                        $R -C opt-level=$o /src/$p.rs -o /out/$p-O$o
                        e glibc/$p-O$o "$R -C opt-level=$o src/$p.rs (dynamic glibc, PIE)"
                    done
                    $R -C opt-level=3 -C strip=symbols /src/$p.rs -o /out/$p-O3-strip-symbols
                    e glibc/$p-O3-strip-symbols "$R -C opt-level=3 -C strip=symbols src/$p.rs (dynamic glibc)"
                    $R -C opt-level=2 -C target-feature=+crt-static /src/$p.rs -o /out/$p-O2-crt-static
                    e glibc/$p-O2-crt-static "$R -C opt-level=2 -C target-feature=+crt-static src/$p.rs (static glibc)"
                done
                for o in 0 3; do
                    $R --crate-type cdylib -C opt-level=$o /src/clib.rs -o /out/libclib-O$o.so
                    e glibc/libclib-O$o.so "$R --crate-type cdylib -C opt-level=$o src/clib.rs"
                done
                $R --crate-type cdylib -C opt-level=3 -C strip=symbols /src/clib.rs -o /out/libclib-O3-strip.so
                e glibc/libclib-O3-strip.so "$R --crate-type cdylib -C opt-level=3 -C strip=symbols src/clib.rs"
                $R --crate-type dylib -C opt-level=1 -C prefer-dynamic /src/clib.rs -o /out/libclib-rust-dylib.so
                e glibc/libclib-rust-dylib.so "$R --crate-type dylib -C opt-level=1 -C prefer-dynamic src/clib.rs (Rust dylib, has .rustc)"
                # Real-world files. -L: copy symlink targets as regular files.
                s() { cp -L "$1" "/sys-out/$2"; printf "%s\t%s\n" "system/$2" "copied from $1 in the docker image" >> /meta/entries.txt; }
                s /bin/ls ls; s /bin/bash bash; s /usr/bin/env env; s /usr/bin/find find
                s /usr/bin/sort sort; s /usr/bin/tar tar
                s /lib/x86_64-linux-gnu/libc.so.6 libc.so.6
                s /lib64/ld-linux-x86-64.so.2 ld-linux-x86-64.so.2
                s /lib/x86_64-linux-gnu/libm.so.6 libm.so.6
                s /lib/x86_64-linux-gnu/libgcc_s.so.1 libgcc_s.so.1
                s /usr/lib/x86_64-linux-gnu/crt1.o crt1.o
                # Real-world Rust release binaries shipped by rustup itself.
                s "$(command -v rustup)" rustup
                s "$(rustc --print sysroot)/bin/cargo" cargo
                s "$(rustc --print sysroot)/bin/rustdoc" rustdoc
                touch /meta/DONE
            ' > "$GEN/docker.log" 2>&1; then
            log "docker part finished in $(( $(date +%s) - start ))s"
        else
            DOCKER_NOTE="docker part FAILED after $(( $(date +%s) - start ))s; see .gen/docker.log"
            log "$DOCKER_NOTE"
            tail -20 "$GEN/docker.log" >&2
        fi
    fi
    [[ -f "$DMETA/entries.txt" ]] && cat "$DMETA/entries.txt" >> "$ENTRIES"
else
    DOCKER_NOTE="docker part skipped (--no-docker or docker not available)"
    log "$DOCKER_NOTE"
fi

printf '%s\n' "$STAMP" > "$GEN/stamp"

# ---------------------------------------------------------------------------
# MANIFEST.txt
# ---------------------------------------------------------------------------
# Every regular file in OUT except .gen/ and the manifest itself, with its
# sha256 and the command recorded for it (or a marker if none was recorded).
FILES="$GEN/files.txt"
(cd "$OUT" && find . -path ./.gen -prune -o -type f ! -name MANIFEST.txt -print | sed 's|^\./||' | sort) > "$FILES"

{
    echo "# unforge test corpus manifest (generated by testdata/build.sh)"
    echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# Host: $(uname -sm)"
    echo "#"
    echo "# == Host compiler (every file not under glibc/ or system/) =="
    echo "# pinned by rust-toolchain.toml: channel = \"$PINNED\""
    sed 's/^/#   /' <<< "$RUSTC_VV"
    echo "# rust-src installed: $([[ -d "$SYSROOT/lib/rustlib/src/rust" ]] && echo yes || echo no)"
    echo "#"
    echo "# == Host linker (every host-built executable) =="
    echo "# rustc flags: $(san "${LINK[*]}")"
    echo "# \$SYSROOT/lib/rustlib/$HOST/bin/rust-lld -flavor gnu --version:"
    sed 's/^/#   /' <<< "$LLD_VERSION"
    echo "#   sha256 $(sha256 "$LLD")  rust-lld"
    [[ -f "$SYSROOT/lib/libLLVM.dylib" ]] && echo "#   sha256 $(sha256 "$SYSROOT/lib/libLLVM.dylib")  \$SYSROOT/lib/libLLVM.dylib"
    if [[ -x "$SYSROOT/lib/rustlib/$HOST/bin/gcc-ld/ld.lld" ]]; then
        echo "# gcc-ld/ld.lld --version: $(\
            "$SYSROOT/lib/rustlib/$HOST/bin/gcc-ld/ld.lld" --version 2>&1 | head -1) (not used: rust-lld is called directly)"
    fi
    echo "# Linker invocation rustc actually made (--print link-args, first lines):"
    for T in x86_64-unknown-linux-musl i686-unknown-linux-musl aarch64-unknown-linux-musl; do
        f="$LINKCHECK/$T.txt"
        # The line is `ENV=... "<linker>" "<arg>" ...`; the first quoted word
        # after the environment assignments is the program rustc executed.
        line="$(tr ' ' '\n' < "$f" | awk '/^"/ && !n { n = 3 } n { printf "%s ", $0; if (!--n) exit }')"
        if [[ "$line" == "\"$LLD\" \"-flavor\" \"gnu\" " ]]; then
            verdict="OK: rust-lld from the pinned toolchain"
        else
            verdict="CHECK FAILED: linker is not the pinned rust-lld"
        fi
        echo "#   $T: $(san "$line")-> $verdict"
        objs="$(grep -oE 'self-contained/[A-Za-z0-9_]+\.o' "$f" | sed 's|self-contained/||' | tr '\n' ' ')"
        echo "#     CRT objects on the link line: $objs"
    done
    echo "# Self-contained musl CRT objects and libraries shipped with the targets"
    echo "# (rust-std component; linked into every host-built executable):"
    for T in x86_64-unknown-linux-musl i686-unknown-linux-musl aarch64-unknown-linux-musl; do
        for f in "$SYSROOT/lib/rustlib/$T/lib/self-contained/"*; do
            [[ -f "$f" ]] && echo "#   sha256 $(sha256 "$f")  \$SYSROOT/lib/rustlib/$T/lib/self-contained/$(basename "$f")"
        done
    done
    echo "# (the musl release of that libc.a is not recorded by the toolchain and is not verified here)"
    echo "#"
    echo "# == Docker (glibc/*, system/*) =="
    if [[ -f "$DMETA/rustc-vV.txt" ]]; then
        echo "# image: $DOCKER_IMAGE (platform linux/amd64)"
        id="$(docker image inspect --format '{{.Id}}' "$DOCKER_IMAGE" 2> /dev/null || true)"
        [[ -n "$id" ]] && echo "# docker image inspect .Id: $id"
        echo "# Verdicts and binaries from this part come from the amd64 user-mode"
        echo "# emulator inside Docker Desktop, not from a native x86_64 kernel."
        sed 's/^/#   /' "$DMETA/toolchain.txt"
        echo "# rustc -vV in the image (compiler for glibc/*; system/* are copied from the image):"
        sed 's/^/#   /' "$DMETA/rustc-vV.txt"
    fi
    [[ -n "$DOCKER_NOTE" ]] && echo "# NOTE: $DOCKER_NOTE"
    echo "#"
    echo "# == Inputs =="
    for f in "$SRC"/*.rs; do echo "#   sha256 $(sha256 "$f")  src/$(basename "$f")"; done
    echo "#   sha256 $(sha256 "$MANY")  .gen/src/many_sections.rs (generated)"
    echo "#   sha256 $(sha256 "$HERE/build.sh")  build.sh"
    leaks="$(cd "$OUT" && grep -lF -e "$HOME" -e "$HERE" -e "$OUT" $(cat "$FILES") 2> /dev/null | tr '\n' ' ')"
    echo "#"
    echo "# Files embedding a host path (\$HOME, testdata/ or \$OUT): ${leaks:-none}"
    echo "#"
    echo "# Format: <sha256>\t<path relative to the output dir>\t<exact command>"
    echo "# Paths in commands: testdata/ = this directory, \$SYSROOT = the toolchain"
    echo "# sysroot, \$OUT = the output directory. Lines starting with FAILED were"
    echo "# attempted but did not build on this host (no file, no hash)."
    echo
    while IFS= read -r rel; do
        cmd="$(awk -F'\t' -v p="$rel" '$1 == p { sub(/^[^\t]*\t/, ""); print; exit }' "$ENTRIES")"
        printf '%s\t%s\t%s\n' "$(sha256 "$OUT/$rel")" "$rel" "${cmd:-(no command recorded: stale file?)}"
    done < "$FILES"
    sort "$GEN/failed.txt"
} > "$MANIFEST"

log "built=$ok up-to-date=$skipped failed=$failed; manifest: $MANIFEST"
exit 0

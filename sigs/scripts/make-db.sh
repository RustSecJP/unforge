#!/usr/bin/env bash
# Build one fingerprint database from many ELF files with symbols.
#
# Usage: sigs/scripts/make-db.sh <unforge> <out.db> <stats.tsv> <list>
#   <unforge>    the unforge binary built from this checkout (job `tools`)
#   <list>       file with one input path per line
#   <stats.tsv>  written: one line per input: path, status (ok / failed),
#                named functions, fingerprints added
#
# `unforge sig build` refuses to write anything when one input cannot be
# used, so every input gets its own database first and the good ones are
# merged. Prints `fingerprints=<n>` and `bytes=<n>` of the result on stdout.
# Exit status 1 when no input could be used.
#
# Only reads the inputs (unforge parses them; nothing is executed), so it
# is safe on untrusted executables.

set -uo pipefail
export LC_ALL=C

UNFORGE="${1:?unforge}"; OUT="${2:?out.db}"; STATS="${3:?stats.tsv}"; LIST="${4:?list}"
PARTS="$(mktemp -d)"
trap 'rm -rf "$PARTS"' EXIT
: > "$STATS"

n=0
while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    n=$((n + 1))
    part="$PARTS/$(printf '%06d' "$n").db"
    if "$UNFORGE" sig build -o "$part" -- "$f" 2> "$PARTS/log"; then
        # "unforge: <file>: note: <added> of <named> named functions added (...)"
        read -r added named < <(sed -n 's/.*note: \([0-9]*\) of \([0-9]*\) named functions added.*/\1 \2/p' "$PARTS/log" | tail -1)
        printf '%s\tok\t%s\t%s\n' "$f" "${named:-0}" "${added:-0}" >> "$STATS"
    else
        printf '%s\tfailed\t0\t0\n' "$f" >> "$STATS"
        sed -n '1,5p' "$PARTS/log" >&2
        rm -f "$part"
    fi
done < "$LIST"

parts=("$PARTS"/*.db)
if [[ ! -e "${parts[0]}" ]]; then
    echo "make-db.sh: no usable input in $LIST" >&2
    exit 1
fi
if ! "$UNFORGE" sig build -o "$OUT" -- "${parts[@]}" 2> "$PARTS/log"; then
    cat "$PARTS/log" >&2
    exit 1
fi
# "unforge: <out>: note: <n> fingerprints, <b> bytes"
sed -n 's/.*note: \([0-9]*\) fingerprints, \([0-9]*\) bytes$/fingerprints=\1\nbytes=\2/p' "$PARTS/log" | tail -2

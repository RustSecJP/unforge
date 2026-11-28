#!/usr/bin/env bash
# Turn the executables of one crate (from sigs/scripts/build-crate.sh, job
# `crate-build`) into its fingerprint database.
#
# Usage: sigs/scripts/crate-db.sh <unforge> <in-dir> <out-dir> <crate> <version> <rustc>
#   <in-dir>   the `crate-bins-<id>` artifact (may be missing or empty)
# Output:
#   <out>/<crate>-<version>-rustc<rustc>.db     when anything could be used
#   <out>/<crate>-<version>-rustc<rustc>.json   status for the summary
# Always exits 0.
#
# The input was produced by a job that ran third-party code, so it is
# untrusted: the executables are only parsed by unforge (never run), the
# crate, version and rustc come from the workflow matrix (not from the
# artifact), and only validated fields of its status.json are used.

set -uo pipefail
export LC_ALL=C

UNFORGE="${1:?unforge}"; IN="${2:?in dir}"; OUT="${3:?out dir}"
CRATE="${4:?crate}"; VERSION="${5:?version}"; R="${6:?rustc}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ID="$CRATE-$VERSION-rustc$R"
mkdir -p "$OUT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

: > "$WORK/list"
if [[ -d "$IN/bin" ]]; then
    # Regular files only (no symlinks out of the artifact).
    find "$IN/bin" -type f | sort > "$WORK/list"
fi
res=""
if [[ -s "$WORK/list" ]]; then
    res="$(bash "$HERE/make-db.sh" "$UNFORGE" "$OUT/$ID.db" "$WORK/stats.tsv" "$WORK/list")"
fi
fps="$(sed -n 's/^fingerprints=//p' <<< "$res")"
bytes="$(sed -n 's/^bytes=//p' <<< "$res")"
named=0; usable=0
if [[ -f "$WORK/stats.tsv" ]]; then
    named="$(awk -F'\t' '$2 == "ok" { s += $3 } END { print s + 0 }' "$WORK/stats.tsv")"
    usable="$(awk -F'\t' '$2 == "ok" { n++ } END { print n + 0 }' "$WORK/stats.tsv")"
fi

python3 -I - "$IN/status.json" "$OUT/$ID.json" "$CRATE" "$VERSION" "$R" \
    "$(wc -l < "$WORK/list")" "$usable" "$named" "${fps:-0}" "${bytes:-0}" "$ID.db" << 'PY'
import json, re, sys
src, out, crate, version, rustc, files, usable, named, fps, size, db = sys.argv[1:]
build, attempts, commit = "missing", {}, ""
try:
    with open(src, encoding="utf-8") as f:
        s = json.load(f)
    # Untrusted: keep only values of a known shape.
    build = s.get("status") if s.get("status") in ("ok", "failed") else "invalid"
    if re.fullmatch(r"[0-9a-f]{40}", str(s.get("rustc_commit", ""))):
        commit = s["rustc_commit"]
    for name, p in dict(s.get("profiles", {})).items():
        a = str(p.get("attempt", ""))
        if re.fullmatch(r"[a-z0-9]{1,16}", str(name)) and re.fullmatch(r"[A-Za-z0-9 ,_+./-]{0,256}", a):
            attempts[name] = a
except (OSError, ValueError, AttributeError, TypeError):
    pass
fps = int(fps)
if fps > 0:
    status = "ok"
elif build == "missing":
    status = "no build artifact"
elif build == "failed":
    status = "build failed"
else:
    status = "no fingerprints"
with open(out, "w") as f:
    json.dump({"crate": crate, "version": version, "rustc": rustc,
               "rustc_commit": commit, "status": status, "build": build,
               "attempts": attempts, "executables": int(files),
               "usable": int(usable), "named": int(named),
               "fingerprints": fps, "bytes": int(size),
               "db": db if fps > 0 else None}, f, indent=2)
    f.write("\n")
PY
echo "$ID: $(wc -l < "$WORK/list") executables, ${fps:-0} fingerprints" >&2
exit 0

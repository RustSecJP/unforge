#!/usr/bin/env python3
"""Summaries of the fingerprint databases built by .github/workflows/sigs.yml.

  summary.py std DIR      reads DIR/std-*.json (sigs/scripts/build-std.sh),
                          writes DIR/TOOLCHAINS.tsv (release -> rustc commit
                          -> database) and prints a Markdown table
  summary.py crates DIR   reads DIR/*-rustc*.json (sigs/scripts/crate-db.sh),
                          writes DIR/CRATES.tsv and prints a Markdown table

Only reads JSON; never runs anything.
"""

import glob
import json
import os
import sys


def cell(v):
    return str(v).replace("|", "\\|").replace("\n", " ")


def table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(cell(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def mb(n):
    return f"{n / 1e6:.1f} MB"


def std(d):
    rows, tsv = [], ["release\trustc_commit\tcommit_date\tllvm\tdb\tfingerprints\tbytes"]
    items = []
    for p in glob.glob(os.path.join(d, "std-*.json")):
        with open(p, encoding="utf-8") as f:
            items.append(json.load(f))
    items.sort(key=lambda s: tuple(int(x) for x in s["release"].split(".")))
    for s in items:
        rows.append([s["release"], f"`{s['rustc_commit_short']}`", s["commit_date"], s["llvm"],
                     s["executables"], s["failed_variants"], s["fingerprints"], mb(s["bytes"]),
                     s["db"] or "(none)"])
        tsv.append("\t".join(str(s[k] if s[k] is not None else "") for k in
                             ("release", "rustc_commit", "commit_date", "llvm", "db",
                              "fingerprints", "bytes")))
    with open(os.path.join(d, "TOOLCHAINS.tsv"), "w", encoding="utf-8") as f:
        f.write("\n".join(tsv) + "\n")
    print("## std fingerprint databases\n")
    print(table(["release", "rustc commit", "date", "LLVM", "executables", "failed variants",
                 "fingerprints", "size", "database"], rows))


def crates(d):
    rows, tsv = [], ["crate\tversion\trustc\tstatus\texecutables\tfingerprints\tbytes\tdb"]
    items = []
    for p in glob.glob(os.path.join(d, "*-rustc*.json")):
        with open(p, encoding="utf-8") as f:
            items.append(json.load(f))
    items.sort(key=lambda s: (s["crate"], s["version"], s["rustc"]))
    ok = sum(1 for s in items if s["status"] == "ok")
    for s in items:
        attempts = "; ".join(f"{k}: {v}" for k, v in sorted(s["attempts"].items()))
        rows.append([s["crate"], s["version"], s["rustc"], s["executables"],
                     s["named"], s["fingerprints"], mb(s["bytes"]), s["status"],
                     attempts or "-"])
        tsv.append("\t".join(str(s[k] if s[k] is not None else "") for k in
                             ("crate", "version", "rustc", "status", "executables",
                              "fingerprints", "bytes", "db")))
    with open(os.path.join(d, "CRATES.tsv"), "w", encoding="utf-8") as f:
        f.write("\n".join(tsv) + "\n")
    print(f"## crate fingerprint databases ({ok} of {len(items)} built)\n")
    print(table(["crate", "version", "rustc", "binaries", "named functions (sum over binaries)",
                 "functions added (fingerprints)", "size", "status", "cargo arguments"], rows))


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("std", "crates"):
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    (std if sys.argv[1] == "std" else crates)(sys.argv[2])


if __name__ == "__main__":
    main()

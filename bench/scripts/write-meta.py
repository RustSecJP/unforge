#!/usr/bin/env python3
"""Write <id>.meta.json for one corpus item (see crates/unforge-bench/src/model.rs).

Usage:
  write-meta.py --out FILE --id ID --crate NAME --version VER --bin BIN \
      --source crates.io|testdata --target TRIPLE \
      --variant NAME --opt-level L --lto off|fat|thin --panic unwind|abort \
      --debug FILE --stripped FILE --rustc-vv FILE [--cargo-lock FILE]

Only reads the files it is given; never runs anything.
"""

import argparse
import hashlib
import json


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser()
    for a in ("out", "id", "crate", "version", "bin", "source", "target", "variant",
              "opt-level", "lto", "panic", "debug", "stripped", "rustc-vv"):
        p.add_argument("--" + a, required=True)
    p.add_argument("--cargo-lock")
    p.add_argument("--codegen-units", type=int, default=1)
    p.add_argument("--debuginfo", type=int, default=2)
    a = p.parse_args()
    lock = None
    if a.cargo_lock:
        with open(a.cargo_lock, encoding="utf-8", errors="replace") as f:
            lock = f.read()
    with open(a.rustc_vv, encoding="utf-8", errors="replace") as f:
        rustc = f.read()
    meta = {
        "schema": "unforge-bench-meta/1",
        "id": a.id,
        "crate": a.crate,
        "version": a.version,
        "bin": a.bin,
        "source": a.source,
        "target": a.target,
        "variant": {
            "name": a.variant,
            "opt_level": a.opt_level,
            "lto": a.lto,
            "panic": a.panic,
            "codegen_units": a.codegen_units,
            "debug": a.debuginfo,
        },
        "rustc": rustc,
        "sha256": {"debug": sha256(a.debug), "stripped": sha256(a.stripped)},
        "cargo_lock": lock,
    }
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()

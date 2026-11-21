#!/usr/bin/env python3
"""Read bench/corpus.toml for the corpus workflow (needs Python 3.11+, tomllib).

  corpus.py SPEC matrix     JSON list of {"name", "version"} for the build matrix
  corpus.py SPEC variants   one line per enabled variant: name opt_level lto panic
  corpus.py SPEC targets    one target triple per line
  corpus.py SPEC common     KEY=VALUE lines (codegen_units, debug, strip)

Only parses the file; never runs anything.
"""

import json
import re
import sys
import tomllib

NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$")
VARIANT_VALUE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def fail(msg):
    print(f"corpus.py: {msg}", file=sys.stderr)
    sys.exit(2)


def main():
    if len(sys.argv) != 3:
        fail(__doc__)
    with open(sys.argv[1], "rb") as f:
        spec = tomllib.load(f)
    what = sys.argv[2]
    if what == "matrix":
        out = []
        for c in spec.get("crate", []):
            name, version = c.get("name", ""), c.get("version", "")
            # Values end up in shell commands and artifact names: be strict.
            if not NAME.match(name) or not VERSION.match(version):
                fail(f"bad crate entry {c!r} (exact versions only)")
            out.append({"name": name, "version": version})
        print(json.dumps(out))
    elif what == "variants":
        for v in spec.get("variant", []):
            if not v.get("enabled", True):
                continue
            vals = [str(v.get(k, "")) for k in ("name", "opt_level", "lto", "panic")]
            if not all(VARIANT_VALUE.match(x) for x in vals):
                fail(f"bad variant {v!r}")
            print(" ".join(vals))
    elif what == "targets":
        for t in spec.get("targets", []):
            if not VARIANT_VALUE.match(t.replace("_", "-").replace(".", "-")):
                fail(f"bad target {t!r}")
            print(t)
    elif what == "common":
        for k, v in spec.get("common", {}).items():
            if not VARIANT_VALUE.match(str(v)):
                fail(f"bad common value {k}={v!r}")
            print(f"{k}={v}")
    else:
        fail(f"unknown query {what!r}")


if __name__ == "__main__":
    main()

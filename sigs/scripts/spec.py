#!/usr/bin/env python3
"""Read sigs/toolchains.txt and sigs/crates.toml for .github/workflows/sigs.yml
(needs Python 3.11+, tomllib).

  spec.py toolchains TOOLCHAINS RUST_TOOLCHAIN_TOML
                                  JSON list of releases; fails if the release
                                  pinned in rust-toolchain.toml is missing
  spec.py crates CRATES           JSON list of {"name", "version", "rustc", "id"}
  spec.py profiles CRATES         one line per enabled profile: name opt_level
  spec.py crate-opts CRATES NAME VERSION
                                  `features=<list>` and `env=<KEY>=<VALUE>` lines

Only parses the files; never runs anything. Every value ends up in shell
commands, cargo arguments or artifact names, so all of them are checked
against strict patterns.
"""

import json
import re
import sys
import tomllib

RELEASE = re.compile(r"^1\.[0-9]{1,3}\.[0-9]{1,3}$")
NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$")
FEATURES = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_+./-]*(,[A-Za-z0-9_][A-Za-z0-9_+./-]*)*$")
ENV_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
ENV_VALUE = re.compile(r"^[A-Za-z0-9._-]{0,128}$")
PROFILE_NAME = re.compile(r"^[a-z0-9]{1,16}$")
OPT_LEVEL = re.compile(r"^[0-3sz]$")
# Environment variables that would change how cargo or rustc runs.
ENV_DENY = re.compile(r"^(CARGO|RUST|RUSTUP|LD_|PATH$|HOME$)")


def fail(msg):
    print(f"spec.py: {msg}", file=sys.stderr)
    sys.exit(2)


def load(path):
    with open(path, "rb") as f:
        spec = tomllib.load(f)
    if spec.get("schema") != "unforge-sigs-crates/1":
        fail(f"{path}: unknown schema {spec.get('schema')!r}")
    return spec


def releases(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if not RELEASE.match(line):
                fail(f"{path}: bad release {line!r} (exact stable releases only)")
            if line in out:
                fail(f"{path}: duplicate release {line}")
            out.append(line)
    return out


def pinned(path):
    with open(path, "rb") as f:
        return tomllib.load(f).get("toolchain", {}).get("channel", "")


def crates(spec):
    rustcs = spec.get("rustc", [])
    if not rustcs or not all(RELEASE.match(str(r)) for r in rustcs):
        fail(f"bad rustc list {rustcs!r}")
    out, seen = [], set()
    for c in spec.get("crate", []):
        name, version = c.get("name", ""), c.get("version", "")
        if not NAME.match(name) or not VERSION.match(version):
            fail(f"bad crate entry {c!r} (exact versions only)")
        if (name, version) in seen:
            fail(f"duplicate crate entry {name} {version}")
        seen.add((name, version))
        opts(c)
        for r in rustcs:
            out.append({"name": name, "version": version, "rustc": r,
                        "id": f"{name}-{version}-rustc{r}"})
    return out


def opts(c):
    lines = []
    features = c.get("features")
    if features is not None:
        if not isinstance(features, str) or not FEATURES.match(features):
            fail(f"bad features {features!r} for {c.get('name')}")
        lines.append(f"features={features}")
    for k, v in c.get("env", {}).items():
        v = str(v)
        if not ENV_KEY.match(k) or ENV_DENY.match(k) or not ENV_VALUE.match(v):
            fail(f"bad env {k}={v!r} for {c.get('name')}")
        lines.append(f"env={k}={v}")
    for k in c:
        if k not in ("name", "version", "features", "env"):
            fail(f"unknown key {k!r} for {c.get('name')}")
    return lines


def main():
    a = sys.argv[1:]
    if len(a) == 3 and a[0] == "toolchains":
        rel = releases(a[1])
        pin = pinned(a[2])
        if pin not in rel:
            fail(f"{a[1]} does not contain the pinned toolchain {pin!r} of {a[2]}")
        print(json.dumps(rel))
    elif len(a) == 2 and a[0] == "crates":
        print(json.dumps(crates(load(a[1]))))
    elif len(a) == 2 and a[0] == "profiles":
        for p in load(a[1]).get("profile", []):
            if not p.get("enabled", True):
                continue
            name, opt = str(p.get("name", "")), str(p.get("opt_level", ""))
            if not PROFILE_NAME.match(name) or not OPT_LEVEL.match(opt):
                fail(f"bad profile {p!r}")
            print(name, opt)
    elif len(a) == 4 and a[0] == "crate-opts":
        for c in load(a[1]).get("crate", []):
            if c.get("name") == a[2] and c.get("version") == a[3]:
                print("\n".join(opts(c)))
                return
        fail(f"no crate entry {a[2]} {a[3]}")
    else:
        fail(__doc__)


if __name__ == "__main__":
    main()

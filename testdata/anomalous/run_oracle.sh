#!/bin/sh
# Run every file in testdata/anomalous/files under Linux and record what the
# loader did, in testdata/anomalous/verdicts.tsv.
#
#   testdata/anomalous/run_oracle.sh            # regenerate files, snapshot binfmt_misc, run all
#   ORACLE_KEEP_BINFMT=1 run_oracle.sh          # reuse the committed binfmt_misc.txt snapshot
#
# The files are hostile by design. They are NEVER executed on the host: each
# one runs in its own throw-away container with no network, a read-only root
# file system, a read-only bind mount of that single file, no capabilities,
# no-new-privileges, a pid and memory limit, a non-root user and a hard
# timeout. The only process started directly on a file is the probe
# (probe/probe.rs), which execve()s it and classifies the outcome.
#
# Which loader produced a verdict (README.md, "Kernel or emulator"):
# - The container shares the HOST kernel (Docker Desktop's linuxkit VM), so
#   the image digest does not pin the kernel; `uname -r`/`uname -m` are
#   recorded per row.
# - "kernel": the file's architecture equals the host kernel's, the container
#   is native, and no binfmt_misc entry matches the file. Only then did
#   fs/binfmt_elf.c decide.
# - "emulator:<entries>": a foreign-architecture container (the probe itself
#   is emulated) or a binfmt_misc entry matches the file, so qemu-user or
#   Rosetta loaded it. Such verdicts are NOT kernel verdicts.
#   "emulator:unmatched" is a foreign-architecture file that no binfmt_misc
#   entry claims: the host (aarch64) kernel refused or ran it as a foreign
#   machine, which says nothing about a native kernel of that architecture.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
work=$repo/target/anomalous-oracle
mkdir -p "$work"

# Pinned image: debian:bookworm-slim, multi-arch index
# sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc.
# Each platform is pinned by its own manifest digest so a re-tagged index
# cannot change what runs.
IMAGE_INDEX=debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
IMAGE_ARM64=debian@sha256:ec8534cda2cb30f29f44f23e135297af7a1496f2990fd8e4e84aa36b081a757a
IMAGE_AMD64=debian@sha256:c67e92c8099ba22853ab4cfda7cfb494d253d6012ca82dee98ba8976772af018

PROBE_TIMEOUT_MS=3000
HARD_TIMEOUT_S=30

image_for() { case $1 in aarch64) echo "$IMAGE_ARM64" ;; x86_64) echo "$IMAGE_AMD64" ;; esac; }
platform_for() { case $1 in aarch64) echo linux/arm64 ;; x86_64) echo linux/amd64 ;; esac; }

# --- 1. build the probe and the generator, regenerate the corpus -------------
for arch in aarch64 x86_64; do
  rustc --edition 2024 --target "$arch-unknown-linux-musl" \
    -C linker=rust-lld -C link-self-contained=yes \
    -C opt-level=s -C panic=abort -C strip=symbols \
    "$here/probe/probe.rs" -o "$work/probe-$arch"
done
(cd "$repo" && cargo build -q -p unforge-testgen)
testgen=$repo/target/debug/unforge-testgen
"$testgen" generate --root "$repo"

docker_server=$(docker version --format '{{.Server.Version}}')
case $(docker version --format '{{.Server.Arch}}') in
  arm64|aarch64) native=aarch64 ;;
  amd64|x86_64) native=x86_64 ;;
  *) echo "unsupported docker server architecture" >&2; exit 1 ;;
esac

# --- 2. snapshot binfmt_misc --------------------------------------------------
# Needs a privileged container to mount binfmt_misc. No test file is mounted
# into it; it only reads the handler table.
snapshot=$here/binfmt_misc.txt
if [ "${ORACLE_KEEP_BINFMT:-0}" != 1 ]; then
  docker run --rm --platform "$(platform_for "$native")" --network none --privileged \
    "$(image_for "$native")" sh -c '
      mount -t binfmt_misc none /proc/sys/fs/binfmt_misc 2>/dev/null || true
      cd /proc/sys/fs/binfmt_misc || exit 1
      for f in *; do
        case $f in register|status) continue ;; esac
        echo "### $f"; cat "$f"
      done' > "$snapshot.tmp"
  mv "$snapshot.tmp" "$snapshot"
fi
snapshot_sha=$(shasum -a 256 "$snapshot" | cut -d' ' -f1)

# --- 3. the host kernel, as seen from a native container ----------------------
kinfo=$(docker run --rm --platform "$(platform_for "$native")" --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 \
  "$(image_for "$native")" sh -c 'uname -r; uname -m')
kernel_r=$(echo "$kinfo" | sed -n 1p)
kernel_m=$(echo "$kinfo" | sed -n 2p)

# --- 4. run every file --------------------------------------------------------
run_one() { # run_one <arch> <file> <outfile>
  arch=$1; file=$2; out=$3
  cname=unforge-oracle-$$-$(basename "$file" .elf)-$arch
  docker run --rm --name "$cname" \
    --platform "$(platform_for "$arch")" \
    --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 16 --memory 64m --memory-swap 64m --cpus 1 \
    --ulimit core=0 --ulimit nofile=64 \
    --user 65534:65534 \
    -v "$work/probe-$arch:/oracle/probe:ro" \
    -v "$file:/oracle/target:ro" \
    --entrypoint /bin/sh \
    "$(image_for "$arch")" \
    -c "uname -r; uname -m; exec /oracle/probe /oracle/target $PROBE_TIMEOUT_MS" \
    > "$out" 2>&1 < /dev/null &
  pid=$!
  waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$waited" -ge "$HARD_TIMEOUT_S" ]; then
      docker kill "$cname" >/dev/null 2>&1 || true
      echo "verdict=timeout" >> "$out"
      echo "detail=hard timeout ${HARD_TIMEOUT_S}s, container killed" >> "$out"
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done
  wait "$pid" 2>/dev/null || true
}

tsv=$here/verdicts.tsv
tmp=$tsv.tmp
{
  echo "# unforge anomalous-ELF oracle verdicts. Generated by run_oracle.sh; do not edit."
  echo "# kernel_uname_r=$kernel_r"
  echo "# kernel_uname_m=$kernel_m"
  echo "# docker_server=$docker_server"
  echo "# image_index=$IMAGE_INDEX"
  echo "# image.linux/arm64=$IMAGE_ARM64"
  echo "# image.linux/amd64=$IMAGE_AMD64"
  echo "# binfmt_misc_snapshot=binfmt_misc.txt sha256=$snapshot_sha"
  echo "# probe=probe/probe.rs timeout_ms=$PROBE_TIMEOUT_MS"
  echo "# date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# source=kernel means: native container, file arch = kernel arch, no binfmt_misc match."
  printf 'path\tsha256\tarch\ttechnique\tsource\tuname_r\tverdict\tdetail\n'
} > "$tmp"

grep -v '^#' "$here/files/MANIFEST.tsv" | while IFS="$(printf '\t')" read -r rel arch name technique seed size what; do
  file=$here/$rel
  out=$work/out.txt
  : > "$out"
  run_one "$arch" "$file" "$out"
  uname_r=$(sed -n 1p "$out")
  uname_m=$(sed -n 2p "$out")
  verdict=$(sed -n 's/^verdict=//p' "$out" | tail -1)
  detail=$(sed -n 's/^detail=//p' "$out" | tail -1)
  hint=$(sed -n 's/^emulator_hint=//p' "$out" | tail -1)
  if [ -z "$verdict" ]; then
    verdict=oracle_error
    detail=$(tr '\n\t' '  ' < "$out" | cut -c1-200)
  fi
  match=$("$testgen" binfmt-match "$snapshot" "$file")
  if [ "$arch" = "$native" ] && [ "$match" = none ]; then
    source=kernel
  else
    if [ "$match" = none ]; then match=unmatched; fi
    source=emulator:$match
  fi
  sha=$(shasum -a 256 "$file" | cut -d' ' -f1)
  detail="uname_m=$uname_m; probe_under=$hint; $detail"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$rel" "$sha" "$arch" "$name" "$source" "$uname_r" "$verdict" "$(printf '%s' "$detail" | tr '\t' ' ')" >> "$tmp"
  printf '%-8s %-50s %-24s %s\n' "$arch" "$name" "$source" "$verdict" >&2
done
mv "$tmp" "$tsv"
echo "wrote $tsv" >&2

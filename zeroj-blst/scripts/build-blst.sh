#!/usr/bin/env bash
#
# ADR-0029 M9 — build libblst from source and stage it for the FFM binding.
#
# supranational/blst ships NO precompiled release binaries (source only), so zeroj-blst builds its
# own, pinned to a known tag. This produces the shared library the FFM binding (BlstFfm) loads and
# copies it into src/main/resources/native/<os>/<arch>/libblst.<ext>.
#
# Usage:
#   scripts/build-blst.sh                # build for the current OS/arch
#   BLST_TAG=v0.3.15 BLST_COMMIT=<40-hex> scripts/build-blst.sh
#
# The source is pinned by commit hash (ADR-0062 D6): the clone fails unless the tag resolves to
# BLST_COMMIT. The tag is only a label. Overriding BLST_TAG requires overriding BLST_COMMIT too.
#
# Requirements: git, a C toolchain (clang/gcc). Cross-arch builds run in CI per runner (see
# .github/workflows/build-blst.yml); locally this builds only the host arch.
set -euo pipefail

DEFAULT_BLST_TAG="v0.3.15"
DEFAULT_BLST_COMMIT="6d960cd05d6fe2b5bc9ba161edf0c1a131b87c4c"   # supranational/blst v0.3.15
BLST_TAG="${BLST_TAG:-$DEFAULT_BLST_TAG}"
if [ -z "${BLST_COMMIT:-}" ]; then
  if [ "$BLST_TAG" != "$DEFAULT_BLST_TAG" ]; then
    echo "BLST_TAG=$BLST_TAG needs a matching BLST_COMMIT (40-hex commit hash)" >&2
    exit 1
  fi
  BLST_COMMIT="$DEFAULT_BLST_COMMIT"
fi
if ! [[ "$BLST_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "BLST_COMMIT must be a 40-hex commit hash, got: $BLST_COMMIT" >&2
  exit 1
fi
HERE="$(cd "$(dirname "$0")/.." && pwd)"          # zeroj-blst/
RES="$HERE/src/main/resources/native"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---- host os/arch → our resource layout ----
uname_s="$(uname -s)"; uname_m="$(uname -m)"
case "$uname_s" in
  Darwin) OS=mac;   EXT=dylib ;;
  Linux)  OS=linux; EXT=so ;;
  *)      echo "Unsupported OS: $uname_s (use CI for Windows)"; exit 1 ;;
esac
case "$uname_m" in
  arm64|aarch64) ARCH=aarch64 ;;
  x86_64|amd64)  ARCH=$([ "$OS" = mac ] && echo x86_64 || echo amd64) ;;
  *) echo "Unsupported arch: $uname_m"; exit 1 ;;
esac

echo ">> Building libblst $BLST_TAG ($BLST_COMMIT) for $OS/$ARCH"
git clone --depth 1 -b "$BLST_TAG" https://github.com/supranational/blst "$WORK/blst"
cd "$WORK/blst"
ACTUAL_COMMIT="$(git rev-parse HEAD)"
if [ "$ACTUAL_COMMIT" != "$BLST_COMMIT" ]; then
  echo "blst tag $BLST_TAG resolved to $ACTUAL_COMMIT, expected $BLST_COMMIT; refusing to build" >&2
  exit 1
fi
./build.sh                                         # -> libblst.a (static)

# ---- link the static archive into a shared library exporting all blst_* symbols ----
if [ "$OS" = mac ]; then
  clang -dynamiclib -install_name @rpath/libblst.dylib -o "libblst.$EXT" -Wl,-all_load libblst.a
else
  cc -shared -o "libblst.$EXT" -Wl,--whole-archive libblst.a -Wl,--no-whole-archive
fi

DEST="$RES/$OS/$ARCH"
mkdir -p "$DEST"
cp "libblst.$EXT" "$DEST/libblst.$EXT"
echo ">> Wrote $DEST/libblst.$EXT ($(du -h "$DEST/libblst.$EXT" | cut -f1)) from blst $BLST_TAG ($BLST_COMMIT)"

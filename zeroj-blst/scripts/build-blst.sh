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
#   BLST_TAG=v0.3.15 scripts/build-blst.sh
#
# Requirements: git, a C toolchain (clang/gcc). Cross-arch builds run in CI per runner (see
# .github/workflows/build-blst.yml); locally this builds only the host arch.
set -euo pipefail

BLST_TAG="${BLST_TAG:-v0.3.15}"
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

echo ">> Building libblst $BLST_TAG for $OS/$ARCH"
git clone --depth 1 -b "$BLST_TAG" https://github.com/supranational/blst "$WORK/blst"
cd "$WORK/blst"
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
echo ">> Wrote $DEST/libblst.$EXT ($(du -h "$DEST/libblst.$EXT" | cut -f1)) from blst $BLST_TAG"

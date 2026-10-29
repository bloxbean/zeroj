#!/usr/bin/env bash
#
# ADR-0062 D6 / I4 — regenerate the SHA-256 manifest of the bundled libblst binaries.
#
# BlstFfm refuses to load a bundled library whose SHA-256 is not in this manifest, and
# BundledLibblstProvenanceTest fails the build if a bundled library is missing from it or carries
# the symbols of the former third-party JNI binary. Run after replacing any library (build-blst.sh
# and the release workflow call it).
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"          # zeroj-blst/
NATIVE="$HERE/src/main/resources/org/zeroj/blst/native"
MANIFEST="$NATIVE/libblst.sha256"

cd "$NATIVE"
if command -v sha256sum >/dev/null 2>&1; then SUM="sha256sum"; else SUM="shasum -a 256"; fi
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
find . -type f \( -name 'libblst.so' -o -name 'libblst.dylib' -o -name 'libblst.dll' \) | sed 's|^\./||' \
  | LC_ALL=C sort | while read -r f; do
  $SUM "$f"
done > "$TMP"
if [ ! -s "$TMP" ]; then
  echo "no bundled libblst found under $NATIVE" >&2
  exit 1
fi
cp "$TMP" "$MANIFEST"
echo ">> Wrote $MANIFEST"
cat "$MANIFEST"

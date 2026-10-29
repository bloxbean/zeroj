#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build/vendor
fetch() {
  local name="$1" url="$2" revision="$3"
  if [ ! -d "build/vendor/$name/.git" ]; then
    git clone "$url" "build/vendor/$name"
    git -C "build/vendor/$name" checkout --detach "$revision"
  fi
  test "$(git -C "build/vendor/$name" rev-parse HEAD)" = "$revision" || { echo "Unexpected revision in $name" >&2; exit 1; }
  test -z "$(git -C "build/vendor/$name" status --porcelain)" || { echo "Modified dependency $name" >&2; exit 1; }
}
fetch circomlib https://github.com/iden3/circomlib.git 35e54ea21da3e8762557234298dbb553c175ea8d
fetch sha512 https://github.com/Electron-Labs/sha512.git be9f01d870c40c3fe4e0ff27c93232d205bc46f7
npm ci --ignore-scripts --no-audit --no-fund
"${CIRCOM:-circom}" --version
test "$("${CIRCOM:-circom}" --version)" = "circom compiler 2.2.3" || { echo "Circom 2.2.3 required" >&2; exit 1; }
node --version
curl --fail --location --silent --show-error \
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip \
  -o build/shabytetestvectors.zip
python3 verify-nist-source.py

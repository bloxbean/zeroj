#!/usr/bin/env bash
#
# generate-vectors.sh
# Generates Groth16/BN254 test vectors for the ZeroJ project using circom + snarkjs.
#
# Prerequisites:
#   - Node.js (>= 16)
#   - circom   (install: cargo install --git https://github.com/iden3/circom  or  npm i -g circom)
#   - snarkjs  (install: npm i -g snarkjs)
#
# Both tools also work via npx if installed locally.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$SCRIPT_DIR/build"
CIRCUIT_DIR="$SCRIPT_DIR/circuits"
OUTPUT_DIR="$SCRIPT_DIR/../src/main/resources/test-vectors/groth16-bn254"

# ── helpers ──────────────────────────────────────────────────────────────────
info()  { printf '\033[1;34m[INFO]\033[0m  %s\n' "$*"; }
error() { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

require_tool() {
  local tool="$1"
  if command -v "$tool" &>/dev/null; then
    return 0
  fi
  # try npx — check if the package produces any output (some tools exit non-zero for --version)
  local output
  output="$(npx "$tool" --version 2>&1)" || true
  if [ -n "$output" ]; then
    info "$tool found via npx: $output"
    return 0
  fi
  error "$tool is not installed. Please install it first.
  circom  : cargo install --git https://github.com/iden3/circom
  snarkjs : npm install -g snarkjs"
}

run_snarkjs() {
  if command -v snarkjs &>/dev/null; then
    snarkjs "$@"
  else
    npx snarkjs "$@"
  fi
}

run_circom() {
  if command -v circom &>/dev/null; then
    circom "$@"
  else
    npx circom "$@"
  fi
}

# ── pre-flight checks ───────────────────────────────────────────────────────
require_tool circom
require_tool snarkjs

info "All tools found."

# ── workspace ────────────────────────────────────────────────────────────────
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
mkdir -p "$OUTPUT_DIR"

# ── 1. Compile the circuit ───────────────────────────────────────────────────
info "Compiling circuit: multiplier.circom"
run_circom "$CIRCUIT_DIR/multiplier.circom" \
  --r1cs --wasm --sym \
  -o "$WORK_DIR"

# ── 2. Powers of Tau ceremony (tiny — 2^8 is plenty for this toy circuit) ───
info "Generating powers of tau (2^8)"
run_snarkjs powersoftau new bn128 8 "$WORK_DIR/pot8_0000.ptau" -v

info "Contributing to powers of tau"
run_snarkjs powersoftau contribute "$WORK_DIR/pot8_0000.ptau" "$WORK_DIR/pot8_0001.ptau" \
  --name="ZeroJ test vector contribution" -v -e="some random entropy for test vectors"

info "Preparing phase 2"
run_snarkjs powersoftau prepare phase2 "$WORK_DIR/pot8_0001.ptau" "$WORK_DIR/pot8_final.ptau" -v

# ── 3. Circuit-specific setup ────────────────────────────────────────────────
info "Groth16 setup"
run_snarkjs groth16 setup "$WORK_DIR/multiplier.r1cs" "$WORK_DIR/pot8_final.ptau" "$WORK_DIR/multiplier_0000.zkey"

info "Contributing to the circuit key"
run_snarkjs zkey contribute "$WORK_DIR/multiplier_0000.zkey" "$WORK_DIR/multiplier_final.zkey" \
  --name="ZeroJ circuit contribution" -v -e="more random entropy for circuit key"

info "Exporting verification key"
run_snarkjs zkey export verificationkey "$WORK_DIR/multiplier_final.zkey" "$WORK_DIR/verification_key.json"

# ── 4. Generate a proof for a=3, b=11 (c=33) ────────────────────────────────
info "Creating input.json (a=3, b=11)"
cat > "$WORK_DIR/input.json" <<'INPUTEOF'
{
  "a": "3",
  "b": "11"
}
INPUTEOF

info "Computing witness"
run_snarkjs wtns calculate \
  "$WORK_DIR/multiplier_js/multiplier.wasm" \
  "$WORK_DIR/input.json" \
  "$WORK_DIR/witness.wtns"

info "Generating Groth16 proof"
run_snarkjs groth16 prove \
  "$WORK_DIR/multiplier_final.zkey" \
  "$WORK_DIR/witness.wtns" \
  "$WORK_DIR/proof.json" \
  "$WORK_DIR/public.json"

# ── 5. Verify the proof (sanity check) ──────────────────────────────────────
info "Verifying proof (sanity check)"
run_snarkjs groth16 verify \
  "$WORK_DIR/verification_key.json" \
  "$WORK_DIR/public.json" \
  "$WORK_DIR/proof.json"

# ── 6. Copy output to resources ─────────────────────────────────────────────
info "Copying artifacts to $OUTPUT_DIR"
cp "$WORK_DIR/verification_key.json" "$OUTPUT_DIR/verification_key.json"
cp "$WORK_DIR/proof.json"             "$OUTPUT_DIR/proof.json"
cp "$WORK_DIR/public.json"            "$OUTPUT_DIR/public.json"

info "Done! Test vectors written to:"
info "  $OUTPUT_DIR/verification_key.json"
info "  $OUTPUT_DIR/proof.json"
info "  $OUTPUT_DIR/public.json"

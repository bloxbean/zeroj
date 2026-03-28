#!/usr/bin/env bash
#
# generate-plonk-vectors.sh
# Generates PlonK/BN254 test vectors for the ZeroJ project using circom + snarkjs.
#
# Prerequisites:
#   - circom   (/Users/satya/.cargo/bin/circom)
#   - snarkjs  (/Users/satya/.npm-global/bin/snarkjs)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$SCRIPT_DIR/build-plonk"
CIRCUIT_DIR="$SCRIPT_DIR/circuits"
OUTPUT_DIR="$SCRIPT_DIR/../src/main/resources/test-vectors/plonk-bn254"

# ── helpers ──────────────────────────────────────────────────────────────────
info()  { printf '\033[1;34m[INFO]\033[0m  %s\n' "$*"; }
error() { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

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
  --name="ZeroJ PlonK test vector contribution" -v -e="plonk random entropy for test vectors"

info "Preparing phase 2"
run_snarkjs powersoftau prepare phase2 "$WORK_DIR/pot8_0001.ptau" "$WORK_DIR/pot8_final.ptau" -v

# ── 3. PlonK setup ──────────────────────────────────────────────────────────
info "PlonK setup"
run_snarkjs plonk setup "$WORK_DIR/multiplier.r1cs" "$WORK_DIR/pot8_final.ptau" "$WORK_DIR/multiplier_plonk.zkey"

info "Exporting PlonK verification key"
run_snarkjs zkey export verificationkey "$WORK_DIR/multiplier_plonk.zkey" "$WORK_DIR/verification_key.json"

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

info "Generating PlonK proof"
run_snarkjs plonk prove \
  "$WORK_DIR/multiplier_plonk.zkey" \
  "$WORK_DIR/witness.wtns" \
  "$WORK_DIR/proof.json" \
  "$WORK_DIR/public.json"

# ── 5. Verify the proof (sanity check) ──────────────────────────────────────
info "Verifying proof (sanity check)"
run_snarkjs plonk verify \
  "$WORK_DIR/verification_key.json" \
  "$WORK_DIR/public.json" \
  "$WORK_DIR/proof.json"

# ── 6. Copy output to resources ─────────────────────────────────────────────
info "Copying artifacts to $OUTPUT_DIR"
cp "$WORK_DIR/verification_key.json" "$OUTPUT_DIR/verification_key.json"
cp "$WORK_DIR/proof.json"             "$OUTPUT_DIR/proof.json"
cp "$WORK_DIR/public.json"            "$OUTPUT_DIR/public.json"

info "Done! PlonK BN254 test vectors written to:"
info "  $OUTPUT_DIR/verification_key.json"
info "  $OUTPUT_DIR/proof.json"
info "  $OUTPUT_DIR/public.json"

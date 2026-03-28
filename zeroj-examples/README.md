# zeroj-examples

End-to-end demonstrations of ZeroJ capabilities.

## Two Demo Flows

### 1. EndToEndDemo — snarkjs Groth16/BN254 (pure Java, no native deps)

Shows the complete flow using externally-generated snarkjs proofs:

1. **Load proof** — Parse a snarkjs-generated Groth16/BN254 proof
2. **Set up verifier** — Register pure Java verification backends
3. **Verify standalone** — Cryptographic proof verification in Java
4. **Submit state transition** — Signed submission through 6-stage ingestion pipeline
5. **Anchor on Cardano** — Generate CIP-10 metadata for L1 anchoring
6. **Security demo** — Replay attack is automatically rejected

**External tools needed:** circom + snarkjs (for proof generation only, run beforehand)
**Runtime deps:** None — pure Java verification

```bash
./gradlew :zeroj-examples:run
```

### 2. GnarkPlonkEndToEndDemo — gnark PlonK/BLS12-381 (in-process FFM)

Shows the complete flow with gnark proving **inside the JVM** — no external tools at runtime:

1. **gnark FFM: setup + prove** — PlonK setup and proof generation via Go native library, in-process
2. **Pure Java: verify** — PlonK verification with zero native dependencies
3. **Pipeline: governance** — 6-stage validation with circuit lifecycle and audit

**External tools needed:** None at runtime (gnark native lib loaded via FFM)
**Runtime deps:** gnark `.dylib`/`.so` (for proving only); verification is pure Java

```bash
# Build gnark native library first (one-time):
cd zeroj-prover-gnark/gnark-wrapper && make build

# Run the demo:
./gradlew :zeroj-examples:run -PmainClass=com.bloxbean.cardano.zeroj.examples.GnarkPlonkEndToEndDemo
```

## Architecture Comparison

```
Demo 1: snarkjs flow (current EndToEndDemo)
────────────────────────────────────────────
  circom CLI      →  compile circuit (.circom → .r1cs + .wasm)
  snarkjs CLI     →  setup + prove (Node.js, external)
  ZeroJ Java      →  verify (pure Java) + pipeline + anchor

Demo 2: gnark flow (GnarkPlonkEndToEndDemo)
────────────────────────────────────────────
  gnark Go code   →  define circuit (one-time, compiled into native lib)
  gnark FFM       →  setup + prove (in-process, no external tools)
  ZeroJ Java      →  verify (pure Java) + pipeline + anchor
```

## Prover Toolchains

| Toolchain | Circuit Language | Prove | Verify | External Deps |
|-----------|-----------------|-------|--------|---------------|
| **snarkjs** | circom | Node.js CLI | Pure Java | circom + Node.js |
| **gnark FFM** | Go | In-process FFM | Pure Java | gnark native lib |
| **rapidsnark FFM** | circom | In-process FFM | Pure Java | rapidsnark native lib + circom |

## Future: GraalWasm Witness Calculator

The remaining Node.js dependency (for circom circuits) can be eliminated using GraalVM's WASM runtime:

```
Current circom flow:
  circom CLI → .wasm + .r1cs
  Node.js snarkjs → witness calculation    ← requires Node.js
  rapidsnark FFM → prove

Future with GraalWasm:
  circom CLI → .wasm + .r1cs
  GraalWasm → witness calculation           ← Java only, no Node.js
  rapidsnark FFM → prove
```

This would make the entire runtime Java-only for circom circuits too — the only external tool would be `circom` itself (a build-time Rust CLI for compiling `.circom` files).

## Verification Options (all pure Java)

| Proof System | Curve | Verifier Class | Native Deps |
|-------------|-------|----------------|-------------|
| Groth16 | BN254 | `Groth16BN254Verifier` | None |
| Groth16 | BLS12-381 | `Groth16BLS12381PureJavaVerifier` | None |
| Groth16 | BLS12-381 | `Groth16BLS12381Verifier` | blst (optional, faster) |
| PlonK | BN254 | `PlonkBN254Verifier` | None |
| PlonK | BLS12-381 | `PlonkBLS12381Verifier` | None |

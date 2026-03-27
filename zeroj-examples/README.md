# zeroj-examples

End-to-end demonstrations of ZeroJ capabilities.

This module contains runnable examples that show the complete ZeroJ flow — from loading an externally generated proof to anchoring the verified result on Cardano L1.

## EndToEndDemo

The main demo (`EndToEndDemo.java`) walks through 6 steps:

1. **Load proof** — Parse a snarkjs-generated Groth16/BN254 proof
2. **Set up verifier** — Register backends and verification keys
3. **Verify standalone** — Cryptographic proof verification in Java
4. **Submit state transition** — Signed submission through 6-stage ingestion pipeline
5. **Anchor on Cardano** — Generate CIP-10 metadata for L1 anchoring
6. **Security demo** — Replay attack is automatically rejected

## Running

```bash
./gradlew :zeroj-examples:run
```

Or run `EndToEndDemo.main()` directly from your IDE.

## Sample Output

```
==================================================================
  ZeroJ End-to-End Demo
  Prove once, verify everywhere, settle on Cardano
==================================================================

[Step 1] Loading externally-generated Groth16/BN254 proof...
  Proof system: groth16 / bn128
  Public inputs: [33, 3]

[Step 2] Setting up ZeroJ verifier...
  Registered backends: Groth16/BN254 (pure Java), Groth16/BLS12-381 (blst)

[Step 3] Verifying proof (standalone)...
  Proof valid: true

[Step 4] Submitting proof-backed state transition...
  Result: ACCEPTED

[Step 5] Anchoring verified result on Cardano L1...
  Anchor pattern: FULL_VERIFICATION_REF
  Metadata CBOR: 218 bytes

[Step 6] Security demo — replay attack...
  Result: REJECTED
  Reason: DUPLICATE_SEQUENCE

  ZeroJ: Prove once, verify everywhere, settle on Cardano.
==================================================================
```

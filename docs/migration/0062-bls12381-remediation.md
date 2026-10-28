# Migration 0062: BLS12-381 review remediation

ADR-0062 makes several BLS12-381 entry points fail closed. Every behaviour change below affects
only inputs that were wrong before: silently accepted, silently truncated, or answered with a
meaningless value. Honest callers and snarkjs-produced proofs are unaffected.

## Why

An independent review of the BLS12-381 stack (ADR-0062 §Findings) found entry points that
accepted malformed input instead of rejecting it. Examples: a rescaled projective encoding of a
Groth16 proof point that still verified, an empty pairing product reported as a successful check,
and a negative exponent that returned a wrong power.

## What changed

| Area | Before | After | ADR |
|---|---|---|---|
| `MontFp381.pow(BigInteger)`, `MontFr381.pow(BigInteger)` | a negative exponent returned a wrong value (`pow(−1) = 1`) | `IllegalArgumentException` | D8 |
| `Bls12381Provider.pairingProductIsIdentity` (pure Java, blst, WASM) | empty arrays returned `true` | `IllegalArgumentException`; the length check message is now the same on every provider | D7 |
| `BLS12381Pairing.millerLoop` / `pairingCheck` | a `G2` point outside the subgroup could reach a wrong vertical-line branch silently | `IllegalArgumentException` when the loop reaches `T = ±Q` (impossible for subgroup points); the class still validates nothing else, as now documented | D7 |
| `Bls12381Hash.expandMessage*`, every `hashTo*` / `encodeTo*` / `hashToScalar*` | an empty DST was accepted | `IllegalArgumentException` (RFC 9380 §3.1: tags MUST be non-empty) | D10 |
| Groth16 BLS12-381 verifiers (pure Java and blst), proof **and** verification-key points | any non-zero `z` was accepted and divided out, so `(λx, λy, λ)` verified like `(x, y, 1)` | only `z = 1` (G1) and `z = (1, 0)` (G2) are accepted; anything else is `INVALID_PROOF` with "must be affine" | D5 |
| `SnarkjsToCardano.g1Compress` / `g2Compress` (`zeroj-onchain-julc`) | G1 divided by any non-zero `z`; G2 threw `UnsupportedOperationException` | both throw `IllegalArgumentException` for `z ≠ 1` | D5 |

No proof format, verification key format, transcript, encoding, circuit or on-chain script
changes. Julc script hashes are unchanged.

## What you must do

1. If you build Groth16 proof or verification-key JSON yourself, emit affine points:
   `z = "1"` for G1 and `z = ["1", "0"]` for G2, as snarkjs does. Normalise any projective point
   before serialising it.
2. If you call `pairingProductIsIdentity` with arrays you build dynamically, an empty input now
   throws. Decide what an empty input means for your protocol and handle it before the call.
3. Use a non-empty domain separation tag for every hash-to-curve or hash-to-scalar call.
4. If you call the raw `BLS12381Pairing` class with untrusted points, validate them first with
   `Bls12381Codecs.requireValid` or the checked decoders, or use a `Bls12381Provider`.

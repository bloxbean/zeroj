# PlonK Support in ZeroJ

## Table of Contents

- [Status](#status-off-chain-implemented-experimental-on-chain)
- [What Works Today](#what-works-today)
- [Quick Start (Off-Chain)](#quick-start-off-chain)
- [Use Cases](#use-cases)
- [Limitations](#limitations)
- [Architecture](#architecture)
- [Test Vectors](#test-vectors)
- [Related ADRs](#related-adrs)

---

## Status: Off-Chain Implemented, Experimental On-Chain

ZeroJ supports PlonK proof generation via the pure Java prover and gnark FFM,
plus **pure Java verification** for structured snarkjs/ZeroJ PlonK proof JSON
on BLS12-381 and BN254 curves.
gnark's opaque binary PlonK proof JSON should be verified with gnark native
verification until a dedicated adapter is added. The Julc on-chain PlonK path is
an experimental prototype today: transcript and inverse checks are implemented,
but the KZG batch opening pairing check is still deferred.

## What Works Today

### Off-Chain PlonK
- **Setup**: Universal SRS generation (one setup works for any circuit up to the SRS size)
- **Prove**: Generate PlonK proofs with the pure Java prover or with gnark FFM
- **Verify**: **Pure Java verification** for structured snarkjs/ZeroJ proof JSON; gnark binary PlonK proof JSON uses gnark native verification until an adapter lands
- **Both BN254 and BLS12-381 curves supported**

### On-Chain PlonK (Experimental)
- Prototype verifier via `PlonkBLS12381FullVerifier` in `zeroj-onchain-julc`
- Fiat-Shamir challenge re-derivation matching gnark's exact transcript format
- KZG batch opening pairing check still deferred
- BLS12-381 only (Plutus V3 builtins)
- Useful for budget and data-shape work, not yet a full trustless on-chain verifier

### Advantage Over Groth16
| Feature | Groth16 | PlonK |
|---------|---------|-------|
| Trusted setup | Per-circuit ceremony | Universal SRS (one-time, updatable) |
| Circuit changes | New setup needed | Same SRS, new keys only |
| Proof size | ~192 bytes | ~656 bytes |
| Verification cost | 3 pairings | 2 pairings + ~18 scalar muls |

## Quick Start (Off-Chain)

```java
var circuit = CircuitBuilder.create("multiplier")
        .publicVar("c")
        .secretVar("a")
        .secretVar("b")
        .define(api -> api.assertEqual(
                api.mul(api.var("a"), api.var("b")),
                api.var("c")));

var plonk = circuit.compilePlonK(CurveId.BLS12_381);
var witness = circuit.calculateWitness(Map.of(
        "c", List.of(BigInteger.valueOf(33)),
        "a", List.of(BigInteger.valueOf(3)),
        "b", List.of(BigInteger.valueOf(11))), CurveId.BLS12_381);

var srs = PowersOfTauBLS381.generate(8); // local test setup only
int numGates = plonk.numGates();
BigInteger[][] gateSelectors = new BigInteger[numGates][5];
for (int i = 0; i < numGates; i++) {
    var row = plonk.gateRows().get(i);
    gateSelectors[i] = new BigInteger[]{row.qL(), row.qR(), row.qO(), row.qM(), row.qC()};
}

var pk = PlonKSetupBLS381.setup(numGates, plonk.numPublicInputs(),
        gateSelectors, plonk.sigmaA(), plonk.sigmaB(), plonk.sigmaC(),
        plonk.numWires(), srs);

var extendedWitness = plonk.extendWitness(witness);
int n = pk.domainSize();
MontFr381[] wireA = new MontFr381[n];
MontFr381[] wireB = new MontFr381[n];
MontFr381[] wireC = new MontFr381[n];
for (int i = 0; i < n; i++) {
    if (i < numGates) {
        var row = plonk.gateRows().get(i);
        wireA[i] = MontFr381.fromBigInteger(extendedWitness[row.wireA()]);
        wireB[i] = MontFr381.fromBigInteger(extendedWitness[row.wireB()]);
        wireC[i] = MontFr381.fromBigInteger(extendedWitness[row.wireC()]);
    } else {
        wireA[i] = wireB[i] = wireC[i] = MontFr381.ZERO;
    }
}

BigInteger[] publicInputs = new BigInteger[plonk.numPublicInputs()];
for (int i = 0; i < publicInputs.length; i++) {
    publicInputs[i] = witness[i + 1];
}

var proof = PlonKProverBLS381.prove(pk, wireA, wireB, wireC, publicInputs);
```

See `PlonKBLS381EndToEndTest.java` for the full wire-evaluation and verification code.

## Use Cases

### Today (Off-Chain)
- **Yaci app-layer verification**: Nodes verify PlonK proof-backed state transitions without recomputing
- **Java backend services**: Validate client ZK proofs in server-side applications
- **Enterprise privacy**: Verifiable computation with universal setup (no per-circuit ceremony)
- **Development/testing**: Iterate on ZK circuits without re-running trusted setup

### Future (On-Chain)
- PlonK verification on Cardano Plutus V3 is feasible using BLS12-381 builtins
- **Limitation**: Plutus V3 lacks SHA-256 (needed for Fiat-Shamir transcript). Workaround: pass pre-computed challenges as redeemer data
- **CIP-0133 (Multi-Scalar Multiplication)**: Would improve the shape of on-chain PlonK verification if available
- See [ADR-0008](adr/0008-plonk-support-via-gnark.md) for detailed analysis

## Limitations

1. **Test SRS**: Local test setups are not suitable beyond development. Use MPC-generated SRS artifacts when evaluating non-local deployments.
2. **gnark format**: Proofs and VKs are in gnark's binary format, not snarkjs format. A codec adapter is planned.

## Architecture

```
Java Application
    |
CircuitBuilder.compilePlonK(...)
    |
PlonKConstraintSystem
    |
PlonKSetupBLS381 / PlonKProverBLS381
    |
PlonkBLS12381Verifier / PlonkBN254Verifier
    |
Optional: GnarkProver for native proving and native verification of gnark binary artifacts
```

## Test Vectors

Real PlonK test vectors are generated by `gnark-wrapper/cmd/gentestvectors`:

```bash
cd zeroj-prover-gnark/gnark-wrapper
go run ./cmd/gentestvectors -output ../../zeroj-test-vectors/src/main/resources/test-vectors/plonk-bls12381/
```

Circuit: `X * Y = Z` (multiplier), Witness: X=3, Y=11, Z=33

## Related ADRs
- [ADR-0008: PlonK Support via gnark](adr/0008-plonk-support-via-gnark.md)

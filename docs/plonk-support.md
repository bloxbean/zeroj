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
on BLS12-381. BN254 PlonK remains a legacy/off-chain compatibility path and is
disabled by default behind explicit opt-in.
gnark's opaque binary PlonK proof JSON should be verified with gnark native
verification until a dedicated adapter is added. The Julc on-chain PlonK path is
implemented for BLS12-381 Cardano profiles with compressed-point Fiat-Shamir
binding and the KZG batch opening pairing check. The strict v1 profile supports
exactly one public input, and the MPI profile supports 1 through 8 public
inputs. It is eligible for labeled non-value-bearing public testnet trials, but
remains experimental and opt-in until the remaining value-bearing release gates,
including third-party audit and broader fuzz/differential CI gates, are closed.

## What Works Today

### Off-Chain PlonK
- **Setup**: Universal SRS generation (one setup works for any circuit up to the SRS size)
- **Prove**: Generate PlonK proofs with the pure Java prover or with gnark FFM
- **Verify**: **Pure Java verification** for structured snarkjs/ZeroJ proof JSON; gnark binary PlonK proof JSON uses gnark native verification until an adapter lands
- **BLS12-381 is the Cardano/default path**; BN254 is legacy/off-chain only and
  requires `-Dzeroj.allowLegacyBn254=true` or `ZEROJ_ALLOW_LEGACY_BN254=true`

### On-Chain PlonK (Experimental)
- Reusable `@OnchainLibrary` via `PlonkBLS12381Lib` for custom validators that
  need to compose PlonK verification with application-specific `ScriptContext`
  policy
- Full verifier via `PlonkBLS12381Verifier` in `zeroj-onchain-julc` for the current one-public-input Cardano profile
- Bounded multi-public-input verifier via `PlonkBLS12381MultiInputVerifier` for the `zeroj-plonk-bls12381-cardano-mpi-v1-json` profile (`1..8` datum-supplied public inputs)
- Script-parameter MPI variant via `PlonkBLS12381MultiInputParamVerifier` for statements whose public inputs should be pinned by the script hash
- Cardano-profile Fiat-Shamir challenge re-derivation over compressed BLS12-381 G1 bytes
- KZG batch opening pairing check implemented with Plutus V3 BLS12-381 builtins
- Strict scalar, compressed point, domain, coset, inverse, and public-input shape validation
- BLS12-381 only (Plutus V3 builtins)
- Experimental opt-in pending broader release-assurance vectors and independent audit

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

// Local test setup only; requires -Dzeroj.allowInsecureTrustedSetup=true.
var srs = PowersOfTauBLS381.generate(8);
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

### On-Chain Release Gates
- PlonK verification on Cardano Plutus V3 is BLS12-381 only because Cardano does
  not expose BN254 builtins.
- The first supported Cardano profile is pinned to ZeroJ pure-Java proofs with
  compressed BLS12-381 transcript encoding and exactly one public input.
- The MPI Cardano profile is separate and bounded to 1 through 8 public inputs.
  It binds the profile tag, public input count, and ordered fixed-width public
  input scalars into the transcript, then verifies per-input inverse witnesses
  before computing the public-input polynomial on-chain. Use
  `PlonkBLS12381MultiInputVerifier` when public inputs are transaction-specific
  datum values, and `PlonkBLS12381MultiInputParamVerifier` when public inputs
  should be fixed at script-application time.
- Value-bearing/mainnet use still requires independent security audit, broader
  cross-implementation/adversarial vectors, and pinned ceremony artifacts.
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
PlonkBLS12381Verifier
    |
Optional Cardano profile: PlonKProverBLS381.proveCardano(...)
    |
PlonKProverToCardano -> PlonkBLS12381Verifier (Julc, BLS12-381 one-input profile)
    |
Custom validator -> PlonkBLS12381Lib (Julc library, BLS12-381 one-input or MPI profile)
    |
Optional MPI Cardano profile: PlonKProverBLS381.proveCardanoMpi(...)
    |
PlonKProverToCardano.compressMpiProof -> PlonkBLS12381MultiInputVerifier (Julc, BLS12-381 1..8-input profile)
    |
Alternative pinned-statement deployment: PlonkBLS12381MultiInputParamVerifier
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

The BLS12-381 off-chain verifier also includes a structured snarkjs PlonK
multiplier vector under
`zeroj-verifier-plonk/src/test/resources/test-vectors/snarkjs-plonk-bls12381/`.

## Related ADRs
- [ADR-0008: PlonK Support via gnark](adr/0008-plonk-support-via-gnark.md)

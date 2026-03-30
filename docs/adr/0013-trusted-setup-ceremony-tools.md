# ADR-0013: Trusted Setup Ceremony Tools

## Status
Proposed

## Date
2026-03-30

## Context

ZeroJ's pure Java provers (ADR-0012) import trusted setup outputs from external tools:
- Powers of Tau `.ptau` files from snarkjs ceremonies
- Groth16 `.zkey` files from `snarkjs groth16 setup`
- PlonK `.zkey` files from `snarkjs plonk setup`

This creates a dependency on Node.js/snarkjs for the **setup** phase, even though proving
and verification are fully pure Java. For development and testing, requiring an external
Node.js toolchain is friction that breaks the "all Java" experience.

### Setup requirements by proof system

| Proof System | Setup Type | Ceremony | Reusable? |
|-------------|-----------|----------|-----------|
| Groth16 | Per-circuit | Phase 1 (Powers of Tau) + Phase 2 (circuit-specific) | Phase 1 yes, Phase 2 no |
| PlonK | Universal | Powers of Tau only | Yes (across all circuits up to max size) |
| Halo2 IPA | None | Transparent (deterministic) | N/A |

## Decision

### Build a pure Java Powers of Tau generator for development and testing

Provide `PowersOfTau.generate()` that creates a `.ptau`-compatible SRS (Structured
Reference String) in pure Java. This is for **development and testing only** — not for
production multi-party ceremonies.

Also provide `Groth16Setup.setup()` that takes an R1CS constraint system + SRS and
produces a Groth16 proving key (Phase 2), completing the pure Java pipeline.

### For production: use established MPC ceremony outputs

**Production deployments MUST use SRS from established multi-party computation (MPC)
ceremonies.** A single-party generator (like ours) provides no trust guarantee — the
generator knows the toxic waste (tau) and could forge proofs.

Recommended production ceremony sources:

| Source | Contributors | Max Size | Format | URL |
|--------|-------------|----------|--------|-----|
| Hermez Phase 1 (Polygon) | 54 | 2^28 (268M) | .ptau | [hermez-ceremony](https://github.com/iden3/snarkjs#7-prepare-phase-2) |
| Zcash Powers of Tau | 87 | 2^21 | raw | [powersoftau](https://github.com/ebfull/powersoftau) |
| Perpetual Powers of Tau | 70+ | 2^28 | .ptau | [ppot](https://github.com/privacy-scaling-explorations/perpetualpowersoftau) |

These ceremony outputs can be imported directly using `PtauImporter.importPtau()`.

### Module structure

```
zeroj-crypto/
  src/main/java/com/bloxbean/cardano/zeroj/crypto/
    setup/
      PowersOfTau.java        — single-party PoT generator (dev/test only)
      Groth16Setup.java        — Phase 2 setup from R1CS + SRS
```

### API design

```java
// === Development / Testing ===
// Generate a Powers of Tau SRS (single-party, NOT for production)
var srs = PowersOfTau.generate(CurveId.BN254, power: 12);
// Produces tau^i * G1 for i=0..2^12 and tau^i * G2 for i=0..1
// The toxic waste (tau) is securely discarded after generation

// Groth16 Phase 2: compile R1CS + SRS → proving key
var pk = Groth16Setup.setup(r1cs, srs);

// PlonK setup (already exists)
var plonkPk = PlonKSetup.setup(constraints, srs);

// Full pure Java pipeline — zero external tools
var circuit = CircuitBuilder.create("example").publicVar("out").secretVar("x")
    .define(api -> api.assertEqual(api.mul(api.var("x"), api.var("x")), api.var("out")));
var r1cs = circuit.compileR1CS(CurveId.BN254);
var srs = PowersOfTau.generate(CurveId.BN254, 12);
var pk = Groth16Setup.setup(r1cs, srs);
var witness = circuit.calculateWitness(inputs, CurveId.BN254);
var proof = Groth16Prover.prove(pk, witness, constraints, numWires);
// → proof verifies with pure Java Groth16BN254Verifier

// === Production ===
// Import SRS from a real MPC ceremony
var srs = PtauImporter.importPtau(new FileInputStream("hermez_2^20.ptau"));
var pk = Groth16Setup.setup(r1cs, srs);
// Security guarantee: 54+ independent contributors, toxic waste destroyed
```

### Security warnings

The `PowersOfTau.generate()` method MUST:
1. Print a clear warning to stderr: `"WARNING: Single-party Powers of Tau — for development/testing only. Use MPC ceremony outputs for production."`
2. Be annotated with `@DevelopmentOnly` or equivalent documentation
3. Securely zero the toxic waste (`tau`) after computing the SRS points
4. Use `SecureRandom` for tau generation

## Implementation Plan

### PowersOfTau.generate()

1. Sample random `tau` from `SecureRandom` (512-bit, reduced mod Fr)
2. Compute `tau^i * G1` for i=0..2^power using iterated scalar multiplication
3. Compute `tau^0 * G2` (= G2 generator) and `tau^1 * G2`
4. Zero `tau` from memory (overwrite with zeros)
5. Return `PtauImporter.SRS` object (compatible with existing import path)

### Groth16Setup.setup()

1. Parse R1CS constraints into QAP polynomials (A, B, C matrices → Lagrange form)
2. Sample random `alpha`, `beta`, `gamma`, `delta` from `SecureRandom`
3. Compute:
   - `[alpha]_1`, `[beta]_1`, `[beta]_2`, `[delta]_1`, `[delta]_2`
   - `[A_i(tau)]_1` for each wire i (MSM with SRS)
   - `[B_i(tau)]_1` and `[B_i(tau)]_2` for each wire i
   - `[H_j(tau)]_1` for the quotient polynomial basis (Lagrange on coset)
   - `[L_k(tau)]_1` for private wires (includes alpha, beta contribution)
4. Zero all toxic waste
5. Return `Groth16ProvingKey`

## Consequences

### Positive
- **Complete pure Java pipeline** — define → compile → setup → prove → verify with zero external tools
- **Fast development iteration** — no Node.js/snarkjs needed for testing
- **GraalVM native-image** — the entire ZK pipeline compiles to a single native binary
- **CI/CD friendly** — no external tool installation in build pipelines

### Negative
- **Single-party setup is NOT secure for production** — must be clearly documented
- **Groth16 Phase 2 is complex** — QAP polynomial computation, Lagrange evaluation at tau
- **Performance** — setup is compute-intensive (large MSMs), but only done once per circuit

## Known Limitations

### Constant-time operations

The pure Java cryptographic primitives (Montgomery multiplication, EC scalar multiplication,
field inversion) are **NOT constant-time**. This is standard and acceptable for a ZK prover
(which runs locally with secret witness data), but would be a vulnerability in contexts where
timing side-channels are observable:

| Operation | Constant-time? | Acceptable for prover? |
|-----------|---------------|----------------------|
| `montMul` (CIOS) | Yes | Yes |
| `add`, `sub` | Yes | Yes |
| `subtractModIfNeeded` | No (branches on comparison) | Yes — standard practice |
| `inverse()` | No (BigInteger GCD) | Yes for prover; NOT for signing |
| `pow()` | No (square-and-multiply) | Yes if exponent is public |
| `scalarMul` | No (double-and-add) | Yes for prover |

**If these primitives are ever used in a signing, key generation, or verifier-with-secret
context, constant-time alternatives (addition chains for inversion, Montgomery ladder for
scalar multiplication) must be implemented first.**

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Developer uses single-party SRS in production | High | Loud warning in generate(), documentation, annotation |
| Toxic waste not properly zeroed | Medium | Use `Arrays.fill(0)` + volatile write; Java has no guaranteed memory zeroing but best-effort is standard |
| Groth16 Phase 2 computation errors | High | Cross-validate: generate .zkey with snarkjs, import with ZkeyImporter, compare proving key points |
| Performance of setup for large circuits | Low | Setup is one-time; acceptable to be slow |

## References

- [Powers of Tau ceremony specification](https://eprint.iacr.org/2017/1050)
- [Hermez Phase 1 ceremony](https://blog.hermez.io/hermez-cryptographic-setup/)
- [snarkjs Powers of Tau implementation](https://github.com/iden3/snarkjs/blob/master/src/powersoftau_new.js)
- ADR-0012: Pure Java Provers for Groth16 and PlonK

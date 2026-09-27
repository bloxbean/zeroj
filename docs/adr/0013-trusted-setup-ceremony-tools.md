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

Also provide development-only `Groth16Setup.setup()` that takes an R1CS constraint
system and the known tau scalar, and produces a Groth16 proving key (Phase 2).
Imported ceremony SRS files do not expose tau and cannot drive this single-party API.

### For production: use established MPC ceremony outputs

**Production deployments MUST use SRS from established multi-party computation (MPC)
ceremonies.** A single-party generator (like ours) provides no trust guarantee — the
generator knows the toxic waste (tau) and could forge proofs.

Ceremony sources must match both the curve and the importer format:

| Source | Curve / import boundary |
|--------|-------------------------|
| [Hermez Phase 1](https://github.com/iden3/snarkjs/tree/v0.7.6#7-prepare-phase-2) | BN254 snarkjs `.ptau` artifacts; use `PtauImporter` after independent verification and hash pinning |
| [Perpetual Powers of Tau](https://github.com/privacy-scaling-explorations/perpetualpowersoftau) | BN254; select and verify a snarkjs-format `.ptau` artifact before using `PtauImporter` |
| Filecoin source selected in [ADR-0031](0031-groth16-mpc-trusted-setup-ceremony.md) | BLS12-381; conversion, provenance and external-review gates remain open |

Raw ceremony formats and curves are not interchangeable. In particular, Zcash's
BLS12-381 Powers of Tau is not an input for the BN254 `PtauImporter`. Phase 1 alone
does not supply Groth16's circuit-specific MPC phase 2.

### Module structure

```
zeroj-crypto/
  src/main/java/org/zeroj/crypto/
    setup/
      PowersOfTau.java        — single-party PoT generator (dev/test only)
      Groth16Setup.java        — dev-only Phase 2 setup from R1CS + known tau
```

### Historical development API sketch

The following is the original proposal sketch, not a current compilable API example.
See the module README for current development APIs and required opt-ins.

```java
// === Development / Testing ===
// Generate a Powers of Tau SRS (single-party, NOT for production)
var srs = PowersOfTau.generate(CurveId.BN254, power: 12);
// Produces tau^i * G1 for i=0..2^12 and tau^i * G2 for i=0..1
// Development-only: tau is retained for phase 2; immutable Java secrets are not securely erased

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
```

### Production Groth16 artifact flow (supersedes the original example)

```text
verified, hash-pinned phase-1 .ptau for the selected curve
  → circuit-specific MPC phase 2 using the exact R1CS (ADR-0031)
  → independently verify the final .zkey transcript against that R1CS and .ptau
  → import the final .zkey with the matching ZeroJ importer and a trusted hash pin
```

Do not call the local `Groth16Setup.setup(..., tau)` as the production phase-2 step.
An imported `.ptau` contains public group elements, not tau, and a local single-party
phase 2 still exposes its alpha/beta/gamma/delta to that party. Contributor counts,
process exit and Java reference assignments do not prove secret destruction. The
ceremony trust assumptions and remaining production gates in ADR-0031 still apply.

### Security warnings

The `PowersOfTau.generate()` method MUST:
1. Print a clear warning to stderr: `"WARNING: Single-party Powers of Tau — for development/testing only. Use MPC ceremony outputs for production."`
2. Be annotated with `@DevelopmentOnly` or equivalent documentation
3. State that immutable Java secrets are not securely erased. Clearing owned mutable buffers is lifetime hygiene only; implementations may do so without promising exhaustive cleanup or erasure
4. Use `SecureRandom` for tau generation

## Implementation Plan

### PowersOfTau.generate()

1. Sample random `tau` from `SecureRandom` (512-bit, reduced mod Fr)
2. Compute `tau^i * G1` for i=0..2^power using iterated scalar multiplication
3. Compute `tau^0 * G2` (= G2 generator) and `tau^1 * G2`
4. Owned mutable buffers may be cleared as lifetime hygiene only; do not claim exhaustive cleanup or erasure of immutable tau, derived values or aliases
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
4. Do not claim toxic-waste erasure; isolate development setup and discard the process afterward. Delete any insecure-dev SRS files containing tau and their copies; process exit does not remove persisted toxic waste
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

These development setup paths have no JVM constant-time guarantee. Secret tau,
phase-2 scalars and derived values reach variable-time `BigInteger` arithmetic and
scalar multiplication. A local prover or isolated process does not by itself make
observable timing or memory-access leakage acceptable.

The original per-operation table and blanket claims of acceptability for provers
are superseded by this contract and ADR-0026's security gates. Any production
secret-processing path requires an accepted design and evidence for its actual
implementation and platform; neither a fixed operation schedule nor native-image
compilation alone establishes constant-time behavior.

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Developer uses single-party SRS in production | High | Loud warning in generate(), documentation, annotation |
| Toxic waste not properly zeroed | Medium | No reliable heap-erasure claim; explicit dev-only isolation, no production ceremony secrets, imported verified/pinned artifacts |
| Groth16 Phase 2 computation errors | High | Cross-validate: generate .zkey with snarkjs, import with ZkeyImporter, compare proving key points |
| Performance of setup for large circuits | Low | Setup is one-time; acceptable to be slow |

## References

- [Powers of Tau ceremony specification](https://eprint.iacr.org/2017/1050)
- [Hermez Phase 1 ceremony](https://blog.hermez.io/hermez-cryptographic-setup/)
- [snarkjs Powers of Tau implementation](https://github.com/iden3/snarkjs/blob/master/src/powersoftau_new.js)
- ADR-0012: Pure Java Provers for Groth16 and PlonK

## Secret-lifetime clarification (issue #49, 2026-09-26)

Risk: R3 documentation of the existing development-only trust boundary, with removal of
misleading local-reference assignments. Secret values are tau, alpha, beta, gamma, delta,
inverses and derived QAP/field intermediates. Their arithmetic remains variable-time, and
immutable BigInteger instances, aliases, GC copies, swap and dumps cannot be reliably erased
by assigning a local to ZERO or filling an array of references. Tau is intentionally returned
for development phase 2. The same limitation applies to heap and streaming setup and BN254.

Use an isolated development process without real private witnesses; avoid retaining its dumps
or swap and terminate it afterward. Any insecure-dev SRS file written by
`Groth16SetupCache.saveBls12381InsecureDevSrsWithTau` or
`PlonkSetupCache.saveBls12381InsecureDevSrsWithTau` contains toxic waste and outlives
the process: delete it and any copies after testing. Owner-only permissions restrict
access; neither permissions nor file deletion guarantee erasure from storage,
snapshots or backups. These measures reduce exposure, not guarantee erasure.
The existing TrustedSetupPolicy opt-in remains mandatory. Production uses independently
verified, hash-pinned ceremony outputs appropriate to the curve and exact circuit; Hermez
artifacts are BN254-only, not a BLS12-381 source. A Java single-party setup is not an MPC
ceremony merely because its scalar references were cleared.

Any future production-secret setup/contributor implementation needs its own accepted R3
design, pinned reference protocol, ownership/wipe and side-channel evidence, and independent
review. Mutable/off-heap storage alone does not meet those gates. This clarification does not
change proof bytes, setup equations, randomness, validation, opt-in behavior or maturity.

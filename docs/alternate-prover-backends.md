# Alternate Prover Backends — blst acceleration and snarkjs

## Table of Contents

- [Backend Comparison](#backend-comparison)
- [blst-accelerated Groth16](#blst-accelerated-groth16)
- [snarkjs CLI](#snarkjs-cli)
- [circom Integration](#circom-integration)
- [When to Use Each Backend](#when-to-use-each-backend)
- [Removed backends](#removed-backends)

---

ZeroJ's **recommended** prover is the [pure Java prover](pure-java-prover-guide.md)
(`zeroj-crypto`), which requires zero native dependencies. This document covers the
alternatives: an opt-in native acceleration backend, and interoperability with
existing snarkjs/circom workflows.

## Backend Comparison

| Backend | Proof Systems | Curves | Dependencies | Module |
|---------|-------------|--------|--------------|--------|
| **Pure Java** | Groth16, PlonK | BLS12-381 | None | `zeroj-crypto` |
| **blst-accelerated** | Groth16 | BLS12-381 | bundled `libblst` (FFM) | `zeroj-crypto-blst` |
| **snarkjs CLI** | Groth16, PlonK | BLS12-381 | Node.js + snarkjs | external process |

BN254 artifacts are legacy/off-chain only in ZeroJ. High-level BN254 proving and
verification require explicit opt-in, and BN254 verifiers are not registered by
default; use BLS12-381 for Cardano-oriented proving and verification.

## blst-accelerated Groth16

`zeroj-crypto-blst` is a thin bridge that wires `zeroj-blst`'s native
multi-scalar multiplication into the `zeroj-crypto` prover backend. It is a
**performance** option, not a different proof system: it produces bit-identical
proofs to the pure Java path, and cross-provider equivalence is tested.

Since the large-circuit memory and FFT work in
[ADR-0033](adr/0033-prover-memory-reduction.md) and
[ADR-0034](adr/0034-frontend-memory-reduction.md), the pure Java prover matches
or beats blst at large circuit sizes. Measure before adopting it.

`libblst` is built from source (pinned v0.3.15), not taken from a third-party
wrapper. See [ADR-0029](adr/0029-blst-accelerated-groth16-prover.md).

### Gradle

```gradle
implementation platform('com.bloxbean.cardano:zeroj-bom-core:0.1.0')
implementation 'com.bloxbean.cardano:zeroj-crypto'
implementation 'com.bloxbean.cardano:zeroj-crypto-blst'   // opt-in acceleration
```

## snarkjs CLI

For teams already using snarkjs workflows. Runs as an external Node.js process.

snarkjs is also one of ZeroJ's **independent oracles**: the interoperability
tests in `zeroj-integration-tests` have snarkjs prove circuits that ZeroJ
compiled, then verify those proofs with ZeroJ's pure Java verifier, so expected
values do not come from the implementation under test.

### Prerequisites

```bash
npm install -g snarkjs
```

### Usage

The `SnarkjsProver` helper shown below is a **test fixture** in
`zeroj-integration-tests`, not a published API. Treat it as a worked example of
driving the CLI.

```java
var snarkjs = new SnarkjsProver();

// 1. Generate Powers of Tau
Path ptau = snarkjs.powersOfTau("bls12-381", 13, workDir);

// 2. Groth16 setup
var setup = snarkjs.groth16Setup(r1csBytes, ptau, workDir);

// 3. Prove
var proof = snarkjs.groth16Prove(setup.zkeyFile(), wtnsBytes, workDir, setup.vkJson());

// 4. Verify (via snarkjs CLI)
boolean valid = snarkjs.groth16Verify(workDir);
```

### Verification of external artifacts

Groth16 artifacts from snarkjs normalize into the ZeroJ envelope model and are
verified by the pure Java verifiers:

```java
var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson, publicJson, circuitId);
var verifier = new Groth16BLS12381PureJavaVerifier();
var result = verifier.verify(envelope, material);
```

The pure Java PlonK verifier consumes structured snarkjs/ZeroJ proof JSON.

### Mixing: snarkjs Setup + Pure Java Prove

You can use snarkjs for the trusted setup ceremony and the pure Java prover for
proof generation:

```java
// Import snarkjs .zkey (from multi-party ceremony)
var zkeyData = ZkeyImporterBLS381.importZkeyFull(Files.readAllBytes(Path.of("circuit.zkey")));

// Prove with pure Java (no snarkjs needed at runtime)
var proof = Groth16ProverBLS381.prove(zkeyData.provingKey(), witness,
    zkeyData.constraints(), zkeyData.numWires());
```

This is the recommended ceremony/import pattern when evaluating a setup beyond
local single-party test keys. The in-repo development setup is flag-gated
(`zeroj.allowInsecureTrustedSetup`) and is **not** a production ceremony; see
the [ceremony user guide](ceremony/USER-GUIDE.md).

## circom Integration

Circuits written in circom work with both backends:

```bash
# Compile circom → R1CS
circom circuit.circom --r1cs --wasm --sym -p bls12381

# Generate witness
node circuit_js/generate_witness.js circuit.wasm input.json witness.wtns

# Setup via snarkjs
snarkjs groth16 setup circuit.r1cs pot_final.ptau circuit.zkey
```

Then prove:

```java
// Pure Java
var zkeyData = ZkeyImporterBLS381.importZkeyFull(zkeyBytes);
var proof = Groth16ProverBLS381.prove(zkeyData.provingKey(), witness, ...);

// OR snarkjs CLI
var proof = snarkjs.groth16Prove(zkeyPath, wtnsPath, workDir);
```

## When to Use Each Backend

| Scenario | Recommended Backend |
|----------|-------------------|
| **Cardano on-chain verification** | Pure Java BLS12-381 path |
| **Development / testing** | Pure Java local setup |
| **Large circuits, measured win** | `zeroj-crypto-blst`, after benchmarking against pure Java |
| **Existing snarkjs workflow** | snarkjs CLI for setup/artifacts, then import `.zkey` |
| **Mobile / serverless** | Pure Java path |
| **CI/CD pipelines** | Pure Java path when native build toolchains are undesirable |

## Removed backends

[ADR-0044](adr/0044-focused-module-surface-and-optional-provider-isolation.md)
removed two native runtime providers. **Neither is a shipping ZeroJ backend any
more**, and there is no replacement artifact for either:

| Removed | Why | What to use instead |
|---|---|---|
| `zeroj-prover-gnark` — in-process Go Groth16/PlonK proving via FFM | Both proof systems now have Java product paths, no use case consumed the binding, and it carried a Go runtime, an FFM surface, a per-platform release matrix and a `GOMAXPROCS(2)` stability workaround | `zeroj-crypto`, optionally with `zeroj-crypto-blst` |
| `zeroj-verifier-halo2` — Rust Halo2 verification via FFM | No consumer and no committed product path | No replacement; pin the last release that contained it |

The pinned gnark implementation survives **only** as a non-published fixture
generator at `assurance/gnark-fixtures/`. It keeps the committed independent
PlonK BLS12-381 vectors in `zeroj-test-vectors` reproducible, so
`GnarkTranscriptCompatTest` continues to check ZeroJ's Fiat-Shamir transcript
against an implementation ZeroJ does not control. It exposes no Java API, builds
no shared library, and is absent from the runtime dependency graph.

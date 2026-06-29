# ZeroJ

> [!WARNING]
> **Status: Experimental — Research & Learning Project**
>
> This project is generated using AI, with human-assisted design, testing, and verification.
> It is an experimental project created mainly for research and exploration purposes.
>
> **Please do not use this in production.** Expect rough edges, incomplete features, and potential bugs.

Java-first zero-knowledge proof toolkit for Cardano.

ZeroJ lets Java developers **define ZK circuits**, **generate proofs**, **verify** them off-chain, and **execute on-chain verification** on Cardano. The Java DSL and pure-Java proving path require no native libraries or external CLIs.

## What You Can Do Today

### Define ZK Circuits
- **CircuitSpec Java DSL** (recommended) — define circuits as reusable Java classes with `CircuitSpec`
- **Inline lambda DSL** — quick prototyping with `CircuitBuilder.define(api -> ...)`
- **circom interop** — use externally compiled circom/snarkjs artifacts (`.r1cs`, `.zkey`, `.wtns`; `.wasm` witness calculation in incubator)
- **Standard library** — Poseidon, PoseidonN, MiMC, MiMCSponge, Merkle, Comparators, Binary, Mux, AliasCheck, symbolic `Zk*` adapters, and a per-gadget status table in [`zeroj-circuit-lib`](zeroj-circuit-lib/README.md)
- **Multi-backend compilation** — one Java circuit can compile to R1CS for Groth16 or to PlonK

### Generate Proofs
- **Pure Java prover** (recommended) — Groth16 + PlonK for BLS12-381. Zero native dependencies. GraalVM compatible.
- **gnark FFM** — optional in-process Groth16/PlonK proving via Go native library
- **snarkjs CLI** — external CLI for circom-based circuits
- **snarkjs key import** — import `.zkey` files, prove with the pure Java prover

### Verify ZK Proofs (Pure Java, Zero Native Deps)
- **Groth16 BLS12-381** — pure Java verification; optional blst-backed native verifier is also available
- **PlonK BLS12-381** — pure Java verification
- **BN254 is disabled by default** — legacy off-chain proving and verification classes remain for explicit experiments only (`-Dzeroj.allowLegacyBn254=true`); BN254 is not a Cardano on-chain curve.
- Parse snarkjs proof artifacts (`proof.json`, `verification_key.json`, `public.json`)
- Pluggable backend SPI — add new proof systems without changing application code

### Verify On-Chain (Cardano Plutus V3)
- **Groth16 BLS12-381** — reusable Plutus V3 spending validator via Julc
- **PlonK BLS12-381** — experimental Julc validators; supported profiles perform the KZG pairing check, but value-bearing use remains gated pending release gates and external review
- VK baked at deploy time, proof passed as redeemer, public inputs as datum
- **Proven end-to-end for Groth16**: Java DSL circuit → pure Java prove → Yaci DevKit on-chain verify

Reusable on-chain verifiers only verify the cryptographic proof statement. A
real application validator must also bind replay protection, nullifiers,
authorization, and any `ScriptContext` policy required by the business flow.

### Anchor on Cardano L1
- 4 anchor patterns: proof hash, state root + proof hash, full verification ref, nullifier commitment
- CCL integration — fluent helpers for attaching proof metadata to transactions

## Quick Start — Zero Dependencies

Define a circuit, prove it, and verify — all in pure Java.

ZeroJ supports multiple ways to write the same circuit. For new application
circuits, start with symbolic annotations. Use `CircuitSpec` when you want a
manual reusable circuit class, and use the inline DSL for small tests or
experiments.

### Recommended: Symbolic Annotations

```java
// Define the circuit with @ZKCircuit and symbolic Zk* values.
@ZKCircuit(name = "secret-multiplier", version = 1)
public class SecretMultiplier {
    @Prove
    ZkBool prove(
            ZkContext zk,
            @Public ZkField a,
            @Public ZkField product,
            @Secret ZkField b) {
        return a.mul(b).isEqual(product);
    }
}

// The annotation processor generates SecretMultiplierCircuit.
var circuit = SecretMultiplierCircuit.build();
```

### Equivalent CircuitSpec

```java
public class SecretMultiplierSpecCircuit implements CircuitSpec {
    @Override
    public void define(SignalBuilder c) {
        Signal a = c.publicInput("a");
        Signal b = c.privateInput("b");       // secret — never revealed
        Signal product = c.publicOutput("product");
        c.assertEqual(a.mul(b), product);
    }

    public static CircuitBuilder build() {
        return CircuitBuilder.create("secret-multiplier")
                .publicVar("a").publicVar("product").secretVar("b")
                .defineSignals(new SecretMultiplierSpecCircuit());
    }
}

var circuit = SecretMultiplierSpecCircuit.build();
```

Choose one definition style. Both produce a `CircuitBuilder`, and the proof flow
is the same after that point:

```java
// 1. Compile and compute witness
var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
var witness = circuit.calculateWitness(Map.of(
    "a", List.of(BigInteger.valueOf(3)),
    "b", List.of(BigInteger.valueOf(11)),      // secret!
    "product", List.of(BigInteger.valueOf(33))
), CurveId.BLS12_381);

// 2. Setup + Prove (pure Java — zero native dependencies)
// Dev/test only; requires -Dzeroj.allowInsecureTrustedSetup=true.
var srs = PowersOfTauBLS381.generate(4);
var constraints = r1cs.constraints();
var setup = Groth16SetupBLS381.setup(
        constraints, r1cs.numWires(), r1cs.numPublicInputs(), srs.tauScalar());
var proof = Groth16ProverBLS381.prove(
        setup.provingKey(), witness, constraints, r1cs.numWires());

// 3. Verify off-chain (pure Java)
boolean valid = BLS12381Pairing.pairingCheck(...);  // Groth16 pairing equation

// 4. Verify on-chain (Cardano Plutus V3)
var script = JulcScriptLoader.load(Groth16BLS12381Verifier.class, vkParams...);
// Lock ADA → unlock with ZK proof → Cardano verifies BLS12-381 pairing
```

For setup beyond local tests, use an MPC ceremony `.zkey` instead of
`PowersOfTauBLS381.generate()`. See the
[Pure Java Prover Guide](docs/pure-java-prover-guide.md).

### Alternative: gnark FFM

```java
// Same circuit, but prove via gnark (requires Go native lib)
try (var prover = new GnarkProver()) {
    var result = prover.groth16FullProve(r1cs, witness, CurveId.BLS12_381);
    String proofJson = result.proveResponse().proofJson();
    String vkJson = result.vkJson();
    List<BigInteger> publicSignals = result.proveResponse().publicSignals();
}
```

See [Alternate Prover Backends](docs/alternate-prover-backends.md).

## Prerequisites

### Required

| Dependency | Version | Notes |
|------------|---------|-------|
| **Java** | 25+ | GraalVM recommended for native-image support |
| **Gradle** | 9.2+ | Included via wrapper (`./gradlew`) |

Install Java 25 with [SDKMAN!](https://sdkman.io/):

```bash
sdk install java 25.0.2-graal
sdk use java 25.0.2-graal
```

### Optional (for specific backends)

| Dependency | Version | Required By | Notes |
|------------|---------|-------------|-------|
| **Go** | 1.21+ | `zeroj-prover-gnark` | For the optional gnark native prover |
| **circom** | 2.x | Circuit compilation (if using circom) | `cargo install circom` |
| **snarkjs** | 0.7+ | Proof generation (if using snarkjs) | `npm install -g snarkjs` |

The **pure Java prover and verifier require no optional dependencies**.

## Building

```bash
# Build the full repository, including opt-in WASM/native modules
./gradlew build

# Build the core privacy path only
./gradlew :zeroj-bom-core:build :zeroj-verifier-core:build :zeroj-verifier-groth16:build :zeroj-verifier-plonk:build :zeroj-crypto:build :zeroj-onchain-julc:build

# Run all tests
./gradlew test

# Run end-to-end on-chain tests (requires Yaci DevKit)
./gradlew :zeroj-examples:e2eTest
```

## Architecture

```
         CircuitSpec (Java DSL)           circom (.circom)
                  │                            │
         compileR1CS(BLS12_381)         snarkjs setup → .zkey
                  │                            │
                  │                   ZkeyImporterBLS381
                  │                            │
                  └──────────┬─────────────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
     Pure Java Prover               gnark FFM Prover
     (Groth16ProverBLS381)          (GnarkProver)
     Zero native deps               Optional native backend
              │                             │
              └──────────┬──────────────────┘
                         │
                Pure Java Verify
             (BLS12381Pairing / Verifier SPI)
                         │
                On-Chain Verify (Julc)
             (Plutus V3, BLS12-381 pairings)
                         │
                 Yaci DevKit / Cardano
```

### Module Organization

#### Core Modules (`zeroj-bom-core`)

| Module | Description |
|--------|-------------|
| [`zeroj-api`](zeroj-api/) | Core proof model, envelopes, verification result types |
| [`zeroj-codec`](zeroj-codec/) | Proof serialization — snarkjs JSON, CBOR, canonical hashing |
| [`zeroj-backend-spi`](zeroj-backend-spi/) | Service Provider Interface for verification backends |
| [`zeroj-verifier-core`](zeroj-verifier-core/) | Verifier orchestration and backend routing |
| [`zeroj-verifier-groth16`](zeroj-verifier-groth16/) | Groth16 verification — BLS12-381 pure Java/native blst; BN254 legacy verifier disabled by default |
| [`zeroj-verifier-plonk`](zeroj-verifier-plonk/) | PlonK verification — BLS12-381 pure Java; BN254 legacy verifier disabled by default |
| [`zeroj-bls12381`](zeroj-bls12381/) | Pure Java BLS12-381 field, curve, and pairing primitives |
| [`zeroj-blst`](zeroj-blst/) | BLS12-381 pairing operations via blst native library |
| [`zeroj-crypto`](zeroj-crypto/) | **Pure Java prover** — Montgomery field arithmetic, EC operations, Groth16 + PlonK for BLS12-381; BN254 high-level proving APIs require legacy opt-in |
| [`zeroj-circuit-dsl`](zeroj-circuit-dsl/) | Java Circuit DSL — define circuits with CircuitSpec, compile to R1CS/PlonK |
| [`zeroj-circuit-lib`](zeroj-circuit-lib/) | Circuit standard library — Poseidon, PoseidonN, MiMC, MiMCSponge, Merkle, Comparators, Binary, Mux, AliasCheck, symbolic adapters, and [per-gadget status](zeroj-circuit-lib/README.md#gadget-status) |
| [`zeroj-prover-spi`](zeroj-prover-spi/) | Minimal prover request/response SPI shared by prover implementations |
| [`zeroj-prover-gnark`](zeroj-prover-gnark/) | gnark native prover (Groth16 + PlonK) via FFM |
| [`zeroj-patterns`](zeroj-patterns/) | High-level ZK patterns — state transitions, nullifier claims, membership proofs |
| [`zeroj-cardano`](zeroj-cardano/) | Cardano anchoring — proof anchor model, metadata encoding |
| [`zeroj-ccl`](zeroj-ccl/) | Cardano Client Lib integration — fluent transaction helpers |
| [`zeroj-onchain-julc`](zeroj-onchain-julc/) | Reusable Plutus V3 on-chain verifiers via Julc; Groth16 is the primary supported path, PlonK is an experimental prototype |

#### Mainline Opt-In Modules (`zeroj-bom-all` only)

| Module | Description |
|--------|-------------|
| [`zeroj-bbs`](zeroj-bbs/) | BBS/BBS+ selective disclosure credential backend |
| [`zeroj-bbs-wasm`](zeroj-bbs-wasm/) | WASM-backed BBS provider |
| [`zeroj-bls12381-wasm`](zeroj-bls12381-wasm/) | WASM-backed BLS12-381 provider |

#### Support Modules

| Module | Description |
|--------|-------------|
| [`zeroj-test-vectors`](zeroj-test-vectors/) | Shared test fixtures — pre-generated proofs and VKs |
| [`zeroj-examples`](zeroj-examples/) | End-to-end demos: circuit definition to on-chain verification |
| [`zeroj-bom-core`](zeroj-bom-core/) | BOM for the v3 core path |
| [`zeroj-bom-all`](zeroj-bom-all/) | BOM for core plus opt-in and incubator modules |

#### Incubator Modules (`incubator/`)

| Module | Description |
|--------|-------------|
| [`zeroj-prover-wasm`](incubator/zeroj-prover-wasm/) | Circom witness calculation via GraalVM WebAssembly |

## Dependency (Gradle)

```gradle
dependencies {
    implementation platform('com.bloxbean.cardano:zeroj-bom-core:0.1.0')

    // Circuit definition + standard library
    implementation 'com.bloxbean.cardano:zeroj-circuit-dsl'
    implementation 'com.bloxbean.cardano:zeroj-circuit-lib'

    // Pure Java prover (Groth16 + PlonK, BLS12-381)
    implementation 'com.bloxbean.cardano:zeroj-crypto'

    // Verification (pure Java, zero native deps)
    implementation 'com.bloxbean.cardano:zeroj-verifier-core'
    implementation 'com.bloxbean.cardano:zeroj-verifier-groth16'
    implementation 'com.bloxbean.cardano:zeroj-verifier-plonk'

    // On-chain verification (Cardano Plutus V3)
    implementation 'com.bloxbean.cardano:zeroj-onchain-julc'

    // Optional: gnark FFM prover (requires Go native lib)
    // implementation 'com.bloxbean.cardano:zeroj-prover-gnark'
}
```

## Documentation

### Guides
- **[Getting Started](docs/getting-started.md)** — end-to-end: circuit to on-chain verification
- **[ZK Trusted Setup Beginner Guide](docs/zk-trusted-setup-beginner-guide.md)** — tau, SRS, Powers of Tau, Groth16 phases, and PlonK setup
- **[Pure Java Prover Guide](docs/pure-java-prover-guide.md)** — zero-dependency proving pipeline
- **[Circuit DSL User Guide](docs/circuit-dsl-user-guide.md)** — CircuitSpec, Signal API, standard library
- **[Circuit Library Gadget Status](zeroj-circuit-lib/README.md#gadget-status)** — current curve, symbolic, and Cardano-readiness status for each reusable gadget
- **[Alternate Prover Backends](docs/alternate-prover-backends.md)** — gnark FFM and snarkjs
- **[Architecture Overview](docs/architecture-overview.md)** — module design and layer separation
- **[PlonK Support](docs/plonk-support.md)** — PlonK proving, off-chain verification, and the experimental Julc prototype

### Use Cases
- **[ZK Use Cases on Cardano](docs/usecases/README.md)** — 8 real-world applications with secret/public input breakdowns
- **[Private Voting — Detailed Design](docs/usecases/private-voting.md)** — nullifiers, UTXO patterns, Julc contracts, architecture

### Architecture Decision Records
- [ADR-0001: Verifier-First Architecture](docs/adr/0001-verifier-first-architecture.md)
- [ADR-0003: Hybrid Crypto Backend](docs/adr/0003-pure-java-mvp.md)
- [ADR-0007: Module Structure](docs/adr/0007-module-structure-and-boundaries.md)
- [ADR-0010: Java Circuit DSL](docs/adr/0010-java-circuit-dsl.md)
- [ADR-0012: Pure Java Provers](docs/adr/0012-pure-java-provers-groth16-plonk.md)

## Examples

| Example | What It Demonstrates |
|---------|---------------------|
| `SealedBidPureJavaE2ETest` | BLS12-381 Poseidon commitment + range proof → pure Java prove → pairing verify |
| `AnonymousVotingPureJavaE2ETest` | BLS12-381 Poseidon commitment + boolean → prove → verify |
| `BalanceThresholdPureJavaE2ETest` | Range comparison → prove → verify |
| `PureJavaProverYaciE2ETest` | **Full stack: prove → Yaci DevKit on-chain verify** |
| `CircomToOnChainE2ETest` | circom `.zkey` → Java prove → Julc VM on-chain verify |
| `ParameterizedCircuitE2ETest` | Parameterized circuits (depth, arity, hash function) |
| `Groth16BLS381ZkeyEndToEndTest` | snarkjs `.zkey` import → Java prove → pairing verify |

```bash
# Run all examples (off-chain)
./gradlew :zeroj-examples:test

# Run on-chain tests (requires Yaci DevKit)
./gradlew :zeroj-examples:e2eTest
```

## License

MIT License — see [LICENSE](LICENSE) for details.

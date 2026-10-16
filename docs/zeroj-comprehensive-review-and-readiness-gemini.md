# ZeroJ: Comprehensive Cryptographic Review, Release Readiness & Technical Debt Assessment

**Review Date**: August 2026  
**Auditor / Reviewer**: Google DeepMind / Antigravity (Gemini 3.7)  
**Baseline Evaluated**: `0.1.0-pre5` / Main branch (`zeroj` repository)  
**Evidence Baseline**: 3,540+ passing unit/integration tests across all active modules; live end-to-end Cardano Plutus V3 on-chain pairing verification against Yaci DevKit; 5M-entry authenticated state tree benchmarks.

---

## 1. Executive Summary & Cryptographic Posture

**ZeroJ** is an open-source, Java-first Zero-Knowledge proof and credential toolkit specifically engineered for the Cardano blockchain ecosystem. Its mission is to enable JVM developers to define ZK circuits, calculate witnesses, generate proofs, verify proofs off-chain, and execute on-chain Plutus V3 verifications without requiring external CLIs, Node.js runtimes, or complex C/C++ build chains.

### Core Architectural Accomplishments
1. **High-Fidelity Cryptographic Primitives**:
   - **BLS12-381 Point Encodings**: Adheres strictly to IETF / ZCash serialization specifications (compression flags, $G_2$ coordinate endianness, sort-bit rules, field element canonical range $x < p$).
   - **Hash-to-Curve**: Complete RFC 9380 Simplified Shallue-van de Woestijne-Ulas (SSWU) implementation passing official test vectors.
   - **CFRG BBS Credentials**: Fully compliant with IRTF CFRG draft-10 for both SHA-256 and SHAKE-256 ciphersuites.
   - **PlonK Fiat-Shamir Transcript**: Absorptions, MPI domain tags, and challenge derivations are byte-identical across the pure Java prover, off-chain verifier, and on-chain Plutus V3 UPLC script.
2. **Breakthrough Memory Architecture for Large Circuits**:
   - Through ADR-0033/0034/0035/0036, ZeroJ solved the classic JVM ZK memory wall. By utilizing flat-limb Montgomery representations, compressed sparse-row (CSR) constraint matrices, disk-streamed trusted setups, and memory-mapped sparse proving key files (`Groth16PkStore` / `Groth16Pipeline`), ZeroJ can prove massive circuits (~19M constraints for CIP-1852 / Ed25519 Cardano key ownership) within $\le 8\text{ GB}$ of JVM heap without JNI or native memory leaks.
3. **End-to-End On-Chain Verifier Execution**:
   - Proven live on Cardano Plutus V3 using `Groth16BLS12381Lib` / `Groth16BLS12381TxOutRefBindingVerifier`. Execution consumes ~2.14e9 CPU units and ~71.5k memory units (~21% of the Cardano transaction budget limit for 2 public inputs).

---

## 2. Deep-Dive Cryptographic Correctness & Security Audit Feedback

### 2.1 Elliptic Curve & Pairing Primitives (`zeroj-bls12381`, `zeroj-blst`)

| Finding ID | Severity | Area | Description & Security Impact | Remediation Recommendation |
| :--- | :---: | :--- | :--- | :--- |
| **SEC-01** | **HIGH** | Subgroup Checks | In `G1Point.java` and `G2Point.java`, `isInSubgroup()` performs a full affine scalar multiplication by the 255-bit scalar field order $r$ (`scalarMul(R)`). This is computationally expensive ($O(\log r)$ doublings/additions in affine space). In untrusted deserialization endpoints (e.g. proof verification services), verifying untrusted $G_1/G_2$ points creates a **severe CPU DoS vulnerability**. | Implement **fast endomorphism-based subgroup checks**: Bowe's check for $G_1$ ($(z^2-1)\phi(P) = \mathcal{O}$) and Scott / $\psi$-endomorphism check for $G_2$. |
| **SEC-02** | **HIGH** | Pairing Engine | In `BLS12381Pairing.java`, final exponentiation computes $f^{(p^{12}-1)/r}$. The hard part is evaluated via `t2.pow(hardExp)` where `hardExp` is a ~2031-bit integer. This generic `BigInteger` exponentiation is an order of magnitude slower than optimal. | Refactor final exponentiation to utilize **cyclotomic squaring** in $F_{p^12}$, Frobenius automorphisms, and the addition chain for the BLS parameter $x = -0xd201000000010000$. |
| **SEC-03** | **MEDIUM** | Side Channels | Pure Java cryptographic operations (BBS issuer signing, Jubjub signing, scalar multiplication) route secret keys through `java.math.BigInteger`. `BigInteger` is inherently variable-time (branching on bit lengths, non-constant-time modular inversion). | Do not run private issuer/prover keys in shared or multi-tenant cloud JVMs with the pure-Java backend. Require `zeroj-blst` for secret-bearing operations. |

---

### 2.2 Proof Systems & Setup Pipeline (`zeroj-crypto`, `zeroj-tools`)

| Finding ID | Severity | Area | Description & Security Impact | Remediation Recommendation |
| :--- | :---: | :--- | :--- | :--- |
| **SEC-04** | **MEDIUM** | Trusted Setup | `PowersOfTauBLS381` and `Groth16SetupBLS381` generate single-party in-memory setups with known toxic waste $\tau$. | Keep `-Dzeroj.allowInsecureTrustedSetup=true` strictly required for in-memory setup. Mandate snarkjs Phase-2 ceremony `.zkey` artifacts or `zeroj-tools` / `ZkeyContributor` for any production deployment. |
| **SEC-05** | **LOW** | PlonK Blinding | `PlonKProverBLS381.java` generates 9 blinding scalars. Snarkjs and the PlonK reference paper use 11 scalars (including $b_{10}, b_{11}$ for quotient split polynomials). | Add the 2 missing blinding scalars to guarantee exact statistical ZK margins under repeated queries. |
| **SEC-06** | **MEDIUM** | Interoperability | Verification of snarkjs-generated proofs in ZeroJ is extensively tested. However, continuous verification of ZeroJ-generated proofs by `snarkjs verify` CLI is not automated in CI. | Add automated bidirectional CI tests where snarkjs CLI validates proofs generated by `Groth16ProverBLS381` and `PlonKProverBLS381`. |

---

### 2.3 Circuit DSL & Gadgets (`zeroj-circuit-dsl`, `zeroj-circuit-lib`)

| Finding ID | Severity | Area | Description & Security Impact | Remediation Recommendation |
| :--- | :---: | :--- | :--- | :--- |
| **SEC-07** | **HIGH** | Comparator Soundness | In earlier versions, comparator gadgets did not enforce range checks on both operands, allowing wraparound modulo $r$. | ZeroJ hardened `CircuitAPI.lessThan` to constrain both variable operands to $n$ bits and validate `BitDecomposition` circuit ownership. Ensure developers use `ZkUInt` which enforces ranges on instantiation. |
| **SEC-08** | **MEDIUM** | Jubjub Point Binding | Prover-supplied Edwards curve points could be forged if not explicitly constrained to the curve. | All prover-supplied points in `InCircuitJubjub` must use `witnessAffine(...)` ($Z=1, T=u \cdot v$) or `assertWellFormed(...)`. Enforce strict verifiers (`verifyStrict`) when the public key is secret or supplied by the prover. |

---

### 2.4 Cardano On-Chain Validation (`zeroj-onchain-julc`)

| Finding ID | Severity | Area | Description & Security Impact | Remediation Recommendation |
| :--- | :---: | :--- | :--- | :--- |
| **SEC-09** | **CRITICAL** | Replay & Front-running | A generic ZK verifier script that only validates the proof statement (`verify(datum, proof, vk)`) is vulnerable to transaction front-running and replay attacks on Cardano. An attacker can copy a valid proof from the mempool and attach their own payout address. | Never deploy generic verifiers for value-bearing transactions. Always use `Groth16BLS12381TxOutRefBindingVerifier` or bind the first public input to `blake2b_256(spentTxId \|\| outputIndex) mod Fr`, signer PKH, and application nullifiers. |
| **SEC-10** | **MEDIUM** | PlonK On-Chain Cost | The on-chain PlonK verifier (`PlonkBLS12381Lib`) consumes ~4.8–4.95e9 CPU units (~49% of block budget), limiting transaction composability. | Optimize the linearized polynomial computation and scalar multiplications in Plutus Core to bring CPU cost closer to Groth16 levels (~2.1e9 CPU). |

---

## 3. Module Pruning & Technical Debt Cleanup

Over the course of ZeroJ's rapid evolution, several experimental proofs-of-concept (POCs), redundant native wrappers, and legacy artifacts accumulated in the repository. Removing these will dramatically simplify the codebase, accelerate build times, reduce security attack surfaces, and provide a clean, production-focused API.

```
┌────────────────────────────────────────────────────────────────────────┐
│                       PROPOSED MODULE CLEANUP                          │
├─────────────────────────┬──────────────────────────────────────────────┤
│ 🗑️ REMOVE               │ • incubator/zeroj-verifier-halo2             │
│   (Dead POCs & Debt)    │ • incubator/zeroj-prover-wasm                │
│                         │ • zeroj-prover-gnark                         │
│                         │ • zeroj-bls12381-wasm                        │
│                         │ • zeroj-bbs-wasm                             │
│                         │ • zeroj-mpf-poseidon-load (move to bench)    │
│                         │ • zeroj-jmt-poseidon-load (move to bench)    │
│                         │ • Legacy BN254 classes across core           │
├─────────────────────────┼──────────────────────────────────────────────┤
│ 🔄 CONSOLIDATE          │ • zeroj-ceremony ──► merge into zeroj-tools │
│   (Streamline footprint)│ • zeroj-patterns ──► merge into zeroj-cardano│
│                         │ • zeroj-mpf/jmt  ──► merge into state-poseidon│
└─────────────────────────┴──────────────────────────────────────────────┘
```

### 3.1 Modules Recommended for Immediate Removal

#### 1. `incubator/zeroj-verifier-halo2` (`zeroj-verifier-halo2`)
- **Reason**: Experimental POC for Halo2 verification on the Pallas curve via Rust FFM bindings.
- **Why Remove**: Cardano Plutus V3 has no support for Halo2 IPA or Pallas curve. Requires external Rust compilation (`cargo build`), creates build friction, and is disconnected from Cardano's BLS12-381 roadmap.
- **Action**: Delete directory and remove from `settings.gradle`.

#### 2. `incubator/zeroj-prover-wasm` (`zeroj-prover-wasm`)
- **Reason**: Experimental GraalVM WASM runner to compute circom witnesses without Node.js.
- **Why Remove**: Pulls in heavy GraalVM polyglot dependencies (`org.graalvm.polyglot:wasm/js`). ZeroJ now features its own pure-Java `CircuitSpec` DSL and witness calculator that runs directly on the JVM without circom WASM compilation.
- **Action**: Delete directory and remove from `settings.gradle`.

#### 3. `zeroj-prover-gnark`
- **Reason**: Go-based gnark prover FFM wrapper.
- **Why Remove**: Requires CGO, Go 1.21+, and shipping platform-dependent ~50MB binaries containing the Go runtime. ZeroJ's pure-Java prover (`zeroj-crypto`) combined with `zeroj-crypto-blst` achieves comparable performance without foreign runtime overhead.
- **Action**: Deprecate and remove from the main repository.

#### 4. `zeroj-bls12381-wasm` and `zeroj-bbs-wasm`
- **Reason**: Rust implementations compiled to WASM and interpreted via Chicory.
- **Why Remove**: Pure Java (`zeroj-bls12381`, `zeroj-bbs`) and native FFM (`zeroj-blst`) provide complete functionality with much higher throughput (Chicory WASM interpretation is single-threaded and slow for pairing arithmetic). Requires Rust toolchains (`wasm32-unknown-unknown`) during Gradle builds.
- **Action**: Remove both WASM modules from the core build.

#### 5. Legacy BN254 Code & Classes
- **Reason**: Early Groth16/PlonK implementations on the Ethereum-native BN254 curve (`Groth16Setup`, `Groth16Prover`, `PlonKSetup`, `PlonKProver`, `MiMC`).
- **Why Remove**: BN254 is not supported on Cardano L1. It is disabled by default (`-Dzeroj.allowLegacyBn254=true`) and lacks the security hardening of the BLS12-381 pipeline.
- **Action**: Delete legacy BN254 classes from `zeroj-crypto`, `zeroj-verifier-groth16`, `zeroj-verifier-plonk`, and `zeroj-circuit-lib`.

#### 6. Benchmark Load Harnesses (`zeroj-mpf-poseidon-load`, `zeroj-jmt-poseidon-load`)
- **Reason**: Standalone, non-published load tools used for the 5M-entry stress benchmarks.
- **Why Relocate**: They pull in RocksDB dependencies and contain non-production harness code. Their experimental validation data is already preserved in `docs/benchmarks/`.
- **Action**: Move out of root `settings.gradle` into a dedicated `benchmarks/` folder.

---

### 3.2 Modules Recommended for Consolidation

1. **Merge `zeroj-ceremony` into `zeroj-tools`**:
   - `zeroj-tools` contains the reusable library code (`ZkeyContributor`, `SnarkjsHashToG2`), while `zeroj-ceremony` is just a single CLI class (`CeremonyCli.java`). Merging them eliminates an unnecessary module boundary.
2. **Merge `zeroj-patterns` into `zeroj-cardano` / `zeroj-ccl`**:
   - `zeroj-patterns` contains only 5 small classes (`MembershipProof`, `StateTransition`). Folding it into `zeroj-cardano` simplifies dependency management for developers.
3. **Unify `zeroj-mpf-poseidon` & `zeroj-jmt-poseidon`**:
   - Merge both into a single `zeroj-state-poseidon` module with `mpf` and `jmt` packages.

---

## 4. Component-by-Component Release Readiness Assessment

Risk Classification:
- **R0**: Build, documentation, test utilities.
- **R1**: Correctness-critical APIs, codecs, orchestration logic.
- **R2**: Security-sensitive validation, circuit gadgets, on-chain smart contracts.
- **R3**: Primitives, curve/field arithmetic, side-channel sensitive operations, proof systems.

```
========================================================================================
                               RELEASE READINESS SUMMARY
========================================================================================
🟢 PRODUCTION READY / STABLE BETA (Testnet Verified)
   ├── zeroj-api [R1]
   ├── zeroj-codec [R2]
   ├── zeroj-backend-spi [R1]
   ├── zeroj-verifier-core [R1]
   ├── zeroj-verifier-groth16 [R2]
   ├── zeroj-circuit-dsl [R1]
   ├── zeroj-circuit-annotation-api / processor [R1]
   ├── zeroj-circuit-lib [R2]
   ├── zeroj-crypto (Groth16) [R3]
   ├── zeroj-tools [R2]
   ├── zeroj-cardano / zeroj-ccl [R1]
   └── zeroj-onchain-julc (Groth16) [R2]

🟡 BETA WITH GATED CAVEATS (Requires blst / Setup Pinning)
   ├── zeroj-bls12381 (Pure Java) [R3] (Needs fast subgroup checks & cyclotomic final exp)
   ├── zeroj-blst [R3] (FFM native wrapper; needs GraalVM native image CI smoke test)
   ├── zeroj-crypto (PlonK) [R3] (Needs b10/b11 blinding & O(n log n) FFT scaling)
   ├── zeroj-verifier-plonk [R2] (Off-chain verifier complete; awaits external audit)
   └── zeroj-bbs [R3] (CFRG draft-10 complete; pure Java variable-time; blst required for issuers)

🟠 EXPERIMENTAL / LABELED TESTNET ONLY
   ├── zeroj-onchain-julc (PlonK) [R2] (Functional KZG check; high CPU budget ~4.9e9)
   ├── zeroj-mpf-poseidon [R2] (5M benchmark passed; large circuit size)
   └── zeroj-jmt-poseidon [R2] (5M benchmark passed; large circuit size)

🔴 DEPRECATE / REMOVE (Technical Debt)
   ├── incubator/zeroj-verifier-halo2 [R2]
   ├── incubator/zeroj-prover-wasm [R2]
   ├── zeroj-prover-gnark [R2]
   ├── zeroj-bls12381-wasm [R3]
   ├── zeroj-bbs-wasm [R3]
   └── Legacy BN254 classes across core modules
========================================================================================
```

### Detailed Component Assessment Table

| Component / Module | Risk | Status | Release Readiness Assessment | Production & Audit Gates Remaining |
| :--- | :---: | :---: | :--- | :--- |
| **`zeroj-api`** | R1 | **Beta** | Clean proof envelopes, typed public inputs, and verification results. | API freeze review for v1.0. |
| **`zeroj-codec`** | R2 | **Beta** | Strict snarkjs JSON parsing (duplicate keys, bounds checks), canonical CBOR. | External parser fuzzing. |
| **`zeroj-backend-spi`** | R1 | **Beta** | SPI abstraction for proof backends and verifier registry. | None. |
| **`zeroj-verifier-core`** | R1 | **Beta** | Verifier orchestration, schema routing, and dispatch. | None. |
| **`zeroj-bls12381`** | R3 | **Beta** | Pure-Java field, curve, pairing, hash-to-curve (RFC 9380). | Fast subgroup checks; cyclotomic final exponentiation; formal crypto review. |
| **`zeroj-blst`** | R3 | **Beta (Opt-in)** | FFM native bindings to pinned `libblst` v0.3.15. High-speed MSM and pairing. | GraalVM native image automated CI tests. |
| **`zeroj-crypto` (Groth16)** | R3 | **Beta** | Advanced pure-Java prover. `Groth16Pipeline`/`Groth16PkStore` proves ~19M constraints in commodity heap. | SHA-256 pinning of official MPC ceremony artifacts. |
| **`zeroj-crypto` (PlonK)** | R3 | **Beta** | 5-round PlonK prover, `.zkey`/`.ptau` import. | Add $b_{10}, b_{11}$ blinding; implement $O(n \log n)$ coset FFTs. |
| **`zeroj-crypto-blst`** | R3 | **Beta (Opt-in)** | Bridge routing `zeroj-blst` MSM into `zeroj-crypto` prover pipeline. | None. |
| **`zeroj-verifier-groth16`** | R2 | **Beta** | Strict point validation, subgroup checks, canonical scalar range `[0, r)`. | Differential fuzzing against snarkjs/arkworks. |
| **`zeroj-verifier-plonk`** | R2 | **Beta** | Full KZG batch pairing check. Fiat-Shamir transcript verified byte-for-byte. | Independent cryptographic audit. |
| **`zeroj-circuit-dsl`** | R1 | **Beta** | `CircuitSpec`, `SignalBuilder`, constant-one wire pinning, R1CS/PlonK compilers. | Static linter for unconstrained wires. |
| **`zeroj-circuit-annotation-*`**| R1 | **Beta** | `@ZKCircuit` annotation processor with `Zk*` symbolic types. | None. |
| **`zeroj-circuit-lib`** | R2 | **Beta** | Standard gadgets (Poseidon, Merkle, Comparators, Blake2b, SHA-512, CIP-1852). | Independent circuit soundness review. |
| **`zeroj-onchain-julc` (Groth16)** | R2 | **Beta (Testnet)** | Plutus V3 spending validator verified on Yaci DevKit (~21% CPU budget). TxOutRef binding. | External smart contract audit for mainnet deployment. |
| **`zeroj-onchain-julc` (PlonK)** | R2 | **Experimental** | Linearized polynomial + batched KZG check (~4.9e9 CPU budget). | CPU budget optimization. |
| **`zeroj-bbs`** | R3 | **Beta** | Byte-exact against CFRG draft-10 vectors. Secret key redacted. | CFRG RFC ratification; mandate `blst` for issuers. |
| **`zeroj-cardano` & `zeroj-ccl`** | R1 | **Beta** | 4 anchor patterns, CIP-30 / CCL integration. | None. |
| **`zeroj-patterns`** | R2 | **Beta** | Reusable state transition and nullifier claim patterns. | Merge into `zeroj-cardano`. |
| **`zeroj-tools`** | R2 | **Beta** | snarkjs-compatible Phase-2 contributor (`ZkeyContributor`). | Standalone transcript verification CLI. |
| **`zeroj-mpf-poseidon`** | R2 | **Experimental** | Poseidon-rooted MPF circuits (inclusion, update, split insert). 5M tested. | Circuit constraint tuning for on-chain verifier. |
| **`zeroj-jmt-poseidon`** | R2 | **Experimental** | Poseidon-rooted JMT circuits. 5M tested. | Circuit constraint tuning. |

---

## 5. Prioritized List of Enhancements & Roadmap

### 5.1 Cryptographic Soundness & Security (P0 / P1)

```
[P0 / P1 Security Enhancements]
 ├── 1. Fast Subgroup Checks (Bowe G1 + Scott/Psi G2) ──────► Eliminates CPU DoS
 ├── 2. Cyclotomic Final Exponentiation ────────────────────► 10x Pairing Speedup
 ├── 3. PlonK 11-Scalar Blinding (b10, b11) ────────────────► Full Snarkjs Parity
 └── 4. Bidirectional Interop CI (Snarkjs CLI) ─────────────► Verifies ZeroJ Proofs
```

1. **Fast Endomorphism-Based Subgroup Checks**:
   - Replace full scalar multiplication ($r \cdot P$) in `G1Point` and `G2Point` with Bowe's endomorphism test for $G_1$ ($(z^2-1)\phi(P) = \mathcal{O}$) and the $\psi$-endomorphism test for $G_2$. This resolves the deserialization CPU DoS risk on untrusted inputs.
2. **Dedicated Cyclotomic Final Exponentiation**:
   - Rewrite final exponentiation in `BLS12381Pairing.java` using cyclotomic squaring in $F_{p^{12}}$, Frobenius automorphisms, and addition chains for the BLS parameter $x = -0xd201000000010000$.
3. **PlonK Full 11-Scalar Blinding**:
   - Implement $b_{10}, b_{11}$ quotient polynomial blinding scalars in `PlonKProverBLS381.java` to align with snarkjs and the PlonK reference paper.
4. **Continuous Bidirectional CI Testing**:
   - Add a GitHub Actions CI step where `snarkjs verify` validates proofs produced by ZeroJ's `Groth16ProverBLS381` and `PlonKProverBLS381`.

---

### 5.2 Prover Performance & Scalability (P1 / P2)

1. **Parallel Multi-Scalar Multiplication (MSM)**:
   - Implement multithreaded chunked Pippenger MSM in `zeroj-crypto` using Java 25 virtual threads or ForkJoinPool, bringing pure-Java MSM performance within 1.5x of native `blst`.
2. **PlonK FFT / Coset NTT Acceleration**:
   - Replace $O(n^2)$ polynomial evaluation loops in `PlonKSetupBLS381` and `PlonKProverBLS381` with $O(n \log n)$ radix-2 Fast Fourier Transforms over the scalar field.
3. **ZKey Sparse Store Converter Tool**:
   - Provide a CLI utility in `zeroj-tools` to convert existing `.zkey` files directly into ZeroJ's high-speed memory-mapped sparse `.bin` store format.

---

### 5.3 Circuit DSL & Developer Ergonomics (P2)

1. **Static Analysis Linter for Unconstrained Signals**:
   - Build a compiler-time check in `zeroj-circuit-dsl` that warns developers if a private/public signal is defined or assigned via hints but has no binding R1CS constraints.
2. **Lookup Arguments (Plookup / Log-Derivative)**:
   - Extend the DSL to support lookup tables, drastically reducing constraint counts for bitwise hash functions (Blake2b, SHA-256, SHA-512) and range checks.
3. **Unified PlonK Pipeline Facade**:
   - Mirror `Groth16Pipeline` / `Groth16Keys` for PlonK (`PlonKPipeline` / `PlonKKeys`), simplifying the compilation, setup, witness mapping, and proving workflow into a single unified API.

---

### 5.4 Cardano & On-Chain Integration (P1 / P2)

1. **PlonK On-Chain Budget Reduction**:
   - Optimize `PlonkBLS12381Lib.java` to reduce UPLC execution cost from ~4.9e9 CPU units closer to ~2.5e9 CPU units, enabling multi-input PlonK verifications on standard Cardano transactions.
2. **Turnkey DApp Smart Contract Templates**:
   - Package ready-to-deploy Aiken and Julc validators implementing common ZK patterns: private voting, anonymous airdrop claims, selective disclosure KYC, and state-tree root transitions.
3. **CIP-0030 / CIP-0095 Wallet Integration Utilities**:
   - Provide frontend TypeScript/Java helpers in `zeroj-ccl` to allow browser dApps to submit ZeroJ ZK proofs directly through standard Cardano CIP-30 wallets (Eternl, Lace, Yoroi).

---

## 6. Pre-Production Audit & Release Gate Checklist

Before declaring ZeroJ **v1.0 Production-Ready (Mainnet Value-Bearing)**:

- [ ] **External Cryptographic Audit**: Commission an independent security audit covering:
  - BLS12-381 field, curve, pairing, and hash-to-curve primitives in `zeroj-bls12381`.
  - Groth16 and PlonK provers in `zeroj-crypto`.
  - Plutus V3 UPLC validator scripts in `zeroj-onchain-julc`.
- [ ] **Primitive Performance Hardening**: Implement fast subgroup checks (Bowe/$\psi$) and cyclotomic final exponentiation.
- [ ] **Production Ceremony Pinning**: Select and publish cryptographic SHA-256 hashes for verified Powers-of-Tau / Phase-2 MPC ceremony `.zkey` files.
- [ ] **Bidirectional CI Interoperability**: Continuous automated verification of ZeroJ proofs via `snarkjs verify`.
- [ ] **GraalVM Native Image CI Smoke Tests**: Add CI verification ensuring native compilation and execution of `zeroj-blst` and `zeroj-crypto`.
- [ ] **Developer Validator Security Guidelines**: Publish security best practices emphasizing `ScriptContext` binding, nullifier double-spend prevention, and datum authorization.

---

## 7. Conclusion

ZeroJ is in an outstanding **Beta** state for Cardano testnet development. Its mathematical precision, strict adherence to cryptographic standards, and pioneering pure-Java memory architecture for million-constraint circuits establish it as a premier ZK toolkit for the JVM.

By executing the proposed **module pruning** (retiring outdated POCs like Halo2, WASM runners, gnark, and legacy BN254) and implementing the **P0/P1 performance enhancements** (fast subgroup checks and cyclotomic final exponentiation), ZeroJ will be exceptionally well-positioned for its formal audit and subsequent v1.0 mainnet production release.

# PoseidonMPF Scalability and Module Cleanup Assessment

## Status

Analysis and implementation plan. No production-readiness claim is made by this
document.

Implementation update (2026-08-01): [ADR-0041](adr/0041-poseidon-mpf-production-readiness-and-load-benchmark.md)
has since pinned every CCL artifact to `0.8.0-pre4`, introduced the total
`zeroj-poseidon-mpf-v2` byte profile, replaced the MPF hot path with
bit-identical fixed-limb Poseidon arithmetic, added bounded binary-pair caching,
and added the resumable `zeroj-mpf-poseidon-load` module. The benchmark has now
completed; see the [five-million-entry measurements](benchmarks/poseidon-mpf-5m-2026-08-02.md)
and [practical large-state report](poseidon-mpf-large-state-production-report.md).
Statements below about version drift and missing tooling describe the baseline
that motivated ADR-0041 and are retained as a point-in-time assessment.

ADR-0042 update (2026-08-04): the repository now uses published CCL `0.8.0-pre5`, the unreleased
MPF `v2` alias was explicitly migrated to `v1`, MPF and JMT are separate published structure
modules with named operation-specific circuits, and both retained five-million-entry paths
have current benchmarks. Use the
[practical large-state guide](merkle/practical-large-state-guide.md) and
[ADR-0042](adr/0042-operation-specific-poseidon-mpf-and-jmt-circuits.md) for current guidance.
The module-cleanup analysis below remains a point-in-time recommendation and was not executed
as part of ADR-0042.

## Date

2026-08-01

## Scope

This document records two repository-wide assessments:

1. whether the Poseidon-rooted Merkle Patricia Forestry integration can support
   a five-million-entry off-chain registry whose private inclusion statements
   are proved with ZeroJ and verified on Cardano; and
2. which Gradle modules can be removed, extracted, consolidated, or moved out
   of the shipping core to reduce repository and release noise.

The conclusions are based on the current source, tests, Gradle dependency
graph, BOMs, CI/release workflows, and relevant ADRs. The five-million-entry
conclusion is a design and static-cost assessment, not a benchmark result.

## Executive Summary

PoseidonMPF has the correct broad architecture, but it is not currently ready
for a production five-million-entry claim.

- Cardano Client Lib (CCL) generates an MPF wire proof off-chain.
- `PoseidonMpfCodec` converts the wire proof to a secret circuit witness.
- `ZkMpf` verifies membership in the symbolic circuit.
- A Groth16 prover generates the succinct proof.
- A Plutus V3 validator can verify that Groth16 proof using BLS12-381 builtins.

The number of registry entries affects off-chain tree construction, storage,
and proof generation. It does not directly affect Groth16 proof size or
on-chain verification cost. Circuit and setup cost instead depend on a fixed
maximum MPF proof-step bound.

The current blockers are:

- no disk-backed five-million-entry benchmark;
- expensive `BigInteger` Poseidon hashing and full 16-child branch
  recomputation;
- a byte-to-field encoding that rejects many arbitrary 32-byte inputs;
- a constraint-heavy circuit that calculates all branch, fork, and leaf
  candidates for every proof slot;
- repeated linear 64-element path multiplexing;
- no MPF-specific setup, proving, JuLC, Yaci DevKit, or testnet flow; and
- application-specific raw-key, root, value, domain, and nullifier binding that
  has not yet been frozen as a protocol specification.

PoseidonMPF is already structurally compatible with the CCL MPF APIs. It is not
cryptographically compatible with native CCL/Aiken Blake2b MPF roots. It must
remain a separately versioned commitment profile.

The module audit found 32 Gradle projects. A focused repository can reasonably
target approximately 20 to 22 projects by extracting research/WASM providers,
moving app-level helpers and examples out of the core, removing the all-modules
BOM, consolidating very small SPI modules, and making gnark retention depend on
measured value.

## Part I: PoseidonMPF

### Current capability status

| Capability | Status |
| --- | --- |
| Store five million entries off-chain | Architecturally possible with a persistent CCL `NodeStore`; not demonstrated and likely too slow in the current implementation |
| Generate a CCL MPF inclusion proof | Implemented through `MpfTrie.getProofWire` |
| Convert a CCL proof to circuit witness data | Implemented by `PoseidonMpfCodec` |
| Verify Poseidon MPF inclusion in a symbolic circuit | Implemented and covered by small witness/circuit tests |
| Generate a Groth16 proof for a realistic MPF path | Generic infrastructure exists; MPF-specific path is not demonstrated |
| Verify an MPF-backed proof on Cardano | Technically feasible through the generic Groth16 BLS12-381 verifier; no MPF end-to-end flow exists |
| Use CCL stores and trie APIs | Already supported |
| Produce the same root as native CCL/Aiken MPF | Not supported; the commitment profiles use different hashes and roots |

### Correct end-to-end model

The MPF proof and the Groth16 proof are different artifacts:

1. A persistent CCL `MpfTrie` stores the registry off-chain.
2. CCL generates a wire inclusion proof for a key.
3. `PoseidonMpfCodec` converts that proof and key path to private witness
   arrays.
4. `ZkMpf.verifyInclusionPoseidon` constrains the witness against a public or
   otherwise application-bound Poseidon root.
5. A Groth16 prover proves satisfaction of the circuit.
6. The off-chain MPF proof remains private; Cardano sees only the succinct
   Groth16 proof and the selected public inputs.

Groth16 proof size is fixed. With a fixed verification key and fixed public
input count, on-chain verification cost does not grow with the five-million
entry registry.

### Off-chain scalability analysis

`PoseidonMpfTrie.inMemory()` creates an `InMemoryNodeStore` and is suitable only
for examples and small tests. The factory also accepts an arbitrary CCL
`NodeStore`, which permits a RocksDB-backed implementation without changing the
public adapter.

The present commitment scheme makes bulk construction expensive:

- a branch has 16 child commitments;
- every changed branch recomputes a full four-level binary Merkle tree, which
  requires 15 digest calls;
- the prefixed branch commitment adds another digest;
- a 64-byte digest is represented by five field inputs and uses four folded
  Poseidon T3 permutations; and
- the off-chain Poseidon implementation uses `BigInteger` arithmetic.

For uniformly distributed hashed keys, `log16(5,000,000)` is approximately
5.6. A rough static estimate is therefore about 384 Poseidon T3 permutations
per mature-tree insertion, or about 1.9 billion permutations for a five-million
entry initial build before leaf hashing and persistence. This estimate is not a
runtime measurement, but it is sufficient to require a benchmark and likely
optimization before a scalability claim.

A persistent benchmark must also measure content-addressed node retention,
orphan/history growth, RocksDB WAL and compaction behavior, snapshot recovery,
and the garbage-collection mode used by the selected CCL store.

### Byte-to-field encoding blocker

`PoseidonMpfHash.digestField` supports at most three 32-byte chunks. More
importantly, each complete 32-byte chunk is interpreted directly as a scalar
and rejected when it is greater than or equal to the BLS12-381 scalar modulus.

This is not a total hash for arbitrary byte strings. Random 32-byte keys,
identifiers, values, or existing digests will frequently be rejected. The
profile must be revised before durable roots are published. A suitable versioned
profile should use an unambiguous total encoding such as fixed 31-byte limbs,
an explicit length, fixed endianness, domain separation, and a documented
maximum length.

Changing this encoding changes every key path, node commitment, proof, and
root, so it must precede production data migration or a trusted setup tied to
the final circuit.

### Circuit scalability analysis

Five million entries do not imply five million circuit operations. The circuit
checks one compressed proof path. For uniformly hashed keys, a typical proof is
expected to contain roughly six explicit branch levels, but the exact
distribution and maximum must be measured from the real dataset. The
theoretical path limit is 64 nibbles, and adversarial or unusually colliding
keys can produce longer paths than the average.

The circuit is compiled for `MAX_STEPS`. A proof longer than that bound is
rejected. A shorter proof is padded, but padding does not eliminate most of the
cost because the current circuit constructs branch, fork, and leaf candidate
computations for every slot before selecting the applicable result.

The path representation also performs repeated dynamic access into 64-element
arrays. `CircuitAPIImpl.arrayAccess` implements dynamic access as a linear scan
of equality selectors and multiplications. This becomes a major cost when used
throughout every proof-step candidate.

Current tests establish small-example witness correctness, R1CS compilation,
and negative tamper behavior. They do not measure exact large-path constraint
counts, setup time, proving-key size, proving time, peak memory, or Cardano
execution budget.

### Statement and privacy binding

`PoseidonMpfCodec` hashes the raw key off-circuit and supplies the resulting
64-nibble path as secret witness data. The circuit proves membership of that
path, but does not itself establish that the path came from a particular public
raw key.

That can be the intended privacy statement when the public output is a
domain-separated nullifier derived from the secret path. It is insufficient if
the application intends to prove membership of a specific public raw key. The
protocol must select and specify one of the following:

- keep the raw key private and expose a domain-separated path nullifier;
- expose a trusted commitment to the path and bind it in-circuit; or
- hash a fixed-size raw-key representation inside the circuit.

The same protocol specification must define value semantics, root provenance,
domain separation, replay behavior, datum/state binding, and whether inclusion
alone is supported in the first production profile.

### CCL and native MPF compatibility

PoseidonMPF already reuses CCL interfaces and formats:

- CCL `MpfTrie`;
- CCL `NodeStore`;
- custom CCL `HashFunction`;
- custom CCL `CommitmentScheme`; and
- CCL wire proofs consumed by `PoseidonMpfCodec`.

This is API and storage compatibility, not root compatibility. Native
CCL/Aiken MPF uses Blake2b-256. ZeroJ PoseidonMPF uses a BLS12-381 Poseidon
commitment designed for a Groth16 circuit. The same entries necessarily produce
different roots, and the native Aiken MPF verifier cannot verify the Poseidon
root.

If native-root interoperability is mandatory, the available designs are:

1. verify the native Blake2b commitment inside the circuit, accepting a much
   larger circuit;
2. maintain native Blake2b and Poseidon roots and enforce their synchronization
   through authenticated state transitions or a separate batch proof; or
3. use only the native root and give up the inexpensive Poseidon membership
   gadget.

At the time of the original assessment, the modules used three different CCL baselines.
ADR-0041 resolved this: all `com.bloxbean.cardano:cardano-client-*` artifacts now resolve to
`0.8.0-pre4` from one root Gradle property.

### PoseidonMPF implementation plan

#### Phase 1: Freeze the protocol and commitment profile

- Make the byte-to-field encoding total and versioned.
- Select inclusion-only as the initial profile unless exclusion has a concrete
  product requirement.
- Define key and value length limits.
- Freeze domain tags, field encoding, endianness, wire-proof normalization,
  root representation, nullifier semantics, and public inputs.
- State explicitly that the Poseidon root is not a native Aiken MPF root.
- Add independent test vectors before any durable roots are published.

#### Phase 2: Execute a five-million-entry storage benchmark

- Use a deterministic dataset and a disk-backed CCL store.
- Compare CCL default Blake2b and the current Poseidon profile to isolate hash
  overhead.
- Measure initial build and incremental update throughput.
- Measure wall time, CPU, heap, native memory, database size, WAL size, write
  amplification, live and retained nodes, and restart/recovery behavior.
- Measure proof generation p50, p95, p99, maximum latency, encoded proof size,
  and actual proof-step distribution.
- Include random, production-shaped, and deliberately long-prefix keys.

#### Phase 3: Optimize off-chain construction

- Replace reference `BigInteger` Poseidon with optimized fixed-limb,
  vectorized, or carefully isolated native arithmetic.
- Cache or incrementally update the binary levels of a 16-child branch instead
  of recomputing all 15 internal hashes.
- Add a sorted/batched bulk-loader path and batched persistence.
- Define snapshot, history-retention, and garbage-collection policy.
- Rerun Phase 2 and record the before/after results.

#### Phase 4: Benchmark and redesign the inclusion circuit

- Compile exact inclusion-only circuits for representative bounds such as 4,
  8, 12, and 16 steps.
- Record constraints, wires, witness time, compile time, setup time, proving
  time, proving/verifying-key sizes, proof size, verification time, and peak
  memory.
- Use the real five-million-entry path distribution to select a bound.
- Avoid calculating exclusion-only and inapplicable step candidates.
- Replace repeated 64-way path multiplexing with prepacked path chunks or a
  more efficient constrained normalization.
- Consider per-depth circuit profiles, a normalized single-step
  representation, or recursive/folded verification if fixed-bound circuits
  remain impractical.

#### Phase 5: Complete Cardano end-to-end verification

- CCL proof generation.
- Witness conversion.
- Exact-circuit trusted setup.
- Groth16 proof generation and off-chain verification.
- JuLC VM verification with the production validator.
- Yaci DevKit and public-testnet transaction tests.
- Script budget measurement with safety margin.
- Root, domain, nullifier, datum, transaction-context, and replay binding.
- Operational documentation for root updates, key rotation, setup artifacts,
  and recovery.

### PoseidonMPF release gates

Production support requires recorded evidence that:

- every supported byte string hashes successfully and canonically;
- a deterministic five-million-entry build completes within the selected
  operational SLA;
- restart and recovery reproduce the exact root;
- proof generation and step-count distributions fit the chosen circuit bound;
- the exact production circuit completes setup and proving within its memory
  and latency SLAs;
- Groth16 verification succeeds off-chain, in JuLC VM, in Yaci DevKit, and on
  testnet;
- script execution remains below the chosen Cardano budget margin; and
- independent security review covers the commitment profile, circuit, public
  statement, and validator binding.

## Part II: Module Cleanup

### Current repository surface

`settings.gradle` includes 32 projects:

- 23 modules described as core;
- 4 support/BOM modules;
- 3 mainline opt-in modules; and
- 2 incubator modules.

The root build publishes every project except `zeroj-test-vectors` and
`zeroj-examples`. Consequently, experimental and incubating projects become
release artifacts by default. The CI, snapshot, and release workflows also
build gnark and Halo2 native libraries across multiple platforms. The WASM
provider modules invoke Cargo as part of resource processing.

`zeroj-examples` depends on nearly every major project, including incubator
providers. It therefore makes peripheral modules appear internally consumed
even when no production module depends on them.

ADR-0020 performed a useful first cleanup, but later evidence has made some of
its decisions stale. In particular, ADR-0020 calls gnark the production fast
path, while ADR-0033 records that the current large-circuit gnark entry point
serializes the full R1CS and witness to JSON and repeats setup, making it
infeasible for the flagship 19-million-constraint circuit without a separate
integration effort and ceremony.

### Highest-priority extraction or removal candidates

| Module | Recommendation | Rationale |
| --- | --- | --- |
| `zeroj-verifier-halo2` | Extract to a research repository or archive | Incubator Pallas/Halo2 path is not part of Cardano BLS12-381 verification, but adds multi-platform Rust/native CI and release burden |
| `zeroj-prover-wasm` | Extract or archive unless browser proving is a committed product goal | Peripheral experimental provider with no production consumer outside examples |
| `zeroj-bbs-wasm` | Move to a provider/interop repository | Rust/Cargo/WASM maintenance with no production consumer outside its own surface |
| `zeroj-bls12381-wasm` | Move to a provider/interop repository while preserving useful differential tests | Adds Cargo and Chicory requirements; its current incoming use is primarily BBS testing |
| `zeroj-bom-all` | Remove in favor of one stable BOM | A BOM does not pull dependencies; including incubator artifacts mainly blurs support status |
| `zeroj-cardano` | Move to reference integration or combine with `zeroj-ccl` | Three small classes implementing app-level proof metadata/anchoring rather than core cryptography |
| `zeroj-ccl` | Move to reference integration or combine with `zeroj-cardano` | One production helper class and an older CCL version pin |
| `zeroj-patterns` | Move to a use-cases/reference project | Application-level membership, nullifier, credential, range, and state patterns; no production consumer outside examples |
| `zeroj-examples` | Replace with focused integration-test source sets and separately maintained examples | Its broad dependency graph hides actual module demand and couples default builds to experimental providers |

Removal from the main repository does not require deleting all useful source.
Research backends and examples can be archived or moved to a separate
`zeroj-experimental` or `zeroj-usecases` repository with independent release
and CI policies.

### Consolidation candidates

#### `zeroj-prover-spi`

The module contains four small types and no tests. The gnark module consumes
only response/error types; the pure-Java prover does not implement the service
interface.

- If a provider-neutral prover API is a committed public contract, move it into
  `zeroj-api` and make every prover implement it.
- Otherwise, move the used types into `zeroj-prover-gnark` and remove the
  standalone module.

#### `zeroj-verifier-core`

The module contains two substantive orchestration classes. It can be merged
with `zeroj-backend-spi`, optionally renaming the combined module to
`zeroj-verifier-api`. Keeping it separate is defensible only if that boundary
has external consumers or a documented evolution plan.

#### Modules that should remain separate

- `zeroj-circuit-annotation-api` and
  `zeroj-circuit-annotation-processor`, because compile-time annotation
  processing requires a clean API/processor boundary.
- `zeroj-tools` and `zeroj-ceremony`, because the former contains reusable
  ceremony machinery and the latter is the operator CLI.
- `zeroj-crypto-blst`, because it is a small optional bridge that avoids
  forcing native acceleration into the pure-Java cryptography module.

### Conditional decisions

#### `zeroj-prover-gnark`

Remove it from the stable core BOM and mandatory default CI while its status is
resolved. Retain it temporarily as a standalone optional provider and evaluate:

- real external/internal consumers;
- small- and medium-circuit performance;
- whether PlonK depends on this provider as a shipping requirement;
- setup reuse and artifact interoperability;
- large-circuit serialization and memory behavior; and
- the cost of maintaining three-platform Go/FFM artifacts.

If it does not provide a measured workload advantage that justifies its native
release burden, extract or remove it. If it remains, its documentation must not
describe the current large-circuit route as a production fast path.

#### `zeroj-mpf-poseidon`

Keep the module because it supports a concrete privacy use case, but move it
out of `zeroj-bom-core` and classify it as incubator until the production gates
in this document pass.

#### `zeroj-verifier-plonk` and `zeroj-bbs`

Keep them as opt-in mainline modules unless the project deliberately narrows to
a Groth16-only product. Both have substantive implementations and test suites;
their product positioning should be decided separately from removing obvious
repository noise.

### Core modules to retain

The focused Java/Cardano/Groth16 path should retain:

- `zeroj-api`;
- `zeroj-codec`;
- the consolidated verifier API/SPI;
- `zeroj-verifier-groth16`;
- `zeroj-bls12381`;
- `zeroj-blst`;
- `zeroj-crypto`;
- `zeroj-crypto-blst`;
- `zeroj-circuit-dsl`;
- `zeroj-circuit-lib`;
- circuit annotation API and processor;
- `zeroj-tools`;
- `zeroj-ceremony`;
- `zeroj-onchain-julc`;
- `zeroj-test-vectors`;
- one stable BOM; and
- focused integration tests.

PlonK, BBS, gnark, and PoseidonMPF can remain opt-in or incubating according to
the decisions above.

### Module cleanup implementation plan

#### Phase 0: Verify the product and compatibility boundary

- Freeze the definition of shipping, optional, incubator, example, and archived
  modules.
- Inspect Maven downloads, external GitHub references, downstream builds, and
  known consumers before removing published artifacts.
- Define deprecation and migration policy for any public module.
- Record the target module graph and allowed dependency directions.

#### Phase 1: Correct the public surface without deleting code

- Remove experimental modules from the stable core BOM.
- Replace `zeroj-bom-core` and `zeroj-bom-all` with one stable BOM.
- Stop publishing incubator artifacts as part of the default release.
- Split stable CI from optional provider/research CI.
- Remove Halo2 and WASM builds from mandatory stable build/release jobs.
- Mark PoseidonMPF and unresolved gnark paths accurately in documentation.

#### Phase 2: Separate examples and app-level integrations

- Move essential regression coverage from `zeroj-examples` into focused
  integration-test source sets or a dedicated non-published integration module.
- Move tutorial applications to the maintained use-cases repository.
- Rehome or combine `zeroj-cardano` and `zeroj-ccl`.
- Rehome `zeroj-patterns` as reference application code.
- Ensure examples no longer act as artificial consumers of every provider.

#### Phase 3: Extract research and WASM providers

- Archive or move `zeroj-verifier-halo2`.
- Archive or move `zeroj-prover-wasm`.
- Move the BLS12-381 and BBS WASM providers to a provider/interop repository.
- Preserve interoperability vectors and valuable differential tests in a form
  runnable independently from the stable Java build.

#### Phase 4: Consolidate small modules

- Resolve the public role of `zeroj-prover-spi` and merge it accordingly.
- Merge `zeroj-verifier-core` with the verifier SPI/API if the consumer audit
  finds no reason for the boundary.
- Align all retained CCL dependencies to a tested version matrix.
- Remove stale package/module documentation and duplicate conversion helpers.

#### Phase 5: Decide conditional backends

- Benchmark gnark against pure Java on representative small, medium, and large
  circuits.
- Decide whether PlonK and BBS remain mainline opt-in products or move to
  separately released product lines.
- Apply the PoseidonMPF release gates before promoting it from incubator.

#### Phase 6: Migration and release verification

- Supersede ADR-0020 with the final decisions.
- Publish a module-to-replacement migration table.
- Verify stable dependency boundaries and absence of cycles.
- Run the complete stable test suite and focused optional-provider suites.
- Verify generated POMs, BOM constraints, source/javadoc jars, signing, and
  clean-checkout build requirements.
- Confirm that the default Java build no longer requires Go, Rust, Cargo, or
  platform-specific native artifacts unless the corresponding provider is
  explicitly selected.

### Expected outcome

A conservative cleanup should reduce the default surface to roughly 22 to 24
projects. Applying the small-module consolidations and extracting gnark when it
does not pass its value gate can reduce the repository to approximately 20 to
22 projects while preserving the core Java circuit, Groth16, ceremony, and
Cardano verification capabilities.

## References

- [PoseidonMPF module](../zeroj-mpf-poseidon/README.md)
- [Circuit library status](../zeroj-circuit-lib/README.md)
- [ADR-0020: Module Cleanup and Core Restructure](adr/0020-module-cleanup-and-core-restructure.md)
- [ADR-0033: Prover Memory Reduction](adr/0033-prover-memory-reduction.md)
- [Aiken Merkle Patricia Forestry](https://github.com/aiken-lang/merkle-patricia-forestry)
- [Cardano Client Lib releases](https://github.com/bloxbean/cardano-client-lib/releases)
- [Cardano Plutus V3 BLS primitives](https://developers.cardano.org/docs/developers/curriculum/smart-contracts/advanced/bls-primitives/)

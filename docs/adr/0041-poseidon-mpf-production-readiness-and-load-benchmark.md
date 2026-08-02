# ADR-0041: Poseidon MPF production profile and five-million-entry benchmark

- **Status**: accepted; reference benchmark completed 2026-08-02
- **Date**: 2026-08-01
- **Tracks**: [GitHub issue #25](https://github.com/bloxbean/zeroj/issues/25)
- **Extends**: [Symbolic MPF Gadget for Poseidon-Rooted Cardano State](circuit-annotation/zk-mpf-gadget.md)
- **Superseded in part by**:
  [ADR-0042](0042-operation-specific-poseidon-mpf-and-jmt-circuits.md) replaces the branch-wide
  CCL `0.8.0-pre4` pin with `0.8.0-pre5-dev1` and renames the unreleased MPF `v2` candidate to
  the first supported `v1` profile without changing its cryptographic outputs. This ADR remains
  the provenance of the pre4 five-million-entry benchmark and its historical `v2` label.

## Context

ZeroJ already has a Poseidon-backed adapter for Cardano Client Lib's Merkle Patricia
Forestry (MPF), a codec for CCL wire proofs, and a symbolic circuit verifier. The existing
tests establish small in-memory proof compatibility. They do not establish that the complete
system is suitable for a state set containing millions of entries.

The production question has two different scaling dimensions:

1. the off-chain MPF must store and update five million entries without retaining the whole
   trie in heap; and
2. one lookup proof from that trie must fit a bounded ZeroJ circuit, produce a Groth16 proof,
   and verify independently.

The circuit does not contain five million entries. It contains one bounded MPF authentication
path. Dataset size affects RocksDB size, build time, proof-depth distribution, and the maximum
path bound selected for the circuit. Once that bound is fixed, Groth16 proof size and verifier
work do not grow with the number of off-chain entries.

CCL `0.8.0-pre4` supplies all APIs required by ZeroJ:

- `MpfTrie(NodeStore, HashFunction, byte[], CommitmentScheme)`;
- pluggable key/value hashing through `HashFunction`;
- pluggable leaf and persisted-node commitments through `CommitmentScheme`;
- MPF RocksDB storage; and
- the MPF fixes and performance work released with `0.8.0-pre4`.

The development build `0.8.0-pre5-dev1` is therefore not required. A comparison of the two
tags found no MPF hash or commitment API change needed by this work.

There is one production defect in ZeroJ's existing Poseidon byte adapter. Its fixed digest
profile rejects an arbitrary 32-byte chunk when the unsigned value is greater than or equal to
the BLS12-381 scalar modulus, and it rejects inputs over 96 bytes. That restriction is safe for
the internal MPF byte strings mirrored by the circuit, but it violates CCL's general
`HashFunction.digest(byte[])` contract for ordinary application keys and values.

## Decision

### 1. Use CCL `0.8.0-pre4` everywhere

ZeroJ will define one root Gradle property for the CCL version and use
`0.8.0-pre4` for every direct `com.bloxbean.cardano:cardano-client-*` dependency.
Module-local CCL version declarations are removed. New CCL dependencies must use the root
property.

`julc-cardano-client-lib` follows the separately managed Julc release and is not rewritten by
this decision.

Moving away from `0.8.0-pre4` requires an explicit dependency update with the Poseidon MPF
compatibility suite and the persisted-root checks rerun. A development CCL build must not be
used merely because it is newer.

### 2. Freeze a versioned Poseidon MPF profile before generating durable roots

The production profile identifier is:

```text
zeroj-poseidon-mpf-v2
```

It uses BLS12-381 scalar-field Poseidon with the ZeroJ `t=3`, `alpha=5` parameter set and
32-byte unsigned big-endian field encodings.

CCL's wire verifier rolls branch pairs and compressed prefixes through the same
`HashFunction` used for raw keys and values. Consequently, ZeroJ cannot assign a different
hash implementation to raw data and proof roll-up without forking CCL. The v2 adapter remains
one deterministic hash function with two injective encodings:

1. **Circuit-compatible encoding.** Inputs of at most three 32-byte-aligned chunks whose full
   chunks are canonical BLS12-381 scalar elements retain the existing fixed form:

   ```text
   PoseidonN(DOMAIN_BYTES, byteLength, chunk0, chunk1, chunk2)
   ```

   Missing chunks are zero. The first short chunk, if any, comes first. Every MPF-internal
   pair (`left || right`) and prefix (`nibbleBytes || childDigest`) has this form, so the
   symbolic circuit can consume child digests as fields without decomposing 255-bit field
   elements into bytes.

2. **Total raw-byte fallback.** Any input that cannot use the circuit-compatible encoding is
   split left-to-right into 31-byte unsigned chunks and hashed as:

   ```text
   PoseidonN(DOMAIN_RAW_BYTES_V2, byteLength, chunk0, ..., chunkN)
   ```

   A 31-byte chunk is always below the BLS12-381 scalar modulus. This makes
   `digest(byte[])` total for every practical Java byte array while preserving a separate
   domain from the circuit-compatible form.

Raw-key hashing is deliberately outside `ZkMpf`. The circuit receives the 64-nibble path
produced by CCL and the value commitment. Applications that must prove a relation to original
key or value bytes need a separate, application-specific binding gadget.

The leaf commitment remains:

```text
PoseidonN(
  DOMAIN_LEAF,
  suffixLength,
  suffixChunk0,
  suffixChunk1,
  suffixChunk2,
  valueDigest
)
```

where suffix nibbles are encoded as bytes and packed into `31 / 31 / 2` byte chunks. Branch
values remain unsupported. Empty subtrees remain the all-zero field digest. Native
Blake2b/Aiken MPF roots and ZeroJ Poseidon MPF roots are separate commitment universes.

The profile identifier, exact Poseidon parameter fingerprint, CCL version, dataset schema,
seed, and root are written to every load manifest. A database with a mismatched manifest must
fail closed; it is never silently reopened under another profile.

### 3. Keep RocksDB and load tooling out of the library module

`zeroj-mpf-poseidon` stays storage-neutral and publishable. A separate, non-published
`zeroj-mpf-poseidon-load` application module will contain:

- the CCL MPF RocksDB dependency;
- deterministic dataset generation;
- resumable batched loading;
- proof sampling and independent verification; and
- circuit compile, witness, setup, prove, and verify benchmarks.

This avoids forcing RocksDB/native dependencies on library users and makes the load harness an
operator/development tool rather than a runtime API.

### 4. Make the five-million-entry load deterministic and resumable

The reference run contains exactly `5_000_000` unique entries. Keys and values use a stable,
versioned binary encoding derived from `(dataset seed, entry index)`; the generator must not
allocate or retain the full dataset.

Writes are committed in bounded batches. Each durable checkpoint records the completed entry
count and current root in the same RocksDB write batch as its trie-node writes when the CCL
store API permits it. Restart resumes only after validating the manifest and checkpoint.

The reference run uses CCL `0.8.0-pre4`'s `RocksDbConfig.highThroughput()` profile. The
selected RocksDB profile is recorded in the report; changing it affects physical performance,
not the commitment profile or root.

The final root must be reproducible for the same profile, CCL version, schema, seed, insertion
order, and entry count. A small deterministic vector is kept in tests so root drift is caught
without rerunning five million inserts on every build.

The load report records at least:

- start/end timestamps and elapsed time;
- entries, batch size, resumed entry, and throughput;
- final root and checkpoint count;
- database bytes before/after;
- configured JVM and peak observed heap; and
- host/JDK/OS information needed to interpret a benchmark.

### 5. Sample real proofs from the completed trie

The harness selects deterministic indices across the dataset plus configurable seeded random
indices. For each selected key it must:

1. read the expected value;
2. obtain CCL's CBOR wire proof;
3. verify it through the CCL/ZeroJ reference verifier using the v2 hash and commitment;
4. convert it with `PoseidonMpfCodec`;
5. build and validate the circuit witness; and
6. record proof bytes, step count, generation latency, and verification latency.

The report includes min/median/p95/p99/max latency, proof-size distribution, and proof-step
distribution. The configured `MAX_STEPS` must be written to the report. Any sampled proof that
exceeds the bound fails the circuit phase rather than being truncated.

Sampling is evidence about the observed distribution, not a mathematical proof that a future
proof cannot be deeper. The benchmark tool also provides an opt-in streaming current-root
scan that counts every inclusion path without materializing the trie in heap. Production
applications must pin a reviewed bound, rescan or maintain depth metadata after updates, and
define how an over-bound lookup is handled.

### 6. Benchmark the complete Groth16 path

At least one proof sampled from the five-million-entry database must complete:

```text
CCL proof -> Poseidon witness -> R1CS -> Groth16 proof -> independent pairing verification
```

The harness records constraint/wire/public-input counts, compile time, setup time, proving
time, verification time, proof size, proving-key storage, and peak observed heap.

For realistic circuits the harness uses ZeroJ's store-backed `Groth16Keys` and
`Groth16Pipeline` paths. In-memory setup may be used only for small smoke tests. Locally
generated single-party parameters are explicitly labelled **benchmark-only/insecure** and do
not satisfy a production trusted-setup requirement. Production deployment requires imported
or ceremonially generated parameters tied to the exact R1CS fingerprint.

The off-chain verifier must first accept the generated proof and must reject at least one
mutated public input. On-chain/Yaci integration remains a separate deployment gate; the
Groth16 proof and public-input count are independent of the five-million-entry database size.

## Reference benchmark result

The 2026-08-02 reference run completed all local high-volume gates. Full machine metadata,
commands, timings, distributions, and limitations are recorded in the
[five-million-entry benchmark report](../benchmarks/poseidon-mpf-5m-2026-08-02.md).

Key results:

| Metric | Result |
|---|---:|
| Entries/root | 5,000,000 / `5988af1bdc5883f6cf67b748c85b7fa32de9e4cbf309d971288d86d6d1129ad8` |
| Timed resumed load | 4,070,000 inserts in 20,827.443 s; 195.415 entries/s |
| Sampled MPF proofs | 32/32 passed CCL and independent ZeroJ verification |
| Sampled proof steps/bytes | 6-7 steps / 805-939 bytes |
| Complete current-root depth | 5-9 steps; 218 of 5M paths require 9 steps |
| Circuit | 17,399,380 constraints; 37,718,764 wires; 1 public input |
| Benchmark-only setup | 895.707 s; 10,269,150,876-byte sparse key store |
| Groth16 | 213.826 s prove; 153.868 ms verify; 192-byte proof |
| Negative gate | Mutated public root rejected off-chain and in Julc VM |
| Julc VM budget | CPU 2,627,770,348; memory 177,749 |

The completed RocksDB dataset and benchmark artifacts are preserved locally at
`.benchmark-data/poseidon-mpf-5m`, outside Gradle build directories. This path is ignored by
Git and survives `./gradlew clean`; it is not a repository backup.

This result establishes high-volume compatibility and local end-to-end feasibility. It does
not approve the fixed single-party benchmark setup for production or close the security and
network-deployment gates.

## Production readiness gates

The Poseidon MPF feature may be labelled production-ready only after all of the following are
recorded with reproducible commands and machine metadata:

| Gate | Status | 2026-08-02 evidence / remaining work |
|---|---|---|
| Dependency baseline | Passed | Resolution is pinned to CCL `0.8.0-pre4` |
| Hash totality | Passed | Boundary/property tests cover arbitrary raw byte arrays |
| Commitment compatibility | Passed | CCL build/proof, two off-chain verifiers, witness, and circuit agree |
| Root stability | Partial | Small golden roots/profile tests pass and the 5M root is recorded; a second independent 5M rebuild has not been run |
| Persistence | Passed | Interrupted load resumed from 930,000 and proof sampling reopened the completed store |
| Five-million load | Passed | Exactly 5M entries completed with manifest and resource report |
| Proof distribution | Passed | 32 deterministic samples recorded size, latency, and 6-7-step distribution |
| Circuit bound | Partial | Selected 7-step proof fits `MAX_STEPS=8`, but the complete scan found 218 nine-step paths; use at least 9 for this exact root or route overflow |
| Groth16 | Passed for benchmark | Store setup/load, prove, positive verify, and negative verify passed; setup is insecure benchmark-only |
| Security review | Open | Independent review and production setup provenance are still required |
| Cardano deployment | Partial | Exact artifacts passed Julc VM with measured budget; Yaci and public target-network tests remain open |

Passing the CCL five-million-entry load alone establishes storage scalability, not circuit or
cryptographic production readiness. Passing a small circuit test alone establishes neither
RocksDB scalability nor a safe production setup.

## Consequences

### Positive

- Every ZeroJ module uses one verified CCL baseline.
- Ordinary binary keys and values no longer fail because a 32-byte chunk is outside the
  scalar field.
- The MPF library remains free of RocksDB/native runtime requirements.
- A five-million-entry result is reproducible and resumable instead of being a one-off timing.
- Storage performance, proof depth, circuit cost, and on-chain verification are reported as
  separate dimensions.

### Costs and limitations

- `zeroj-poseidon-mpf-v2` is a distinct commitment profile. Existing experimental databases
  must be rebuilt or explicitly proven to use byte inputs whose roots are unchanged.
- The raw-byte fallback is not verified inside `ZkMpf`; proving raw application bytes requires
  another gadget.
- A fixed-size circuit must choose a maximum proof-step bound in advance.
- RocksDB disk usage and load time remain linear in entry count even though one circuit proof
  does not.
- Benchmark-generated Groth16 parameters are not a production ceremony.
- The Poseidon-rooted profile is not compatible with the native Aiken MPF verifier.

## Rejected alternatives

- **Use `0.8.0-pre5-dev1` by default.** Rejected because `0.8.0-pre4` already exposes custom
  hash and commitment support and the development tag adds no required MPF API.
- **Add RocksDB to `zeroj-mpf-poseidon`.** Rejected because storage is an optional operational
  concern and introduces native dependencies for all consumers.
- **Run five million entries in a unit test.** Rejected because it is machine- and
  resource-sensitive. CI runs deterministic small integration tests; the full run is an
  explicit benchmark task.
- **Model all five million leaves in the circuit.** Rejected because MPF authentication needs
  only one path; doing so would destroy the succinctness and scalability benefit.
- **Keep rejecting non-canonical 32-byte raw chunks.** Rejected because CCL's hash function is
  expected to accept ordinary byte arrays and application data must not fail probabilistically.

## Relationship to the earlier MPF document

This ADR supersedes the dependency-version, generic-byte-digest totality, production status,
and full-benchmark portions of
[the earlier MPF gadget document](circuit-annotation/zk-mpf-gadget.md). That document remains
the detailed source for CCL wire semantics, symbolic proof shape, inclusion/exclusion logic,
and the distinction between native Cardano and Poseidon-rooted MPF commitments.

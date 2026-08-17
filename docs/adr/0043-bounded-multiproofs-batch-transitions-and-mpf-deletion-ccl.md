# ADR-0043-CCL: Canonical multiproofs and transition witnesses for authenticated structures

- **Status**: proposed handoff; not a CCL decision until adopted by the CCL maintainers
- **Date**: 2026-08-03
- **Target repository**:
  [bloxbean/cardano-client-lib](https://github.com/bloxbean/cardano-client-lib)
- **Tracking enhancement**:
  [CCL #642](https://github.com/bloxbean/cardano-client-lib/issues/642)
- **Baseline reviewed by ZeroJ**: `v0.8.0-pre5` (verified-structures behavior originally
  qualified on the source-identical `v0.8.0-pre5-dev1` tag)
- **ZeroJ companion**:
  [ADR-0043](0043-bounded-multiproofs-batch-transitions-and-mpf-deletion.md)
- **Scope in CCL**: `verified-structures/merkle-patricia-forestry` and
  `verified-structures/jellyfish-merkle`, with applicable RocksDB/RDBMS backends

## Purpose and ownership

This document is a handoff proposal from ZeroJ to the CCL team. It records the host-side proof
and mutation contracts needed before ZeroJ can safely implement bounded Poseidon MPF/JMT
multiproof, batch-transition, and physical MPF-delete circuits. It does not ask CCL to implement
R1CS, Groth16, Cardano validators, or ZeroJ-specific field-array witnesses.

If accepted, the CCL team should copy, renumber, or supersede this document under its own ADR
process. Exact Java type and package names are CCL implementation decisions. The semantic and
security acceptance criteria are the interoperability contract.

## Current baseline and gap

At `v0.8.0-pre5` CCL provides:

- MPF `put`, `get`, physical `delete`, single-key wire proof generation, and single-key wire
  verification;
- custom MPF hash/commitment support used by `zeroj-poseidon-mpf-v1`;
- versioned JMT `put(version, Map)` for atomic insert/update storage batches;
- JMT inclusion and both non-inclusion proof forms, object/wire proof APIs, and a pluggable
  `JmtProofCodec`;
- custom `JmtProfile` hash, commitment, proof-codec, and persistent format descriptors used by
  `zeroj-poseidon-jmt-v1`; and
- in-memory, RocksDB, and RDBMS persistence implementations.

The baseline does not provide:

- a shared MPF or JMT multiproof object/wire format/verifier;
- a canonical minimal-path or authenticated-subtree contract;
- a public MPF delete result containing the old/new rewrite trace;
- a cryptographic JMT batch-transition trace, despite having an atomic storage batch; or
- JMT physical key deletion. JMT batch values are non-null.

The phrase “independent oracle” means a caller can ask CCL to generate a proof/transition result
and can verify it against expected roots without linking ZeroJ or reproducing ZeroJ's witness
normalization. CCL and ZeroJ may share commitment parameters and golden vectors; they must not
share the same proof-construction logic.

## Proposed decision

### 1. Add structure-specific, profile-bound proof contracts

MPF and JMT have different node shapes and commitment semantics. They should expose parallel
concepts, not one type-erased universal Merkle proof. Conceptual APIs are:

```java
Optional<MpfMultiProof> getMultiProof(List<byte[]> keys);
boolean verifyMultiProof(
        byte[] expectedRoot,
        List<MpfQuery> queries,
        MpfMultiProof proof);

MpfDeleteResult deleteWithWitness(byte[] key);
MpfBatchResult applyWithWitness(List<MpfOperation> operations);

Optional<JmtMultiProof> getMultiProof(List<byte[]> keys, long version);
boolean verifyMultiProof(
        byte[] expectedRoot,
        List<JmtQuery> queries,
        JmtMultiProof proof);

JmtBatchResult putWithWitness(long version, List<JmtUpdate> updates);
```

These names are illustrative. Object APIs, deterministic wire codecs, and verification APIs are
all required. A proof/result is bound to:

- structure (`mpf` or `jmt`);
- commitment/profile descriptor;
- proof/trace format identifier and version;
- expected root, or both old and new roots for a transition; and
- exact query or operation-set semantics.

Decoders and verifiers fail closed when the supplied tree/profile does not match the envelope.
Adding a proof format must not alter existing root calculation or silently reinterpret a
persistent database.

### 2. Canonicalize keys by full hash

All public entry points continue accepting original key bytes and hash them exactly once through
the selected profile. Internally and on wire:

1. key hashes have the profile's fixed canonical width;
2. unsigned lexicographic full-hash order is canonical;
3. duplicate original-key byte sequences are rejected;
4. duplicate resulting key hashes are rejected, even if original keys differ;
5. query/result indices refer to that canonical order; and
6. caller `Map` iteration order, Java array identity, and field reduction never determine proof
   or transition order.

For initial batch transitions, CCL accepts at most one operation per key hash. It rejects
ambiguous first-wins/last-wins batches. A future sequential batch allowing repeated keys needs a
separate transcript format and explicit semantics.

An API that needs to preserve error reporting or an application-supplied order may return a
mapping from caller index to canonical index, but the committed/proved representation remains
canonical.

### 3. Specify a deterministic minimal multiproof

The multiproof is the minimal union of the requested key paths under one root:

- every shared internal node or compressed prefix is encoded once;
- every unopened boundary subtree contributes exactly one commitment;
- each requested key maps to exactly one authenticated terminal;
- no proof node is unattached or unused;
- no node, edge, boundary, or query is duplicated; and
- serialization is deterministic.

Deduplication is by shared authenticated tree position, never merely by equal commitment bytes.
Two distinct positions with the same digest remain distinct edges/positions in the proof.

The recommended canonical node order is root-first depth-first traversal with children visited in
ascending nibble/index order. Stable integer references may point only to nodes/boundaries in the
allowed traversal relationship. The decoder rejects forward/cyclic references unless a different
reviewed topological rule explicitly permits them.

The proof envelope should contain or unambiguously derive:

- format and profile identifiers;
- root;
- canonical query key hashes;
- query terminal/result type;
- included value or value commitment as defined by the profile;
- internal node/prefix data needed by that structure;
- boundary commitments;
- query-to-terminal mapping; and
- counts needed for bounded decoding.

The first delivery may support inclusion only. If CCL later supports mixed results, inclusion,
missing-child non-inclusion, and different-leaf non-inclusion remain explicit terminal variants.
A verifier cannot treat an unknown terminal as empty, ignore an extra terminal, or authenticate a
conflicting leaf without its complete key/value commitment.

Verification reconstructs the root from the proof and expected query data. Re-encoding a proof,
checking only stored node hashes, or trusting an embedded “valid” flag is insufficient.

### 4. Bind codecs to format descriptors and resource limits

Each wire format has an immutable identifier and version separate from the commitment profile.
The envelope binds both so the same proof bytes cannot cross MPF/JMT, classic/Poseidon, or codec
versions.

Canonical encoding requirements include:

- one encoding for integers, byte strings, null/empty, node variants, and arrays;
- no ignored trailing fields or bytes;
- no alternative node/reference order;
- defensive copying at public byte-array boundaries; and
- byte-identical output for the same tree root and query set.

Every decoder accepts configured or API-level maximums for:

- total wire bytes;
- query/operation count;
- node, boundary, and edge count;
- path depth and prefix/nibble length;
- value bytes where values are carried; and
- nesting/reference depth.

Limits are checked before large allocation. Malformed or oversized untrusted input produces a
documented checked/validation failure, not partial verification, unbounded allocation, stack
overflow, or silent truncation.

### 5. Return an authenticated MPF delete-existing trace

Keep existing `MpfTrie.delete(byte[])` behavior for compatibility if desired, but add an API that
distinguishes:

- `DELETED_EXISTING` with a complete transition result; and
- `ABSENT_NO_OP` with no claim that a physical deletion occurred.

For `DELETED_EXISTING`, the result binds:

- profile/format;
- old root and new root;
- original or hashed key according to the API layer;
- removed value/value commitment;
- old inclusion path;
- affected branch/prefix nodes;
- surviving sibling/boundary commitments;
- replacement nodes and merged prefixes; and
- the exact canonical collapse route to the new root.

Required cases include root-leaf to empty, ordinary branch removal, branch-value handling, one
surviving child, neighboring leaf, fork/extension merge, multi-level collapse, and no-collapse.
All nibble/prefix boundaries and maximum key depth receive vectors.

The mutation algorithm should emit this trace while it still has both pre-state and post-state
context. A wrapper must not generate an old proof, invoke an unrelated mutation, reopen the tree,
and infer the rewrite afterward. If the storage abstraction supports transactions, persistence of
the new state and return of the transition result follow one documented atomicity contract.

CCL should provide a pure verifier/replayer that takes the expected old root, operation, trace,
and profile and derives the new root without access to the database. That is the independent
oracle ZeroJ needs.

### 6. Add deterministic batch-transition results, distinct from storage batches

`TreeUpdateBatch`, stale-node indices, RocksDB write batches, and `CommitResult.nodes()` are
persistence details. They may help build an implementation but are not the public cryptographic
contract.

A transition result binds:

- profile and transition-format identifiers;
- old root and new root;
- canonical unique operation list;
- operation types and preconditions;
- old and new value commitments where applicable;
- a minimal shared authenticated pre-state/post-state frontier;
- deterministic intermediate or equivalent shared-rewrite data; and
- for JMT, the relevant old/new version metadata without implying that a version authenticates a
  root.

The CCL verifier/replayer must independently derive `newRoot` from `oldRoot` and the complete
operation list. It rejects partial batches, reordering, missing operations, extra operations,
duplicate keys, wrong preconditions, and trace/root splicing.

Initial transition families should be homogeneous:

| Structure | Initial operations |
|---|---|
| MPF | existing-value updates, empty-terminal inserts, different-leaf inserts, physical deletes |
| JMT | existing-value updates, empty-terminal inserts, different-leaf inserts, explicit tombstone-value updates |

CCL may expose one result envelope with explicit operation variants, but each variant's
precondition is unambiguous. ZeroJ will initially create separate circuit templates.

JMT `putWithWitness` must preserve the existing one-logical-writer, version validation, replay,
rollback, prune, and access-coordination guarantees. Proof/trace generation must hold an
appropriate read/update lease or database snapshot so concurrent pruning cannot produce a torn
path.

### 7. Do not introduce JMT physical deletion in this enhancement

The baseline JMT accepts only non-null insert/update values. Internal “delete old node then create
new node” and stale-node garbage collection are not logical key deletion.

An application may select and commit a tombstone byte value. The transition result labels that as
a value update, not absence. Inclusion of the tombstone and non-inclusion of the key remain
different proof statements.

Future JMT physical deletion must separately define:

- canonical root behavior after leaf removal and path compression;
- value-store tombstone/history behavior;
- version reads and rollback;
- stale-node visibility across all backends;
- pruning and retained-root semantics;
- replay/idempotency;
- proof types and wire compatibility; and
- migration or profile implications.

It is deliberately outside this handoff so multiproof and transition-witness work does not
silently broaden JMT storage semantics.

### 8. Publish independent conformance vectors

Vectors should be data files consumable without CCL internals. Each positive vector records:

- CCL version and format/profile descriptors;
- hash/commitment identifiers;
- ordered raw keys where disclosure is acceptable;
- full key/value hashes;
- initial entries or reproducible seed;
- expected old/root/new root;
- canonical query/operation list;
- object-semantic rendering;
- deterministic wire proof/trace bytes; and
- expected verification result.

Negative vectors mutate one property at a time and record the required rejection. Required suites
include:

- empty, one-key, shared-prefix, disjoint-prefix, and maximum-depth trees;
- `b2`, `b4`, and `b8` candidate query sets;
- unsorted and duplicate keys;
- mixed terminal confusion;
- missing, duplicate, unused, cyclic, and reordered nodes/references;
- corrupted boundary commitments, values, roots, and format/profile identifiers;
- truncated, overlong, non-canonical, and resource-limit encodings;
- every MPF delete collapse/merge case;
- partial/reordered/spliced batch transitions; and
- reopen/replay/rollback/prune behavior for each supported persistent backend.

Run randomized state-machine and property tests against independent single-key proofs and
full-tree roots. Fuzz every decoder and verifier with strict memory/time limits. Cross-backend
tests must yield the same root and proof/trace bytes for the same profile and logical state.

### 9. Preserve compatibility and make release boundaries explicit

This proposal is additive:

- current MPF and JMT root algorithms remain unchanged;
- existing databases require no rebuild;
- existing single-key proof APIs and codecs remain supported;
- custom hash and commitment profiles remain first-class; and
- new wire formats receive new immutable identifiers.

A multiproof or trace codec can evolve only under a new format version. Decoders never guess a
version. CCL should document whether object models are stable APIs and which wire formats are
release compatibility commitments.

ZeroJ may integrate a reviewed development build for implementation work. Production use waits
for a released CCL version containing the adopted contract and repeats root/proof compatibility,
durable-store, load, and malformed-input gates.

## Suggested delivery plan for CCL

### CCL Phase 0: Semantic specification

- Adopt/replace this ADR.
- Freeze ordering, duplicate, terminal, encoding, and limit rules.
- Choose immutable format identifiers.
- Specify snapshot/update atomicity for each backend.

### CCL Phase 1: Inclusion multiproofs

- Implement MPF and JMT object models, generators, pure verifiers, and deterministic codecs.
- Start with inclusion-only query sets.
- Add vectors, property tests, decoder fuzzing, and JMH/load benchmarks.

### CCL Phase 2: MPF physical-delete trace

- Add delete-existing versus absent-no-op results.
- Emit the trace from the mutation core.
- Add a pure transition verifier and complete collapse/merge vectors.

### CCL Phase 3: Homogeneous transition traces

- Add value-update traces first, then inserts, MPF deletes, and JMT tombstone updates.
- Ensure canonical unique operation order and atomic old/new root derivation.
- Qualify in-memory, RocksDB, and RDBMS semantics where supported.

### CCL Phase 4: Optional mixed proofs

- Consider mixed inclusion/non-inclusion and heterogeneous batches only after consumers show a
  need and the simpler contracts are stable.
- Version the format for any incompatible extension.

## Acceptance criteria for ZeroJ integration

The CCL dependency is ready for ZeroJ ADR-0043 Phase 1 when:

1. public generators and database-independent verifiers exist for both inclusion multiproofs;
2. MPF delete-existing exposes and verifies a complete canonical rewrite trace;
3. every supported batch result can independently derive the advertised new root;
4. custom Poseidon MPF/JMT profiles work without special-casing ZeroJ;
5. encoding/profile identifiers and resource bounds are documented and fail closed;
6. duplicate/order/terminal/atomicity semantics are covered by negative tests;
7. deterministic positive and negative vectors are published;
8. in-memory and applicable durable backends pass cross-backend/state-machine tests;
9. benchmarks report generation/verification time, bytes, allocations, and peak memory versus
   independent proofs; and
10. the feature is available from a pinned CCL revision with release notes.

## Consequences

### Positive

- CCL gains reusable compact proof and transition contracts independent of ZeroJ.
- ZeroJ has a genuinely independent oracle for future circuits.
- Other off-chain, light-client, bridge, rollup, and audit consumers can reuse the same formats.
- Root compatibility and persistence remain separate from proof-format evolution.

### Costs

- Canonical multiproofs and mutation traces add public protocol surface that must be maintained.
- Pure verifiers duplicate some tree logic by design and require independent testing.
- Defensive decoding and backend snapshot semantics add implementation complexity.
- Physical MPF delete traces expose structural cases not visible in the current void API.

## Rejected alternatives

### Put the contract only in ZeroJ

Rejected because it would not be an independent CCL oracle and would couple a general-purpose
authenticated structure to one ZK implementation.

### Return internal node/stale batches directly

Rejected because persistence layouts and garbage-collection metadata are not stable
cryptographic semantics and vary by backend.

### Make one generic MerkleMultiProof type

Rejected because MPF compressed Patricia paths and JMT versioned radix-16 nodes have different
terminal and rewrite rules. Shared low-level utilities do not justify a type-erased public proof.

### Add JMT key deletion as part of this work

Rejected because it changes logical map and historical-storage behavior well beyond the proof
format requested here.

## Handoff recommendation

Treat this as an enhancement to CCL's verified-structures layer, not a defect report. Deliver
canonical inclusion multiproofs first, then the MPF delete-existing trace, then homogeneous
transition traces. Keep codecs profile-bound and resource-bounded, preserve existing roots, and
publish deterministic vectors so CCL, ZeroJ, and future consumers can verify the same protocol
independently.

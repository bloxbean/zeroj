# ADR-0043: Bounded multiproofs, batch transitions, and MPF physical deletion

- **Status**: proposed; implementation is blocked on the companion CCL contract
- **Date**: 2026-08-03
- **Extends**:
  [ADR-0042](0042-operation-specific-poseidon-mpf-and-jmt-circuits.md), especially
  deferred Phase 8 and `ZkMpfDelete`
- **Companion CCL handoff**:
  [ADR-0043-CCL](0043-bounded-multiproofs-batch-transitions-and-mpf-deletion-ccl.md)
- **CCL tracking enhancement**:
  [bloxbean/cardano-client-lib#642](https://github.com/bloxbean/cardano-client-lib/issues/642)
- **Applies to**: `zeroj-mpf-poseidon`, `zeroj-jmt-poseidon`, their load modules,
  test vectors, artifact manifests, and Cardano verification examples

## Context

ADR-0042 deliberately completed and qualified operation-specific single-key Poseidon MPF and
JMT circuits before attempting multiproofs or batches. It left four optional circuit families
and one physical-delete primitive open:

- `ZkMpfMultiInclusion` and `ZkJmtMultiInclusion`;
- `ZkMpfBatchTransition` and `ZkJmtBatchTransition`; and
- `ZkMpfDelete`.

That deferral was not a statement that Groth16 cannot prove these operations. It was a protocol
boundary. A sound circuit needs a canonical host-side definition of the proof or transition it
checks, plus an implementation that can independently generate roots and witnesses. CCL
`0.8.0-pre5` provides qualified single-key proof APIs, MPF physical deletion, and JMT
atomic batch storage updates, but it does not provide a frozen shared multiproof or
cryptographic transition-witness contract.

ZeroJ must not invent a private multipath format, generate it with the same code that builds the
circuit witness, and call matching outputs correctness evidence. The same misunderstanding also
applies to mutation:

- a list of independent proofs is not a deduplicated multiproof;
- CCL's JMT `put(version, Map)` is an atomic storage batch, not a proof of that transition;
- an MPF inclusion proof before `delete` does not by itself authenticate every canonical
  collapse or prefix merge performed after deletion; and
- a tombstone or zero-valued leaf remains an included leaf and is not physical non-inclusion.

This ADR defines the ZeroJ side of that future work. The companion `-ccl` ADR specifies the
host contract ZeroJ needs and is intended for handoff to the CCL team. Neither ADR changes the
current `zeroj-poseidon-mpf-v1` or `zeroj-poseidon-jmt-v1` root algorithms.

## Terminology

| Term | Meaning in this ADR |
|---|---|
| Independent proofs | One complete single-key path and one Groth16 proof per statement |
| Multiproof | One canonical, minimal union of paths for several queries under one root, with shared nodes represented once |
| Storage batch | Several writes committed atomically by a database/tree API; it need not expose a cryptographic witness |
| Transition witness | Canonical authenticated data sufficient to recompute both the old and new roots for a mutation |
| ZK batch transition | One bounded circuit proving that a committed batch transforms `oldRoot` into `newRoot` |
| Physical delete | Removing a key from the authenticated map and canonically normalizing its structure |
| Tombstone update | Replacing a live value with an application-defined marker; the key is still included |
| Independent host oracle | CCL generates and verifies the canonical result without relying on ZeroJ's circuit or witness builder |

## Decision

### 1. Freeze the CCL proof and transition contract before implementing these circuits

The companion CCL work is a hard Phase 0 dependency. ZeroJ implementation starts only after a
CCL revision provides:

1. canonical multiproof semantics and an independently usable verifier;
2. profile- and format-bound deterministic encodings and golden vectors;
3. explicit key ordering, duplicate, inclusion/non-inclusion, and resource-limit rules;
4. an MPF deletion result that authenticates the structural rewrite; and
5. deterministic transition traces for any batch operation ZeroJ intends to prove.

The first usable dependency may be a reviewed CCL development build, but ZeroJ production
qualification ultimately requires a released and pinned CCL version. The CCL implementation is
the semantic oracle; ZeroJ still treats every decoded proof and trace as untrusted input and
constrains all security-relevant fields.

Read-only multiproofs are proof-format additions and do not change the MPF or JMT root. Transition
traces describe existing root algorithms and likewise must not silently create a new commitment
profile. Any root drift requires a separate migration ADR and new profile identifier.

### 2. Use bounded, operation-specific circuit templates

Multiproof and batch size are compile-time circuit dimensions. They do not expand dynamically
when the application adds records. Every released artifact fixes:

- structure and commitment profile;
- operation and proof form;
- maximum path steps `sN`;
- maximum item or operation count `bN`;
- public-input schema and statement-commitment algorithm; and
- exact R1CS fingerprint and Groth16 setup identity.

Initial candidates should be benchmarked at `b2`, `b4`, and `b8`. Those numbers are candidates,
not promises. Only bounds with a practical constraint count, proving-key size, proving latency,
and peak-memory result are published.

A candidate identifier has this shape:

```text
zeroj-{mpf|jmt}-v1-{operation}-s{steps}-b{items}-p{public-schema}
```

For example, `zeroj-jmt-v1-multi-inclusion-s64-b8-p1` denotes a different circuit and
verification key from its `b4` or `s12` counterpart. Unused slots use constrained canonical
padding; they are never selected by an unconstrained validity flag.

### 3. Implement the circuit catalog in increasing semantic complexity

The first catalog is intentionally narrower than a universal `ZkMpfBatchTransition` or
`ZkJmtBatchTransition` switch circuit.

| Structure | Circuit template | Statement | Initial priority |
|---|---|---|---|
| MPF | `ZkMpfDelete` | One existing key is physically removed and the Patricia structure is canonically normalized | P1 |
| MPF | `ZkMpfMultiInclusion` | Every committed item is included under one MPF root using one shared multipath | P2 |
| JMT | `ZkJmtMultiInclusion` | Every committed item is included at one JMT root/version using one shared multipath | P2 |
| MPF | `ZkMpfBatchValueUpdate` | A bounded set of existing values changes `oldRoot` to `newRoot` | P3 |
| JMT | `ZkJmtBatchValueUpdate` | A bounded set of existing values changes one version root into the next | P3 |
| MPF | `ZkMpfBatchInsertEmpty` | A bounded set of missing-branch insertions changes the root | P4 |
| MPF | `ZkMpfBatchInsertDifferentLeaf` | A bounded set of conflicting-leaf insertions changes the root | P4 |
| JMT | `ZkJmtBatchInsertEmpty` | A bounded set of empty-terminal insertions changes the root | P4 |
| JMT | `ZkJmtBatchInsertDifferentLeaf` | A bounded set of conflicting-leaf insertions changes the root | P4 |
| MPF | `ZkMpfBatchDelete` | A bounded set of existing keys is physically removed with canonical Patricia normalization | P5 |
| JMT | `ZkJmtBatchTombstoneUpdate` | A bounded set of live values is replaced with an explicitly bound tombstone commitment | P5 |

Source-level facades may dispatch to these templates, but they do not imply one generic R1CS.
Homogeneous batches come first because their preconditions and soundness rules are reviewable.
A heterogeneous `ZkMpfBatchTransition` or `ZkJmtBatchTransition` circuit is optional future work.
It requires public or statement-committed operation tags, constraints for every selected form,
and evidence that it is better than composing homogeneous batches.

Multi-non-inclusion and mixed inclusion/non-inclusion proofs are also future extensions. If
implemented, empty-terminal and different-leaf non-inclusion remain distinct circuit templates
unless a reviewed discriminator is fully constrained. The initial inclusion-only multiproof must
not accept either non-inclusion terminal.

There is no `ZkJmtDelete` in this catalog. CCL `0.8.0-pre5` rejects null values and has no
logical key-delete API. JMT physical deletion requires a separate CCL storage, versioning,
rollback, pruning, proof, and commitment decision. A tombstone update is useful, but it proves
inclusion of the tombstone.

### 4. Canonicalize query sets and batches before they enter a circuit

CCL hashes original keys using the selected profile. Canonical ordering is unsigned
lexicographic order of the full fixed-width key hashes, not Java object identity, caller map
iteration order, field-reduced values, or shortened path prefixes.

For the initial circuits:

1. all key hashes must be fixed-width and canonical for the profile;
2. the host rejects duplicate original-key bytes and duplicate resulting key hashes;
3. multiproof queries are sorted by key hash;
4. batch operations contain at most one operation per key hash;
5. transition operations are normalized to the same key-hash order;
6. the public item count is within `1..bN`; and
7. slots from `itemCount` through `bN - 1` have one canonical no-op encoding and are
   constrained not to affect either root or statement commitment.

Rejecting duplicate operation keys avoids ambiguous first-wins/last-wins behavior and prevents a
batch from hiding multiple sequential updates to one key. An application that needs two ordered
changes to the same key uses separate transitions or a future explicitly sequential transcript
circuit.

The canonical operation list is committed with a structure- and operation-specific Poseidon
domain. The commitment binds at least profile, operation family, item count, each full key hash,
the required old/new value commitments, and any application-visible version. Host raw-byte
encodings and circuit field encodings receive independent golden vectors.

### 5. Bind a meaningful public statement

The default multiproof template exposes:

- `root`;
- `itemsCommitment`; and
- `itemCount`.

The default transition template exposes:

- `oldRoot`;
- `newRoot`;
- `batchCommitment`; and
- `operationCount`.

JMT templates may additionally expose or commit the old/new version when the application uses
versioned state. A version never authenticates a root by itself; the application remains
responsible for binding the root to a Cardano chain point or other trusted checkpoint.

This default prevents a proof with only a root from meaning merely “I know some unspecified set
of entries.” Applications may compose the gadget into a more private statement, but the complete
application circuit must bind the entries or their policy consequence through a public
commitment, nullifier, signature, transaction reference, or equivalent constraint.

The native CCL multiproof or transition trace is private prover input. A successful Groth16 proof
remains 192 bytes for the current BLS12-381 Groth16 encoding. Public inputs and validator datum
may grow slightly, but native MPF/JMT proof bytes are not placed on chain.

### 6. Define physical MPF deletion as delete-existing, not a no-op

CCL's current `MpfTrie.delete(key)` is a no-op when the key is absent. `ZkMpfDelete` proves the
stronger and more useful statement:

> The key and old value were included under `oldRoot`, and removing exactly that leaf followed
> by canonical MPF normalization produces `newRoot`.

The circuit therefore rejects an absent-key no-op. If an application needs “delete if present,”
it must select either a delete-existing proof or an independently authenticated non-inclusion
proof at the application layer.

The CCL witness and circuit must cover every reachable structural case, including:

- deleting the only root leaf and producing the canonical empty root;
- removing a leaf from a multi-child branch;
- preserving a branch that still has enough content;
- collapsing a branch with one surviving child;
- preserving or moving a branch value where the MPF profile permits it;
- merging extension/prefix fragments without losing a nibble;
- retaining a neighboring leaf or fork commitment; and
- recursively propagating collapse to the root.

The trace must be captured by the actual mutation algorithm under the same logical operation,
not inferred afterward from an old inclusion proof and a separately reopened new tree. Old and
new roots, removed key/value commitments, affected prefixes, siblings, and replacement nodes are
all constrained. Empty, zero, and application tombstone values have no deletion magic.

### 7. Represent a multiproof as one minimal authenticated subtree

The host proof is the minimal union of the requested root-to-terminal paths:

- shared prefixes and branch nodes occur once;
- boundary subtrees not opened by a query appear once as their commitments;
- query terminals are mapped unambiguously to their full key hashes and values;
- no unattached, duplicate, cyclic, or unused proof node is accepted; and
- deterministic traversal and encoding make semantically equivalent proofs byte-identical.

Only a genuinely shared authenticated tree position is deduplicated. Equal commitment bytes at
two different positions do not make those positions interchangeable.

ZeroJ need not reproduce the host wire representation inside R1CS. Its adapter may normalize the
proof into fixed arrays of node values, references, child indices, query indices, and padding.
However, the circuit recomputes the root and constrains every reference, range, ordering rule,
terminal, and used-node bit. The witness builder cannot assert that the host verifier already ran.

### 8. Preserve transition atomicity inside the circuit

For a batch transition, every real slot is applied to one constrained evolving state. Intermediate
roots may remain private, but they cannot be unconstrained hints. The final intermediate root
must equal `newRoot`, and the first must derive from `oldRoot`.

When a shared-subtree transition witness performs several changes together, the circuit must
prove the equivalent atomic map transformation rather than trust per-operation paths that become
stale after the first update. It must reject:

- a pre-state proof combined with an unrelated post-state root;
- partial application or reordering;
- duplicate-key conflicts;
- unused operations hidden outside `operationCount`;
- old/new value substitution;
- insert/update/delete precondition confusion; and
- a trace that commits successfully in storage but is not the same logical batch.

The CCL oracle must produce the root and trace from one deterministic batch operation. RocksDB or
RDBMS transaction atomicity remains a host durability concern; the ZK proof establishes the
cryptographic state transformation, not that bytes were durably flushed.

### 9. Benchmark before deciding that batching is an optimization

One batch Groth16 proof is constant-size, but its circuit may cost more than several independent
proofs. Qualification compares each `bN` profile with `N` single-operation proofs using:

- exact constraints and R1CS digest;
- setup time and proving/verification key size;
- witness conversion time;
- proof-generation median and tail latency;
- host and Julc verification time;
- peak heap, RSS, and temporary artifact size;
- native proof/trace bytes and final Groth16/public-input bytes; and
- throughput under the intended proving-service concurrency.

Both MPF and JMT tests run against small adversarial fixtures and durable high-volume databases.
At minimum, the preserved five-million-entry MPF state and the qualified five-million-entry JMT
load profile are exercised. Entry count itself is not a circuit input and does not impose a
five-million-record cap; observed path depth and the chosen `sN` bound do. A larger database needs
no circuit change when every witness still fits the released bound.

A batch profile is recommended only if it provides measured application value: lower aggregate
proving/on-chain cost, lower witness I/O, atomic policy binding, or operational simplicity.
Independent 192-byte proofs remain a supported fallback and may be faster or easier to schedule.

## Delivery plan

### Phase 0: CCL contract and oracle

- Adopt the companion CCL ADR or an equivalent reviewed contract.
- Implement canonical encoders, decoders, verifiers, mutation traces, and resource bounds.
- Publish cross-profile, cross-backend, positive, negative, and malformed golden vectors.
- Pin the qualified CCL revision in ZeroJ.

Exit condition: ZeroJ can consume CCL proofs/traces without using any ZeroJ circuit code to
generate their expected roots or semantics.

### Phase 1: ZeroJ codecs, statement commitments, and differential harness

- Add fail-closed CCL-to-ZeroJ normalization with fixed bounds.
- Add Poseidon item/batch commitment vectors.
- Differentially verify CCL roots, CCL verification, normalized witnesses, and circuit outputs.
- Add mutation, malformed encoding, alias, duplicate, ordering, and padding tests.

Exit condition: all host fixtures round-trip independently and every negative mutation fails.

### Phase 2: Single MPF physical deletion

- Implement and review `ZkMpfDelete` before batch deletion.
- Cover every collapse/merge case and maximum-depth overflow.
- Run state-machine properties over insert, update, delete, reopen, and proof generation.
- Benchmark against current MPF single-operation circuits.

Exit condition: old/new roots match CCL across randomized sequences and durable stores.

### Phase 3: Inclusion multiproofs

- Implement MPF and JMT `b2` candidates first.
- Review used-node accounting, shared-path ownership, ordering, and padding.
- Expand to `b4`/`b8` only when measurements justify the artifact cost.

Exit condition: at least one bounded profile is safer or materially more useful than independent
proofs and passes adversarial differential testing.

### Phase 4: Homogeneous batch transitions

- Implement batch value updates first.
- Add insertion forms, then MPF deletion and JMT tombstone updates.
- Bind canonical operation commitments and atomic old/new roots.
- Test backend replay, reopen, rollback/prune boundaries, and concurrency assumptions.

Exit condition: every circuit family has exact manifests, vectors, performance data, and Cardano
VM verification.

### Phase 5: Optional mixed or aggregated proofs

Only after Phase 4, evaluate:

- mixed inclusion/non-inclusion multiproofs;
- heterogeneous transition circuits;
- recursive aggregation of independent Groth16 proofs; and
- application-specific rollup circuits.

Each option requires a separate decision and benchmark. This ADR does not authorize a generic
witness-selected universal circuit.

## Verification and security requirements

Every released circuit and adapter must test at least:

- valid CCL-generated cases for every supported proof/transition form;
- empty, one-item, full-bound, maximum-depth, and shared/disjoint-prefix cases;
- unsorted, duplicate, missing, extra, unattached, cyclic, and reordered nodes;
- duplicate raw keys, duplicate key hashes, and conflicting operations;
- truncated, overlong, non-canonical, and cross-profile encodings;
- field aliases and non-canonical fixed-width field encodings;
- invalid child/reference indices and invalid padding;
- mutation of roots, count, item/batch commitment, key, value, prefix, sibling, operation, and
  version;
- MPF deletion collapse and prefix-merge boundaries;
- old-root/post-root trace splicing and partial application;
- decoder byte/node/item/depth limits before large allocation; and
- application replay and statement-binding examples.

Hints, host-valid flags, node-use flags, intermediate roots, and normalized indices are not
trusted. The circuit derives or constrains them. Audit, production ceremony, exact verification
key allowlisting, Yaci/current-protocol-budget testing, and target-network transaction gates from
ADR-0042 continue to apply independently to every new R1CS.

## Consequences

### Positive

- Several entries or updates can be bound by one constant-size Groth16 proof.
- Native JMT proof-size disadvantages remain private to the prover.
- CCL supplies one reusable canonical oracle for ZeroJ and other consumers.
- Separate circuit families keep operation soundness and setup identities auditable.
- Physical MPF deletion becomes a real authenticated transition rather than a value convention.
- Existing MPF/JMT roots, databases, and single-key proof APIs remain valid.

### Costs

- Every `sN`/`bN`/operation combination needs its own R1CS, setup, keys, manifest, vectors,
  benchmark, and lifecycle.
- Batch proving keys and memory may grow quickly even while proof bytes remain constant.
- CCL and ZeroJ must coordinate proof-format and vector releases.
- Canonical rewrite traces expose more host structure and require strong decoder limits.
- The independent-proof fallback may remain preferable for latency-sensitive workloads.

## Rejected alternatives

### Define a ZeroJ-only multipath and use it as the oracle

Rejected because the witness builder and circuit could share the same structural bug, and other
CCL applications could not independently verify the protocol.

### Treat CCL JMT batch put or TreeUpdateBatch as a ZK transition witness

Rejected because those APIs describe storage work and stale-node bookkeeping, not a stable,
profile-bound cryptographic proof contract.

### Use one universal circuit for every read and mutation

Rejected because witness-selected alternatives increase constraints and soundness surface and
make operation-specific verification-key policy harder.

### Model MPF deletion as writing zero or a tombstone

Rejected because the resulting leaf remains included and the root is not the canonical root of a
physically deleted MPF key.

### Add JMT physical deletion now

Rejected because the reviewed CCL baseline has no such map operation. Storage, versioning,
rollback, pruning, root, and proof behavior must be designed together first.

### Assume a batch circuit is faster because it emits one proof

Rejected because shared constraints, setup/key size, and proving memory can outweigh path
deduplication. The decision is benchmark-driven.

## Final recommendation

Keep the ADR-0042 single-operation circuits as the production path and independent-proof fallback.
First give CCL a canonical, resource-bounded, profile-aware multiproof and transition-witness
contract. Then implement `ZkMpfDelete`, inclusion multiproofs, and homogeneous batch transitions
in bounded operation-specific ZeroJ circuits. Defer mixed/universal batches and JMT physical
deletion until their semantics and measured benefit justify a separate security boundary.

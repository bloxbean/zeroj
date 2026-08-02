# ADR-0042: Operation-specific Poseidon MPF and JMT circuits

- **Status**: accepted; implementation planned
- **Date**: 2026-08-02
- **Supersedes in part**: the CCL `0.8.0-pre4` dependency and pre-release MPF `v2` naming
  decisions in
  [ADR-0041](0041-poseidon-mpf-production-readiness-and-load-benchmark.md)
- **Keeps**: the full-semantics `ZkMpf` circuit capability and current Poseidon MPF commitment
  algorithm/root; preview package and module locations are not compatibility commitments
- **Introduces**: separate MPF/JMT Poseidon modules and operation-specific circuit families
- **Related**:
  [Poseidon MPF gadget design](circuit-annotation/zk-mpf-gadget.md),
  [five-million-entry MPF benchmark](../benchmarks/poseidon-mpf-5m-2026-08-02.md), and
  [large-state production report](../poseidon-mpf-large-state-production-report.md)

## Context

ZeroJ currently exposes `ZkMpf`, a complete symbolic verifier for the ZeroJ Poseidon MPF
profile. It supports inclusion and supported exclusion paths while representing the different
CCL MPF proof node forms in one bounded circuit:

- branch, fork, neighboring-leaf, and padding steps;
- variable Patricia prefixes and skipped nibbles;
- dynamic key-path cursors and prefix/suffix packing;
- inclusion and exclusion selection; and
- leaf divergence and proof-shape checks.

This full-semantics design is useful and must remain available. It is also expensive.
The measured eight-step circuit has 17,399,380 constraints and took 213.826 seconds to create
a Groth16 proof in the 2026-08-02 reference benchmark. That cost is tied to the circuit shape,
not to the five million entries stored in RocksDB.

An exploratory CCL `0.8.0-pre5-dev1` JMT integration demonstrated a different approach: define
one circuit for one operation and use a circuit-native radix-16 Poseidon commitment. A JMT
inclusion proof then needs four binary sibling hashes per traversed radix-16 level. The
exploratory results were:

| Circuit | Constraints | Groth16 proving time | Proof size |
|---|---:|---:|---:|
| Operation-specific JMT inclusion, 8 levels | 25,730 | 8.261 s | 192 B |
| Operation-specific JMT inclusion, 64 levels | 186,394 | 17.4-19.3 s | 192 B |
| Existing full-semantics MPF, 8 steps | 17,399,380 | 213.826 s | 192 B |

These are feasibility measurements on one development machine using insecure local benchmark
setup parameters. They are not release SLAs. The difference shows the value of specialization;
it does not establish that JMT is intrinsically faster than MPF. An operation-specific MPF
circuit may also become much smaller than the current `ZkMpf` circuit.

The same JMT experiment loaded 100,000 entries in durable RocksDB, generated real CCL object
and wire proofs, converted a proof into a ZeroJ witness, proved it with Groth16, and verified
the resulting artifact in the Julc Plutus V3 VM. The native JMT wire proof was 2,157 bytes at
the median and 2,404 bytes at the observed maximum. The on-chain Groth16 proof remained 192
bytes. Consequently, JMT's larger native proof is private prover input and does not need to be
processed by the Cardano validator.

CCL `0.8.0-pre5-dev1` also changes the JMT decision materially. It provides a named custom
`JmtProfile` containing a format descriptor, hash function, commitment scheme, and proof codec.
It fixes proof-key binding and persistence/replay/rollback/pruning defects present before the
dev1 hardening work. Its production qualification remains intentionally bounded to serialized
off-chain state with one logical writer, durable storage, and an application-authenticated
mapping between chain point, version, and root. See the
[CCL JMT audit](https://github.com/bloxbean/cardano-client-lib/blob/v0.8.0-pre5-dev1/verified-structures/jellyfish-merkle/docs/security-performance-audit.md)
and
[production-readiness gates](https://github.com/bloxbean/cardano-client-lib/blob/v0.8.0-pre5-dev1/verified-structures/jellyfish-merkle/adr/002-production-readiness-gates.md).

## Terminology

This ADR distinguishes three layers that must not be conflated.

### Commitment profile

A commitment profile fixes the hash parameters, domains, byte/field encodings, leaf format,
branch format, empty-node value, and root interpretation. A root is meaningful only under one
specific commitment profile.

### Circuit primitive or gadget

A primitive verifies one authenticated-data-structure operation over symbolic inputs. It does
not decide which inputs are public, which application identity is authorized, or how a root is
anchored on Cardano. A larger application circuit can compose a primitive with signatures,
nullifiers, range checks, credential rules, or other policy.

### Standalone circuit template

A template chooses input visibility and a public statement for one primitive. Its exact R1CS,
maximum path bound, public-input schema, and circuit fingerprint determine the Groth16 proving
and verification keys. Reusing a Java gadget does not imply that every composed application
can reuse one verification key.

## Decision

### 1. Use CCL `0.8.0-pre5-dev1` throughout this branch

The root `cclVersion` property will move from `0.8.0-pre4` to `0.8.0-pre5-dev1`. Every direct
`com.bloxbean.cardano:cardano-client-*` dependency continues to resolve through that one root
property and the existing resolution rule. ZeroJ will not place pre4 MPF and dev1 JMT artifacts
on the same runtime classpath because they publish the same Maven coordinates and Java packages.

This supersedes ADR-0041's dependency-version decision. It does not change the existing Poseidon
MPF commitment algorithm/root, preserved five-million-entry database, benchmark methodology, or
production gates. Section 3 separately replaces the pre-release `v2` profile label with `v1`.

Before accepting the dependency update as complete, the implementation must:

1. run the small MPF golden-root and wire-proof compatibility suites;
2. reopen the preserved five-million-entry MPF database under dev1;
3. verify its recorded root without mutation;
4. generate and verify proofs for deterministic existing entries; and
5. confirm that no resolved CCL dependency remains on pre4.

Source comparison found no intended MPF commitment/root-format change between these tags; the
RocksDB MPF difference is resource-lifecycle cleanup. The compatibility checks remain mandatory
because persisted roots are production data, not an assumption. If any root or wire proof drifts,
the version update stops and requires a separate migration ADR.

`0.8.0-pre5-dev1` is a development release. ZeroJ will move to the first stable CCL release that
contains the same JMT fixes and profile API after repeating the same compatibility gates.

### 2. Retain the full-semantics `ZkMpf` circuit, but relocate it into the MPF module

The behavior represented by the current `ZkMpf` and `ZkMpfProof` remains available as the
full-semantics MPF option. It is not a structure-neutral circuit primitive and therefore does not
belong in `zeroj-circuit-lib`.

Because ZeroJ is still preview software with no external MPF application compatibility contract,
the existing package and module location will not be preserved through a forwarding facade. The
classes move from:

```text
com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMpf
com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMpfProof
```

to the MPF-owned circuit package:

```text
com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit.ZkMpf
com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit.ZkMpfProof
```

The move retains the full feature as a migration/reference circuit; it does not promise Java
source/binary compatibility or reuse of benchmark-only proving/setup artifacts. Any changed R1CS
receives a new fingerprint and new keys. Tests will continue to compare its accepted statements
with the operation-specific primitives where their semantics overlap.

For new applications, ZeroJ recommends the smallest operation-specific primitive that expresses
the required statement. The full `ZkMpf` gadget remains appropriate only when an application
genuinely needs its combined proof semantics.

### 3. Name the first supported MPF profile `v1` and use structure-specific profiles

MPF and JMT use the same ZeroJ ZK-friendly hash family:

- BLS12-381 scalar field;
- Poseidon `t=3`, `alpha=5` and the existing reviewed ZeroJ round constants;
- canonical 32-byte unsigned big-endian field encodings; and
- the existing total raw-byte hashing behavior required by CCL's `HashFunction` contract.

This shared family may be described as `zeroj-poseidon-authenticated-state-v1` in documentation
and common code. It is not itself a root format.

The first supported MPF profile identifier will be:

```text
zeroj-poseidon-mpf-v1
```

The current pre-release worktree and five-million-entry benchmark called this candidate
`zeroj-poseidon-mpf-v2` because the total raw-byte fallback was the second internal iteration of
the adapter. The earlier strict adapter was never assigned a stable persistent profile, released,
or used by an external application. An internal implementation iteration is not a public profile
version. Publishing the first supported profile as `v2` would therefore create compatibility
history that does not exist.

The rename is metadata/source naming, not a cryptographic redesign. The numeric raw-byte domain,
Poseidon parameters, encodings, node commitments, and all resulting roots remain unchanged.
`DOMAIN_RAW_BYTES_V2` will be renamed to `DOMAIN_RAW_BYTES_V1` without changing its field value.
The profile identifier is not an input to the commitment hash.

The preserved five-million-entry benchmark report remains honest about the `v2` label present
during that run. Before the database is reused under the final `v1` name, an explicit benchmark
manifest migration must:

1. back up the small manifest metadata;
2. verify the recorded root and deterministic proofs under the unchanged algorithm;
3. replace only the profile identifier;
4. verify the same root and proofs again; and
5. record that `v2` was an unreleased alias for the final `v1`, not a different commitment.

Runtime code must not silently accept arbitrary profile aliases. The one-time benchmark metadata
migration is an operator action and does not establish a general `v2` compatibility promise.

The concrete structure profiles remain separate:

| Structure | Profile | Decision |
|---|---|---|
| MPF | `zeroj-poseidon-mpf-v1` | First supported profile; preserve current roots and semantics unchanged |
| JMT | `zeroj-poseidon-jmt-v1` | New profile; specify and independently vector before release |

JMT leaf, branch, empty-node, and optional transition commitments receive JMT-specific domain
separators. An MPF root and JMT root are never interchangeable even when they represent the same
key/value set. A database cannot be opened under the other structure's descriptor, and there is
no implicit MPF-to-JMT root conversion.

The shared raw-byte Poseidon implementation should be extracted behind an internal common helper
only if this can be done without changing MPF v1 outputs. The public MPF adapter may delegate to
that helper after golden vectors prove exact compatibility.

### 4. Define a circuit-native Poseidon JMT commitment

The default CCL classic JMT commitment hashes a radix-16 node representation intended for normal
off-chain verification. It is not the root format used by the new ZK circuit.

`zeroj-poseidon-jmt-v1` will use:

1. a leaf commitment that binds a structure-specific leaf tag, the complete 256-bit key hash,
   and the value hash;
2. sixteen logical child slots for each radix-16 branch, with the empty child represented by the
   profile's fixed empty value;
3. a fixed four-level binary Poseidon subtree over those sixteen children; and
4. four sibling field elements per traversed JMT level in the normalized circuit witness.

The complete key hash must be bound in the leaf, not only the traversed suffix. Every key nibble
must be range constrained, and any conversion of a 256-bit encoding into one field element must
reject values greater than or equal to the BLS12-381 scalar modulus so that field aliases cannot
produce a second accepted key encoding.

CCL persistence will use `JmtProfile.custom(...)` and a stable `JmtFormatDescriptor` identifier.
Opening a RocksDB namespace under a different profile must fail closed. Classic Blake2b JMT,
classic CCL wire commitments, MPF v1, and Poseidon JMT v1 are four different compatibility
domains.

### 5. Provide operation-specific MPF primitives

The following catalog covers the core authenticated-map operations. Names describe the intended
public API; implementation may use package-private shared helpers to avoid duplicated constraints.

| Primitive | Statement | Minimum public inputs in the standalone template | Private witness | Priority |
|---|---|---|---|---|
| `ZkMpfInclusion` | A key path maps to a value commitment under `root` | `root` | key path, value commitment, normalized proof | P0 |
| `ZkMpfNonInclusion` | A key path is absent under `root` using a sound supported terminal form | `root` | query path and exclusion proof | P0 |
| `ZkMpfValueUpdate` | Replacing an existing value transforms `oldRoot` into `newRoot` | `oldRoot`, `newRoot` | key path, old/new values, authentication path | P1 |
| `ZkMpfInsert` | A previously absent key is inserted canonically, producing `newRoot` | `oldRoot`, `newRoot` | key/value, exclusion witness, structural rewrite witness | P1 |
| `ZkMpfDelete` | An existing key is removed and the Patricia path is canonically normalized | `oldRoot`, `newRoot` | key/value, inclusion witness, merge/rewrite witness | P2 |
| `ZkMpfMultiInclusion` | Several entries are included under one root | `root` | entries and a deduplicated multipath | P2 |
| `ZkMpfBatchTransition` | An ordered batch of supported operations transforms one root into another | `oldRoot`, `newRoot`, optional batch commitment | operations and shared transition witness | P3 |

`ZkMpfValueUpdate` is the first transition primitive because it can normally reuse one
authentication path. Insert and delete must reproduce CCL's canonical Patricia restructuring;
they are not implemented by merely swapping a leaf digest.

`ZkMpfNonInclusion` must fail closed for any CCL proof form whose terminal commitment is not fully
authenticated by the normalized witness. Unsupported forms are not accepted merely to offer a
single broad API.

### 6. Provide operation-specific JMT primitives

JMT proof forms are simpler but remain distinct statements:

| Primitive | Statement | Minimum public inputs in the standalone template | Private witness | Priority |
|---|---|---|---|---|
| `ZkJmtInclusion` | A full key hash maps to a value hash under `root` | `root` | key hash/path, value hash, four siblings per valid level | P0 |
| `ZkJmtNonInclusionEmpty` | The queried path reaches an authenticated empty child | `root` | query key/path and branch siblings | P1 |
| `ZkJmtNonInclusionDifferentLeaf` | The queried key diverges from an authenticated conflicting leaf | `root` | query key, conflicting leaf, divergence data, siblings | P1 |
| `ZkJmtValueUpdate` | Updating an existing leaf transforms `oldRoot` into `newRoot` | `oldRoot`, `newRoot` | key, old/new values and one path | P1 |
| `ZkJmtInsert` | A valid non-inclusion becomes a canonical included leaf | `oldRoot`, `newRoot` | key/value, non-inclusion proof and rewrite witness | P1 |
| `ZkJmtTombstoneUpdate` | A live value is replaced with an application-defined tombstone | `oldRoot`, `newRoot` | key, live/tombstone values and path | P2 |
| `ZkJmtMultiInclusion` | Several entries are included under one root | `root` | entries and deduplicated multipath | P2 |
| `ZkJmtBatchTransition` | An ordered batch transforms one version root into the next | `oldRoot`, `newRoot`, optional batch/version commitment | operations and shared transition witness | P3 |

`ZkJmtDelete` is deliberately not promised by this ADR. CCL dev1 has no native key deletion;
storing a tombstone still proves inclusion of that tombstone. A future physical/canonical delete
requires CCL storage semantics, proof semantics, circuit semantics, pruning behavior, and test
vectors to be specified together in a separate ADR.

JMT version numbers, Cardano chain points, rollback horizons, and pruning metadata are not Merkle
membership constraints. The application or validator must authenticate `{chain point, version,
root}`. A transition template may expose a version or batch commitment when the application needs
it, but a version number alone does not authenticate a root.

### 7. Keep primitives composable and visibility-neutral

The reusable Java gadget accepts symbolic values without forcing all of them to be public or
private. Standalone templates provide conservative defaults, but application circuits decide the
complete statement.

For example, a circuit with only one public root proves only:

```text
I know some private key/value entry included in this root.
```

That is sufficient only when existential anonymous membership is the intended policy. Most
applications must additionally bind at least one of:

- a public or committed key/value;
- a domain-separated nullifier;
- an owner signature or credential subject;
- a transaction input/output reference;
- a policy result, amount, epoch, or expiry; or
- an operation/batch commitment.

Applications compose those checks around `ZkMpfInclusion` or `ZkJmtInclusion`. The resulting
application circuit has a new fingerprint and normally needs its own Groth16 setup. A standard
standalone circuit and verification key may be shared across applications only when the complete
R1CS and public-input schema are identical.

ZeroJ will not claim recursive proof composition. Verifying a standalone primitive proof inside
another Groth16 circuit would require a separate recursion design. "Composable" in this ADR means
source/gadget composition before R1CS compilation, or independent on-chain verification when an
application deliberately uses two proofs.

### 8. Version bounded circuit templates explicitly

Groth16 circuit size is fixed before the witness is known. Every released template identifier
must include or resolve unambiguously to:

- structure and commitment profile;
- operation kind;
- maximum proof levels/steps or batch size;
- public-input schema and order;
- circuit/R1CS fingerprint;
- Poseidon parameter fingerprint; and
- trusted-setup/verification-key identifier.

Illustrative identifiers are:

```text
zeroj-mpf-v1-inclusion-s12-p1
zeroj-jmt-v1-inclusion-s8-p1
zeroj-jmt-v1-inclusion-s64-p1
zeroj-jmt-v1-update-s64-p2
```

The final naming format will be documented with generated manifests rather than inferred from
class names. A witness deeper than the selected bound fails before proving; it is never truncated.

ZeroJ may publish a small common-path profile and a full-bound fallback. The initial candidates
are JMT S8 plus S64. MPF presets will be chosen only after the operation-specific circuit and the
preserved five-million-entry proof-depth data are benchmarked. Applications requiring one fixed
latency profile may choose only the full bound; applications allowing routing may use a smaller
common profile and a slower fallback.

Groth16 proof size remains 192 bytes for these BLS12-381 circuits. Proving time and proving-key
size scale with the circuit. On-chain verification work scales mainly with the number of public
inputs, so adding public application bindings is a deliberate verifier-budget decision.

### 9. Use separate MPF and JMT modules; do not create one implementation monolith

The publishable structure artifacts are:

```text
zeroj-mpf-poseidon
zeroj-jmt-poseidon
```

The names are structure-first deliberately. They group the authenticated structure before the
commitment specialization and leave room for an explicitly different commitment implementation
without making `zeroj-merkle` ambiguous.

MPF and JMT share Poseidon building blocks, but they are separate commitment universes with
different CCL dependencies, proof types, witnesses, update/delete semantics, security reviews,
and readiness status. Package separation inside one JAR would not enforce those boundaries and
would make every consumer resolve both structures.

The dependency direction is:

```text
                         zeroj-circuit-lib
                    generic Poseidon/Merkle helpers
                           ▲             ▲
                           │             │
              zeroj-mpf-poseidon     zeroj-jmt-poseidon
              CCL MPF + ZkMpf*       CCL JMT + ZkJmt*
                           ▲             ▲
                           │             │
         zeroj-mpf-poseidon-load     zeroj-jmt-poseidon-load
             MPF RocksDB/tooling         JMT RocksDB/tooling

              zeroj-onchain-julc (generic Groth16 verifier)
```

The module responsibilities are:

| Module | Responsibility |
|---|---|
| `zeroj-circuit-lib` | Structure-neutral Poseidon parameters/hashing, binary Merkle helpers, canonical field/nibble checks, selectors, and padding utilities; no CCL MPF/JMT semantics |
| `zeroj-mpf-poseidon` | MPF v1 profile/domains, CCL MPF adapter, commitments, codec, witnesses, full `ZkMpf`, and operation-specific `ZkMpf*` circuits |
| `zeroj-jmt-poseidon` | JMT v1 profile/domains, CCL JMT adapter, commitments, codec, witnesses, and operation-specific `ZkJmt*` circuits |
| `zeroj-mpf-poseidon-load` | Non-published durable MPF RocksDB benchmark/operator tooling |
| `zeroj-jmt-poseidon-load` | Non-published durable JMT RocksDB benchmark/operator tooling |
| `zeroj-onchain-julc` | Structure-independent Groth16 verifier plus operation/VK binding examples or validators |

The structure packages are:

```text
com.bloxbean.cardano.zeroj.merkle.mpf.poseidon
    profile
    ccl
    witness
    circuit

com.bloxbean.cardano.zeroj.merkle.jmt.poseidon
    profile
    ccl
    witness
    circuit
```

Profile identifiers, domain separators, leaf/branch commitments, CCL codecs, normalized proof
forms, and transition semantics stay in the corresponding structure module. Only code that is
genuinely independent of both root formats may move into `zeroj-circuit-lib`.

The dependency rules are:

1. `zeroj-circuit-lib` must not depend on a CCL MPF/JMT artifact or either structure module.
2. `zeroj-mpf-poseidon` may depend on circuit-lib and only the CCL MPF/core artifacts it needs.
3. `zeroj-jmt-poseidon` may depend on circuit-lib and only the CCL JMT/core artifacts it needs.
4. Neither structure module depends on the other or reuses the other's profile class.
5. RocksDB dependencies remain confined to load/integration modules.
6. The root CCL version constraint still ensures both structures use `0.8.0-pre5-dev1`.

ZeroJ will not add a `zeroj-merkle` umbrella implementation JAR. The BOM provides version
alignment without pulling both implementations into an application. ZeroJ will also not create a
`zeroj-merkle-core` module initially: the project already has many artifacts, and the currently
shared circuit-level functionality has a natural home in `zeroj-circuit-lib`. A core module may
be proposed later only if a meaningful structure-neutral host API emerges and cannot fit an
existing module without creating a dependency cycle.

Discovery is handled with one Merkle/authenticated-state guide comparing MPF and JMT, not by
combining their code into one artifact.

### 10. Treat the operation and verification key as application policy

A valid Groth16 proof establishes only the statement encoded in its circuit. The on-chain
validator must bind:

- the expected operation primitive or approved verification-key identifier;
- the authoritative old/current root from datum or other authenticated state;
- the new root for transition operations;
- required application public inputs; and
- replay protection such as a transaction reference, version, epoch, or nullifier where needed.

A parameterized generic Groth16 verifier may serve several primitives, but it must not accept an
attacker-selected verification key. The application chooses from an explicit allowlist or embeds
the correct key in the validator parameters.

## Implementation plan

### Phase 0: Specifications and vectors

1. Freeze the module names, package hierarchy, and dependency rules from Section 9.
2. Freeze the final `zeroj-poseidon-mpf-v1` name and unchanged commitment vectors.
3. Freeze the `zeroj-poseidon-jmt-v1` domains, encodings, empty child, leaf commitment, branch
   commitment, key canonicality rule, and stable CCL format descriptor.
4. Record cross-language-friendly golden vectors for raw hashing, leaf commitments, every branch
   position, complete roots, object proofs, wire proofs, and negative mutations.
5. Record the input schemas and soundness statement for every P0/P1 primitive.
6. Assign versioned circuit/profile identifiers and manifest schemas.

Exit criterion: two independent host-side implementations or one implementation plus a simple
independent vector checker agree on all v1 vectors.

### Phase 1: Common CCL dev1 baseline

1. Change the root CCL pin to `0.8.0-pre5-dev1`.
2. Run dependency insight to prove one CCL version across all ZeroJ configurations.
3. Run all MPF unit, wire, root, RocksDB, and circuit tests.
4. Reopen and sample the preserved five-million-entry MPF database.
5. Migrate only the preserved benchmark manifest label from the unreleased `v2` alias to `v1`,
   with root/proof checks before and after.
6. Record the compatibility and relabelling result in ADR-0041's benchmark report without
   rewriting its original pre4 measurement provenance.

Exit criterion: the stored root and selected proofs are unchanged and all CCL dependencies resolve
to dev1, or the phase stops for a migration decision.

### Phase 2: Operation-specific MPF reads

1. Move `ZkMpf` and `ZkMpfProof` from `zeroj-circuit-lib` into the MPF module and the
   `com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit` package.
2. Move only genuinely structure-neutral Poseidon, binary-Merkle, canonical-field, nibble, and
   padding helpers into appropriate `zeroj-circuit-lib` packages. Keep all MPF node/proof semantics
   in `zeroj-mpf-poseidon`.
3. Implement `ZkMpfInclusion` and `ZkMpfNonInclusion` as separate public gadgets/templates.
4. Add CCL proof normalization, positive/negative vectors, malformed-proof tests, and differential
   checks against the existing `ZkMpf` result.
5. Benchmark S8/S9/S12 and any full-bound candidate on preserved real proofs.

Exit criterion: the new primitives accept every supported valid reference witness, reject all
mutations, preserve MPF v1 roots, demonstrate a material constraint/proving improvement, and leave
`zeroj-circuit-lib` with no CCL MPF/JMT dependency or structure-specific public class.

### Phase 3: MPF transitions

1. Implement `ZkMpfValueUpdate` first.
2. Specify and implement canonical `ZkMpfInsert` against CCL-generated before/after roots.
3. Specify `ZkMpfDelete` only after host canonicalization and collapse/merge cases have exhaustive
   vectors.
4. Add small state-machine/property tests that apply random operations both in CCL and in circuit
   witnesses and compare every root.

Exit criterion: old-root and new-root mutations, wrong operations, wrong old values, wrong keys,
and non-canonical rewrites are rejected.

### Phase 4: Poseidon JMT host profile

1. Add `zeroj-jmt-poseidon` under
   `com.bloxbean.cardano.zeroj.merkle.jmt.poseidon` with a stable `JmtProfile.custom(...)`, hash
   adapter, commitment scheme, proof codec integration, normalized witnesses, and fail-closed
   format descriptor.
2. Add in-memory and RocksDB tests for inclusion, both non-inclusion forms, version replay, reopen,
   historical proofs, rollback, pruning, profile mismatch, and crash recovery.
3. Confirm full-key leaf binding and reject proof-type confusion and malformed wire proofs.

Exit criterion: CCL object verification, CCL wire verification, an independent host verifier, and
all golden vectors agree on roots and proofs.

### Phase 5: Operation-specific JMT circuits

1. Implement and harden `ZkJmtInclusion`.
2. Implement the two non-inclusion circuits separately.
3. Implement `ZkJmtValueUpdate` and `ZkJmtInsert` with CCL before/after differential tests.
4. Keep tombstone semantics explicit and do not label a tombstone proof as non-inclusion.

Exit criterion: every primitive has statement documentation, constraint counts, adversarial tests,
R1CS fingerprints, and real CCL proof-to-witness tests.

### Phase 6: Scale and performance qualification

1. Preserve deterministic 10K and 100K smoke databases outside build directories.
2. Run 1M and 5M JMT loads with production RocksDB options and recorded batch/version policies.
3. Measure load/update/reopen/rollback/prune time, database growth, Java heap/RSS, native proof
   depth/bytes, normalization, witness, setup, prove, verify, and key storage.
4. Compare operation-specific MPF and JMT circuits using the same machine, prover backend, setup
   mode, public inputs, and security settings.
5. Run complete or defensibly bounded depth analysis before choosing release presets.

Exit criterion: published reproducible reports distinguish storage scale, proof depth, circuit
bound, prover cost, and on-chain verifier cost.

### Phase 7: Cardano and release gates

1. Export real proof/VK artifacts for every release template and test positive plus mutated inputs
   in the Julc Plutus V3 VM.
2. Bind operation/VK identifiers and root transitions in representative application validators.
3. Compare VM budgets against the selected network's current protocol limits and run Yaci plus a
   public target-network transaction before value-bearing use.
4. Complete independent circuit/commitment review and a production Groth16 ceremony for exact
   released fingerprints.
5. Publish compatibility, setup provenance, supported proof forms, and known limitations.

Exit criterion: no primitive is labelled production-ready solely because a local proof passed.

### Phase 8: Optional multiproofs and batches

Implement multipath and batch primitives only after single-operation circuits are stable. Measure
deduplicated-path witnesses against multiple independent proofs. Do not assume one batch circuit is
cheaper or operationally safer without data, and cap batch sizes in the circuit identifier.

## Verification and security requirements

Every primitive must have tests covering at least:

- valid proofs generated by the corresponding CCL structure;
- mutated root, key/path, value, sibling, node kind, prefix, validity flag, and operation;
- field alias/canonical-encoding boundaries;
- zero/empty values and maximum supported depth;
- too-deep witnesses and malformed/truncated/overlong proofs;
- padding as a true suffix rather than an arbitrary mask;
- proof-form confusion, especially inclusion versus non-inclusion;
- differential old/new roots for transition circuits; and
- application-level replay or statement-binding examples.

Circuit hints or witness-only normalization are never trusted for a security property. Every value
used to select a path, node type, prefix length, operation, or validity state must be constrained or
derived from constrained data.

## Consequences

### Positive

- New applications pay only for the authenticated-map operation they use.
- Circuit statements become smaller, easier to audit, and easier to benchmark independently.
- The full `ZkMpf` behavior remains available in its owning MPF module, while preview package
  layout is cleaned up before release.
- MPF-only applications do not resolve JMT APIs, and JMT-only applications do not resolve MPF APIs.
- Each structure has an independent audit/readiness boundary and can evolve without expanding the
  other artifact.
- Current MPF roots remain supported under the first published v1 profile name.
- MPF and JMT can coexist as complementary structures rather than forcing one global choice.
- JMT gains versioned off-chain state while its native proof-size disadvantage is hidden behind a
  constant-size Groth16 proof at the Cardano boundary.
- Shared Poseidon parameters and common helpers reduce duplication without conflating root formats.
- Transition circuits can let an untrusted operator propose state changes while Cardano verifies
  the old-root to new-root relation.

### Costs

- Each released circuit shape/public schema requires fingerprints, setup artifacts, verification
  keys, vectors, documentation, and lifecycle management.
- Applications must select and bind the correct operation/VK; a generic verifier alone is not
  sufficient policy.
- Multiple maximum-depth profiles complicate proving-service routing and artifact distribution.
- Insert/delete/batch transitions require substantially more canonical-structure testing than
  membership.
- JMT adds another persistent root universe and requires rebuilding data rather than converting an
  MPF root.
- Preview users must update imports when `ZkMpf` moves into the MPF package.
- Two structure artifacts and two load tools require coordinated documentation and BOM entries.
- CCL dev1 is a pre-release dependency and must later be replaced by a qualified stable release.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| A specialized primitive omits a necessary soundness check | Differential tests against CCL and the existing full MPF verifier; independent statement review |
| An application proves meaningless existential membership | Require statement documentation and examples binding key/value/nullifier/application context |
| Wrong verification key or operation accepted on-chain | Embed or explicitly allowlist VK identifiers and bind the operation in validator policy |
| MPF/JMT domain confusion | Structure-specific domains, persistent descriptors, golden vectors, and no root-conversion API |
| The unreleased `v2` label is mistaken for a supported legacy profile | Document the rename, migrate only benchmark metadata explicitly, and publish only v1 |
| CCL dev1 regresses the preserved MPF state | Mandatory five-million-entry reopen/root/proof gate before accepting the pin change |
| A small path-bound circuit fails on production data | Complete depth scan or maintained bound, fail-closed overflow, and optional full-bound fallback |
| Transition circuit disagrees with canonical host updates | Randomized state-machine testing against CCL before/after roots |
| JMT tombstones are mistaken for absence | Name and document tombstone update as inclusion; use a real non-inclusion primitive for absence |
| Benchmark setup keys escape into production | Label and isolate insecure artifacts; require exact-fingerprint ceremony provenance |
| Native JMT operational weaknesses are assumed solved by ZK | Retain CCL's single-writer, root/version authentication, durability, integrity, rollback, and pruning gates |

## Rejected alternatives

### Remove the full-semantics `ZkMpf` circuit entirely

Rejected because it remains a useful reference and supports combined MPF proof semantics that an
application may genuinely need. It is relocated, not preserved as a compatibility facade; new code
receives more focused choices.

### Put MPF and JMT implementations in one `zeroj-merkle` JAR

Rejected because it would force both CCL structures and both proof/commitment APIs onto every
consumer, blur incompatible root and security boundaries, and couple their release/readiness
status. Common documentation and BOM constraints provide discoverability without a monolithic
runtime artifact.

### Create `zeroj-merkle-core` immediately

Rejected for now because the shared functionality is circuit-level and already belongs in
`zeroj-circuit-lib`. Adding another mostly empty artifact would increase the module noise this
repository is trying to reduce. A later core module requires a demonstrated structure-neutral
host API and a clean dependency reason.

### Keep `ZkMpf` or add `ZkJmt` directly in `zeroj-circuit-lib`

Rejected because these classes encode CCL structure semantics, profile domains, proof forms, and
transition rules. Circuit-lib supplies their generic cryptographic building blocks but must not own
either authenticated structure.

### Put every MPF or JMT operation in one universal circuit

Rejected because a static circuit must constrain and often evaluate alternative proof forms. This
increases constraints, proving keys, proving latency, audit surface, and the chance that an unused
branch contains a soundness defect.

### Treat the same Poseidon parameters as one shared MPF/JMT root profile

Rejected because domain and structural ambiguity would make roots unsafe to interpret. Sharing a
hash primitive does not make different authenticated structures commitment-compatible.

### Publish the first supported MPF profile as `v2`

Rejected because the earlier strict adapter was an unversioned prototype, not a released v1
profile. ZeroJ is still pre-release and has no external application compatibility obligation. The
current commitment therefore becomes the first supported `zeroj-poseidon-mpf-v1` profile without
changing its cryptographic outputs.

### Keep CCL pre4 for MPF and load dev1 only for JMT in the same JVM

Rejected because the artifacts share coordinates and packages. A single root pin is reproducible
and avoids classpath-dependent behavior. A separately deployed JMT service is possible but is not
the architecture selected for this branch.

### Use CCL's classic JMT commitment directly inside the ZK circuit

Rejected for the new profile because it commits the radix-16 representation in a format optimized
for normal hashing rather than field-native circuit verification. It remains valid for classic
off-chain JMT deployments but produces a different root universe.

### Publish only one small-depth template

Rejected because observed depth is not a universal bound. Small profiles may be offered for low
latency only with explicit overflow handling or a full-bound fallback.

### Claim JMT physical deletion through tombstones

Rejected because a tombstone is still an included value. Native canonical deletion remains outside
CCL dev1 and outside this ADR's accepted JMT feature set.

## Final recommendation

Retain the full `ZkMpf` circuit inside `zeroj-mpf-poseidon` and publish the current Poseidon MPF
commitment as the first v1 profile. For new application designs, choose and compose the smallest
operation-specific primitive. Add JMT in the separate `zeroj-jmt-poseidon` artifact as a versioned
off-chain authenticated-state option using the same reviewed Poseidon parameter family but its own
v1 commitment profile. Keep structure-neutral helpers in `zeroj-circuit-lib`, RocksDB in the two
load modules, and use one CCL `0.8.0-pre5-dev1` baseline throughout this branch. Do not call either
structure or any new circuit production-ready until its operation-specific review, scale benchmark,
Cardano validation, and trusted-setup gates pass.

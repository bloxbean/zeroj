# ADR-0042: Operation-specific Poseidon MPF and JMT circuits

- **Status**: accepted; phases 0-6 implemented, Phase 7 local release gates implemented,
  external production gates open, optional Phase 8 deferred
- **Date**: 2026-08-02
- **Supersedes in part**: the CCL `0.8.0-pre4` dependency and pre-release MPF `v2` naming
  decisions in
  [ADR-0041](0041-poseidon-mpf-production-readiness-and-load-benchmark.md)
- **Keeps**: the full-semantics `ZkMpf` circuit capability and current Poseidon MPF commitment
  algorithm/root; preview package and module locations are not compatibility commitments
- **Introduces**: separate MPF/JMT Poseidon modules and operation-specific circuit families
- **Related**:
  [Poseidon MPF gadget design](circuit-annotation/zk-mpf-gadget.md),
  [five-million-entry MPF benchmark](../benchmarks/poseidon-mpf-5m-2026-08-02.md),
  [five-million-entry JMT benchmark](../benchmarks/poseidon-jmt-5m-2026-08-03.md), and
  [current practical large-state guide](../merkle/practical-large-state-guide.md)

## Context

ZeroJ currently exposes `ZkMpf`, a complete symbolic verifier for the ZeroJ Poseidon MPF
profile. It supports inclusion and supported exclusion paths while representing the different
CCL MPF proof node forms in one bounded circuit:

- branch, fork, neighboring-leaf, and padding steps;
- variable Patricia prefixes and skipped nibbles;
- dynamic key-path cursors and prefix/suffix packing;
- inclusion and exclusion selection; and
- leaf divergence and proof-shape checks.

This full-semantics design is useful and remains available, but it is expensive. The historical
pre-ADR-0042 S8 circuit had 17,399,380 constraints and took 213.826 seconds to prove. That result
is retained as compatibility/provenance evidence, not as the current recommended MPF circuit.

ADR-0042 now implements operation-specific MPF and JMT circuits. On the same development
machine, with fresh single-party benchmark-only setup material and three proof trials, the
current inclusion profiles measured:

| Structure/profile | Exact constraints | Setup | Median prove | Host verify | Proof |
|---|---:|---:|---:|---:|---:|
| MPF S8 | 50,768 | 2.349 s | 3.999 s | 115.6 ms | 192 B |
| MPF S9 | 56,635 | 2.421 s | 4.173 s | 119.2 ms | 192 B |
| MPF S12 | 74,236 | 2.961 s | 4.489 s | 117.8 ms | 192 B |
| JMT S8 | 10,069 | 1.142 s | 2.856 s | 114.0 ms | 192 B |
| JMT S10 | 12,063 | 1.172 s | 2.911 s | 113.3 ms | 192 B |
| JMT S12 | 14,057 | 1.306 s | 2.901 s | 114.4 ms | 192 B |
| JMT S64 | 65,901 | 2.947 s | 4.582 s | 115.2 ms | 192 B |

These are local feasibility measurements, not release SLAs. The exact R1CS digest, setup mode,
all trials, key size, heap/RSS, and artifact directory are retained in the preserved reports.
The earlier 25,730/186,394-constraint JMT prototype measurements are superseded by this matrix.

On 2026-08-04 the repository also moved from Julc `0.1.0-pre14` to published
`0.1.0-pre16`. Fresh on-chain tests passed positive proofs, malformed/field/arity/replay
rejections, authenticated MPF/JMT transitions, cross-structure substitution rejection, script
size gates, and the examples suite. The authenticated-state release identity now binds
`julc-0.1.0-pre16/plutus-v3`. Existing recorded Julc budgets and applied script bytes remain
historical pre14 measurements; deployment must regenerate and remeasure pre16 artifacts rather
than relabel them.

The durable JMT qualification loaded five million entries, generated real CCL object/wire proofs,
converted them into ZeroJ witnesses, and verified every selected circuit artifact in the Julc
Plutus V3 VM. The 32 native JMT proof samples were 2,744-3,161 bytes (2,881-byte median); these
bytes are private prover input. The Cardano-facing Groth16 proof remained 192 bytes, so native
JMT proof size does not expand the on-chain proof.

CCL `0.8.0-pre5` also changes the JMT decision materially. It provides a named custom
`JmtProfile` containing a format descriptor, hash function, commitment scheme, and proof codec.
It fixes proof-key binding and persistence/replay/rollback/pruning defects present before the
pre5 hardening work. The profile was first qualified on `0.8.0-pre5-dev1`; comparison with the
published pre5 tag found no changes in CCL's `verified-structures` subtree. Its production
qualification remains intentionally bounded to serialized
off-chain state with one logical writer, durable storage, and an application-authenticated
mapping between chain point, version, and root. See the
[CCL JMT audit](https://github.com/bloxbean/cardano-client-lib/blob/v0.8.0-pre5/verified-structures/jellyfish-merkle/docs/security-performance-audit.md)
and
[production-readiness gates](https://github.com/bloxbean/cardano-client-lib/blob/v0.8.0-pre5/verified-structures/jellyfish-merkle/adr/002-production-readiness-gates.md).

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

### 1. Use CCL `0.8.0-pre5` throughout this branch

The root `cclVersion` property is pinned to `0.8.0-pre5`. Every direct
`com.bloxbean.cardano:cardano-client-*` dependency resolves through that one root
property and the existing resolution rule. ZeroJ will not place pre4 MPF and pre5 JMT artifacts
on the same runtime classpath because they publish the same Maven coordinates and Java packages.

This supersedes ADR-0041's dependency-version decision. It does not change the existing Poseidon
MPF commitment algorithm/root, preserved five-million-entry database, benchmark methodology, or
production gates. Section 3 separately replaces the pre-release `v2` profile label with `v1`.

The original dev1 compatibility gate and the subsequent published-pre5 promotion gate:

1. ran the small MPF golden-root and wire-proof compatibility suites;
2. compared `v0.8.0-pre5-dev1...v0.8.0-pre5` and found no changed file below CCL's
   `verified-structures/` subtree;
3. reopened both preserved five-million-entry stores under published pre5 without changing their
   dev1 provenance manifests;
4. verified the recorded MPF root and 32 deterministic proofs, and generated/verified 32 JMT
   object and wire proofs against its recorded root; and
5. ran fresh roots, proof-wire, transitions, durability, malformed-proof, and Julc VM suites while
   confirming that all resolved CCL artifacts use pre5.

Source comparison found no intended MPF commitment/root-format change between these tags; the
RocksDB MPF difference is resource-lifecycle cleanup. The same checks remain mandatory for future
dependency changes because persisted roots are production data, not an assumption. Any root or
wire-proof drift requires a separate migration ADR.

The non-published load tools retain the original CCL version as dataset provenance. They accept
exactly `0.8.0-pre5-dev1` stores when the running build is `0.8.0-pre5`; the exception is one-way
and does not accept pre4, a different development build, or any future CCL release. Every later
dependency change must repeat this qualification or provide an explicit migration.

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
| `ZkMpfNonInclusionEmpty` | A key path reaches an authenticated empty child under `root` | `root` | query path and missing-branch proof | P0 |
| `ZkMpfNonInclusionDifferentLeaf` | A different authenticated leaf proves the query path absent | `root` | query path, conflicting leaf, divergence data and path | P0 |
| `ZkMpfValueUpdate` | Replacing an existing value transforms `oldRoot` into `newRoot` | `oldRoot`, `newRoot` | key path, old/new values, authentication path | P1 |
| `ZkMpfInsert` | A previously absent key is inserted canonically, producing `newRoot` | `oldRoot`, `newRoot` | key/value, exclusion witness, structural rewrite witness | P1 |
| `ZkMpfDelete` | An existing key is removed and the Patricia path is canonically normalized | `oldRoot`, `newRoot` | key/value, inclusion witness, merge/rewrite witness | P2 |
| `ZkMpfMultiInclusion` | Several entries are included under one root | `root` | entries and a deduplicated multipath | P2 |
| `ZkMpfBatchTransition` | An ordered batch of supported operations transforms one root into another | `oldRoot`, `newRoot`, optional batch commitment | operations and shared transition witness | P3 |

`ZkMpfValueUpdate` is the first transition primitive because it can normally reuse one
authentication path. Insert and delete must reproduce CCL's canonical Patricia restructuring;
they are not implemented by merely swapping a leaf digest.

The implemented initial catalog contains the three read circuits, value update, and two distinct
insertion templates: `insert-empty` and `insert-different-leaf`. `ZkMpfInsert` is a source-level
facade over those insertion gadgets; there is intentionally no generic
`zeroj-mpf-v1-insert-sN-p2` R1CS. Physical delete remains a P2 follow-up because canonical branch
collapse needs additional authenticated rewrite data not present in an ordinary inclusion path.
Multiproofs and batches remain under the optional Phase 8 decision below.

The two non-inclusion shapes are distinct circuits so an attacker cannot select
the terminal soundness rule through a witness flag. A convenience Java facade
may dispatch after fail-closed host decoding, but there is no universal
`ZkMpfNonInclusion` R1CS. Both circuits fail closed for any CCL proof form whose
terminal commitment is not fully authenticated by the normalized witness.
Unsupported forms are not accepted merely to offer one broad API.

### 6. Provide operation-specific JMT primitives

JMT proof forms are simpler but remain distinct statements:

| Primitive | Statement | Minimum public inputs in the standalone template | Private witness | Priority |
|---|---|---|---|---|
| `ZkJmtInclusion` | A full key hash maps to a value hash under `root` | `root` | key hash/path, value hash, four siblings per valid level | P0 |
| `ZkJmtNonInclusionEmpty` | The queried path reaches an authenticated empty child | `root` | query key/path and branch siblings | P1 |
| `ZkJmtNonInclusionDifferentLeaf` | The queried key diverges from an authenticated conflicting leaf | `root` | query key, conflicting leaf, divergence data, siblings | P1 |
| `ZkJmtValueUpdate` | Updating an existing leaf transforms `oldRoot` into `newRoot` | `oldRoot`, `newRoot` | key, old/new values and one path | P1 |
| `ZkJmtInsert` | A valid non-inclusion becomes a canonical included leaf | `oldRoot`, `newRoot` | key/value, non-inclusion proof and rewrite witness | P1 |
| `ZkJmtTombstoneUpdate` | A live value is replaced with the application-selected tombstone commitment | `oldRoot`, `newRoot`, `jmt_tombstone_value_hash` | key, live value and path | P2 |
| `ZkJmtMultiInclusion` | Several entries are included under one root | `root` | entries and deduplicated multipath | P2 |
| `ZkJmtBatchTransition` | An ordered batch transforms one version root into the next | `oldRoot`, `newRoot`, optional batch/version commitment | operations and shared transition witness | P3 |

`ZkJmtDelete` is deliberately not promised by this ADR. CCL `0.8.0-pre5` has no native key deletion;
storing a tombstone still proves inclusion of that tombstone. A future physical/canonical delete
requires CCL storage semantics, proof semantics, circuit semantics, pruning behavior, and test
vectors to be specified together in a separate ADR.

The implemented initial catalog contains all three reads, value update, both insertion shapes,
and public-tombstone update. `ZkJmtInsert` is likewise a source-level facade over
`insert-empty` and `insert-different-leaf`; no generic `...-insert-sN-p2` template exists.

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

Implemented identifier examples are:

```text
zeroj-mpf-v1-inclusion-s12-p1
zeroj-jmt-v1-inclusion-s8-p1
zeroj-jmt-v1-inclusion-s64-p1
zeroj-jmt-v1-value-update-s64-p2
```

The naming format is frozen by the canonical circuit manifest rather than inferred from class
names. A witness deeper than the selected bound fails before proving; it is never truncated.

The measured five-million-entry MPF reached S9: S8 covered 4,999,782 entries and missed 218;
S9 covered the complete measured root. The measured five-million-entry JMT reached S12: S8
covered 4,987,028 entries, S10 missed 32, and S12 covered all entries. These are dataset results,
not universal bounds. Applications may route common paths to S8 and overflow to a larger profile;
MPF S12 provides measured margin, while JMT S64 is the format-maximum fallback. A deployment that
requires one key/VK and cannot route must select a bound justified for its own dataset, or use the
format maximum.

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
6. The root CCL version constraint still ensures both structures use `0.8.0-pre5`.

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

Implementation status: complete after adversarial re-review. The frozen corpus now includes
literal/cross-checked MPF wires, all pre5 JMT proof forms, neighbor metadata, a single-neighbor
case, a valid zero-step root-leaf exclusion, manifest canonical bytes/hash, and depth-gap,
proof-form, canonical-CBOR, and resource-bound regressions.

1. Freeze the module names, package hierarchy, and dependency rules from Section 9.
2. Freeze the final `zeroj-poseidon-mpf-v1` name and unchanged commitment vectors.
3. Freeze the `zeroj-poseidon-jmt-v1` domains, encodings, empty child, leaf commitment, branch
   commitment, key canonicality rule, and stable CCL format descriptor.
4. Record cross-language-friendly golden vectors for raw hashing, leaf commitments, every branch
   position, complete roots, object proofs, wire proofs, and negative mutations. The commitment
   vectors and MPF fixtures form Phase 0A. CCL JMT object/wire and persistence vectors form Phase
   0B and close immediately after Phase 1 installs the required pre5 API; this explicit
   prerequisite avoids pretending pre4 can generate pre5 JMT fixtures.
5. Record the input schemas and soundness statement for every P0/P1 primitive.
6. Assign versioned circuit/profile identifiers and manifest schemas.

Exit criterion: two independent host-side implementations or one implementation plus a simple
independent vector checker agree on all v1 vectors. Under this plan, Phase 0 remained open across
the narrow Phase 1 dependency prerequisite and closed only after the Phase 0B CCL JMT corpus
passed; that criterion is now satisfied.

### Phase 1: Common CCL pre5 baseline

Implementation status: complete. The work was first qualified on `0.8.0-pre5-dev1` and promoted
to published `0.8.0-pre5` after proving the verified-structures source subtree unchanged. All
resolved CCL artifacts now use pre5. The preserved five-million-entry MPF root and sampled proofs
remained unchanged across the explicit profile-label migration and release promotion; the preserved
JMT root and 32 sampled object/wire proofs also passed under pre5.

1. Change the root CCL pin to `0.8.0-pre5`.
2. Run dependency insight to prove one CCL version across all ZeroJ configurations.
3. Run all MPF unit, wire, root, RocksDB, and circuit tests.
4. Reopen and sample the preserved five-million-entry MPF database.
5. Migrate only the preserved benchmark manifest label from the unreleased `v2` alias to `v1`,
   with root/proof checks before and after.
6. Record the compatibility and relabelling result in ADR-0041's benchmark report without
   rewriting its original pre4 measurement provenance.

Exit criterion: the stored roots and selected proofs are unchanged and all CCL dependencies resolve
to published pre5, or the phase stops for a migration decision.

### Phase 2: Operation-specific MPF reads

Implementation status: complete. The full-semantics classes moved into the MPF module; the three
read forms have separate fail-closed witnesses/templates, randomized and adversarial tests, pinned
R1CS identities, and real CCL differential checks. Current inclusion profiles are 50,768
constraints at S8, 56,635 at S9, and 74,236 at S12.

1. Move `ZkMpf` and `ZkMpfProof` from `zeroj-circuit-lib` into the MPF module and the
   `com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit` package.
2. Move only genuinely structure-neutral Poseidon, binary-Merkle, canonical-field, nibble, and
   padding helpers into appropriate `zeroj-circuit-lib` packages. Keep all MPF node/proof semantics
   in `zeroj-mpf-poseidon`.
3. Implement `ZkMpfInclusion`, `ZkMpfNonInclusionEmpty`, and
   `ZkMpfNonInclusionDifferentLeaf` as separate public gadgets/templates.
4. Add CCL proof normalization, positive/negative vectors, malformed-proof tests, and differential
   checks against the existing `ZkMpf` result.
5. Benchmark S8/S9/S12 and any full-bound candidate on preserved real proofs.

Exit criterion: the new primitives accept every supported valid reference witness, reject all
mutations, preserve MPF v1 roots, demonstrate a material constraint/proving improvement, and leave
`zeroj-circuit-lib` with no CCL MPF/JMT dependency or structure-specific public class.

### Phase 3: MPF transitions

Implementation status: complete for the accepted P1 single-operation scope. Value update and the
two canonical insertion shapes match CCL before/after roots under randomized state-machine and
mutation tests. `ZkMpfInsert` dispatches to the two shape-specific gadgets. Physical delete is not
misrepresented as a zero terminal: canonical Patricia collapse remains the explicitly deferred P2
follow-up described in Section 5.

1. Implement `ZkMpfValueUpdate` first.
2. Specify and implement canonical `ZkMpfInsert` against CCL-generated before/after roots.
3. Specify `ZkMpfDelete` only after host canonicalization and collapse/merge cases have exhaustive
   vectors.
4. Add small state-machine/property tests that apply random operations both in CCL and in circuit
   witnesses and compare every root.

Exit criterion: old-root and new-root mutations, wrong operations, wrong old values, wrong keys,
and non-canonical rewrites are rejected.

### Phase 4: Poseidon JMT host profile

Implementation status: complete. The pre5 custom profile, full-key leaf binding, prefix-independent
radix-16 commitment, CCL object/wire bridge, strict reference verifier, durable RocksDB facade,
profile manifest, rollback/pruning policy, in-flight crash recovery, and golden corpus are present.
The durable store enforces one logical writer and fails closed on foreign or ahead manifests.

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

Implementation status: complete for the catalog promised by Section 6: inclusion, both
non-inclusion forms, value update, both insertion forms, and tombstone update. Tests cover real CCL
proofs, randomized deep insertions, S64 padding/boundaries, field aliases, proof-form confusion,
old/new-root mutations, and the exact public tombstone binding. JMT inclusion is 10,069 constraints
at S8 and 65,901 at S64.

1. Implement and harden `ZkJmtInclusion`.
2. Implement the two non-inclusion circuits separately.
3. Implement `ZkJmtValueUpdate` and `ZkJmtInsert` with CCL before/after differential tests.
4. Keep tombstone semantics explicit and do not label a tombstone proof as non-inclusion.

Exit criterion: every primitive has statement documentation, constraint counts, adversarial tests,
R1CS fingerprints, and real CCL proof-to-witness tests.

### Phase 6: Scale and performance qualification

Implementation status: complete for local qualification. Preserved MPF and JMT databases, exact
five-million-key depth censuses, native proof samples, fixed-heap/RSS telemetry, update/rollback/
prune timing, exact R1CS/key identities, three-trial proving matrices, and strict Cardano artifact
bundles are recorded. The results establish local scale/correctness evidence, not a service SLA.

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

Implementation status: local engineering gates complete; external production gates open. All
seven selected inclusion bundles pass strict manifest/file/path/VK/public-input checks, positive
Julc VM verification, and mutated-root rejection. A representative state-transition validator
binds the authoritative datum root/version, continuing state token/value/address, signer, release
ID, new root, and operation-specific VK. Real MPF and JMT value-update proofs pass end to end and
cross-structure/key/manifest substitutions fail. Release identity also binds an audited unapplied
validator digest, compiler profile, exact circuit manifest, policy/token/signer, and one-shot token
genesis attestation; the Cardano V3 script hash is derived internally and cross-checked with CCL.
The independent Python R1CS checker agrees with the Java canonical digest and rejects tampering.

Yaci/public-network execution, comparison with the protocol parameters at deployment time,
external cryptographic review, and an exact-fingerprint multi-party ceremony require external
infrastructure and governance. They were not fabricated or marked complete. Consequently all
generated bundles remain `productionApproved=false` and mainnet manifest creation fails closed.

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

Implementation status: deliberately deferred, as allowed by this optional phase. CCL pre5 exposes
the single-key proof APIs qualified here but no frozen cross-structure multiproof contract that can
serve as an independent host oracle. Inventing a ZeroJ-only multipath format in this ADR would add
a new commitment/proof protocol after the single-operation security boundary was frozen. A future
ADR must specify bounded batch size, duplicate-key/order semantics, path deduplication, transition
atomicity, CCL interoperability, vectors, and whether several independent 192-byte proofs are
actually worse for the target application.

That follow-up is now specified by
[ADR-0043](0043-bounded-multiproofs-batch-transitions-and-mpf-deletion.md), with the host-side
contract separated into its
[CCL handoff companion](0043-bounded-multiproofs-batch-transitions-and-mpf-deletion-ccl.md).

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
- Every later CCL version requires another source/behavior/store compatibility gate or migration.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| A specialized primitive omits a necessary soundness check | Differential tests against CCL and the existing full MPF verifier; independent statement review |
| An application proves meaningless existential membership | Require statement documentation and examples binding key/value/nullifier/application context |
| Wrong verification key or operation accepted on-chain | Embed or explicitly allowlist VK identifiers and bind the operation in validator policy |
| MPF/JMT domain confusion | Structure-specific domains, persistent descriptors, golden vectors, and no root-conversion API |
| The unreleased `v2` label is mistaken for a supported legacy profile | Document the rename, migrate only benchmark metadata explicitly, and publish only v1 |
| A CCL upgrade regresses preserved MPF/JMT state | Mandatory five-million-entry reopen/root/proof gate before accepting the pin change; only the source-identical dev1-to-pre5 promotion is allowlisted |
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
CCL pre5 and outside this ADR's accepted JMT feature set.

## Final recommendation

Retain the full `ZkMpf` circuit inside `zeroj-mpf-poseidon` and publish the current Poseidon MPF
commitment as the first v1 profile. For new application designs, choose and compose the smallest
operation-specific primitive. Add JMT in the separate `zeroj-jmt-poseidon` artifact as a versioned
off-chain authenticated-state option using the same reviewed Poseidon parameter family but its own
v1 commitment profile. Keep structure-neutral helpers in `zeroj-circuit-lib`, RocksDB in the two
load modules, and use one CCL `0.8.0-pre5` baseline throughout this branch. Do not call either
structure or any new circuit production-ready until external operation-specific review,
exact-fingerprint production setup, Yaci/current-protocol-budget validation, and public target-
network transaction gates pass. Local scale, proof, artifact, and Julc VM qualification is
complete and is evidence for those gates, not a substitute for them.

# ADR: Symbolic MPF Gadget for Poseidon-Rooted Cardano State

## Status

Implemented for off-chain Poseidon MPF adapters, codec, symbolic inclusion,
conservative symbolic exclusion, annotated example coverage, and a standalone
witness-level usecase. Groth16/Yaci full-stack MPF proving remains follow-up
work because the first symbolic verifier is constraint-heavy.

## Date

2026-05-18

## Vision

ZeroJ should let Java developers prove statements about large Cardano-style
state commitments without revealing the full lookup proof, key, or value to the
validator.

The intended developer experience is:

```java
@ZKCircuit(name = "PrivateRegistryMembership", version = 1)
public final class PrivateRegistryMembership {
    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    @CircuitParam("MAX_STEPS")
    private final int maxSteps;
    @CircuitParam("MAX_FORK_PREFIX_CHUNKS")
    private final int maxForkPrefixChunks;

    public PrivateRegistryMembership(
            @CircuitParam("MAX_STEPS") int maxSteps,
            @CircuitParam("MAX_FORK_PREFIX_CHUNKS") int maxForkPrefixChunks) {
        this.maxSteps = maxSteps;
        this.maxForkPrefixChunks = maxForkPrefixChunks;
    }

    @Prove
    public void prove(
            ZkContext zk,
            @Public ZkField registryRoot,
            @Public ZkField keyPathNullifier,
            @Secret @FixedSize(64) @UInt(bits = 4) ZkArray<ZkUInt> keyPath,
            @Secret ZkField valueCommitment,
            @Secret @FixedSize(param = "MAX_STEPS") @UInt(bits = 2) ZkArray<ZkUInt> stepKind,
            @Secret @FixedSize(param = "MAX_STEPS") @UInt(bits = 8) ZkArray<ZkUInt> stepSkip,
            @Secret @FixedSize(param = "MAX_STEPS", inner = 4) ZkArray<ZkArray<ZkField>> neighbors,
            @Secret @FixedSize(param = "MAX_STEPS") @UInt(bits = 4) ZkArray<ZkUInt> neighborNibble,
            @Secret @FixedSize(param = "MAX_STEPS") @UInt(bits = 8) ZkArray<ZkUInt> forkPrefixLength,
            @Secret @FixedSize(param = "MAX_STEPS", innerParam = "MAX_FORK_PREFIX_CHUNKS") ZkArray<ZkArray<ZkField>> forkPrefixChunks,
            @Secret @FixedSize(param = "MAX_STEPS") ZkArray<ZkField> forkRoot,
            @Secret @FixedSize(param = "MAX_STEPS", inner = 64) @UInt(bits = 4) ZkArray<ZkArray<ZkUInt>> leafKeyPath,
            @Secret @FixedSize(param = "MAX_STEPS") ZkArray<ZkField> leafValueDigest,
            @Secret @FixedSize(param = "MAX_STEPS") ZkArray<ZkBool> valid) {

        ZkMpfProof proof = ZkMpfProof.fromArrays(
                stepKind, stepSkip, neighbors, neighborNibble,
                forkPrefixLength, forkPrefixChunks, forkRoot,
                leafKeyPath, leafValueDigest, valid);

        ZkMpf.verifyInclusionPoseidon(
                zk, POSEIDON, keyPath, valueCommitment, registryRoot, proof);

        ZkMpf.keyPathNullifier(zk, POSEIDON, keyPath).assertEqual(keyPathNullifier);
    }
}
```

The public validator sees only:

```text
Groth16 proof + public inputs chosen by the application
```

For a private registry that may be only `(registryRoot, keyPathNullifier)`.
For a public proof it may expose the key path nibbles or a path commitment,
depending on the application. The MPF proof itself remains a witness inside the
circuit.

The core MPF gadget works over `keyPath`, the nibble array obtained from
CCL's `hashFn.digest(key)`, not raw key bytes. This avoids unsafe 255-bit field
byte decomposition in the circuit and exactly matches the path consumed by CCL
`WireProof`. Applications that need to prove how raw key bytes map to
`keyPath` can add a separate byte/key binding gadget. The v1 usecase uses
field-native registry identifiers and publishes a nullifier/commitment of the
CCL key path.

## Context

Cardano Client Lib (CCL) provides Merkle Patricia Forestry (MPF) with:

- `MpfTrie`
- pluggable `HashFunction`
- pluggable `CommitmentScheme`
- wire proofs consumed by `ProofVerifier`

The default Cardano path uses Blake2b-256 and Aiken's native
`aiken-lang/merkle-patricia-forestry` verifier. That path is the right tool for
normal public inclusion or exclusion checks.

ZeroJ needs a separate path for:

- private registry membership/non-membership
- Java L2 or rollup state proofs
- proof compression for many off-chain MPF reads
- applications that already use CCL MPF off-chain but want a succinct Cardano
  Groth16 verifier on-chain

This ADR defines a Poseidon-rooted MPF path that is compatible with CCL's MPF
structure, but not interchangeable with the default Blake2b/Aiken commitment.

CCL itself must not be changed for this feature. ZeroJ integrates with CCL
through public constructors and proof APIs.

## Source Of Truth: CCL MPF Wire Semantics

The circuit must match CCL's wire proof recomputation, not an independent MPF
interpretation.

The local CCL checkout is at:

```text
/Users/satya/work/bloxbean/cardano-client-lib
```

The relevant CCL classes are:

- `com.bloxbean.cardano.vds.mpf.MpfTrie`
- `com.bloxbean.cardano.vds.mpf.commitment.CommitmentScheme`
- `com.bloxbean.cardano.vds.mpf.commitment.MpfCommitmentScheme`
- `com.bloxbean.cardano.vds.mpf.proof.ProofSerializer`
- `com.bloxbean.cardano.vds.mpf.proof.ProofVerifier`
- `com.bloxbean.cardano.vds.mpf.proof.WireProof`

Important CCL facts the ZeroJ implementation must preserve:

- `MpfTrie.put(key, value)` stores the path `hashFn.digest(key)`.
- `MpfTrie.getProofWire(key)` generates a proof for `hashFn.digest(key)`.
- `ProofVerifier.verify(root, key, value, including, proof, hashFn,
  commitments)` recomputes the path by calling `hashFn.digest(key)`.
- `WireProof.computeRoot(...)` recursively recomputes the root.
- Branch proof steps carry four neighbor commitments. The neighbor order is the
  CCL order produced by `ProofSerializer.computeNeighbors(...)`, from the
  largest opposite subtree down to the local sibling.
- Branch recomputation uses `hashFn.digest(prefixBytes || binarySubRoot)`.
- Fork recomputation has two CCL cases:
  - terminal fork non-inclusion returns `fork.root()` directly after checking
    that the query nibble diverges from the fork neighbor nibble; this CCL wire
    shape is not accepted by the v1 circuit because `fork.root()` is not
    authenticated by any in-circuit hash relation;
  - non-terminal fork roll-up hashes `forkPrefixBytes || forkRoot` before
    placing the fork neighbor into a sparse branch.
- Leaf recomputation uses `commitments.commitLeaf(suffix, valueHash)`.
- Inclusion has an implicit terminal leaf when the proof step list is
  exhausted. CCL does not require a terminal `LeafStep` for normal inclusion.
  An empty proof is valid for a single-leaf inclusion.
- Empty-trie exclusion is represented by an empty proof whose recomputed root is
  `null`, normalized by `ProofVerifier` to `commitments.nullHash()`.
- `LeafStep` is a terminal step only for the different-leaf non-inclusion case.
- CCL's default `MpfCommitmentScheme.commitLeaf(...)` uses MPF odd/even suffix
  byte encoding, including the empty-suffix marker. The Poseidon ZK path does
  not reuse that default byte encoding because some valid suffixes produce
  32-byte chunks that are not scalar-field elements. Instead,
  `PoseidonMpfCommitmentScheme.commitLeaf(...)` defines a custom
  circuit-friendly leaf commitment through CCL's public `CommitmentScheme`
  interface.
- Branch `branchValueHash` is outside the v1 circuit-compatible profile. CCL's
  default MPF mode for fixed-length hashed keys does not need branch values.
  The codec must reject proofs that contain branch value hashes.
- `CommitmentScheme` customizes node commitment behavior, but it does not by
  itself define all proof recomputation. `WireProof.computeRoot(...)` is the
  complete behavior to mirror.

Therefore the first implementation milestone is a CCL-compatible Poseidon MPF
reference and test-vector suite. Circuit code starts only after those vectors
are stable.

## Key Distinction

There are two different MPF commitment universes:

| Path | Hash | Verifier | Interchangeable? |
|------|------|----------|------------------|
| Native Cardano MPF | Blake2b-256 | Aiken MPF verifier | Compatible with existing Aiken MPF roots |
| ZeroJ ZK MPF | BLS12-381 Poseidon byte digest | Groth16 BLS12-381 verifier | Not compatible with Blake2b/Aiken roots |

The ZK path does not execute MPF logic on-chain. A proof-only test can use the
generic `Groth16BLS12381Verifier`. A real application validator should call the
reusable `Groth16BLS12381Lib.verify(...)` helper and then apply domain logic
such as registry-root matching and nullifier uniqueness in the same validator.

## Decision

Add a Poseidon-rooted MPF stack in ZeroJ:

1. **`zeroj-mpf-poseidon` module**
   - Provides a CCL `HashFunction` backed by BLS12-381 Poseidon.
   - Provides a CCL `CommitmentScheme` compatible with the Poseidon digest.
   - Provides `PoseidonMpfTrie` convenience builders around CCL `MpfTrie`.
   - Provides `PoseidonMpfCodec` to convert CCL wire proofs into symbolic
     witness inputs.
   - Provides `PoseidonMpfReference` that calls or mirrors CCL
     `ProofVerifier` behavior with the Poseidon adapters.

2. **`ZkMpf` gadget in `zeroj-circuit-lib`**
   - Verifies Poseidon-rooted MPF inclusion and conservative exclusion proofs
     over `CurveId.BLS12_381`.
   - Uses explicit `PoseidonParams`.
   - Rejects mismatched circuit fields through the same field-guard pattern as
     `ZkPoseidon` and `ZkMerkle`.

3. **`ZkMpfProof` ergonomic wrapper in `zeroj-circuit-lib` or annotation API**
   - Does not extend `ZkArray`; `ZkArray` is final today.
   - Wraps arrays already supported by the annotation processor.
   - Keeps v1 implementation compatible with existing generated-code support.

4. **Annotated examples and witness-level usecase**
   - Unit and integration tests live in ZeroJ.
   - A standalone demonstration lives in `zeroj-usecases`, building the CCL
     registry, witness arrays, and BLS12-381 circuit witness. Proof generation
     and Yaci submission are follow-up work once constraint cost is reduced.

## Non-Goals

- No CCL source changes.
- No in-circuit Blake2b.
- No conversion between Blake2b MPF roots and Poseidon MPF roots.
- No native Aiken verifier for Poseidon MPF.
- No variable-length symbolic proof inputs. Proof length is bounded by
  `@CircuitParam`.
- No batched MPF reads in v1. Batching is a follow-up once single-key proofs are
  correct.
- No state-transition proof in v1. `(rootBefore, rootAfter, key, oldValue,
  newValue)` is a follow-up built on the same proof primitives.

## Poseidon Digest Contract

CCL's `HashFunction.digest(byte[])` accepts arbitrary bytes. Poseidon accepts
field elements. The ZeroJ adapter must define a canonical byte-to-field digest
that is efficient to reproduce in-circuit for the byte strings that CCL
`WireProof` hashes directly: branch prefixes, fork prefixes, and child/root
commitments. Leaf commitments are handled by `PoseidonMpfCommitmentScheme`
instead of by CCL's default HP-byte leaf encoding.

Define `PoseidonMpfHash.digest(bytes)` as a fixed-width, padded digest:

```text
chunks = canonical 32-byte-aligned chunks:
  if len(bytes) % 32 != 0:
      chunk0 = first len(bytes) % 32 bytes as an unsigned integer
      remaining chunks are 32-byte unsigned integers
  else:
      all chunks are 32-byte unsigned integers
fields = [domain, byteLength, chunk0, chunk1, chunk2]
missing chunks are zero
digest = PoseidonN_BLS12_381(fields)
output = digest encoded as exactly 32 big-endian bytes
```

Rules:

- `domain` is a fixed field constant for MPF byte digests.
- `byteLength` is included to avoid chunk-padding ambiguity.
- v1 supports at most three digest chunks, enough for all CCL MPF internal
  byte strings over a 64-nibble path: pair hashes (`64` bytes), prefix+root
  hashes (`32..96` bytes), and field-native key/value examples.
- Every 32-byte chunk must be the canonical unsigned big-endian encoding of a
  BLS12-381 scalar-field element. The adapter rejects byte strings whose
  32-byte chunks are not `< field modulus`.
- The first short chunk, when present, is always `< 2^248` and therefore is
  safely inside the scalar field.
- Output bytes must be exactly 32 bytes, unsigned, big-endian.
- The in-circuit gadget operates on the field value of the digest and avoids
  decomposing a 255-bit field element into bytes. Whenever CCL concatenates a
  prefix with a digest, the circuit mirrors the same three padded chunks before
  calling one fixed-arity `PoseidonN`.
- The generic digest must not be used for CCL default leaf HP byte strings in
  the Poseidon profile. Leaf commitments use the custom leaf contract below.
- The same implementation is used by:
  - CCL `HashFunction`
  - off-chain test vectors
  - `ZkMpf` circuit byte-digest helper

This digest contract is a ZeroJ commitment. It is not Aiken MPF's Blake2b
digest and must be documented as a separate commitment scheme.

Define `PoseidonMpfCommitmentScheme.commitLeaf(suffix, valueHash)` as:

```text
suffixNibbles = suffix.getNibbles()
suffixChunks = pack suffix nibbles, 31 bytes per chunk, each nibble in [0, 15]
leaf = PoseidonN_BLS12_381(
    DOMAIN_MPF_LEAF,
    suffixLengthInNibbles,
    suffixChunk0,
    suffixChunk1,
    suffixChunk2,
    valueHashField)
```

This deliberately does not match Aiken/native MPF leaf bytes. It is still
CCL-compatible for the Poseidon profile because both CCL `MpfTrie` and CCL
`ProofVerifier` receive the same custom `PoseidonMpfCommitmentScheme`.

Define `PoseidonMpfCommitmentScheme.commitBranch(prefix, children, valueHash)`
as the CCL `WireProof` branch behavior for the Poseidon profile:

```text
subRoot = binary Merkle root over the 16 child commitments using
          PoseidonMpfHash.digest(leftDigest || rightDigest)
branch = PoseidonMpfHash.digest(prefixNibbleBytes || subRootDigest)
```

`valueHash` in branch commitments is unsupported in v1; the codec rejects any
proof carrying branch value hashes.

For v1 circuit-compatible tries, original keys and values should be encoded as
one or more canonical scalar-field byte chunks. The MPF gadget itself accepts
the resulting `keyPath` nibbles and `valueCommitment`; raw byte binding is
separate application logic.

## Proof Input Shape

The originally proposed `ZkMpfProof extends ZkArray<ZkMpfStep>` is rejected.
It is not compatible with current ZeroJ because `ZkArray` is final and the
annotation processor currently binds only:

- `ZkField`
- `ZkBool`
- `ZkUInt`
- `ZkArray<ZkField>`
- `ZkArray<ZkBool>`
- `ZkArray<ZkUInt>`
- rectangular `ZkArray<ZkArray<...>>` for those scalar leaves

The v1 proof shape uses supported arrays:

```java
public final class ZkMpfProof implements ZkValue {
    private final ZkArray<ZkUInt> kind;              // bits=2
    private final ZkArray<ZkUInt> skip;              // bits=8 or MAX_SKIP bits
    private final ZkArray<ZkArray<ZkField>> neighbors; // [MAX_STEPS][4]
    private final ZkArray<ZkUInt> neighborNibble;    // bits=4, fork/leaf divergent nibble
    private final ZkArray<ZkUInt> forkPrefixLength;  // bytes in fork prefix
    private final ZkArray<ZkArray<ZkField>> forkPrefixChunks;
    private final ZkArray<ZkField> forkRoot;
    private final ZkArray<ZkArray<ZkUInt>> leafKeyPath;
    private final ZkArray<ZkField> leafValueDigest;
    private final ZkArray<ZkBool> valid;

    public static ZkMpfProof fromArrays(...);
}
```

The generated annotated circuit declares these arrays directly. Application
code wraps them immediately with `ZkMpfProof.fromArrays(...)`.

Use explicit annotation names for codec-facing arrays. The annotation processor
singularizes array names by default, so generated examples should prefer:

```java
@Secret(name = "mpf_kind")
@Secret(name = "mpf_neighbor")
@Secret(name = "mpf_fork_prefix")
```

`ZkMpfProof` must implement `signals()` by concatenating the wrapped arrays and
`assertWellFormed()` by delegating to every wrapped array.

Future work may add true composite symbolic inputs to the annotation processor,
but the MPF v1 should not depend on that larger compiler feature.

## Step Encoding

Each proof slot is one of:

| Kind | Meaning | Fields used |
|-----:|---------|-------------|
| `0` | Branch | `skip`, `neighbors[4]` |
| `1` | Fork | `skip`, `neighborNibble`, `forkPrefixLength`, `forkPrefixChunks`, `forkRoot` |
| `2` | Leaf | `skip`, `leafKeyPath[64]`, `leafValueDigest` |
| `3` | Padding | none; all payload fields must be zero or ignored |

Circuit constraints:

- `valid[i + 1] => valid[i]`.
- `valid[i] <=> kind[i] != 3`, except an all-padding proof is allowed for the
  two CCL empty-step cases: single-leaf inclusion and empty-trie exclusion.
- `kind` is constrained to two bits and must be one of `0..3`.
- `neighborNibble` is constrained to four bits.
- `skip` is constrained to the configured maximum.
- The cumulative cursor must stay within the digest path length:
  `cursor + skip + 1 <= 64` for valid branch/fork/leaf steps.
- Padding steps do not affect the accumulator.
- Inclusion termination is implicit when the valid step suffix is exhausted:
  commit the remaining key-path suffix with `valueCommitment`, exactly as CCL
  `WireProof.computeRoot(...)` does.
- Exclusion termination supports missing-branch, different-leaf, and empty-tree
  cases. CCL terminal fork exclusion is rejected in v1 because the terminal
  `forkRoot` payload is not authenticated by an in-circuit hash relation.
- The circuit must reject a proof that contains valid steps after padding.
- The query child nibble is always derived from `keyPath` at
  `cursor + skip`; it is not witness-provided.
- A non-terminal fork or different-leaf terminal step must prove the neighbor
  nibble differs from the query nibble. Terminal fork exclusion steps are
  rejected.
- A different-leaf terminal step derives the neighbor suffix from
  `leafKeyPath`, checks that it shares the already-consumed prefix with
  `keyPath`, and checks that it diverges at the terminal nibble. It must not
  use an opaque field in place of the neighbor path.
- Invalid slots must have zero payloads in the codec output; the circuit ignores
  them through `valid` selectors.

The codec is responsible for preserving CCL's exact neighbor ordering and
termination payloads. Tests must cover every CCL step type.
The codec must emit `keyPath = nibbles(hashFn.digest(rawKeyBytes))`; tests must
reject a witness where the proof is valid but `keyPath` is changed.

## Public Inputs And Privacy Modes

The gadget must not force `key` or `value` to be public.

Recommended application modes:

| Mode | Public inputs | Secret inputs | Use case |
|------|---------------|---------------|----------|
| Public inclusion | `[root, keyPathCommitment, valueCommitment, mode=1]` | `keyPath`, proof | Transparent-ish proof with compact public path binding |
| Private inclusion | `[root, keyPathNullifier]` | `keyPath`, `valueCommitment`, proof | Registry membership without revealing key/value |
| Public exclusion | `[root, keyPathCommitment, mode=0]` | `keyPath`, proof | Non-membership with compact public path binding |
| Private exclusion | `[root, keyPathNullifier]` | `keyPath`, proof | Private non-membership or anti-duplication |

Encoding:

- Public inputs are field integers in generated schema order.
- The datum public-input list passed to the generic verifier is positional and
  must match the verification key's `IC` vector.
- Private inclusion schema order is exactly `[root, keyPathNullifier]`.
- Private exclusion schema order is exactly `[root, keyPathNullifier]`.
- Public inclusion schema order is exactly `[root, keyPathCommitment,
  valueCommitment, mode]`.
- Public exclusion schema order is exactly `[root, keyPathCommitment, mode]`.
- `mode` is encoded as field `1` for inclusion and field `0` for exclusion.
- A custom application validator that needs domain checks must not use the
  generic proof-only validator directly. It should call
  `Groth16BLS12381Lib.verify(...)` and then enforce root/nullifier/domain
  logic in the same validator.

`mode_flag` should be public only when one circuit intentionally supports both
inclusion and exclusion. If the application has separate circuits, the mode
should be fixed by the circuit identity instead.

## In-Circuit API

```java
public final class ZkMpf {
    public static ZkBool isIncludedPoseidon(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            ZkField valueCommitment,
            ZkField expectedRoot,
            ZkMpfProof proof);

    public static void verifyInclusionPoseidon(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            ZkField valueCommitment,
            ZkField expectedRoot,
            ZkMpfProof proof);

    public static ZkBool isExcludedPoseidon(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            ZkField expectedRoot,
            ZkMpfProof proof);

    public static void verifyExclusionPoseidon(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            ZkField expectedRoot,
            ZkMpfProof proof);

    public static ZkField keyPathCommitment(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath);

    public static ZkField keyPathNullifier(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath);
}
```

Argument order follows the existing symbolic convention:

```text
zk, params, statement values, expected root, proof
```

`keyPath` is the nibble vector represented by `hashFn.digest(rawKeyBytes)` in
CCL. For the CCL-compatible profile, `valueCommitment` is the field value
represented by `hashFn.digest(rawValueBytes)`. Applications that want a
different symbolic value commitment must store that commitment as the MPF value
or use a separate non-CCL profile; otherwise the circuit root will not match the
root produced by CCL `MpfTrie`.

`ZkMpf.keyPathCommitment(...)` and `ZkMpf.keyPathNullifier(...)` hash the
fixed-size nibble vector with PoseidonN so applications can expose a compact
public binding without making the full path public.

All `ZkMpf` entry points reject non-BLS12-381 Poseidon params. This is stricter
than generic `ZkPoseidon` because this ADR is a Cardano MPF feature, not a
BN254/off-chain compatibility feature.

## Module Placement

Add a new module:

```text
zeroj-mpf-poseidon
```

Dependencies:

```gradle
api project(':zeroj-circuit-lib')
api "com.bloxbean.cardano:cardano-client-merkle-patricia-forestry:<cclVersion>"
api "com.bloxbean.cardano:cardano-client-verified-structures-core:<cclVersion>"
```

The module belongs in `zeroj-bom-all`. Whether it belongs in `zeroj-bom-core`
depends on dependency weight after implementation review. If it pulls only CCL
verified-structure artifacts and ZeroJ circuit lib, include it in core; if it
pulls RocksDB or application storage, keep those as optional or separate.

Do not depend on RocksDB in the core Poseidon MPF module. Provide helpers that
accept a CCL `NodeStore`; examples can choose in-memory or RocksDB storage.

## Implementation Plan

### Phase 1: ADR Review And Test Vector Lock

Deliverables:

- This amended ADR.
- Three independent reviews:
  - CCL compatibility review
  - symbolic annotation/API review
  - Cardano/on-chain/usecase review
- ADR iterations until all reviewers approve or findings are explicitly
  accepted as follow-up work.

Exit criteria:

- No unresolved blocker on CCL wire compatibility.
- No unresolved blocker on symbolic input binding.
- No unresolved blocker on Cardano public-input semantics.

### Phase 2: Off-Chain Poseidon MPF Adapter

Deliverables:

- `zeroj-mpf-poseidon` module.
- `PoseidonMpfHashFunction`.
- `PoseidonMpfCommitmentScheme`.
- `PoseidonMpfTrie` convenience factory.
- `PoseidonMpfValueCommitment`.
- `PoseidonMpfReference`.

Tests:

- Build a CCL `MpfTrie` with the Poseidon adapters.
- Insert deterministic fixtures.
- Verify inclusion and exclusion through CCL `ProofVerifier` with the same
  adapters.
- Verify deterministic roots and wire proofs.
- Negative tests for tampered root, key, value, and proof bytes.

Exit criteria:

- CCL `verifyProofWire(...)` succeeds for valid Poseidon MPF proofs and fails
  for tampered proofs.
- Golden vectors are stored under ZeroJ tests.

### Phase 3: Codec To Symbolic Witness Inputs

Deliverables:

- `PoseidonMpfCodec`.
- Stable witness key naming for generated annotation input maps.
- Proof padding support for `MAX_STEPS`.
- Fork prefix chunking support, bounded by `MAX_FORK_PREFIX_CHUNKS`.
- Leaf-step support for CCL different-leaf non-inclusion, including
  `leafKeyPath` nibble payloads.
- Empty proof support for single-leaf inclusion and empty-trie exclusion.
- Proof-shape validation before producing a witness map.

Tests:

- CCL proof -> witness map -> reference recomputation.
- Short proofs are padded as a suffix only.
- Proofs longer than `MAX_STEPS` fail with a clear error.
- Neighbor order matches CCL `ProofSerializer`.
- Branch proofs with `branchValueHash` are rejected in v1.

Exit criteria:

- An annotated circuit can receive the proof arrays generated by the codec.

### Phase 4: Inclusion Gadget

Deliverables:

- `ZkMpfProof`.
- `ZkMpf.verifyInclusionPoseidon(...)`.
- In-circuit Poseidon byte digest helper for the exact `PoseidonMpfHash`
  contract.
- Branch, fork, and leaf recomputation needed for inclusion paths.
- Implicit terminal leaf handling when valid steps are exhausted.

Tests:

- Differential tests against `PoseidonMpfReference`.
- Generated annotated circuit test.
- BLS12-381 compile/witness success.
- BN254 compile rejection.
- Negative witnesses for tampered neighbors, wrong key, wrong value, and bad
  padding.

Exit criteria:

- A CCL-generated Poseidon MPF inclusion proof verifies inside a generated
  annotated circuit.

### Phase 5: Conservative Exclusion Gadget

Deliverables:

- `ZkMpf.isExcludedPoseidon(...)`.
- `ZkMpf.verifyExclusionPoseidon(...)`.
- Termination support for:
  - missing branch/empty slot
  - different leaf
  - empty tree
- Explicit rejection for terminal fork exclusion.

Tests:

- CCL reference parity for supported exclusion modes.
- Negative test: exclusion for a key that exists must fail.
- Negative test: forged terminal fork exclusion must fail.
- Fuzz tests over deterministic random tries.

Exit criteria:

- Supported exclusion proofs generated by CCL with the Poseidon adapters verify
  inside ZeroJ circuits.

### Phase 6: Groth16/Cardano Integration Test (Follow-Up)

Deliverables in ZeroJ:

- E2E test that:
  1. builds a Poseidon MPF,
  2. generates an annotated circuit witness,
  3. compiles over `CurveId.BLS12_381`,
  4. generates a Groth16 proof,
  5. verifies with `Groth16BLS12381Lib.verify(...)` in `JulcVm`,
  6. records or asserts budget headroom.

Yaci Devkit:

- Use the already-running Yaci Devkit instance for a real transaction-style
  validation path when available.
- Keep the default CI test runnable without requiring a long-lived external
  node. Yaci-backed tests should be opt-in or guarded by environment
  variables.

Current status:

- Deferred. The v1 symbolic verifier is correct for tested witness evaluation
  but too constraint-heavy for a practical default Groth16/Yaci demonstration.

Exit criteria:

- Local deterministic E2E passes.
- Yaci-backed test passes in the developer environment or is clearly skipped
  with a reason when Yaci configuration is absent.

### Phase 7: Witness-Level Usecase

Deliverables in `/Users/satya/work/bloxbean/zeroj-usecases`:

- New example project, for example:

```text
zk-mpf-private-registry/
```

- Off-chain code:
  - builds a Poseidon MPF registry with CCL
  - generates inclusion witnesses
  - evaluates the generated BLS12-381 circuit witness

- On-chain code is a follow-up:
  - custom Julc validator using `Groth16BLS12381Lib.verify(...)`
  - app-specific public input checks such as root matching and nullifier
    uniqueness

- README explaining:
  - why this is not native Aiken MPF
  - which values are public
  - how to extend the witness demo into a Groth16/Yaci flow after constraint
    optimization

Exit criteria:

- The usecase demonstrates private MPF membership witness generation end to end.
- It uses the locally published ZeroJ snapshot.

### Phase 8: Documentation And Support Matrix

Deliverables:

- Update `cardano-gadget-support-matrix.md`.
- Add a `ZkMpf` row: BLS12-381/Groth16 yes, native Aiken/Blake2b MPF no,
  proof arrays secret by default, public inputs application-defined.
- Add annotation API docs for `ZkMpf`.
- Add `zeroj-mpf-poseidon/README.md`.
- Document known limitations and when to drop to lower-level APIs.

Exit criteria:

- A new developer can choose between `ZkMerkle`, native CCL/Aiken MPF, and
  `ZkMpf` without reading source code.

## Testing Strategy

Implemented minimum tests:

- CCL adapter unit tests.
- CCL `ProofVerifier` parity tests.
- Deterministic tests for roots, proof bytes, and witness maps.
- Negative test where `keyPath` differs from `nibbles(hashFn.digest(rawKeyBytes))`.
- Codec validation tests.
- Symbolic gadget unit tests.
- Generated annotation processor tests.
- Negative witness tests.
- Randomized deterministic trie tests.
- BLS12-381 positive compile/witness tests.
- BN254 rejection tests.
- Witness-level usecase smoke test using Maven-local ZeroJ artifacts.

Follow-up tests before MPF is promoted as a practical full on-chain flow:

- Groth16 proof generation and verification tests for an optimized MPF circuit.
- Julc VM verifier tests for the MPF application's custom validator.
- Yaci-backed integration test where environment is available.
- Full-stack proof/Yaci usecase smoke test.

Before implementation is considered complete, run multiple review agents:

- Review A: CCL compatibility and proof semantics.
- Review B: circuit soundness and symbolic API.
- Review C: Cardano/on-chain integration and usecase ergonomics.

Findings must be fixed or explicitly documented as accepted follow-up work.

## Risks And Mitigations

### Risk: CCL Wire Semantics Drift

Mitigation:

- Tests call CCL `ProofVerifier` directly with the ZeroJ Poseidon adapters.
- Codec tests are based on generated CCL wire proofs.
- Golden vectors include proof bytes and witness maps.

### Risk: Unsound Padding

Mitigation:

- Monotonic `valid` constraints.
- Padded steps are accumulator no-ops.
- Proof codec emits suffix-only padding.
- Circuit rejects valid steps after invalid slots.

### Risk: Private Inputs Accidentally Made Public

Mitigation:

- ADR documents public and private modes separately.
- Examples include at least one private-key/private-value circuit.
- Generated schema tests assert public-input order.

### Risk: Poseidon Byte Digest Ambiguity

Mitigation:

- Digest includes domain and byte length.
- Chunk parsing is fixed to the three-padded-chunk, 32-byte-aligned rule in
  the Poseidon digest contract.
- Same helper is used off-circuit and in-circuit.
- Golden vectors lock the digest.

### Risk: Constraint Cost

Mitigation:

- Start with `MAX_STEPS` values of 4 and 8.
- Record constraint counts and proving time.
- Keep Yaci/on-chain cost tied to Groth16 public-input count, not MPF proof
  length.

## Acceptance Criteria

The feature is ready when:

- ADR reviewers approve the amended design.
- CCL Poseidon MPF adapter tests pass.
- Inclusion and exclusion gadgets pass differential tests against CCL-derived
  references.
- Annotated circuits can use MPF proofs without annotation processor composite
  support.
- Groth16 BLS12-381 verification works through the canonical Julc verifier for
  the general verifier path; MPF-specific proof/Yaci coverage remains follow-up
  until constraint cost is reduced.
- `zeroj-usecases` contains a witness-level MPF example using the locally
  published ZeroJ snapshot.
- Documentation explains that Poseidon MPF and native Aiken Blake2b MPF are
  separate commitments.

## Follow-Up Work

- Batched MPF proofs.
- State transition proofs.
- Constraint optimization for MPF proof generation and Yaci-backed tests.
- Authenticated terminal-fork exclusion witness format.
- Composite symbolic input support in the annotation processor.
- Optional fixed-public-input generated validators for budget-critical
  applications.
- Optional bridge to Blake2b MPF only if a future use case justifies the much
  higher circuit cost.

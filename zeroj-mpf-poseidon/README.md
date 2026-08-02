# ZeroJ Poseidon MPF

`zeroj-mpf-poseidon` connects Cardano Client Lib MPF proofs to ZeroJ symbolic
circuits.

It is a separate commitment profile from native Cardano/Aiken MPF:

| Profile | Hash | Verifier path |
| --- | --- | --- |
| Native MPF | Blake2b-256 | Aiken MPF verifier |
| ZeroJ Poseidon MPF v2 | BLS12-381 Poseidon | ZeroJ Groth16 BLS12-381 verifier path |

Use this module when an application needs to keep the MPF key, value, and proof
private inside a symbolic circuit, with the Cardano path going through a
Groth16 BLS12-381 proof. It uses the custom hash and commitment constructors in
CCL `0.8.0-pre4`.

The profile identifier persisted by load tooling is `zeroj-poseidon-mpf-v2`.
Poseidon roots are not interchangeable with native Blake2b/Aiken MPF roots.

## Gradle

```gradle
dependencies {
    implementation "com.bloxbean.cardano:zeroj-mpf-poseidon:<zeroj-version>"
}
```

## Off-chain Flow

```java
MpfTrie trie = PoseidonMpfTrie.inMemory();
trie.put(keyBytes, valueBytes);

byte[] root = trie.getRootHash();
byte[] proof = trie.getProofWire(keyBytes).orElseThrow();

PoseidonMpfWitness witness = PoseidonMpfCodec.toWitness(
        keyBytes,
        proof,
        maxSteps,
        2);
BigInteger valueCommitment = PoseidonMpfValueCommitment.field(valueBytes);
```

The v2 hash accepts arbitrary key and value byte arrays. MPF-internal strings
retain the fixed three-field-chunk encoding mirrored by `ZkMpf`; raw inputs that
cannot use that encoding fall back to domain-separated 31-byte chunks. The
default commitment scheme also has a bounded memoization cache for unchanged
binary Merkle pairs. This changes only off-chain performance, never roots.

For persistent high-volume state, use the non-published
[`zeroj-mpf-poseidon-load`](../zeroj-mpf-poseidon-load/README.md) tool. It uses
CCL RocksDB without adding RocksDB to this library's dependency surface and can
resume from atomic `(completed entries, root)` checkpoints.

The [2026-08-02 five-million-entry benchmark](../docs/benchmarks/poseidon-mpf-5m-2026-08-02.md)
completed the RocksDB load, generated a 192-byte Groth16 proof, and verified the exact artifacts
in the Julc Plutus V3 VM path. A later complete current-root scan measured 5-9 proof steps: the
benchmarked 8-step circuit covers 4,999,782 entries but not the 218 nine-step paths. High-volume
storage feasibility is established; a production bound/fallback policy, trusted setup, security
review, and target-network deployment remain open.

See the [practical large-state MPF/MPT report](../docs/poseidon-mpf-large-state-production-report.md)
for circuit-profile guidance, an application flow, update/root policies, alternative data
structures, ecosystem comparisons, and the production work plan.

`PoseidonMpfCodec` emits the flattened arrays expected by `ZkMpfProof` and can
write them directly into a `ZkInputMap`.

The default witness names emitted by `PoseidonMpfWitness.putInto(inputs)` are:

```text
key_path
mpf_kind
mpf_skip
mpf_neighbor
mpf_neighbor_nibble
mpf_fork_prefix_length
mpf_fork_prefix
mpf_fork_root
mpf_leaf_key_path
mpf_leaf_value_digest
mpf_valid
```

Annotated circuits should use matching `@Secret(name = "...")` values. For
non-empty proof bounds, use `maxForkPrefixChunks >= 2`.

## Circuit Flow

```java
ZkMpfProof proof = ZkMpfProof.fromArrays(
        stepKind, stepSkip, neighbors, neighborNibble,
        forkPrefixLength, forkPrefixChunks, forkRoot,
        leafKeyPath, leafValueDigest, valid);

ZkMpf.verifyInclusionPoseidon(
        zk,
        PoseidonParamsBLS12_381T3.INSTANCE,
        keyPath,
        valueCommitment,
        registryRoot,
        proof);

ZkMpf.keyPathNullifier(zk, PoseidonParamsBLS12_381T3.INSTANCE, keyPath)
        .assertEqual(publicNullifier);
```

## Limits

- BLS12-381 Poseidon only.
- Branch values are rejected by the current profile.
- The circuit-compatible internal digest is fixed to three padded 32-byte
  chunks; arbitrary raw keys and values use the v2 total-byte fallback.
- Terminal fork exclusions from CCL are not accepted by the in-circuit verifier
  because that proof shape carries an unauthenticated root. Empty-trie,
  missing-branch, and different-leaf exclusions remain the supported exclusion
  paths.
- Raw key-to-path binding is application-specific; the gadget verifies the
  CCL key path nibbles emitted by `PoseidonMpfCodec`.
- For on-chain MPF applications, use `Groth16BLS12381Lib.verify(...)`
  inside a custom validator when additional root, nullifier, or domain checks
  are needed. Circuit cost grows with the configured proof-step bound, not with
  the total number of entries in the off-chain trie; benchmark and pin that
  bound before setup.

See [ADR-0041](../docs/adr/0041-poseidon-mpf-production-readiness-and-load-benchmark.md)
for the commitment contract and production gates.

# ZeroJ Poseidon MPF

`zeroj-mpf-poseidon` connects Cardano Client Lib MPF proofs to ZeroJ symbolic
circuits.

It is a separate commitment profile from native Cardano/Aiken MPF:

| Profile | Hash | Verifier path |
| --- | --- | --- |
| Native MPF | Blake2b-256 | Aiken MPF verifier |
| ZeroJ Poseidon MPF | BLS12-381 Poseidon | Intended Groth16 BLS12-381 verifier path; current checked-in demo is witness-level |

Use this module when an application needs to keep the MPF key, value, and proof
private inside a symbolic circuit, with the Cardano path going through a
Groth16 BLS12-381 proof after MPF constraint optimization.

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
- Branch values are rejected in v1.
- MPF byte digests are fixed to three padded 32-byte chunks.
- Terminal fork exclusions from CCL are not accepted by the in-circuit verifier
  in v1 because that proof shape carries an unauthenticated root. Empty-trie,
  missing-branch, and different-leaf exclusions remain the supported exclusion
  paths.
- Raw key-to-path binding is application-specific; the gadget verifies the
  CCL key path nibbles emitted by `PoseidonMpfCodec`.
- For future on-chain MPF applications, use `Groth16BLS12381Lib.verify(...)`
  inside a custom validator when additional root, nullifier, or domain checks
  are needed. The current example suite demonstrates witness evaluation; a
  practical Groth16/Yaci MPF flow is deferred until the circuit cost is reduced.

# ZeroJ Poseidon MPF

`zeroj-mpf-poseidon` connects CCL Merkle Patricia Forestry storage/proofs to
operation-specific ZeroJ circuits. Its `zeroj-poseidon-mpf-v1` root profile uses
BLS12-381 Poseidon and is incompatible with native Blake2b/Aiken MPF roots and with Poseidon JMT.

```gradle
dependencies {
    implementation "com.bloxbean.cardano:zeroj-mpf-poseidon:<zeroj-version>"
}
```

## Recommended operation-specific flow

Create or reopen the off-chain trie, request a strict CCL proof, normalize it with the factory for
the exact statement, and compile the matching bounded template:

```java
PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
trie.put(keyBytes, valueBytes);

byte[] root = trie.getRootHash();
byte[] proofWire = trie.getProofWire(keyBytes).orElseThrow();
int maxBranches = 8;

PoseidonMpfBranchWitness witness = PoseidonMpfBranchWitness.inclusion(
        root, keyBytes, valueBytes, proofWire, maxBranches);

ZkInputMap inputs = new ZkInputMap()
        .put(PoseidonMpfCircuitTemplates.ROOT,
                PoseidonMpfHash.fieldFromDigestBytes(root))
        .put(PoseidonMpfCircuitTemplates.VALUE,
                PoseidonMpfValueCommitment.field(valueBytes));
witness.putInto(inputs);

CircuitBuilder circuit = PoseidonMpfCircuitTemplates.inclusion(maxBranches);
BigInteger[] circuitWitness = circuit.calculateWitness(
        inputs.toWitnessMap(), CurveId.BLS12_381);
```

Witness factories first perform strict MPF v1 verification through CCL's proof verifier and then
fail-closed normalization. They reject the wrong proof form, malformed wire data, non-canonical
fields, terminal forks, and paths deeper than the selected bound.

## Implemented circuits

| Template/gadget | Public inputs | Host witness |
|---|---|---|
| `inclusion` / `ZkMpfInclusion` | `root` | `PoseidonMpfBranchWitness.inclusion` |
| `non-inclusion-empty` / `ZkMpfNonInclusionEmpty` | `root` | `PoseidonMpfBranchWitness.emptyNonInclusion` |
| `non-inclusion-different-leaf` / `ZkMpfNonInclusionDifferentLeaf` | `root` | `PoseidonMpfDifferentLeafWitness.nonInclusion` |
| `value-update` / `ZkMpfValueUpdate` | `oldRoot,newRoot` | verified inclusion path plus old/new values |
| `insert-empty` / `ZkMpfInsertEmpty` | `oldRoot,newRoot` | verified empty-child path plus inserted value |
| `insert-different-leaf` / `ZkMpfInsertDifferentLeaf` | `oldRoot,newRoot` | verified conflicting leaf/path plus inserted value |

`ZkMpfInsert` is a source-level facade over the two insertion shapes. Proof-form selection is not
an attacker-controlled circuit flag, and no generic `...-insert-sN-p2` R1CS exists. Physical
delete remains deferred because canonical Patricia branch collapse requires more authenticated
rewrite data than an ordinary inclusion proof carries.

## Full-semantics compatibility circuit

`ZkMpf`, `ZkMpfProof`, `PoseidonMpfCodec`, and `PoseidonMpfWitness` remain in this module for
reference/migration use when an application genuinely needs the historical union of MPF proof
forms. New applications should use the smallest operation-specific template.

For the full-semantics layout, MPF's 64-nibble path has exactly two 32-nibble fork-prefix chunks:
the chunk count is exactly `2` for a nonzero proof bound and exactly `0` for S0. The operation-
specific branch witnesses do not expose this allocation parameter.

## Scale and profile selection

The preserved five-million-entry RocksDB trie has root
`5988af1bdc5883f6cf67b748c85b7fa32de9e4cbf309d971288d86d6d1129ad8`.
An exact full-root census found proof depths 5-9: S8 covered 4,999,782 entries and missed 218;
S9 covered that measured root. This is evidence for that deterministic dataset, not a universal
capacity formula.

Fresh benchmark-only setup material and three trials measured:

| Profile | Constraints | Setup | Median prove | JVM Groth16 verify |
|---|---:|---:|---:|---:|
| S8 | 50,768 | 2.349 s | 3.999 s | 115.6 ms |
| S9 | 56,635 | 2.421 s | 4.173 s | 119.2 ms |
| S12 | 74,236 | 2.961 s | 4.489 s | 117.8 ms |

Every compressed proof is 192 bytes and every one-public-input compressed VK is 432 bytes. Route
common paths to a smaller profile only when the application has an explicit overflow/fallback
policy. Proving cost is determined by the fixed circuit bound, not directly by the number of
entries in RocksDB.

For persistent state and reproducible benchmarks, use
[`zeroj-mpf-poseidon-load`](../zeroj-mpf-poseidon-load/README.md). RocksDB remains outside this
published library's dependency surface.

## Security boundary

- Raw key-to-path/application identity binding remains an application-circuit responsibility.
- A root-only inclusion template proves existential private membership; add the key/value
  commitment, nullifier, owner, transaction, version, or policy fields your application needs.
- Terminal-fork exclusions are rejected because the CCL shape does not authenticate the required
  terminal root for this circuit statement.
- Bounded padding is a constrained suffix and too-deep proofs fail before proving.
- Generated local setup bundles are benchmark-only and `productionApproved=false`.
- Production use still requires an exact-fingerprint ceremony, external review, representative
  validator binding, current protocol-budget evaluation, and target-network testing.

The compatibility contract is frozen in
[the authenticated-state v1 specification](../docs/merkle/poseidon-authenticated-state-v1.md) and
[ADR-0042](../docs/adr/0042-operation-specific-poseidon-mpf-and-jmt-circuits.md). ADR-0041 and the
[five-million MPF report](../docs/benchmarks/poseidon-mpf-5m-2026-08-02.md) retain the historical
pre-ADR-0042 benchmark provenance.

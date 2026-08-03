# ZeroJ Poseidon JMT

`zeroj-jmt-poseidon` provides a CCL Jellyfish Merkle Tree profile and operation-specific ZeroJ
circuits under the `zeroj-poseidon-jmt-v1` commitment. It is deliberately incompatible with
classic Blake2b JMT and `zeroj-poseidon-mpf-v1`.

```gradle
dependencies {
    implementation "com.bloxbean.cardano:zeroj-jmt-poseidon:<zeroj-version>"
}
```

The profile uses CCL `0.8.0-pre5-dev1`'s custom `JmtProfile`: a complete-key Poseidon leaf and a
four-level binary Poseidon commitment over each radix-16 branch. A circuit witness carries four
sibling fields per valid JMT level.

## Off-chain tree and strict witness flow

```java
PoseidonJmtTree tree = new PoseidonJmtTree(new InMemoryJmtStore());
byte[] root = tree.put(0, Map.of(keyBytes, valueBytes)).rootHash();
JmtProof proof = tree.getProof(keyBytes, 0).orElseThrow();

int maxLevels = 8;
PoseidonJmtInclusionWitness witness = PoseidonJmtInclusionWitness.create(
        root, keyBytes, valueBytes, proof, maxLevels);

ZkInputMap inputs = new ZkInputMap()
        .put("root", PoseidonJmtHash.decode(root));
witness.putInto(inputs);

CircuitBuilder circuit = PoseidonJmtCircuitTemplates.inclusion(maxLevels);
BigInteger[] circuitWitness = circuit.calculateWitness(
        inputs.toWitnessMap(), CurveId.BLS12_381);
```

Use `PoseidonJmtEmptyWitness.create(...)` for an authenticated empty terminal and
`PoseidonJmtDifferentLeafWitness.create(...)` for an authenticated conflicting leaf. Every factory
strictly verifies the real CCL object proof and enforces the exact proof form before emitting
circuit inputs.

## Implemented circuits

| Template/gadget | Public inputs | Meaning |
|---|---|---|
| `inclusion` / `ZkJmtInclusion` | `root` | complete key/value leaf is included |
| `non-inclusion-empty` / `ZkJmtNonInclusionEmpty` | `root` | query reaches an authenticated empty terminal |
| `non-inclusion-different-leaf` / `ZkJmtNonInclusionDifferentLeaf` | `root` | an authenticated different full key occupies the route |
| `value-update` / `ZkJmtValueUpdate` | `oldRoot,newRoot` | one included value changes on a shared path |
| `insert-empty` / `ZkJmtInsertEmpty` | `oldRoot,newRoot` | insertion at an empty terminal |
| `insert-different-leaf` / `ZkJmtInsertDifferentLeaf` | `oldRoot,newRoot` | insertion beside a conflicting leaf |
| `tombstone-update` / `ZkJmtTombstoneUpdate` | `oldRoot,newRoot,jmt_tombstone_value_hash` | exact public tombstone replaces an included value |

`ZkJmtInsert` is a source facade over the two insertion shapes; no generic attacker-selectable
insert R1CS exists. CCL dev1 has no physical key deletion. A tombstone remains an included value
and must never be presented as proof of absence.

## Version and persistence model

JMT versions are off-chain storage coordinates, not authenticated application state by
themselves. The application must bind `{chain point, version, root}` and serialize updates through
one logical writer. A Cardano state validator should authenticate the current root/version datum,
the state-token instance, signer/release, and the exact transition VK.

Persistent RocksDB operation belongs to the non-published
[`zeroj-jmt-poseidon-load`](../zeroj-jmt-poseidon-load/README.md) module. Its production-durability
profile keeps WAL and sync enabled, writes a checkpoint manifest only after the CCL commit, fails
closed on ahead/foreign manifests, exercises graceful and in-flight-kill recovery, and exposes
rollback/pruning as explicit operator actions. Pruning historical nodes does not change the latest
root; retain enough versions for the application's rollback horizon.

The commitment scheme has a bounded, level-tagged binary-pair cache. The default capacity is
262,144 entries and can be set to zero; cache state changes performance only, never roots.

## Five-million-entry qualification

The preserved durable run loaded 5,000,000 entries with 1,000 synchronized checkpoints in
6,916.5 seconds (722.9 entries/s overall). Its root is
`1f2d236ccbcb0314b8dbaa3886d301d08e488a70374bfe4ead23ae492d2f14c2`.
RocksDB reported 8.713 GB of logical files; observed peak Java heap was 2.587 GB and peak RSS was
5.840 GB under a fixed 4 GB heap.

An exact all-key census found levels 5-12. S8 covered 4,987,028 keys (99.74056%), S10 missed 32,
and S12 covered all five million. S64 remains the format-maximum fallback. Thirty-two native proof
samples were 2,744-3,161 bytes with a 2,881-byte median; that proof is private prover input.

Fresh benchmark-only setup material and three trials measured:

| Profile | Constraints | Setup | Median prove | JVM Groth16 verify |
|---|---:|---:|---:|---:|
| S8 | 10,069 | 1.142 s | 2.856 s | 114.0 ms |
| S10 | 12,063 | 1.172 s | 2.911 s | 113.3 ms |
| S12 | 14,057 | 1.306 s | 2.901 s | 114.4 ms |
| S64 | 65,901 | 2.947 s | 4.582 s | 115.2 ms |

Every compressed proof is 192 bytes and every one-public-input compressed VK is 432 bytes.
Strict bundle checks and positive/mutated-root Julc VM tests passed for all four profiles. The
larger native JMT proof therefore does not enlarge the Cardano-facing ZK proof.

## Security and release boundary

- Complete 32-byte keys are bound in leaves and field aliases are rejected.
- Branch prefixes/cursors must match exact query nibbles; a merely increasing prefix is unsound
  because the v1 branch commitment is prefix-independent.
- Valid levels form one constrained prefix and padding one canonical zero suffix.
- A root-only template proves existential membership; application circuits must add any required
  key/value/nullifier/owner/version/transaction bindings.
- Local bundles use known single-party toxic waste, remain `productionApproved=false`, and cannot
  produce a mainnet deployment manifest.
- Production still requires an exact-circuit ceremony, external review, current protocol-budget
  comparison, and target-network execution.

See [ADR-0042](../docs/adr/0042-operation-specific-poseidon-mpf-and-jmt-circuits.md), the
[authenticated-state v1 specification](../docs/merkle/poseidon-authenticated-state-v1.md), and the
[five-million JMT report](../docs/benchmarks/poseidon-jmt-5m-2026-08-03.md).

# Poseidon JMT durable load and benchmark tool

`zeroj-jmt-poseidon-load` is a non-published operator/benchmark module. It keeps RocksDB and its
native runtime out of the public JMT circuit artifact while providing deterministic load, proof,
depth, operation, setup/prove, and recovery qualification.

Always pass an absolute `--work-dir`. Gradle's application task runs with the subproject as its
working directory, so a relative path can create a different empty database.

## Stages

| Stage | Work performed |
|---|---|
| `load` | deterministic cumulative-version load with synchronized checkpoints/resume |
| `proofs` | reopen, generate/verify strict CCL proofs, measure wire size and normalization |
| `depth-scan` | exact all-key depth census; intentionally opt-in |
| `operations` | disposable full-copy update/insert, proof, rollback, reopen, and scratch-prune timing |
| `circuit` | proof normalization, exact R1CS, setup/load, three-trial prove/verify, Cardano bundle |
| `all` | load, proofs, circuit, operations; excludes the expensive exact depth scan |

Example durable load:

```bash
./gradlew :zeroj-jmt-poseidon-load:run -PbenchmarkMaxHeap=4g --args='\
--stage=load \
--work-dir=/absolute/path/poseidon-jmt-5m \
--entries=5000000 --batch=5000 --seed=42 \
--pair-cache=262144 --rocksdb-profile=high-throughput \
--progress-every=100000'
```

Example exact census and operation sample:

```bash
./gradlew :zeroj-jmt-poseidon-load:run -PbenchmarkMaxHeap=4g --args='\
--stage=depth-scan --work-dir=/absolute/path/poseidon-jmt-5m \
--entries=5000000 --batch=5000 --seed=42'

./gradlew :zeroj-jmt-poseidon-load:run -PbenchmarkMaxHeap=4g --args='\
--stage=operations --work-dir=/absolute/path/poseidon-jmt-5m \
--entries=5000000 --batch=5000 --seed=42 --operation-entries=1000'
```

## Durability and recovery

The tool requires CCL's production-durability options: WAL enabled, commit/prune/truncate sync
enabled, rollback index enabled, and one logical writer. Each cumulative batch uses its completed
entry count as the JMT version. The manifest advances only after CCL commits the batch, storing the
exact `(completedEntries, latestVersion, root)` checkpoint.

Reopen validates profile/format/dataset identity, the latest committed version/root, and manifest
ordering. A foreign, ahead, or inconsistent manifest fails closed. Integration tests exercise
graceful restart, process termination after committed checkpoints, and termination during an
in-flight batch. A kill after the database commit but before the fsynced atomic manifest replacement
can leave the database ahead of the manifest. That state is rejected rather than automatically
adopted; an operator must restore a matching backup or perform an explicit authenticated
reconciliation.

The current build uses published CCL `0.8.0-pre5`. A store whose manifest records
`0.8.0-pre5-dev1` may be reopened because the release comparison contains no changes in CCL's
verified-structures subtree; the manifest is retained as original dataset provenance. This is an
exact, one-way exception. Every other CCL mismatch remains a hard failure pending qualification or
an explicit migration.

The operations stage first validates and closes the retained database, then makes a disposable
full file copy. Temporary updates, proof creation, rollback, and reopen verification run only on
that copy, which is removed on normal completion. A crash may leave a directory named
`operation-update-scratch-*`, but cannot advance or truncate the retained `rocksdb/` head.
Reserve enough free disk space for a physical copy of the complete database; copy-on-write
filesystem acceleration is an optimization, not a requirement the tool assumes.

The persistent database must live outside `build/`. The five-million reference database is kept at
the repository-level `.benchmark-data/poseidon-jmt-5m`; normal Gradle clean tasks do not remove it.
Back it up before destructive operator experiments.

## Pair-cache and storage profiles

`--pair-cache=262144` is the default bounded, level-tagged binary-Poseidon LRU. `0` disables it.
The cache is not persisted and does not affect commitments. On a 100K comparison, the default cache
improved load throughput from about 333 to 1,434 entries/s; a one-million-entry cache produced only
a small additional gain and materially more heap, so it is not the default.

`--rocksdb-profile=high-throughput|balanced|low-memory|default` changes RocksDB resource behavior,
not tree identity. Reports record logical database bytes, pending compaction, memtable bytes,
pair-cache hits/misses, fixed maximum heap, sampled used heap, process RSS, runtime/OS, CCL version,
git/source-tree provenance, and exact roots.

## Circuit setup and artifacts

Use one keys directory per exact R1CS fingerprint:

```bash
./gradlew :zeroj-jmt-poseidon-load:run -PbenchmarkMaxHeap=4g --args='\
--stage=circuit --work-dir=/absolute/path/poseidon-jmt-5m \
--entries=5000000 --seed=42 --samples=32 --max-levels=12 \
--circuit-trials=3 --setup=store \
--keys-dir=/absolute/path/poseidon-jmt-5m/groth16-keys-s12 \
--allow-insecure-setup=true'
```

Setup modes are `none`, `in-memory`, `store`, and `load`. `in-memory` and `store` require the
explicit insecure-setup opt-in and use known single-party toxic waste for benchmarking only.
`load` verifies the exact key/R1CS binding and fails closed on mismatch.

Successful proving writes:

```text
cardano-artifacts/<templateId>/<exactFingerprint>/
  vk-<vkSha256>/bundle-<bundleSha256>/
```

The bundle leaf contains the canonical circuit manifest, canonical encoded VK, compressed proof,
ordered 32-byte public inputs, per-file hashes/lengths, complete setup provenance, and
`productionApproved=false`. Point the optional Julc test property at the final `bundle-*` leaf:

```bash
./gradlew \
  -Dzeroj.poseidonJmt.cardanoArtifacts=/absolute/path/to/bundle-... \
  :zeroj-onchain-julc:test --tests '*PoseidonJmtCardanoArtifactTest'
```

Local success is not production approval. Ceremony, external review, representative application
binding, current Cardano protocol-budget comparison, and target-network execution remain separate
release gates.

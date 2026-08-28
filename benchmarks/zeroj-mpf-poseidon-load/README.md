# ZeroJ Poseidon MPF load benchmark

This non-published module implements the reproducible production-readiness run from
[ADR-0041](../docs/adr/0041-poseidon-mpf-production-readiness-and-load-benchmark.md).
It keeps RocksDB out of the `zeroj-mpf-poseidon` library.

The completed 2026-08-02 reference run and all timings are recorded in the
[five-million-entry benchmark report](../docs/benchmarks/poseidon-mpf-5m-2026-08-02.md).

The default dataset contains five million deterministic entries and is resumable at committed
batch boundaries:

```bash
POSEIDON_MPF_BENCH_DIR="$(pwd)/.benchmark-data/poseidon-mpf-5m"

./gradlew :zeroj-mpf-poseidon-load:run \
  --args="--stage=all --work-dir=$POSEIDON_MPF_BENCH_DIR --entries=5000000 \
  --batch=1000 --rocksdb-profile=high-throughput --pair-cache=262144 \
  --samples=32 --max-steps=8 --circuit-trials=3 --setup=store \
  --keys-dir=$POSEIDON_MPF_BENCH_DIR/groth16-keys-s8 --allow-insecure-setup=true"
```

Keep long-lived datasets under the ignored root `.benchmark-data/`, not a Gradle `build/`
directory. `./gradlew clean` does not remove `.benchmark-data/`. The completed local reference
dataset is preserved at `.benchmark-data/poseidon-mpf-5m`. Use one explicit keys directory for
each exact S8/S9/S12 R1CS fingerprint. `--setup=load` fails closed if the selected key directory
does not match the exact circuit; keys are never reusable merely because dimensions look similar.

An ADR-0041 database whose manifest still contains the unreleased `v2` alias must be migrated
explicitly once. Normal load/proof opens reject that metadata. The migration does not rewrite
RocksDB nodes: it verifies the root and deterministic proofs before and after, creates
`manifest.pre-adr0042-v2.json` without overwriting an existing backup, and records timings in
`report.json`:

```bash
./gradlew :zeroj-mpf-poseidon-load:run \
  --args="--stage=migrate-profile --work-dir=$POSEIDON_MPF_BENCH_DIR \
  --entries=5000000 --batch=1000 --seed=25 --samples=32 \
  --rocksdb-profile=high-throughput"
```

The current build uses published CCL `0.8.0-pre5`. A v1 store whose manifest records the
source-identical `0.8.0-pre5-dev1` predecessor may be reopened without relabelling its provenance.
This is an exact, one-way exception; every other CCL mismatch still fails closed until separately
qualified or explicitly migrated.

The locally generated Groth16 setup is deliberately insecure and benchmark-only. Use
`--setup=none` to measure load, CCL proof generation, strict CCL MPF v1 verification, circuit
construction, witness generation, and R1CS compilation without generating parameters. Use
`--setup=load --keys-dir=...` to prove with an existing key bundle for the exact circuit
fingerprint.

To measure the proof-step bound of every entry under the current root without generating each
wire proof, run the opt-in streaming depth scan:

```bash
./gradlew :zeroj-mpf-poseidon-load:run \
  --args="--stage=depth-scan --work-dir=$POSEIDON_MPF_BENCH_DIR --entries=5000000 \
  --progress-every=500000 --rocksdb-profile=high-throughput"
```

`--depth-scan-version=N` selects a retained historical root checkpoint, for example
`--depth-scan-version=100000`. The scan follows CCL inclusion-proof semantics and counts branch
records; compressed extension prefixes are folded into the following branch record. It streams
nodes from RocksDB and records the full step histogram in `report.json`. `--stage=all` does not
run this potentially long full traversal; it remains explicitly opt-in.

The report field `verifiedWitnessNormalizationLatency` includes the witness factory's mandatory
second strict proof verification plus normalization; it is not a pure array-encoding time.

Outputs are written below the work directory:

- `manifest.json` — immutable dataset/profile identity plus the latest observed checkpoint;
- `report.json` — load, proof-distribution, circuit, setup, prove, and verify metrics;
- `rocksdb/` — CCL MPF nodes and root checkpoints; and
- `groth16-keys-<profile>/` — one sparse store-backed benchmark key bundle per exact fingerprint;
  and
- `cardano-artifacts/<templateId>/<exactFingerprint>/vk-<vkSha256>/bundle-<bundleSha256>/` —
  canonical circuit manifest, encoded VK, compressed proof, ordered public inputs, per-file hashes,
  complete setup provenance, and `productionApproved=false`.

The root checkpoint version is the number of completely committed entries. Trie-node writes and
the checkpoint root use one RocksDB `WriteBatch`; the authenticated manifest is then replaced with
an fsynced atomic rename. A normal restart resumes only when those two durable views agree. A kill
after the database commit but before the manifest replacement leaves the database ahead of the
manifest and deliberately fails closed. The tool never guesses or automatically adopts that head;
an operator must restore a matching backup or perform an explicit authenticated reconciliation.

The harness uses CCL `0.8.0-pre5`'s `highThroughput()` RocksDB profile by default. The
`balanced`, `low-memory`, and raw RocksDB `default` profiles remain selectable so benchmark
reports identify the physical-store policy instead of conflating it with Poseidon cost.

After a circuit run has produced an artifact bundle, point the Julc property at the final
`bundle-*` leaf, not the `cardano-artifacts` root:

```bash
./gradlew \
  -Dzeroj.poseidonMpf.cardanoArtifacts=/absolute/path/to/bundle-... \
  :zeroj-onchain-julc:test \
  --tests '*PoseidonMpfCardanoArtifactTest'
```

The bridge checks the outer and canonical manifests, every file digest/length, VK arity/identity,
public-input canonicality, directory identities, the real proof, and mutated-root rejection. Local
success does not approve benchmark setup material: exact-fingerprint ceremony, external review,
representative validator binding, current protocol-budget evaluation, Yaci, and public-network
transaction checks remain separate deployment gates.

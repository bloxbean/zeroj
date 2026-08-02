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
  --samples=32 --max-steps=8 --setup=store --allow-insecure-setup=true"
```

Keep long-lived datasets under the ignored root `.benchmark-data/`, not a Gradle `build/`
directory. `./gradlew clean` does not remove `.benchmark-data/`. The completed local reference
dataset is preserved at `.benchmark-data/poseidon-mpf-5m`; use `--setup=load` to reuse its
existing `groth16-keys/` bundle instead of asking `--setup=store` to overwrite it.

The locally generated Groth16 setup is deliberately insecure and benchmark-only. Use
`--setup=none` to measure load, CCL proof generation, independent proof verification, circuit
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

Outputs are written below the work directory:

- `manifest.json` — immutable dataset/profile identity plus the latest observed checkpoint;
- `report.json` — load, proof-distribution, circuit, setup, prove, and verify metrics;
- `rocksdb/` — CCL MPF nodes and root checkpoints; and
- `groth16-keys/` — sparse store-backed benchmark keys when requested; and
- `cardano-artifacts/` — compressed Groth16 proof/VK points and the public root in the byte
  formats consumed by ZeroJ's Plutus V3 verifier.

The root checkpoint version is the number of completely committed entries. Trie-node writes
and the checkpoint root use one RocksDB `WriteBatch`, so an interrupted run resumes from the
last durable batch rather than guessing from a log file.

The harness uses CCL `0.8.0-pre4`'s `highThroughput()` RocksDB profile by default. The
`balanced`, `low-memory`, and raw RocksDB `default` profiles remain selectable so benchmark
reports identify the physical-store policy instead of conflating it with Poseidon cost.

After a circuit run has produced `cardano-artifacts/`, verify the exact proof in the Julc VM:

```bash
./gradlew \
  -Dzeroj.poseidonMpf.cardanoArtifacts=/absolute/path/to/cardano-artifacts \
  :zeroj-onchain-julc:test \
  --tests '*PoseidonMpfCardanoArtifactTest'
```

The bridge requires the real root to pass and a one-field mutation of that root to fail. Yaci
DevKit and public-testnet transaction checks remain separate deployment gates.

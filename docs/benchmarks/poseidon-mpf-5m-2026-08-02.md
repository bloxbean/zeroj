# Poseidon MPF five-million-entry benchmark — 2026-08-02

This report records the reference run for
[ADR-0041](../adr/0041-poseidon-mpf-production-readiness-and-load-benchmark.md)
and [GitHub issue #25](https://github.com/bloxbean/zeroj/issues/25).
The broader application architecture and current MPF/JMT profile guidance are in the
[practical large-state guide](../merkle/practical-large-state-guide.md). The original
pre-ADR-0042 assessment remains archived for decision history.

## Outcome

The first ADR-0041 run below is retained as historical evidence. It used the then-current
generic MPF circuit and CCL `0.8.0-pre4`; its 17.4-million-constraint and 3.5-minute proving
figures must not be used to size ADR-0042 operation-specific circuits. A later compatibility
migration and fresh ADR-0042 measurements are recorded near the end of this report.

The high-volume path works end to end:

```text
5,000,000 deterministic entries
        |
        v
CCL 0.8.0-pre4 RocksDB MPF + historical zeroj-poseidon-mpf-v2 alias
        |
        v
real CCL inclusion proof (5-9 steps across the complete current root)
        |
        v
historical generic ZeroJ witness -> 17,399,380-constraint R1CS
        |
        v
192-byte Groth16 proof -> off-chain pairing verification
        |
        v
Cardano-formatted proof -> Julc Plutus V3 VM verification
```

This establishes that a Poseidon-rooted CCL MPF can hold five million off-chain entries while
the circuit proves one bounded inclusion path. The circuit does **not** contain all five
million entries. Its size is determined by the pinned proof-step bound, not directly by the
database entry count. The benchmarked 8-step circuit proved the selected 7-step path, but a
later complete current-root scan found 218 entries requiring 9 steps. Therefore the 8-step
circuit is not a universal circuit for this five-million-entry root.

The high-volume implementation is validated, but the feature is not yet ready for a
value-bearing production deployment. The benchmark used a deliberately insecure local
single-party Groth16 setup. An exact-circuit production ceremony or approved imported key,
security review, and Yaci/public-network deployment tests remain open.

## Preserved local artifacts

The completed dataset is retained at:

```text
.benchmark-data/poseidon-mpf-5m
```

It contains the RocksDB MPF, manifest, raw JSON report, historical 9.6 GiB sparse Groth16 key,
new operation-specific keys, and Cardano proof artifacts. The root `.gitignore` excludes
`.benchmark-data/`, and
the directory is outside every Gradle `build/` directory, so `./gradlew clean` does not remove
it.

The dataset is local benchmark state: it is neither committed to Git nor backed up by the
repository. Filesystem deletion or workspace removal can still destroy it.

## Historical ADR-0041 configuration

| Setting | Value |
|---|---:|
| CCL | `0.8.0-pre4` |
| Commitment profile | `zeroj-poseidon-mpf-v2` |
| Poseidon parameter fingerprint | `3920ef069c36d968b77c99cef6dbc7e6f20f957e373a28fc84d145ee0a0d824d` |
| Dataset schema | `zeroj-poseidon-mpf-load-v1` |
| Dataset seed | 25 |
| Entries | 5,000,000 |
| Key/value bytes | 24 / 32 |
| Batch size | 1,000 |
| WAL | enabled |
| RocksDB profile | CCL `highThroughput()` |
| Pair-hash cache | 262,144 entries |
| Proof samples | 32 deterministic boundary/random indices |
| Complete depth scan | all 5,000,000 current-root entries plus selected historical roots |
| Circuit bound | 8 MPF steps, 2 fork-prefix chunks per step |
| Curve/proof system | BLS12-381 Groth16 |

Final root:

```text
5988af1bdc5883f6cf67b748c85b7fa32de9e4cbf309d971288d86d6d1129ad8
```

## Machine

| Property | Value |
|---|---|
| OS | macOS 26.0.1, `aarch64` |
| JDK | BellSoft OpenJDK 25.0.2 |
| Logical processors | 16 |
| JVM maximum heap | 32,178,700,288 bytes |

These are single-machine measurements, not portable service-level objectives.

## Load result

The run deliberately exercised restartability. The first process committed 930,000 entries,
was stopped after a durable batch, and the final process resumed from that checkpoint. No
entries were regenerated in heap and no committed work was lost.

| Metric | Result |
|---|---:|
| Final entries | 5,000,000 |
| Resume point | 930,000 |
| Timed resumed inserts | 4,070,000 |
| Timed resumed load | 20,827.443 s (5h 47m 7.443s) |
| Timed resumed throughput | 195.415 entries/s |
| Checkpoints written after resume | 4,070 |
| Manifest creation-to-completion | approximately 7h 0m 52s, including the intentional stop |
| Reported final RocksDB logical bytes | 27,724,535,579 |
| Preserved RocksDB physical usage after close | approximately 14 GiB |
| Peak observed Java heap | 1,304,987,384 bytes (approximately 1.22 GiB) |
| Pair-cache hits / misses | 213,547,240 / 172,494,125 |

The 195.415 entries/s value is the steady resumed segment, not an average over all five
million entries. The initial 930,000-entry process used an earlier physical-store run before
the final high-throughput profile restart, so combining the two as one throughput number
would be misleading.

## CCL MPF proof sampling

All 32 sampled values matched the deterministic dataset. Every CCL wire proof passed strict
CCL MPF-profile verification before witness encoding. The later ADR-0042 witness-normalization
path performs the same mandatory strict verification again; it is not an independent hash
implementation.

| Metric | Min | Median | p95 | p99 / max |
|---|---:|---:|---:|---:|
| MPF proof generation | 10.465 ms | 12.222 ms | 25.071 ms | 26.730 ms |
| MPF proof verification | 10.428 ms | 11.839 ms | 20.781 ms | 21.143 ms |
| Witness encoding | 0.277 ms | 0.387 ms | 0.997 ms | 6.222 ms |
| Serialized proof | 805 B | 805 B | 939 B | 939 B |
| Proof steps | 6 | 6 | 7 | 7 |

Step histogram:

- 18 proofs had 6 steps.
- 14 proofs had 7 steps.

The proof-sampling peak observed heap was 72,313,272 bytes. The circuit used the boundary
sample at dataset index 0, which had 7 proof steps and fit the pinned 8-step bound.

These millisecond measurements are for the CCL MPF authentication proof. They are distinct
from the Groth16 proof generated from the symbolic circuit below.

## Complete current-root proof-depth scan

After the original sampled benchmark, a streaming traversal measured the branch-step depth of
every inclusion path under the exact five-million-entry root. The scanner follows CCL's proof
semantics: compressed extension prefixes are folded into the next branch record, so only
branch nodes increase an inclusion proof's step count. A 100-entry correctness test compared
the scanner histogram against every decoded CCL wire proof before the large scan was accepted.

| Proof steps | Entries | Share |
|---:|---:|---:|
| 5 | 129 | 0.002580% |
| 6 | 2,589,301 | 51.786020% |
| 7 | 2,318,120 | 46.362400% |
| 8 | 92,232 | 1.844640% |
| 9 | 218 | 0.004360% |

An 8-step circuit therefore accepts 4,999,782 of these paths (99.995640%) but rejects 218.
A 9-step circuit covers this exact current root. Neither number is a permanent entry-count
guarantee: later insertions or adversarially selected keys can change the maximum.

The complete scan visited 6,683,882 current-root nodes in 562.235 seconds (9m 22.235s), at
11,888 nodes/s, with 1,263,677,352 bytes peak observed Java heap. It streamed from RocksDB and
did not materialize the trie or five million keys in heap.

The preserved versioned roots also provide an exact dataset-specific depth ladder:

| Entries at root | Maximum steps | Scan time | Step histogram |
|---:|---:|---:|---|
| 1,000 | 5 | 0.404 s | 3: 573; 4: 407; 5: 20 |
| 10,000 | 6 | 1.432 s | 3: 47; 4: 7,113; 5: 2,779; 6: 61 |
| 20,000 | 6 | 1.833 s | 3: 1; 4: 10,227; 5: 9,401; 6: 371 |
| 100,000 | 7 | 10.292 s | 4: 3,497; 5: 78,122; 6: 18,164; 7: 217 |
| 1,000,000 | 8 | 86.836 s | 5: 121,519; 6: 772,682; 7: 105,043; 8: 756 |
| 5,000,000 | 9 | 562.235 s | 5: 129; 6: 2,589,301; 7: 2,318,120; 8: 92,232; 9: 218 |

These are measurements of the deterministic seed-25 history, not universal capacities for
all key sets of the same size. The Poseidon key digest makes honest paths approximately
balanced, but its scalar-field output is not literally uniform over all 256-bit strings and
an untrusted caller can grind candidate keys for shared prefixes.

## Historical generic circuit and Groth16 result

| Metric | Result |
|---|---:|
| Circuit fingerprint | `c17399380-w37718764-p1` |
| Constraints | 17,399,380 |
| Wires | 37,718,764 |
| Public inputs | 1 (the MPF root) |
| Declared private inputs | 681 |
| Circuit graph build | 3.058 s |
| R1CS compilation | 23.504 s |
| Witness circuit rebuild | 1.747 s |
| Witness calculation | 17.291 s |
| Sparse store-backed local setup | 895.707 s (14m 55.707s) |
| Key loading | 2.897 ms |
| Groth16 proof generation | 213.826 s (3m 33.826s) |
| Positive off-chain pairing verification | 153.868 ms |
| Mutated-root off-chain rejection | 148.395 ms |
| Compressed Groth16 proof | 192 B |
| Compressed Cardano verification key | 432 B |
| Sparse key-store bytes | 10,269,150,876 (approximately 9.56 GiB) |
| Peak observed Java heap | 13,175,385,008 bytes (approximately 12.27 GiB) |
| Circuit-stage wall time | 1,155.970 s (19m 15.970s) |
| Gradle invocation wall time | 19m 18s |

The generated proof passed independent pairing verification. Incrementing the public MPF
root by one field element caused verification to fail, establishing that the public root is
actually bound into the proof.

This Groth16 timing applies specifically to the 8-step circuit and selected 7-step witness.
It does not prove that every entry under the five-million-entry root fits that circuit; the
complete scan above establishes that 218 do not.

Setup provenance was
`single-party-fixed-toxic-waste-benchmark-only/sparse-store`. These keys must not be used for
production funds or credentials.

## Historical generic Cardano/Julc verification

The exact proof and verification key emitted by the five-million-entry circuit were loaded by
`PoseidonMpfCardanoArtifactTest` and evaluated in the Julc Plutus V3 VM path. The real proof
passed and the mutated root failed.

| Metric | Result |
|---|---:|
| Julc VM budget | CPU 2,627,770,348; memory 177,749 |
| Cold host-side VM evaluation | 375.406 ms |
| Warm positive host-side VM evaluation | 3.162 ms |
| Warm mutated-root rejection | 2.979 ms |

The cold/warm wall times describe this host and JVM. The execution budget is the relevant
ledger-style measure and still needs comparison against the selected network's live protocol
parameters in the deployment test. No Yaci DevKit transaction or public testnet transaction
was submitted by this benchmark.

## Reuse commands

Run these commands from the repository root. They reuse the preserved database and the
ADR-0042 S9 operation-specific key; they do not rebuild five million entries. Always pass the
absolute work directory because Gradle runs the application from its module directory.

```bash
POSEIDON_MPF_BENCH_DIR="$(pwd)/.benchmark-data/poseidon-mpf-5m"

./gradlew :zeroj-mpf-poseidon-load:run \
  --args="--stage=proofs --work-dir=$POSEIDON_MPF_BENCH_DIR --entries=5000000 \
  --samples=32 --max-steps=9 --rocksdb-profile=high-throughput"

./gradlew :zeroj-mpf-poseidon-load:run \
  --args="--stage=depth-scan --work-dir=$POSEIDON_MPF_BENCH_DIR --entries=5000000 \
  --progress-every=500000 --rocksdb-profile=high-throughput"

./gradlew :zeroj-mpf-poseidon-load:run \
  --args="--stage=circuit --work-dir=$POSEIDON_MPF_BENCH_DIR --entries=5000000 \
  --samples=32 --max-steps=9 --circuit-trials=3 --setup=load \
  --keys-dir=$POSEIDON_MPF_BENCH_DIR/groth16-keys-release-v2-s9 \
  --rocksdb-profile=high-throughput --allow-insecure-setup=true"

MPF_ARTIFACT_BUNDLE="$(jq -r \
  '.["circuit-s9"].cardanoArtifactsDirectory' \
  "$POSEIDON_MPF_BENCH_DIR/report.json")"
test -d "$MPF_ARTIFACT_BUNDLE"

./gradlew \
  -Dzeroj.poseidonMpf.cardanoArtifacts="$MPF_ARTIFACT_BUNDLE" \
  :zeroj-onchain-julc:test \
  --tests com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator.PoseidonMpfCardanoArtifactTest
```

`--setup=load` is important for reuse. It fails if the key manifest does not match the exact
R1CS SHA-256. `--setup=store` intentionally refuses to overwrite an existing key directory.
The Julc property must identify the final `bundle-*` leaf, whose ancestors bind template,
exact circuit fingerprint, and VK identity.

## ADR-0042 CCL dev1 compatibility and profile-label migration

On 2026-08-02, the preserved database was reopened under the repository-wide CCL
`0.8.0-pre5-dev1` baseline. The one-time `migrate-profile` operator stage verified the
recorded root, stored values, CCL proofs, and ZeroJ reference verification for 32
deterministic samples before changing metadata. It then backed up the original manifest,
changed the unreleased profile alias to `zeroj-poseidon-mpf-v1`, updated the CCL and complete
Poseidon-parameter fingerprints, reopened the database, and repeated the same checks.

| Compatibility check | Result |
|---|---:|
| Root before and after | `5988af1bdc5883f6cf67b748c85b7fa32de9e4cbf309d971288d86d6d1129ad8` |
| Deterministic samples | 32 |
| Pre-migration root/value/proof pass | 0.807 s |
| Post-migration root/value/proof pass | 0.470 s |
| Serialized proof digests unchanged | yes |
| RocksDB nodes/roots rewritten | no |
| Original metadata backup | `.benchmark-data/poseidon-mpf-5m/manifest.pre-adr0042-v2.json` |

The original load, proof, setup, Groth16, and Cardano measurements earlier in this report
remain CCL `0.8.0-pre4` measurements; this compatibility note does not relabel their
provenance. The old `v2` string was an unreleased metadata alias, not a different root
algorithm. Normal opens now reject it, so migration is explicit and auditable rather than a
silent runtime alias.

## ADR-0042 operation-specific rerun

After migration, the preserved root was reopened with CCL `0.8.0-pre5-dev1` and the new
inclusion primitive. Thirty-two deterministic native proofs again passed strict CCL-profile
verification and mandatory witness normalization.

The fresh S9 run recorded Git revision
`98c303176df01c7aff7fe9bb51502e1278b3e758` from a deliberately dirty ADR-0042 working tree,
with source-tree SHA-256
`292ea2637cb7b8aeaae00f87e3cfeda7e895b1a25477b35fce1a3d2a0c3eaafb` and 105 untracked
source files. These values are preserved in `circuit-s9Provenance`; they prevent the benchmark
from being misrepresented as a clean release build.

| Native path metric | Minimum | Median | p95 | Maximum |
|---|---:|---:|---:|---:|
| Proof generation | 5.945 ms | 6.351 ms | 8.701 ms | 17.333 ms |
| Proof verification | 2.989 ms | 3.204 ms | 4.527 ms | 6.266 ms |
| Verified witness normalization | 3.084 ms | 3.347 ms | 4.451 ms | 6.621 ms |
| Serialized proof | 805 B | 805 B | 939 B | 939 B |

The fresh circuit measurements use one packed public digest, three timed proof/verification
trials, separate exact-fingerprint key directories, and the known benchmark-only setup.
Timings below are medians.

| Profile | Constraints / wires | Exact R1CS SHA-256 | Setup | Prove | Verify / reject | Peak heap / RSS |
|---|---:|---|---:|---:|---:|---:|
| S8 | 50,768 / 283,384 | `e3a9fe7f2bcce454395a5bb0f2fac12e3fd99065d6b6c82325d7cdce16c1b74c` | 2.349 s | 3.999 s | 115.560 / 114.201 ms | 2.772 / 3.258 GB |
| S9 | 56,635 / 316,949 | `540279f349be215c837245a888934dd507bbfecf21c4a66146a3febcd33d427d` | 2.421 s | 4.173 s | 119.222 / 114.560 ms | 2.733 / 3.297 GB |
| S12 | 74,236 / 417,644 | `84975e990f84da821650147a9e6b8f5fdd2b67b20ce06c31ecb490411915bf00` | 2.961 s | 4.489 s | 117.807 / 118.152 ms | 2.868 / 3.445 GB |

Every row produced a 192-byte proof and 432-byte Cardano VK. Positive proofs verified and a
mutated public root was rejected. On 2026-08-03, one retained multi-bundle
artifact-bundle-v2 test invocation loaded S8, S9, and S12, recomputed every nested identity,
passed all three positive Julc evaluations, and rejected all three mutated roots. Every profile
used the same ledger-style budget (CPU 2,627,770,348; memory 177,749); warm host VM evaluation
was 2.134–2.277 ms in the final run. These current figures replace the historical generic circuit for
planning purposes, while leaving the original result above as reproducibility evidence.

S8 still misses the 218 known 9-step paths. S9 is the smallest measured profile that covers
this exact five-million-entry root; S12 provides headroom but is not a permanent capacity
guarantee. Each deployed profile needs its own reviewed R1CS/VK and production ceremony.

## Production conclusion

The answer to the storage-scaling question is **yes** for the measured architecture: five
million entries can remain off-chain in CCL RocksDB, while a real inclusion path is converted
to a fixed-bound symbolic circuit, proved with Groth16, and verified through the Cardano VM
path. With ADR-0042 the measured S9 proof takes about 4.17 seconds, rather than the historical
generic circuit's 3.5 minutes. The stronger statement "the 8-step circuit supports every
entry in a 5M MPF" remains false for this root. Exact all-entry coverage requires at least 9
steps here, or an explicit larger-profile/fallback policy.

The main operational costs observed here are linear off-chain build time and substantial
one-time circuit setup/proving resources. On-chain proof and verification-key sizes do not
scale with the number of MPF entries.

Before calling the feature production-ready, complete all of the following:

1. select the deployed operation/profile, freeze its full exact R1CS SHA-256 and VK identity,
   and generate or import a reviewed production setup for that exact circuit; never reuse
   either the historical `c17399380-w37718764-p1` key or the retained ADR-0042 benchmark keys;
2. complete cryptographic and circuit-semantics review, including the MPF v1 hash domains and
   raw-key/value binding policy;
3. select a bound using the complete scan, enforce or monitor it across later updates, and
   define over-bound routing; the current 8-step profile misses 218 paths;
4. run Yaci DevKit and target-network tests with current protocol parameters; and
5. define backup, compaction, corruption recovery, monitoring, and rebuild procedures for the
   off-chain RocksDB state.

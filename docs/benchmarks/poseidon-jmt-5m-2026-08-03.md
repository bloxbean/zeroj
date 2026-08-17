# Poseidon JMT five-million-entry benchmark — 2026-08-03

This report records the ADR-0042 scale run for the CCL-backed Poseidon JMT host and the
operation-specific ZeroJ inclusion circuit. It complements the historical
[MPF benchmark](poseidon-mpf-5m-2026-08-02.md) and the
[authenticated-state profile](../merkle/poseidon-authenticated-state-v1.md). Application
selection and deployment guidance is in the
[practical large-state guide](../merkle/practical-large-state-guide.md).

## Outcome

The measured path works end to end:

```text
5,000,000 deterministic entries in a versioned RocksDB JMT
        |
        v
CCL 0.8.0-pre5-dev1 native proof at version 5,000,000
        |
        v
strict proof verification and witness normalization
        |
        v
operation-specific Poseidon JMT inclusion circuit
        |
        v
192-byte Groth16 proof + 432-byte Cardano verification key
        |
        v
off-chain verification and Julc Plutus V3 VM verification
```

Five million entries therefore do not need to fit in circuit memory. The database remains
off-chain; circuit cost is determined by the fixed proof-level profile. For this exact
seed-42 root, 12 levels cover every entry. S8 covers 4,987,028 entries (99.74056%), S10 misses
32 entries, and S12 covers all 5,000,000. These are measured properties of this root, not
universal capacity promises for every future or adversarial key set.

This is a local engineering benchmark, not a production authorization. Its Groth16 keys use
a known, single-party benchmark trapdoor. External circuit review, a production setup for
each exact R1CS identity, and Yaci/target-network validation remain release gates.

### Published CCL pre5 compatibility update — 2026-08-04

The load and timings below retain their original `0.8.0-pre5-dev1` provenance. After published
CCL `0.8.0-pre5` became available, the tag comparison showed no changes below CCL's
`verified-structures/` subtree. The published pre5 build then reopened this preserved
dev1-manifest store without rewriting its manifest and generated and strictly verified the same 32
deterministic
object/wire proof samples against the recorded root. The sampled 6/7-level histogram and
2,744-3,161-byte wire range were unchanged. The refreshed raw `proofs` section records the pre5
run; the historical load, circuit, setup, and Julc measurements in this report are not relabelled.

## Preserved artifacts

The reusable database, reports, proving keys, and Cardano artifacts are retained at:

```text
.benchmark-data/poseidon-jmt-5m
```

The directory currently consumes about 3.0 GiB physically. It is ignored by Git and is
outside all Gradle `build/` directories, so `./gradlew clean` does not remove it. It is still
local benchmark state rather than a backup; deleting the workspace can destroy it.

## Configuration and provenance

| Setting | Value |
|---|---:|
| CCL used for the original measured load | `0.8.0-pre5-dev1` |
| Host profile | `zeroj-poseidon-jmt-v1` |
| Hash algorithm | `zeroj-poseidon-bls12-381-t3-a5-jmt-v1` |
| Poseidon parameter fingerprint | `4bf489f3a231cbdba3e9b8c2d21966e052bf9132b9ddf6529aa3f569297a8fc2` |
| Native proof codec | `ccl-classic-jmt-proof-cbor-v1` |
| Dataset seed | 42 |
| Entries / final version | 5,000,000 / 5,000,000 |
| Key/value bytes | 24 / 32 |
| Batch size | 5,000 |
| Pair-hash cache | 262,144 entries |
| RocksDB profile | high throughput, production durability options enabled |
| JVM heap | 4 GiB fixed maximum |
| Curve/proof system | BLS12-381 Groth16 |

Final root:

```text
1f2d236ccbcb0314b8dbaa3886d301d08e488a70374bfe4ead23ae492d2f14c2
```

The run used macOS 26.0.1 on `aarch64`, BellSoft OpenJDK 25.0.2, and 16 logical processors.
The recorded Git revision was `98c303176df01c7aff7fe9bb51502e1278b3e758`, but the ADR-0042
implementation was deliberately benchmarked from a dirty working tree. The original
load/depth/first-operations source-tree digest was
`5faa13e63a8ad413f77d7bc9e227842df3ce79d6f90cd40539d7c77029fd1fd8`; the
later proof/circuit digest was
`292ea2637cb7b8aeaae00f87e3cfeda7e895b1a25477b35fce1a3d2a0c3eaafb`.
The raw `manifest.json` and `report.json` retain commands, JVM arguments, run IDs, timestamps,
and per-stage source provenance.

## Load result

| Metric | Result |
|---|---:|
| Entries | 5,000,000 |
| Elapsed | 6,916.514 s (1h 55m 16.514s) |
| Throughput | 722.907 entries/s |
| Durable checkpoints | 1,000 |
| Latest version | 5,000,000 |
| Reported logical RocksDB bytes | 8,712,760,992 |
| Current complete workspace physical usage | approximately 3.0 GiB |
| Peak observed Java heap | 2,586,782,752 B |
| Peak observed process RSS | 5,839,634,432 B |
| Pair-cache hits / misses | 562,821,912 / 213,768,168 |
| Pending compaction bytes at completion | 0 |

Entries and batches are deterministic and restartable. The manifest is fsynced only after a
durable JMT commit, and reopening validates the stored version/root/profile before any later
stage proceeds.

## Exact all-entry proof-depth census

The scanner hashes every deterministic key, sorts the fixed-width digests, and derives the
nearest-neighbor longest-common-prefix depth. Tests cross-check this calculation against CCL
proofs; for this immutable manifest dataset the result is exact.

| Proof levels | Entries | Share |
|---:|---:|---:|
| 5 | 135 | 0.00270% |
| 6 | 2,589,073 | 51.78146% |
| 7 | 2,209,279 | 44.18558% |
| 8 | 188,541 | 3.77082% |
| 9 | 12,110 | 0.24220% |
| 10 | 830 | 0.01660% |
| 11 | 30 | 0.00060% |
| 12 | 2 | 0.00004% |

The scan took 463.621 s, including 463.331 s hashing. It used a 160,000,000-byte digest
buffer, peaked at 2,737,794,288 B observed Java heap and 3,747,381,248 B RSS, and found a
maximum of 12 levels.

Profile coverage for this root:

| Profile | Covered entries | Missing entries | Coverage |
|---|---:|---:|---:|
| S8 | 4,987,028 | 12,972 | 99.74056% |
| S10 | 4,999,968 | 32 | 99.99936% |
| S12 | 5,000,000 | 0 | 100% |

Later updates can change the distribution. A production service must monitor maximum depth
and define a larger-profile or rejection path before a proof exceeds its circuit bound.

## Native CCL proof path

Thirty-two deterministic samples were read from a freshly reopened database. Every proof
passed strict CCL-profile verification before normalization into a circuit witness.

| Metric | Minimum | Median | p95 | Maximum / average |
|---|---:|---:|---:|---:|
| Proof generation | 0.497 ms | 0.642 ms | 1.154 ms | 9.040 ms / 0.992 ms |
| Proof verification | 3.733 ms | 4.732 ms | 6.886 ms | 12.558 ms / 5.053 ms |
| Verified witness normalization | 6.427 ms | 7.004 ms | 8.785 ms | 11.419 ms / 7.292 ms |
| Native wire proof | 2,744 B | 2,881 B | 3,025 B | 3,161 B / 2,892 B |

Twenty samples used 6 levels and twelve used 7. Reopen time was 0.309 s; the stage peaked at
101,841,112 B heap and 360,611,840 B RSS. The native JMT proof is larger than MPF's compressed
path proof, but after Groth16 compression both structures produce the same 192-byte proof
size and the on-chain verifier does not process the native path.

## Operation-specific circuit and Groth16 results

All circuit rows use the inclusion primitive with one packed public digest and three timed
prove/positive-verify/negative-verify trials. Timings are medians. Each exact R1CS hash has a
separate proving-key directory and artifact identity.

| Profile | Constraints / wires | Exact R1CS SHA-256 | Setup | Prove | Verify / reject | Key store | Peak heap / RSS |
|---|---:|---|---:|---:|---:|---:|---:|
| S8 | 10,069 / 51,614 | `3f967bc5a1376ccbbddab7b1fe3fdf183e400be82d0171ef1342536fde18b73d` | 1.142 s | 2.856 s | 113.983 / 113.302 ms | 7,349,385 B | 2.563 / 3.073 GB |
| S10 | 12,063 / 63,116 | `28bd1f4c582bc8fac65e1449c4272b014a84b71a0f85f7c8d4b88a55602261fc` | 1.172 s | 2.911 s | 113.266 / 113.426 ms | 8,575,841 B | 2.586 / 3.077 GB |
| S12 | 14,057 / 74,618 | `9c4a1cade586c4013d9901ac33e299230aa362ef21262c8b8a8fd92043782e7e` | 1.306 s | 2.901 s | 114.414 / 114.890 ms | 9,802,457 B | 2.268 / 3.070 GB |
| S64 | 65,901 / 373,670 | `725996176f225f33ebbdb794902537c3bdd602c91cdaf257f3c5eb2fab79d6dd` | 2.947 s | 4.582 s | 115.174 / 114.635 ms | 52,787,949 B | 2.730 / 3.511 GB |

Every positive proof verified and every public-root mutation was rejected. Proof size was 192
bytes and the compressed Cardano verification key was 432 bytes for every row. The dramatic
reduction from the historical generic MPF circuit comes from operation specialization,
strict bounded encodings, and the shared optimized Poseidon gadget; it does not make setup
trusted or remove the need for review.

## Version operations and recovery

The operations stage was rerun after the release-safety hardening. It first validated and closed
the retained database, created a disposable file copy, and exercised every temporary mutation,
rollback, and reopen against only that copy. The retained five-million-entry head remained
`1f2d236ccbcb0314b8dbaa3886d301d08e488a70374bfe4ead23ae492d2f14c2`.

| Operation | Result |
|---|---:|
| Disposable database copy | 3,047,957,193 logical B in 13.272 ms |
| 1,000-entry update on copy | 2.988 s (334.699 entries/s) |
| Updated-version native proof | 0.936 ms, 3,025 B |
| Roll back copied temporary version | 1.885 s |
| Reopen copied database and verify original root/value | 0.099 s |
| Independent scratch prune | 2,114 records in 7.689 ms |

The copy timing is specific to this APFS host, where file cloning/copy-on-write can make a logical
3.05 GB copy very fast. Other filesystems may physically copy every byte. Production sizing must
reserve enough free space for a full independent copy and must not rely on this wall time. The
new operations provenance records dirty-tree SHA-256
`8a2e6c2b69ae9e621cf5595de54442c735aa2290c15778aae6e635fd783e0436` and the exact command.

The prune test intentionally used a small retained scratch database. RocksDB file bytes grew
from 555,396 to 709,118 during the immediate measurement because logical deletion does not
imply instant physical compaction; record count and version visibility are the correctness
signals.

## Cardano/Julc result

On 2026-08-03, one retained multi-bundle artifact-bundle-v2 test invocation loaded the exact
S8, S10, S12, and S64 proof/VK/manifests, recomputed every nested identity, and evaluated them
through the Julc Plutus V3 VM path. All four positive proofs passed and all four mutated roots
failed.

| Metric | Result |
|---|---:|
| Ledger-style Julc budget | CPU 2,627,770,348; memory 177,749 |
| Warm host-side VM evaluation | 2.239–3.046 ms |
| First cold host-side VM evaluation | 608.545 ms |

The host timing is machine/JVM-specific. The budget must still be checked against the target
network's current protocol parameters. The release factory also binds the exact circuit
manifest, R1CS/VK identities, fixed validator-template identity and SHA-256, Plutus V3 script
hash, typed Cardano network, state-token policy/name, authorized signer, and one-shot genesis
attestation. No Yaci or public-network transaction was submitted in this run.

## Reuse commands

Run from the repository root. Always use the absolute benchmark path; a relative path from a
module working directory would create a different database.

```bash
POSEIDON_JMT_BENCH_DIR="$(pwd)/.benchmark-data/poseidon-jmt-5m"

./gradlew :zeroj-jmt-poseidon-load:run \
  --args="--stage=proofs --work-dir=$POSEIDON_JMT_BENCH_DIR --entries=5000000 \
  --seed=42 --samples=32 --max-levels=12 --pair-cache=262144"

./gradlew :zeroj-jmt-poseidon-load:run \
  --args="--stage=depth-scan --work-dir=$POSEIDON_JMT_BENCH_DIR --entries=5000000 \
  --seed=42 --progress-every=100000"

./gradlew :zeroj-jmt-poseidon-load:run \
  --args="--stage=circuit --work-dir=$POSEIDON_JMT_BENCH_DIR --entries=5000000 \
  --seed=42 --samples=32 --max-levels=12 --circuit-trials=3 --setup=load \
  --keys-dir=$POSEIDON_JMT_BENCH_DIR/groth16-keys-release-v2-s12 \
  --allow-insecure-setup=true"

JMT_ARTIFACT_BUNDLE="$(jq -r \
  '.["circuit-s12"].cardanoArtifactsDirectory' \
  "$POSEIDON_JMT_BENCH_DIR/report.json")"
test -d "$JMT_ARTIFACT_BUNDLE"

./gradlew \
  -Dzeroj.poseidonJmt.cardanoArtifacts="$JMT_ARTIFACT_BUNDLE" \
  :zeroj-onchain-julc:test \
  --tests com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator.PoseidonJmtCardanoArtifactTest
```

`--setup=load` reuses the exact stored key. `--setup=store` refuses to overwrite an existing
key directory. `--allow-insecure-setup=true` is deliberately explicit because these retained
keys are benchmark-only.

## Production conclusion

For the measured architecture, JMT is practical for large off-chain, versioned state. Its
host-side advantages are fast proof generation, versioned roots, rollback, and pruning. Its
larger native proof no longer determines the on-chain payload once the path is hidden behind
a Groth16 proof. S12 is the smallest measured profile that covers every entry in this exact
five-million-entry root; S10 is a useful common fast path only if 32 over-bound entries have
an explicit fallback.

Production still requires:

1. an external security/circuit review of the exact operation and hash profile;
2. a production ceremony or approved imported key for every deployed exact R1CS/VK;
3. depth monitoring and an over-bound routing policy after every state update;
4. Yaci and target-network evaluation against current protocol parameters;
5. tested backup, corruption recovery, compaction, rollback-retention, and pruning policy;
6. deployment evidence for the one-shot, total-supply-one state-token invariant.

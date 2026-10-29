# Retained SHA-2 optimization evidence

Measured implementation: `e8947a6dd751fe490c5d2064cd9e83d848ce1b5c`.
Baseline: `3f1570f33ef2f45d26abeaf6085de5a2dc7a1c5e`.
Date: 2026-10-29. All witnesses are intentionally public ascending-byte fixtures.
All keys came from explicit insecure single-party development setup. Verification
keys are public; proving keys were temporary and removed by the runner.

The [results report](../../../docs/reviews/sha2-optimization-results.md) explains
performance, memory regressions, compatibility, security boundaries and limitations.
The [runner protocol](../README.md) documents fresh measurements. Its Java/Python
source was identical for baseline and candidate. Unrelated report edits during
measurement did not alter the recorded production/harness/runtime identities.

| Directory | Scope | Fresh JVMs | Independent checks |
|---|---|---:|---:|
| `comparison` | Pure Java, both hashes, 32/128/1024 bytes, 6g/8g, one warmup + three measured proofs | 24 | 192 |
| `memory-repeat` | SHA-512/1024, 6g, reversed baseline/candidate order, GC logging, same sample count | 2 | 18 |
| `timing-repeat` | SHA-512/128, 8g, one warmup + seven measured proofs | 2 | 26 |
| `blst-comparison` | Native proving backend, both hashes, 32/128 bytes, 6g/8g, one warmup + three measured proofs | 16 | 128 |
| `cardano` | Four new local DevKit spends of optimized 32-byte proofs, both hashes and heaps | 4 | Separate VM/ledger checks |

Each benchmark directory retains matrix controls, both prepared source/runtime
identity manifests, summary tables, every process result, raw JVM output, sampled
metrics, all randomized proofs, verification keys and invalid fixtures. The
`independent-verification/result.json` records the pinned snarkjs verdicts. In total,
184 valid randomized proofs were accepted and 180 invalid fixtures rejected.

`manifest.json` hashes every other retained file. The benchmark `process.json`
records additionally hash each artifact consumed by the independent verifier.
Absolute paths in execution records describe the measured host, not installation
requirements. Timings came from a shared host with existing background services;
there is no universal speed or memory improvement claim.

## Recheck the public proof vectors without setup

Install pinned snarkjs 0.7.6 using the existing optional bootstrap, or supply its
CLI path. Copy one retained matrix into a **new** ignored directory, excluding the
old verdicts so the verifier cannot silently reuse them:

```sh
python3 - <<'PY'
from pathlib import Path
import shutil
source = Path('assurance/sha2-optimization/evidence/comparison')
target = Path('assurance/sha2-optimization/build/recheck-comparison')
shutil.copytree(source, target,
                ignore=shutil.ignore_patterns('independent-verification'))
PY
python3 -B assurance/sha2-optimization/run.py verify \
  assurance/sha2-optimization/build/recheck-comparison \
  --snarkjs assurance/sha2-circom/node_modules/snarkjs/build/cli.cjs
```

Repeat with the other three benchmark directory names to recheck all 364 cases.
No private data, setup or proving key is required. The verifier checks artifact
hashes, complete SHA digests and expected accept/reject results; a tool crash does
not count as a valid rejection.

## Reproduce the diagnostic repeats

Use fresh output directories and the baseline worktree described in the runner
README. The primary matrix used defaults. The native comparison used
`--lengths 32 128 --backends blst --heaps 6g 8g`. Timing-repeat controls were:

```sh
python3 -B assurance/sha2-optimization/run.py run \
  --baseline ../zeroj-sha2-baseline --candidate . \
  --heaps 8g --algorithms SHA-512 --lengths 128 --samples 7 \
  --output assurance/sha2-optimization/build/new-timing-repeat
```

The memory repeat used `--heaps 6g --algorithms SHA-512 --lengths 1024`, default
three measured proofs, and this additional JVM option via `JAVA_TOOL_OPTIONS`:

```text
-Xlog:gc*:file=/tmp/sha2-gc-%p.log:time,uptime,pid,level,tags
```

Its one profile runs baseline first, reversing the original primary matrix's
candidate-first order for that profile. `gc-baseline.log` and `gc-candidate.log`
are exact copies of the two measured 6 GiB JVM logs; original identities and
interpretation are in the [memory review](../../../docs/reviews/sha2-optimization-memory-review.md).
GC logging changes the protocol, so this is a separate diagnostic result.

## Cardano reproduction boundary

The Cardano integration uses the existing separate `sha2-groth16-cardano-poc`
research workspace, **not a bundled submission runner**. Its source/runtime hashes
and exact toolchain versions are in `cardano/provenance.json`. The verifier,
validator and codec source were checked byte-for-byte against this PR. The toolchain
is JuLC pre20/CCL pre7; the ZeroJ default build instead uses pre18/pre5.

With that research workspace and its local Yaci DevKit running, compile its
`cardano/pom.xml` and launch `org.zeroj.sha2.cardano.CardanoBench` with:

1. `-Xmx6g` or `-Xmx8g`, eight visible processors and native access enabled;
2. the matching retained `comparison/<heap>/pure-java/sha256-32/candidate/artifacts`
   (or `sha512-32`) directory;
3. a new output directory.

The complete Java command and confirmed heap setting are in each Cardano
`process.json`/`stderr.txt`. Each run retains signed transaction CBOR, applied
script, compressed proof, public statement, VM checks, Haskell cost result,
rejected-submission records and confirmed local transaction IDs. Replaying a
signed transaction after its UTxO has been spent is not a fresh ledger test;
build a new local transaction with the runner. Wallet secrets are not retained.

All four cases confirmed valid spends, rejected eight VM negatives and two signed
invalid transactions, and matched Java/backend/Haskell budgets. Fees and sizes
matched the earlier baseline. Parameters are a retained local snapshot, not a
promise of future mainnet prices. The generic preimage validator does not provide
application authorization, replay protection or private-state policy by itself.

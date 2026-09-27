# Streaming Groth16 import timing — PR #61 review

Measured on 2026-09-27 on an Apple M4 Max (16 available processors, 128 GiB RAM),
macOS/aarch64, Liberica OpenJDK 25.0.2+12-LTS, `-Xms1g -Xmx1g`. These measurements use
PR #61's review changes based on `167bc8d`; the subgroup predicate is unchanged from that
commit. Other development jobs were active on the host. These are local observations, not
release performance guarantees.

**The 19M-constraint ownership import has not been measured.** No such `.zkey` was available
in the inspected checkout, and its path and trusted hash have been requested. Do not report
the extrapolation below as an actual finalize run. Full-scale wall time, CPU time, peak RSS,
temporary disk use and storage throughput remain evidence to collect under #48.

## Predicate measurement

[SubgroupImportTiming.java](SubgroupImportTiming.java) checks 512 distinct non-infinity public
points per group using the same on-curve plus Jacobian multiply-by-r predicate as the importer.
Point construction is excluded. One thread executes three warmup passes followed by five
measured passes. CPU time is current-thread CPU time; wall time includes scheduling and GC.

| Pass | G1 wall ms/point | G1 CPU ms/point | G2 wall ms/point | G2 CPU ms/point |
|---|---:|---:|---:|---:|
| 1 | 0.5051 | 0.5044 | 1.4732 | 1.4684 |
| 2 | 0.5121 | 0.5113 | 1.4955 | 1.4840 |
| 3 | 0.5143 | 0.5121 | 1.4902 | 1.4867 |
| 4 | 0.5111 | 0.5091 | 1.4760 | 1.4715 |
| 5 | 0.5225 | 0.5221 | 1.4956 | 1.4908 |
| Median | 0.5121 | 0.5113 | 1.4902 | 1.4840 |

Using the reviewer's **assumed** 70–90 million non-infinity G1 points and 19 million G2 points,
these median CPU costs imply about **64–74 thousand core-seconds** for point validation alone.
Dividing by 16 gives an idealized **1.1–1.3 hours**; this is not a wall-time prediction. It assumes
perfect scaling across heterogeneous cores and excludes decoding, copies, hashing, I/O,
allocation/GC interference and other import work. Actual point counts have not been measured
from the ownership key. An import that skips subgroup validation is not an acceptable faster
alternative. Future optimization must preserve the predicate and be independently qualified.

Reproduce from the repository root (set `CEREMONY_JAR` to the fat jar produced by the build):

```bash
./gradlew :zeroj-tools:fatJar
export CEREMONY_JAR=zeroj-tools/build/libs/zeroj-ceremony-<version>-all.jar
TIMING_CLASSES=$(mktemp -d)
javac -cp "$CEREMONY_JAR" -d "$TIMING_CLASSES" docs/benchmarks/SubgroupImportTiming.java
java -Xms1g -Xmx1g -cp "$TIMING_CLASSES:$CEREMONY_JAR" org.zeroj.benchmarks.SubgroupImportTiming
```

## Small complete import

The checked-in `zeroj-crypto/src/test/resources/test-circuits/multiplier-bls381/multiplier.zkey`
is 3,652 bytes (4 wires, 1 public input, domain 4), SHA-256
`9839919f7951828d2c4ac8af231ab640ca2ade07fa9b834c872cc36512dc6252`.
Three fresh JVM CLI runs with `-Djava.util.concurrent.ForkJoinPool.common.parallelism=15`
and a new output directory each completed with:

| Run | Process wall s | User CPU s | System CPU s | Peak RSS bytes |
|---|---:|---:|---:|---:|
| 1 | 0.16 | 0.27 | 0.03 | 107757568 |
| 2 | 0.16 | 0.27 | 0.03 | 108625920 |
| 3 | 0.16 | 0.27 | 0.03 | 108199936 |

The CLI rounded import time to 0.1 s in each run. All returned manifest SHA-256
`96d4a699cfadbc7407d56a7b39cc44cad76ce4f0a9e7d5a4d943f6cc939dc8b8` (unbound circuit metadata).
This tiny, cached-input experiment mostly measures startup; it cannot establish large-key
throughput or memory use. The fixture is test material, not a production ceremony artifact.

For a full-size run, obtain `VERIFIED_ZKEY_SHA256` through a trusted verification process,
provide the matching key path as `VERIFIED_ZKEY`, and use a **new** `NEW_PK_STORE` directory:

```bash
# macOS time; on Linux use /usr/bin/time -v instead of -lp.
/usr/bin/time -lp java -Xms1g -Xmx1g \
  -Djava.util.concurrent.ForkJoinPool.common.parallelism=15 \
  -jar "$CEREMONY_JAR" finalize --sha256 "$VERIFIED_ZKEY_SHA256" \
  --zkey "$VERIFIED_ZKEY" --pk-store "$NEW_PK_STORE"
```

Record the revision, JDK/OS/CPU, heap and worker settings, source hash/size, exact circuit
fingerprint, counts of non-infinity points, output manifest pin, disk configuration, peak
space, process CPU/wall time and peak RSS. Include `--circuit-fingerprint` when that verified
metadata is available. Keep source and mapped store directories protected from concurrent
mutation throughout verification/import/proving. Performance evidence does not establish
ceremony trust or production readiness.

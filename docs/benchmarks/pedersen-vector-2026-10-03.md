# Pedersen vector commitments — end-to-end measurements (ADR-0051 M3)

**Date:** 2026-10-03
**Harness:** `PedersenVectorBenchmark`, run in its own JVM with
`./gradlew :zeroj-integration-tests:pedersenVectorBenchmark` (dev trusted setup).
**Machine:** Apple M4 Max (arm64, 16 processors), macOS, Java HotSpot 25.0.2, 2 GB max heap.

Each circuit commits to `n` values of 64 bits under a bound schema: the schema-digest public
input, decompositions, canonical blinding, the multi-scalar sum and the affine `(u, v)` public
binding. Times are medians of 7 runs after 3 warm-up runs; proving is the pure-Java Groth16
prover. The heap columns show the live heap after an explicit collection just before proving,
and how far the heap peak rose above that during proving.

| n | rows | nonzeros | domain | witness median (ms) | prove median (ms) | live heap before prove (MB) | peak heap growth during prove (MB) |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 2,411 | 11,686 | 4,096 | 0.9 | 1,181.5 | 9 | 634 |
| 4 | 3,581 | 17,755 | 4,096 | 0.8 | 1,248.3 | 13 | 640 |
| 16 | 8,261 | 42,031 | 16,384 | 1.7 | 1,573.2 | 26 | 675 |

## Reading

- At these sizes proving cost is dominated by a fixed overhead of about 1.2 s and 630 MB of
  transient heap that does not depend on the circuit. Going from `n = 1` to `n = 16` adds about
  3.4× the rows but only about 33% to proving time. A constraint-count reduction would therefore
  not translate proportionally into end-to-end time, which is the point of this gate.
- Each additional 64-bit value costs about 390 rows. The `n = 16` circuit crosses into a
  16,384 domain.
- The fixed prover overhead is a property of the pure-Java prover, not of this profile. It is
  recorded here as an observation for the prover work (ADR-0029/0033), not addressed by ADR-0051.

These numbers record behaviour on one machine. They are not a performance claim.

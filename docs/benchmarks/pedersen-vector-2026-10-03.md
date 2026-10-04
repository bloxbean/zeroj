# Pedersen commitments — end-to-end measurements (ADR-0051 M3 and M4)

**Date:** 2026-10-03
**Harness:** `PedersenVectorBenchmark`, run in its own JVM with
`./gradlew :zeroj-integration-tests:pedersenVectorBenchmark` (dev trusted setup).
**Machine:** Apple M4 Max (arm64, 16 processors), macOS, Java HotSpot 25.0.2, 2 GB max heap.

Each vector circuit commits to `n` values of 64 bits under a bound schema: the schema-digest
public input, decompositions, canonical blinding, the multi-scalar sum and the affine `(u, v)`
public binding. The confidential-note circuit is the M4 reference application: three
`pedersen-jubjub-v1` commitments (one input, two outputs; 64-bit amounts, 252-bit blindings) bound
to six public inputs, plus `assertBalanced`. Times are medians of 7 runs after 3 warm-up runs; proving is the pure-Java Groth16
prover. The heap columns show the live heap after an explicit collection just before proving,
and how far the heap peak rose above that during proving.

| circuit | rows | nonzeros | domain | witness median (ms) | prove median (ms) | live heap before prove (MB) | peak heap growth during prove (MB) |
|---|---:|---:|---:|---:|---:|---:|---:|
| vector n = 1 | 2,411 | 11,686 | 4,096 | 1.0 | 1,160.0 | 9 | 634 |
| vector n = 4 | 3,581 | 17,755 | 4,096 | 0.9 | 1,225.0 | 13 | 640 |
| vector n = 16 | 8,261 | 42,031 | 16,384 | 1.7 | 1,530.0 | 26 | 675 |
| confidential note (1 in, 2 out) | 8,755 | 40,384 | 16,384 | 1.6 | 2,039.7 | 21 | 657 |
| confidential note, after the value-canonicality optimization | 7,231 | 35,053 | 8,192 | 1.6 | 1,781.5 | 19 | 650 |

(Re-run 2026-10-04 with the M4 circuit added; the vector rows agree with the first run within a
few percent. The last row is from a later run of the same harness after `ZkPedersen` stopped
emitting the 252-bit comparator for values narrower than 252 bits; vector rows in that run were
within 1% of those above.)

## Reading

- At these sizes proving cost is dominated by a fixed overhead of about 1.2 s and 630 MB of
  transient heap that does not depend on the circuit. Going from `n = 1` to `n = 16` adds about
  3.4× the rows but only about 33% to proving time. A constraint-count reduction would therefore
  not translate proportionally into end-to-end time, which is the point of this gate.
- Each additional 64-bit value costs about 390 rows. The `n = 16` circuit crosses into a
  16,384 domain.
- The confidential note had about the same rows as `n = 16` but proved about 0.5 s slower: it
  carries three full-width blindings and three commitments' worth of witness wires.
- Dropping the redundant value comparator (about 508 rows per commitment) took the confidential
  note under the 8,192 domain boundary: 8,755 → 7,231 rows, and 2.04 s → 1.78 s to prove (about
  13% in this harness). Most of the remaining time is the fixed prover overhead noted above.
- On-chain verification costs are separate and measured in the Julc VM: 3.66×10⁹ CPU / 0.56M mem
  for the confidential-note validator and 3.07×10⁹ CPU / 0.40M mem for the vector consumer.
- The fixed prover overhead is a property of the pure-Java prover, not of this profile. It is
  recorded here as an observation for the prover work (ADR-0029/0033), not addressed by ADR-0051.

These numbers record behaviour on one machine. They are not a performance claim.

# ElGamal on Jubjub and threshold key generation — host measurements (ADR-0052, ADR-0053)

**Date:** 2026-10-05
**Harness:** `ElGamalBenchmark`, run in its own JVM with
`./gradlew :zeroj-circuit-lib:elgamalBenchmark`.
**Machine:** Apple M4 Max (arm64, 16 processors), macOS, Java 25.0.2, 2 GB max heap.

These numbers are evidence for this JVM and CPU only. They record throughput and make no
timing-side-channel claim. Secret operations are compatibility/offline class (ADR-0039).

## Host operations

| Operation | µs/op |
|---|---:|
| Point decode (`JubjubPoint.fromBytes`, no subgroup check) | 38 (185 before the Tonelli–Shanks change) |
| Subgroup check, `BigInteger` (`JubjubPoint.isInSubgroup`) | 960 |
| Subgroup check, Montgomery fast path (public data) | 85 |
| Ciphertext decode (64 bytes, two subgroup checks) | 221 (523 before) |
| Encrypt (three blinded secret multiplications) | 4,700 |
| Decryption share (one blinded secret multiplication) | 1,650 |
| Homomorphic sum, per ciphertext (2,000-term `sum`) | 1.6 |

The secret multiplications use the fixed 316-iteration blinded schedule of ADR-0038. They
dominate encryption and share computation, which are client-side and once per ballot or tally.
Public-data work (decoding, subgroup checks, sums, verification equations, search) runs on
Montgomery limbs.

## Bounded discrete log (baby-step giant-step)

| Bound | Table build | Solve, random `t` | Solve, `t = bound` (worst case) |
|---|---:|---:|---:|
| `2^16` | 0.3 ms | 0.2 ms | 0.2 ms |
| `2^24` | 1.6 ms | 1.8 ms | 1.6 ms |
| `2^32` | 21 ms | 7 ms | 19 ms |
| `2^40` | 108 ms | 551 ms | 819–904 ms |

The default caps (`2^18` baby steps, about 6 MiB of table, and `2^24` giant steps) reach bounds
near `2^43`. A table is immutable and reusable across decryptions.

## Threshold key generation (all `n` participants in one JVM)

| `(t, n)` | Whole run | Per participant |
|---|---:|---:|
| (1, 3) | 62 ms | 21 ms |
| (2, 5) | 176 ms | 35 ms |
| (3, 7) | 346 ms | 49 ms |
| (5, 11) | 963 ms | 88 ms |
| (10, 21) | 4,503 ms | 214 ms |

Each participant does the following:
- deals `2(t + 1)` blinded commitments;
- decodes and subgroup-checks every broadcast point;
- checks `n − 1` received pairs with equations (4) and (5), whose right-hand sides it evaluates
  by Horner's rule with a small multiplier;
- recomputes the public rules and every `Y_j`, by Horner over the coefficient-wise sum of the
  extraction vectors.

ADR-0053 estimated this work as host-side only; these figures confirm it. The ballot circuit and
its proofs are unchanged.

## In-circuit relations (rows)

| Circuit | Rows |
|---|---:|
| Encryption, width 1, verifier-fixed key | 6,558 |
| Encryption, width 16 | 6,650 |
| Encryption, width 64 | 6,938 |
| Encryption, width 1, key witnessed in the subgroup | 12,105 |
| DLEQ (possession or decryption share) | 6,546 |

These counts are pinned in `ZkElGamalTest`. Groth16 proving at this size takes about 1–2 s
with the pure-Java prover (compare the Pedersen measurements of 2026-10-03).

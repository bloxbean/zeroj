# Encrypted DKG share delivery (`dkg-share-delivery-hpke-v1`): host measurements (ADR-0054)

**Date:** 2026-10-09
**Harness:** `ElGamalBenchmark.dkgShareDelivery`, run in its own JVM with
`./gradlew :zeroj-circuit-lib:elgamalBenchmark --tests '*ElGamalBenchmark.dkgShareDelivery'`.
**Machine:** Apple M4 Max (arm64), macOS, Oracle GraalVM JDK 25.0.2 (JIT, not native image).

These numbers are evidence for this JVM and CPU only. They record throughput and make no
timing-side-channel claim. X25519, HKDF and ChaCha20-Poly1305 are the JDK providers (SunEC,
SunJCE); secret operations are compatibility/offline class (ADR-0039).

## Per envelope

| Operation (100-byte `SHARE`) | µs/op |
|---|---:|
| `SealBase`: ephemeral key, DH, key schedule, AEAD | 114 |
| `OpenBase`: DH, key schedule, AEAD, recipient's public key supplied | 59 |
| Announcement small-order probe (one X25519) | 54 |

Sealing needs two X25519 operations: the ephemeral public key and the DH. Opening needs one,
because `closeRound1` passes the recipient's known public key. An earlier version that
recomputed it cost 111 µs per open. The harness calls the `byte[]` overload, which also rebuilds
the provider private key on every open. `closeRound1` builds it once per round, so the row is an
upper bound for production.

## Per participant and per run

Each participant:
- seals `n − 1` envelopes and opens `n − 1`;
- runs the probe on up to `n` announcements;
- runs two platform self-tests, one seal and one open each, in `start` and `closeRound1`
  (ADR-0054 implementation note 7).

The delivery work per participant is therefore about
`(n − 1) · 0.17 ms + n · 0.05 ms + 0.35 ms`:

| `n` | Delivery work per participant (computed from the table above) |
|---:|---:|
| 3 | ≈ 0.9 ms |
| 7 | ≈ 1.8 ms |
| 21 | ≈ 4.9 ms |
| 64 | ≈ 15 ms |

Whole encrypted runs, with all `n` participants in one JVM, measured against plain runs on the same
dealings. These were measured before the self-tests were added; they add about 0.35 ms per
participant, well inside the run-to-run noise:

| DKG (t, n) | Plain run | Encrypted run |
|---|---:|---:|
| (1, 3) | 45 ms | 48 ms |
| (2, 5) | 144 ms | 129 ms |
| (3, 7) | 298 ms | 279 ms |
| (5, 11) | 766 ms | 764 ms |
| (10, 21) | 3,819 ms | 3,540 ms |

The difference is within run-to-run noise. The threshold key generation's own work (blinded
dealing, VSS checks, recomputation) dominates, and the two harnesses differ slightly in overhead.
The board cost is `n(n − 1)` envelopes of 223 bytes per attempt plus `n` announcements of 106
bytes: about 0.9 MB of envelopes at `n = 64`.

## GraalVM native image

`HpkeNativeProbe` (in `zeroj-circuit-lib` test sources) compiled with `native-image` 25.0.2
(`--no-fallback`; about 19 s build) prints exactly the JVM's output:
- the RFC 9180 A.2.1 values;
- all 257 sequence ciphertexts (by digest);
- the RFC 7748 §6.1 public key;
- the small-order refusals.

No `META-INF/native-image` configuration was needed.

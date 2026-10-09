# Confidential notes on Jubjub (`confidential-note-jubjub-v1`): host and on-chain measurements (ADR-0055)

**Date:** 2026-10-09
**Harness:**
- Host: `ConfidentialNoteBenchmark.matrix`, run with `./gradlew :zeroj-circuit-lib:confidentialNoteBenchmark`.
- On-chain D3a: `AuditedConfidentialNoteOnChainTest`. The direct layout runs with
  `./gradlew :zeroj-integration-tests:test --tests '*AuditedConfidentialNote*'`. The
  hash-compressed layout is tagged `heavy` and runs with
  `./gradlew :zeroj-integration-tests:heavyTest --tests '*AuditedConfidentialNote*'`.

**Machine:** Apple M4 Max (arm64, 16 cores), macOS, Oracle GraalVM JDK 25.0.2 (JIT, not native
image), 2 GB heap for the host matrix.

These numbers are evidence for this JVM and CPU only. They record throughput and allocation, and
make no timing-side-channel claim. Every secret operation is compatibility/offline class
(ADR-0039): run it in the user's own wallet process, never as a shared scanning service.

## Host operations

| Operation | µs/op | KiB allocated/op |
|---|---:|---:|
| Viewing key generation (1 blinded multiplication) | 2,797 | 3,688 |
| Seal, 1 reader (AEAD self-test + 2 blinded multiplications) | 5,647 | 7,398 |
| Seal, 2 readers (owner + auditor) | 8,506 | 14,779 |
| Open: full acceptance (Agree + KDF + AEAD + blinded recomputation of `C`) | 7,155 | 11,414 |
| Open: failed trial decryption (another reader's key: Agree + KDF + AEAD reject) | 2,209 | 4,038 |
| Open: invalid `E`, rejected before any secret work | 9 | 2.5 |
| Open: wrong length, rejected | < 1 | 0.1 |
| Scanner creation (AEAD known-answer self-test) | 15 | 14 |

The failed trial decryption is the wallet's dominant cost: a note that is not the wallet's costs
about 2.2 ms. An accepted note costs about 7.2 ms, because acceptance recomputes the commitment
with two more blinded multiplications (ADR-0055 I13). ADR-0055 estimated about 1.8 ms and
about 5 ms from components; the measured values include point normalization and the KDF.

**Allocation.** Almost all allocation is short-lived garbage of the blinded `BigInteger`
scalar-multiplication schedule, about 3.7 MB per multiplication (316 iterations of extended-
coordinate arithmetic). The profile's own code allocates only fixed-size buffers: under 3 KiB per
reject before secret work. The schedule is ADR-0039's approved compatibility path. The
allocation-free fixed-limb kernel (`CtJubjubPointOps`) is an unapproved candidate (ADR-0039 M9).
Moving the profile to it is a separate, reviewed decision, not an optimization made here.

## Scanning throughput

Notes sealed to another reader, so every one is a failed trial; a scanner is thread-safe.

| Threads | 512 notes | Notes/s |
|---:|---:|---:|
| 1 | 1,170 ms | 438 |
| 4 | 327 ms | 1,566 |
| 16 | 250 ms | 2,049 |

To keep the candidate set small, a wallet opens only the delivery at its own reader position
and, as an owner, filters by owner credential first (ADR-0055 D6).

## D3a on-chain (ADR-0055 M5a)

A two-output confidential transfer with one auditor. Every created note's amount is encrypted
as two 32-bit `elgamal-jubjub-v1` limbs and bound to its commitment in the same Groth16 proof.
The validator is `AuditedConfidentialNoteValidator`, evaluated in the Julc VM (Plutus V3). The
limits are mainnet's per-transaction limits on 2026-10-09: 10,000,000,000 steps and 16,500,000
memory units.

| Layout | Public inputs | Constraints | Prove (pure Java) | CPU steps | % of step limit | Memory | % of memory limit |
|---|---:|---:|---:|---:|---:|---:|---:|
| Direct (spec §8.2) | 24 | 34,184 | 3.9 s | 7,291,680,254 | 72.9% | 1,631,971 | 9.9% |
| Hash-compressed (spec §8.3) | 10 | 355,514 | 16.6 s | 4,684,809,021 | 46.8% | 1,496,117 | 9.1% |

For comparison, the same transfer without D3a (`ConfidentialNoteValidator`, 6 public inputs,
7,231 constraints) costs about 3.85e9 steps.

- **Both layouts pass ADR-0055's gate** of at most 80% of both limits.
- **Direct layout.** Each extra public input costs about 0.19e9 steps on-chain, close to the
  builtin-cost estimate (one `G1` decompression, multiplication and addition per input). The
  direct layout is cheap to prove, but scales as `2a + 8a·n` inputs: a second auditor or a third
  output would exceed the gate.
- **Hash-compressed layout.** The digest replaces the 16 coordinates with two inputs, at about
  321,000 more constraints, mostly the in-circuit BLAKE2b over 512 bytes. It leaves room for more
  auditors or outputs on-chain, at a prover cost.
- **Scope of the measurement.** These figures are for ZeroJ's reference validator, a single
  spending script. An application that also runs a minting policy in the same transaction (as
  the points demo does) adds that script's cost. ADR-0055 M3 measures the demo.

## GraalVM native image

`NoteNativeProbe` was compiled with `native-image` 25.0.2 (`--no-fallback`, no configuration
files). It reproduces the first Zcash Sapling vector (shared secret from both sides, `k_enc`),
the profile's KDF, a personalised BLAKE2b and a deterministic delivery and its opening. Its
output was identical to the JVM's, except the last line, which comes from a random round trip and
also matched. No `META-INF/native-image` configuration was needed.

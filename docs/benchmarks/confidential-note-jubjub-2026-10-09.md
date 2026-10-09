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

Single runs of the matrix (warm-up of a quarter of the operations). Two runs on the same machine
differed by up to about 40%: the first overlapped with other heavy jobs; the table is the second,
on an otherwise idle machine.

| Operation | µs/op | KiB allocated/op |
|---|---:|---:|
| Viewing key generation (1 blinded multiplication) | 1,699 | 3,689 |
| Seal, 1 reader (AEAD self-test + 2 blinded multiplications) | 3,593 | 7,407 |
| Seal, 2 readers (owner + auditor) | 5,618 | 14,791 |
| Open: full acceptance (Agree + KDF + AEAD + blinded recomputation of `C`) | 5,047 | 11,415 |
| Open: failed trial decryption (another reader's key: Agree + KDF + AEAD reject) | 1,691 | 4,038 |
| Open: `E` the identity, rejected before any secret work | 7 | 2.5 |
| Open: `E` on the curve but off the subgroup, rejected by the public subgroup check | 83 | 341 |
| Open: wrong length, rejected | < 1 | 0.1 |
| Scanner creation (AEAD known-answer self-test) | 18 | 23 |

The failed trial decryption is the wallet's dominant cost: a note that is not the wallet's costs
about 1.7 ms (2.2 ms on the busier first run). An accepted note costs about 5 ms, because
acceptance recomputes the commitment with two more blinded multiplications (ADR-0055 I13). An
adversarial `E` off the subgroup is refused by public work alone, at about 5% of a failed trial.

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
| 1 | 774 ms | 662 |
| 4 | 197 ms | 2,599 |
| 16 | 101 ms | 5,061 |

Scaling is sublinear beyond the performance cores and is bounded by allocation (garbage
collection of the blinded schedule's temporaries, 2 GB heap). The busier first run measured 438,
1,566 and 2,049 notes/s.

To keep the candidate set small, a wallet opens only the delivery at its own reader position
and, as an owner, filters by owner credential first (ADR-0055 D6).

## D3a on-chain (ADR-0055 M5a)

Confidential notes with one auditor. Every created note carries its commitment, two 32-bit
`elgamal-jubjub-v1` limb encryptions of its amount to the auditor's key (bound to the commitment
in the same Groth16 proof), and two 89-byte deliveries (owner, auditor). The validator is
`AuditedConfidentialNoteValidator`, evaluated in the Julc VM with its pinned Plutus V3 cost model
(protocol version 11), not a node. It checks the datum shapes and delivery lengths, reads the
auditor key from exactly one registry entry, and requires distinct limb handles. The limits are
mainnet's per-transaction limits on 2026-10-09: 10,000,000,000 steps and 16,500,000 memory units.

| Spend, layout | Public inputs | Constraints | Prove (pure Java, single run) | CPU steps | % of step limit | Memory | % of memory limit |
|---|---:|---:|---:|---:|---:|---:|---:|
| Transfer (two notes), direct (spec §8.2) | 24 | 34,184 | 2.9–5.7 s | 7,335,025,102 | 73.4% | 1,773,956 | 10.8% |
| Redeem (one change note, public price), direct | 15 | 18,366 | 2.4 s | 5,517,318,556 | 55.2% | 1,249,126 | 7.6% |
| Transfer (two notes), hash-compressed (spec §8.3) | 10 | 355,514 | 11.7–22 s | 4,728,153,869 | 47.3% | 1,638,102 | 9.9% |

Prove times are single runs on a busy machine; repeated runs varied by up to a factor of two. CPU
steps and memory are deterministic.

For comparison, the same transfer without D3a (`ConfidentialNoteValidator`, 6 public inputs,
7,231 constraints) costs about 3.85e9 steps.

- **Every measured spend passes ADR-0055's gate** of at most 80% of both limits, for this
  reference validator. Carrying the deliveries and the registry and handle checks added about
  0.04e9 steps to the transfer (from 7.29e9 without them).
- **Direct layout.** Each extra public input costs about 0.19e9 steps on-chain, close to the
  builtin-cost estimate (one `G1` decompression, multiplication and addition per input). The
  direct layout is cheap to prove, but scales as `2a + 8a·n` inputs: a second auditor or a third
  output would exceed the gate.
- **Hash-compressed layout.** The digest replaces the 16 coordinates with two inputs, at about
  321,000 more constraints, mostly the in-circuit BLAKE2b over 512 bytes. It leaves room for more
  auditors or outputs on-chain, at a prover cost.
- **Scope of the measurement.** These figures are for ZeroJ's reference validator, a single
  spending script. An application that also runs a minting policy in the same transaction (as
  the points demo does) adds that script's cost; the direct transfer leaves 6.6 percentage points
  below the gate. ADR-0055 M3 measures the demo's complete transaction, which is the final gate
  check for that application.
- **Circuit overhead.** The compressed circuit range-checks each hashed byte twice (once as a
  witness byte, once inside the BLAKE2b gadget), about 4,900 redundant constraints (1.4%). Soundness
  is unaffected; sharing the decomposition is a possible optimization.

## GraalVM native image

`NoteNativeProbe` was compiled with `native-image` 25.0.2 (`--no-fallback`, no configuration
files). It reproduces the first Zcash Sapling vector (shared secret from both sides, `k_enc`),
the profile's KDF, a personalised BLAKE2b and a deterministic delivery and its opening. Its
output was identical to the JVM's, except the last line, which comes from a random round trip and
also matched. No `META-INF/native-image` configuration was needed.

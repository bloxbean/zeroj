# ADR-0029: blst-Accelerated Groth16 Prover (Native MSM/Setup)

## Status
Proposed

## Date
2026-07-07

## Context

ADR-0028 shrank the *circuit* — the Ed25519 scalar mult went ~29M → ~3M constraints and the full
CIP-1852 derivation is now in the low-double-digit millions, roughly the same order of magnitude as
circom/gnark. But the **prover** did not change, and it is now the binding constraint for
proving at scale.

**ADR-0027 M7 measured** ZeroJ's pure-Java Groth16 prover (BLS12-381): 2¹⁸ setup 895 s / prove
69 s; extrapolated 2²¹ prove ~9 min, ~10.5 GB; 2²³ ~37 min, ~42 GB. **Memory is the binding
ceiling, not time**, and the M7 note called out the root cause and the fix:

> "the prover uses pure-Java `PippengerBLS381` MSM (no blst path wired in). A native-MSM prover
> would move these numbers; that wiring is future work."

Concretely, the cost lives in two places, both pure-Java:
- **Prove** (`Groth16ProverBLS381`): three/four **multi-scalar multiplications** — `computePiA`,
  `computePiB_G1`, `computePiC` via `PippengerBLS381.msm` (G1) and `computePiB_G2` via a
  hand-rolled `g2Msm` (G2) — plus `computeH`'s FFT (`FieldFFTBLS381`). MSM dominates.
- **Setup** (`Groth16SetupBLS381`): builds `pointsA[numWires]`, `pointsB1`, `pointsB2` (G2),
  `pointsH[domainSize]`, `pointsL`, `IC` — each by a per-wire pure-Java scalar multiplication.
  (Setup is a one-time / MPC-ceremony cost in production, but dominates the dev loop.)

**What already exists.** The `zeroj-blst` module (`BlstBls12381Provider`, `BlstPairing`) binds
`foundation.icon:blst-java:0.3.2` (JNI) and is used for **pairing and single EC ops** — but *not*
by the prover. blst is the fastest open BLS12-381 implementation (native, constant-time-optional,
assembly-optimized); its MSM is typically **10–50× faster** than a naive Java Pippenger, and it
allocates points in **native (off-heap) memory** — which directly relieves M7's binding JVM-heap
ceiling.

**Constraints discovered.** blst-java 0.3.2 exposes native single scalar-mul (`P1.mult`, `P2.mult`)
and `add`, but **not** a batched Pippenger MSM (`blst_p1s_mult_pippenger`) — so a maximal-speed MSM
needs either a JNI extension or a Pippenger loop built over blst's native add/double. Two further
known issues from the Jul-2026 production-readiness review: blst-java 0.3.2 **supply-chain
provenance**, and **GraalVM native-image** requires `jni-config` + the `libblst.so` resource bundled
(the same class of problem yaci-store ADR 017 addresses for its evaluator).

## Decision

Add a **blst-accelerated Groth16 prover/setup as an opt-in provider**, keeping the pure-Java prover
as the **default** (GraalVM-native-image-friendly, no JNI, deterministic). Accelerate the two hot
paths behind a provider seam mirroring the existing `Bls12381Provider` SPI, and gate correctness on
**bit-identical proofs**.

### 1. blst-backed MSM (the primary win)

A `BlstMsmBLS381` producing G1/G2 multi-scalar multiplications. Two rungs:
- **Rung A (now):** a Pippenger bucketing loop whose inner point add/double are blst native ops
  (`P1.add`/`P2.add`), replacing `PippengerBLS381`/`g2Msm`. Big speedup, no JNI change.
- **Rung B (max):** bind blst's native `blst_p1s_mult_pippenger` / `blst_p2s_mult_pippenger`
  directly (a small JNI extension or a newer binding). Fastest; pursue after Rung A proves out.

### 2. Wire MSM into the prover

Route `computePiA`, `computePiB_G1`, `computePiB_G2`, `computePiC` through the MSM provider. The
choice is per-`ProverBackend` (SPI), selected at runtime; the pure-Java path stays the default.

### 3. Wire scalar-mul into setup

Replace the per-wire scalar multiplications in `Groth16SetupBLS381` with the blst provider. Points
are held in native memory, cutting the JVM-heap pressure that M7 identified as the ceiling.

### 4. FFT / Fr acceleration (optional, later)

`computeH`'s FFT is O(n log n) Fr operations — less dominant than MSM. Optionally accelerate the
Montgomery-Fr multiply via blst `Scalar`, or leave `FieldFFTBLS381` in Java. Deferred until the
M7-with-blst benchmark shows FFT is the next bottleneck.

### 5. Correctness gate — bit-identical proofs

The blst prover MUST produce **the same proof** as the pure-Java prover for the same
(circuit, witness, SRS) — Groth16 with fixed blinding is deterministic, so this is testable
directly. And both proofs MUST be accepted by the off-chain (`Groth16BLS12381Verifier`) and
on-chain (Julc) verifiers. This is the release gate for every accelerated component (MSM, then
setup): the pure-Java path is the frozen reference oracle (same discipline as ADR-0028).

### 6. Deployment posture

- Pure-Java prover: **default**, for GraalVM native-image and JNI-free deployments.
- blst prover: **opt-in** (server-side proving), where JNI is available. Ships with `jni-config` +
  the `libblst.so`/`.dylib` resources for native-image users who opt in (reuse `zeroj-blst`'s
  config; mirror yaci-store ADR 017).

## Milestones

| # | Scope | Validation | 
|---|-------|-----------|
| **M1** | `BlstMsmBLS381` G1/G2 MSM (Rung A: blst native add/double) | differential vs `PippengerBLS381`/`g2Msm` — **identical** points over random (points, scalars), incl. edge scalars (0, 1, r−1) |
| **M2** | Wire MSM into `Groth16ProverBLS381` (blst `ProverBackend`) | **bit-identical proof** vs pure-Java for the same (circuit, witness, SRS); off-chain + on-chain verifier accept both |
| **M3** | Wire blst scalar-mul into `Groth16SetupBLS381` | setup PK/VK points identical vs pure-Java; full prove→verify loop passes |
| **M4** | Rung B: bind native `blst_p1s/p2s_mult_pippenger` (JNI ext) | identical vs Rung A; benchmark delta |
| **M5** | **Re-run the ADR-0027 M7 benchmark with blst** (2¹⁸–2²³) | prove time + peak (heap **and** native) memory vs pure-Java; go/no-go on at-scale provability, incl. a real proof of the ~11–12M derivation |
| **M6** | GraalVM native-image `jni-config` + `libblst` resource for the opt-in provider | native-image build with blst prover runs; pure-Java default unaffected |

Per-milestone branch → the integration branch; the pure-Java reference is never removed.

## Consequences

### Easier
- **At-scale proving becomes feasible**: expected ~10–50× faster MSM and native-memory point
  storage should turn M7's ~9 min / 10.5 GB at 2²¹ into seconds–tens-of-seconds and relieve the
  heap ceiling — making a real Groth16 proof of the ~11–12M derivation practical, which closes the
  loop ADR-0028 opened and is what "prover comparable to circom" actually requires.
- Benefits every ZeroJ proving use case (all usecases), not just the derivation.

### Harder
- **Two prover paths** to keep in lockstep — mitigated by the bit-identical differential gate.
- **JNI + native-image** operational complexity for opt-in users.

### Neutral
- No circuit or verifier changes; proofs are identical, so on-chain verification is unaffected.
- Trusted setup security is unchanged (still needs an MPC ceremony per ADR-0013/0025 — blst only
  makes the dev-loop setup faster, it is not the production setup).

## Risks

1. **blst-java 0.3.2 supply-chain provenance** (flagged in the Jul-2026 review). *Mitigation:* pin +
   checksum-verify the artifact; evaluate building blst from source / a vetted binding; keep the
   pure-Java default so no deployment is *forced* onto JNI.
2. **Proof divergence** (a blst-vs-Java mismatch would silently break verification). *Mitigation:*
   the bit-identical gate (M2/M3) over random and edge inputs, plus verifier-accept checks.
3. **GraalVM native-image JNI** (`libblst` missing → `NoClassDefFoundError`, the exact failure seen
   with yaci-store's evaluator). *Mitigation:* M6 config; pure-Java default for native-image.
4. **Constant-time / side-channels** for the *witness*-dependent scalar muls. Proving is not usually
   a side-channel target (the prover knows the witness), but if it becomes one, blst offers
   constant-time variants. *Mitigation:* note; use blst constant-time muls where the scalar is
   secret if a threat model demands it.

## References

- ADR-0027 M7 — the prover-scale benchmark and the "no blst path wired in" finding.
- ADR-0028 — the circuit optimizations that made the prover the bottleneck.
- ADR-0018 / ADR-0021 — shared BLS12-381 primitives / blst provider hardening.
- ADR-0013 / ADR-0025 — trusted-setup ceremony / audit readiness (setup security is separate).
- yaci-store ADR 017 — blst JNI in a GraalVM native image (the native-image config pattern).
- supranational/blst — the native library; `foundation.icon:blst-java` — the current JNI binding.

# ADR-0029: Groth16 Prover Performance — Memory (mmap) and Speed (blst / Vector API)

## Status
Proposed

## Date
2026-07-07

> **Scope: the PROVER only.** Verification is a fixed, tiny cost — ~3–4 pairings + one scalar-mul
> per public input, *independent of circuit size* — so the pure-Java `Groth16BLS12381Verifier` is
> already milliseconds and GraalVM-native-image-clean, and the on-chain verifier is Plutus (built-in
> BLS12-381), not Java. **Nothing here touches the verifier.** blst, mmap, and the Vector API are
> prover-side levers; none of them compromises the native-image story for the code users embed.

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

**Two independent axes.** Prover cost has *two* separable problems, and they need *different* levers:

- **Memory** — the ~150 GB at 2²⁵ is largely JVM object bloat (`BigInteger` coords, point objects,
  GC headroom). Fixed by **compact representation** + **`mmap`-ing the read-only proving key** from a
  file so only the working set is RAM-resident. *This is what makes a big proof `fit`.*
- **Speed** — the arithmetic throughput of MSM/FFT. Fixed by **native asm (blst)** or, JNI-free, by
  **packed-limb arithmetic + the Java Vector API (SIMD)**. *This is what makes a proof `fast`.*

`mmap` (memory) composes with *either* speed backend. And AOT/native-image is **not** a speed lever:
for a minutes-to-hours numeric hot loop a warm JVM JIT matches or beats native image (startup and
footprint, native-image's wins, are irrelevant to a long prover) — native image remains a
*deployment* choice, which only matters for the verifier.

## Decision

Pursue prover performance as **two tracks sharing one memory strategy**, keeping the current
pure-Java prover as the **frozen reference oracle** (gate everything on **bit-identical proofs**):

- **Track A — pure-Java, native-image-clean** (packed `long[]` limbs → Java Vector API → `mmap` PK →
  single-pass Pippenger / external-memory FFT). No JNI; stays GraalVM-native-image-compilable.
  Estimated ~10–20× over today's `BigInteger` prover (mostly the `long[]` specialization; the Vector
  API adds ~1.5–3× **if** carry-heavy field mul vectorizes — the most speculative number here,
  must be measured), and `mmap` makes it *fit* on modest RAM. Prove time still likely tens of
  minutes — this is the **feasibility + native-image** path.
- **Track B — native blst** (native MSM/setup, optionally + `mmap` PK). ~30–50× over today; the
  **speed** path. Costs JNI + native-image config, so it's **opt-in / server-side** only.

| approach | RAM (≈2²⁵) | prove time | JNI / native-image |
|---|---|---|---|
| current pure-Java (`BigInteger`) | ~150 GB (OOM) | hours | none / clean |
| Track A: packed limbs + Vector API | ~30–50 GB | ~tens of min | none / **clean** |
| Track A + `mmap` PK | **fits modest RAM** | ~tens of min (+I/O) | none / **clean** |
| Track B: blst | ~30–50 GB | **minutes** | JNI / native-image cost |
| Track B + `mmap` PK | **fits modest RAM** | minutes (+I/O) | JNI / native-image cost |

Sequencing: **Track A first** (unblocks feasibility while preserving native-image), then Track B if
prove *time* becomes the binding constraint. The blst provider is behind a provider seam mirroring
`Bls12381Provider`; the pure-Java default is never removed.

## Track A — pure-Java, native-image-clean

### A1. Packed `long[]` Montgomery arithmetic (the prerequisite, biggest single win)

Replace the prover's `BigInteger`-backed Fp/Fr and point representations with packed `long[]` limbs
(Montgomery form) and **in-place, allocation-free** field/point ops (reused mutable buffers). This
alone is ~5–10× (specialization + near-zero GC), shrinks resident memory dramatically, and is the
representation `mmap` and SIMD both build on. Differential-tested against the frozen `BigInteger`
path (identical field/point results).

### A2. Java Vector API (SIMD) for field multiply

Vectorize the limb multiply/carry with `jdk.incubator.vector`. Estimated ~1.5–3× *additional* on the
arithmetic hot loop — but **carry propagation is SIMD-hostile**, so the real win depends on an
AVX-512 IFMA (52-bit limb) representation and how well the JIT intrinsifies it. **The most
speculative number in this ADR — must be measured**, and A1 must land first (A2 is meaningless on
`BigInteger`). Preview API in Java 25; acceptable for a backend prover. Native-image-compatible.

### A3. Single-pass Pippenger + external-memory FFT (access-pattern shaping for `mmap`)

Restructure MSM so each proving-key point is read **exactly once** (accumulate into all windows'
buckets in one sequential pass) — otherwise naive per-window Pippenger re-pages the whole PK file per
window. If the read-write FFT scratch also must spill, use a cache-oblivious / external-memory FFT;
otherwise keep it in RAM (mmap suits read-only data, not the strided read-write butterflies).

## Track B — native blst

### B1. blst-backed MSM (the speed win)

A `BlstMsmBLS381` producing G1/G2 multi-scalar multiplications. Two rungs:
- **Rung A (now):** a Pippenger bucketing loop whose inner point add/double are blst native ops
  (`P1.add`/`P2.add`), replacing `PippengerBLS381`/`g2Msm`. Big speedup, no JNI change.
- **Rung B (max):** bind blst's native `blst_p1s_mult_pippenger` / `blst_p2s_mult_pippenger`
  directly (a small JNI extension or a newer binding). Fastest; pursue after Rung A proves out.

### B2. Wire MSM into the prover

Route `computePiA`, `computePiB_G1`, `computePiB_G2`, `computePiC` through the MSM provider. The
choice is per-`ProverBackend` (SPI), selected at runtime; the pure-Java path stays the default.

### B3. Wire scalar-mul into setup

Replace the per-wire scalar multiplications in `Groth16SetupBLS381` with the blst provider. Points
are held in native memory, cutting the JVM-heap pressure that M7 identified as the ceiling.

### B4. FFT / Fr acceleration (optional, later)

`computeH`'s FFT is O(n log n) Fr operations — less dominant than MSM. Optionally accelerate the
Montgomery-Fr multiply via blst `Scalar`, or leave `FieldFFTBLS381` in Java. Deferred until the
benchmark shows FFT is the next bottleneck.

## Shared — memory via `mmap` (composes with either track)

### 5. `mmap` the read-only proving key

The proving key (A/B1/B2/L/H point arrays) is large, read-only, and generated once at setup — the
ideal `mmap` case. Write it to a file at setup; at prove time map it (`FileChannel.map` /
Java 21+ `Arena` + `MemorySegment`) into off-heap memory and hand the pointer to the MSM. The OS
pages the working set; the rest stays on disk. Works for **both** tracks — Track A maps into a Java
`MemorySegment`, Track B maps into blst's native address space. Needs NVMe/SSD; prove time inflates
gracefully as RAM shrinks (a memory↔time dial), never OOM. **`mmap` ≠ disk-offloading of live
compute** — it's file-backed *virtual* memory, so only the read-only PK benefits, not the
read-write FFT scratch (A3).

### 6. Correctness gate — bit-identical proofs

The blst prover MUST produce **the same proof** as the pure-Java prover for the same
(circuit, witness, SRS) — Groth16 with fixed blinding is deterministic, so this is testable
directly. And both proofs MUST be accepted by the off-chain (`Groth16BLS12381Verifier`) and
on-chain (Julc) verifiers. This is the release gate for every accelerated component (MSM, then
setup): the pure-Java path is the frozen reference oracle (same discipline as ADR-0028).

### 7. Deployment posture

- Track A (pure-Java, incl. Vector API + `mmap`): **default**, for GraalVM native-image and JNI-free
  deployments — the prover stays native-image-compilable.
- Track B (blst): **opt-in** (server-side proving), where JNI is available. Ships with `jni-config` +
  the `libblst.so`/`.dylib` resources for native-image users who opt in (reuse `zeroj-blst`'s
  config; mirror yaci-store ADR 017).
- The **verifier** is unaffected by all of the above — pure-Java, native-image-clean, milliseconds.

## Milestones

Track A first (feasibility + native-image), then the shared `mmap`, then Track B (speed).

| # | Track | Scope | Validation |
|---|-------|-------|-----------|
| **M1** | A | Packed `long[]` Montgomery Fp/Fr + point ops, allocation-free | differential vs frozen `BigInteger` path — identical field/point results over random + edge |
| **M2** | A | Rework MSM/FFT onto the packed representation; benchmark | bit-identical proof vs `BigInteger` prover; prove-time + memory delta |
| **M3** | A | Java Vector API (SIMD) field multiply (behind a flag) | identical results; **measure** the real speedup (validate/kill the ~1.5–3× estimate) |
| **M4** | shared | `mmap` the read-only PK (single-pass Pippenger; `Arena`/`MemorySegment`) | identical proof; run a 2²⁵ proof on a modest-RAM box; report resident RAM vs file size |
| **M5** | A | **Real proof of the ~19M derivation** on normal hardware (Track A + `mmap`) | verifier (off-chain + Julc) accepts; first end-to-end at-scale prove-time number |
| **M6** | B | `BlstMsmBLS381` G1/G2 MSM (Rung A: native add/double) | differential vs `PippengerBLS381`/`g2Msm` — identical over random incl. edge scalars (0,1,r−1) |
| **M7** | B | Wire blst MSM into prover + setup (`ProverBackend` SPI) | **bit-identical proof** vs pure-Java; both verifiers accept |
| **M8** | B | Rung B native `blst_p1s/p2s_mult_pippenger`; optional `mmap` PK into native memory | identical vs Rung A; benchmark delta |
| **M9** | B | GraalVM native-image `jni-config` + `libblst` resource (opt-in only) | native-image build with blst prover runs; Track A default unaffected |
| **M10** | — | **Benchmark matrix** (2¹⁸–2²⁵): `BigInteger` vs Track A vs Track A+mmap vs blst vs blst+mmap | prove time + peak (heap **and** native/file-backed) memory; pick the default |

Per-milestone branch → the integration branch; the pure-Java `BigInteger` reference is never removed
(it stays the bit-identical oracle for every accelerated path).

## Consequences

### Easier
- **At-scale proving becomes feasible without JNI** (Track A + `mmap`): a real proof of the ~19M
  derivation runs on a modest-RAM machine while the prover stays **GraalVM-native-image-compilable**
  — the feasibility win, decoupled from the JNI question.
- **And fast when needed** (Track B): blst's ~30–50× turns minutes-to-hours into minutes for
  latency-sensitive server-side proving.
- Both benefit every ZeroJ proving use case, not just the derivation, and both leave the **verifier**
  (the code users embed) exactly as-is: pure-Java, native-image-clean, milliseconds.

### Harder
- **Multiple prover paths** (`BigInteger` reference, Track A, Track B) to keep in lockstep —
  mitigated by the bit-identical differential gate against the frozen `BigInteger` oracle.
- **Packed-limb refactor** (A1) is a real rewrite of the field/point layer.
- **Vector API is a preview feature** (Java 25) and its win is carry-propagation-limited/uncertain.
- **JNI + native-image** operational complexity for Track B opt-in users.

### Neutral
- No circuit or verifier changes; proofs are bit-identical, so on-chain verification is unaffected.
- AOT/native-image is **not** used for prover speed (a warm JIT matches/beats it on long numeric
  loops); native image stays a verifier/deployment concern.
- Trusted setup security is unchanged (still needs an MPC ceremony per ADR-0013/0025 — none of these
  levers changes setup *security*, only its dev-loop speed/memory).

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
5. **Vector API speedup may underdeliver** — carry-heavy field mul is SIMD-hostile; the ~1.5–3×
   estimate could collapse to ~1.2× without AVX-512 IFMA. *Mitigation:* A1 (`long[]` specialization)
   delivers most of the pure-Java win on its own; A3/Vector API is gated behind the M3 measurement —
   ship it only if the number is real.
6. **`mmap` thrashing** if the working set ≫ RAM on slow storage. *Mitigation:* single-pass Pippenger
   (M4) so each PK point is paged once; require NVMe/SSD; treat it as a memory↔time dial, not free.

## References

- ADR-0027 M7 — the prover-scale benchmark and the "no blst path wired in" finding.
- ADR-0028 — the circuit optimizations that made the prover the bottleneck.
- ADR-0018 / ADR-0021 — shared BLS12-381 primitives / blst provider hardening.
- ADR-0013 / ADR-0025 — trusted-setup ceremony / audit readiness (setup security is separate).
- yaci-store ADR 017 — blst JNI in a GraalVM native image (the native-image config pattern).
- supranational/blst — the native library; `foundation.icon:blst-java` — the current JNI binding.
- JEP: Vector API (`jdk.incubator.vector`) — pure-Java SIMD (Track A2); AVX-512 IFMA for field mul.
- JEP: Foreign Function & Memory API (`Arena`/`MemorySegment`) — pure-Java `mmap` into off-heap
  memory, native-image-compatible (the JNI-free path for §5).

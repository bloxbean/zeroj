# ADR-0035: Local setup memory & time reduction — dev setup on a 16 GB machine

**Status:** Proposed (2026-07-10)

## Context

The single-party development setup (`setup --i-understand-insecure`, `Groth16SetupBLS381.setup`)
for the 19,075,097-constraint circuit last measured **~90 GB heap and ~47 min**, producing a
**23 GB key bundle**. That is a hard blocker for any developer who wants to try their own circuit
or their own local bundle: proving now needs only a 16 GB laptop (ADR-0033/0034), but *creating*
keys still needs a rented big-memory box.

Scope: the **local dev setup** and the **bundle size**. The snarkjs multi-party ceremony path
(production) is untouched. Everything below preserves output-key compatibility: a bundle produced
by the optimized setup must be byte-layout identical (same `Groth16PkStore` format, same
fingerprint discipline) and verified by prove + self-check + on-chain verify.

## Audit — where ~90 GB and ~47 min go

`Groth16SetupBLS381.setup` (one file, ~240 lines) at 19M constraints / 43.7M wires / domain 2²⁵.
The ~90 GB figure predates ADR-0034 — the constraint-map share (~8–10 GB) is already gone via the
lazy CSR adapter; the rest still stands:

### Memory (estimated; M1 re-measures)

| # | buffer | est. size | fix |
|---|---|---|---|
| 1 | `pointsB2` — `AffineG2[43.7M]` nested objects (the same monster ADR-0033 removed from the prover) | **~15.7 GB** | M3 stream |
| 2 | flat G1 outputs held simultaneously: `pointsA` + `pointsB1` (4.2 GB each), `pointsL` (~4.2 GB), `pointsH` (3.2 GB) | **~15.8 GB** | M3 stream |
| 3 | QAP evaluations `us`/`vs`/`ws` — 3 × `BigInteger[43.7M]`, live from accumulation through every point loop | ~10 GB | M2 flat limbs |
| 4 | `lagrange` + `omegaPows` — 2 × `BigInteger[2²⁵]` | ~7 GB | M2 flat + early free |
| 5 | circuit graph + CSR retained by the CLI service during setup (measured 5.7 GB + ~1 GB in phase 2) | ~6.7 GB | M2 release graph after compile |
| 6 | GC headroom for massive per-point object churn (G2 `scalarMul` allocates ~250 Jacobian objects per point × 43.7M points) | the rest | M4 kills the churn |

Sum of avoidable ≈ **55 GB+**; with the old constraint maps this reproduces the ~90 GB era.

### Time (~47 min, 12 cores)

| # | cost | est. share | fix |
|---|---|---|---|
| 1 | **165M G1 `toAffine()` inversions** — the comb table (ADR-0029 M2a) made the *multiplication* cheap (≤64 flat adds, no doublings), but every point still pays an individual Fp inversion (~50–100 µs) to normalize | ~15–25 min | M4 batch normalization |
| 2 | **43.7M G2 scalar muls** — generic object-based double-and-add (`g2.scalarMul`, ~255 iterations of immutable-object arithmetic) + a per-point Fp2 inversion in `toAffine()` | ~20–30 min | M4 G2 comb table + batch normalization |
| 3 | 67M `modInverse` calls (Lagrange bases for the main and 2N domains, one per element) + 33.5M `modPow` (`omega2^{2i+1}` recomputed per point) | ~3–6 min | M4 batch inversion (Montgomery's trick) + stride walks |
| 4 | QAP accumulation over the map adapter (transient row materialization) + BigInteger mod arithmetic | ~2–4 min | M2 CSR-direct + `FrArith381` |
| 5 | writing 23 GB | ~1 min | already fine |

## Decision — milestones

### M1 — This ADR + one profiled baseline run
Re-measure the current setup at 19M post-ADR-0034 (`jmap -histo:live` at the QAP phase and the
point-generation phase, `/usr/bin/time -l`): the real starting floor is likely already below
90 GB. Record in Results.

### M2 — Memory quick wins (mirror of ADR-0034 M1/M2 patterns)
1. CLI releases the circuit graph after compile — setup needs only the CSR (−5.7 GB).
2. Setup consumes `R1CSFlat` directly (new overload; the `List<R1CSConstraint>` entry stays as an
   adapter for tests/compat): QAP accumulation reads CSR rows with the Montgomery-converted
   coefficient dictionary — no transient maps.
3. `us`/`vs`/`ws`, `lagrange`, `omegaPows` as flat canonical/Montgomery limbs (`FrArith381`,
   32 B/element): ~17 GB of boxed field elements → ~7 GB flat; `omegaPows` freed after the
   Lagrange pass; `lagrange` freed after accumulation.

### M3 — Stream every point file straight into the PkStore layout (the big one)
`setupToStore(flat, numWires, numPublic, tau, dir)`: map each output file (`pointsA.bin`,
`pointsB1.bin`, `pointsH.bin`, `pointsL.bin` in `MmapG1File` layout; `pointsB2.bin` in the 192 B
BE layout) READ_WRITE and write points chunk-by-chunk as they are computed — **no output array is
ever heap-resident** (−31.5 GB). `Groth16PkStore.save` and the in-RAM `SetupResult` path stay for
tests; the CLI switches to the streaming entry point (it also kills the separate save step and
the double-residency during save). Optionally emit `r1cs.bin` (ADR-0034 M4) in the same pass so
the first prove doesn't recompile.

### M4 — Time: batch normalization + G2 comb + batch inversion
1. **Batch affine normalization** (Montgomery's trick): compute points of a chunk in Jacobian
   form, normalize the whole chunk with ONE field inversion (+3 muls per point) — removes ~209M
   individual Fp/Fp2 inversions. Applies to G1 (comb output) and G2.
2. **G2 fixed-base comb table** (mirror of `FixedBaseG1BLS381`, W=4/64 windows over the G2
   generator): ≤64 mixed additions per point instead of ~255 object-allocating double-and-adds.
   Object-based G2 arithmetic is acceptable with batching; flat G2 arithmetic is a stretch goal.
3. **Batch inversion for the Lagrange bases** (both domains) and stride-walks for
   `omega^i`/`omega2^{2i+1}` (sequential per-chunk multiplies instead of per-point `modPow`).

### M5 — Measure + validate at 19M
Descending `-Xmx` (24g → 16g → 12g → 8g) + wall time; fresh-bundle validation: fingerprint match,
prove + self-check + off-chain verify + on-chain verify against the freshly generated keys, and
`SetupCacheTest`/store round-trip green. Update the CLI setup heap guidance + README/USAGE.

### M6 — Sparse key store: 24.2 GB → 9.3 GB runtime, 4.7 GB distribution
Measured against the real 19M bundle (2026-07-10): **57.8 % of all points are the point at
infinity** — 14.95 GB of literal zero bytes. Wires absent from a matrix's rows produce infinity
points, and most wires never appear in any B row:

| file | infinity | size |
|---|---|---|
| pointsA | 57.4 % | 4.20 GB |
| pointsB1 | **80.6 %** | 4.20 GB |
| pointsB2 | **80.6 %** | 8.40 GB |
| pointsL | 56.8 % | 4.20 GB |
| pointsH | 0 % (dense) | 3.22 GB |

- **M6a — sparse runtime store**: per-file presence bitmap (5.5 MB) + per-block rank prefix sums
  (~a few MB) + packed non-infinity points → **9.3 GB** on disk. `G1AffineReader`/`G2AffineReader`
  implementations answer infinity from the bitmap and rank-index into the packed points — the
  same reader seam ADR-0033 introduced, so the prover is untouched. Bonus: the prove's key
  working set drops 2.6×, directly easing page-cache pressure on 16 GB machines, and MSMs skip
  infinity points with a bit test instead of a 96/192-byte fetch.
- **M6b — compressed distribution format**: sparse + 48 B/96 B point compression →
  **~4.7 GB download** (5.2×), expanded locally once (~88M sqrts over the non-infinity points,
  minutes) into the sparse runtime layout. Generic compression is useless on high-entropy
  coordinates; sparsity + point compression are the real levers.

Compatibility: the dense format stays readable (manifest-versioned); the zkey importer can emit
either.

## Compatibility contract (non-negotiable)

Key bundles reach the CLI by two provenances, and **both must keep working unchanged at every
milestone**:

1. **Local dev setup** (`setup --i-understand-insecure` → `Groth16PkStore` layout).
2. **snarkjs ceremony import** (`import` → `ZkeyPkStoreImporter.importToPkStore`, same layout,
   `snarkjsConstraints=true` binding-row handling).

Rules the milestones must obey:

- **The dense store format remains fully supported.** `Groth16PkStore.load` auto-detects the
  format via the manifest (versioned); existing bundles — including the current 23 GB one and any
  previously distributed — load without migration, forever. The sparse format (M6a) is a new
  manifest version, not a replacement.
- **The importer is untouched until M6**, and when it gains sparse output it stays able to emit
  dense; import→load→prove→pairing-verify round-trips (the existing
  `ZkeyPkStoreImporterTest` against real snarkjs) must stay green throughout.
- **The prover is provenance-agnostic** — it reads through the ADR-0033 reader seams and must not
  learn where a bundle came from. Binding-row semantics for ceremony keys are unchanged.
- **Setup output is format-identical**: with a fixed tau and fixed phase-2 randomness (a
  package-private deterministic entry point for tests), the streamed setup (M3) must produce
  byte-identical files to the legacy `SetupResult` + `PkStore.save` path.
- **Regression gates for every milestone**: full zeroj suite (incl. the live snarkjs ceremony
  round-trip and importer hardening tests) + at 19M: fresh-local-setup bundle AND the existing
  bundle both prove + self-check + off-chain verify (+ on-chain at M5).

## Projected outcome

| | today | after M2–M4 |
|---|---|---|
| setup heap | ~90 GB (era measurement) | **≤ 12–16 GB** — flat QAP ~7 GB + streamed outputs ~0 + chunk buffers |
| setup time | ~47 min | **~8–15 min** — inversions batched, G2 comb, same parallelism |
| bundle download (M6) | 23 GB | ~11.6 GB |

With this, a developer on a 16 GB machine can compile, set up, prove, and verify a 19M-constraint
circuit end-to-end — no rented hardware anywhere in the loop.

## Testing / regression safety

Same discipline as ADR-0033/0034: differential tests at each seam (CSR-QAP vs map-QAP
evaluations; batched vs individual normalization; G2 comb vs `scalarMul`; streamed store vs
`PkStore.save` byte-compare on a small circuit), the existing `Groth16PkStoreTest`/`SetupCacheTest`
suites, and a full 19M setup → prove → verify → on-chain run against the fresh bundle before any
constant/doc changes. The dev-only security posture is unchanged (single-party, gated by
`TrustedSetupPolicy`).

## Results

_(appended as milestones land)_

| milestone | setup heap floor | setup time | notes |
|---|---|---|---|
| baseline (pre-ADR-0034 measurement) | ~90 GB | ~47 min | 23 GB bundle |
| **M1 measured baseline (post-ADR-0034, 2026-07-10)** | max RSS **54.8 GB** (peak footprint 59.3 GB) at `-Xmx80g` | **56.6 min** instrumented (5× `jmap -histo:live` full-GC pauses; ~47 min clean) | 23 GB bundle written, EXIT 0. ADR-0034's CSR adapter already removed the constraint-map share (~90 → ~55 GB for free). Live-set snapshots confirm the audit: point-gen phase holds 8.4 GB `long[]` growing to **15.8 GB at save** (all four flat G1 arrays), **100M boxed BigInteger = 8.8 GB** (us/vs/ws + lagrange + omegaPows — the Lagrange arrays are never freed), circuit graph (~5.5 GB incl. its constants) resident start-to-finish, and 1.7–2.2 GB of live MontFp381 point-object churn during G2 generation. |
| **M5 (measure + validate)** | **`-Xmx12g` PASS** (native, 11.3 min at W=4) — a real 16 GB machine works | **6.3 min** at `-Xmx16g` with **W=8 comb windows** (32 windows × 255 entries, table ~780 KB/G1 + 8160 G2 objects, built in ~1 s) | 2026-07-10: W=4→8 halves the comb additions — 10.9 → 6.3 min (7.5× vs the ~47 min baseline). Setup now also **emits `r1cs.bin` in the same pass**, so the first prove against a fresh bundle skips its compile: fresh-bundle prove = cache hit, constraints mapped 0.0 s, **54.6 s prove**, self-check PASS, verify VALID. **Hard-capped Docker validation** (`--memory=16g --memory-swap=16g`, `-Xmx12g`, output bind-mounted): PASS in 11.5 min (VirtioFS write penalty on the ~17 GB output) — the 16 GB-machine setup claim holds under a real cgroup cap, like ADR-0034 M5 did for prove. README/USAGE/heap guidance updated (~12 GB heap, ~6–7 min). |
| **M4 (batch normalization + G2 comb + batched inversions)** | `-Xmx16g` PASS — JVM peak footprint 13.9 GB | **10.9 min** (4.3× vs baseline) | 2026-07-10: all five writers work in blocks — G1 comb output stays Jacobian and a block is normalized with ONE Fp inversion (`FixedBaseG1BLS381.batchNormalize`, Montgomery's trick); new `FixedBaseG2BLS381` comb table (≤64 additions per point vs ~255 object double-and-adds) + `JacobianG2BLS381.batchToAffine` (one Fp2 inversion per block); both Lagrange domains batch their `modInverse` (one per 512 elements). Store still **byte-identical** to the legacy path (the differential gate caught a real thread-safety bug in the L-scalar producer during development — shared scratch across parallel chunks). Fresh 19M bundle: prove 59 s + self-check PASS + verify VALID. |
| **M2+M3 (flat QAP + streamed store)** | **`-Xmx16g` PASS — JVM peak footprint 12.5 GB** | **39.2 min** (−17 % before M4 touches time — flat arithmetic + collapsed GC pressure) | 2026-07-10: `setupToStore` — QAP evals/Lagrange as flat Montgomery limbs (per-chunk omega walks, no boxed arrays), CSR-direct accumulation, graph released before the heavy phase, every point written straight into the mmap'd `PkStore` files (pre-zeroed = infinity; nothing key-sized on heap). **Byte-identical** to the legacy `setup`+`save` path for fixed randomness (differential test over every store file). Fresh 19M bundle: file sizes byte-exact, prove 68 s + self-check PASS + off-chain verify VALID. Bonus: unwritten infinity pages leave APFS holes — the streamed bundle occupies **17 GB physical** (24.2 GB logical) before M6 even lands. Max RSS 28 GB includes the file-backed dirty output pages passing through the page cache (reclaimable); the anonymous footprint is the 12.5 GB. |

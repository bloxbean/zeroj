# ADR-0034: Frontend memory reduction — packed R1CS, ≤16 GB prove

**Status:** Proposed (2026-07-10)

## Context

ADR-0033 cut the 19M-constraint prove floor from ~70 GB to a measured **20 GB** — and moved the
binding constraint: `-Xmx16g` now dies in the **R1CS frontend compile**
(`R1CSCompiler.addExprs`), before the cryptographic prover is ever reached. The prover itself
(MSMs over the mmap'd key) runs in ~5 GB. This ADR targets the frontend so the full `prove`
fits in ~8–10 GB — i.e. a 16 GB laptop.

Scope note (deliberate): **setup memory (~90 GB) is out of scope** — it is a one-time
coordinator task; `prove` is what end users run.

## Measured heap attribution (live-set histograms, `jmap -histo:live`, 24 GB heap, 2026-07-10)

Three snapshots during a real 19M prove (blst backend, 23 GB key bundle):

**A — mid-compile, ~36 % of constraints emitted: 11.1 GB live** (extrapolates to ~14–16 GB at
full emission — exactly the 16 GB OOM)

| bucket | GB | classes |
|---|---|---|
| expression/constraint maps | **7.4** | `HashMap$Node` 1.95, `BigInteger` 1.81, `int[]` (mags) 1.07, `HashMap$Node[]` 0.86, `HashMap` 0.62, `Map1` 0.44, boxed `Integer` 0.35, cached `Values`/`EntrySet` views 0.26 |
| circuit graph | **3.0** | `Variable` (43.7M × 24 B) 1.05, `Gate$Term` 0.69, `Gate$Add` 0.34, `Gate$Mul` 0.26, `Gate$LinComb` 0.25, `Gate$AssertEq` 0.20, `List12` 0.25 |

**B — early `computeH`: 16.8 GB live — the process peak**

| bucket | GB | note |
|---|---|---|
| boxed field elements | 5.6 | `BigInteger` 3.11 + `int[]` mags 2.49 (constraint coeffs + witness) |
| constraint-map machinery | 4.8 | Node 1.63, `HashMap` 0.86, tables 0.61, `Map1` 0.87, `Integer` 0.34, views 0.49 |
| **circuit graph — dead weight** | **3.0** | witness is already computed; the graph is unused during `computeH` but only released *after* it (`OwnershipCircuitService.prove`) |
| flat FFT scratch | 2.1→3.2 | the ADR-0029 `long[]` arrays — already lean |
| `R1CSConstraint` records | 0.46 | 19M × 24 B |

**C/D — late computeH → MSMs: 5.1 GB live.** The ADR-0033 release works: only witness +
hCoeffs `BigInteger`s (2.1 GB + arrays) remain. The prove tail is already lean.

Two structural findings in `R1CSCompiler` (zeroj-circuit-dsl):
1. **Redundant base-variable entries.** Every input / Mul output / hint / bit gets
   `exprMap.put(id, Map.of(id, ONE))` — but `getExpr` already *defaults* absent wires to exactly
   that value. ~19M pointless entries ≈ 1.5–2 GB (nodes + boxed keys + `Map1` + table growth).
2. **`addExprs` copies per Add gate** (`new HashMap<>(a)` then merge) — 14.3M Add gates; deep
   adder chains (SHA-512) make this the allocation storm the OOM lands in. The `removeIf`
   call also instantiates and caches a `Values` view per map (0.5 GB of views live at B).

## Decision

Milestones ordered by value-per-risk; each is independently shippable and measured against the
same 19M bundle (protocol as ADR-0033).

### M1 — Quick wins (zero-risk, ~−5 GB at the two peaks)
1. **Release the graph before `computeH`** (CLI `OwnershipCircuitService.prove`): the witness is
   computed before the prove call, so null `circuit`/`r1cs` *before* `computeH` (the local
   `cons` reference suffices) instead of after. −3.0 GB at peak B.
2. **Skip redundant base-variable `exprMap` puts** in `R1CSCompiler` — `getExpr`'s default
   already yields `Map.of(id, ONE)` for absent wires; only Const/Add/LinComb outputs need
   storing. ~−1.5–2 GB at the compile peak, and faster (19M fewer puts + smaller table).
3. **Pre-size `constraints` and `exprMap`** from a cheap gate-count pass: un-pre-sized, the 19M
   `ArrayList` re-copies a hundreds-of-MB humongous `Object[]` on every grow (old + new live at
   once — the observed 18 GB OOM trigger), and the exprMap table re-hashes the same way.

### M2 — Packed (CSR) constraint representation — the core (~−7 GB)
Replace `R1CSConstraint`'s three `Map<Integer,BigInteger>` with compact CSR storage owned by
`R1CSConstraintSystem`:
- `int[] rowOffsets` (per matrix A/B/C), `int[] wireIdx`, coefficients as 4-limb packed
  `long[]` (or a small-coeff fast path: the overwhelming majority are ±1).
- `R1CSCompiler` emits straight into CSR builders (no per-row HashMaps for *emitted*
  constraints; `exprMap` keeps maps only for live derived expressions).
- `computeH.evalLinComb` reads CSR directly — no map iteration, no boxed keys; likely a
  compile+H speedup as well.
- **Compatibility:** `constraints()` returns a lazy `List<R1CSConstraint>` adapter view that
  materializes a row on demand — setup, exporters (`R1csExporter`), the zkey importer
  round-trip test, and `snarkjsConstraints` keep working untouched. The prove path uses CSR
  natively. Existing key bundles/VK are unaffected (this is all pre-QAP, structure-identical).
- Replaces at peak B: 4.8 GB map machinery + ~3 GB constraint-coeff boxing + 0.46 GB records
  → ~1.5–2 GB flat. Compile-emission peak drops the same way.

### M3 — Flat witness + hCoeffs (ADR-0033 M4, now worth it) (~−3.5 GB tail)
- Witness: one conversion to packed 32 B/scalar `long[4·n]` after `calculateWitness`, drop the
  `BigInteger[]`; MSM backends take flat scalars (blst's LE encoding comes straight from limbs;
  the pure-Java Pippenger converts to limbs internally anyway).
- hCoeffs: `computeH` already holds the result flat — stop boxing 33.5M `BigInteger`s; feed the
  H-MSM flat.
- Prove tail: 5.1 GB → ~2 GB; peak B loses another ~2.6 GB of witness boxing.

### M4 — Compile-once: cache the packed R1CS beside the key bundle
CSR is directly serializable: write `r1cs.bin` (fingerprint-keyed) next to the key store on
first compile; `prove` mmaps/streams it and **skips the constraint-emission peak entirely**.
The circuit graph still gets built for witness calculation (~3 GB + calc structures) — that,
not the R1CS, becomes the remaining frontend cost. (A full "witness program" artifact that
removes the graph build too is a future ADR, à la snarkjs's calculator.)

### M5 — Validate the 16 GB regime for real
Docker `mem_limit=16g` (the 128 GB box exerts no eviction pressure): the mmap'd 23 GB key must
refault cleanly (ADR-0033 "Regime A"); record wall-clock degradation vs unconstrained.

## Projected outcome

| stage | projected peak | binding phase |
|---|---|---|
| today (post-ADR-0033) | 20 GB pass / 16 GB OOM | compile emission + computeH overlap |
| after M1 | ~13–14 GB | compile emission |
| after M1+M2 | ~9–10 GB | computeH (FFT 3.2 + CSR 1.5 + witness 2.6 + graph-free) |
| after M1–M3 | ~8 GB | FFT scratch + graph build for witness |
| after M1–M4 | ~6–8 GB, compile skipped | witness generation |

Target: **`prove` on a 16 GB machine** with heap ~8–10 GB, key refaulting from disk under a
hard cap (M5 evidence).

## Measurement protocol

As ADR-0033: same 19M key bundle, descending `-Xmx` after each milestone (16g → 12g → 10g →
8g), `jmap -histo:live` at the compile and computeH peaks, prove time must stay ~2–3 min
(blst and pure-Java), self-check + off-chain verify must PASS. CLI `HARD_MIN_HEAP_GB` /
`RECOMMENDED_HEAP_GB` and README/USAGE updated with each measured floor.

## Results

_(appended as milestones land)_

| milestone | -Xmx floor | prove time | notes |
|---|---|---|---|
| baseline (ADR-0033) | 20 GB (16 GB OOMs in compile) | ~2.2–2.9 min | peak B 16.8 GB live; attribution above |
| M1.1+M1.2 (graph-release + no base entries) | 18 GB still OOMs | — | 16 GB dies in `subExprs`, 18 GB dies at `constraints.add` → `ArrayList.grow` — the un-pre-sized 19M-element backing array re-copies (old+new humongous arrays live at once) near the cap. Led to M1.3. |
| M1.3 (pre-size constraints list + exprMap from a gate-count pass) | 18 GB still OOMs; **20 GB PASS** (2.8 min, self-check PASS, same 19,075,097 constraints) | ~2.8 min | **M1 verdict: headroom, not floor.** The live derived-expression maps + constraints + graph are structurally ~13–14 GB; G1 needs ~25 % headroom under this allocation rate, so the floor stays 20 GB until the representation changes. M1 stays in (less GC pressure at 20–24 GB, groundwork for M2) — but **M2 (CSR) is the decisive milestone**. |

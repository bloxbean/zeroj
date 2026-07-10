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
| **M2 (CSR + expression liveness eviction)** | **16 GB PASS** | **2.0 min blst** (2.4 min total) | 2026-07-10: constraints emitted straight into packed CSR (`R1CSFlat`, ~12 B/term, shared coefficient dictionary); exprMap evicts each derived expression on its pre-counted last read (live frontier only); `computeH` reads CSR with a Montgomery-converted dictionary and handles snarkjs binding rows as a count. Same 19,075,097 constraints, self-check PASS, compile 19.9 s (pre-pass included). Prove also got faster (121 s — no map iteration in the H eval). |
| M2 | **12 GB PASS** | 2.4 min total | No GC tax. Peak footprint 28.1 GB (incl. touched file-backed mmap key pages). |
| M2 | **10 GB PASS — the floor** | **2.3 min total** (119 s prove) | Still no slowdown at the floor. |
| M2 | 8 GB **OOM** | — | Compile (16.8 s) and witness (2.1 s) now pass easily; the OOM is in `computeH`'s parallel workers — the remaining live set is witness `BigInteger[]` (~2.6 GB) + boxed hCoeffs (~2.6 GB) + flat FFT (3.2 GB) + CSR (~1 GB). Exactly the M3 target (flat witness + flat hCoeffs → projected ~5 GB floor). |

**M2 outcome: floor 20 GB → 10 GB (2×; 70 GB → 10 GB, 7× across the two ADRs).** Prove is the
fastest yet (119–127 s blst), compile time unchanged (~16–20 s, arithmetic-bound), identical
constraint system (fingerprint match), self-check + verify PASS against the untouched key
bundle/VK. A 16 GB machine can now prove (heap 10–12 GB; the 23 GB key is file-backed —
hard-cap eviction behaviour is the pending M5 validation).

| **M3 (flat witness + flat hCoeffs — `FlatScalars`)** | **8 GB PASS** | **1.9 min blst** (2.2 min total, 111 s prove) | 2026-07-10: witness and hCoeffs are packed canonical 4-limb `long[]` (32 B/scalar) end-to-end — `computeH` runs entirely on `FrArith381` flat limbs (dictionary Montgomery-converted once, witness limbs Montgomery-converted in place via R²), MSM window digits and blst LE scalar bytes read straight from the limbs, `ParallelMsm` chunks are O(1) slice views, and the pure-Java Pippenger's per-MSM 32-byte-per-scalar decode is gone. First 8 GB attempt OOM'd *packing* the witness (boxed array + flat array + circuit graph coexisted): fixed by releasing the graph before packing and consuming the boxed array element-by-element (`packConsuming`). Same 19,075,097 constraints, self-check PASS. |
| M3 | 6 GB **OOM** | — | Back in the R1CS frontend compile (CSR builder + live expression frontier + graph). The next floor lever is M4 (`r1cs.bin` cache — skip compile entirely at prove time). |

**M3 outcome: floor 10 GB → 8 GB — and 70 GB → 8 GB (~9×) across the two ADRs.** Prove
111 s (was ~283 s + ~100 s key load at the ADR-0033 baseline). The prove path no longer boxes a
single field element.

| **M4 (`r1cs.bin` compile-once cache)** | **7 GB PASS (warm)** / 8 GB (first run) | **2.1 min total (warm)** | 2026-07-10: `R1CSFlatIO` writes the packed CSR + coefficient dictionary beside the key bundle, fingerprint-keyed (923 MB, 0.4 s write, 0.1–0.2 s load). A matching cache skips `compileR1CS` entirely; only the header is probed up front and the full load is **deferred until after the witness is packed**, so the constraints never coexist with the witness-generation peak (that deferral is what unlocked 7 GB — an eager load OOM'd). The preflight heap check is cache-aware (7 GB warm / 8 GB cold). 6 GB still OOMs building the circuit graph for the witness — the remaining frontend structure; removing it needs a witness-program artifact (future ADR). Integrity: a stale/foreign cache is ignored via the fingerprint; a tampered one cannot yield a false proof (fails the pairing self-check against the bundle VK) — worst case is a wasted run. |

**M4 outcome: warm floor 7 GB, warm total ~2.1 min (compile off the prove path).** The frontier
is now witness generation (graph build + evaluation): the target of a future witness-program
workstream if a sub-7 GB floor is ever needed.

| **M5 (hard-capped validation, Docker `--memory=16g --memory-swap=16g`)** | **16 GiB cap PASS, pure Java** | **2.6 min total** (147.8 s prove) | 2026-07-10: a true cgroup limit with the 23 GB key bind-mounted (VirtioFS — the worst-case I/O path). The container rode the cap at 15.6/16 GiB with the kernel evicting/refaulting key pages the whole MSM phase (Regime A) and finished barely slower than uncapped. The pure-Java multi-pass window reads did **not** thrash — the per-chunk working set (~4 GB) fits the remaining cache. |
| M5 | 16 GiB cap **OOM-kill (exit 137), blst** | — | **The cap exposed what `-Xmx` cannot:** blst's per-MSM native FFM arenas — all parallel chunks deserialize concurrently, ~8.4 GB native during the G2 MSM (43.7M × 192 B) + ~4.2 GB G1 — on top of the 10 GB heap. Fine on a big host, fatal under 16 GiB. Fix applied: the CLI's `--backend` default is now **`java`** (measured same-speed at this circuit size, no native memory, native-image-clean); `--backend blst` is the explicit opt-in for big-memory machines, with a warning when total (cgroup-aware) memory is under ~24 GB. This also resolves the long-open "pick the default backend" question — pure Java won on safety at equal speed. Future zeroj item: bound blst's concurrent arena footprint (execute chunks K-at-a-time through a semaphored pool → native ≈ K × chunk size) so blst can run capped too. |

**M5 outcome: the "16 GB machine" claim is validated end-to-end** — hard cap, real eviction
pressure, worst-case bind-mount I/O, ~2.6 min, self-check PASS — with the pure-Java backend,
which the CLI now auto-selects on such machines. The same day, a proof from this fully-optimized
prover (CSR + flat scalars + cached constraints) was **verified on-chain** against the running
Yaci DevKit validator (4.9 s, unchanged VK) — closing the E2E loop for the whole
ADR-0033/0034 arc.
